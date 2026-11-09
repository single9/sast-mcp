"""Triage 紀錄測試：fingerprint、inline ignore、API、統計、SARIF 與 UI。"""

from __future__ import annotations

import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import Finding
from app.triage import fingerprint_for, parse_ignore_comment

SOURCE = """\
import hashlib
import os


def run(cmd):
    os.system(cmd)


def digest(data):
    return hashlib.md5(data).hexdigest()
"""


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def make_zip(files: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def wait_for_scan(client: TestClient, scan_id: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = client.get(f"/api/v1/scans/{scan_id}").json()
        if scan["status"] in {"completed", "failed"}:
            return scan
        time.sleep(0.05)
    raise AssertionError(f"掃描 {scan_id} 逾時未完成")


def create_zip_scan(client: TestClient, files: dict[str, str | bytes]) -> dict:
    response = client.post(
        "/api/v1/scans",
        files={"file": ("source.zip", make_zip(files), "application/zip")},
    )
    assert response.status_code == 202, response.text
    return wait_for_scan(client, response.json()["id"])


def finding_by_rule(client: TestClient, scan_id: str, rule_id: str) -> dict:
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    return next(finding for finding in findings if finding["rule_id"] == rule_id)


def test_fingerprint_is_stable_across_line_shifts():
    base = Finding(rule_id="r1", message="m", file="src/app.py", line=10, snippet="os.system(cmd)")
    moved = Finding(rule_id="r1", message="m", file="src/app.py", line=99, snippet="os.system(cmd)")
    changed = Finding(rule_id="r1", message="m", file="src/app.py", line=10, snippet="os.popen(cmd)")
    other_file = Finding(rule_id="r1", message="m", file="src/other.py", line=10, snippet="os.system(cmd)")

    assert fingerprint_for(base) == fingerprint_for(moved)
    assert fingerprint_for(base) != fingerprint_for(changed)
    assert fingerprint_for(base) != fingerprint_for(other_file)


def test_parse_ignore_comment_variants():
    assert parse_ignore_comment("x = 1  # sast:ignore") == (True, None)
    assert parse_ignore_comment("# sast:ignore: rule-a, rule-b -- 原因") == (True, {"rule-a", "rule-b"})
    assert parse_ignore_comment("# sast:ignore: 只有中文原因") == (True, set())
    assert parse_ignore_comment("x = 1") == (False, None)


def test_triage_suppresses_finding_across_stats_and_sarif(client: TestClient):
    scan = create_zip_scan(client, {"src/app.py": SOURCE})
    target = finding_by_rule(client, scan["id"], "builtin-python-os-system")
    assert target["fingerprint"]
    assert target["suppressed"] is False

    response = client.put(
        f"/api/v1/triage/{target['fingerprint']}",
        json={"status": "false_positive", "note": "cmd 來自固定字串", "author": "test"},
    )
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["status"] == "false_positive"
    assert record["last_seen_scan_id"] == scan["id"]

    # 預設不再列出；需要覆核時才 include_suppressed=true
    visible = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert all(finding["rule_id"] != "builtin-python-os-system" for finding in visible)
    everything = client.get(
        f"/api/v1/scans/{scan['id']}/findings?include_suppressed=true"
    ).json()
    suppressed = next(
        finding for finding in everything if finding["rule_id"] == "builtin-python-os-system"
    )
    assert suppressed["suppressed"] is True
    assert suppressed["triage_status"] == "false_positive"
    assert suppressed["triage_note"] == "cmd 來自固定字串"

    refreshed = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert refreshed["stats"]["suppressed"] == 1
    assert refreshed["stats"]["findings_total"] == scan["stats"]["findings_total"]
    assert refreshed["stats"]["findings"] == scan["stats"]["findings"] - 1
    assert refreshed["stats"]["triage"]["by_status"]["false_positive"] == 1

    sarif = client.get(f"/api/v1/scans/{scan['id']}/sarif").json()
    result = next(
        item for item in sarif["runs"][0]["results"] if item["ruleId"] == "builtin-python-os-system"
    )
    assert result["suppressions"][0]["status"] == "accepted"
    assert result["properties"]["suppressed"] is True
    assert result["properties"]["fingerprint"] == target["fingerprint"]

    listed = client.get("/api/v1/triage").json()
    assert any(item["fingerprint"] == target["fingerprint"] for item in listed)

    deleted = client.delete(f"/api/v1/triage/{target['fingerprint']}")
    assert deleted.status_code == 204
    restored = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert any(finding["rule_id"] == "builtin-python-os-system" for finding in restored)
    assert client.get(f"/api/v1/scans/{scan['id']}").json()["stats"]["suppressed"] == 0


def test_needs_review_does_not_suppress(client: TestClient):
    scan = create_zip_scan(client, {"src/app.py": SOURCE})
    target = finding_by_rule(client, scan["id"], "builtin-python-os-system")

    client.put(
        f"/api/v1/triage/{target['fingerprint']}",
        json={"status": "needs_review", "note": "待人工確認"},
    )
    visible = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    kept = next(finding for finding in visible if finding["rule_id"] == target["rule_id"])
    assert kept["triage_status"] == "needs_review"
    assert kept["suppressed"] is False


def test_bulk_triage_export_and_import(client: TestClient):
    scan = create_zip_scan(client, {"src/app.py": SOURCE})
    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    fingerprints = [finding["fingerprint"] for finding in findings[:2]]

    bulk = client.post(
        "/api/v1/triage/bulk",
        json={
            "fingerprints": fingerprints,
            "status": "accepted_risk",
            "note": "內部工具，風險可接受",
        },
    )
    assert bulk.status_code == 200, bulk.text
    assert bulk.json()["updated"] == 2

    export = client.get("/api/v1/triage/export").json()
    assert export["version"] == 1
    assert len(export["records"]) == 2

    for fingerprint in fingerprints:
        assert client.delete(f"/api/v1/triage/{fingerprint}").status_code == 204
    assert client.get("/api/v1/triage").json() == []

    imported = client.post("/api/v1/triage/import", json=export)
    assert imported.status_code == 200, imported.text
    assert imported.json()["imported"] == 2
    assert len(client.get("/api/v1/triage").json()) == 2


def test_inline_ignore_comments_are_applied(client: TestClient):
    source = """\
import hashlib
import os


def run(cmd):
    os.system(cmd)  # sast:ignore


def digest(data):
    # sast:ignore: builtin-python-weak-hash -- 只用來做非安全用途的 checksum
    return hashlib.md5(data).hexdigest()


def other(cmd):
    os.system(cmd)
"""
    scan = create_zip_scan(client, {"src/app.py": source})
    findings = client.get(
        f"/api/v1/scans/{scan['id']}/findings?include_suppressed=true"
    ).json()
    os_system = [f for f in findings if f["rule_id"] == "builtin-python-os-system"]
    weak_hash = [f for f in findings if f["rule_id"] == "builtin-python-weak-hash"]

    # 兩筆 os.system：只有加註解的那筆被抑制
    assert len(os_system) == 2
    assert sum(1 for finding in os_system if finding["suppressed"]) == 1
    assert all(finding["triage_status"] == "inline_ignored" for finding in os_system if finding["suppressed"])
    # 規則限定的上一行註解只影響指定規則
    assert weak_hash and all(finding["suppressed"] for finding in weak_hash)

    assert scan["stats"]["triage"]["inline_suppressed"] >= 2
    assert scan["stats"]["suppressed"] >= 2


def test_ui_shows_and_hides_suppressed_findings(client: TestClient):
    scan = create_zip_scan(client, {"src/app.py": SOURCE})
    target = finding_by_rule(client, scan["id"], "builtin-python-os-system")
    client.put(
        f"/api/v1/triage/{target['fingerprint']}",
        json={"status": "wontfix", "note": "既有系統限制"},
    )

    default_page = client.get(f"/ui/scans/{scan['id']}")
    assert default_page.status_code == 200
    assert "已抑制 1 筆" in default_page.text
    assert "builtin-python-os-system" not in default_page.text

    with_suppressed = client.get(f"/ui/scans/{scan['id']}?show_suppressed=1")
    assert "builtin-python-os-system" in with_suppressed.text
    assert "既有系統限制" in with_suppressed.text


def test_init_db_migrates_legacy_findings_table():
    """既有 SQLite 沒有 fingerprint/triage 欄位時，啟動不應失敗且能回填。"""

    import sqlite3

    from app import db
    from app.config import get_settings

    db_path = get_settings().db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_ref TEXT,
                engine TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                error TEXT,
                stats_json TEXT
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                file TEXT NOT NULL,
                line INTEGER,
                end_line INTEGER,
                col INTEGER,
                cwe TEXT,
                engine TEXT,
                snippet TEXT
            );
            INSERT INTO scans (id, status, source_type, created_at)
            VALUES ('legacy', 'completed', 'zip', '2026-01-01T00:00:00+00:00');
            INSERT INTO findings (scan_id, rule_id, severity, message, file, line, snippet)
            VALUES ('legacy', 'builtin-python-os-system', 'medium', 'os.system',
                    'app.py', 3, 'os.system(cmd)');
            """
        )

    db.init_db()
    assert db.backfill_fingerprints() == 1

    findings = db.get_findings("legacy", include_suppressed=True)
    assert len(findings) == 1
    assert findings[0].fingerprint
    assert findings[0].suppressed is False
    assert db.count_triage() == 0
