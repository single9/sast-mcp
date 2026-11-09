"""基礎測試：API 建立掃描、finding 內容、錯誤處理、SARIF。"""

from __future__ import annotations

import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.config import reset_settings_cache
from app.main import app

VULNERABLE_PY = """\
import hashlib
import os
import yaml


def run(cmd):
    os.system(cmd)


def digest(data):
    return hashlib.md5(data).hexdigest()


def load(text):
    return yaml.load(text)


PASSWORD = "demo-password-value"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""

PRIVATE_KEY = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0000000000000000000000000000000000000000000000
-----END RSA PRIVATE KEY-----
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
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        scan = response.json()
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


def test_health(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["engine"] == "builtin-regex"


def test_zip_scan_completes_and_finds_issues(client: TestClient):
    scan = create_zip_scan(
        client,
        {
            "src/vulnerable.py": VULNERABLE_PY,
            "keys/server.pem": PRIVATE_KEY,
        },
    )
    assert scan["status"] == "completed", scan
    assert scan["engine"] == "builtin-regex"
    assert scan["stats"]["files_scanned"] >= 2
    assert scan["stats"]["findings"] >= 5

    language_stats = scan["stats"]["languages"]
    assert language_stats["primary_language"] == "python"
    assert language_stats["primary_language_name"] == "Python"
    assert language_stats["total_files"] >= 1
    assert any(item["id"] == "python" for item in language_stats["languages"])

    language_risk = scan["stats"]["language_risk"]
    python_risk = next(item for item in language_risk["languages"] if item["id"] == "python")
    assert python_risk["findings"] >= 5
    assert python_risk["risk_level"] in {"critical", "high"}
    assert python_risk["severity_counts"]["high"] >= 1

    languages = client.get(f"/api/v1/scans/{scan['id']}/languages").json()
    assert languages["scan_id"] == scan["id"]
    assert languages["status"] == "completed"
    assert languages["primary_language"] == "python"
    python_language = next(item for item in languages["languages"] if item["id"] == "python")
    assert python_language["findings"] >= 5
    assert python_language["risk_level"] in {"critical", "high"}
    assert python_language["severity_counts"]["high"] >= 1

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    rules = {finding["rule_id"] for finding in findings}

    assert "builtin-python-os-system" in rules
    assert "builtin-python-weak-hash" in rules
    assert "builtin-python-yaml-load" in rules
    assert "builtin-hardcoded-secret" in rules
    assert "builtin-private-key" in rules
    assert "builtin-aws-access-key" in rules

    os_system = next(f for f in findings if f["rule_id"] == "builtin-python-os-system")
    assert os_system["file"] == "src/vulnerable.py"
    assert os_system["line"] == 7
    assert os_system["cwe"] == ["CWE-78"]
    assert "os.system" in (os_system["snippet"] or "")

    high_only = client.get(f"/api/v1/scans/{scan['id']}/findings?severity=critical,high").json()
    assert high_only
    assert all(finding["severity"] in {"critical", "high"} for finding in high_only)


def test_rust_scan_includes_dependencies_and_supply_chain(client: TestClient):
    rust_source = """\
use std::process::Command;

fn run(cmd: &str, path: &str) {
    Command::new("sh").arg("-c").arg(cmd).spawn();
    let _ = md5::compute(b"x");
    let _ = NamedFile::open(path);
    unsafe { let _ = 1; }
}
"""
    cargo_toml = """\
[package]
name = "demo"
version = "0.1.0"

[dependencies]
foo = { git = "https://example.com/repo" }
"""
    cargo_lock = """\
version = 3

[[package]]
name = "demo"
version = "0.1.0"
"""
    scan = create_zip_scan(
        client,
        {
            "src/main.rs": rust_source,
            "Cargo.toml": cargo_toml,
            "Cargo.lock": cargo_lock,
            "build.rs": "fn main() {}\n",
        },
    )
    assert scan["status"] == "completed", scan

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    rules = {finding["rule_id"] for finding in findings}
    assert "builtin-rust-shell-command" in rules
    assert "builtin-rust-weak-hash" in rules
    assert "builtin-rust-path-traversal" in rules
    assert "builtin-rust-unsafe" in rules
    assert "supply-chain-build-script" in rules
    assert "supply-chain-unpinned-git" in rules

    stats = scan["stats"]
    assert stats["dependencies"]["enabled"] is False
    assert stats["supply_chain"]["manifests"] == 1
    assert stats["supply_chain"]["build_scripts"] == 1
    assert stats["primary_language"] == "rust"

    ui = client.get(f"/ui/scans/{scan['id']}")
    assert ui.status_code == 200
    assert "依賴與供應鏈" in ui.text
    assert "Rust" in ui.text


def test_findings_can_be_filtered_by_severity_validation(client: TestClient):
    scan = create_zip_scan(client, {"src/vulnerable.py": VULNERABLE_PY})
    response = client.get(f"/api/v1/scans/{scan['id']}/findings?severity=bogus")
    assert response.status_code == 400


def test_sarif_export(client: TestClient):
    scan = create_zip_scan(client, {"src/vulnerable.py": VULNERABLE_PY})
    response = client.get(f"/api/v1/scans/{scan['id']}/sarif")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")

    sarif = response.json()
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "sast-service"
    assert run["results"]
    assert run["properties"]["scanId"] == scan["id"]
    assert run["properties"]["primaryLanguage"] == "python"
    assert run["properties"]["languages"]
    assert run["properties"]["languageRisk"]
    assert "dependencies" in run["properties"]
    assert "supplyChain" in run["properties"]
    first = run["results"][0]
    assert first["ruleId"]
    assert first["properties"]["language"] == "python"
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_rejects_zip_slip(client: TestClient):
    payload = make_zip({"../escaped.py": "print('nope')"})
    response = client.post(
        "/api/v1/scans",
        files={"file": ("evil.zip", payload, "application/zip")},
    )
    assert response.status_code == 400
    assert "zip slip" in response.json()["detail"].lower()
    assert client.get("/api/v1/scans").json() == []


def test_rejects_non_zip_upload(client: TestClient):
    response = client.post(
        "/api/v1/scans",
        files={"file": ("notes.txt", b"hello world", "text/plain")},
    )
    assert response.status_code == 400

    response = client.post(
        "/api/v1/scans",
        files={"file": ("fake.zip", b"this is not a zip", "application/zip")},
    )
    assert response.status_code == 400


def test_requires_file_or_repo_url(client: TestClient):
    response = client.post("/api/v1/scans", data={})
    assert response.status_code == 400


def test_repo_url_is_checked(client: TestClient, monkeypatch):
    monkeypatch.setenv("SAST_ALLOW_GIT_SOURCES", "true")
    reset_settings_cache()

    response = client.post("/api/v1/scans", data={"repo_url": "http://127.0.0.1/repo.git"})
    assert response.status_code == 400

    response = client.post("/api/v1/scans", data={"repo_url": "file:///etc/passwd"})
    assert response.status_code == 400


def test_api_key_enforcement(client: TestClient, monkeypatch):
    monkeypatch.setenv("SAST_API_KEY", "secret-key")
    reset_settings_cache()

    assert client.get("/api/v1/scans").status_code == 401
    response = client.get("/api/v1/scans", headers={"X-API-Key": "secret-key"})
    assert response.status_code == 200

    # UI 與健康檢查不受 API key 保護（適合放在反向代理後）
    assert client.get("/health").status_code == 200


def test_ui_pages_render(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "建立掃描" in response.text

    scan = create_zip_scan(client, {"src/vulnerable.py": VULNERABLE_PY})
    detail = client.get(f"/ui/scans/{scan['id']}")
    assert detail.status_code == 200
    assert "builtin-python-os-system" in detail.text
    assert "專案語言與風險" in detail.text
    assert "Python" in detail.text


def test_dataflow_roundtrip_and_sarif():
    from app.db import add_findings, create_scan, get_findings, get_scan, init_db
    from app.models import DataflowStep, Finding
    from app.sarif import scan_to_sarif

    init_db()
    create_scan("scan-dataflow", "zip", "source.zip")
    finding = Finding(
        rule_id="python-taint-command-injection",
        severity="high",
        message="command injection",
        file="src/app.py",
        line=5,
        cwe=["CWE-78"],
        engine="semgrep",
        dataflow=[
            DataflowStep(role="source", file="src/app.py", line=1, code="name = input()"),
            DataflowStep(role="propagator", file="src/app.py", line=3, code="cmd = 'echo ' + name"),
            DataflowStep(role="sink", file="src/app.py", line=5, code="os.system(cmd)"),
        ],
    )
    add_findings("scan-dataflow", [finding])

    loaded = get_findings("scan-dataflow")
    assert len(loaded) == 1
    assert [step.role for step in loaded[0].dataflow] == ["source", "propagator", "sink"]
    assert loaded[0].dataflow[-1].code == "os.system(cmd)"

    scan = get_scan("scan-dataflow")
    sarif = scan_to_sarif(scan, loaded)
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["dataflowSteps"] == 3
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [loc["location"]["physicalLocation"]["region"]["startLine"] for loc in locations] == [1, 3, 5]
    assert "sink: os.system(cmd)" in locations[-1]["location"]["message"]["text"]
