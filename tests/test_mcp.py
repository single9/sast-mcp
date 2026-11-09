"""MCP server 測試：本機打包、輸出格式化、API client 與工具行為。"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from sast_mcp import server
from sast_mcp.client import SastClient, SastError
from sast_mcp.config import reset_mcp_settings_cache
from sast_mcp.formatting import aggregate_findings, redact_snippet
from sast_mcp.local import LocalSourceError, create_source_zip


@pytest.fixture(autouse=True)
def isolated_mcp_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SAST_BASE_URL", "http://sast.test")
    monkeypatch.setenv("SAST_MCP_ALLOWED_ROOTS", "")
    monkeypatch.setenv("SAST_MCP_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("SAST_MAX_UPLOAD_MB", "5")
    monkeypatch.setenv("SAST_MAX_EXTRACT_MB", "10")
    monkeypatch.setenv("SAST_MAX_FILES", "100")
    monkeypatch.setenv("SAST_MAX_FILE_MB", "2")
    reset_mcp_settings_cache()
    yield
    reset_mcp_settings_cache()


@pytest.fixture()
def git_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git 不在 PATH")
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (repo / "src" / "extra.py").write_text("print('extra')\n", encoding="utf-8")
    (repo / "node_modules" / "pkg" / "index.js").write_text("module.exports=1\n", encoding="utf-8")
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    (repo / ".env").write_text("TOKEN=abc123456789\n", encoding="utf-8")
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (repo / "debug.log").write_text("ignored\n", encoding="utf-8")
    (repo / "link.py").symlink_to(repo / "src" / "app.py")

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
    subprocess.run(["git", "add", "src/app.py", "README.md", ".gitignore"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


def test_create_source_zip_is_git_aware(git_repo):
    archive = create_source_zip(git_repo)
    try:
        assert archive.git_aware is True
        assert archive.file_count == 5
        names = set(__import__("zipfile").ZipFile(archive.path).namelist())
        assert names == {".env", ".gitignore", "README.md", "src/app.py", "src/extra.py"}
        assert "node_modules/pkg/index.js" not in names
        assert "debug.log" not in names
        assert "link.py" not in names
        assert any(item["path"] == "link.py" for item in archive.skipped)
    finally:
        archive.cleanup()
    assert not archive.path.exists()


def test_create_source_zip_walks_non_git_directory(tmp_path):
    root = tmp_path / "plain"
    (root / "node_modules").mkdir(parents=True)
    (root / "app.py").write_text("print(1)\n", encoding="utf-8")
    (root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    (root / "image.png").write_bytes(b"\x89PNG")
    (root / "node_modules" / "x.js").write_text("x", encoding="utf-8")
    (root / "link.py").symlink_to(root / "app.py")

    archive = create_source_zip(root)
    try:
        assert archive.git_aware is False
        names = set(__import__("zipfile").ZipFile(archive.path).namelist())
        assert names == {"app.py", "Cargo.lock"}
    finally:
        archive.cleanup()


def test_create_source_zip_respects_allowed_roots(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "a.py").write_text("print(1)\n", encoding="utf-8")
    (outside / "b.py").write_text("print(2)\n", encoding="utf-8")
    monkeypatch.setenv("SAST_MCP_ALLOWED_ROOTS", str(allowed))
    reset_mcp_settings_cache()

    archive = create_source_zip(allowed)
    archive.cleanup()
    with pytest.raises(LocalSourceError, match="允許範圍"):
        create_source_zip(outside)


def test_redact_snippet_masks_common_secrets():
    text = (
        'PASSWORD = "hunter2"\n'
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        "token: ghp_abcdefghijklmnopqrstuvwxyz123456\n"
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
    )
    redacted = redact_snippet(text)
    assert "hunter2" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "***" in redacted


def test_aggregate_findings_groups_and_truncates():
    findings = [
        {"rule_id": "r1", "severity": "high", "message": "m1", "file": "a.py", "line": 1},
        {"rule_id": "r1", "severity": "high", "message": "m1", "file": "a.py", "line": 2},
        {"rule_id": "r2", "severity": "low", "message": "m2", "file": "b.py", "line": 3},
    ]
    summary = aggregate_findings(findings, top=1)
    assert summary["total_findings"] == 3
    assert summary["by_severity"] == {"high": 2, "low": 1}
    assert summary["by_engine"] == {"unknown": 3}
    assert summary["by_rule"][0]["rule_id"] == "r1"
    assert summary["by_rule"][0]["count"] == 2
    assert summary["omitted_rule_groups"] == 1
    assert summary["by_file"][0]["file"] == "a.py"


def test_aggregate_findings_includes_language_risk():
    findings = [
        {"rule_id": "py-high", "severity": "high", "message": "m1", "file": "src/app.py", "line": 1},
        {"rule_id": "js-critical", "severity": "critical", "message": "m2", "file": "web/app.js", "line": 2},
        {"rule_id": "other-medium", "severity": "medium", "message": "m3", "file": "notes.txt", "line": 3},
    ]
    summary = aggregate_findings(findings, top=2)

    by_language = {item["id"]: item for item in summary["by_language"]}
    # 沒有專案語言統計時，退回以風險最高的語言作為 primary。
    assert summary["primary_language"] == "javascript"
    assert by_language["javascript"]["risk_level"] == "critical"
    assert by_language["python"]["risk_level"] == "high"
    assert by_language["other"]["findings"] == 1
    assert summary["language_risk_levels"]["critical"] == 1


def test_client_requests_and_error_mapping():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path == "/health":
            return httpx.Response(200, json={"status": "ok", "engine": "semgrep"})
        if path == "/api/v1/scans" and request.method == "POST":
            if b"repo_url" in request.content:
                return httpx.Response(202, json={"id": "git-scan", "status": "queued"})
            return httpx.Response(202, json={"id": "zip-scan", "status": "queued"})
        if path.endswith("/findings"):
            return httpx.Response(200, json=[{"rule_id": "r1", "severity": "high"}])
        if path.endswith("/sarif"):
            return httpx.Response(200, json={"version": "2.1.0", "runs": []})
        return httpx.Response(400, json={"detail": "bad request"})

    async def run():
        transport = httpx.MockTransport(handler)
        async with SastClient(
            base_url="http://sast.test", api_key="secret", transport=transport
        ) as client:
            assert (await client.health())["status"] == "ok"
            assert (await client.create_scan_from_git("https://example.com/repo.git"))["id"] == "git-scan"
            findings = await client.fetch_findings("s1", severities=["high", "medium"])
            assert findings[0]["rule_id"] == "r1"
            assert (await client.get_sarif("s1"))["version"] == "2.1.0"
            with pytest.raises(SastError, match="bad request"):
                await client.get_scan("missing")

    asyncio.run(run())
    assert all(request.headers["x-api-key"] == "secret" for request in seen)
    findings_request = next(request for request in seen if request.url.path.endswith("/findings"))
    assert findings_request.url.params["severity"] == "high,medium"


def test_client_connection_error_has_start_hint():
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    async def run():
        async with SastClient(
            base_url="http://sast.test", transport=httpx.MockTransport(handler)
        ) as client:
            with pytest.raises(SastError, match="請先啟動服務"):
                await client.health()

    asyncio.run(run())


def test_tool_surface():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    expected = {
        "health",
        "scan_path",
        "scan_zip",
        "scan_git",
        "wait_for_scan",
        "get_scan",
        "list_scans",
        "get_findings",
        "summarize_scan",
        "export_sarif",
        "delete_scan",
        "triage_findings",
        "list_triage",
        "delete_triage",
        "export_triage",
        "import_triage",
    }
    assert expected <= set(tools)
    assert tools["scan_path"].inputSchema["properties"]["path"]["default"] == "."
    assert tools["get_findings"].inputSchema["properties"]["include_snippet"]["default"] is False


class FakeClient:
    base_url = "http://sast.test"

    def __init__(self, scan=None, findings=None, sarif=None, languages=None):
        self.languages = languages or {}
        self.scan = scan or {
            "id": "scan1",
            "status": "completed",
            "source_type": "zip",
            "source_ref": "source.zip",
            "engine": "semgrep",
            "stats": {"files_scanned": 2},
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        }
        self.findings = findings or []
        self.sarif = sarif or {"version": "2.1.0", "runs": []}
        self.uploaded_path: Path | None = None
        self.triage: dict[str, dict] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return None

    async def get_scan(self, _scan_id):
        return dict(self.scan)

    async def fetch_findings(self, _scan_id, severities=None, limit=5000, include_suppressed=True):
        findings = self.findings
        if not include_suppressed:
            findings = [f for f in findings if not f.get("suppressed")]
        if severities:
            return [f for f in findings if f.get("severity") in severities]
        return list(findings)

    async def get_languages(self, _scan_id):
        return dict(self.languages)

    async def get_sarif(self, _scan_id):
        return dict(self.sarif)

    async def create_scan_from_zip(self, path, filename=None):
        self.uploaded_path = Path(path)
        assert self.uploaded_path.exists()
        return dict(self.scan)

    async def delete_scan(self, _scan_id):
        return None

    async def bulk_triage(self, fingerprints, status, note=None, author=None):
        for fingerprint in fingerprints:
            finding = next(
                (f for f in self.findings if f.get("fingerprint") == fingerprint), {}
            )
            suppressed = status in {"false_positive", "accepted_risk", "wontfix"}
            self.triage[fingerprint] = {
                "fingerprint": fingerprint,
                "rule_id": finding.get("rule_id", ""),
                "file": finding.get("file", ""),
                "line": finding.get("line"),
                "status": status,
                "note": note,
                "author": author,
                "last_seen_scan_id": self.scan["id"],
            }
            for item in self.findings:
                if item.get("fingerprint") == fingerprint:
                    item["triage_status"] = status
                    item["triage_note"] = note
                    item["suppressed"] = suppressed
        return {"updated": len(fingerprints), "affected_scans": [self.scan["id"]]}

    async def list_triage(self, status=None, rule_id=None, file=None, limit=100, offset=0):
        records = list(self.triage.values())
        if status:
            records = [r for r in records if r["status"] == status]
        if rule_id:
            records = [r for r in records if rule_id.lower() in r["rule_id"].lower()]
        if file:
            records = [r for r in records if file.lower() in r["file"].lower()]
        return records[offset : offset + limit]

    async def delete_triage(self, fingerprint):
        self.triage.pop(fingerprint, None)
        for item in self.findings:
            if item.get("fingerprint") == fingerprint:
                item["triage_status"] = None
                item["triage_note"] = None
                item["suppressed"] = False

    async def export_triage(self):
        return {
            "version": 1,
            "exported_at": "2026-01-01T00:00:00Z",
            "records": list(self.triage.values()),
        }

    async def import_triage(self, records):
        for record in records:
            self.triage[record["fingerprint"]] = dict(record)
        return {"imported": len(records), "affected_scans": [self.scan["id"]]}


FINDINGS = [
    {
        "rule_id": "generic-hardcoded-secret",
        "severity": "high",
        "message": "hardcoded secret",
        "file": "src/app.py",
        "line": 3,
        "snippet": 'PASSWORD = "hunter2"',
    },
    {
        "rule_id": "builtin-python-os-system",
        "severity": "medium",
        "message": "os.system",
        "file": "src/run.py",
        "line": 8,
        "snippet": "os.system(cmd)",
    },
]


def test_get_findings_filters_and_hides_snippets(monkeypatch):
    monkeypatch.setattr(server, "_client", lambda: FakeClient(findings=FINDINGS))

    result = asyncio.run(
        server.get_findings("scan1", severity=["high"], file_contains="app", limit=10)
    )
    assert result["total_matched"] == 1
    assert result["returned"] == 1
    assert "snippet" not in result["findings"][0]
    assert result["findings"][0]["location"] == "src/app.py:3"

    with_snippet = asyncio.run(
        server.get_findings("scan1", severity=["high"], include_snippet=True, limit=10)
    )
    assert "hunter2" not in with_snippet["findings"][0]["snippet"]
    assert "***" in with_snippet["findings"][0]["snippet"]

    with pytest.raises(ToolError, match="無效的 severity"):
        asyncio.run(server.get_findings("scan1", severity=["bogus"]))


def test_summarize_scan_returns_groups(monkeypatch):
    monkeypatch.setattr(server, "_client", lambda: FakeClient(findings=FINDINGS))
    result = asyncio.run(server.summarize_scan("scan1", top=1))
    assert result["scan"]["id"] == "scan1"
    assert result["total_findings"] == 2
    assert result["by_rule"][0]["rule_id"] == "generic-hardcoded-secret"
    assert result["omitted_rule_groups"] == 1
    assert result["primary_language"] == "python"
    assert result["by_language"][0]["id"] == "python"
    assert result["by_language"][0]["findings"] == 2
    assert "dependencies" in result
    assert "supply_chain" in result


def test_summarize_scan_backfills_language_stats_for_old_scans(monkeypatch):
    fake = FakeClient(
        findings=FINDINGS,
        languages={
            "primary_language": "rust",
            "primary_language_name": "Rust",
            "languages": [
                {
                    "id": "rust",
                    "name": "Rust",
                    "category": "code",
                    "files": 1,
                    "lines": 2,
                    "bytes": 20,
                    "percent": 100.0,
                }
            ],
        },
    )
    monkeypatch.setattr(server, "_client", lambda: fake)

    result = asyncio.run(server.summarize_scan("scan1"))
    assert result["primary_language"] == "rust"
    assert result["scan"]["stats"]["languages"]["primary_language"] == "rust"
    assert any(item["id"] == "rust" for item in result["by_language"])


def test_scan_path_uploads_and_cleans_temp_zip(monkeypatch, tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    fake = FakeClient()
    monkeypatch.setattr(server, "_client", lambda: fake)

    result = asyncio.run(server.scan_path(str(source)))
    assert result["scan"]["id"] == "scan1"
    assert result["source"]["files"] == 1
    assert fake.uploaded_path is not None
    assert not fake.uploaded_path.exists()


def test_export_sarif_writes_file_and_refuses_overwrite(monkeypatch, tmp_path):
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "r1"}, {"id": "r2"}]}},
                "results": [{"ruleId": "r1"}],
            }
        ],
    }
    monkeypatch.setattr(server, "_client", lambda: FakeClient(sarif=sarif))
    target = tmp_path / "out.sarif"

    result = asyncio.run(server.export_sarif("scan1", output_path=str(target)))
    assert result["results"] == 1
    assert result["rule_count"] == 2
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"

    with pytest.raises(ToolError, match="檔案已存在"):
        asyncio.run(server.export_sarif("scan1", output_path=str(target), overwrite=False))

    asyncio.run(server.export_sarif("scan1", output_path=str(target), overwrite=True))


def test_delete_scan_requires_confirmation(monkeypatch):
    monkeypatch.setattr(server, "_client", lambda: FakeClient())
    with pytest.raises(ToolError, match="confirm=true"):
        asyncio.run(server.delete_scan("scan1", confirm=False))
    assert asyncio.run(server.delete_scan("scan1", confirm=True))["deleted"] is True


TRIAGE_FINDINGS = [
    {
        "rule_id": "generic-hardcoded-secret",
        "severity": "high",
        "message": "hardcoded secret",
        "file": "src/app.py",
        "line": 3,
        "fingerprint": "fp-high",
        "suppressed": False,
    },
    {
        "rule_id": "builtin-python-os-system",
        "severity": "medium",
        "message": "os.system",
        "file": "src/run.py",
        "line": 8,
        "fingerprint": "fp-medium",
        "suppressed": False,
    },
]


def test_triage_tools_suppress_and_roundtrip(monkeypatch, tmp_path):
    fake = FakeClient(findings=[dict(finding) for finding in TRIAGE_FINDINGS])
    monkeypatch.setattr(server, "_client", lambda: fake)

    result = asyncio.run(
        server.triage_findings(
            "scan1", ["fp-high"], "false_positive", note="固定字串", author="agent"
        )
    )
    assert result["status"] == "false_positive"
    assert result["updated"] == 1

    visible = asyncio.run(server.get_findings("scan1", limit=10))
    assert visible["total_matched"] == 1
    assert visible["suppressed_in_scan"] == 1

    hidden = asyncio.run(
        server.get_findings(
            "scan1",
            include_suppressed=True,
            triage_status=["false_positive"],
            limit=10,
        )
    )
    assert hidden["total_matched"] == 1
    assert hidden["findings"][0]["triage_status"] == "false_positive"

    summary = asyncio.run(server.summarize_scan("scan1"))
    assert summary["total_findings"] == 1
    assert summary["suppressed_findings"] == 1
    assert summary["include_suppressed"] is False

    listed = asyncio.run(server.list_triage())
    assert listed["returned"] == 1
    assert listed["records"][0]["fingerprint"] == "fp-high"

    target = tmp_path / "triage.json"
    exported = asyncio.run(server.export_triage(output_path=str(target)))
    assert exported["records"] == 1
    assert target.exists()

    asyncio.run(server.delete_triage("fp-high", confirm=True))
    assert asyncio.run(server.list_triage())["returned"] == 0

    imported = asyncio.run(server.import_triage(str(target)))
    assert imported["imported"] == 1
    assert asyncio.run(server.list_triage())["returned"] == 1


def test_triage_findings_rejects_unknown_fingerprint(monkeypatch):
    fake = FakeClient(findings=[dict(finding) for finding in TRIAGE_FINDINGS])
    monkeypatch.setattr(server, "_client", lambda: fake)

    with pytest.raises(ToolError, match="不在這個掃描"):
        asyncio.run(server.triage_findings("scan1", ["missing"], "false_positive"))


def test_triage_status_validation(monkeypatch):
    monkeypatch.setattr(server, "_client", lambda: FakeClient())

    with pytest.raises(ToolError, match="無效的 triage status"):
        asyncio.run(server.triage_findings("scan1", ["fp"], "bogus"))

    with pytest.raises(ToolError, match="無效的 triage status"):
        asyncio.run(server.get_findings("scan1", triage_status=["bogus"]))

    with pytest.raises(ToolError, match="confirm=true"):
        asyncio.run(server.delete_triage("fp", confirm=False))
