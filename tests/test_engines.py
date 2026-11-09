"""直接測試兩個引擎的解析與規則行為。"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app.engines.regex_engine import RegexEngine
from app.engines.semgrep_engine import SemgrepEngine, extract_cwes


def test_extract_cwes_handles_strings_and_lists():
    assert extract_cwes("CWE-79: XSS") == ["CWE-79"]
    assert extract_cwes(["CWE-78: cmd", "cwe-89"]) == ["CWE-78", "CWE-89"]
    assert extract_cwes(None) == []


def test_regex_engine_skips_dependencies_and_binaries(tmp_path):
    (tmp_path / "app.py").write_text("import os\nos.system('id')\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendor.js").write_text("eval('x')\n", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"\x89PNG\x00\x00")

    result = RegexEngine().scan(tmp_path, timeout=30)
    files = {finding.file for finding in result.findings}
    assert "app.py" in files
    assert not any("node_modules" in path for path in files)
    assert result.files_scanned == 1


def test_regex_engine_does_not_flag_environment_lookup(tmp_path):
    (tmp_path / "config.py").write_text(
        "import os\npassword = os.environ['PASSWORD']\n", encoding="utf-8"
    )
    result = RegexEngine().scan(tmp_path, timeout=30)
    assert all(finding.rule_id != "builtin-hardcoded-secret" for finding in result.findings)


def test_regex_engine_covers_rust(tmp_path):
    source = """\
use std::process::Command;

fn demo(ptr: *const u8, len: usize, values: &[u8], path: &str, id: u64, token: &str) {
    Command::new("sh").arg("-c").arg("id").spawn();
    let _ = builder.danger_accept_invalid_certs(true);
    let _ = md5::compute(b"x");
    let _ = format!("SELECT * FROM users WHERE id = {}", id);
    unsafe { let _ = 1; }
    let _: u64 = std::mem::transmute(1u32);
    let _ = std::slice::from_raw_parts(ptr, len);
    let _ = values.get_unchecked(0);
    let _ = NamedFile::open(path);
    println!("token={}", token);
    let _ = CorsLayer::permissive();
}
"""
    (tmp_path / "main.rs").write_text(source, encoding="utf-8")

    result = RegexEngine().scan(tmp_path, timeout=30)
    rules = {finding.rule_id for finding in result.findings}
    assert result.files_scanned == 1
    assert {
        "builtin-rust-shell-command",
        "builtin-rust-insecure-tls",
        "builtin-rust-weak-hash",
        "builtin-rust-sql-format",
        "builtin-rust-unsafe",
        "builtin-rust-transmute",
        "builtin-rust-from-raw-parts",
        "builtin-rust-get-unchecked",
        "builtin-rust-path-traversal",
        "builtin-rust-secret-logged",
        "builtin-rust-permissive-cors",
    } <= rules


def test_semgrep_engine_parses_json(monkeypatch, tmp_path):
    """以假 semgrep 執行檔驗證輸出轉換，不需要真的安裝 Semgrep。"""
    from app.config import reset_settings_cache

    fake = tmp_path / "fake-semgrep"
    (tmp_path / "app.py").write_text(
        "value = 1\nvalue = 2\neval(user_input)\n", encoding="utf-8"
    )
    payload = {
        "results": [
            {
                "check_id": "python-eval",
                "path": "app.py",
                "start": {"line": 3, "col": 5},
                "end": {"line": 3, "col": 12},
                "extra": {
                    "message": "使用 eval()",
                    "severity": "ERROR",
                    "lines": "requires login",
                    "metadata": {"cwe": ["CWE-95: Improper Neutralization"]},
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": ["app.py"]},
    }
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('1.99.0')\n"
        "    raise SystemExit(0)\n"
        f"print({json.dumps(json.dumps(payload))})\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    monkeypatch.setenv("SAST_SEMGREP_BIN", str(fake))
    reset_settings_cache()
    try:
        from app.engines.semgrep_engine import SemgrepEngine

        engine = SemgrepEngine()
        assert engine.available()
        assert engine.version() == "1.99.0"

        result = engine.scan(tmp_path, timeout=30)
        assert result.files_scanned == 1
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_id == "python-eval"
        assert finding.severity == "high"
        assert finding.line == 3
        assert finding.cwe == ["CWE-95"]
        # 即使 Semgrep 的 extra.lines 被替換成 "requires login"，也要從原始碼補回片段
        assert finding.snippet == "eval(user_input)"
    finally:
        reset_settings_cache()


def test_settings_parse_extra_semgrep_configs(monkeypatch):
    from app.config import get_settings, reset_settings_cache

    monkeypatch.setenv("SAST_SEMGREP_EXTRA_CONFIGS", " p/rust, ,p/secrets,p/rust ")
    reset_settings_cache()
    try:
        assert get_settings().semgrep_extra_configs == ("p/rust", "p/secrets")
    finally:
        reset_settings_cache()


def test_semgrep_engine_passes_extra_configs(monkeypatch, tmp_path):
    """主規則集與額外規則集都要以 --config 傳給 Semgrep。"""
    from app.config import reset_settings_cache

    argv_file = tmp_path / "argv.json"
    fake = tmp_path / "fake-semgrep"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('1.99.0')\n"
        "    raise SystemExit(0)\n"
        "with open(os.environ['FAKE_ARGV_FILE'], 'w', encoding='utf-8') as f:\n"
        "    json.dump(sys.argv, f)\n"
        "print(json.dumps({'results': [], 'errors': [], 'paths': {'scanned': []}}))\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    extra_rules = tmp_path / "extra.yml"
    extra_rules.write_text("rules: []\n", encoding="utf-8")

    monkeypatch.setenv("SAST_SEMGREP_BIN", str(fake))
    monkeypatch.setenv("SAST_SEMGREP_EXTRA_CONFIGS", f"p/rust,{extra_rules}")
    monkeypatch.setenv("FAKE_ARGV_FILE", str(argv_file))
    reset_settings_cache()
    try:
        result = SemgrepEngine().scan(tmp_path, timeout=30)
    finally:
        reset_settings_cache()

    assert result.findings == []
    argv = json.loads(argv_file.read_text(encoding="utf-8"))
    configs = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--config"]
    assert configs[0].endswith("app/rules")
    assert configs[1:] == ["p/rust", str(extra_rules)]


def test_semgrep_engine_falls_back_when_extra_config_fails(monkeypatch, tmp_path):
    """額外規則集下載失敗時，仍套用主規則集完成掃描並留下 warning。"""
    from app.config import reset_settings_cache

    fake = tmp_path / "fake-semgrep"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('1.99.0')\n"
        "    raise SystemExit(0)\n"
        "if 'p/broken' in sys.argv:\n"
        "    print('failed to download p/broken', file=sys.stderr)\n"
        "    raise SystemExit(2)\n"
        "print(json.dumps({'results': [], 'errors': [], 'paths': {'scanned': []}}))\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    monkeypatch.setenv("SAST_SEMGREP_BIN", str(fake))
    monkeypatch.setenv("SAST_SEMGREP_EXTRA_CONFIGS", "p/broken")
    reset_settings_cache()
    try:
        result = SemgrepEngine().scan(tmp_path, timeout=30)
    finally:
        reset_settings_cache()

    assert result.findings == []
    assert any("額外規則集載入失敗" in warning for warning in result.errors)


def test_builtin_rust_rules_detect_patterns(monkeypatch, tmp_path):
    """用真的 Semgrep 驗證內建 Rust 規則；沒有 Semgrep 時跳過。"""
    from app.config import reset_settings_cache

    semgrep = shutil.which("semgrep")
    if not semgrep:
        candidate = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "semgrep"
        semgrep = str(candidate) if candidate.exists() else None
    if not semgrep:
        pytest.skip("semgrep 未安裝")

    (tmp_path / "vuln.rs").write_text(
        "use std::process::Command;\n"
        "fn main() {\n"
        "    Command::new(\"sh\").arg(\"-c\").arg(\"id\").status().unwrap();\n"
        "    let _ = md5::compute(b\"abc\");\n"
        "    let _ = Sha1::new();\n"
        "    let _ = reqwest::Client::builder().danger_accept_invalid_certs(true).build();\n"
        "    let table = \"orders\";\n"
        "    let _sql = format!(\"SELECT data FROM {table}\");\n"
        "    let token = \"abc\";\n"
        "    println!(\"token: {token}\");\n"
        "    let _ = CorsLayer::permissive();\n"
        "    unsafe { let p = 1 as *const i32; let _ = *p; }\n"
        "}\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("SAST_SEMGREP_BIN", semgrep)
    reset_settings_cache()
    try:
        result = SemgrepEngine().scan(tmp_path, timeout=60)
    finally:
        reset_settings_cache()

    rule_ids = {finding.rule_id for finding in result.findings}
    assert {
        "rust-shell-command",
        "rust-insecure-tls",
        "rust-weak-hash",
        "rust-sql-format",
        "rust-secret-logged",
        "rust-permissive-cors",
        "rust-unsafe-block",
    } <= rule_ids



def test_parse_json_dataflow_trace(tmp_path):
    from app.engines.semgrep_engine import _parse_json_dataflow

    (tmp_path / "app.py").write_text(
        "user = request.args.get('name')\ncmd = 'echo ' + user\nos.system(cmd)\n",
        encoding="utf-8",
    )
    trace = {
        "taint_source": [
            "CliLoc",
            [
                {
                    "path": "app.py",
                    "start": {"line": 1, "col": 8},
                    "end": {"line": 1, "col": 34},
                },
                "request.args.get('name')",
            ],
        ],
        "intermediate_vars": [
            {
                "location": {
                    "path": "app.py",
                    "start": {"line": 2, "col": 1},
                    "end": {"line": 2, "col": 4},
                },
                "content": "cmd",
            }
        ],
        "taint_sink": [
            "CliLoc",
            [
                {
                    "path": "app.py",
                    "start": {"line": 3, "col": 11},
                    "end": {"line": 3, "col": 14},
                },
                "cmd",
            ],
        ],
    }

    steps = _parse_json_dataflow(trace, tmp_path)

    assert [step.role for step in steps] == ["source", "propagator", "sink"]
    assert [step.line for step in steps] == [1, 2, 3]
    assert steps[0].code == "request.args.get('name')"
    assert steps[1].code == "cmd"
    assert steps[2].file == "app.py"


def test_parse_text_dataflow_output(tmp_path):
    from app.engines.semgrep_engine import _parse_text_dataflow

    (tmp_path / "app.py").write_text("x\n", encoding="utf-8")
    output = """\
    app.py
   ❯❯❱ python-taint-command-injection
          ❰❰ Blocking ❱❱
          message

            4┆ user = request.args.get("name")
            5┆ cmd = "echo " + user
            6┆ os.system(cmd)

          Taint comes from:

            4┆ user = request.args.get("name")

          Taint flows through these intermediate variables:

            5┆ cmd = "echo " + user

                This is how taint reaches the sink:

            6┆ os.system(cmd)

            ⋮┆----------------------------------------
"""
    traces = _parse_text_dataflow(output, tmp_path)

    steps = traces[("python-taint-command-injection", "app.py", 6)]
    assert [step.role for step in steps] == ["source", "propagator", "sink"]
    assert [step.line for step in steps] == [4, 5, 6]
    assert steps[-1].code == "os.system(cmd)"


def test_semgrep_engine_backfills_dataflow_from_text_output(monkeypatch, tmp_path):
    """JSON 沒有 dataflow_trace 時，要用 --text --dataflow-traces 補上。"""
    from app.config import reset_settings_cache

    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\nname = request.args.get('name')\nos.system('echo ' + name)\n",
        encoding="utf-8",
    )
    payload = {
        "results": [
            {
                "check_id": "python-taint-command-injection",
                "path": "app.py",
                "start": {"line": 4, "col": 1},
                "end": {"line": 4, "col": 28},
                "extra": {"message": "command injection", "severity": "ERROR"},
            }
        ],
        "errors": [],
        "paths": {"scanned": ["app.py"]},
    }
    text_output = """\
    app.py
   ❯❯❱ python-taint-command-injection
          ❰❰ Blocking ❱❱
          command injection

          Taint comes from:

            3┆ name = request.args.get('name')

                This is how taint reaches the sink:

            4┆ os.system('echo ' + name)

            ⋮┆----------------------------------------
"""
    fake = tmp_path / "fake-semgrep"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('1.99.0')\n"
        "    raise SystemExit(0)\n"
        "if '--text' in sys.argv:\n"
        f"    print({text_output!r})\n"
        "    raise SystemExit(0)\n"
        f"print({json.dumps(json.dumps(payload))})\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)

    monkeypatch.setenv("SAST_SEMGREP_BIN", str(fake))
    monkeypatch.setenv("SAST_DATAFLOW_TRACES", "true")
    reset_settings_cache()
    try:
        result = SemgrepEngine().scan(tmp_path, timeout=30)
    finally:
        reset_settings_cache()

    assert len(result.findings) == 1
    steps = result.findings[0].dataflow
    assert [step.role for step in steps] == ["source", "sink"]
    assert [step.line for step in steps] == [3, 4]
    assert steps[0].code == "name = request.args.get('name')"


def test_parse_text_dataflow_handles_multiple_files(tmp_path):
    """每個檔案的最後一筆 finding 不會印 ⋮┆，仍要正確切換檔案。"""
    from app.engines.semgrep_engine import _parse_text_dataflow

    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("x\n", encoding="utf-8")
    output = """\
    a.py
   ❯❯❱ python-taint-command-injection
          ❰❰ Blocking ❱❱
          message

          Taint comes from:

            2┆ name = input()

                This is how taint reaches the sink:

            3┆ os.system(name)

    b.py
   ❯❯❱ python-taint-sql-injection
          ❰❰ Blocking ❱❱
          message

          Taint comes from:

            5┆ name = input()

                This is how taint reaches the sink:

            6┆ cur.execute(name)
"""
    traces = _parse_text_dataflow(output, tmp_path)

    assert ("python-taint-command-injection", "a.py", 3) in traces
    assert ("python-taint-sql-injection", "b.py", 6) in traces
