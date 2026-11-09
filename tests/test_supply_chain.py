"""Cargo 供應鏈檢查測試。"""

from __future__ import annotations

from app.config import reset_settings_cache
from app.supply_chain import scan_supply_chain

MANIFEST = """\
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
wild = "*"
gitdep = { git = "http://example.com/repo" }
pinned = { git = "https://example.com/repo", rev = "abc123" }
local = { path = "../outside" }

[patch.crates-io]
foo = { git = "https://example.com/foo" }
"""

CARGO_CONFIG = """\
[source.crates-io]
replace-with = "internal"

[registries.internal]
index = "http://insecure.example/index"

[target.x86_64-unknown-linux-gnu]
runner = "./run.sh"

[build]
rustflags = ["-C", "link-arg=-Wl,-rpath,/tmp"]
"""


def test_scan_supply_chain_reports_manifest_and_config_risks(tmp_path, monkeypatch):
    monkeypatch.setenv("SAST_SUPPLY_CHAIN_ENABLED", "true")
    reset_settings_cache()
    (tmp_path / "Cargo.toml").write_text(MANIFEST, encoding="utf-8")
    (tmp_path / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
    (tmp_path / ".cargo").mkdir()
    (tmp_path / ".cargo" / "config.toml").write_text(CARGO_CONFIG, encoding="utf-8")

    findings, warnings, stats = scan_supply_chain(tmp_path)
    rules = {finding.rule_id for finding in findings}

    assert warnings == []
    assert "supply-chain-build-script" in rules
    assert "supply-chain-wildcard-version" in rules
    assert "supply-chain-insecure-git" in rules
    assert "supply-chain-unpinned-git" in rules
    assert "supply-chain-path-outside" in rules
    assert "supply-chain-cargo-patch" in rules
    assert "supply-chain-missing-lockfile" in rules
    assert "supply-chain-source-replacement" in rules
    assert "supply-chain-insecure-registry" in rules
    assert "supply-chain-cargo-runner" in rules
    assert "supply-chain-custom-linker-args" in rules

    assert stats["manifests"] == 1
    assert stats["build_scripts"] == 1
    assert stats["cargo_configs"] == 1
    assert stats["findings"] == len(findings)

    # pinned git 依賴不應被標記
    unpinned = [f for f in findings if f.rule_id == "supply-chain-unpinned-git"]
    assert len(unpinned) == 1
    assert unpinned[0].line == 8


def test_scan_supply_chain_ignores_lockfile_when_present(tmp_path):
    (tmp_path / "Cargo.toml").write_text(MANIFEST, encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")

    findings, _warnings, stats = scan_supply_chain(tmp_path)
    assert all(f.rule_id != "supply-chain-missing-lockfile" for f in findings)
    assert stats["lockfiles"] == 1


def test_scan_supply_chain_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SAST_SUPPLY_CHAIN_ENABLED", "false")
    reset_settings_cache()
    (tmp_path / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

    findings, warnings, stats = scan_supply_chain(tmp_path)
    assert findings == []
    assert warnings == []
    assert stats["enabled"] is False


def test_scan_supply_chain_handles_invalid_manifest(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[dependencies\n", encoding="utf-8")

    findings, warnings, stats = scan_supply_chain(tmp_path)
    assert findings == []
    assert warnings and "Cargo.toml 解析失敗" in warnings[0]
    assert stats["manifests"] == 1
