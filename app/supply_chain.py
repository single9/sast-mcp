"""Cargo 供應鏈檢查：建置腳本、registry 覆寫、依賴 pin 與 lockfile。

這些檢查是確定性的檔案／manifest 分析，不需要 Rust toolchain，也不依賴
Semgrep 規則。發現的問題多為 low/medium，重點是讓 Agent 知道有哪些供應鏈
面需要人工確認。
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Iterator

from .config import EXCLUDE_DIRS, get_settings
from .models import Finding, count_by_severity

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

_DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}


def _iter_files(root: Path, name: str) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        if name in filenames:
            path = Path(dirpath) / name
            if not path.is_symlink():
                yield path


def _iter_cargo_configs(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        if Path(dirpath).name != ".cargo":
            continue
        for name in ("config.toml", "config"):
            if name in filenames:
                path = Path(dirpath) / name
                if not path.is_symlink():
                    yield path


def _line_of(text: str, pattern: str, *, start: int = 0) -> int | None:
    match = re.search(pattern, text[start:], re.MULTILINE)
    if not match:
        return None
    return text.count("\n", 0, start + match.start()) + 1


def _finding(
    rule_id: str,
    severity: str,
    message: str,
    file: str,
    line: int | None,
    cwe: tuple[str, ...],
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        message=message,
        file=file,
        line=line,
        cwe=list(cwe),
        engine="supply-chain",
    )


def _walk_tables(
    data: dict[str, Any], prefix: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    for key, value in data.items():
        if isinstance(value, dict):
            path = prefix + (str(key),)
            yield path, value
            yield from _walk_tables(value, path)


def _dependency_entries(data: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    for path, table in _walk_tables(data):
        if not path or path[-1] not in _DEPENDENCY_TABLES:
            continue
        for name, spec in table.items():
            yield str(name), spec


def _check_manifest(
    root: Path, manifest: Path, lockfiles: set[Path]
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    relative = str(manifest.relative_to(root))
    try:
        text = manifest.read_text(encoding="utf-8", errors="ignore")
        data = tomllib.loads(text)
    except (OSError, ValueError) as exc:
        warnings.append(f"Cargo.toml 解析失敗：{relative}: {exc}")
        return findings, warnings

    if "patch" in data:
        findings.append(
            _finding(
                "supply-chain-cargo-patch",
                "medium",
                "Cargo [patch] 會覆寫依賴來源；請確認被替換的 crate 與來源可信。",
                relative,
                _line_of(text, r"^\s*\[patch"),
                ("CWE-829",),
            )
        )

    for name, spec in _dependency_entries(data):
        line = _line_of(text, rf"^\s*{re.escape(name)}\s*=")
        if isinstance(spec, str):
            if spec.strip() == "*":
                findings.append(
                    _finding(
                        "supply-chain-wildcard-version",
                        "low",
                        f"依賴 {name} 使用萬用版本 '*'，可能拉入不相容或惡意版本。",
                        relative,
                        line,
                        ("CWE-829",),
                    )
                )
            continue

        if not isinstance(spec, dict):
            continue

        git = spec.get("git")
        if git:
            git_text = str(git)
            if git_text.lower().startswith("http://"):
                findings.append(
                    _finding(
                        "supply-chain-insecure-git",
                        "high",
                        f"依賴 {name} 以明文 HTTP 取得 git 來源，可能遭中間人竄改。",
                        relative,
                        line,
                        ("CWE-319",),
                    )
                )
            if not any(spec.get(key) for key in ("rev", "tag", "branch")):
                findings.append(
                    _finding(
                        "supply-chain-unpinned-git",
                        "medium",
                        f"git 依賴 {name} 未 pin rev/tag/branch，遠端內容變動會直接進入建置。",
                        relative,
                        line,
                        ("CWE-829",),
                    )
                )

        path = spec.get("path")
        if path and ".." in Path(str(path)).parts:
            findings.append(
                _finding(
                    "supply-chain-path-outside",
                    "medium",
                    f"依賴 {name} 的 path 指向專案外（{path}），可能載入未受控程式碼。",
                    relative,
                    line,
                    ("CWE-829",),
                )
            )

        version = spec.get("version")
        if version is not None and str(version).strip() == "*":
            findings.append(
                _finding(
                    "supply-chain-wildcard-version",
                    "low",
                    f"依賴 {name} 使用萬用版本 '*'，可能拉入不相容或惡意版本。",
                    relative,
                    line,
                    ("CWE-829",),
                )
            )

    if (manifest.parent / "Cargo.lock") not in lockfiles and (root / "Cargo.lock") not in lockfiles:
        findings.append(
            _finding(
                "supply-chain-missing-lockfile",
                "info",
                "Cargo.toml 旁沒有 Cargo.lock；建置不可重現，也無法檢查鎖定的套件版本。",
                relative,
                _line_of(text, r"^\s*\[package\]"),
                ("CWE-829",),
            )
        )
    return findings, warnings


def _check_cargo_config(root: Path, config: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    relative = str(config.relative_to(root))
    try:
        text = config.read_text(encoding="utf-8", errors="ignore")
        tomllib.loads(text)
    except (OSError, ValueError) as exc:
        warnings.append(f".cargo 設定解析失敗：{relative}: {exc}")
        return findings, warnings

    if re.search(r"^\s*replace-with\s*=", text, re.MULTILINE):
        findings.append(
            _finding(
                "supply-chain-source-replacement",
                "high",
                "Cargo source replacement 會把依賴導向其他 registry／目錄；請確認未被惡意覆寫。",
                relative,
                _line_of(text, r"^\s*replace-with\s*="),
                ("CWE-494",),
            )
        )

    if re.search(r"^\s*runner\s*=", text, re.MULTILINE):
        findings.append(
            _finding(
                "supply-chain-cargo-runner",
                "medium",
                "自訂 cargo runner 會在測試／執行時呼叫任意程式；請確認指令與來源可信。",
                relative,
                _line_of(text, r"^\s*runner\s*="),
                ("CWE-829",),
            )
        )

    if re.search(r"(?:registry|index)\s*=\s*[\"']http://", text, re.IGNORECASE):
        findings.append(
            _finding(
                "supply-chain-insecure-registry",
                "high",
                "Cargo registry 使用明文 HTTP，下載的 crate 可能遭中間人竄改。",
                relative,
                _line_of(text, r"(?:registry|index)\s*=\s*[\"']http://"),
                ("CWE-319",),
            )
        )

    if re.search(r"rustflags", text) and re.search(r"link-arg", text):
        findings.append(
            _finding(
                "supply-chain-custom-linker-args",
                "low",
                "rustflags 含自訂 linker 參數；請確認沒有載入未受控的函式庫或物件檔。",
                relative,
                _line_of(text, r"^\s*rustflags\s*="),
                ("CWE-829",),
            )
        )

    return findings, warnings


def scan_supply_chain(
    root: Path,
) -> tuple[list[Finding], list[str], dict[str, Any]]:
    """檢查 Cargo 供應鏈設定，回傳 findings、warnings 與統計。"""

    settings = get_settings()
    stats: dict[str, Any] = {"enabled": settings.supply_chain_enabled}
    if not settings.supply_chain_enabled:
        return [], [], stats

    warnings: list[str] = []
    findings: list[Finding] = []

    manifests = list(_iter_files(root, "Cargo.toml"))
    configs = list(_iter_cargo_configs(root))
    lockfiles = set(_iter_files(root, "Cargo.lock"))
    build_scripts = list(_iter_files(root, "build.rs"))

    for script in build_scripts:
        findings.append(
            _finding(
                "supply-chain-build-script",
                "low",
                "build.rs 會在編譯時執行任意程式碼；請確認內容，並避免在不受信任的環境建置。",
                str(script.relative_to(root)),
                1,
                ("CWE-829",),
            )
        )

    for manifest in manifests:
        found, found_warnings = _check_manifest(root, manifest, lockfiles)
        findings.extend(found)
        warnings.extend(found_warnings)

    for config in configs:
        found, found_warnings = _check_cargo_config(root, config)
        findings.extend(found)
        warnings.extend(found_warnings)

    stats.update(
        {
            "manifests": len(manifests),
            "cargo_configs": len(configs),
            "lockfiles": len(lockfiles),
            "build_scripts": len(build_scripts),
            "findings": len(findings),
            "by_severity": count_by_severity(findings),
        }
    )
    return findings, warnings, stats
