"""Semgrep 引擎：呼叫 semgrep CLI 並把 JSON 輸出轉成正規化 findings。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from ..config import EXCLUDE_DIRS, get_settings
from ..errors import EngineError
from ..models import Finding, normalize_severity
from .base import Engine, EngineResult

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_MAX_SNIPPET = 500


def extract_cwes(value) -> list[str]:
    if not value:
        return []
    items = value if isinstance(value, list) else [value]
    found: list[str] = []
    for item in items:
        for match in _CWE_RE.findall(str(item)):
            cwe = match.upper()
            if cwe not in found:
                found.append(cwe)
    return found


def _trim(text: str | None) -> str | None:
    if not text:
        return None
    text = text.strip()
    if len(text) > _MAX_SNIPPET:
        text = text[:_MAX_SNIPPET] + "…"
    return text


def _read_snippet(root: Path, rel_path: str, line: int | None, end_line: int | None) -> str | None:
    """直接從工作區讀取片段。

    新版 Semgrep 會把 JSON 的 extra.lines 換成 "requires login"，
    因此不依賴它；同時確保路徑不會跳出掃描根目錄。
    """
    if not line:
        return None
    try:
        root_resolved = root.resolve()
        target = (root / rel_path).resolve()
        if target != root_resolved and root_resolved not in target.parents:
            return None
        with target.open("r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except (OSError, ValueError):
        return None

    if line > len(lines):
        return None
    stop = end_line if end_line and end_line >= line else line
    stop = min(stop, line + 3, len(lines))
    return _trim("".join(lines[line - 1 : stop]))


class SemgrepEngine(Engine):
    name = "semgrep"
    description = "Semgrep OSS 規則引擎（語意比對，建議安裝）"

    def __init__(self) -> None:
        self._version: str | None = None

    def available(self) -> bool:
        return shutil.which(get_settings().semgrep_bin) is not None

    def version(self) -> str | None:
        if self._version is None:
            if not self.available():
                return None
            try:
                proc = subprocess.run(
                    [get_settings().semgrep_bin, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self._version = (proc.stdout or "").strip() or "unknown"
            except (OSError, subprocess.SubprocessError):
                self._version = "unknown"
        return self._version

    def scan(self, root: Path, timeout: int) -> EngineResult:
        settings = get_settings()
        primary = settings.semgrep_config or str(settings.rules_dir)
        configs: list[str] = []
        for config in (primary, *settings.semgrep_extra_configs):
            if config not in configs:
                configs.append(config)
        for config in configs:
            if not config.startswith(("p/", "r/")) and not Path(config).exists():
                raise EngineError(f"Semgrep 規則設定不存在：{config}")

        base_cmd = [
            settings.semgrep_bin,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--timeout",
            str(max(10, min(timeout, 120))),
            "--max-target-bytes",
            "2000000",
        ]

        def build_cmd(active: list[str]) -> list[str]:
            cmd = list(base_cmd)
            for config in active:
                cmd.extend(["--config", config])
            for directory in sorted(EXCLUDE_DIRS):
                cmd.extend(["--exclude", directory])
            cmd.append(".")
            return cmd

        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"

        # 額外規則集（例如 registry pack）可能因離線或下載失敗而讓整個掃描失敗；
        # 此時退回主規則集，並在結果 warnings 中留下原因。
        attempts = [configs]
        if len(configs) > 1:
            attempts.append(configs[:1])

        fallback_note: str | None = None
        proc: subprocess.CompletedProcess[str] | None = None
        for index, active in enumerate(attempts):
            try:
                proc = subprocess.run(
                    build_cmd(active),
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                raise EngineError(f"Semgrep 掃描逾時（{timeout + 60} 秒）") from exc
            except OSError as exc:
                raise EngineError(f"無法執行 Semgrep：{exc}") from exc

            # Semgrep: 0 = 無發現, 1 = 有發現
            if proc.returncode in (0, 1):
                break
            stderr = (proc.stderr or "").strip()[:500]
            if index + 1 < len(attempts):
                reason = stderr or f"exit {proc.returncode}"
                fallback_note = f"額外規則集載入失敗，已改用主規則集：{reason[:200]}"
                continue
            raise EngineError(f"Semgrep 執行失敗（exit {proc.returncode}）：{stderr}")

        if proc is None:
            raise EngineError("Semgrep 未產生任何結果")

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise EngineError("無法解析 Semgrep JSON 輸出") from exc

        findings: list[Finding] = []
        seen: set[tuple[str, str, int | None]] = set()
        for item in data.get("results", []):
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            start = item.get("start") or {}
            end = item.get("end") or {}
            path = str(item.get("path") or "").replace(os.sep, "/")
            if os.path.isabs(path):
                path = os.path.relpath(path, root).replace(os.sep, "/")

            snippet = _read_snippet(root, path, start.get("line"), end.get("line"))
            if snippet is None:
                raw_lines = extra.get("lines")
                if raw_lines and raw_lines.strip().lower() != "requires login":
                    snippet = _trim(raw_lines)

            finding = Finding(
                rule_id=str(item.get("check_id") or "unknown"),
                severity=normalize_severity(extra.get("severity")),
                message=str(extra.get("message") or item.get("check_id") or ""),
                file=path,
                line=start.get("line"),
                end_line=end.get("line"),
                column=start.get("col"),
                cwe=extract_cwes(metadata.get("cwe")),
                engine=self.name,
                snippet=snippet,
            )
            key = (finding.rule_id, finding.file, finding.line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

        errors = [fallback_note] if fallback_note else []
        for error in data.get("errors", []):
            message = error.get("message") if isinstance(error, dict) else str(error)
            if message:
                errors.append(str(message)[:300])

        paths = data.get("paths") or {}
        scanned = paths.get("scanned") if isinstance(paths, dict) else None
        files_scanned = len(scanned) if isinstance(scanned, list) else 0

        return EngineResult(findings=findings, files_scanned=files_scanned, errors=errors)
