"""Semgrep 引擎：呼叫 semgrep CLI 並把 JSON 輸出轉成正規化 findings。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml

from ..config import EXCLUDE_DIRS, get_settings
from ..errors import EngineError
from ..models import DataflowStep, Finding, normalize_severity
from .base import Engine, EngineResult

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_MAX_SNIPPET = 500
_CODE_LINE_RE = re.compile(r"^\s*(\d+)┆\s?(.*)$")
_RULE_HEADER_RE = re.compile(r"❯+\s*❱?\s*(\S+)")
_TRACE_SOURCE = "Taint comes from:"
_TRACE_PROPAGATOR = "Taint flows through these intermediate variables:"
_TRACE_SINK = "This is how taint reaches the sink:"


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


def _normalize_rel(root: Path, value: str) -> str:
    """把 Semgrep 的絕對／相對路徑統一成掃描根目錄下的相對路徑。"""
    raw = str(value or "").replace(os.sep, "/")
    if not raw:
        return ""
    path = Path(raw)
    if path.is_absolute():
        try:
            return str(path.resolve().relative_to(root.resolve())).replace(os.sep, "/")
        except (OSError, ValueError):
            return raw
    if raw.startswith("./"):
        raw = raw[2:]
    return raw


def _path_exists(root: Path, candidate: str) -> bool:
    try:
        path = Path(candidate)
        return path.exists() if path.is_absolute() else (root / path).exists()
    except (OSError, ValueError):
        return False


def _first_location(value) -> tuple[dict | None, str | None]:
    """從 Semgrep 的 CliLoc / CliCall trace 取出第一個位置與程式碼字串。"""
    locations: list[dict] = []
    path_values: set[str] = set()
    candidates: list[str] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            path_value = node.get("path")
            if isinstance(path_value, str):
                path_values.add(path_value)
            if "path" in node and "start" in node:
                locations.append(node)
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str) and node not in {"CliLoc", "CliCall"}:
            if "\n" not in node:
                candidates.append(node)

    walk(value)
    content = next((item for item in candidates if item not in path_values), None)
    return (locations[0] if locations else None), content


def _step_from_location(
    root: Path,
    location: dict,
    content: str | None,
    role: str,
) -> DataflowStep | None:
    rel = _normalize_rel(root, str(location.get("path") or ""))
    if not rel:
        return None
    start = location.get("start") or {}
    end = location.get("end") or {}
    line = start.get("line") if isinstance(start, dict) else None
    end_line = end.get("line") if isinstance(end, dict) else None
    column = start.get("col") if isinstance(start, dict) else None
    code = _trim(content) if content else _read_snippet(root, rel, line, end_line)
    return DataflowStep(
        role=role,  # type: ignore[arg-type]
        file=rel,
        line=line,
        end_line=end_line,
        column=column,
        code=code,
    )


def _dedupe_steps(steps: list[DataflowStep]) -> list[DataflowStep]:
    """去掉重複的 source/propagator；source 與 sink 同位置時兩者都保留。"""
    anchors = {
        (step.file, step.line)
        for step in steps
        if step.role in {"source", "sink"}
    }
    seen: set[tuple[str, str, int | None, str | None]] = set()
    result: list[DataflowStep] = []
    for step in steps:
        if step.role == "propagator" and (step.file, step.line) in anchors:
            continue
        key = (step.role, step.file, step.line, step.code)
        if key in seen:
            continue
        seen.add(key)
        result.append(step)
    return result


def _parse_json_dataflow(trace, root: Path) -> list[DataflowStep]:
    """解析 Semgrep JSON 的 extra.dataflow_trace（需要登入或未來版本才會出現）。"""
    if not isinstance(trace, dict):
        return []

    steps: list[DataflowStep] = []
    source_location, source_content = _first_location(trace.get("taint_source"))
    if source_location:
        step = _step_from_location(root, source_location, source_content, "source")
        if step:
            steps.append(step)

    intermediate = trace.get("intermediate_vars")
    if isinstance(intermediate, list):
        for item in intermediate:
            if not isinstance(item, dict):
                continue
            location = item.get("location")
            if not isinstance(location, dict):
                continue
            step = _step_from_location(root, location, item.get("content"), "propagator")
            if step:
                steps.append(step)

    sink_location, sink_content = _first_location(trace.get("taint_sink"))
    if sink_location:
        step = _step_from_location(root, sink_location, sink_content, "sink")
        if step:
            steps.append(step)

    return _dedupe_steps(steps)


def _load_taint_rules(rules_dir: Path) -> tuple[set[str], list[dict]]:
    """讀出內建規則中的 taint 規則，供第二輪文字掃描補資料流。"""
    ids: set[str] = set()
    rules: list[dict] = []
    if not rules_dir.is_dir():
        return ids, rules
    for path in sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue
        for rule in data.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            if rule.get("mode") == "taint" and rule.get("id"):
                ids.add(str(rule["id"]))
                rules.append(rule)
    return ids, rules


def _parse_text_dataflow(
    output: str, root: Path
) -> dict[tuple[str, str, int | None], list[DataflowStep]]:
    """解析 semgrep --text --dataflow-traces 的輸出。

    Semgrep OSS 的 JSON 在未登入時會過濾 dataflow_trace，但文字輸出仍會
    顯示 source → intermediate → sink。這裡只把文字輸出當成補充來源，
    主要 findings 仍以 JSON 為準。
    """
    traces: dict[tuple[str, str, int | None], list[DataflowStep]] = {}
    current_file: str | None = None
    current_rule: str | None = None
    in_trace = False
    section: str | None = None
    source_steps: list[DataflowStep] = []
    propagator_steps: list[DataflowStep] = []
    sink_steps: list[DataflowStep] = []

    def flush() -> None:
        nonlocal in_trace, section, source_steps, propagator_steps, sink_steps
        if in_trace and current_file and current_rule and sink_steps:
            sink = sink_steps[-1]
            key = (current_rule, current_file, sink.line)
            traces.setdefault(key, _dedupe_steps(source_steps + propagator_steps + [sink]))
        in_trace = False
        section = None
        source_steps = []
        propagator_steps = []
        sink_steps = []

    for raw_line in (output or "").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        if "❯" in line:
            match = _RULE_HEADER_RE.search(line)
            if match:
                current_rule = match.group(1)
            continue

        if "┆" not in line and stripped and _path_exists(root, stripped):
            # 新檔案區塊開始。Semgrep 只在 finding 之間印 ⋮┆ 分隔線，
            # 每個檔案的最後一筆不會印，所以這裡要先 flush 上一筆。
            if in_trace:
                flush()
            current_file = _normalize_rel(root, stripped)
            continue

        if _TRACE_SOURCE in line:
            if in_trace:
                flush()
            in_trace = True
            section = "source"
            continue
        if _TRACE_PROPAGATOR in line:
            section = "propagator"
            continue
        if _TRACE_SINK in line:
            section = "sink"
            continue
        if "⋮┆" in line:
            if in_trace:
                flush()
            continue

        match = _CODE_LINE_RE.match(line)
        if not (match and in_trace and current_file):
            continue
        line_number = int(match.group(1))
        code = _trim(match.group(2))
        step = DataflowStep(
            role="propagator",
            file=current_file,
            line=line_number,
            end_line=line_number,
            code=code,
        )
        if section == "source":
            step.role = "source"
            source_steps.append(step)
        elif section == "sink":
            step.role = "sink"
            sink_steps.append(step)
        else:
            propagator_steps.append(step)

    if in_trace:
        flush()
    return traces


class SemgrepEngine(Engine):
    name = "semgrep"
    description = "Semgrep OSS 規則引擎（語意比對與 taint 資料流，建議安裝）"

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

    def _build_command(
        self,
        configs: list[str],
        *,
        output: str,
        pro: bool,
        timeout: int,
        dataflow_traces: bool,
    ) -> list[str]:
        settings = get_settings()
        cmd = [
            settings.semgrep_bin,
            "scan",
            output,
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--timeout",
            str(max(10, min(timeout, 120))),
            "--max-target-bytes",
            "2000000",
        ]
        if dataflow_traces:
            cmd.append("--dataflow-traces")
        if pro:
            cmd.append("--pro")
        for config in configs:
            cmd.extend(["--config", config])
        for directory in sorted(EXCLUDE_DIRS):
            cmd.extend(["--exclude", directory])
        return cmd

    def _collect_text_traces(
        self,
        root: Path,
        findings: list[Finding],
        taint_rules: list[dict],
        timeout: int,
        env: dict[str, str],
        *,
        pro: bool,
    ) -> dict[tuple[str, str, int | None], list[DataflowStep]]:
        files = sorted({finding.file for finding in findings if finding.file})
        if not files or not taint_rules:
            return {}

        with tempfile.TemporaryDirectory(prefix="sast-taint-") as tmp:
            config_path = Path(tmp) / "taint.yml"
            config_path.write_text(
                yaml.safe_dump(
                    {"rules": taint_rules},
                    allow_unicode=True,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            cmd = self._build_command(
                [str(config_path)],
                output="--text",
                pro=pro,
                timeout=timeout,
                dataflow_traces=True,
            )
            # 只掃有 taint finding 的檔案；太多檔案時退回整個目錄。
            cmd.extend(files if len(files) <= 300 else ["."])
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60,
                    env=env,
                )
            except (OSError, subprocess.SubprocessError):
                return {}
            if proc.returncode not in (0, 1):
                return {}
            return _parse_text_dataflow(proc.stdout or "", root)

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

        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"

        # 額外規則集（例如 registry pack）可能因離線或下載失敗而讓整個掃描失敗；
        # 此時退回主規則集，並在結果 warnings 中留下原因。
        attempts = [configs]
        if len(configs) > 1:
            attempts.append(configs[:1])

        warnings: list[str] = []
        proc: subprocess.CompletedProcess[str] | None = None
        pro_active = settings.semgrep_pro
        for index, active in enumerate(attempts):
            try:
                proc = subprocess.run(
                    self._build_command(
                        active,
                        output="--json",
                        pro=pro_active,
                        timeout=timeout,
                        dataflow_traces=settings.dataflow_traces,
                    )
                    + ["."],
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
            if pro_active:
                warnings.append(
                    f"Semgrep Pro 無法使用，已退回 OSS 引擎：{stderr[:200] or f'exit {proc.returncode}'}"
                )
                pro_active = False
                try:
                    proc = subprocess.run(
                        self._build_command(
                            active,
                            output="--json",
                            pro=False,
                            timeout=timeout,
                            dataflow_traces=settings.dataflow_traces,
                        )
                        + ["."],
                        cwd=str(root),
                        capture_output=True,
                        text=True,
                        timeout=timeout + 60,
                        env=env,
                    )
                except (OSError, subprocess.SubprocessError) as exc:
                    raise EngineError(f"無法執行 Semgrep：{exc}") from exc
                if proc.returncode in (0, 1):
                    break

            if index + 1 < len(attempts):
                reason = stderr or f"exit {proc.returncode}"
                warnings.append(f"額外規則集載入失敗，已改用主規則集：{reason[:200]}")
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
                path = _normalize_rel(root, path)

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
                dataflow=_parse_json_dataflow(extra.get("dataflow_trace"), root),
            )
            key = (finding.rule_id, finding.file, finding.line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

        # Semgrep OSS 未登入時不會把 dataflow_trace 放進 JSON；用第二輪
        # 文字輸出補上 source → propagator → sink，讓報告能解釋資料流。
        if settings.dataflow_traces:
            taint_ids, taint_rules = _load_taint_rules(settings.rules_dir)
            if taint_ids and taint_rules:
                pending = [
                    finding
                    for finding in findings
                    if finding.rule_id in taint_ids and not finding.dataflow
                ]
                if pending:
                    pending_ids = {finding.rule_id for finding in pending}
                    selected_rules = [
                        rule for rule in taint_rules if str(rule.get("id")) in pending_ids
                    ]
                    try:
                        traces = self._collect_text_traces(
                            root,
                            pending,
                            selected_rules,
                            timeout,
                            env,
                            pro=pro_active,
                        )
                    except (OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
                        warnings.append(
                            f"資料流追蹤失敗：{type(exc).__name__}: {exc}"
                        )
                    else:
                        for finding in pending:
                            steps = traces.get((finding.rule_id, finding.file, finding.line))
                            if steps:
                                finding.dataflow = steps

        errors = list(warnings)
        for error in data.get("errors", []):
            message = error.get("message") if isinstance(error, dict) else str(error)
            if message:
                errors.append(str(message)[:300])

        paths = data.get("paths") or {}
        scanned = paths.get("scanned") if isinstance(paths, dict) else None
        files_scanned = len(scanned) if isinstance(scanned, list) else 0

        return EngineResult(findings=findings, files_scanned=files_scanned, errors=errors)
