"""跨函式 taint 引擎的對外入口：把分析結果轉成 Finding 並與 Semgrep 結果合併。"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import DataflowStep, Finding, normalize_severity

logger = logging.getLogger(__name__)


def _to_finding(hit) -> Finding:
    return Finding(
        rule_id=f"taint-{hit.rule.kind}",
        severity=normalize_severity(hit.rule.severity),
        message=hit.rule.message,
        file=hit.file,
        line=hit.line,
        column=hit.column,
        cwe=[hit.rule.cwe] if hit.rule.cwe else [],
        engine="taint",
        snippet=hit.code or None,
        dataflow=[
            DataflowStep(role=step.role, file=step.file, line=step.line, code=step.code)
            for step in hit.steps
        ],
    )


_KIND_HINTS = {
    "command-injection": ("command", "exec", "system", "spawn", "shell"),
    "sql-injection": ("sql", "injection"),
    "path-traversal": ("path", "traversal", "directory"),
    "ssrf": ("ssrf", "server-side", "url"),
    "code-injection": ("code-injection", "eval", "exec", "code execution"),
    "deserialization": ("deserial", "pickle", "yaml", "objectinputstream"),
    "xss": ("xss", "cross-site", "html", "escape"),
    "format-string": ("format", "printf"),
    "buffer-overflow": ("buffer", "overflow", "strcpy", "memcpy"),
}


def _same_issue(existing: Finding, candidate: Finding, kind: str) -> bool:
    if existing.file != candidate.file or existing.line != candidate.line:
        return False
    if set(existing.cwe) & set(candidate.cwe):
        return True
    if kind and kind in existing.rule_id:
        return True
    hints = _KIND_HINTS.get(kind, ())
    haystack = f"{existing.rule_id} {existing.message}".lower()
    if hints and any(hint in haystack for hint in hints):
        return True
    if existing.engine == "taint" and candidate.engine == "taint":
        return False
    return bool(existing.dataflow) and not existing.cwe and not candidate.cwe


def _merge(existing: Finding, candidate: Finding) -> bool:
    """把候選 finding 的資料流併進既有 finding；回傳是否有變更。"""

    changed = False
    if len(candidate.dataflow) > len(existing.dataflow):
        existing.dataflow = candidate.dataflow
        changed = True
    for cwe in candidate.cwe:
        if cwe not in existing.cwe:
            existing.cwe.append(cwe)
            changed = True
    if not existing.snippet and candidate.snippet:
        existing.snippet = candidate.snippet
        changed = True
    return changed


def scan_taint(
    root: Path, existing: list[Finding], max_files: int = 5000
) -> tuple[list[Finding], list[str], dict]:
    """跑跨函式 taint 分析。

    回傳 (新 findings, warnings, stats)。已存在的 Semgrep finding 若指向同一個
    sink，會把較長／跨檔案的資料流補上去，而不是重複回報。
    """

    try:
        from .analyzer import analyze_repository
        from .rules import load_rules
    except ImportError as exc:  # tree-sitter 未安裝時優雅停用
        logger.info("taint 引擎停用：%s", exc)
        return [], [f"taint 引擎停用：{exc}"], {"enabled": False, "error": str(exc)}

    try:
        hits, stats = analyze_repository(root, load_rules(), max_files=max_files)
    except Exception as exc:  # noqa: BLE001 - 分析失敗不應讓整個掃描失敗
        logger.warning("taint 分析失敗：%s", exc, exc_info=True)
        return [], [f"taint 分析失敗：{type(exc).__name__}: {exc}"], {
            "enabled": True,
            "error": str(exc),
        }

    index: dict[tuple[str, int | None], list[Finding]] = {}
    for finding in existing:
        index.setdefault((finding.file, finding.line), []).append(finding)

    new_findings: list[Finding] = []
    merged = 0
    for hit in hits:
        candidate = _to_finding(hit)
        bucket = index.setdefault((candidate.file, candidate.line), [])
        duplicate = next(
            (item for item in bucket if _same_issue(item, candidate, hit.rule.kind)), None
        )
        if duplicate is not None:
            if _merge(duplicate, candidate):
                merged += 1
            continue
        bucket.append(candidate)
        new_findings.append(candidate)

    interprocedural = sum(
        1 for finding in existing if len({step.file for step in finding.dataflow}) > 1
    )
    by_kind: dict[str, int] = {}
    for finding in new_findings:
        by_kind[finding.rule_id] = by_kind.get(finding.rule_id, 0) + 1

    stats.update(
        {
            "enabled": True,
            "findings": len(new_findings),
            "merged": merged,
            "interprocedural": interprocedural,
            "by_kind": by_kind,
        }
    )
    return new_findings, [], stats
