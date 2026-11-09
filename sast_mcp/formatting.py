"""把 API 回傳整理成適合 Agent 讀取的形狀。"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from app.languages import aggregate_language_risk

_MAX_MESSAGE = 500

_SECRET_KEY_VALUE = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*[:=]\s*)(['\"]?)([^\s'\",;]{3,})"
)
_TOKEN_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "ghp_***"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "xox-***"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "sk-***"),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{12,}=*"), r"\1***"),
    (
        re.compile(
            r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)"
        ),
        r"\1 [REDACTED] \2",
    ),
]


def decorate_scan(scan: dict[str, Any], base_url: str) -> dict[str, Any]:
    data = dict(scan)
    scan_id = data.get("id")
    if scan_id:
        data["ui_url"] = f"{base_url}/ui/scans/{scan_id}"
        data["sarif_url"] = f"{base_url}/api/v1/scans/{scan_id}/sarif"
        data["findings_url"] = f"{base_url}/api/v1/scans/{scan_id}/findings"
    return data


def redact_snippet(text: str) -> str:
    """遮蔽片段中的常見憑證樣式；保留足夠脈絡供判讀。"""

    redacted = _SECRET_KEY_VALUE.sub(r"\1\2***\2", text)
    for pattern, replacement in _TOKEN_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def finding_to_dict(
    finding: dict[str, Any],
    *,
    include_snippet: bool = False,
    redact_secrets: bool = True,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "message": str(finding.get("message") or "")[:_MAX_MESSAGE],
        "file": finding.get("file"),
        "line": finding.get("line"),
        "end_line": finding.get("end_line"),
        "column": finding.get("column"),
        "cwe": finding.get("cwe") or [],
        "engine": finding.get("engine"),
        "fingerprint": finding.get("fingerprint"),
        "triage_status": finding.get("triage_status"),
        "triage_note": finding.get("triage_note"),
        "suppressed": bool(finding.get("suppressed")),
        "regressed": bool(finding.get("regressed")),
    }
    if data["file"] is not None:
        data["location"] = f"{data['file']}:{data['line'] or 0}"

    if include_snippet:
        snippet = finding.get("snippet")
        if snippet:
            data["snippet"] = redact_snippet(snippet) if redact_secrets else snippet
        else:
            data["snippet"] = None
    return data


def aggregate_findings(
    findings: list[dict[str, Any]],
    *,
    top: int = 20,
    sample_locations: int = 3,
    language_stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    by_severity: Counter[str] = Counter()
    by_rule: Counter[str] = Counter()
    by_file: Counter[str] = Counter()
    by_engine: Counter[str] = Counter()
    file_severities: dict[str, Counter[str]] = defaultdict(Counter)
    rule_info: dict[str, dict[str, Any]] = {}
    rule_locations: dict[str, list[str]] = defaultdict(list)

    for finding in findings:
        severity = str(finding.get("severity") or "info")
        rule_id = str(finding.get("rule_id") or "unknown")
        file = str(finding.get("file") or "unknown")
        line = finding.get("line") or 0
        location = f"{file}:{line}"

        by_severity[severity] += 1
        by_rule[rule_id] += 1
        by_file[file] += 1
        by_engine[str(finding.get("engine") or "unknown")] += 1
        file_severities[file][severity] += 1

        if rule_id not in rule_info:
            rule_info[rule_id] = {
                "rule_id": rule_id,
                "severity": severity,
                "message": str(finding.get("message") or "")[:_MAX_MESSAGE],
                "cwe": finding.get("cwe") or [],
            }
        if len(rule_locations[rule_id]) < sample_locations:
            rule_locations[rule_id].append(location)

    rules = [
        {
            **rule_info[rule_id],
            "count": count,
            "sample_locations": rule_locations[rule_id],
        }
        for rule_id, count in by_rule.most_common(top)
    ]
    files = [
        {
            "file": file,
            "count": count,
            "severity_counts": dict(file_severities[file]),
        }
        for file, count in by_file.most_common(top)
    ]

    language_risk = aggregate_language_risk(findings, language_stats)

    return {
        "total_findings": len(findings),
        "primary_language": language_risk["primary_language"],
        "primary_language_name": language_risk["primary_language_name"],
        "by_severity": dict(by_severity),
        "by_engine": dict(by_engine),
        "by_rule": rules,
        "by_file": files,
        "by_language": language_risk["languages"],
        "language_risk_levels": language_risk["risk_levels"],
        "omitted_rule_groups": max(0, len(by_rule) - len(rules)),
        "omitted_file_groups": max(0, len(by_file) - len(files)),
    }
