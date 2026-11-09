"""API 與內部共用的資料模型。"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from .config import SEVERITIES

Severity = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "error": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "low": "low",
    "minor": "low",
    "note": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
}


def normalize_severity(value: str | None) -> Severity:
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), "info")  # type: ignore[return-value]


def count_by_severity(findings: list["Finding"]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


class DataflowStep(BaseModel):
    """Taint 資料流的一站：source、中間傳遞或 sink。"""

    role: Literal["source", "propagator", "sink"] = "propagator"
    file: str
    line: int | None = None
    end_line: int | None = None
    column: int | None = None
    code: str | None = None


class Finding(BaseModel):
    rule_id: str
    severity: Severity = "info"
    message: str
    file: str
    line: int | None = None
    end_line: int | None = None
    column: int | None = None
    cwe: list[str] = Field(default_factory=list)
    engine: str = ""
    snippet: str | None = None
    # Semgrep taint mode 的 source → propagator → sink 路徑。
    # 只有 taint 規則且引擎能提供追蹤時才會有內容。
    dataflow: list[DataflowStep] = Field(default_factory=list)
    # 跨掃描穩定識別碼；由 rule_id + 檔案 + 程式碼片段（或訊息）雜湊而來。
    fingerprint: str | None = None
    triage_status: str | None = None
    triage_note: str | None = None
    suppressed: bool = False
    regressed: bool = False


class TriageUpdate(BaseModel):
    status: Literal[
        "false_positive",
        "accepted_risk",
        "wontfix",
        "fixed",
        "needs_review",
    ]
    note: str | None = Field(default=None, max_length=2000)
    author: str | None = Field(default=None, max_length=200)


class TriageBulkUpdate(TriageUpdate):
    fingerprints: list[str] = Field(min_length=1, max_length=1000)


class TriageRecord(BaseModel):
    fingerprint: str
    rule_id: str = ""
    file: str = ""
    line: int | None = None
    status: str
    note: str | None = None
    author: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    last_seen_scan_id: str | None = None
    last_seen_at: str | None = None


class TriageImportItem(BaseModel):
    fingerprint: str
    status: str
    rule_id: str = ""
    file: str = ""
    line: int | None = None
    note: str | None = Field(default=None, max_length=2000)
    author: str | None = Field(default=None, max_length=200)


class TriageImport(BaseModel):
    records: list[TriageImportItem] = Field(min_length=1, max_length=5000)


class ScanOut(BaseModel):
    id: str
    status: str
    source_type: str
    source_ref: str | None = None
    engine: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    stats: dict[str, Any] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)


class EngineInfo(BaseModel):
    name: str
    description: str
    available: bool
    active: bool = False
    version: str | None = None
