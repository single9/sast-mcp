"""Triage 紀錄：讓人工判讀結果能跨掃描重複使用。

問題：同一批誤報每次掃描都會再出現，Agent 每次都要重新判讀。
解法：每個 finding 有穩定的 fingerprint（rule + 檔案 + 程式碼內容），
把「誤報／接受風險／不修補／已修補」等判定存在 triage 表；之後的掃描
會自動把已抑制的 finding 排除在統計、摘要與 SARIF 之外。

另外支援原始碼 inline 忽略，判定跟著 repo 走：

    x = dangerous()  # sast:ignore
    y = dangerous()  # sast:ignore: rule-id-a, rule-id-b -- 原因

fingerprint 刻意不含行號：程式碼往上搬幾行不應該讓判定失效。
若片段內容真的改了，fingerprint 會改變，舊判定自然不再套用。
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path

from .config import INLINE_IGNORE_STATUS, SUPPRESSED_TRIAGE_STATUSES
from .models import Finding

_MAX_INLINE_FILE_BYTES = 2 * 1024 * 1024
_MAX_CACHE_ENTRIES = 2000

_IGNORE_RE = re.compile(r"sast:ignore(?:\s*:\s*([^\n]*))?", re.IGNORECASE)
_RULE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_SPLIT_RE = re.compile(r"[,\s]+")


def normalize_text(text: str | None) -> str:
    """壓縮空白，讓 fingerprint 不受縮排與換行影響。"""

    return " ".join(str(text or "").split())


def fingerprint_for_values(rule_id: str, file: str, basis: str | None) -> str:
    raw = f"{rule_id}\x00{file}\x00{normalize_text(basis)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def fingerprint_for(finding: Finding) -> str:
    """優先用程式碼片段；依賴／供應鏈 finding 沒有片段時改用訊息。"""

    basis = finding.snippet or finding.message
    return fingerprint_for_values(finding.rule_id, finding.file, basis)


def parse_ignore_comment(line: str) -> tuple[bool, set[str] | None]:
    """解析一行是否含 ``sast:ignore``。

    回傳 ``(found, rules)``：

    * ``found=False``：這行沒有忽略指令。
    * ``rules=None``：忽略這一行上的所有規則。
    * ``rules=set()``：有指令但規則清單無法解析，不忽略任何規則。
    * ``rules={...}``：只忽略指定規則。
    """

    match = _IGNORE_RE.search(line)
    if not match:
        return False, None

    rest = (match.group(1) or "").strip()
    rest = rest.split("--", 1)[0].strip()
    if not rest:
        return True, None

    tokens = {token for token in _SPLIT_RE.split(rest) if token}
    rules = {token for token in tokens if _RULE_TOKEN_RE.match(token)}
    return True, rules


def inline_ignore_reason(lines: list[str], line_no: int, rule_id: str) -> str | None:
    """檢查 finding 所在行與上一行是否有針對該規則的忽略指令。"""

    for index in (line_no - 1, line_no - 2):
        if 0 <= index < len(lines):
            found, rules = parse_ignore_comment(lines[index])
            if found and (rules is None or rule_id in rules):
                return lines[index].strip()[:300]
    return None


class _LineCache:
    """掃描期間快取檔案內容；只讀取掃描根目錄內、大小合理的文字檔。"""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._cache: dict[str, list[str] | None] = {}

    def lines_for(self, rel_path: str) -> list[str] | None:
        if rel_path in self._cache:
            return self._cache[rel_path]

        lines: list[str] | None = None
        try:
            target = (self.root / rel_path).resolve()
            if target == self.root or self.root not in target.parents:
                lines = None
            elif target.stat().st_size > _MAX_INLINE_FILE_BYTES:
                lines = None
            else:
                lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
        except (OSError, ValueError):
            lines = None

        if len(self._cache) >= _MAX_CACHE_ENTRIES:
            self._cache.clear()
        self._cache[rel_path] = lines
        return lines


def apply_inline_ignores(findings: list[Finding], root: Path) -> int:
    """把原始碼裡的 ``sast:ignore`` 套用到 findings，回傳抑制筆數。"""

    cache = _LineCache(root)
    suppressed = 0
    for finding in findings:
        if not finding.line:
            continue
        lines = cache.lines_for(finding.file)
        if not lines:
            continue
        reason = inline_ignore_reason(lines, finding.line, finding.rule_id)
        if reason is None:
            continue
        finding.triage_status = INLINE_IGNORE_STATUS
        finding.triage_note = f"原始碼忽略：{reason}"
        finding.suppressed = True
        suppressed += 1
    return suppressed


def annotate_findings(findings: list[Finding], root: Path, scan_id: str) -> dict:
    """計算 fingerprint、套用 inline ignore 與既有 triage 判定。

    回傳要寫進 ``scan.stats.triage`` 的統計。
    """

    from . import db  # 延遲匯入，避免 db <-> triage 循環依賴

    triage_map = db.get_triage_map()
    inline_suppressed = apply_inline_ignores(findings, root)
    counts: Counter[str] = Counter()

    for finding in findings:
        finding.fingerprint = fingerprint_for(finding)
        if finding.suppressed:  # inline ignore
            counts[INLINE_IGNORE_STATUS] += 1
            continue

        record = triage_map.get(finding.fingerprint)
        if record is None:
            continue

        status = str(record.get("status") or "")
        finding.triage_status = status or None
        finding.triage_note = record.get("note")
        finding.suppressed = status in SUPPRESSED_TRIAGE_STATUSES
        finding.regressed = status == "fixed"
        counts[status or "unknown"] += 1

    db.touch_triage_seen(
        [
            finding.fingerprint
            for finding in findings
            if finding.fingerprint and not finding.suppressed
        ],
        scan_id,
    )

    return {
        "records": sum(counts.values()),
        "inline_suppressed": inline_suppressed,
        "suppressed": sum(
            1 for finding in findings if finding.suppressed
        ),
        "by_status": dict(counts),
    }


def triage_counts(findings: list[Finding]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for finding in findings:
        if finding.triage_status:
            counts[finding.triage_status] += 1
    return dict(counts)


def triage_summary(findings: list[Finding]) -> dict:
    """與掃描時相同的 triage 統計格式，供重算舊掃描統計使用。"""

    by_status = triage_counts(findings)
    return {
        "records": sum(by_status.values()),
        "inline_suppressed": by_status.get(INLINE_IGNORE_STATUS, 0),
        "suppressed": sum(1 for finding in findings if finding.suppressed),
        "by_status": by_status,
    }
