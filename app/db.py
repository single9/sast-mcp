"""SQLite 存取層。每次操作使用獨立連線，適合多執行緒 worker。"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Sequence

from .config import SUPPRESSED_TRIAGE_STATUSES, get_settings
from .languages import aggregate_language_risk
from .models import DataflowStep, Finding, ScanOut, count_by_severity
from .triage import fingerprint_for_values, triage_summary

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_ref  TEXT,
    engine      TEXT,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    error       TEXT,
    stats_json  TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id  TEXT NOT NULL,
    severity TEXT NOT NULL,
    message  TEXT NOT NULL,
    file     TEXT NOT NULL,
    line     INTEGER,
    end_line INTEGER,
    col      INTEGER,
    cwe      TEXT,
    engine   TEXT,
    snippet  TEXT,
    dataflow TEXT,
    fingerprint   TEXT,
    triage_status TEXT,
    triage_note   TEXT,
    suppressed    INTEGER NOT NULL DEFAULT 0,
    regressed     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

CREATE TABLE IF NOT EXISTS triage (
    fingerprint      TEXT PRIMARY KEY,
    rule_id          TEXT NOT NULL DEFAULT '',
    file             TEXT NOT NULL DEFAULT '',
    line             INTEGER,
    status           TEXT NOT NULL,
    note             TEXT,
    author           TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    last_seen_scan_id TEXT,
    last_seen_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_triage_status ON triage(status);
CREATE INDEX IF NOT EXISTS idx_triage_file ON triage(file);
"""

_SEVERITY_ORDER_SQL = """
CASE severity
    WHEN 'critical' THEN 0
    WHEN 'high' THEN 1
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 3
    ELSE 4
END
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        # 既有資料庫沒有新欄位，補上（SQLite 的 ALTER TABLE 只支援 ADD COLUMN）。
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        additions = {
            "dataflow": "TEXT",
            "fingerprint": "TEXT",
            "triage_status": "TEXT",
            "triage_note": "TEXT",
            "suppressed": "INTEGER NOT NULL DEFAULT 0",
            "regressed": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, ddl in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {ddl}")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)"
        )


def backfill_fingerprints() -> int:
    """替舊掃描的 findings 補上 fingerprint，讓 triage 判定能沿用到舊資料。"""

    with connect() as conn:
        rows = conn.execute(
            "SELECT id, rule_id, file, message, snippet FROM findings WHERE fingerprint IS NULL"
        ).fetchall()
        updates = [
            (
                fingerprint_for_values(
                    row["rule_id"], row["file"], row["snippet"] or row["message"]
                ),
                row["id"],
            )
            for row in rows
        ]
        if updates:
            conn.executemany("UPDATE findings SET fingerprint=? WHERE id=?", updates)
    return len(updates)


def ping() -> None:
    with connect() as conn:
        conn.execute("SELECT 1").fetchone()


def create_scan(scan_id: str, source_type: str, source_ref: str | None) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, status, source_type, source_ref, created_at) VALUES (?, 'queued', ?, ?, ?)",
            (scan_id, source_type, source_ref, utcnow()),
        )


def set_running(scan_id: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET status='running', started_at=? WHERE id=? AND status='queued'",
            (utcnow(), scan_id),
        )


def set_completed(scan_id: str, engine: str, stats: dict) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET status='completed', engine=?, finished_at=?, stats_json=?, error=NULL WHERE id=?",
            (engine, utcnow(), json.dumps(stats, ensure_ascii=False), scan_id),
        )


def set_failed(scan_id: str, error: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?",
            (utcnow(), error[:2000], scan_id),
        )


def add_findings(scan_id: str, findings: Sequence[Finding]) -> None:
    if not findings:
        return
    rows = [
        (
            scan_id,
            finding.rule_id,
            finding.severity,
            finding.message,
            finding.file,
            finding.line,
            finding.end_line,
            finding.column,
            json.dumps(finding.cwe, ensure_ascii=False),
            finding.engine,
            finding.snippet,
            json.dumps([step.model_dump() for step in finding.dataflow], ensure_ascii=False)
            if finding.dataflow
            else None,
            finding.fingerprint,
            finding.triage_status,
            finding.triage_note,
            1 if finding.suppressed else 0,
            1 if finding.regressed else 0,
        )
        for finding in findings
    ]
    with connect() as conn:
        conn.executemany(
            """
            INSERT INTO findings
                (scan_id, rule_id, severity, message, file, line, end_line, col, cwe, engine, snippet,
                 dataflow, fingerprint, triage_status, triage_note, suppressed, regressed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def _to_scan(row: sqlite3.Row) -> ScanOut:
    stats: dict = {}
    if row["stats_json"]:
        try:
            parsed = json.loads(row["stats_json"])
            if isinstance(parsed, dict):
                stats = parsed
        except json.JSONDecodeError:
            stats = {}
    counts = stats.get("severity") if isinstance(stats.get("severity"), dict) else {}
    return ScanOut(
        id=row["id"],
        status=row["status"],
        source_type=row["source_type"],
        source_ref=row["source_ref"],
        engine=row["engine"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        error=row["error"],
        stats=stats,
        severity_counts={k: int(v) for k, v in counts.items()},
    )


def get_scan(scan_id: str) -> ScanOut | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _to_scan(row) if row else None


def list_scans(limit: int = 50, offset: int = 0, status: str | None = None) -> list[ScanOut]:
    sql = "SELECT * FROM scans"
    params: list = []
    if status:
        sql += " WHERE status=?"
        params.append(status)
    sql += " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_to_scan(row) for row in rows]


def count_scans() -> int:
    with connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])


def _to_finding(row: sqlite3.Row) -> Finding:
    try:
        cwe = json.loads(row["cwe"]) if row["cwe"] else []
    except json.JSONDecodeError:
        cwe = []
    dataflow: list[DataflowStep] = []
    if row["dataflow"]:
        try:
            parsed = json.loads(row["dataflow"])
        except json.JSONDecodeError:
            parsed = []
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    try:
                        dataflow.append(DataflowStep.model_validate(item))
                    except ValueError:
                        continue
    return Finding(
        rule_id=row["rule_id"],
        severity=row["severity"],
        message=row["message"],
        file=row["file"],
        line=row["line"],
        end_line=row["end_line"],
        column=row["col"],
        cwe=cwe if isinstance(cwe, list) else [],
        engine=row["engine"] or "",
        snippet=row["snippet"],
        dataflow=dataflow,
        fingerprint=row["fingerprint"],
        triage_status=row["triage_status"],
        triage_note=row["triage_note"],
        suppressed=bool(row["suppressed"]),
        regressed=bool(row["regressed"]),
    )


def get_findings(
    scan_id: str,
    severities: Sequence[str] | None = None,
    limit: int = 1000,
    offset: int = 0,
    include_suppressed: bool = True,
    triage_status: Sequence[str] | None = None,
) -> list[Finding]:
    sql = f"SELECT * FROM findings WHERE scan_id=?"
    params: list = [scan_id]
    if severities:
        placeholders = ",".join("?" for _ in severities)
        sql += f" AND severity IN ({placeholders})"
        params.extend(severities)
    if not include_suppressed:
        sql += " AND suppressed=0"
    if triage_status:
        placeholders = ",".join("?" for _ in triage_status)
        sql += f" AND triage_status IN ({placeholders})"
        params.extend(triage_status)
    sql += f" ORDER BY {_SEVERITY_ORDER_SQL}, file, line LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_to_finding(row) for row in rows]


def count_findings(scan_id: str, include_suppressed: bool = True) -> int:
    sql = "SELECT COUNT(*) FROM findings WHERE scan_id=?"
    if not include_suppressed:
        sql += " AND suppressed=0"
    with connect() as conn:
        return int(conn.execute(sql, (scan_id,)).fetchone()[0])


def delete_scan(scan_id: str) -> bool:
    with connect() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    return cursor.rowcount > 0


def mark_interrupted() -> int:
    """服務重啟後，把卡在 queued/running 的掃描標記為失敗。"""
    with connect() as conn:
        cursor = conn.execute(
            """
            UPDATE scans
               SET status='failed', finished_at=?, error='服務重新啟動，掃描中斷，請重新送出'
             WHERE status IN ('queued', 'running')
            """,
            (utcnow(),),
        )
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Triage：跨掃描保存人工判讀結果
# ---------------------------------------------------------------------------


def _to_triage(row: sqlite3.Row) -> dict:
    return {
        "fingerprint": row["fingerprint"],
        "rule_id": row["rule_id"] or "",
        "file": row["file"] or "",
        "line": row["line"],
        "status": row["status"],
        "note": row["note"],
        "author": row["author"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_seen_scan_id": row["last_seen_scan_id"],
        "last_seen_at": row["last_seen_at"],
    }


def get_triage_map() -> dict[str, dict]:
    """一次載入全部 triage 紀錄，掃描時比對用。"""

    with connect() as conn:
        rows = conn.execute("SELECT * FROM triage").fetchall()
    return {row["fingerprint"]: _to_triage(row) for row in rows}


def get_triage(fingerprint: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM triage WHERE fingerprint=?", (fingerprint,)).fetchone()
    return _to_triage(row) if row else None


def list_triage(
    status: str | None = None,
    rule_id: str | None = None,
    file: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    sql = "SELECT * FROM triage"
    conditions: list[str] = []
    params: list = []
    if status:
        conditions.append("status=?")
        params.append(status)
    if rule_id:
        conditions.append("rule_id LIKE ?")
        params.append(f"%{rule_id}%")
    if file:
        conditions.append("file LIKE ?")
        params.append(f"%{file}%")
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY updated_at DESC, rowid DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_to_triage(row) for row in rows]


def count_triage() -> int:
    with connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM triage").fetchone()[0])


def upsert_triage(records: Sequence[dict]) -> list[dict]:
    """新增或更新 triage 紀錄；回傳更新後的完整紀錄。"""

    now = utcnow()
    fingerprints: list[str] = []
    with connect() as conn:
        for record in records:
            fingerprint = str(record["fingerprint"])
            fingerprints.append(fingerprint)
            conn.execute(
                """
                INSERT INTO triage
                    (fingerprint, rule_id, file, line, status, note, author, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    rule_id=excluded.rule_id,
                    file=excluded.file,
                    line=excluded.line,
                    status=excluded.status,
                    note=excluded.note,
                    author=excluded.author,
                    updated_at=excluded.updated_at
                """,
                (
                    fingerprint,
                    str(record.get("rule_id") or ""),
                    str(record.get("file") or ""),
                    record.get("line"),
                    str(record["status"]),
                    record.get("note"),
                    record.get("author"),
                    now,
                    now,
                ),
            )
    return [record for fingerprint in fingerprints if (record := get_triage(fingerprint))]


def delete_triage(fingerprint: str) -> bool:
    with connect() as conn:
        cursor = conn.execute("DELETE FROM triage WHERE fingerprint=?", (fingerprint,))
    return cursor.rowcount > 0


def touch_triage_seen(fingerprints: Sequence[str], scan_id: str) -> None:
    unique = list(dict.fromkeys(fingerprints))
    if not unique:
        return
    now = utcnow()
    with connect() as conn:
        conn.executemany(
            "UPDATE triage SET last_seen_scan_id=?, last_seen_at=? WHERE fingerprint=?",
            [(scan_id, now, fingerprint) for fingerprint in unique],
        )


def refresh_findings_for(fingerprints: Sequence[str]) -> list[str]:
    """把 triage 判定同步到所有掃描的 findings；回傳受影響的 scan id。"""

    unique = list(dict.fromkeys(fingerprints))
    if not unique:
        return []

    scan_ids: set[str] = set()
    with connect() as conn:
        for fingerprint in unique:
            record = conn.execute(
                "SELECT status, note FROM triage WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if record is None:
                conn.execute(
                    """
                    UPDATE findings
                       SET triage_status=NULL, triage_note=NULL, suppressed=0, regressed=0
                     WHERE fingerprint=?
                    """,
                    (fingerprint,),
                )
            else:
                status = record["status"]
                conn.execute(
                    """
                    UPDATE findings
                       SET triage_status=?, triage_note=?, suppressed=?, regressed=?
                     WHERE fingerprint=?
                    """,
                    (
                        status,
                        record["note"],
                        1 if status in SUPPRESSED_TRIAGE_STATUSES else 0,
                        1 if status == "fixed" else 0,
                        fingerprint,
                    ),
                )
            for row in conn.execute(
                "SELECT DISTINCT scan_id FROM findings WHERE fingerprint=?", (fingerprint,)
            ).fetchall():
                scan_ids.add(row["scan_id"])
    return sorted(scan_ids)


def recompute_scan_stats(scan_id: str) -> None:
    """triage 變更後重算統計，讓舊掃描的數字與目前判定一致。"""

    scan = get_scan(scan_id)
    if scan is None:
        return

    all_findings = get_findings(scan_id, limit=100000, include_suppressed=True)
    active = [finding for finding in all_findings if not finding.suppressed]
    stats = dict(scan.stats or {})
    stats["findings"] = len(active)
    stats["findings_total"] = len(all_findings)
    stats["suppressed"] = len(all_findings) - len(active)
    stats["severity"] = count_by_severity(active)
    stats["triage"] = triage_summary(all_findings)
    stats["language_risk"] = aggregate_language_risk(active, stats.get("languages"))
    if isinstance(stats.get("dataflow"), dict):
        stats["dataflow"]["findings"] = sum(1 for finding in active if finding.dataflow)

    with connect() as conn:
        conn.execute(
            "UPDATE scans SET stats_json=? WHERE id=?",
            (json.dumps(stats, ensure_ascii=False), scan_id),
        )


def finding_meta_for(fingerprints: Sequence[str]) -> dict[str, dict]:
    """取得 fingerprint 最近一次出現的 rule/file/line，供 triage 紀錄顯示。"""

    unique = list(dict.fromkeys(fingerprints))
    if not unique:
        return {}
    placeholders = ",".join("?" for _ in unique)
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT fingerprint, scan_id, rule_id, file, line
              FROM findings
             WHERE fingerprint IN ({placeholders})
             ORDER BY id DESC
            """,
            unique,
        ).fetchall()
    meta: dict[str, dict] = {}
    for row in rows:
        meta.setdefault(
            row["fingerprint"],
            {
                "scan_id": row["scan_id"],
                "rule_id": row["rule_id"],
                "file": row["file"],
                "line": row["line"],
            },
        )
    return meta
