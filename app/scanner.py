"""掃描協調流程：準備原始碼 -> 執行引擎 -> 寫入結果。"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from . import db, git_source, workspace
from .config import get_settings
from .dependencies import scan_cargo_lock
from .engines import EngineError, EngineResult, select_engine
from .errors import ScanInputError
from .languages import aggregate_language_risk, detect_languages
from .models import count_by_severity
from .supply_chain import scan_supply_chain
from .triage import annotate_findings

logger = logging.getLogger(__name__)


def _error_message(exc: BaseException) -> str:
    if isinstance(exc, (ScanInputError, EngineError)):
        return str(exc)
    logger.exception("掃描執行失敗", exc_info=exc)
    return f"掃描失敗：{type(exc).__name__}: {exc}"


def _resolve_source(scan_id: str, source_type: str, source_ref: str | None) -> Path:
    root = workspace.src_dir(scan_id)
    if source_type == "git":
        if not root.is_dir() or not any(root.iterdir()):
            git_source.clone_repo(scan_id, source_ref or "")
    if not root.is_dir():
        raise ScanInputError("找不到待掃描的原始碼，請重新建立掃描")
    return root


def run_scan(scan_id: str) -> EngineResult | None:
    scan = db.get_scan(scan_id)
    if scan is None:
        logger.warning("掃描 %s 不存在，略過", scan_id)
        return None

    settings = get_settings()
    started = time.monotonic()
    db.set_running(scan_id)

    try:
        root = _resolve_source(scan_id, scan.source_type, scan.source_ref)
        engine = select_engine()
        result = engine.scan(root, settings.scan_timeout_sec)

        findings = list(result.findings)
        warnings = list(result.errors)

        try:
            dependency_findings, dependency_warnings, dependency_stats = scan_cargo_lock(root)
        except Exception as exc:  # noqa: BLE001 - 依賴掃描失敗不應讓掃描失敗
            logger.warning("依賴掃描失敗 id=%s: %s", scan_id, exc)
            dependency_findings, dependency_warnings = [], [f"依賴掃描失敗：{type(exc).__name__}: {exc}"]
            dependency_stats = {"enabled": True, "error": str(exc)}
        findings.extend(dependency_findings)
        warnings.extend(dependency_warnings)

        try:
            supply_findings, supply_warnings, supply_stats = scan_supply_chain(root)
        except Exception as exc:  # noqa: BLE001 - 供應鏈檢查失敗不應讓掃描失敗
            logger.warning("供應鏈檢查失敗 id=%s: %s", scan_id, exc)
            supply_findings, supply_warnings = [], [f"供應鏈檢查失敗：{type(exc).__name__}: {exc}"]
            supply_stats = {"enabled": True, "error": str(exc)}
        findings.extend(supply_findings)
        warnings.extend(supply_warnings)

        try:
            triage_stats = annotate_findings(findings, root, scan_id)
        except Exception as exc:  # noqa: BLE001 - triage 標註失敗不應讓掃描失敗
            logger.warning("triage 標註失敗 id=%s: %s", scan_id, exc)
            triage_stats = {"error": f"{type(exc).__name__}: {exc}"}

        active_findings = [finding for finding in findings if not finding.suppressed]

        try:
            language_stats = detect_languages(root)
        except Exception as exc:  # noqa: BLE001 - 語言統計失敗不應讓掃描失敗
            logger.warning("語言偵測失敗 id=%s: %s", scan_id, exc)
            language_stats = {}
            warnings.append(f"語言偵測失敗：{type(exc).__name__}: {exc}")
        language_risk = aggregate_language_risk(active_findings, language_stats)

        duration_ms = int((time.monotonic() - started) * 1000)
        stats = {
            "files_scanned": result.files_scanned,
            "findings": len(active_findings),
            "findings_total": len(findings),
            "suppressed": len(findings) - len(active_findings),
            "severity": count_by_severity(active_findings),
            "triage": triage_stats,
            "duration_ms": duration_ms,
            "engine": engine.name,
            "engine_version": engine.version(),
            "warnings": warnings[:20],
            "languages": language_stats,
            "language_risk": language_risk,
            "primary_language": language_stats.get("primary_language"),
            "primary_language_name": language_stats.get("primary_language_name"),
            "dependencies": dependency_stats,
            "supply_chain": supply_stats,
        }

        result.findings = findings
        db.add_findings(scan_id, findings)
        db.set_completed(scan_id, engine.name, stats)
        logger.info(
            "掃描完成 id=%s engine=%s findings=%d suppressed=%d files=%d duration=%dms",
            scan_id,
            engine.name,
            len(active_findings),
            len(findings) - len(active_findings),
            result.files_scanned,
            duration_ms,
        )
        return result
    except Exception as exc:  # noqa: BLE001 - 任何錯誤都要反映在掃描狀態
        message = _error_message(exc)
        db.set_failed(scan_id, message)
        logger.warning("掃描失敗 id=%s: %s", scan_id, message)
        return None
