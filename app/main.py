"""FastAPI 應用：REST API + 簡易 Web UI。"""

from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import db, git_source, services, workspace
from .config import (
    BASE_DIR,
    INLINE_IGNORE_STATUS,
    SCAN_STATUSES,
    SEVERITIES,
    TRIAGE_STATUSES,
    TRIAGE_STATUS_LABELS,
    get_settings,
)
from .engines import describe_engines, select_engine
from .errors import ScanInputError
from .languages import aggregate_language_risk, detect_languages
from .models import (
    EngineInfo,
    Finding,
    ScanOut,
    TriageBulkUpdate,
    TriageImport,
    TriageRecord,
    TriageUpdate,
)
from .sarif import scan_to_sarif
from .worker import shutdown_worker

logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db.init_db()
    backfilled = db.backfill_fingerprints()
    if backfilled:
        logger.info("已替 %d 筆既有 findings 補上 fingerprint", backfilled)
    interrupted = db.mark_interrupted()
    if interrupted:
        logger.warning("已將 %d 筆中斷的掃描標記為失敗", interrupted)
    yield
    shutdown_worker()


app = FastAPI(
    title="SAST 掃描服務",
    description="上傳 ZIP 或提供 Git repo URL，執行靜態應用程式安全測試並輸出 findings / SARIF。",
    version="0.1.0",
    lifespan=lifespan,
)


def api_key_guard(x_api_key: str | None = Header(default=None)) -> None:
    required = get_settings().api_key
    if required and not (x_api_key and secrets.compare_digest(x_api_key, required)):
        raise HTTPException(status_code=401, detail="API key 無效或缺少 X-API-Key")


api = APIRouter(prefix="/api/v1", dependencies=[Depends(api_key_guard)])


def _parse_severities(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    values = [item.strip().lower() for item in raw.split(",") if item.strip()]
    invalid = sorted(set(values) - set(SEVERITIES))
    if invalid:
        raise HTTPException(status_code=400, detail=f"無效的 severity：{', '.join(invalid)}")
    return values or None


def _parse_triage_statuses(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    allowed = set(TRIAGE_STATUSES) | {INLINE_IGNORE_STATUS}
    values = [item.strip().lower() for item in raw.split(",") if item.strip()]
    invalid = sorted(set(values) - allowed)
    if invalid:
        raise HTTPException(status_code=400, detail=f"無效的 triage status：{', '.join(invalid)}")
    return values or None


def _scan_or_404(scan_id: str) -> ScanOut:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="找不到掃描")
    return scan


def _language_data(scan: ScanOut, findings: list[Finding]) -> tuple[dict, dict]:
    """取得掃描的語言統計與風險；舊掃描沒有 stats 時即時從工作區推導。"""

    stats = scan.stats or {}
    stored = stats.get("language_risk")
    if isinstance(stored, dict) and isinstance(stored.get("languages"), list):
        languages = stats.get("languages")
        return languages if isinstance(languages, dict) else {}, stored

    active = [finding for finding in findings if not finding.suppressed]
    language_stats: dict = {}
    root = workspace.src_dir(scan.id)
    if root.is_dir():
        try:
            language_stats = detect_languages(root)
        except Exception as exc:  # noqa: BLE001 - 舊掃描的即時統計失敗不應讓頁面壞掉
            logger.warning("掃描 %s 語言偵測失敗：%s", scan.id, exc)
    return language_stats, aggregate_language_risk(active, language_stats or None)


def _scan_with_language_stats(scan: ScanOut, findings: list[Finding]) -> ScanOut:
    """回傳帶有語言統計的 scan；新掃描直接沿用已保存的 stats。"""

    stats = scan.stats or {}
    if isinstance(stats.get("language_risk"), dict):
        return scan

    language_stats, language_risk = _language_data(scan, findings)
    if not language_stats and not language_risk.get("languages"):
        return scan

    updated = dict(stats)
    updated["languages"] = language_stats
    updated["language_risk"] = language_risk
    updated["primary_language"] = language_stats.get("primary_language") or language_risk.get(
        "primary_language"
    )
    updated["primary_language_name"] = language_stats.get(
        "primary_language_name"
    ) or language_risk.get("primary_language_name")
    return scan.model_copy(update={"stats": updated})


# --------------------------------------------------------------------------
# REST API
# --------------------------------------------------------------------------


@api.post("/scans", response_model=ScanOut, status_code=202, tags=["scans"])
def create_scan(
    file: UploadFile | None = File(default=None),
    repo_url: str | None = Form(default=None),
) -> ScanOut:
    """建立掃描：上傳 .zip 或提供 repo_url，兩者擇一。"""
    if repo_url is not None and not repo_url.strip():
        repo_url = None
    if file is not None and repo_url is not None:
        raise HTTPException(status_code=400, detail="file 與 repo_url 請擇一")
    if file is None and repo_url is None:
        raise HTTPException(status_code=400, detail="請提供 file（.zip）或 repo_url")

    try:
        if file is not None:
            scan_id = services.create_scan_from_upload(file.file, file.filename)
        else:
            scan_id = services.create_scan_from_repo(repo_url or "")
    except ScanInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return _scan_or_404(scan_id)


@api.get("/scans", response_model=list[ScanOut], tags=["scans"])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
) -> list[ScanOut]:
    if status is not None and status not in SCAN_STATUSES:
        raise HTTPException(status_code=400, detail=f"無效的 status：{status}")
    return db.list_scans(limit=limit, offset=offset, status=status)


@api.get("/scans/{scan_id}", response_model=ScanOut, tags=["scans"])
def get_scan(scan_id: str) -> ScanOut:
    return _scan_or_404(scan_id)


@api.get("/scans/{scan_id}/findings", response_model=list[Finding], tags=["scans"])
def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None, description="逗號分隔，例如 critical,high"),
    triage_status: str | None = Query(default=None, description="逗號分隔，例如 false_positive,wontfix"),
    include_suppressed: bool = Query(default=False, description="是否包含已判定誤報／接受風險的項目"),
    limit: int = Query(default=1000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> list[Finding]:
    _scan_or_404(scan_id)
    return db.get_findings(
        scan_id,
        severities=_parse_severities(severity),
        limit=limit,
        offset=offset,
        include_suppressed=include_suppressed,
        triage_status=_parse_triage_statuses(triage_status),
    )


@api.get("/scans/{scan_id}/languages", tags=["scans"])
def get_scan_languages(scan_id: str) -> dict:
    """專案語言統計與依語言的風險分類。

    新掃描會直接使用 stats 內已計算的結果；舊掃描若沒有語言統計，則由
    findings 的檔案路徑即時推導。
    """
    scan = _scan_or_404(scan_id)
    findings = db.get_findings(scan_id, limit=5000, include_suppressed=False)
    language_stats, language_risk = _language_data(scan, findings)
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "languages": language_risk.get("languages", []),
        "primary_language": language_stats.get("primary_language") or language_risk.get("primary_language"),
        "primary_language_name": language_stats.get("primary_language_name")
        or language_risk.get("primary_language_name"),
        "total_findings": language_risk.get("total_findings", len(findings)),
        "risk_levels": language_risk.get("risk_levels", {}),
    }


@api.get("/scans/{scan_id}/sarif", tags=["scans"])
def get_scan_sarif(scan_id: str) -> JSONResponse:
    scan = _scan_or_404(scan_id)
    findings = db.get_findings(scan_id, limit=5000, include_suppressed=True)
    sarif = scan_to_sarif(_scan_with_language_stats(scan, findings), findings)
    return JSONResponse(
        sarif,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'inline; filename="sast-{scan_id}.sarif"'},
    )


@api.delete("/scans/{scan_id}", status_code=204, tags=["scans"])
def delete_scan(scan_id: str) -> Response:
    if not services.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="找不到掃描")
    return Response(status_code=204)


@api.get("/engines", response_model=list[EngineInfo], tags=["meta"])
def get_engines() -> list[EngineInfo]:
    return describe_engines()


# --------------------------------------------------------------------------
# Triage（跨掃描保存誤報／接受風險等判定）
# --------------------------------------------------------------------------


def _apply_triage(
    fingerprints: list[str],
    status: str,
    note: str | None,
    author: str | None,
    meta_overrides: dict[str, dict] | None = None,
) -> tuple[list[dict], list[str]]:
    meta = db.finding_meta_for(fingerprints)
    payload = []
    for fingerprint in fingerprints:
        overrides = (meta_overrides or {}).get(fingerprint, {})
        base = meta.get(fingerprint, {})
        payload.append(
            {
                "fingerprint": fingerprint,
                "rule_id": overrides.get("rule_id") or base.get("rule_id") or "",
                "file": overrides.get("file") or base.get("file") or "",
                "line": overrides.get("line") if overrides.get("line") is not None else base.get("line"),
                "status": status,
                "note": note,
                "author": author,
            }
        )
    records = db.upsert_triage(payload)
    affected = db.refresh_findings_for(fingerprints)

    by_scan: dict[str, list[str]] = {}
    for fingerprint in fingerprints:
        scan_id = (meta.get(fingerprint) or {}).get("scan_id")
        if scan_id:
            by_scan.setdefault(str(scan_id), []).append(fingerprint)
    for scan_id, seen in by_scan.items():
        db.touch_triage_seen(seen, scan_id)

    for scan_id in affected:
        db.recompute_scan_stats(scan_id)
    return [record for fingerprint in fingerprints if (record := db.get_triage(fingerprint))], affected


@api.get("/triage", response_model=list[TriageRecord], tags=["triage"])
def list_triage(
    status: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    file: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    if status is not None and status not in TRIAGE_STATUSES:
        raise HTTPException(status_code=400, detail=f"無效的 triage status：{status}")
    return db.list_triage(status=status, rule_id=rule_id, file=file, limit=limit, offset=offset)


@api.get("/triage/export", tags=["triage"])
def export_triage() -> JSONResponse:
    records = db.list_triage(limit=100000)
    payload = {
        "version": 1,
        "exported_at": db.utcnow(),
        "records": [
            {
                key: record.get(key)
                for key in ("fingerprint", "rule_id", "file", "line", "status", "note", "author")
            }
            for record in records
        ],
    }
    return JSONResponse(
        payload,
        headers={"Content-Disposition": 'attachment; filename="sast-triage.json"'},
    )


@api.post("/triage/import", tags=["triage"])
def import_triage(payload: TriageImport) -> dict:
    invalid = sorted({item.status for item in payload.records} - set(TRIAGE_STATUSES))
    if invalid:
        raise HTTPException(status_code=400, detail=f"無效的 triage status：{', '.join(invalid)}")

    grouped: dict[tuple[str, str | None, str | None], list] = {}
    for item in payload.records:
        grouped.setdefault((item.status, item.note, item.author), []).append(item)

    records: list[dict] = []
    affected: set[str] = set()
    for (status, note, author), items in grouped.items():
        overrides = {
            item.fingerprint: {"rule_id": item.rule_id, "file": item.file, "line": item.line}
            for item in items
        }
        saved, touched = _apply_triage(
            [item.fingerprint for item in items], status, note, author, overrides
        )
        records.extend(saved)
        affected.update(touched)
    return {"imported": len(records), "affected_scans": sorted(affected), "records": records}


@api.post("/triage/bulk", tags=["triage"])
def bulk_triage(payload: TriageBulkUpdate) -> dict:
    records, affected = _apply_triage(
        payload.fingerprints, payload.status, payload.note, payload.author
    )
    return {"updated": len(records), "affected_scans": affected, "records": records}


@api.put("/triage/{fingerprint}", response_model=TriageRecord, tags=["triage"])
def update_triage(fingerprint: str, payload: TriageUpdate) -> dict:
    records, _ = _apply_triage([fingerprint], payload.status, payload.note, payload.author)
    if not records:
        raise HTTPException(status_code=404, detail="找不到 triage 紀錄")
    return records[0]


@api.delete("/triage/{fingerprint}", status_code=204, tags=["triage"])
def remove_triage(fingerprint: str) -> Response:
    if not db.delete_triage(fingerprint):
        raise HTTPException(status_code=404, detail="找不到 triage 紀錄")
    for scan_id in db.refresh_findings_for([fingerprint]):
        db.recompute_scan_stats(scan_id)
    return Response(status_code=204)


# --------------------------------------------------------------------------
# 健康檢查
# --------------------------------------------------------------------------


@app.get("/health", tags=["meta"])
def health() -> JSONResponse:
    try:
        db.ping()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)

    try:
        engine = select_engine().name
    except Exception as exc:  # noqa: BLE001
        engine = None
        logger.warning("引擎初始化失敗：%s", exc)

    return JSONResponse(
        {
            "status": "ok",
            "engine": engine,
            "git": git_source.git_available(),
        }
    )


app.include_router(api)


# --------------------------------------------------------------------------
# Web UI
# --------------------------------------------------------------------------


def _index_response(request: Request, error: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "scans": db.list_scans(limit=50),
            "engines": describe_engines(),
            "total": db.count_scans(),
            "error": error,
        },
        status_code=status_code,
    )


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request):
    return _index_response(request)


@app.post("/ui/scans", include_in_schema=False)
def ui_create_scan(
    request: Request,
    file: UploadFile | None = File(default=None),
    repo_url: str | None = Form(default=None),
):
    if repo_url is not None and not repo_url.strip():
        repo_url = None
    if file is not None and file.filename == "":
        file = None

    if (file is None) == (repo_url is None):
        return _index_response(request, "請擇一提供 ZIP 檔或 Git repo URL", status_code=400)

    try:
        if file is not None:
            scan_id = services.create_scan_from_upload(file.file, file.filename)
        else:
            scan_id = services.create_scan_from_repo(repo_url or "")
    except ScanInputError as exc:
        return _index_response(request, str(exc), status_code=400)

    return RedirectResponse(url=f"/ui/scans/{scan_id}", status_code=303)


@app.get("/ui/scans/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def ui_scan_detail(request: Request, scan_id: str, show_suppressed: bool = False):
    scan = db.get_scan(scan_id)
    if scan is None:
        return _index_response(request, "找不到掃描", status_code=404)
    findings = db.get_findings(scan_id, limit=1000, include_suppressed=show_suppressed)
    stored_language_risk = (scan.stats or {}).get("language_risk")
    language_findings = (
        findings
        if isinstance(stored_language_risk, dict)
        else db.get_findings(scan_id, limit=5000, include_suppressed=False)
    )
    language_stats, language_risk = _language_data(scan, language_findings)
    suppressed_count = db.count_findings(scan_id) - db.count_findings(
        scan_id, include_suppressed=False
    )
    return templates.TemplateResponse(
        request=request,
        name="scan.html",
        context={
            "scan": scan,
            "findings": findings,
            "total_findings": db.count_findings(
                scan_id, include_suppressed=show_suppressed
            ),
            "suppressed_count": suppressed_count,
            "show_suppressed": show_suppressed,
            "triage_statuses": TRIAGE_STATUSES,
            "triage_labels": TRIAGE_STATUS_LABELS,
            "severities": SEVERITIES,
            "language_stats": language_stats,
            "language_risk": language_risk,
        },
    )


@app.post("/ui/scans/{scan_id}/triage", include_in_schema=False)
def ui_triage_finding(
    request: Request,
    scan_id: str,
    fingerprint: str = Form(...),
    status: str = Form(default=""),
    note: str = Form(default=""),
    next: str = Form(default=""),
):
    scan = db.get_scan(scan_id)
    if scan is None:
        return _index_response(request, "找不到掃描", status_code=404)

    if status == "":
        if db.delete_triage(fingerprint):
            for affected in db.refresh_findings_for([fingerprint]):
                db.recompute_scan_stats(affected)
    else:
        if status not in TRIAGE_STATUSES:
            raise HTTPException(status_code=400, detail=f"無效的 triage status：{status}")
        _apply_triage([fingerprint], status, note.strip() or None, None)

    target = next if next.startswith(f"/ui/scans/{scan_id}") else f"/ui/scans/{scan_id}"
    return RedirectResponse(url=target, status_code=303)


@app.get("/ui/scans/{scan_id}/sarif", include_in_schema=False)
def ui_scan_sarif(scan_id: str) -> JSONResponse:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="找不到掃描")
    findings = db.get_findings(scan_id, limit=5000)
    sarif = scan_to_sarif(_scan_with_language_stats(scan, findings), findings)
    return JSONResponse(
        sarif,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="sast-{scan_id}.sarif"'},
    )


@app.post("/ui/scans/{scan_id}/delete", include_in_schema=False)
def ui_delete_scan(scan_id: str):
    services.delete_scan(scan_id)
    return RedirectResponse(url="/", status_code=303)


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)
