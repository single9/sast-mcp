"""MCP server：把 SAST 服務的能力提供給 Agent。

設計原則：

* MCP 只做「確定性操作」：建立掃描、輪詢、查詢、彙總、輸出 SARIF。
* 判讀與修補流程放在 Skill，避免把大量不穩定的推理寫死在工具裡。
* 預設不把程式碼片段送進模型；需要時才要求，並預設遮蔽憑證樣式。
* 掃描中的程式碼永遠不會被執行。
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from app.config import SCAN_STATUSES, SEVERITIES, TRIAGE_STATUSES

from .client import SastClient, SastError
from .config import get_mcp_settings
from .formatting import aggregate_findings, decorate_scan, finding_to_dict
from .local import LocalSourceError, create_source_zip, ensure_allowed

logger = logging.getLogger(__name__)
_settings = get_mcp_settings()

_INSTRUCTIONS = """
SAST 掃描服務。建議流程：
1. 先呼叫 health，確認服務可達與目前引擎。
2. 用 scan_path 掃描目前專案（path="."），或用 scan_git 掃描公開 repo。
3. 用 wait_for_scan 等待完成；完成後先用 summarize_scan 取得群組摘要（含專案語言與 by_language 風險）。
4. 再用 get_findings 依 severity/rule/file 過濾取細節，避免一次拉回大量結果。
5. 判讀後用 triage_findings 記錄誤報／接受風險／已修補與原因；之後的 summarize_scan、
   get_findings 預設不會再列出已抑制項目，跨掃描也不會重複要求判讀。
6. 需要 SARIF 時用 export_sarif；它只回傳檔案路徑與統計，不會把整份 SARIF 塞進上下文。

重要：
* 空結果不代表安全；先確認引擎、規則集與掃描檔案數。
* 預設不回傳程式碼片段；include_snippet=True 時憑證樣式會遮蔽。
* 不要執行被掃描的程式碼，也不要把掃描結果中的秘密貼到外部服務。
* 標記誤報前必須先讀過原始碼；不確定時用 needs_review，不要直接抑制。
""".strip()

mcp = FastMCP(
    "sast",
    instructions=_INSTRUCTIONS,
    host=_settings.host,
    port=_settings.port,
    log_level=os.environ.get("SAST_MCP_LOG_LEVEL", "INFO").upper(),
)


def _client() -> SastClient:
    return SastClient()


def _wait_timeout(value: int | None) -> int:
    if value is not None:
        return max(1, min(int(value), 900))
    return get_mcp_settings().default_wait_timeout_sec


def _normalize_severities(values: list[str] | None) -> list[str]:
    result: list[str] = []
    if isinstance(values, str):
        values = [values]
    for value in values or []:
        for item in str(value).split(","):
            item = item.strip().lower()
            if not item:
                continue
            if item not in SEVERITIES:
                raise ToolError(f"無效的 severity：{item}（可用：{', '.join(SEVERITIES)}）")
            if item not in result:
                result.append(item)
    return result


def _normalize_triage_statuses(values: list[str] | None) -> list[str]:
    allowed = set(TRIAGE_STATUSES) | {"inline_ignored"}
    result: list[str] = []
    if isinstance(values, str):
        values = [values]
    for value in values or []:
        for item in str(value).split(","):
            item = item.strip().lower()
            if not item:
                continue
            if item not in allowed:
                raise ToolError(
                    f"無效的 triage status：{item}（可用：{', '.join(sorted(allowed))}）"
                )
            if item not in result:
                result.append(item)
    return result


def _scan_summary(scan: dict[str, Any], base_url: str) -> dict[str, Any]:
    data = decorate_scan(scan, base_url)
    return {
        key: data.get(key)
        for key in (
            "id",
            "status",
            "source_type",
            "source_ref",
            "engine",
            "created_at",
            "started_at",
            "finished_at",
            "error",
            "stats",
            "severity_counts",
            "ui_url",
            "sarif_url",
        )
    }


def _next_step(scan: dict[str, Any]) -> str:
    status = scan.get("status")
    if status == "completed":
        return "呼叫 summarize_scan 取得摘要，再用 get_findings 過濾細節。"
    if status == "failed":
        return "掃描失敗；讀取 scan.error，修正來源或設定後重新建立掃描。"
    return "掃描仍在進行；再次呼叫 wait_for_scan。"


def _scan_result(
    scan: dict[str, Any],
    base_url: str,
    *,
    source: dict[str, Any],
    wait_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "scan": decorate_scan(scan, base_url),
        "source": source,
        "next": _next_step(scan),
    }
    if wait_result is not None:
        result["wait"] = {
            "timed_out": wait_result.get("timed_out"),
            "elapsed_sec": wait_result.get("elapsed_sec"),
            "polls": wait_result.get("polls"),
        }
    return result


# ----------------------------------------------------------------------
# Meta
# ----------------------------------------------------------------------


@mcp.tool(
    name="health",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
)
async def health() -> dict[str, Any]:
    """檢查 SAST 服務是否可達，並回傳目前引擎與 git 可用性。

    連線失敗時不會拋錯，而是回傳 reachable=false 與啟動提示，方便 Agent 自行修正。
    """

    settings = get_mcp_settings()
    async with _client() as api:
        try:
            health_data = await api.health()
        except SastError as exc:
            return {
                "reachable": False,
                "base_url": settings.base_url,
                "error": str(exc),
                "hint": "啟動服務：`make run` 或 `docker compose up -d`；再確認 SAST_BASE_URL。",
            }

        engines: list[dict[str, Any]] | None = None
        engines_error: str | None = None
        try:
            engines = await api.engines()
        except SastError as exc:
            engines_error = str(exc)

    return {
        "reachable": True,
        "healthy": health_data.get("status") == "ok",
        "base_url": settings.base_url,
        "health": health_data,
        "engines": engines,
        "engines_error": engines_error,
    }


# ----------------------------------------------------------------------
# 建立掃描
# ----------------------------------------------------------------------


@mcp.tool(
    name="scan_path",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
    ),
)
async def scan_path(
    path: Annotated[str, Field(description="本機目錄，相對於 MCP server 的工作目錄；預設為目前專案。")] = ".",
    wait: Annotated[bool, Field(description="建立後是否輪詢到完成（長時間掃描建議分開呼叫 wait_for_scan）。")] = False,
    wait_timeout_sec: Annotated[int | None, Field(description="wait=true 時的等待上限，1-900 秒。", ge=1, le=900)] = None,
    poll_interval_sec: Annotated[float, Field(description="輪詢間隔，0.5-30 秒。", ge=0.5, le=30.0)] = 2.0,
    include_gitignored: Annotated[bool, Field(description="Git repo 預設只送 tracked+untracked（排除 ignored）；設 true 改走完整目錄走訪。")] = False,
) -> dict[str, Any]:
    """掃描本機目錄：自動打包成 ZIP 後上傳到 SAST 服務。

    Git repo 會用 `git ls-files` 排除 node_modules、build 等 ignored 內容；
    非 Git 目錄則套用服務內建的排除規則。符號連結不會被送出。
    """

    try:
        archive = create_source_zip(path, include_gitignored=include_gitignored)
    except LocalSourceError as exc:
        raise ToolError(str(exc)) from exc

    try:
        async with _client() as api:
            try:
                scan = await api.create_scan_from_zip(archive.path, archive.filename)
            except SastError as exc:
                raise ToolError(str(exc)) from exc
            source = archive.summary()
    finally:
        archive.cleanup()

    wait_result: dict[str, Any] | None = None
    if wait:
        async with _client() as api:
            try:
                wait_result = await api.wait_for_scan(
                    scan["id"], timeout_sec=_wait_timeout(wait_timeout_sec), poll_interval_sec=poll_interval_sec
                )
            except SastError as exc:
                raise ToolError(str(exc)) from exc
            scan = wait_result["scan"]

    return _scan_result(scan, get_mcp_settings().base_url, source=source, wait_result=wait_result)


@mcp.tool(
    name="scan_zip",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
    ),
)
async def scan_zip(
    zip_path: Annotated[str, Field(description="本機 .zip 檔路徑（不會修改或刪除原檔）。")],
    wait: Annotated[bool, Field(description="建立後是否輪詢到完成。")] = False,
    wait_timeout_sec: Annotated[int | None, Field(description="wait=true 時的等待上限，1-900 秒。", ge=1, le=900)] = None,
    poll_interval_sec: Annotated[float, Field(description="輪詢間隔，0.5-30 秒。", ge=0.5, le=30.0)] = 2.0,
) -> dict[str, Any]:
    """上傳本機 ZIP 檔並建立掃描。"""

    settings = get_mcp_settings()
    try:
        source_path = ensure_allowed(Path(zip_path))
    except LocalSourceError as exc:
        raise ToolError(str(exc)) from exc
    if not source_path.is_file():
        raise ToolError(f"不是檔案：{source_path}")
    if source_path.suffix.lower() != ".zip":
        raise ToolError("請提供 .zip 檔")
    if source_path.stat().st_size > settings.max_upload_bytes:
        raise ToolError(f"ZIP 超過上傳上限 {settings.max_upload_mb} MB")

    async with _client() as api:
        try:
            scan = await api.create_scan_from_zip(source_path)
        except SastError as exc:
            raise ToolError(str(exc)) from exc
        wait_result: dict[str, Any] | None = None
        if wait:
            wait_result = await api.wait_for_scan(
                scan["id"], timeout_sec=_wait_timeout(wait_timeout_sec), poll_interval_sec=poll_interval_sec
            )
            scan = wait_result["scan"]

    source = {"path": str(source_path), "bytes": source_path.stat().st_size, "filename": source_path.name}
    return _scan_result(scan, settings.base_url, source=source, wait_result=wait_result)


@mcp.tool(
    name="scan_git",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
    ),
)
async def scan_git(
    repo_url: Annotated[str, Field(description="公開的 http(s) Git repo URL；不支援 ssh 或帳密。")],
    wait: Annotated[bool, Field(description="建立後是否輪詢到完成。")] = False,
    wait_timeout_sec: Annotated[int | None, Field(description="wait=true 時的等待上限，1-900 秒。", ge=1, le=900)] = None,
    poll_interval_sec: Annotated[float, Field(description="輪詢間隔，0.5-30 秒。", ge=0.5, le=30.0)] = 2.0,
) -> dict[str, Any]:
    """掃描公開 Git repo（服務端會 shallow clone）。"""

    settings = get_mcp_settings()
    async with _client() as api:
        try:
            scan = await api.create_scan_from_git(repo_url)
        except SastError as exc:
            raise ToolError(str(exc)) from exc
        wait_result: dict[str, Any] | None = None
        if wait:
            wait_result = await api.wait_for_scan(
                scan["id"], timeout_sec=_wait_timeout(wait_timeout_sec), poll_interval_sec=poll_interval_sec
            )
            scan = wait_result["scan"]

    return _scan_result(
        scan,
        settings.base_url,
        source={"repo_url": repo_url},
        wait_result=wait_result,
    )


# ----------------------------------------------------------------------
# 查詢
# ----------------------------------------------------------------------


@mcp.tool(
    name="wait_for_scan",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
)
async def wait_for_scan(
    scan_id: Annotated[str, Field(description="掃描 ID。")],
    timeout_sec: Annotated[int | None, Field(description="等待上限，1-900 秒；預設 180。", ge=1, le=900)] = None,
    poll_interval_sec: Annotated[float, Field(description="輪詢間隔，0.5-30 秒。", ge=0.5, le=30.0)] = 2.0,
) -> dict[str, Any]:
    """輪詢掃描直到 completed/failed 或逾時；逾時會回傳最後狀態。"""

    async with _client() as api:
        try:
            result = await api.wait_for_scan(
                scan_id, timeout_sec=_wait_timeout(timeout_sec), poll_interval_sec=poll_interval_sec
            )
        except SastError as exc:
            raise ToolError(str(exc)) from exc
        scan = result["scan"]
        return {
            **result,
            "scan": decorate_scan(scan, api.base_url),
            "next": _next_step(scan),
        }


@mcp.tool(
    name="get_scan",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
)
async def get_scan(scan_id: Annotated[str, Field(description="掃描 ID。")]) -> dict[str, Any]:
    """取得單一掃描的狀態、統計與 UI/API 連結。"""

    async with _client() as api:
        try:
            scan = await api.get_scan(scan_id)
        except SastError as exc:
            raise ToolError(str(exc)) from exc
        return {"scan": decorate_scan(scan, api.base_url), "next": _next_step(scan)}


@mcp.tool(
    name="list_scans",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
)
async def list_scans(
    limit: Annotated[int, Field(description="回傳筆數，1-200。", ge=1, le=200)] = 20,
    offset: Annotated[int, Field(description="略過筆數。", ge=0)] = 0,
    status: Annotated[str | None, Field(description="可選：queued/running/completed/failed。")] = None,
) -> dict[str, Any]:
    """列出最近的掃描。"""

    if status is not None and status not in SCAN_STATUSES:
        raise ToolError(f"無效的 status：{status}（可用：{', '.join(SCAN_STATUSES)}）")

    async with _client() as api:
        try:
            scans = await api.list_scans(limit=limit, offset=offset, status=status)
        except SastError as exc:
            raise ToolError(str(exc)) from exc
        return {
            "count": len(scans),
            "offset": offset,
            "scans": [decorate_scan(scan, api.base_url) for scan in scans],
        }


@mcp.tool(
    name="get_findings",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
)
async def get_findings(
    scan_id: Annotated[str, Field(description="掃描 ID。")],
    severity: Annotated[list[str] | None, Field(description="severity 過濾，例如 ['critical','high']；也可傳 'high,medium'。")] = None,
    rule_id_contains: Annotated[str | None, Field(description="rule id 子字串（不分大小寫）。")] = None,
    file_contains: Annotated[str | None, Field(description="檔案路徑子字串（不分大小寫）。")] = None,
    message_contains: Annotated[str | None, Field(description="訊息子字串（不分大小寫）。")] = None,
    triage_status: Annotated[list[str] | None, Field(description="triage 狀態過濾，例如 ['false_positive','accepted_risk']。")] = None,
    include_suppressed: Annotated[bool, Field(description="是否包含已抑制（誤報／接受風險）的項目；預設 false。")] = False,
    include_snippet: Annotated[bool, Field(description="是否回傳程式碼片段；預設 false，以降低機密外洩與 token 消耗。")] = False,
    redact_secrets: Annotated[bool, Field(description="include_snippet=true 時遮蔽常見憑證樣式；預設 true。")] = True,
    limit: Annotated[int, Field(description="本頁回傳筆數，1-500。", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="略過符合條件的筆數。", ge=0)] = 0,
) -> dict[str, Any]:
    """取得掃描 findings，支援 severity/rule/file/message/triage 過濾與分頁。

    預設不列出已判定誤報／接受風險的項目；需要覆核時設 include_suppressed=true。
    先使用 summarize_scan 看群組，再針對高風險項目呼叫此工具，可避免上下文爆炸。
    """

    severities = _normalize_severities(severity)
    triage_filter = _normalize_triage_statuses(triage_status)
    async with _client() as api:
        try:
            scan = await api.get_scan(scan_id)
            findings = await api.fetch_findings(
                scan_id, severities=severities, limit=5000, include_suppressed=True
            )
        except SastError as exc:
            raise ToolError(str(exc)) from exc

        suppressed_count = sum(1 for finding in findings if finding.get("suppressed"))
        filtered = findings
        if not include_suppressed:
            filtered = [f for f in filtered if not f.get("suppressed")]
        if triage_filter:
            filtered = [f for f in filtered if f.get("triage_status") in triage_filter]
        if rule_id_contains:
            needle = rule_id_contains.lower()
            filtered = [f for f in filtered if needle in str(f.get("rule_id") or "").lower()]
        if file_contains:
            needle = file_contains.lower()
            filtered = [f for f in filtered if needle in str(f.get("file") or "").lower()]
        if message_contains:
            needle = message_contains.lower()
            filtered = [f for f in filtered if needle in str(f.get("message") or "").lower()]

        total = len(filtered)
        page = filtered[offset : offset + limit]
        return {
            "scan_id": scan_id,
            "scan_status": scan.get("status"),
            "scan_severity_counts": scan.get("severity_counts") or {},
            "suppressed_in_scan": suppressed_count,
            "include_suppressed": include_suppressed,
            "total_matched": total,
            "returned": len(page),
            "offset": offset,
            "has_more": offset + len(page) < total,
            "truncated_scan_window": len(findings) >= 5000,
            "snippet_policy": (
                "include_snippet=true, redact_secrets=" + str(redact_secrets)
                if include_snippet
                else "snippets omitted; prefer reading the file locally at file:line"
            ),
            "findings": [
                finding_to_dict(
                    finding,
                    include_snippet=include_snippet,
                    redact_secrets=redact_secrets,
                )
                for finding in page
            ],
            "next": "需要更多細節時調整 offset/limit 或收窄 severity/rule/file 條件。",
        }


@mcp.tool(
    name="summarize_scan",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
)
async def summarize_scan(
    scan_id: Annotated[str, Field(description="掃描 ID。")],
    top: Annotated[int, Field(description="每個群組最多回傳幾項，1-100。", ge=1, le=100)] = 20,
    include_suppressed: Annotated[bool, Field(description="是否把已抑制（誤報／接受風險）的項目計入摘要；預設 false。")] = False,
) -> dict[str, Any]:
    """用群組摘要取代大量 findings，適合掃描後第一步。

    回傳包含 by_language：每個語言的檔案／行數、findings 數、severity 分佈、
    risk_level 與熱門規則，可直接看出哪個語言風險最高。
    by_engine 可區分 semgrep、builtin-regex、osv（依賴漏洞）與 supply-chain。
    預設排除已 triage 抑制的項目，並在 suppressed_findings 回報數量。
    """

    async with _client() as api:
        try:
            scan = await api.get_scan(scan_id)
            all_findings = await api.fetch_findings(scan_id, limit=5000, include_suppressed=True)
        except SastError as exc:
            raise ToolError(str(exc)) from exc

        suppressed_findings = [f for f in all_findings if f.get("suppressed")]
        findings = all_findings if include_suppressed else [
            f for f in all_findings if not f.get("suppressed")
        ]

        stats = scan.get("stats") or {}
        language_stats = stats.get("languages") if isinstance(stats, dict) else None

        # 舊掃描可能沒有 language stats；此時向服務取得即時推導的結果。
        if not (isinstance(language_stats, dict) and language_stats.get("languages")):
            try:
                language_data = await api.get_languages(scan_id)
            except SastError:
                language_data = {}
            if isinstance(language_data, dict) and language_data.get("languages"):
                language_stats = {
                    "primary_language": language_data.get("primary_language"),
                    "primary_language_name": language_data.get("primary_language_name"),
                    "languages": language_data.get("languages"),
                }
                if isinstance(stats, dict):
                    stats["languages"] = language_stats
                    stats["primary_language"] = language_data.get("primary_language")
                    stats["primary_language_name"] = language_data.get("primary_language_name")
                    scan["stats"] = stats

    summary = aggregate_findings(
        findings,
        top=top,
        language_stats=language_stats if isinstance(language_stats, dict) else None,
    )
    return {
        "scan": _scan_summary(scan, api.base_url),
        **summary,
        "include_suppressed": include_suppressed,
        "suppressed_findings": len(suppressed_findings),
        "triage": (scan.get("stats") or {}).get("triage"),
        "dependencies": (scan.get("stats") or {}).get("dependencies"),
        "supply_chain": (scan.get("stats") or {}).get("supply_chain"),
        "truncated_scan_window": len(all_findings) >= 5000,
        "next": (
            "用 get_findings(severity=['critical','high']) 取得高風險細節；"
            "判讀後用 triage_findings 記錄誤報／接受風險，避免下次重複判讀。"
        ),
    }


# ----------------------------------------------------------------------
# Triage：記錄判讀結果，避免每次掃描重複出現同一批誤報
# ----------------------------------------------------------------------


@mcp.tool(
    name="triage_findings",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
async def triage_findings(
    scan_id: Annotated[str, Field(description="掃描 ID。")],
    fingerprints: Annotated[
        list[str],
        Field(description="要標記的 finding fingerprint（由 get_findings 取得），一次最多 1000 筆。", min_length=1, max_length=1000),
    ],
    status: Annotated[
        str,
        Field(description="false_positive、accepted_risk、wontfix、fixed 或 needs_review。"),
    ],
    note: Annotated[str | None, Field(description="判讀原因；會顯示在 UI、API 與 SARIF。", max_length=2000)] = None,
    author: Annotated[str | None, Field(description="記錄者（例如 agent 名稱）。", max_length=200)] = None,
) -> dict[str, Any]:
    """把 findings 標記為誤報／接受風險／不修補／已修補，並保存原因。

    false_positive、accepted_risk、wontfix 會抑制 finding：之後的掃描統計、
    summarize_scan 與 get_findings 預設都不再列出。fixed 代表已修補，若之後
    又出現會標成 regressed。needs_review 只記錄、不抑制。
    """

    if status not in TRIAGE_STATUSES:
        raise ToolError(
            f"無效的 triage status：{status}（可用：{', '.join(TRIAGE_STATUSES)}）"
        )

    async with _client() as api:
        try:
            all_findings = await api.fetch_findings(scan_id, limit=5000, include_suppressed=True)
            known = {finding.get("fingerprint") for finding in all_findings}
            unknown = [fingerprint for fingerprint in fingerprints if fingerprint not in known]
            if unknown:
                raise ToolError(
                    "以下 fingerprint 不在這個掃描中（請先用 get_findings 取得）："
                    + ", ".join(unknown[:5])
                )
            result = await api.bulk_triage(fingerprints, status, note, author)
            scan = await api.get_scan(scan_id)
        except SastError as exc:
            raise ToolError(str(exc)) from exc

    stats = scan.get("stats") or {}
    return {
        "scan_id": scan_id,
        "status": status,
        "updated": result.get("updated", 0),
        "affected_scans": result.get("affected_scans", []),
        "scan_stats": {
            "findings": stats.get("findings"),
            "findings_total": stats.get("findings_total"),
            "suppressed": stats.get("suppressed"),
            "triage": stats.get("triage"),
        },
        "next": "呼叫 summarize_scan 確認已抑制項目不再出現在摘要；需要覆核時設 include_suppressed=true。",
    }


@mcp.tool(
    name="list_triage",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
)
async def list_triage(
    status: Annotated[str | None, Field(description="false_positive、accepted_risk、wontfix、fixed、needs_review。")] = None,
    rule_id_contains: Annotated[str | None, Field(description="rule id 子字串（不分大小寫）。")] = None,
    file_contains: Annotated[str | None, Field(description="檔案路徑子字串（不分大小寫）。")] = None,
    limit: Annotated[int, Field(description="回傳筆數，1-1000。", ge=1, le=1000)] = 50,
    offset: Annotated[int, Field(description="略過筆數。", ge=0)] = 0,
) -> dict[str, Any]:
    """列出已記錄的 triage 判定，可用來確認哪些誤報已被處理過。"""

    if status is not None and status not in TRIAGE_STATUSES:
        raise ToolError(
            f"無效的 triage status：{status}（可用：{', '.join(TRIAGE_STATUSES)}）"
        )
    async with _client() as api:
        try:
            records = await api.list_triage(
                status=status,
                rule_id=rule_id_contains,
                file=file_contains,
                limit=limit,
                offset=offset,
            )
        except SastError as exc:
            raise ToolError(str(exc)) from exc

    return {
        "returned": len(records),
        "limit": limit,
        "offset": offset,
        "records": records,
        "next": "用 delete_triage 移除失效的判定，或重新掃描確認抑制結果。",
    }


@mcp.tool(
    name="delete_triage",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
    ),
)
async def delete_triage(
    fingerprint: Annotated[str, Field(description="要移除的 triage fingerprint。")],
    confirm: Annotated[bool, Field(description="必須明確設為 true 才會刪除。")] = False,
) -> dict[str, Any]:
    """移除 triage 判定；之後該 finding 會重新出現在掃描結果中。"""

    if not confirm:
        raise ToolError("刪除 triage 會讓該 finding 重新出現；請設定 confirm=true。")

    async with _client() as api:
        try:
            await api.delete_triage(fingerprint)
        except SastError as exc:
            raise ToolError(str(exc)) from exc
    return {"deleted": True, "fingerprint": fingerprint, "base_url": api.base_url}


@mcp.tool(
    name="export_triage",
    annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True, openWorldHint=False),
)
async def export_triage(
    output_path: Annotated[str | None, Field(description="輸出 JSON 路徑；預設寫到 SAST_MCP_EXPORT_DIR。")] = None,
    overwrite: Annotated[bool, Field(description="檔案已存在時是否覆寫。")] = False,
) -> dict[str, Any]:
    """把 triage 判定匯出成 JSON，可提交進 repo 當 baseline 或搬到另一台機器。"""

    settings = get_mcp_settings()
    async with _client() as api:
        try:
            payload = await api.export_triage()
        except SastError as exc:
            raise ToolError(str(exc)) from exc

    target = Path(output_path).expanduser() if output_path else settings.export_dir / "sast-triage.json"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        ensure_allowed(target.parent)
    except (OSError, LocalSourceError) as exc:
        raise ToolError(str(exc)) from exc

    if target.exists() and not overwrite:
        raise ToolError(f"檔案已存在：{target}；需要覆寫請設 overwrite=true。")

    records = payload.get("records") or []
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "path": str(target),
        "records": len(records),
        "version": payload.get("version", 1),
        "next": "把這個檔案提交進 repo；新機器用 import_triage 匯入即可沿用判定。",
    }


@mcp.tool(
    name="import_triage",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
async def import_triage(
    path: Annotated[str, Field(description="要匯入的 triage JSON 路徑（export_triage 的輸出）。")],
) -> dict[str, Any]:
    """從 JSON 匯入 triage 判定；相同 fingerprint 以檔案內容覆蓋。"""

    try:
        source = ensure_allowed(Path(path).expanduser())
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError, LocalSourceError) as exc:
        raise ToolError(f"無法讀取 triage 檔：{exc}") from exc

    records = raw.get("records") if isinstance(raw, dict) else raw
    if not isinstance(records, list) or not records:
        raise ToolError("triage 檔格式錯誤：需要 {\"records\": [...]} 或非空陣列。")

    invalid = sorted(
        {
            str(record.get("status"))
            for record in records
            if isinstance(record, dict) and record.get("status") not in TRIAGE_STATUSES
        }
    )
    if invalid:
        raise ToolError(f"triage 檔含無效 status：{', '.join(invalid)}")

    async with _client() as api:
        try:
            result = await api.import_triage(records)
        except SastError as exc:
            raise ToolError(str(exc)) from exc

    return {
        "path": str(source),
        "imported": result.get("imported", 0),
        "affected_scans": result.get("affected_scans", []),
        "next": "重新掃描或呼叫 summarize_scan，確認已抑制項目不再出現。",
    }


# ----------------------------------------------------------------------
# 輸出與刪除
# ----------------------------------------------------------------------


@mcp.tool(
    name="export_sarif",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
async def export_sarif(
    scan_id: Annotated[str, Field(description="掃描 ID。")],
    output_path: Annotated[str | None, Field(description="選填輸出路徑；預設寫到 SAST_MCP_EXPORT_DIR 或系統暫存目錄。")] = None,
    overwrite: Annotated[bool, Field(description="若指定檔案已存在，是否覆寫。")] = False,
) -> dict[str, Any]:
    """把掃描結果寫成 SARIF 檔，回傳路徑與統計（不會回傳整份 SARIF 內容）。"""

    settings = get_mcp_settings()
    async with _client() as api:
        try:
            scan = await api.get_scan(scan_id)
            if scan.get("status") != "completed":
                raise ToolError(f"掃描尚未完成（status={scan.get('status')}），請先 wait_for_scan。")
            sarif = await api.get_sarif(scan_id)
        except SastError as exc:
            raise ToolError(str(exc)) from exc

    if output_path:
        target = Path(output_path).expanduser()
        if not target.is_absolute():
            target = Path.cwd() / target
        if output_path.endswith(("/", os.sep)):
            target = target / f"sast-{scan_id}.sarif"
        elif target.exists() and target.is_dir():
            target = target / f"sast-{scan_id}.sarif"
        if not target.suffix:
            target = target.with_suffix(".sarif")
        try:
            target = ensure_allowed(target, must_exist=False)
        except LocalSourceError as exc:
            raise ToolError(str(exc)) from exc
        if target.exists() and not overwrite:
            raise ToolError(f"檔案已存在：{target}（設定 overwrite=true 可覆寫）")
    else:
        target = settings.export_dir / f"sast-{scan_id}.sarif"

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(sarif, ensure_ascii=False, indent=2)
        target.write_text(payload, encoding="utf-8")
    except OSError as exc:
        raise ToolError(f"無法寫入 SARIF：{exc}") from exc

    runs = sarif.get("runs") or []
    results = sum(len(run.get("results") or []) for run in runs)
    rule_ids: list[str] = []
    for run in runs:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        for rule in rules:
            rule_id = rule.get("id")
            if rule_id and rule_id not in rule_ids:
                rule_ids.append(rule_id)

    return {
        "scan_id": scan_id,
        "path": str(target),
        "bytes": target.stat().st_size,
        "runs": len(runs),
        "results": results,
        "rules": rule_ids[:100],
        "rule_count": len(rule_ids),
        "next": "可用 GitHub Code Scanning 或 SARIF viewer 檢視；不要把整份檔案讀進模型上下文。",
    }


@mcp.tool(
    name="delete_scan",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
    ),
)
async def delete_scan(
    scan_id: Annotated[str, Field(description="掃描 ID。")],
    confirm: Annotated[bool, Field(description="必須明確設為 true 才會刪除掃描與工作區。")] = False,
) -> dict[str, Any]:
    """刪除掃描紀錄與工作區（不可復原）。"""

    if not confirm:
        raise ToolError("刪除不可復原；請設定 confirm=true 後再呼叫。")

    async with _client() as api:
        try:
            await api.delete_scan(scan_id)
        except SastError as exc:
            raise ToolError(str(exc)) from exc
        return {"deleted": True, "scan_id": scan_id, "base_url": api.base_url}


# ----------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------


def main() -> None:
    settings = get_mcp_settings()
    transport = settings.transport
    if transport in {"http", "streamable_http"}:
        transport = "streamable-http"
    if transport not in {"stdio", "sse", "streamable-http"}:
        raise SystemExit(
            f"不支援的 SAST_MCP_TRANSPORT={settings.transport!r}；"
            "可用 stdio、sse、streamable-http"
        )

    logging.basicConfig(
        level=os.environ.get("SAST_MCP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logger.info("SAST MCP server 啟動：transport=%s base_url=%s", transport, settings.base_url)
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
