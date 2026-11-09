"""SAST REST API 的非同步客戶端。"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import httpx

from .config import get_mcp_settings

_MAX_FINDINGS_WINDOW = 5000


class SastError(RuntimeError):
    """SAST 服務連線或 API 錯誤。"""


class SastClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings = get_mcp_settings()
        self.base_url = (base_url or settings.base_url).rstrip("/")
        self.api_key = settings.api_key if api_key is None else api_key
        self.timeout = timeout if timeout is not None else settings.request_timeout_sec

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=self.timeout,
            transport=transport,
            follow_redirects=False,
        )

    async def __aenter__(self) -> "SastClient":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise SastError(
                f"SAST 服務逾時（{self.timeout:.0f} 秒）：{self.base_url}{path}"
            ) from exc
        except httpx.HTTPError as exc:
            raise SastError(
                f"無法連線至 SAST 服務 {self.base_url}。請先啟動服務"
                "（`make run` 或 `docker compose up -d`），並確認 SAST_BASE_URL 正確。"
                f" 原始錯誤：{exc}"
            ) from exc

        if response.status_code >= 400:
            detail = ""
            try:
                data = response.json()
                detail = str(data.get("detail") or data)
            except ValueError:
                detail = (response.text or "").strip()
            raise SastError(
                f"SAST API 回應 {response.status_code}"
                + (f"：{detail[:800]}" if detail else "")
            )

        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise SastError(f"SAST API 回傳非 JSON 內容（{path}）") from exc

    # ------------------------------------------------------------------
    # Meta
    # ------------------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        try:
            response = await self._client.get("/health")
        except httpx.TimeoutException as exc:
            raise SastError(f"健康檢查逾時：{self.base_url}/health") from exc
        except httpx.HTTPError as exc:
            raise SastError(
                f"無法連線至 SAST 服務 {self.base_url}。請先啟動服務"
                "（`make run` 或 `docker compose up -d`）。"
                f" 原始錯誤：{exc}"
            ) from exc

        try:
            data = response.json()
        except ValueError:
            data = {"status": "error", "detail": (response.text or "").strip()}
        data["http_status"] = response.status_code
        return data

    async def engines(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/api/v1/engines")
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    async def create_scan_from_zip(self, path: Path, filename: str | None = None) -> dict[str, Any]:
        with path.open("rb") as handle:
            files = {"file": (filename or path.name, handle, "application/zip")}
            return await self._request("POST", "/api/v1/scans", files=files)

    async def create_scan_from_git(self, repo_url: str) -> dict[str, Any]:
        return await self._request("POST", "/api/v1/scans", data={"repo_url": repo_url})

    async def list_scans(
        self, limit: int = 20, offset: int = 0, status: str | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        data = await self._request("GET", "/api/v1/scans", params=params)
        return data if isinstance(data, list) else []

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/api/v1/scans/{scan_id}")

    async def fetch_findings(
        self,
        scan_id: str,
        severities: list[str] | None = None,
        limit: int = _MAX_FINDINGS_WINDOW,
        include_suppressed: bool = True,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "limit": min(max(limit, 1), _MAX_FINDINGS_WINDOW),
            "include_suppressed": str(include_suppressed).lower(),
        }
        if severities:
            params["severity"] = ",".join(severities)
        data = await self._request("GET", f"/api/v1/scans/{scan_id}/findings", params=params)
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    async def list_triage(
        self,
        status: str | None = None,
        rule_id: str | None = None,
        file: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if rule_id:
            params["rule_id"] = rule_id
        if file:
            params["file"] = file
        data = await self._request("GET", "/api/v1/triage", params=params)
        return data if isinstance(data, list) else []

    async def bulk_triage(
        self,
        fingerprints: list[str],
        status: str,
        note: str | None = None,
        author: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "fingerprints": fingerprints,
            "status": status,
            "note": note,
            "author": author,
        }
        data = await self._request("POST", "/api/v1/triage/bulk", json=payload)
        return data if isinstance(data, dict) else {}

    async def delete_triage(self, fingerprint: str) -> None:
        await self._request("DELETE", f"/api/v1/triage/{fingerprint}")

    async def export_triage(self) -> dict[str, Any]:
        data = await self._request("GET", "/api/v1/triage/export")
        return data if isinstance(data, dict) else {}

    async def import_triage(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        data = await self._request("POST", "/api/v1/triage/import", json={"records": records})
        return data if isinstance(data, dict) else {}

    async def get_languages(self, scan_id: str) -> dict[str, Any]:
        data = await self._request("GET", f"/api/v1/scans/{scan_id}/languages")
        return data if isinstance(data, dict) else {}

    async def get_sarif(self, scan_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/api/v1/scans/{scan_id}/sarif")

    async def delete_scan(self, scan_id: str) -> None:
        await self._request("DELETE", f"/api/v1/scans/{scan_id}")

    async def wait_for_scan(
        self,
        scan_id: str,
        timeout_sec: float = 180.0,
        poll_interval_sec: float = 2.0,
    ) -> dict[str, Any]:
        started = time.monotonic()
        deadline = started + max(0.0, timeout_sec)
        polls = 0
        last: dict[str, Any] = {}

        while True:
            last = await self.get_scan(scan_id)
            polls += 1
            if last.get("status") in {"completed", "failed"}:
                return {
                    "scan": last,
                    "timed_out": False,
                    "elapsed_sec": round(time.monotonic() - started, 2),
                    "polls": polls,
                }

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "scan": last,
                    "timed_out": True,
                    "elapsed_sec": round(time.monotonic() - started, 2),
                    "polls": polls,
                }
            await asyncio.sleep(min(max(0.5, poll_interval_sec), remaining))
