"""MCP server 設定。

MCP server 是獨立程序，透過 HTTP 呼叫 SAST 服務；因此這裡只讀取
MCP 自身的連線設定，掃描上限則沿用 SAST 服務的環境變數。
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_paths(name: str) -> tuple[Path, ...]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ()
    roots: list[Path] = []
    for item in raw.split(os.pathsep):
        item = item.strip()
        if not item:
            continue
        try:
            roots.append(Path(item).expanduser().resolve())
        except OSError:
            continue
    return tuple(roots)


@dataclass(frozen=True)
class McpSettings:
    base_url: str
    api_key: str | None
    request_timeout_sec: float
    allowed_roots: tuple[Path, ...]
    max_upload_bytes: int
    max_extract_bytes: int
    max_files: int
    max_file_bytes: int
    transport: str
    host: str
    port: int
    export_dir: Path
    default_wait_timeout_sec: int

    @property
    def max_upload_mb(self) -> int:
        return self.max_upload_bytes // (1024 * 1024)


@lru_cache(maxsize=1)
def get_mcp_settings() -> McpSettings:
    export_raw = os.environ.get("SAST_MCP_EXPORT_DIR", "").strip()
    export_dir = (
        Path(export_raw).expanduser()
        if export_raw
        else Path(tempfile.gettempdir()) / "sast-mcp"
    )
    return McpSettings(
        base_url=os.environ.get("SAST_BASE_URL", "http://127.0.0.1:8000").strip().rstrip("/"),
        api_key=os.environ.get("SAST_API_KEY", "").strip() or None,
        request_timeout_sec=max(1.0, _env_float("SAST_MCP_TIMEOUT_SEC", 30.0)),
        allowed_roots=_env_paths("SAST_MCP_ALLOWED_ROOTS"),
        max_upload_bytes=max(1, _env_int("SAST_MAX_UPLOAD_MB", 50)) * 1024 * 1024,
        max_extract_bytes=max(1, _env_int("SAST_MAX_EXTRACT_MB", 200)) * 1024 * 1024,
        max_files=max(1, _env_int("SAST_MAX_FILES", 20000)),
        max_file_bytes=max(1, _env_int("SAST_MAX_FILE_MB", 2)) * 1024 * 1024,
        transport=os.environ.get("SAST_MCP_TRANSPORT", "stdio").strip().lower() or "stdio",
        host=os.environ.get("SAST_MCP_HOST", "127.0.0.1").strip() or "127.0.0.1",
        port=_env_int("SAST_MCP_PORT", 8001),
        export_dir=export_dir,
        default_wait_timeout_sec=max(1, _env_int("SAST_MCP_WAIT_TIMEOUT_SEC", 180)),
    )


def reset_mcp_settings_cache() -> None:
    get_mcp_settings.cache_clear()
