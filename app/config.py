"""服務設定：全部由環境變數覆寫，方便容器化部署。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

# 掃描時一律忽略的目錄（第三方依賴、版本控制、建置產物）
EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "out",
        "target",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".next",
        ".nuxt",
        "coverage",
        "htmlcov",
        ".idea",
        ".vs",
        "bin",
        "obj",
    }
)

# 二進位／壓縮檔等不需要逐行掃描的副檔名
SKIP_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".svgz",
        ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
        ".class", ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a",
        ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg", ".webm",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".db", ".sqlite", ".sqlite3",
    }
)

SEVERITIES = ("critical", "high", "medium", "low", "info")
SCAN_STATUSES = ("queued", "running", "completed", "failed")

# Triage 狀態：把人工判讀結果保存下來，避免同一批誤報每次掃描都要重看。
# false_positive / accepted_risk / wontfix 會抑制 finding（不列入統計與摘要）；
# fixed 代表已修補，若之後又出現會標成 regressed；needs_review 不抑制。
TRIAGE_STATUSES = (
    "false_positive",
    "accepted_risk",
    "wontfix",
    "fixed",
    "needs_review",
)
SUPPRESSED_TRIAGE_STATUSES = frozenset({"false_positive", "accepted_risk", "wontfix"})
INLINE_IGNORE_STATUS = "inline_ignored"
TRIAGE_STATUS_LABELS = {
    "false_positive": "誤報",
    "accepted_risk": "接受風險",
    "wontfix": "不修補",
    "fixed": "已修補",
    "needs_review": "待確認",
    INLINE_IGNORE_STATUS: "原始碼忽略",
}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> tuple[str, ...]:
    """逗號分隔的設定值；保留順序並去除重複。"""
    items: list[str] = []
    for part in os.environ.get(name, "").split(","):
        value = part.strip()
        if value and value not in items:
            items.append(value)
    return tuple(items)


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    rules_dir: Path
    engine: str
    semgrep_config: str | None
    semgrep_extra_configs: tuple[str, ...]
    semgrep_bin: str
    max_upload_mb: int
    max_extract_mb: int
    max_files: int
    max_file_mb: int
    scan_timeout_sec: int
    git_timeout_sec: int
    max_workers: int
    api_key: str | None
    allow_git_sources: bool
    osv_enabled: bool
    osv_api_url: str
    osv_timeout_sec: int
    osv_max_packages: int
    supply_chain_enabled: bool

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sast.db"

    @property
    def workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_extract_bytes(self) -> int:
        return self.max_extract_mb * 1024 * 1024

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    data_dir = Path(os.environ.get("SAST_DATA_DIR", str(PROJECT_DIR / "data"))).expanduser()
    semgrep_config = os.environ.get("SAST_SEMGREP_CONFIG", "").strip() or None
    return Settings(
        data_dir=data_dir,
        rules_dir=BASE_DIR / "rules",
        engine=os.environ.get("SAST_ENGINE", "auto").strip().lower(),
        semgrep_config=semgrep_config,
        semgrep_extra_configs=_env_list("SAST_SEMGREP_EXTRA_CONFIGS"),
        semgrep_bin=os.environ.get("SAST_SEMGREP_BIN", "semgrep").strip() or "semgrep",
        max_upload_mb=_env_int("SAST_MAX_UPLOAD_MB", 50),
        max_extract_mb=_env_int("SAST_MAX_EXTRACT_MB", 200),
        max_files=_env_int("SAST_MAX_FILES", 20000),
        max_file_mb=_env_int("SAST_MAX_FILE_MB", 2),
        scan_timeout_sec=_env_int("SAST_SCAN_TIMEOUT_SEC", 300),
        git_timeout_sec=_env_int("SAST_GIT_TIMEOUT_SEC", 120),
        max_workers=max(1, _env_int("SAST_MAX_WORKERS", 2)),
        api_key=os.environ.get("SAST_API_KEY", "").strip() or None,
        allow_git_sources=_env_bool("SAST_ALLOW_GIT_SOURCES", True),
        osv_enabled=_env_bool("SAST_OSV_ENABLED", True),
        osv_api_url=os.environ.get("SAST_OSV_API_URL", "https://api.osv.dev").strip()
        or "https://api.osv.dev",
        osv_timeout_sec=max(1, _env_int("SAST_OSV_TIMEOUT_SEC", 20)),
        osv_max_packages=max(1, _env_int("SAST_OSV_MAX_PACKAGES", 1000)),
        supply_chain_enabled=_env_bool("SAST_SUPPLY_CHAIN_ENABLED", True),
    )


def reset_settings_cache() -> None:
    """測試或動態調整設定時使用。"""
    get_settings.cache_clear()
