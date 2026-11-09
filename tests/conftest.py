"""測試共用設定：使用暫存資料目錄與內建 regex 引擎，避免依賴 Semgrep。"""

from __future__ import annotations

import pytest

from app.config import reset_settings_cache


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SAST_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SAST_ENGINE", "regex")
    monkeypatch.setenv("SAST_API_KEY", "")
    monkeypatch.setenv("SAST_ALLOW_GIT_SOURCES", "false")
    monkeypatch.setenv("SAST_OSV_ENABLED", "false")
    monkeypatch.setenv("SAST_MAX_UPLOAD_MB", "5")
    monkeypatch.setenv("SAST_MAX_EXTRACT_MB", "10")
    monkeypatch.setenv("SAST_MAX_FILES", "100")
    reset_settings_cache()
    yield
    reset_settings_cache()
