"""可預期的使用者輸入錯誤，對應 HTTP 400。"""

from __future__ import annotations


class ScanInputError(ValueError):
    """掃描來源不合法（格式、大小、路徑、URL 等）。"""


class EngineError(RuntimeError):
    """偵測引擎執行失敗。"""
