"""自建的跨函式／跨檔案 taint 引擎。"""

from .runner import scan_taint

__all__ = ["scan_taint"]
