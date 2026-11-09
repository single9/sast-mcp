"""程序內背景 worker（ThreadPoolExecutor）。

僅適用單一 uvicorn worker 的部署；多 worker 請改用 Celery/RQ 等外部佇列。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from .config import get_settings
from .scanner import run_scan

logger = logging.getLogger(__name__)

_executor: ThreadPoolExecutor | None = None
_lock = threading.Lock()


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=get_settings().max_workers,
                thread_name_prefix="sast-scan",
            )
        return _executor


def enqueue(scan_id: str) -> None:
    _get_executor().submit(run_scan, scan_id)


def shutdown_worker() -> None:
    global _executor
    with _lock:
        if _executor is not None:
            _executor.shutdown(wait=False, cancel_futures=True)
            _executor = None
