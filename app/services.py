"""建立掃描的高階流程，供 API 與 Web UI 共用。"""

from __future__ import annotations

import uuid
import zipfile
from pathlib import Path
from typing import BinaryIO

from . import db, git_source, workspace
from .config import get_settings
from .errors import ScanInputError
from .worker import enqueue


def _new_scan_id() -> str:
    return uuid.uuid4().hex


def create_scan_from_upload(stream: BinaryIO, filename: str | None) -> str:
    settings = get_settings()
    name = filename or ""
    if not name.lower().endswith(".zip"):
        raise ScanInputError("請上傳 .zip 原始碼壓縮檔")

    scan_id = _new_scan_id()
    workspace.ensure_workspace(scan_id)
    try:
        upload_path = workspace.workspace_root(scan_id) / "upload.zip"
        workspace.save_upload(stream, upload_path, settings.max_upload_bytes)
        if not zipfile.is_zipfile(upload_path):
            raise ScanInputError("上傳檔案不是有效的 ZIP 檔")

        workspace.safe_extract(
            upload_path,
            workspace.src_dir(scan_id),
            max_total_bytes=settings.max_extract_bytes,
            max_files=settings.max_files,
            max_file_bytes=settings.max_file_bytes,
        )
        db.create_scan(scan_id, "zip", Path(name).name)
    except Exception:
        workspace.remove_workspace(scan_id)
        raise

    enqueue(scan_id)
    return scan_id


def create_scan_from_repo(repo_url: str) -> str:
    settings = get_settings()
    if not settings.allow_git_sources:
        raise ScanInputError("目前已停用 Git repo 掃描（SAST_ALLOW_GIT_SOURCES=false）")
    url = git_source.validate_repo_url(repo_url)

    scan_id = _new_scan_id()
    workspace.ensure_workspace(scan_id)
    try:
        db.create_scan(scan_id, "git", url)
    except Exception:
        workspace.remove_workspace(scan_id)
        raise

    enqueue(scan_id)
    return scan_id


def delete_scan(scan_id: str) -> bool:
    deleted = db.delete_scan(scan_id)
    workspace.remove_workspace(scan_id)
    return deleted
