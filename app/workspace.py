"""掃描工作區管理：上傳落地、安全解壓縮、清理。

安全重點：
* 上傳大小上限（串流計數，不信任 Content-Length）
* 解壓縮總量 / 檔案數 / 單檔大小上限（防 zip bomb）
* 正規化路徑後必須仍位於目的目錄內（防 zip slip）
* 拒絕符號連結項目
"""

from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path
from typing import BinaryIO

from .config import get_settings
from .errors import ScanInputError

_CHUNK = 1024 * 1024


def workspace_root(scan_id: str) -> Path:
    return get_settings().workspaces_dir / scan_id


def src_dir(scan_id: str) -> Path:
    return workspace_root(scan_id) / "src"


def ensure_workspace(scan_id: str) -> Path:
    root = workspace_root(scan_id)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def remove_workspace(scan_id: str) -> None:
    shutil.rmtree(workspace_root(scan_id), ignore_errors=True)


def save_upload(stream: BinaryIO, dest: Path, max_bytes: int) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with dest.open("wb") as out:
        while True:
            chunk = stream.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ScanInputError(f"上傳檔案超過上限（{max_bytes // (1024 * 1024)} MB）")
            out.write(chunk)
    if total == 0:
        raise ScanInputError("上傳檔案是空的")
    return total


def safe_extract(
    zip_path: Path,
    dest: Path,
    *,
    max_total_bytes: int,
    max_files: int,
    max_file_bytes: int,
) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    extracted = 0
    total_written = 0

    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise ScanInputError("不是有效的 ZIP 檔") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > max_files:
            raise ScanInputError(f"壓縮檔內檔案數超過上限（{max_files}）")

        for info in infos:
            name = info.filename
            if not name or info.is_dir():
                continue
            if name.startswith("__MACOSX/") or Path(name).name == ".DS_Store":
                continue

            # 拒絕符號連結 / 特殊檔案
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == stat.S_IFLNK:
                raise ScanInputError("壓縮檔含有符號連結，已拒絕")

            target = (dest / name).resolve()
            if target != root and root not in target.parents:
                raise ScanInputError("壓縮檔含有超出目的目錄的路徑（zip slip）")

            if info.file_size > max_file_bytes:
                raise ScanInputError(f"壓縮檔內單一檔案過大：{name}")

            target.parent.mkdir(parents=True, exist_ok=True)
            file_written = 0
            try:
                with archive.open(info) as source, target.open("wb") as sink:
                    while True:
                        chunk = source.read(_CHUNK)
                        if not chunk:
                            break
                        file_written += len(chunk)
                        total_written += len(chunk)
                        if file_written > max_file_bytes:
                            raise ScanInputError(f"解壓縮後單一檔案過大：{name}")
                        if total_written > max_total_bytes:
                            raise ScanInputError(
                                f"解壓縮後總大小超過上限（{max_total_bytes // (1024 * 1024)} MB）"
                            )
                        sink.write(chunk)
            except (RuntimeError, zipfile.BadZipFile) as exc:
                raise ScanInputError(f"ZIP 項目無法解壓縮（可能加密或損毀）：{name}") from exc

            extracted += 1

    if extracted == 0:
        raise ScanInputError("壓縮檔中沒有可掃描的檔案")
    return extracted
