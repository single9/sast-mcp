"""把本機目錄打包成可供 SAST 服務上傳的 ZIP。

Agent 通常想掃描「目前這個專案」，但服務只接受 ZIP 或 Git URL。
這個模組負責：

* 若是 Git repo，使用 ``git ls-files`` 取得 tracked + untracked（排除 ignored）
* 否則走訪目錄，套用與服務相同的排除目錄與二進位副檔名規則
* 拒絕符號連結，檢查檔案數與大小，避免把整個 home 目錄或巨型專案送上傳
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from app.config import EXCLUDE_DIRS, SKIP_EXTENSIONS

from .config import get_mcp_settings


class LocalSourceError(RuntimeError):
    """本機來源無法打包成掃描用 ZIP。"""


@dataclass
class SourceArchive:
    path: Path
    filename: str
    root: Path
    file_count: int
    total_bytes: int
    zip_bytes: int
    git_aware: bool
    skipped: list[dict[str, str]] = field(default_factory=list)
    _temp_dir: Path | None = None

    def cleanup(self) -> None:
        if self._temp_dir is not None:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def summary(self) -> dict:
        return {
            "path": str(self.root),
            "files": self.file_count,
            "total_bytes": self.total_bytes,
            "zip_bytes": self.zip_bytes,
            "git_aware": self.git_aware,
            "skipped": self.skipped[:20],
            "skipped_count": len(self.skipped),
        }


def ensure_allowed(path: Path, *, must_exist: bool = True) -> Path:
    """回傳解析後的路徑；若設定了允許根目錄則檢查是否位於其下。"""

    try:
        resolved = path.expanduser().resolve(strict=must_exist)
    except OSError as exc:
        raise LocalSourceError(f"路徑不存在或無法存取：{path}") from exc

    roots = get_mcp_settings().allowed_roots
    if roots and not any(resolved == root or root in resolved.parents for root in roots):
        allowed = ", ".join(str(root) for root in roots)
        raise LocalSourceError(f"路徑不在允許範圍內（SAST_MCP_ALLOWED_ROOTS）：{allowed}")
    return resolved


def _safe_filename(root: Path) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", root.name).strip("._") or "source"
    return f"{name[:80]}.zip"


def _is_skipped_file(path: Path) -> bool:
    return path.suffix.lower() in SKIP_EXTENSIONS or path.name == ".DS_Store"


def _has_excluded_component(rel: str) -> bool:
    return any(part in EXCLUDE_DIRS for part in rel.split("/") if part)


def _git_file_list(root: Path) -> list[str] | None:
    """取得 Git 追蹤與未忽略的檔案；不是 repo 或 git 不可用時回傳 None。"""

    if shutil.which("git") is None:
        return None

    env = os.environ.copy()
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "true",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
            cwd=str(root),
            capture_output=True,
            timeout=60,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if proc.returncode != 0:
        return None

    files: list[str] = []
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        rel = os.fsdecode(raw).replace("\\", "/")
        if not rel or rel.startswith("../") or rel.startswith("/"):
            continue
        if _has_excluded_component(rel):
            continue
        files.append(rel)
    return files


def _walk_file_list(root: Path) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in EXCLUDE_DIRS and not (current / name).is_symlink()
        )
        for name in sorted(filenames):
            path = current / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            if _has_excluded_component(rel):
                continue
            yield rel


def _selected_files(root: Path, include_gitignored: bool) -> tuple[list[str], bool]:
    if not include_gitignored:
        git_files = _git_file_list(root)
        if git_files is not None:
            return git_files, True
    return list(_walk_file_list(root)), False


def create_source_zip(path: str | Path, *, include_gitignored: bool = False) -> SourceArchive:
    """把目錄打包成暫存 ZIP，呼叫端負責在掃描建立後執行 ``cleanup()``。"""

    settings = get_mcp_settings()
    root = ensure_allowed(Path(path))
    if not root.is_dir():
        raise LocalSourceError(f"不是目錄：{root}")

    rel_files, git_aware = _selected_files(root, include_gitignored)
    if not rel_files:
        raise LocalSourceError("目錄中沒有可掃描的檔案（可能是空目錄或全部被忽略）")

    temp_dir = Path(tempfile.mkdtemp(prefix="sast-mcp-"))
    archive_path = temp_dir / _safe_filename(root)
    skipped: list[dict[str, str]] = []
    total_bytes = 0
    count = 0

    try:
        with zipfile.ZipFile(
            archive_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
            strict_timestamps=False,
        ) as archive:
            for rel in rel_files:
                src = root / rel
                if not src.is_file() or src.is_symlink():
                    skipped.append({"path": rel, "reason": "not_a_regular_file"})
                    continue
                if _is_skipped_file(src):
                    skipped.append({"path": rel, "reason": "binary_or_unsupported"})
                    continue

                try:
                    size = src.stat().st_size
                except OSError:
                    skipped.append({"path": rel, "reason": "unreadable"})
                    continue
                if size > settings.max_file_bytes:
                    skipped.append(
                        {
                            "path": rel,
                            "reason": f"file_too_large>{settings.max_file_bytes // (1024 * 1024)}MB",
                        }
                    )
                    continue

                count += 1
                if count > settings.max_files:
                    raise LocalSourceError(
                        f"檔案數超過上限（{settings.max_files}）；請縮小掃描範圍或調整 SAST_MAX_FILES"
                    )
                total_bytes += size
                if total_bytes > settings.max_extract_bytes:
                    raise LocalSourceError(
                        f"檔案總大小超過上限（{settings.max_extract_bytes // (1024 * 1024)} MB）；"
                        "請縮小掃描範圍或調整 SAST_MAX_EXTRACT_MB"
                    )
                try:
                    archive.write(src, arcname=rel)
                except OSError as exc:
                    skipped.append({"path": rel, "reason": f"read_error: {exc}"})

        if count == 0:
            raise LocalSourceError("目錄中沒有可上傳的檔案（全部被排除或過大）")

        zip_bytes = archive_path.stat().st_size
        if zip_bytes > settings.max_upload_bytes:
            raise LocalSourceError(
                f"壓縮後大小 {zip_bytes // (1024 * 1024)} MB 超過上傳上限 "
                f"{settings.max_upload_mb} MB；請縮小掃描範圍或調整 SAST_MAX_UPLOAD_MB"
            )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

    return SourceArchive(
        path=archive_path,
        filename=archive_path.name,
        root=root,
        file_count=count,
        total_bytes=total_bytes,
        zip_bytes=zip_bytes,
        git_aware=git_aware,
        skipped=skipped,
        _temp_dir=temp_dir,
    )
