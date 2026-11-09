"""Git 來源：URL 驗證（基本 SSRF 防護）與 shallow clone。"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .config import get_settings
from .errors import ScanInputError
from .workspace import ensure_workspace, src_dir

_BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
}
_MAX_URL_LENGTH = 2048


def git_available() -> bool:
    return shutil.which("git") is not None


def validate_repo_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ScanInputError("請提供 Git repo URL")
    if len(url) > _MAX_URL_LENGTH:
        raise ScanInputError("Git repo URL 過長")
    if url.startswith("-"):
        raise ScanInputError("Git repo URL 不合法")

    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        raise ScanInputError("僅支援 http(s) 的 Git repo URL（不支援 ssh / file）")
    if parsed.username or parsed.password:
        raise ScanInputError("URL 不可包含帳號密碼，請改用其他認證方式")
    host = parsed.hostname
    if not host:
        raise ScanInputError("Git repo URL 缺少主機名稱")
    if host.lower() in _BLOCKED_HOSTS or host.lower().endswith(".local"):
        raise ScanInputError("不允許掃描本機或內部主機")

    # 阻擋私有 / 保留 IP（含 DNS 解析結果），降低 SSRF 風險
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except OSError as exc:
        raise ScanInputError(f"無法解析 Git 主機：{host}") from exc

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ScanInputError("不允許掃描內部網路或保留位址")

    return url


def clone_repo(scan_id: str, url: str) -> Path:
    settings = get_settings()
    if not git_available():
        raise ScanInputError("系統找不到 git，無法掃描 Git repo")

    dest = src_dir(scan_id)
    if dest.exists() and any(dest.iterdir()):
        raise ScanInputError("掃描工作區已存在，請重新建立掃描")
    dest.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "true",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--quiet",
        url,
        str(dest),
    ]
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=settings.git_timeout_sec,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanInputError(f"Git clone 逾時（{settings.git_timeout_sec} 秒）") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()[:500]
        raise ScanInputError(f"Git clone 失敗：{detail or 'unknown error'}") from exc

    ensure_workspace(scan_id)
    return dest
