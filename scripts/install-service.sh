#!/usr/bin/env bash
# 安裝並啟動 systemd user service。
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_PATH="$UNIT_DIR/sast.service"
PYTHON="$PROJECT_DIR/.venv/bin/python"

if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "錯誤：目前環境沒有可用的 systemd user manager。" >&2
  echo "請改用 Docker，或手動執行 make run。" >&2
  exit 1
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "錯誤：找不到 $PYTHON" >&2
  echo "請先執行：python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt" >&2
  exit 1
fi

if [[ ! -x "$PROJECT_DIR/.venv/bin/semgrep" ]]; then
  echo "警告：找不到 $PROJECT_DIR/.venv/bin/semgrep，服務會退回內建 regex 引擎。" >&2
  echo "      需要 Semgrep 時執行：make semgrep" >&2
fi

mkdir -p "$UNIT_DIR"
sed \
  -e "s|@PROJECT_DIR@|$PROJECT_DIR|g" \
  -e "s|@PYTHON@|$PYTHON|g" \
  "$PROJECT_DIR/deploy/sast.service.in" > "$UNIT_PATH"

systemctl --user daemon-reload
systemctl --user enable sast.service

if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q '127.0.0.1:8000'; then
  if ! systemctl --user is-active --quiet sast.service; then
    echo "錯誤：127.0.0.1:8000 已被其他程序佔用。" >&2
    echo "請先停止手動執行的 uvicorn，再重新執行此腳本。" >&2
    exit 1
  fi
fi

if systemctl --user is-active --quiet sast.service; then
  systemctl --user restart sast.service || {
    echo "重啟失敗；最近日誌：" >&2
    journalctl --user -u sast.service -n 30 --no-pager >&2 || true
    exit 1
  }
else
  systemctl --user start sast.service || {
    echo "啟動失敗；最近日誌：" >&2
    journalctl --user -u sast.service -n 30 --no-pager >&2 || true
    exit 1
  }
fi

# 讓服務在使用者未登入時也能於開機後啟動（需要系統允許）。
if ! loginctl enable-linger "$USER" 2>/dev/null; then
  echo "提示：無法自動啟用 linger；服務仍會在使用者登入後啟動。"
  echo "      若要在開機後常駐，請執行：sudo loginctl enable-linger $USER"
fi

echo
systemctl --user --no-pager status sast.service
