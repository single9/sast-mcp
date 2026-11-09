#!/usr/bin/env bash
# 移除 systemd user service（不會刪除掃描資料）。
set -euo pipefail

UNIT_PATH="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/sast.service"

systemctl --user disable --now sast.service 2>/dev/null || true
rm -f "$UNIT_PATH"
systemctl --user daemon-reload
echo "已移除 sast.service。掃描資料仍保留在專案的 data/ 目錄。"
