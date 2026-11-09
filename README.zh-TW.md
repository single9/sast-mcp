# SAST 掃描服務

[English](README.md) | **繁體中文**

一個可直接執行的基本靜態應用程式安全測試（SAST）服務：上傳原始碼 ZIP 或提供 Git repo URL，背景執行掃描，並以 REST API、Web UI、SARIF 取得結果。

---

## 讓 Agent 自動安裝

如果你要 AI Agent 自動 pull 這個 repo、啟動服務、註冊 MCP server 並安裝 triage Skill，把下面這段貼給 Agent：

```text
請從 https://github.com/single9/sast-mcp.git 安裝 SAST MCP 服務。

1. Clone 到 ~/Development/sast；若已存在則 pull。
2. 讀取 repo 內的 AGENTS.md，照「One-shot setup」章節執行。
3. 如果有 Docker 或 Podman（含 Compose），就用它啟動。若兩者都沒有，不要安裝或啟動
   systemd 服務，也不要啟動其他常駐服務；停下來告訴我必須先安裝 Docker 或 Podman。
4. 對我的客戶端全域註冊 `sast` MCP server、安裝 `sast-triage` Skill，並用 /health
   與客戶端的 MCP list 驗證。
5. 不要覆蓋既有設定；用合併方式加入 `sast` 項目。
6. 回報 repo 路徑、服務 URL、MCP 註冊狀態與 Skill 路徑。
```

完整的 Agent 操作說明在 [`AGENTS.md`](AGENTS.md)，包含可重複執行的 clone/pull、host 依賴安裝、Agent 專用的容器啟動規則、OpenCode / Claude Code / Claude Desktop 的 MCP 註冊、Skill 安裝、驗證與安全規則。

---

## 安裝

### 本機執行

Linux / macOS：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# 選用：安裝 Semgrep 以取得較精準的語意掃描
pip install -r requirements-semgrep.txt

uvicorn app.main:app --reload --port 8000
```

Windows PowerShell：

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# 選用：安裝 Semgrep 以取得較精準的語意掃描
pip install -r requirements-semgrep.txt

uvicorn app.main:app --reload --port 8000
```

開啟 <http://localhost:8000> 使用 Web UI，API 文件在 <http://localhost:8000/docs>。

若把 `semgrep` 裝在虛擬環境內，請確認啟動服務時 PATH 找得到它（先啟用虛擬環境即可）。

### Docker / Podman（建議）

macOS / Windows 可用 Docker Desktop，Linux 用 Docker Engine 搭配 Compose plugin。Podman 搭配 `podman-compose`（或已設定的 `podman compose` provider）也可以。服務網址一律是 `http://127.0.0.1:8000`。

最快的跨平台方式是 Python bootstrap 腳本。它會偵測 Docker 或 Podman（優先 Docker），用 Compose（不會用 systemd）啟動服務、等待 `/health`，並安裝 triage skill：

```bash
python3 scripts/agent_setup.py --wait-timeout 180
```

兩種 runtime 都裝時，強制使用 Podman：

```bash
python3 scripts/agent_setup.py --runtime podman --wait-timeout 180
```

Windows PowerShell：

```powershell
py -3 scripts/agent_setup.py --wait-timeout 180
```

只驗證既有安裝、不做任何變更：

```bash
python3 scripts/agent_setup.py --check
```

也可以自己操作 Compose：

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f        # 追蹤日誌，Ctrl+C 離開
docker compose down           # 停止並移除容器，data/ 仍保留
```

用 Podman 時把 `docker compose` 換成 `podman compose`（或 `podman-compose`）。Unix 上 Docker 指令同樣有 `make docker-up`、`make docker-status`、`make docker-logs`、`make docker-down`；Windows 沒有 `make` 指令。

容器 runtime 是預設的部署方式：

- 容器 `sast` 只綁定 `127.0.0.1:8000`，不對外開放。
- `restart: unless-stopped` 搭配已啟用的 `docker.service`（或等效的 Podman 設定），開機後會自動啟動；當掉也會自動重啟。
- `./data` 直接掛載到容器 `/data`，SQLite 與掃描工作區沿用專案內既有資料。
- `.env` 內的 `SAST_API_KEY` 等設定會由 Compose 帶入容器。
- 映像預設安裝 Semgrep。不需要時：

  ```bash
  docker build --build-arg INSTALL_SEMGREP=false -t sast-service .   # 或 podman build ...
  ```

服務使用程序內背景佇列，因此 uvicorn 必須維持 **單一 worker**（Dockerfile 已固定 `--workers 1`）。

建置時 pip 可能顯示 `opentelemetry-api` 版本衝突警告：Semgrep 固定 `~=1.37`，而較新的 FastAPI 要求 `>=1.44`。目前啟動、掃描與 SARIF 輸出皆實測正常；若之後 FastAPI 的 OpenTelemetry 功能造成問題，可在 `requirements.txt` 固定較舊的 FastAPI 版本。

MCP server 不要放進容器：`scan_path` 需要讀取你機器上的專案目錄。維持在 host 以 stdio 執行，透過 `http://127.0.0.1:8000` 連到容器即可。

> 若之前裝過 systemd user service，請先執行 `make service-uninstall`，避免兩個服務搶同一個 port。

### 開機自動啟動（systemd user service，替代方案）

沒有 Docker 的環境可以改用 systemd user service：

```bash
make service-install
make service-status
make service-logs      # 追蹤日誌，Ctrl+C 離開
make service-restart
make service-uninstall # 移除 service，保留 data/
```

安裝腳本會依目前專案路徑產生 `~/.config/systemd/user/sast.service`、嘗試 `loginctl enable-linger`，並只綁定 `127.0.0.1:8000`。它會讀取專案根目錄的 `.env`（若存在）。

systemd 與容器 runtime（Docker/Podman）兩種方式**擇一使用**；安裝後不要再手動 `make run`。

> Agent 自動安裝的規則更嚴格：Agent 必須使用 Docker 或 Podman，**不得**安裝 systemd 服務。若兩者都沒有，應停下來請你先安裝 Docker 或 Podman。詳見 [`AGENTS.md`](AGENTS.md)。

---

## 功能

- **偵測引擎**：優先使用 [Semgrep](https://semgrep.dev/)（語意規則，內建 73 條，含 Rust、C#、C/C++、Node.js），未安裝時自動退回內建 regex 引擎，服務仍可運作；Rust 另含 OSV 依賴漏洞與 Cargo 供應鏈檢查。
- **非同步任務**：掃描在背景執行，API 立即回傳 `202`，可輪詢狀態。
- **結果保存**：SQLite 儲存掃描與 findings，工作區保留於 `data/workspaces/<scan_id>`。
- **語言與風險分類**：掃描後自動辨識專案語言（檔案數、行數、佔比），並依語言彙總 findings 與風險等級。
- **標準輸出**：JSON findings 與 SARIF 2.1.0，可串接 GitHub Code Scanning 等工具。
- **Agent 整合**：內建 MCP server（`sast_mcp/`），讓 OpenCode / Claude Code / Claude Desktop 等 Agent 直接掃描、查詢與輸出 SARIF；另附 triage Skill。
- **安全設計**：上傳/解壓縮上限、zip slip 防護、符號連結拒絕、Git URL 的 SSRF 基本防護、不執行被掃描的程式碼。

---

## 使用方式

### Web UI

1. 首頁上傳 `.zip` 或輸入 Git repo URL。
2. 自動跳轉到掃描詳情頁；`queued` / `running` 時頁面每 3 秒更新。
3. 詳情頁會顯示專案語言、各語言檔案／行數／佔比，以及依語言彙總的 findings 與風險等級。
4. 可下載 SARIF、查看 findings、刪除掃描與工作區。
5. findings 可展開「標記判定」，直接標成誤報／接受風險／不修補／已修補；詳情頁可切換顯示已抑制項目。

### REST API

建立掃描（ZIP）：

```bash
curl -sS -X POST http://localhost:8000/api/v1/scans \
  -F "file=@source.zip"
```

建立掃描（Git，僅 http/https，shallow clone）：

```bash
curl -sS -X POST http://localhost:8000/api/v1/scans \
  -F "repo_url=https://github.com/owner/repo.git"
```

回應 `202 Accepted`：

```json
{
  "id": "8f14e45fceea167a5a36dedd4bea2543",
  "status": "queued",
  "source_type": "zip",
  "source_ref": "source.zip",
  "created_at": "2026-11-06T03:00:00+00:00",
  "stats": {},
  "severity_counts": {}
}
```

輪詢與取得結果：

```bash
SCAN_ID=8f14e45fceea167a5a36dedd4bea2543

curl -sS http://localhost:8000/api/v1/scans/$SCAN_ID
curl -sS http://localhost:8000/api/v1/scans/$SCAN_ID/languages
curl -sS "http://localhost:8000/api/v1/scans/$SCAN_ID/findings?severity=critical,high"
curl -sS http://localhost:8000/api/v1/scans/$SCAN_ID/sarif -o report.sarif
```

`/languages` 回應包含主要語言、每個語言的檔案數／行數／佔比，以及 `findings`、`severity_counts`、`risk_score`、`risk_level` 與熱門規則；`risk_level` 取該語言最高 severity（`critical` / `high` / `medium` / `low` / `info` / `none`）。舊掃描若沒有語言 stats，會即時從保留的工作區推導。

其他端點：

| Method | Path | 說明 |
| --- | --- | --- |
| `POST` | `/api/v1/scans` | 建立掃描（`file` 或 `repo_url` 擇一） |
| `GET` | `/api/v1/scans?limit=50&offset=0&status=completed` | 列出掃描 |
| `GET` | `/api/v1/scans/{id}` | 掃描狀態與統計（含語言與語言風險） |
| `GET` | `/api/v1/scans/{id}/languages` | 專案語言統計與依語言風險分類 |
| `GET` | `/api/v1/scans/{id}/findings?severity=high&limit=1000` | findings（可用 severity、`triage_status` 過濾；預設排除已抑制） |
| `GET` | `/api/v1/scans/{id}/sarif` | SARIF 2.1.0（已抑制項目保留並標記 `suppressions`） |
| `DELETE` | `/api/v1/scans/{id}` | 刪除掃描與工作區 |
| `GET` | `/api/v1/triage` | 列出已保存的判讀紀錄（可用 `status` / `rule_id` / `file` 過濾） |
| `PUT` | `/api/v1/triage/{fingerprint}` | 新增或更新單筆判讀 |
| `DELETE` | `/api/v1/triage/{fingerprint}` | 移除判讀（finding 會重新出現） |
| `POST` | `/api/v1/triage/bulk` | 批次標記多筆 fingerprint |
| `GET` | `/api/v1/triage/export` | 匯出 triage baseline JSON |
| `POST` | `/api/v1/triage/import` | 匯入 triage baseline JSON |
| `GET` | `/api/v1/engines` | 引擎可用性與版本 |
| `GET` | `/health` | 健康檢查（含 DB、引擎、git） |

### Triage：讓誤報不要每次重掃都出現

每筆 finding 都有一個跨掃描穩定的 `fingerprint`：

```text
sha256(rule_id + file + 正規化後的程式碼片段或訊息)[:32]
```

fingerprint 不含行號，所以程式碼上下移動不會讓判定失效；若片段內容真的改了，會產生新的 fingerprint，舊判定自然不再套用。

可用的判定狀態：

| 狀態 | 是否抑制 | 用途 |
| --- | --- | --- |
| `false_positive` | 是 | 確認是誤報 |
| `accepted_risk` | 是 | 真陽性但風險已接受 |
| `wontfix` | 是 | 已知問題，暫不修補 |
| `fixed` | 否 | 已修補；若之後又出現會標成 `regressed` |
| `needs_review` | 否 | 只記錄待確認，不移除 |

已抑制的 finding 不會計入 `stats.findings`、`summarize_scan`、`get_findings` 預設結果與語言風險；SARIF 仍會保留，並加上 `suppressions` 與 `properties.triageStatus`。需要覆核時：

```bash
curl -sS "http://localhost:8000/api/v1/scans/$SCAN_ID/findings?include_suppressed=true&triage_status=false_positive"
```

標記與管理：

```bash
# 單筆
curl -sS -X PUT "http://localhost:8000/api/v1/triage/$FINGERPRINT" \
  -H 'Content-Type: application/json' \
  -d '{"status":"false_positive","note":"輸入來自固定字串","author":"agent"}'

# 批次
curl -sS -X POST http://localhost:8000/api/v1/triage/bulk \
  -H 'Content-Type: application/json' \
  -d '{"fingerprints":["fp1","fp2"],"status":"accepted_risk","note":"內部工具"}'

# 匯出／匯入 baseline（可提交進 repo，讓新機器沿用判定）
curl -sS http://localhost:8000/api/v1/triage/export -o sast-triage.json
curl -sS -X POST http://localhost:8000/api/v1/triage/import \
  -H 'Content-Type: application/json' --data-binary @sast-triage.json
```

也可以在原始碼直接忽略，判定會跟著 repo 走：

```python
os.system(cmd)  # sast:ignore

# sast:ignore: rule-id-a, rule-id-b -- 只忽略指定規則並保留原因
dangerous_call()
```

`# sast:ignore` 只影響同一行；寫在上一行時也有效。這類項目的 triage 狀態是 `inline_ignored`，移除註解後就會恢復。

### API Key

設定 `SAST_API_KEY` 後，所有 `/api/v1/*` 需帶標頭：

```bash
curl -H "X-API-Key: $SAST_API_KEY" http://localhost:8000/api/v1/scans
```

Web UI（`/ui/*`）與 `/health` 不受 API key 保護，正式環境請置於反向代理／SSO 之後。

---

## MCP 與 Agent 整合

除了 REST API，專案提供一個獨立的 MCP server（`sast_mcp/`），讓支援 MCP 的 Agent（OpenCode、Claude Code、Claude Desktop 等）直接：

- 掃描目前專案目錄（自動打包；Git repo 會排除 ignored 與常見建置目錄）
- 等待掃描、取得群組摘要（含專案語言與 `by_language` 風險）與過濾後的 findings
- 輸出 SARIF
- 刪除掃描與工作區

MCP server 不直接碰資料庫或 worker，而是呼叫既有 REST API。因此服務與 Agent 可以是不同程序，原本的 API／UI 也完全不受影響。

### 架構

```
Agent（OpenCode / Claude Code / Claude Desktop）
   │  MCP（stdio，預設）
   ▼
sast_mcp（MCP server）
   │  HTTP
   ▼
FastAPI SAST 服務 ──► SQLite / workspaces
```

### 安裝與啟動

MCP server 是 host 上的獨立程序，不需要常駐；Agent 客戶端會用 stdio 啟動它。它透過 HTTP 呼叫 SAST 服務，所以**服務必須先跑起來**：

```bash
# 1. SAST 服務（Docker 或本機 uvicorn 擇一）
docker compose up -d --build
curl -sS http://127.0.0.1:8000/health

# 2. MCP server 依賴（裝在 host 的 venv，不要裝進容器）
pip install -r requirements-mcp.txt
```

客戶端設定請一律使用**絕對路徑**（venv 的 Python 與 `PYTHONPATH`），因為 MCP 程序的 cwd 不一定是專案目錄。

| 平台 | 直譯器路徑 |
| --- | --- |
| Linux / macOS | `/absolute/path/to/sast/.venv/bin/python` |
| Windows | `C:\absolute\path\to\sast\.venv\Scripts\python.exe` |

`python3 scripts/agent_setup.py` 會依目前平台印出正確的註冊指令，包含正確的解譯器路徑。

### OpenCode 註冊

全域註冊（推薦，任何專案都能用）：

```bash
opencode mcp add sast --global \
  --env PYTHONPATH=/absolute/path/to/sast \
  --env SAST_BASE_URL=http://127.0.0.1:8000 \
  -- /absolute/path/to/sast/.venv/bin/python -m sast_mcp.server
opencode mcp list
```

若 SAST 服務有設 `SAST_API_KEY`，再加一個 `--env SAST_API_KEY=...`。Windows 請用上表的 `.venv\Scripts\python.exe` 路徑。

手動設定的等價片段：

```jsonc
{
  "mcp": {
    "servers": {
      "sast": {
        "type": "local",
        "command": ["/absolute/path/to/sast/.venv/bin/python", "-m", "sast_mcp.server"],
        "environment": {
          "PYTHONPATH": "/absolute/path/to/sast",
          "SAST_BASE_URL": "http://127.0.0.1:8000"
        },
        "timeout": { "execution": 900000 }
      }
    }
  }
}
```

> OpenCode V2 預設使用 Code Mode，工具會以 `tools.sast.health(...)`、`tools.sast.scan_path(...)` 的形式出現。若設 `codemode: false`，則回到原生工具名稱 `health`、`scan_path`。

### Claude Code 註冊

Claude Code（`claude` CLI）用 `claude mcp add` 註冊。`--scope user` 是全域，任何專案都能用；拿掉就是只寫進目前專案。

```bash
claude mcp add sast --scope user \
  -e PYTHONPATH=/absolute/path/to/sast \
  -e SAST_BASE_URL=http://127.0.0.1:8000 \
  -- /absolute/path/to/sast/.venv/bin/python -m sast_mcp.server

claude mcp list | grep sast
```

進入 `claude` 後打 `/mcp`，確認 `sast` 是 connected，並核可工具權限。

建議一併限制可掃描範圍，避免 Agent 掃到整顆硬碟：

```bash
claude mcp remove sast --scope user
claude mcp add sast --scope user \
  -e PYTHONPATH=/absolute/path/to/sast \
  -e SAST_BASE_URL=http://127.0.0.1:8000 \
  -e SAST_MCP_ALLOWED_ROOTS=/absolute/path/to/projects \
  -- /absolute/path/to/sast/.venv/bin/python -m sast_mcp.server
```

多個根目錄用 `:` 分隔。`SAST_MCP_ALLOWED_ROOTS` 不設代表不限制。若服務有設 `SAST_API_KEY`，再加 `-e SAST_API_KEY=...`。

### Claude Desktop 設定

Claude Desktop 沒有 CLI，直接改設定檔（沒有 `mcpServers` 鍵就自己加上，其他既有鍵保留）：

| 平台 | 路徑 |
| --- | --- |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "sast": {
      "command": "/absolute/path/to/sast/.venv/bin/python",
      "args": ["-m", "sast_mcp.server"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/sast",
        "SAST_BASE_URL": "http://127.0.0.1:8000",
        "SAST_MCP_ALLOWED_ROOTS": "/absolute/path/to/projects"
      }
    }
  }
}
```

存檔後要**完全結束 Claude Desktop 再重開**（關視窗不算），設定才會生效。若 Claude Desktop 是 Flatpak／Snap 安裝，設定檔可能在該套件的 sandbox 目錄內，請以實際安裝方式為準。

### 其他 stdio MCP 客戶端

任何支援 stdio 的 MCP 客戶端都可以用同樣的 `command` / `args` / `env` 接入，只是外層欄位名稱不同（Claude Desktop 用 `mcpServers`、VS Code 用 `servers`、OpenCode 用 `mcp.servers`）。內容物固定是：

```json
{
  "command": "/absolute/path/to/sast/.venv/bin/python",
  "args": ["-m", "sast_mcp.server"],
  "env": {
    "PYTHONPATH": "/absolute/path/to/sast",
    "SAST_BASE_URL": "http://127.0.0.1:8000"
  }
}
```

把它放到該客戶端設定檔對應的 server map 底下，鍵名用 `sast`，存檔後重啟客戶端。

### 安裝 triage Skill

這個 Skill 採用 [Agent Skills](https://agentskills.io) 開放格式，同一份 `skills/sast-triage/` 可給 OpenCode、Claude Code 與其他支援 `SKILL.md` 的客戶端使用。

```bash
python3 scripts/install_skill.py                 # 自動偵測已安裝的客戶端
python3 scripts/install_skill.py --target claude # 指定單一客戶端
python3 scripts/install_skill.py --target all    # opencode + claude + agents
python3 scripts/install_skill.py --skills-dir /path/to/skills
```

Windows PowerShell：

```powershell
py -3 scripts/install_skill.py
py -3 scripts/install_skill.py --target claude
py -3 scripts/install_skill.py --skills-dir C:\path\to\skills
```

預設安裝位置：

| Target | 目錄 |
| --- | --- |
| `opencode` | `$XDG_CONFIG_HOME/opencode/skills` 或 `~/.config/opencode/skills` |
| `claude` | `~/.claude/skills` |
| `agents` | `~/.agents/skills` |

`auto` 會裝到每個偵測到的客戶端；都沒偵測到時退回 `~/.agents/skills`。若某個客戶端支援 `SKILL.md` 但沒被偵測到，可用 `--target agents` 或 `--skills-dir`。Unix 上 `make install-skill` 與 `make install-skill SKILLS_DIR=/path/to/skills` 效果相同。Skill 定義判讀流程（如何驗證、分類、修補、重掃），MCP 工具只提供動作。

### 驗證安裝

裝好後先確認服務與 MCP 兩層都通：

```bash
python3 scripts/agent_setup.py --check             # 服務健康狀態 + Skill 路徑
claude mcp list | grep sast                        # Claude Code 的 MCP 連線
```

Windows PowerShell：

```powershell
py -3 scripts/agent_setup.py --check
claude mcp list | Select-String sast
```

Agent 端請它先呼叫 `health`；回傳 `{"status":"ok","engine":"semgrep",...}` 就代表整條路徑沒問題。

### 實際用法

服務啟動後，直接用自然語言要求 Agent 掃描即可，例如：

```text
用 sast 掃描目前專案，先給我摘要，不要列出全部 finding。
```

```text
用 sast-triage skill 掃描 src/，確認 high/critical 哪些是真陽性，
提出最小修補，改完後只重掃受影響的目錄。
```

Agent 會依序呼叫 `scan_path` → `wait_for_scan` → `summarize_scan` → `get_findings`。若不指定路徑，`scan_path` 的 `.` 是 Agent session 目前的工作目錄；其他 MCP 客戶端（cwd 不一定是專案）建議傳絕對路徑。

OpenCode Code Mode 等價呼叫：

```js
const scan = await tools.sast.scan_path({ path: ".", wait: false });
const done = await tools.sast.wait_for_scan({ scan_id: scan.scan.id, timeout_sec: 300 });
const summary = await tools.sast.summarize_scan({ scan_id: scan.scan.id });
const high = await tools.sast.get_findings({
  scan_id: scan.scan.id,
  severity: ["critical", "high"],
  include_snippet: false,
});

// 判讀後記錄，之後重掃就不會再出現
await tools.sast.triage_findings({
  scan_id: scan.scan.id,
  fingerprints: [high.findings[0].fingerprint],
  status: "false_positive",
  note: "已對照原始碼：輸入來自固定字串",
});
```

### 可直接貼給 Agent 的提示

```text
你有一個 sast MCP server 可用。請照這個流程：
1. 先呼叫 health 確認服務與引擎。
2. 用 scan_path(path=".") 掃描目前專案；完成後呼叫 summarize_scan。
3. 先看 by_language 與 by_engine，再用 get_findings 依 severity/rule 過濾細節，不要一次拉全部。
4. 每筆 finding 都要對照原始碼判斷真陽性/誤報，不要只看訊息。
5. 確認過的誤報／接受風險用 triage_findings 記錄原因，之後重掃會自動抑制；
   不確定時用 needs_review，不要直接抑制。
6. 需要報告時用 export_sarif，只回傳路徑，不要貼整份 SARIF。
7. 預設不要要求程式碼片段；需要時才用 include_snippet=true。
8. 不要修改被掃描的專案，除非我明確同意。
```

### 疑難排解

| 症狀 | 原因與處理 |
| --- | --- |
| `spawn ... ENOENT` | `command` 的 python 路徑錯；用絕對路徑，且確認 `.venv` 存在 |
| `ModuleNotFoundError: No module named 'sast_mcp'` | 少了 `PYTHONPATH=/absolute/path/to/sast` |
| `Connection refused` / `health` 失敗 | SAST 服務沒跑：`docker compose up -d` 後再試 |
| 客戶端看不到 `sast` 工具 | 客戶端沒重啟、`requirements-mcp.txt` 沒裝，或設定檔 JSON 格式錯誤 |
| `路徑不在允許範圍內` | 放寬 `SAST_MCP_ALLOWED_ROOTS`，或把專案移到允許的根目錄下 |
| 大專案掃描逾時 | 提高 `SAST_MCP_TIMEOUT_SEC`（MCP→API）與 `wait_for_scan` 的 `timeout_sec`；OpenCode 另可調 `timeout.execution` |
| 掃描結果沒有依賴漏洞 | `SAST_OSV_ENABLED` 被關掉、容器連不到 `api.osv.dev`，或專案沒有 `Cargo.lock` |
| 標記過的誤報又出現 | 程式碼片段已改變會產生新 fingerprint；用 `list_triage` 確認舊紀錄，必要時重新標記。舊掃描也可用 `import_triage` 匯入 baseline |

### 工具

| 工具 | 說明 |
| --- | --- |
| `health` | 服務、引擎、git 狀態 |
| `scan_path` | 掃描本機目錄（Git-aware 打包） |
| `scan_zip` | 掃描本機 ZIP |
| `scan_git` | 掃描公開 Git repo |
| `wait_for_scan` | 輪詢到完成／失敗／逾時 |
| `get_scan` | 掃描狀態與統計 |
| `list_scans` | 最近掃描 |
| `summarize_scan` | 依 rule/file/severity/language 群組摘要（含各語言風險；預設排除已抑制） |
| `get_findings` | severity/rule/file/message/triage 過濾與分頁；可選擇包含已抑制項目 |
| `triage_findings` | 批次記錄誤報／接受風險／不修補／已修補與原因 |
| `list_triage` | 列出已保存的判讀紀錄 |
| `delete_triage` | 移除判讀，讓 finding 重新出現（需 `confirm=true`） |
| `export_triage` | 匯出 triage baseline JSON，回傳路徑 |
| `import_triage` | 匯入 triage baseline JSON |
| `export_sarif` | 寫出 SARIF，回傳路徑與統計 |
| `delete_scan` | 刪除掃描與工作區（需 `confirm=true`） |

Agent 判讀流程與限制請看 `skills/sast-triage/SKILL.md`。

### MCP 安全設定

- `SAST_MCP_ALLOWED_ROOTS`：限制 MCP 可讀取／掃描的本機路徑（`:` 分隔）。遠端或多人環境建議設定。
- `scan_path` 預設不送 ignored 檔案，且拒絕符號連結。
- `get_findings` 預設不回傳 snippet；要求 snippet 時預設遮蔽常見憑證樣式。
- MCP HTTP transport（`SAST_MCP_TRANSPORT=streamable-http`）預設只綁 `127.0.0.1:8001`，且沒有內建認證；對外開放前請加反向代理認證。
- MCP server 以啟動它的使用者權限讀取本機檔案；不要用過高權限的帳號常駐。

---

## 設定

所有設定都是環境變數（見 `.env.example`）：

| 變數 | 預設 | 說明 |
| --- | --- | --- |
| `SAST_DATA_DIR` | `./data` | SQLite 與掃描工作區 |
| `SAST_ENGINE` | `auto` | `auto` / `semgrep` / `regex` |
| `SAST_SEMGREP_CONFIG` | 內建 `app/rules` | 主規則集，可填 `p/default`（需網路）或自訂路徑 |
| `SAST_SEMGREP_EXTRA_CONFIGS` | Compose 為 `p/rust` | 額外規則集，逗號分隔，疊加在主規則集上（如 `p/rust,p/secrets`；registry pack 需網路，失敗時自動退回內建規則） |
| `SAST_SEMGREP_BIN` | `semgrep` | Semgrep 執行檔路徑 |
| `SAST_MAX_UPLOAD_MB` | `50` | ZIP 上傳上限 |
| `SAST_MAX_EXTRACT_MB` | `200` | 解壓縮後總大小上限 |
| `SAST_MAX_FILES` | `20000` | 解壓縮檔案數上限 |
| `SAST_MAX_FILE_MB` | `2` | 單檔掃描大小上限 |
| `SAST_SCAN_TIMEOUT_SEC` | `300` | 掃描逾時 |
| `SAST_GIT_TIMEOUT_SEC` | `120` | Git clone 逾時 |
| `SAST_MAX_WORKERS` | `2` | 背景 worker 數 |
| `SAST_API_KEY` | 空 | 設定後啟用 API key |
| `SAST_ALLOW_GIT_SOURCES` | `true` | 是否允許 Git repo 來源 |
| `SAST_OSV_ENABLED` | `true` | 解析 `Cargo.lock` 並查詢 OSV 的 crates.io 漏洞 |
| `SAST_OSV_API_URL` | `https://api.osv.dev` | OSV API 位址（可指向內部代理） |
| `SAST_OSV_TIMEOUT_SEC` | `20` | OSV 查詢逾時；失敗只留 warning，不讓掃描失敗 |
| `SAST_OSV_MAX_PACKAGES` | `1000` | 單次掃描最多查詢的套件數 |
| `SAST_SUPPLY_CHAIN_ENABLED` | `true` | Cargo 供應鏈檔案檢查（build.rs、registry、依賴 pin） |

MCP server 的設定（獨立程序，見 `.env.example` 後半段）：

| 變數 | 預設 | 說明 |
| --- | --- | --- |
| `SAST_BASE_URL` | `http://127.0.0.1:8000` | SAST 服務位址 |
| `SAST_MCP_TIMEOUT_SEC` | `30` | MCP 呼叫 API 的逾時 |
| `SAST_MCP_ALLOWED_ROOTS` | 空 | 限制可掃描的本機路徑（`:` 分隔） |
| `SAST_MCP_EXPORT_DIR` | 系統暫存目錄 | SARIF 預設輸出位置 |
| `SAST_MCP_WAIT_TIMEOUT_SEC` | `180` | 等待掃描完成的預設值 |
| `SAST_MCP_TRANSPORT` | `stdio` | `stdio` / `streamable-http` / `sse` |
| `SAST_MCP_HOST` | `127.0.0.1` | HTTP transport 綁定位址 |
| `SAST_MCP_PORT` | `8001` | HTTP transport 連接埠 |

`auto` 模式：找得到 `semgrep` 就用 Semgrep，否則用內建 regex 引擎。`semgrep` 模式在找不到執行檔時，掃描會失敗並回報原因。

---

## 偵測規則

內建規則位於 `app/rules/`（`default.yml`、`rust.yml`、`node.yml`、`c_cpp.yml`、`csharp.yml`，Semgrep），涵蓋：

- Python：`eval` / `exec` / `os.system` / `subprocess(shell=True)` / pickle / `yaml.load` / 弱雜湊 / SQL 字串拼接 / Flask debug / `verify=False`
- JavaScript / TypeScript：`eval` / `new Function` / `innerHTML` / `dangerouslySetInnerHTML` / `document.write` / `child_process.exec` / SQL 樣板字串
- Node.js：`vm.runIn*` 動態執行、MD5/SHA-1、停用 TLS 驗證、`spawn`/`execFile` 的 `shell: true`、DES/RC4、JWT `alg=none`、SQL 字串串接
- Java：`Runtime.exec` / SQL 字串串接 / MD5、SHA-1
- Go、PHP、Ruby：指令與動態程式碼執行
- Rust（`rust.yml`）：shell 指令注入、停用 TLS 驗證、MD5 / SHA-1、`format!` 拼接 SQL、`unsafe` 區塊、權杖寫入日誌、過寬的 CORS、`transmute`、`from_raw_parts`、`get_unchecked`、`unsafe impl Send/Sync`、FFI `extern "C"`、Actix `NamedFile` 路徑穿越、open redirect、SSRF、外部輸入反序列化
- C / C++（`c_cpp.yml`）：`gets`、`strcpy`/`strcat`/`sprintf`、`system`/`popen`、格式字串、MD5/SHA-1、`tmpnam`/`mktemp`、`0777` 權限、無長度限制的 `%s`、`exec*`
- C# / .NET（`csharp.yml`）：SQL 字串串接／插值、`Process.Start`、`BinaryFormatter` 等反序列化、MD5/SHA-1、XXE、停用請求驗證、過寬 CORS、未設 `Secure` 的 Cookie、LDAP injection、連線字串密碼
- 跨語言：私鑰、AWS / Google / Slack 權杖、URL 內嵌帳密、硬編碼密碼

內建 regex 引擎（`app/engines/regex_engine.py`）提供對應的近似規則，rule id 以 `builtin-` 開頭。它不進行語意分析，誤報率較高，適合當後備或快速檢查。

### 依賴與供應鏈（Rust / Cargo）

除了原始碼規則，每次掃描會額外執行兩個確定性階段，不需要 `cargo`／`rustc`：

- **OSV 依賴漏洞**（`app/dependencies.py`）：解析所有 `Cargo.lock`，把 crates.io 套件以 `querybatch` 送 OSV，回報 `osv-<ID>` findings（engine=`osv`），包含 CVSS 換算後的 severity、CWE、修復版本與 CVE／GHSA alias。查詢失敗只會在 `warnings` 留下訊息，不影響掃描完成。
- **Cargo 供應鏈檢查**（`app/supply_chain.py`）：標記 `build.rs`、`.cargo/config.toml` 的 source replacement／自訂 runner／明文 HTTP registry／自訂 linker 參數、`Cargo.toml` 的未 pin git 依賴、`*` 萬用版本、指向專案外的 path 依賴、`[patch]` 覆寫，以及缺少 `Cargo.lock`。findings 的 engine=`supply-chain`。

結果會寫入 `scan.stats.dependencies` 與 `scan.stats.supply_chain`，並顯示在掃描詳情頁的「依賴與供應鏈」區塊。MCP `summarize_scan` 另外提供 `by_engine`、`dependencies`、`supply_chain`，可直接區分原始碼、依賴與供應鏈問題。

要停用其中一項：

```bash
SAST_OSV_ENABLED=false SAST_SUPPLY_CHAIN_ENABLED=false docker compose up -d
```

OSV 需要容器能連外；若要走內部代理，設定 `SAST_OSV_API_URL`。

要擴充規則：

- Semgrep：在 `app/rules/` 新增 `.yml`，或設定 `SAST_SEMGREP_CONFIG` 指向自己的規則集。
- 疊加官方規則集：設定 `SAST_SEMGREP_EXTRA_CONFIGS=p/rust,p/secrets`（逗號分隔）。內建規則仍會執行，不會被取代；registry pack 於掃描時下載，需要網路。下載失敗時會自動退回內建規則，並在該次掃描的 `warnings` 留下訊息。
- 內建引擎：在 `regex_engine.py` 的 `RULES` 增加 `RegexRule`。

Docker Compose 預設已疊加 `p/rust`；要停用時設成空字串：

```bash
SAST_SEMGREP_EXTRA_CONFIGS= docker compose up -d
```

可用以下方式驗證規則：

```bash
semgrep --validate --config app/rules
```

---

## 架構

```
Client / UI
    │  multipart(zip) 或 repo_url
    ▼
FastAPI ──────────────► SQLite（scans / findings）
    │  202 + scan_id
    │
    └─ ThreadPoolExecutor（程序內）
           │
           ├─ 準備工作區：安全解壓縮 / git clone
           │      data/workspaces/<scan_id>/src
           │
           ├─ 引擎：Semgrep 或 builtin-regex
           │
           └─ 寫入 findings / stats / status
```

流程重點：

1. ZIP 在上傳請求內完成驗證與解壓（有大小與路徑限制），失敗直接回 `400`。
2. Git 來源在 worker 內 clone，因此建立掃描的回應不會被 clone 時間阻塞。
3. worker 依序更新 `queued → running → completed|failed`；findings 與統計在同一次寫入。
4. 服務重啟時，卡在 `queued`/`running` 的掃描會被標記為失敗，避免永久卡住。
5. 寫入前會套用既有 triage 判定與原始碼 `sast:ignore`，已抑制項目不列入統計與預設摘要；SARIF 仍保留並標記 `suppressions`。

### 專案結構

```
AGENTS.md            Agent 安裝與操作說明
app/
  main.py            FastAPI 路由（API + UI）
  services.py        建立／刪除掃描的高階流程
  scanner.py         準備來源 → 執行引擎 → 依賴／供應鏈檢查 → 語言統計 → 落庫
  triage.py          fingerprint、inline ignore、跨掃描判讀標註
  languages.py       語言偵測、行數統計、依語言風險彙總
  dependencies.py    Cargo.lock 解析與 OSV 依賴漏洞查詢
  supply_chain.py    Cargo 供應鏈檔案／manifest 檢查
  worker.py          程序內 ThreadPoolExecutor
  db.py              SQLite schema 與存取
  workspace.py       安全解壓縮、工作區
  git_source.py      Git URL 驗證與 clone
  sarif.py           SARIF 2.1.0 輸出
  engines/
    semgrep_engine.py
    regex_engine.py
  rules/default.yml
  templates/          Jinja2 UI
sast_mcp/
  server.py          MCP 工具定義與 entrypoint
  client.py          呼叫 SAST REST API 的非同步 client
  local.py           本機目錄 → ZIP（Git-aware、大小/符號連結檢查）
  formatting.py      finding 摘要、憑證遮蔽
  config.py          MCP 環境變數
deploy/
  sast.service.in    systemd user service 範本
scripts/
  agent_setup.py     跨平台 Docker bootstrap 與驗證
  install_skill.py   跨平台 triage Skill 安裝器
  install-service.sh
  uninstall-service.sh
skills/
  sast-triage/       可攜式 Agent Skill（SKILL.md）
tests/
examples/vulnerable_app.py
```

---

## 安全設計與限制

已實作的基本防護：

- 上傳以串流計數，不信任 `Content-Length`。
- 解壓縮限制總量、檔案數、單檔大小，並阻擋 zip slip 與符號連結（防 zip bomb / 覆寫檔案）。
- 被掃描的程式碼 **不會被執行**；Semgrep 與 regex 引擎都只讀取文字。
- regex 引擎不跟隨符號連結，並忽略 `.git`、`node_modules`、`vendor`、建置產物等目錄。
- Git URL 僅允許 http(s)，拒絕帳密、本機名稱與私有／保留 IP（含 DNS 解析結果）；clone 使用 `--depth 1` 且停用互動提示與 LFS smudge。
- 掃描與刪除操作使用隨機 scan id，工作區路徑不會由使用者輸入決定。

目前限制（「基本」服務的取捨）：

- 佇列在程序內，重啟會遺失未完成任務；多 worker／多副本需改用 Celery、RQ 或雲端佇列。
- 沒有資料庫層級的租戶隔離與使用者權限；正式環境請加上認證、授權與審計。
- 沒有速率限制；對外開放前請在反向代理加上限流。
- Git 僅支援公開 http(s) repo，沒有 private repo 的認證流程。
- SSRF 防護在 clone 前解析 DNS；無法完全防禦 DNS rebinding，建議搭配網路層 egress 政策。
- regex 引擎是後備方案，會有誤報／漏報；正式使用請安裝 Semgrep。
- Rust 內建規則涵蓋高訊號樣式；更完整的檢查可用 `SAST_SEMGREP_EXTRA_CONFIGS=p/rust` 疊加官方規則集。依賴漏洞來自 OSV 的 crates.io 資料，沒有 `cargo audit` 的本機 advisory DB 與 `cargo deny` 的 license／bans 檢查。
- 供應鏈檢查是檔案與 manifest 的啟發式分析，不會解析 `build.rs` 的實際行為，也不追蹤 proc-macro。
- 未實作增量掃描、baseline 比對、PR 註解等功能。
- MCP 沒有內建認證（HTTP transport）；本機 stdio 依賴使用者權限，`scan_path` 會讀取 MCP server 所在機器的檔案。
- MCP `scan_path` 一次掃描一個目錄；沒有 diff 或「只掃變更檔案」模式。

---

## 測試

```bash
.venv/bin/pytest -q
```

測試涵蓋：健康檢查、ZIP 掃描與 finding 內容、severity 過濾、SARIF、zip slip、非 ZIP 上傳、Git URL 驗證、API key、UI 渲染、引擎解析（含以假 semgrep 驗證 JSON 轉換）、MCP 本機打包（Git-aware／符號連結）、憑證遮蔽、API client 與工具介面，以及 triage（fingerprint、跨掃描抑制、inline ignore、export/import、舊 DB 遷移）。

Semgrep 規則驗證：

```bash
semgrep --validate --config app/rules
```

手動試掃範例：

```bash
zip -r /tmp/demo.zip examples
curl -sS -X POST http://localhost:8000/api/v1/scans -F "file=@/tmp/demo.zip"
```
