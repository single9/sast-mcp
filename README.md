# SAST Scanning Service

[**English**](README.md) | [繁體中文](README.zh-TW.md)

A ready-to-run basic static application security testing (SAST) service: upload a source ZIP or provide a Git repository URL, run scans in the background, and retrieve results through a REST API, Web UI, or SARIF.

---

## Install

### Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Optional: install Semgrep for more accurate semantic scanning
pip install -r requirements-semgrep.txt

uvicorn app.main:app --reload --port 8000
```

Open <http://localhost:8000> for the Web UI and <http://localhost:8000/docs> for the API docs.

If you install `semgrep` inside the virtual environment, make sure it is on `PATH` when the service starts (`source .venv/bin/activate` is enough).

### Docker (recommended)

```bash
make docker-up     # same as docker compose up -d --build
make docker-status
make docker-logs   # follow logs; Ctrl+C to exit
make docker-down   # stop and remove the container; data/ is preserved
```

Docker is the default deployment method:

- The `sast` container binds only to `127.0.0.1:8000` and is not exposed externally.
- `restart: unless-stopped`, together with an enabled `docker.service`, starts the container on boot and restarts it after crashes.
- `./data` is mounted directly at `/data` in the container, so SQLite and scan workspaces reuse existing project data.
- Settings such as `SAST_API_KEY` in `.env` are passed into the container by Compose.
- The image installs Semgrep by default. To skip it:

  ```bash
  docker build --build-arg INSTALL_SEMGREP=false -t sast-service .
  ```

The service uses an in-process background queue, so uvicorn must stay at **one worker** (the Dockerfile already pins `--workers 1`).

During builds, pip may report an `opentelemetry-api` version conflict: Semgrep pins `~=1.37`, while newer FastAPI requires `>=1.44`. Startup, scanning, and SARIF output have all been tested and work; if FastAPI's OpenTelemetry integration causes problems later, pin an older FastAPI version in `requirements.txt`.

Do not put the MCP server in the container: `scan_path` needs to read project directories on your machine. Keep it on the host and run it over stdio, connecting to the container at `http://127.0.0.1:8000`.

> If you previously installed the systemd user service, run `make service-uninstall` first so the two services do not fight over the same port.

### Start on boot (systemd user service, alternative)

If Docker is not available, use the systemd user service:

```bash
make service-install
make service-status
make service-logs      # follow logs; Ctrl+C to exit
make service-restart
make service-uninstall # remove the service; data/ is preserved
```

The install script generates `~/.config/systemd/user/sast.service` from the current project path, tries `loginctl enable-linger`, and binds only to `127.0.0.1:8000`. It reads `.env` from the project root if present.

Use **either** systemd or Docker, not both. After installation, do not run `make run` manually.

> Agent-driven setup is stricter: an agent must use Docker and must **not** install the systemd service. If Docker is unavailable, it should stop and ask you to install Docker instead. See [`AGENTS.md`](AGENTS.md).

---

## Features

- **Detection engines**: Uses [Semgrep](https://semgrep.dev/) first (semantic rules; 73 built-in rules covering Rust, C#, C/C++, and Node.js). If Semgrep is unavailable, it automatically falls back to the built-in regex engine so the service still works. Rust scans also include OSV dependency vulnerabilities and Cargo supply-chain checks.
- **Asynchronous jobs**: Scans run in the background; the API returns `202` immediately and you can poll for status.
- **Result storage**: SQLite stores scans and findings; workspaces are kept under `data/workspaces/<scan_id>`.
- **Language and risk classification**: After each scan, project languages are detected (file count, line count, percentage), and findings and risk levels are aggregated by language.
- **Standard output**: JSON findings and SARIF 2.1.0, ready for GitHub Code Scanning and similar tools.
- **Agent integration**: Includes an MCP server (`sast_mcp/`) that lets agents such as OpenCode, Claude Code, and Claude Desktop scan, query, and export SARIF directly; a triage skill is also included.
- **Security design**: Upload and extraction limits, zip-slip protection, symlink rejection, basic SSRF protection for Git URLs, and scanned code is never executed.

---

## Usage

### Web UI

1. Upload a `.zip` or enter a Git repository URL on the home page.
2. You are redirected to the scan detail page; while the scan is `queued` / `running`, the page refreshes every 3 seconds.
3. The detail page shows project languages, files/lines/percentage per language, and findings and risk levels aggregated by language.
4. You can download SARIF, inspect findings, and delete scans and workspaces.
5. Each finding can be expanded to "mark verdict", where you can mark it as false positive / accepted risk / wontfix / fixed. The detail page can also show or hide suppressed items.

### REST API

Create a scan from a ZIP:

```bash
curl -sS -X POST http://localhost:8000/api/v1/scans \
  -F "file=@source.zip"
```

Create a scan from Git (http/https only, shallow clone):

```bash
curl -sS -X POST http://localhost:8000/api/v1/scans \
  -F "repo_url=https://github.com/owner/repo.git"
```

Response `202 Accepted`:

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

Poll and retrieve results:

```bash
SCAN_ID=8f14e45fceea167a5a36dedd4bea2543

curl -sS http://localhost:8000/api/v1/scans/$SCAN_ID
curl -sS http://localhost:8000/api/v1/scans/$SCAN_ID/languages
curl -sS "http://localhost:8000/api/v1/scans/$SCAN_ID/findings?severity=critical,high"
curl -sS http://localhost:8000/api/v1/scans/$SCAN_ID/sarif -o report.sarif
```

The `/languages` response includes the primary language, file/line/percentage counts per language, and `findings`, `severity_counts`, `risk_score`, `risk_level`, and top rules per language. `risk_level` is the highest severity in that language (`critical` / `high` / `medium` / `low` / `info` / `none`). For old scans without language stats, the values are derived from the retained workspace on demand.

Other endpoints:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/scans` | Create a scan (`file` or `repo_url`, not both) |
| `GET` | `/api/v1/scans?limit=50&offset=0&status=completed` | List scans |
| `GET` | `/api/v1/scans/{id}` | Scan status and stats (including languages and language risk) |
| `GET` | `/api/v1/scans/{id}/languages` | Project language stats and risk by language |
| `GET` | `/api/v1/scans/{id}/findings?severity=high&limit=1000` | Findings (filter by severity and `triage_status`; suppressed items excluded by default) |
| `GET` | `/api/v1/scans/{id}/sarif` | SARIF 2.1.0 (suppressed items are retained and marked with `suppressions`) |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan and its workspace |
| `GET` | `/api/v1/triage` | List saved verdicts (filter by `status` / `rule_id` / `file`) |
| `PUT` | `/api/v1/triage/{fingerprint}` | Create or update a single verdict |
| `DELETE` | `/api/v1/triage/{fingerprint}` | Remove a verdict (the finding reappears) |
| `POST` | `/api/v1/triage/bulk` | Mark multiple fingerprints in bulk |
| `GET` | `/api/v1/triage/export` | Export the triage baseline as JSON |
| `POST` | `/api/v1/triage/import` | Import a triage baseline JSON |
| `GET` | `/api/v1/engines` | Engine availability and versions |
| `GET` | `/health` | Health check (DB, engine, git) |

### Triage: keep false positives from resurfacing on every scan

Every finding has a cross-scan stable `fingerprint`:

```text
sha256(rule_id + file + normalized code snippet or message)[:32]
```

The fingerprint does not include line numbers, so moving code up or down does not invalidate a verdict. If the snippet actually changes, a new fingerprint is generated and the old verdict no longer applies.

Available verdict statuses:

| Status | Suppressed | Purpose |
| --- | --- | --- |
| `false_positive` | Yes | Confirmed false positive |
| `accepted_risk` | Yes | True positive, but the risk is accepted |
| `wontfix` | Yes | Known issue, not being fixed for now |
| `fixed` | No | Fixed; if it reappears it is marked `regressed` |
| `needs_review` | No | Recorded for review only; not removed |

Suppressed findings are excluded from `stats.findings`, `summarize_scan`, default `get_findings` results, and language risk. SARIF still includes them with `suppressions` and `properties.triageStatus`. To review them:

```bash
curl -sS "http://localhost:8000/api/v1/scans/$SCAN_ID/findings?include_suppressed=true&triage_status=false_positive"
```

Mark and manage verdicts:

```bash
# Single finding
curl -sS -X PUT "http://localhost:8000/api/v1/triage/$FINGERPRINT" \
  -H 'Content-Type: application/json' \
  -d '{"status":"false_positive","note":"Input comes from a fixed string","author":"agent"}'

# Bulk
curl -sS -X POST http://localhost:8000/api/v1/triage/bulk \
  -H 'Content-Type: application/json' \
  -d '{"fingerprints":["fp1","fp2"],"status":"accepted_risk","note":"Internal tool"}'

# Export/import a baseline (commit it to the repo so new machines reuse verdicts)
curl -sS http://localhost:8000/api/v1/triage/export -o sast-triage.json
curl -sS -X POST http://localhost:8000/api/v1/triage/import \
  -H 'Content-Type: application/json' --data-binary @sast-triage.json
```

You can also ignore directly in source code; the verdict travels with the repository:

```python
os.system(cmd)  # sast:ignore

# sast:ignore: rule-id-a, rule-id-b -- ignore only these rules and keep a reason
dangerous_call()
```

`# sast:ignore` affects only the same line; it also works when placed on the line above. These items have triage status `inline_ignored` and reappear when the comment is removed.

### API key

When `SAST_API_KEY` is set, every `/api/v1/*` request must include the header:

```bash
curl -H "X-API-Key: $SAST_API_KEY" http://localhost:8000/api/v1/scans
```

The Web UI (`/ui/*`) and `/health` are not protected by the API key. In production, place them behind a reverse proxy or SSO.

---

## MCP and agent integration

In addition to the REST API, the project provides a standalone MCP server (`sast_mcp/`) that lets MCP-capable agents (OpenCode, Claude Code, Claude Desktop, and others) directly:

- scan the current project directory (packaged automatically; Git repositories exclude ignored and common build directories)
- wait for scans, retrieve grouped summaries (including project languages and `by_language` risk), and filter findings
- export SARIF
- delete scans and workspaces

The MCP server does not touch the database or worker directly; it calls the existing REST API. The service and the agent can therefore run as separate processes, and the existing API/UI are unaffected.

### Architecture

```
Agent (OpenCode / Claude Code / Claude Desktop)
   │  MCP (stdio by default)
   ▼
sast_mcp (MCP server)
   │  HTTP
   ▼
FastAPI SAST service ──► SQLite / workspaces
```

### Install and run

The MCP server is a standalone host process and does not need to run continuously; the agent client starts it over stdio. It calls the SAST service over HTTP, so **the service must already be running**:

```bash
# 1. SAST service (Docker or make run, pick one)
make docker-up
curl -sS http://127.0.0.1:8000/health

# 2. MCP server dependencies (install in the host venv, not in the container)
pip install -r requirements-mcp.txt   # or make mcp
```

Always use **absolute paths** in client configuration (`.venv/bin/python` and `PYTHONPATH`), because the MCP process working directory is not necessarily the project directory.

### Register with OpenCode

Global registration (recommended; available in every project):

```bash
opencode mcp add sast --global \
  --env PYTHONPATH=/absolute/path/to/sast \
  --env SAST_BASE_URL=http://127.0.0.1:8000 \
  -- /absolute/path/to/sast/.venv/bin/python -m sast_mcp.server
opencode mcp list
```

If the SAST service has `SAST_API_KEY` set, add another `--env SAST_API_KEY=...`.

Equivalent manual configuration:

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

> OpenCode V2 uses Code Mode by default, so tools appear as `tools.sast.health(...)`, `tools.sast.scan_path(...)`, and so on. With `codemode: false`, the original tool names (`health`, `scan_path`) are used.

### Register with Claude Code

Claude Code (the `claude` CLI) uses `claude mcp add`. `--scope user` is global and works in every project; omit it to write only to the current project.

```bash
claude mcp add sast --scope user \
  -e PYTHONPATH=/absolute/path/to/sast \
  -e SAST_BASE_URL=http://127.0.0.1:8000 \
  -- /absolute/path/to/sast/.venv/bin/python -m sast_mcp.server

claude mcp list | grep sast
```

Inside `claude`, run `/mcp` to confirm `sast` is connected, then approve the tool permissions.

It is recommended to restrict the scannable paths so the agent cannot scan the entire disk:

```bash
claude mcp remove sast --scope user
claude mcp add sast --scope user \
  -e PYTHONPATH=/absolute/path/to/sast \
  -e SAST_BASE_URL=http://127.0.0.1:8000 \
  -e SAST_MCP_ALLOWED_ROOTS=/absolute/path/to/projects \
  -- /absolute/path/to/sast/.venv/bin/python -m sast_mcp.server
```

Separate multiple roots with `:`. If `SAST_MCP_ALLOWED_ROOTS` is unset, there is no restriction. If the service has `SAST_API_KEY` set, add `-e SAST_API_KEY=...`.

### Configure Claude Desktop

Claude Desktop has no CLI; edit the configuration file directly (add the `mcpServers` key if missing and keep any existing keys):

| Platform | Path |
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

After saving, **fully quit and reopen Claude Desktop** (closing the window is not enough) for the configuration to take effect. If Claude Desktop is installed via Flatpak or Snap, the configuration file may live inside that package's sandbox directory; follow the actual installation method.

### Other stdio MCP clients

Any MCP client that supports stdio can connect with the same `command` / `args` / `env`; only the outer field names differ (Claude Desktop uses `mcpServers`, VS Code uses `servers`, OpenCode uses `mcp.servers`). The payload is always:

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

Place it under the client's server map with the key name `sast`, save, and restart the client.

### Install the triage skill

```bash
make install-skill
```

This copies `.opencode/skills/sast-triage/SKILL.md` to `~/.config/opencode/skills/`. To install it somewhere else, run `make install-skill SKILLS_DIR=/path/to/skills`. The skill defines the triage workflow (how to verify, classify, fix, and rescan); the MCP tools only provide actions.

### Let an agent install everything

If you want an AI agent to pull this repository, start the service, register the MCP server, and install the triage skill, paste this prompt into the agent:

```text
Set up the SAST MCP service from https://github.com/single9/sast-mcp.git.

1. Clone it to ~/Development/sast, or pull if it already exists.
2. Read AGENTS.md in the repository and follow its "One-shot setup" section.
3. Use Docker if Docker and Docker Compose are available. If Docker is not available,
   do not install or start the systemd service and do not start any other persistent
   service; stop and tell me Docker is required.
4. Register the `sast` MCP server globally for my client, install the `sast-triage`
   skill, and verify with /health and the client's MCP list.
5. Do not overwrite existing configuration; merge the `sast` entry.
6. Report the repository path, service URL, MCP registration status, and skill path.
```

The full agent-facing instructions are in [`AGENTS.md`](AGENTS.md). They cover idempotent clone/pull, host dependencies, Docker-only service startup for agents, MCP registration for OpenCode / Claude Code / Claude Desktop, skill installation, verification, and safety rules.

### Verify the installation

After setup, confirm both layers are working:

```bash
curl -sS http://127.0.0.1:8000/health          # SAST service
claude mcp list | grep sast                    # Claude Code MCP connection
```

Ask the agent to call `health` first; a response such as `{"status":"ok","engine":"semgrep",...}` means the whole path is working.

### Usage examples

Once the service is running, you can ask an agent to scan in natural language, for example:

```text
Use sast to scan the current project and give me a summary first; do not list every finding.
```

```text
Use the sast-triage skill to scan src/, confirm which high/critical findings are true positives,
propose minimal fixes, and rescan only the affected directories after the changes.
```

The agent calls `scan_path` → `wait_for_scan` → `summarize_scan` → `get_findings` in sequence. If no path is given, `scan_path` uses `.` (the agent session's current working directory); for other MCP clients (where cwd is not necessarily the project), pass an absolute path.

Equivalent OpenCode Code Mode calls:

```js
const scan = await tools.sast.scan_path({ path: ".", wait: false });
const done = await tools.sast.wait_for_scan({ scan_id: scan.scan.id, timeout_sec: 300 });
const summary = await tools.sast.summarize_scan({ scan_id: scan.scan.id });
const high = await tools.sast.get_findings({
  scan_id: scan.scan.id,
  severity: ["critical", "high"],
  include_snippet: false,
});

// Record the verdict so it does not reappear after the next scan
await tools.sast.triage_findings({
  scan_id: scan.scan.id,
  fingerprints: [high.findings[0].fingerprint],
  status: "false_positive",
  note: "Verified against the source: input comes from a fixed string",
});
```

### Copy-paste prompt for agents

```text
You have a sast MCP server available. Follow this workflow:
1. Call health first to confirm the service and engine.
2. Scan the current project with scan_path(path="."); then call summarize_scan.
3. Look at by_language and by_engine first, then use get_findings to filter details by severity/rule; do not pull everything at once.
4. Check every finding against the actual source code before deciding true positive or false positive; do not rely on the message alone.
5. Record confirmed false positives / accepted risks with triage_findings and a reason; later scans will suppress them automatically.
   Use needs_review when unsure; do not suppress directly.
6. Use export_sarif when a report is needed; return only the path, not the entire SARIF.
7. Do not request code snippets by default; use include_snippet=true only when necessary.
8. Do not modify the scanned project unless I explicitly approve it.
```

### Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `spawn ... ENOENT` | The python path in `command` is wrong; use an absolute path and confirm `.venv` exists |
| `ModuleNotFoundError: No module named 'sast_mcp'` | Missing `PYTHONPATH=/absolute/path/to/sast` |
| `Connection refused` / `health` fails | The SAST service is not running: start it with `docker compose up -d` and retry |
| The client cannot see the `sast` tools | The client was not restarted, `requirements-mcp.txt` is not installed, or the config JSON is invalid |
| `Path is outside the allowed roots` | Loosen `SAST_MCP_ALLOWED_ROOTS` or move the project under an allowed root |
| Large project scans time out | Increase `SAST_MCP_TIMEOUT_SEC` (MCP→API) and `wait_for_scan`'s `timeout_sec`; in OpenCode, also adjust `timeout.execution` |
| No dependency vulnerabilities in results | `SAST_OSV_ENABLED` is disabled, the container cannot reach `api.osv.dev`, or the project has no `Cargo.lock` |
| A previously marked false positive reappears | The code snippet changed, producing a new fingerprint; use `list_triage` to check the old record and re-mark if needed. Old scans can also import a baseline with `import_triage` |

### Tools

| Tool | Description |
| --- | --- |
| `health` | Service, engine, and git status |
| `scan_path` | Scan a local directory (Git-aware packaging) |
| `scan_zip` | Scan a local ZIP |
| `scan_git` | Scan a public Git repository |
| `wait_for_scan` | Poll until completed / failed / timed out |
| `get_scan` | Scan status and stats |
| `list_scans` | Recent scans |
| `summarize_scan` | Group summary by rule/file/severity/language (including per-language risk; suppressed items excluded by default) |
| `get_findings` | Filter and paginate by severity/rule/file/message/triage; optionally include suppressed items |
| `triage_findings` | Record false positives / accepted risks / wontfix / fixed with reasons in bulk |
| `list_triage` | List saved verdicts |
| `delete_triage` | Remove a verdict so the finding reappears (requires `confirm=true`) |
| `export_triage` | Export the triage baseline JSON and return the path |
| `import_triage` | Import a triage baseline JSON |
| `export_sarif` | Write SARIF and return the path and stats |
| `delete_scan` | Delete a scan and its workspace (requires `confirm=true`) |

See `.opencode/skills/sast-triage/SKILL.md` for the agent triage workflow and limitations.

### MCP security settings

- `SAST_MCP_ALLOWED_ROOTS`: restricts the local paths MCP can read/scan (`:`-separated). Recommended for remote or multi-user environments.
- `scan_path` excludes ignored files by default and rejects symlinks.
- `get_findings` does not return snippets by default; when snippets are requested, common credential patterns are redacted by default.
- MCP HTTP transport (`SAST_MCP_TRANSPORT=streamable-http`) binds only to `127.0.0.1:8001` by default and has no built-in authentication; add reverse-proxy authentication before exposing it.
- The MCP server reads local files with the permissions of the user that starts it; do not run it as a highly privileged account.

---

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Description |
| --- | --- | --- |
| `SAST_DATA_DIR` | `./data` | SQLite database and scan workspaces |
| `SAST_ENGINE` | `auto` | `auto` / `semgrep` / `regex` |
| `SAST_SEMGREP_CONFIG` | built-in `app/rules` | Primary rule set; can be `p/default` (requires network) or a custom path |
| `SAST_SEMGREP_EXTRA_CONFIGS` | `p/rust` in Compose | Additional rule sets, comma-separated, layered on top of the primary set (for example `p/rust,p/secrets`; registry packs require network and fall back to built-in rules on failure) |
| `SAST_SEMGREP_BIN` | `semgrep` | Path to the Semgrep executable |
| `SAST_MAX_UPLOAD_MB` | `50` | ZIP upload limit |
| `SAST_MAX_EXTRACT_MB` | `200` | Total extracted size limit |
| `SAST_MAX_FILES` | `20000` | Extracted file count limit |
| `SAST_MAX_FILE_MB` | `2` | Per-file scan size limit |
| `SAST_SCAN_TIMEOUT_SEC` | `300` | Scan timeout |
| `SAST_GIT_TIMEOUT_SEC` | `120` | Git clone timeout |
| `SAST_MAX_WORKERS` | `2` | Number of background workers |
| `SAST_API_KEY` | empty | Enables API key authentication when set |
| `SAST_ALLOW_GIT_SOURCES` | `true` | Whether Git repository sources are allowed |
| `SAST_OSV_ENABLED` | `true` | Parse `Cargo.lock` and query OSV for crates.io vulnerabilities |
| `SAST_OSV_API_URL` | `https://api.osv.dev` | OSV API base URL (can point to an internal proxy) |
| `SAST_OSV_TIMEOUT_SEC` | `20` | OSV query timeout; failures only add warnings and do not fail the scan |
| `SAST_OSV_MAX_PACKAGES` | `1000` | Maximum packages queried per scan |
| `SAST_SUPPLY_CHAIN_ENABLED` | `true` | Cargo supply-chain file checks (build.rs, registries, dependency pinning) |

MCP server settings (a separate process; see the second half of `.env.example`):

| Variable | Default | Description |
| --- | --- | --- |
| `SAST_BASE_URL` | `http://127.0.0.1:8000` | SAST service base URL |
| `SAST_MCP_TIMEOUT_SEC` | `30` | MCP→API request timeout |
| `SAST_MCP_ALLOWED_ROOTS` | empty | Restricts local paths that can be scanned (`:`-separated) |
| `SAST_MCP_EXPORT_DIR` | system temp directory | Default SARIF output location |
| `SAST_MCP_WAIT_TIMEOUT_SEC` | `180` | Default scan wait timeout |
| `SAST_MCP_TRANSPORT` | `stdio` | `stdio` / `streamable-http` / `sse` |
| `SAST_MCP_HOST` | `127.0.0.1` | HTTP transport bind address |
| `SAST_MCP_PORT` | `8001` | HTTP transport port |

`auto` mode: use Semgrep if `semgrep` is available; otherwise use the built-in regex engine. In `semgrep` mode, a missing executable makes the scan fail with an explanation.

---

## Detection rules

Built-in rules live in `app/rules/` (`default.yml`, `rust.yml`, `node.yml`, `c_cpp.yml`, `csharp.yml`, Semgrep) and cover:

- Python: `eval` / `exec` / `os.system` / `subprocess(shell=True)` / pickle / `yaml.load` / weak hashes / SQL string concatenation / Flask debug / `verify=False`
- JavaScript / TypeScript: `eval` / `new Function` / `innerHTML` / `dangerouslySetInnerHTML` / `document.write` / `child_process.exec` / SQL template strings
- Node.js: `vm.runIn*` dynamic execution, MD5/SHA-1, disabled TLS verification, `shell: true` in `spawn`/`execFile`, DES/RC4, JWT `alg=none`, SQL string concatenation
- Java: `Runtime.exec` / SQL string concatenation / MD5, SHA-1
- Go, PHP, Ruby: command and dynamic code execution
- Rust (`rust.yml`): shell command injection, disabled TLS verification, MD5 / SHA-1, SQL built with `format!`, `unsafe` blocks, secrets written to logs, overly broad CORS, `transmute`, `from_raw_parts`, `get_unchecked`, `unsafe impl Send/Sync`, FFI `extern "C"`, Actix `NamedFile` path traversal, open redirect, SSRF, deserialization of external input
- C / C++ (`c_cpp.yml`): `gets`, `strcpy`/`strcat`/`sprintf`, `system`/`popen`, format strings, MD5/SHA-1, `tmpnam`/`mktemp`, `0777` permissions, unbounded `%s`, `exec*`
- C# / .NET (`csharp.yml`): SQL string concatenation/interpolation, `Process.Start`, deserialization such as `BinaryFormatter`, MD5/SHA-1, XXE, disabled request validation, overly broad CORS, cookies without `Secure`, LDAP injection, connection-string passwords
- Cross-language: private keys, AWS / Google / Slack tokens, credentials embedded in URLs, hardcoded passwords

The built-in regex engine (`app/engines/regex_engine.py`) provides approximate equivalents; rule IDs start with `builtin-`. It does not perform semantic analysis and has a higher false-positive rate, making it suitable as a fallback or for quick checks.

### Dependencies and supply chain (Rust / Cargo)

In addition to source rules, every scan runs two deterministic stages that do not require `cargo` or `rustc`:

- **OSV dependency vulnerabilities** (`app/dependencies.py`): parses every `Cargo.lock`, sends crates.io packages to OSV with `querybatch`, and reports `osv-<ID>` findings (engine=`osv`) including CVSS-derived severity, CWE, fixed versions, and CVE/GHSA aliases. Query failures only add a message to `warnings`; the scan still completes.
- **Cargo supply-chain checks** (`app/supply_chain.py`): flags `build.rs`, source replacement / custom runners / plaintext HTTP registries / custom linker arguments in `.cargo/config.toml`, unpinned git dependencies, `*` wildcard versions, path dependencies outside the project, `[patch]` overrides in `Cargo.toml`, and missing `Cargo.lock`. Findings use engine=`supply-chain`.

Results are written to `scan.stats.dependencies` and `scan.stats.supply_chain` and shown in the "Dependencies and supply chain" section of the scan detail page. MCP `summarize_scan` also returns `by_engine`, `dependencies`, and `supply_chain`, so source, dependency, and supply-chain issues can be distinguished directly.

To disable either stage:

```bash
SAST_OSV_ENABLED=false SAST_SUPPLY_CHAIN_ENABLED=false docker compose up -d
```

OSV requires outbound network access from the container; use `SAST_OSV_API_URL` to route through an internal proxy.

To extend the rules:

- Semgrep: add a `.yml` file under `app/rules/`, or point `SAST_SEMGREP_CONFIG` at your own rule set.
- Layer official rule packs: set `SAST_SEMGREP_EXTRA_CONFIGS=p/rust,p/secrets` (comma-separated). Built-in rules still run and are not replaced; registry packs are downloaded during the scan and require network access. On download failure, the service falls back to built-in rules and records a message in that scan's `warnings`.
- Built-in engine: add a `RegexRule` to `RULES` in `regex_engine.py`.

Docker Compose already layers `p/rust`; disable it by setting the variable to an empty string:

```bash
SAST_SEMGREP_EXTRA_CONFIGS= docker compose up -d
```

Validate the rules with:

```bash
semgrep --validate --config app/rules
```

---

## Architecture

```
Client / UI
    │  multipart (zip) or repo_url
    ▼
FastAPI ──────────────► SQLite (scans / findings)
    │  202 + scan_id
    │
    └─ ThreadPoolExecutor (in-process)
           │
           ├─ Prepare workspace: safe extraction / git clone
           │      data/workspaces/<scan_id>/src
           │
           ├─ Engine: Semgrep or builtin-regex
           │
           └─ Write findings / stats / status
```

Flow highlights:

1. The ZIP is validated and extracted during the upload request (with size and path limits); failures return `400`.
2. Git sources are cloned inside the worker, so the scan creation response is not blocked by clone time.
3. The worker updates status in order: `queued → running → completed|failed`; findings and stats are written together.
4. On restart, scans stuck in `queued`/`running` are marked failed so they do not hang forever.
5. Before writing, existing triage verdicts and source-level `sast:ignore` comments are applied; suppressed items are excluded from stats and default summaries, while SARIF retains them with `suppressions`.

### Project layout

```
AGENTS.md            Agent setup and operation instructions
app/
  main.py            FastAPI routes (API + UI)
  services.py        High-level scan creation/deletion flow
  scanner.py         Prepare source → run engine → dependency/supply-chain checks → language stats → persist
  triage.py          Fingerprints, inline ignore, cross-scan verdict annotation
  languages.py       Language detection, line counts, risk aggregation by language
  dependencies.py    Cargo.lock parsing and OSV dependency vulnerability queries
  supply_chain.py    Cargo supply-chain file/manifest checks
  worker.py          In-process ThreadPoolExecutor
  db.py              SQLite schema and data access
  workspace.py       Safe extraction and workspaces
  git_source.py      Git URL validation and clone
  sarif.py           SARIF 2.1.0 output
  engines/
    semgrep_engine.py
    regex_engine.py
  rules/default.yml
  templates/          Jinja2 UI
sast_mcp/
  server.py          MCP tool definitions and entrypoint
  client.py          Async client for the SAST REST API
  local.py           Local directory → ZIP (Git-aware, size/symlink checks)
  formatting.py      Finding summaries and credential redaction
  config.py          MCP environment variables
deploy/
  sast.service.in    systemd user service template
scripts/
  install-service.sh
  uninstall-service.sh
.opencode/skills/
  sast-triage/       Agent triage and remediation workflow
tests/
examples/vulnerable_app.py
```

---

## Security design and limitations

Implemented basic protections:

- Uploads are counted as a stream; `Content-Length` is not trusted.
- Extraction limits total size, file count, and per-file size, and blocks zip slip and symlinks (preventing zip bombs and file overwrites).
- Scanned code is **never executed**; both Semgrep and the regex engine only read text.
- The regex engine does not follow symlinks and ignores `.git`, `node_modules`, `vendor`, build outputs, and similar directories.
- Git URLs allow only http(s) and reject credentials, local hostnames, and private/reserved IPs (including DNS resolution results); clones use `--depth 1` and disable interactive prompts and LFS smudge.
- Scan and delete operations use random scan IDs; workspace paths are never derived from user input.

Current limitations (trade-offs of a "basic" service):

- The queue is in-process; a restart loses unfinished jobs. Multiple workers or replicas require Celery, RQ, or a cloud queue.
- There is no database-level tenant isolation or user authorization; add authentication, authorization, and auditing in production.
- There is no rate limiting; add throttling at the reverse proxy before exposing the service.
- Git supports only public http(s) repositories; there is no private-repository authentication flow.
- SSRF protection resolves DNS before cloning; it cannot fully defend against DNS rebinding, so pair it with network-level egress policies.
- The regex engine is a fallback and will have false positives and false negatives; install Semgrep for production use.
- Built-in Rust rules cover high-signal patterns; for broader coverage, layer the official rule pack with `SAST_SEMGREP_EXTRA_CONFIGS=p/rust`. Dependency vulnerabilities come from OSV's crates.io data, not a local `cargo audit` advisory DB or `cargo deny` license/ban checks.
- Supply-chain checks are heuristic file and manifest analysis; they do not execute `build.rs` or trace proc macros.
- Incremental scans, baseline comparison, PR comments, and similar features are not implemented.
- MCP has no built-in authentication (HTTP transport); local stdio relies on user permissions, and `scan_path` reads files on the machine where the MCP server runs.
- MCP `scan_path` scans one directory at a time; there is no diff or "changed files only" mode.

---

## Testing

```bash
.venv/bin/pytest -q
```

Tests cover: health checks, ZIP scanning and finding contents, severity filtering, SARIF, zip slip, non-ZIP uploads, Git URL validation, API keys, UI rendering, engine selection (including JSON conversion with a fake semgrep), MCP local packaging (Git-aware/symlinks), credential redaction, API client and tool surface, and triage (fingerprints, cross-scan suppression, inline ignore, export/import, legacy DB migration).

Validate Semgrep rules:

```bash
semgrep --validate --config app/rules
```

Try a manual scan of the example:

```bash
zip -r /tmp/demo.zip examples
curl -sS -X POST http://localhost:8000/api/v1/scans -F "file=@/tmp/demo.zip"
```
