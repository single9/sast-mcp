# AGENTS.md

Instructions for AI agents that install, configure, or operate this repository.

This file is written for an agent, not for a human reader. Follow it when the user says
"set up sast-mcp", "install the SAST MCP server", or asks you to scan a project with this
service.

## Platform notes

The examples in this file are POSIX shell snippets. The portable path is the
Python scripts in `scripts/`; they work on Linux, macOS, and Windows without
`command -v`, `make`, `curl`, or a POSIX shell.

- Docker Desktop (macOS/Windows), Docker Engine with Compose (Linux), and Podman
  with `podman-compose` are supported. The service URL is always
  `http://127.0.0.1:8000`.
- Do not use `command -v docker` as the only check. Use
  `scripts/agent_setup.py` (it uses `shutil.which`), or `Get-Command docker` /
  `Get-Command podman` in PowerShell.
- Virtualenv paths: POSIX `.venv/bin/python`; Windows
  `.venv\Scripts\python.exe`.
- `make` targets are Unix-only. On Windows, run the Python scripts directly.
- `scripts/agent_setup.py` detects Docker Compose v2 (`docker compose`), legacy
  `docker-compose`, `podman compose`, and `podman-compose`. Docker is preferred
  in `auto` mode; force Podman with `--runtime podman`.

## One-shot setup

Be idempotent: verify each step and skip it if it is already done. Do not overwrite user
configuration, do not discard local changes, and do not print secrets.

### Rules

- **Docker or Podman is the only supported service deployment for agent setup.** If
  either runtime is available, use it. If neither is available, **do not** install or
  start the systemd service, and do not start any other persistent service. Stop and tell
  the user that Docker or Podman is required.
- Never run a container runtime and systemd at the same time.
- Do not commit `data/`, `reports/`, `.env`, databases, scan workspaces, or generated
  SARIF files.
- Do not modify a project you are asked to scan unless the user explicitly approves it.
- Do not put credentials in command lines, config files, or chat output.
- Ask before deleting scans, triage records, workspaces, or configuration.

### 1. Resolve the repository path

```bash
REPO_DIR="${SAST_HOME:-$HOME/Development/sast}"
```

Windows PowerShell:

```powershell
$REPO_DIR = if ($env:SAST_HOME) { $env:SAST_HOME } else { Join-Path $HOME "Development\sast" }
```

Use a different path only if the user specified one. Always use absolute paths in MCP
configuration.

### 2. Clone or update

```bash
if [ -d "$REPO_DIR/.git" ]; then
  git -C "$REPO_DIR" pull --ff-only
else
  mkdir -p "$(dirname "$REPO_DIR")"
  git clone https://github.com/single9/sast-mcp.git "$REPO_DIR"
fi
```

Windows PowerShell:

```powershell
if (Test-Path (Join-Path $REPO_DIR ".git")) {
  git -C $REPO_DIR pull --ff-only
} else {
  New-Item -ItemType Directory -Force (Split-Path $REPO_DIR) | Out-Null
  git clone https://github.com/single9/sast-mcp.git $REPO_DIR
}
```

If the working tree is dirty and `git pull --ff-only` fails, stop and report the dirty
files. Do not reset, clean, or stash the user's work without permission.

### 3. Install host dependencies

The MCP server runs on the host, not in the container. It needs its own Python
environment:

```bash
cd "$REPO_DIR"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

Windows PowerShell:

```powershell
cd $REPO_DIR
py -3 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes the MCP and test dependencies. If `python3 -m venv` fails,
report the missing system package instead of installing OS packages without permission.

### 4. Start the SAST service with Docker or Podman

Use the cross-platform bootstrap script. It detects Docker or Podman with
`shutil.which`, supports `docker compose`, `docker-compose`, `podman compose`, and
`podman-compose`, starts the service, waits for `/health`, and installs the triage skill:

```bash
cd "$REPO_DIR"
python3 scripts/agent_setup.py --wait-timeout 180
```

Force Podman when both runtimes are installed:

```bash
python3 scripts/agent_setup.py --runtime podman --wait-timeout 180
```

Windows PowerShell:

```powershell
cd $REPO_DIR
py -3 scripts/agent_setup.py --wait-timeout 180
```

If neither Docker nor Podman with Compose is available, the script exits with an error. Do
not fall back to `make service-install` or any other service manager.

If the service is already running and you only want to verify it, run:

```bash
python3 scripts/agent_setup.py --check
```

### 5. Register the MCP server

Use the absolute path to the host venv. On Windows, the interpreter is
`$REPO_DIR\.venv\Scripts\python.exe` instead of `$REPO_DIR/.venv/bin/python`;
`scripts/agent_setup.py` prints the exact command for the current platform. Add
`SAST_API_KEY` only if the service has one configured; never invent or print a key.

#### OpenCode

```bash
opencode mcp add sast --global \
  --env PYTHONPATH="$REPO_DIR" \
  --env SAST_BASE_URL=http://127.0.0.1:8000 \
  -- "$REPO_DIR/.venv/bin/python" -m sast_mcp.server

opencode reload
```

`opencode mcp add` updates an existing `sast` entry in place. Verify with:

```bash
opencode mcp list
```

If the user has `SAST_MCP_ALLOWED_ROOTS` requirements, add another
`--env SAST_MCP_ALLOWED_ROOTS=/path/a:/path/b` argument.

#### Claude Code

```bash
claude mcp remove sast 2>/dev/null || true
claude mcp add sast --scope user \
  -e PYTHONPATH="$REPO_DIR" \
  -e SAST_BASE_URL=http://127.0.0.1:8000 \
  -- "$REPO_DIR/.venv/bin/python" -m sast_mcp.server

claude mcp list | grep sast
```

Inside `claude`, run `/mcp` and approve the tool permissions.

#### Claude Desktop

Edit the client configuration file, merging the `sast` entry instead of replacing the
whole file:

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
        "SAST_BASE_URL": "http://127.0.0.1:8000"
      }
    }
  }
}
```

Fully quit and reopen Claude Desktop after saving.

### 6. Install the triage skill

The setup script in step 4 installs the skill automatically. To reinstall it or choose a
different directory:

```bash
cd "$REPO_DIR"
python3 scripts/install_skill.py
python3 scripts/install_skill.py --skills-dir /path/to/skills
```

Windows PowerShell:

```powershell
cd $REPO_DIR
py -3 scripts/install_skill.py
py -3 scripts/install_skill.py --skills-dir C:\path\to\skills
```

This copies `.opencode/skills/sast-triage/` to `~/.config/opencode/skills/sast-triage/`
by default (or `$XDG_CONFIG_HOME/opencode/skills/`). `make install-skill` remains
available on Unix.

Other clients: keep the skill file in the repository and reference it explicitly, or copy
it into the client's skills directory if the client supports one.

### 7. Verify

```bash
python3 scripts/agent_setup.py --check
opencode mcp list | grep sast
"$REPO_DIR/.venv/bin/python" -c "import sast_mcp.server; print('mcp import ok')"
test -f "$HOME/.config/opencode/skills/sast-triage/SKILL.md" && echo "skill ok"
```

Windows PowerShell:

```powershell
py -3 scripts/agent_setup.py --check
opencode mcp list | Select-String sast
& "$REPO_DIR\.venv\Scripts\python.exe" -c "import sast_mcp.server; print('mcp import ok')"
Test-Path "$HOME\.config\opencode\skills\sast-triage\SKILL.md"
```

Then ask the agent client to call the `health` tool. A response such as
`{"status":"ok","engine":"semgrep",...}` means the full path is working.

### 8. Report

Report these values to the user:

- repository path
- service URL and container status
- MCP client and registration status
- skill installation path
- any warnings, skipped steps, or missing prerequisites

## Using the SAST tools

After setup, use the MCP tools in this order:

1. `health` — confirm the service and engine.
2. `scan_path` — scan the project directory.
3. `wait_for_scan` — wait for completion.
4. `summarize_scan` — inspect `by_language`, `by_engine`, `dependencies`, and
   `supply_chain` first; do not dump every finding.
5. `get_findings` — filter by severity, rule, or file only as needed.
6. Verify findings against the real source before classifying them.
7. `triage_findings` — record `false_positive`, `accepted_risk`, `wontfix`, `fixed`, or
   `needs_review` with a reason. Use `needs_review` when unsure.
8. `export_sarif` — return the file path, not the entire SARIF document.

Do not request code snippets by default. If snippets are necessary, keep redaction enabled
unless the user explicitly approves showing raw values.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Docker/Podman or Compose is missing | Stop; do not start a systemd service. Tell the user Docker or Podman is required. |
| `/health` never becomes ready | Check `docker compose logs --tail=100` or `podman compose logs --tail=100`; report the error. |
| `ModuleNotFoundError: No module named 'sast_mcp'` | Set `PYTHONPATH` to the repository root in the MCP config. |
| MCP client does not show `sast` | Reload or restart the client; check that the config JSON is valid. |
| `Path is outside the allowed roots` | Adjust `SAST_MCP_ALLOWED_ROOTS` or scan a path under an allowed root. |
| A false positive reappears | The snippet changed and produced a new fingerprint; use `list_triage` and re-mark it. |
