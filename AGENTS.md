# AGENTS.md

Instructions for AI agents that install, configure, or operate this repository.

This file is written for an agent, not for a human reader. Follow it when the user says
"set up sast-mcp", "install the SAST MCP server", or asks you to scan a project with this
service.

## One-shot setup

Be idempotent: verify each step and skip it if it is already done. Do not overwrite user
configuration, do not discard local changes, and do not print secrets.

### Rules

- **Docker is the only supported service deployment for agent setup.** If Docker is
  available, use Docker. If Docker is not available, **do not** install or start the
  systemd service, and do not start any other persistent service. Stop and tell the user
  that Docker is required.
- Never run Docker and systemd at the same time.
- Do not commit `data/`, `reports/`, `.env`, databases, scan workspaces, or generated
  SARIF files.
- Do not modify a project you are asked to scan unless the user explicitly approves it.
- Do not put credentials in command lines, config files, or chat output.
- Ask before deleting scans, triage records, workspaces, or configuration.

### 1. Resolve the repository path

```bash
REPO_DIR="${SAST_HOME:-$HOME/Development/sast}"
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

If the working tree is dirty and `git pull --ff-only` fails, stop and report the dirty
files. Do not reset, clean, or stash the user's work without permission.

### 3. Install host dependencies

The MCP server runs on the host, not in the container. It needs its own Python
environment:

```bash
cd "$REPO_DIR"
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes the MCP and test dependencies. If `python3 -m venv` fails,
report the missing system package instead of installing OS packages without permission.

### 4. Start the SAST service with Docker

Check Docker first:

```bash
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker with Compose is required for agent setup; not starting a service."
  exit 1
fi

cd "$REPO_DIR"
docker compose up -d --build
```

Wait for health:

```bash
for i in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    curl -sS http://127.0.0.1:8000/health
    break
  fi
  sleep 2
done
```

If `/health` never succeeds, inspect `docker compose logs --tail=100` and report the
failure. Do not fall back to `make service-install` or any other service manager.

### 5. Register the MCP server

Use the absolute path to the host venv. Add `SAST_API_KEY` only if the service has one
configured; never invent or print a key.

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

For OpenCode:

```bash
cd "$REPO_DIR"
make install-skill
```

This copies `.opencode/skills/sast-triage/` to `~/.config/opencode/skills/sast-triage/`.
To install somewhere else:

```bash
make install-skill SKILLS_DIR=/path/to/skills
```

Other clients: keep the skill file in the repository and reference it explicitly, or copy
it into the client's skills directory if the client supports one.

### 7. Verify

```bash
curl -sS http://127.0.0.1:8000/health
opencode mcp list | grep sast
"$REPO_DIR/.venv/bin/python" -c "import sast_mcp.server; print('mcp import ok')"
test -f "$HOME/.config/opencode/skills/sast-triage/SKILL.md" && echo "skill ok"
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
| Docker or Compose is missing | Stop; do not start a systemd service. Tell the user Docker is required. |
| `/health` never becomes ready | Check `docker compose logs --tail=100`; report the error. |
| `ModuleNotFoundError: No module named 'sast_mcp'` | Set `PYTHONPATH` to the repository root in the MCP config. |
| MCP client does not show `sast` | Reload or restart the client; check that the config JSON is valid. |
| `Path is outside the allowed roots` | Adjust `SAST_MCP_ALLOWED_ROOTS` or scan a path under an allowed root. |
| A false positive reappears | The snippet changed and produced a new fingerprint; use `list_triage` and re-mark it. |
