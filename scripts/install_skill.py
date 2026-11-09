#!/usr/bin/env python3
"""Install the sast-triage Agent Skill for supported clients.

The skill follows the Agent Skills open format (``SKILL.md`` plus YAML
frontmatter), so the same directory works with OpenCode, Claude Code, and other
compatible clients. This installer copies it into each client's global skills
directory:

- OpenCode: ``$XDG_CONFIG_HOME/opencode/skills`` or ``~/.config/opencode/skills``
- Claude Code: ``~/.claude/skills``
- Shared Agent Skills: ``~/.agents/skills``

The default ``auto`` target installs into every detected client, falling back
to ``~/.agents/skills`` when none is detected. Override the destination with
``--skills-dir`` or the per-client environment variables.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

CLIENTS = ("opencode", "claude", "agents")
ENV_OVERRIDES = {
    "opencode": "OPENCODE_SKILLS_DIR",
    "claude": "CLAUDE_SKILLS_DIR",
    "agents": "AGENTS_SKILLS_DIR",
}


def xdg_config_home() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    return Path(xdg).expanduser() if xdg else Path.home() / ".config"


def default_skills_dir(client: str) -> Path:
    override = os.environ.get(ENV_OVERRIDES[client], "").strip()
    if override:
        return Path(override).expanduser()

    if client == "opencode":
        return xdg_config_home() / "opencode" / "skills"
    if client == "claude":
        return Path.home() / ".claude" / "skills"
    if client == "agents":
        return Path.home() / ".agents" / "skills"
    raise ValueError(f"unknown skill target: {client}")


def client_available(client: str) -> bool:
    """Best-effort detection of an installed client."""

    if client == "opencode":
        return shutil.which("opencode") is not None or (xdg_config_home() / "opencode").is_dir()
    if client == "claude":
        return shutil.which("claude") is not None or (Path.home() / ".claude").is_dir()
    if client == "agents":
        return (Path.home() / ".agents").is_dir()
    return False


def resolve_targets(targets: list[str] | None = None) -> list[str]:
    """Turn ``auto`` / ``all`` / explicit targets into client names."""

    requested = targets or ["auto"]

    if "auto" in requested:
        detected = [client for client in ("opencode", "claude") if client_available(client)]
        return detected or ["agents"]

    if "all" in requested:
        return list(CLIENTS)

    resolved: list[str] = []
    for client in requested:
        if client not in CLIENTS:
            raise ValueError(f"unknown skill target: {client}")
        if client not in resolved:
            resolved.append(client)
    return resolved


def install_skill(
    repo_dir: Path,
    skills_dir: Path | None = None,
    targets: list[str] | None = None,
) -> list[Path]:
    """Copy the skill into one or more destinations and return the paths."""

    source = repo_dir.resolve() / "skills" / "sast-triage"
    if not source.is_dir():
        raise SystemExit(f"skill source not found: {source}")

    if skills_dir is not None:
        roots = [skills_dir]
    else:
        roots = [default_skills_dir(client) for client in resolve_targets(targets)]

    destinations: list[Path] = []
    for root in roots:
        destination_root = root.expanduser().resolve()
        destination_root.mkdir(parents=True, exist_ok=True)
        destination = destination_root / "sast-triage"
        shutil.copytree(source, destination, dirs_exist_ok=True)
        destinations.append(destination)
    return destinations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: the parent of this script)",
    )
    parser.add_argument(
        "--target",
        action="append",
        choices=(*CLIENTS, "auto", "all"),
        default=None,
        help="client to install for; repeatable (default: auto-detect clients)",
    )
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=None,
        help="custom skills directory; overrides --target",
    )
    args = parser.parse_args()

    destinations = install_skill(args.repo_dir, args.skills_dir, args.target)
    for destination in destinations:
        print(destination)
    return 0


if __name__ == "__main__":
    sys.exit(main())
