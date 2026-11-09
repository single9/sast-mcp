#!/usr/bin/env python3
"""Cross-platform bootstrap for the SAST service and OpenCode skill.

This script intentionally uses only the Python standard library so it works on
Linux, macOS, and Windows without relying on ``command -v``, ``make``, ``curl``,
or a POSIX shell.

It starts the SAST service with Docker or Podman Compose (never systemd), waits
for ``/health``, installs the ``sast-triage`` skill, and prints the MCP
registration commands for the current platform.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from install_skill import default_skills_dir, install_skill

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


class SetupError(RuntimeError):
    pass


def run(command: list[str], *, cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=check,
    )


def _probe(command: list[str]) -> bool:
    """Return True when a compose command reports a version successfully."""

    for probe in (command + ["version"], command + ["--version"]):
        if run(probe).returncode == 0:
            return True
    return False


def container_compose_command(runtime: str = "auto") -> tuple[list[str], str]:
    """Return a working compose command and its runtime label.

    ``runtime`` is ``auto``, ``docker``, or ``podman``. In auto mode Docker is
    preferred, then Podman, matching the order documented for agents.
    """

    candidates: list[tuple[str, list[str]]] = []

    if runtime in ("auto", "docker"):
        docker = shutil.which("docker")
        if docker:
            candidates.append(("docker", [docker, "compose"]))
        docker_compose = shutil.which("docker-compose")
        if docker_compose:
            candidates.append(("docker", [docker_compose]))

    if runtime in ("auto", "podman"):
        podman = shutil.which("podman")
        if podman:
            candidates.append(("podman", [podman, "compose"]))
        podman_compose = shutil.which("podman-compose")
        if podman_compose:
            candidates.append(("podman", [podman_compose]))

    for label, command in candidates:
        if _probe(command):
            return command, label

    if runtime == "docker":
        raise SetupError(
            "Docker with Compose was not found on PATH. Install Docker Desktop "
            "(macOS/Windows) or Docker Engine with the Compose plugin (Linux), "
            "or pass --runtime podman to use Podman instead."
        )
    if runtime == "podman":
        raise SetupError(
            "Podman with Compose was not found on PATH. Install Podman and "
            "`podman-compose` (or configure a `podman compose` provider), then retry."
        )
    raise SetupError(
        "Neither Docker Compose nor Podman Compose was found on PATH. Install "
        "Docker Desktop/Engine with Compose, or Podman with podman-compose, then retry."
    )


def wait_for_health(base_url: str, timeout_sec: int, interval_sec: float = 2.0) -> dict:
    url = base_url.rstrip("/") + "/health"
    deadline = time.monotonic() + timeout_sec
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = response.read().decode("utf-8", "replace")
                data = json.loads(body)
                print(body)
                return data
        except Exception as exc:  # noqa: BLE001 - retry any connection/parse error
            last_error = exc
            time.sleep(interval_sec)

    raise SetupError(f"SAST service did not become healthy at {url}: {last_error}")


def venv_python(repo_dir: Path) -> Path:
    if os.name == "nt":
        candidates = [
            repo_dir / ".venv" / "Scripts" / "python.exe",
            repo_dir / ".venv" / "Scripts" / "python",
        ]
    else:
        candidates = [
            repo_dir / ".venv" / "bin" / "python",
            repo_dir / ".venv" / "bin" / "python3",
        ]

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path(sys.executable)


def format_command(parts: list[object]) -> str:
    strings = [str(part) for part in parts]
    if os.name == "nt":
        return subprocess.list2cmdline(strings)
    return shlex.join(strings)


def opencode_mcp_command(repo_dir: Path, python_path: Path, base_url: str) -> list[object]:
    return [
        "opencode",
        "mcp",
        "add",
        "sast",
        "--global",
        "--env",
        f"PYTHONPATH={repo_dir}",
        "--env",
        f"SAST_BASE_URL={base_url}",
        "--",
        python_path,
        "-m",
        "sast_mcp.server",
    ]


def claude_mcp_command(repo_dir: Path, python_path: Path, base_url: str) -> list[object]:
    return [
        "claude",
        "mcp",
        "add",
        "sast",
        "--scope",
        "user",
        "-e",
        f"PYTHONPATH={repo_dir}",
        "-e",
        f"SAST_BASE_URL={base_url}",
        "--",
        python_path,
        "-m",
        "sast_mcp.server",
    ]


def register_opencode(repo_dir: Path, python_path: Path, base_url: str) -> None:
    opencode = shutil.which("opencode")
    if not opencode:
        print("opencode was not found on PATH; skipping automatic registration.", file=sys.stderr)
        return

    command = opencode_mcp_command(repo_dir, python_path, base_url)
    command[0] = opencode
    print("+ " + format_command(command))
    subprocess.run([str(part) for part in command], check=True)
    run([opencode, "reload"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: the parent of this script)",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="SAST service base URL")
    parser.add_argument("--wait-timeout", type=int, default=180, help="seconds to wait for /health")
    parser.add_argument(
        "--runtime",
        choices=("auto", "docker", "podman"),
        default="auto",
        help="container runtime to use (default: auto, Docker first then Podman)",
    )
    parser.add_argument("--no-build", action="store_true", help="run compose `up -d` without `--build`")
    parser.add_argument("--skip-service", action="store_true", help="do not start or check the container service")
    parser.add_argument("--skip-skill", action="store_true", help="do not install the triage skill")
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=None,
        help="OpenCode skills directory (default: OPENCODE_SKILLS_DIR or the global config dir)",
    )
    parser.add_argument(
        "--register-opencode",
        action="store_true",
        help="register the sast MCP server in OpenCode's global config",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="only verify the service health and skill installation, then exit",
    )
    args = parser.parse_args()

    repo_dir = args.repo_dir.expanduser().resolve()
    if not (repo_dir / ".git").is_dir():
        raise SetupError(f"not a Git repository: {repo_dir}")

    if args.check:
        wait_for_health(args.base_url, max(1, min(args.wait_timeout, 15)))
        skill_path = (args.skills_dir or default_skills_dir()).expanduser().resolve() / "sast-triage" / "SKILL.md"
        print(f"Skill: {skill_path} ({'ok' if skill_path.exists() else 'missing'})")
        return 0 if skill_path.exists() else 1

    if not args.skip_service:
        compose, runtime = container_compose_command(args.runtime)
        print(f"Container runtime: {runtime}")
        command = compose + ["up", "-d"]
        if not args.no_build:
            command.append("--build")
        print("+ " + format_command(command))
        subprocess.run([str(part) for part in command], cwd=str(repo_dir), check=True)
        health = wait_for_health(args.base_url, args.wait_timeout)
        print(f"Service healthy: {health.get('status', 'unknown')} / {health.get('engine', 'unknown')}")

    if not args.skip_skill:
        destination = install_skill(repo_dir, args.skills_dir)
        print(f"Skill installed: {destination}")

    python_path = venv_python(repo_dir)
    print(f"MCP python: {python_path}")
    print("Register with OpenCode:")
    print("  " + format_command(opencode_mcp_command(repo_dir, python_path, args.base_url)))
    print("Register with Claude Code:")
    print("  " + format_command(claude_mcp_command(repo_dir, python_path, args.base_url)))

    if args.register_opencode:
        register_opencode(repo_dir, python_path, args.base_url)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
