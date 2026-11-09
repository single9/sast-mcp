#!/usr/bin/env python3
"""Install the sast-triage skill for OpenCode on Linux, macOS, and Windows.

The default destination follows OpenCode's global config directory
(``$XDG_CONFIG_HOME/opencode`` or ``~/.config/opencode``). Override it with
``--skills-dir`` or ``OPENCODE_SKILLS_DIR``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path


def default_skills_dir() -> Path:
    override = os.environ.get("OPENCODE_SKILLS_DIR", "").strip()
    if override:
        return Path(override).expanduser()

    # OpenCode uses the XDG config directory when it is set.
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"

    return base / "opencode" / "skills"


def install_skill(repo_dir: Path, skills_dir: Path | None = None) -> Path:
    source = repo_dir.resolve() / ".opencode" / "skills" / "sast-triage"
    if not source.is_dir():
        raise SystemExit(f"skill source not found: {source}")

    destination_root = (skills_dir or default_skills_dir()).expanduser().resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    destination = destination_root / "sast-triage"
    shutil.copytree(source, destination, dirs_exist_ok=True)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: the parent of this script)",
    )
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=None,
        help="OpenCode skills directory (default: OPENCODE_SKILLS_DIR or the global config dir)",
    )
    args = parser.parse_args()

    destination = install_skill(args.repo_dir, args.skills_dir)
    print(destination)
    return 0


if __name__ == "__main__":
    sys.exit(main())
