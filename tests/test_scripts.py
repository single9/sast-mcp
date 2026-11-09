"""Tests for the cross-platform helper scripts."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_install_skill_copies_into_custom_directory(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "install_skill.py"),
            "--repo-dir",
            str(REPO_ROOT),
            "--skills-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    destination = tmp_path / "sast-triage"
    assert (destination / "SKILL.md").is_file()
    assert str(destination) in result.stdout


def test_agent_setup_help_runs_without_docker() -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "agent_setup.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--skip-service" in result.stdout
    assert "--check" in result.stdout
