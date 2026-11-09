"""Tests for the cross-platform helper scripts."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def load_agent_setup() -> ModuleType:
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    spec = importlib.util.spec_from_file_location("agent_setup", SCRIPTS_DIR / "agent_setup.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_setup"] = module
    spec.loader.exec_module(module)
    return module


def completed(command: list[str], returncode: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, "", "")


def test_install_skill_copies_into_custom_directory(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "install_skill.py"),
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
        [sys.executable, str(SCRIPTS_DIR / "agent_setup.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--skip-service" in result.stdout
    assert "--check" in result.stdout
    assert "--runtime" in result.stdout


def test_detects_docker_first(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent_setup()
    monkeypatch.setattr(module.shutil, "which", lambda name: {"docker": "/usr/bin/docker"}.get(name))
    monkeypatch.setattr(module, "run", lambda command, **_: completed(command, 0))

    command, runtime = module.container_compose_command("auto")

    assert command == ["/usr/bin/docker", "compose"]
    assert runtime == "docker"


def test_falls_back_to_podman_compose(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent_setup()
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: {"docker": "/usr/bin/docker", "podman": "/usr/bin/podman"}.get(name),
    )

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["/usr/bin/docker", "compose"]:
            return completed(command, 1)
        return completed(command, 0)

    monkeypatch.setattr(module, "run", fake_run)

    command, runtime = module.container_compose_command("auto")

    assert command == ["/usr/bin/podman", "compose"]
    assert runtime == "podman"


def test_falls_back_to_podman_compose_standalone(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent_setup()
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: {"podman-compose": "/usr/bin/podman-compose"}.get(name),
    )
    monkeypatch.setattr(module, "run", lambda command, **_: completed(command, 0))

    command, runtime = module.container_compose_command("auto")

    assert command == ["/usr/bin/podman-compose"]
    assert runtime == "podman"


def test_forced_docker_does_not_use_podman(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent_setup()
    monkeypatch.setattr(module.shutil, "which", lambda name: {"podman": "/usr/bin/podman"}.get(name))
    monkeypatch.setattr(module, "run", lambda command, **_: completed(command, 0))

    with pytest.raises(module.SetupError, match="Docker"):
        module.container_compose_command("docker")


def test_forced_podman_does_not_use_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent_setup()
    monkeypatch.setattr(module.shutil, "which", lambda name: {"docker": "/usr/bin/docker"}.get(name))
    monkeypatch.setattr(module, "run", lambda command, **_: completed(command, 0))

    with pytest.raises(module.SetupError, match="Podman"):
        module.container_compose_command("podman")
