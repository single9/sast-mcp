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


def load_script(name: str) -> ModuleType:
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
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


def test_skill_frontmatter_is_portable() -> None:
    text = (REPO_ROOT / "skills" / "sast-triage" / "SKILL.md").read_text(encoding="utf-8")

    assert text.startswith("---\n")
    frontmatter = text.split("---", 2)[1]
    assert "name: sast-triage" in frontmatter
    assert "description:" in frontmatter


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
    assert "--skill-target" in result.stdout


def test_install_skill_help_lists_targets() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "install_skill.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--target" in result.stdout
    assert "auto" in result.stdout
    assert "all" in result.stdout


def test_detects_docker_first(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script("agent_setup")
    monkeypatch.setattr(module.shutil, "which", lambda name: {"docker": "/usr/bin/docker"}.get(name))
    monkeypatch.setattr(module, "run", lambda command, **_: completed(command, 0))

    command, runtime = module.container_compose_command("auto")

    assert command == ["/usr/bin/docker", "compose"]
    assert runtime == "docker"


def test_falls_back_to_podman_compose(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script("agent_setup")
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
    module = load_script("agent_setup")
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
    module = load_script("agent_setup")
    monkeypatch.setattr(module.shutil, "which", lambda name: {"podman": "/usr/bin/podman"}.get(name))
    monkeypatch.setattr(module, "run", lambda command, **_: completed(command, 0))

    with pytest.raises(module.SetupError, match="Docker"):
        module.container_compose_command("docker")


def test_forced_podman_does_not_use_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script("agent_setup")
    monkeypatch.setattr(module.shutil, "which", lambda name: {"docker": "/usr/bin/docker"}.get(name))
    monkeypatch.setattr(module, "run", lambda command, **_: completed(command, 0))

    with pytest.raises(module.SetupError, match="Podman"):
        module.container_compose_command("podman")


def test_auto_skill_target_detects_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script("install_skill")
    monkeypatch.setattr(module, "client_available", lambda client: client in {"opencode", "claude"})

    assert module.resolve_targets(["auto"]) == ["opencode", "claude"]


def test_auto_skill_target_falls_back_to_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script("install_skill")
    monkeypatch.setattr(module, "client_available", lambda client: False)

    assert module.resolve_targets() == ["agents"]


def test_all_skill_targets() -> None:
    module = load_script("install_skill")

    assert module.resolve_targets(["all"]) == ["opencode", "claude", "agents"]


def test_explicit_skill_targets_are_deduplicated() -> None:
    module = load_script("install_skill")

    assert module.resolve_targets(["claude", "claude", "agents"]) == ["claude", "agents"]


def test_unknown_skill_target_raises() -> None:
    module = load_script("install_skill")

    with pytest.raises(ValueError, match="unknown skill target"):
        module.resolve_targets(["unknown"])


def test_install_skill_to_multiple_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script("install_skill")
    roots = {"opencode": tmp_path / "opencode", "claude": tmp_path / "claude"}
    monkeypatch.setattr(module, "default_skills_dir", lambda client: roots[client])

    destinations = module.install_skill(REPO_ROOT, targets=["opencode", "claude"])

    assert destinations == [roots["opencode"] / "sast-triage", roots["claude"] / "sast-triage"]
    for destination in destinations:
        assert (destination / "SKILL.md").is_file()
