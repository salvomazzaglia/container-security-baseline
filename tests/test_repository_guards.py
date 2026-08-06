"""Repository guard script and related safety invariants."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def test_repository_guards_script_passes(repo_root: Path) -> None:
    script = repo_root / "scripts" / "repository-guards.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(repo_root),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_no_docker_from_env_in_src(repo_root: Path) -> None:
    src = repo_root / "src"
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "docker.from_env" not in text


def test_no_yaml_unsafe_load_in_src(repo_root: Path) -> None:
    src = repo_root / "src"
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "yaml.load(" not in text


def test_no_shell_true_in_src(repo_root: Path) -> None:
    src = repo_root / "src"
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text


def test_ci_workflow_no_self_hosted_runner(repo_root: Path) -> None:
    workflow = repo_root / ".github" / "workflows" / "ci.yml"
    text = workflow.read_text(encoding="utf-8")
    active_lines = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
    active = "\n".join(active_lines)
    assert "pull_request_target" not in active
    assert not re.search(r"runs-on:\s*\[?\s*self-hosted", active)


def test_examples_have_synthetic_markers(repo_root: Path) -> None:
    compose = repo_root / "examples" / "compose" / "insecure-compose.yml"
    text = compose.read_text(encoding="utf-8")
    assert "SYNTHETIC" in text.upper()
    assert "example.invalid" in text or "registry.example.invalid" in text


def test_no_env_file_in_repo_root(repo_root: Path) -> None:
    assert not (repo_root / ".env").exists()
