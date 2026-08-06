#!/usr/bin/env python3
"""Repository safety guards for tracked source and examples."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ALLOWLIST_FILES = {
    "scripts/repository-guards.py",
    "tests/test_repository_guards.py",
}

# Code patterns: match as executable usage, not documentation mentions
FORBIDDEN_CODE = [
    (re.compile(r"\bdocker\.from_env\s*\("), "docker.from_env"),
    (re.compile(r"""subprocess\.[A-Za-z_]+\([^)]*['\"]docker['\"]"""), "subprocess.*docker"),
    (re.compile(r"\brequests\.get\s*\("), "requests.get"),
    (re.compile(r"\byaml\.load\s*\("), "yaml.load("),
    (re.compile(r"(?<![A-Za-z0-9_])eval\s*\("), "eval("),
    (re.compile(r"(?<![A-Za-z0-9_])exec\s*\("), "exec("),
    (re.compile(r"\bpickle\.(loads?|dump)\s*\("), "pickle"),
    (re.compile(r"shell\s*=\s*True"), "shell=True"),
]

SYNTHETIC_MARKERS = ("SYNTHETIC", "synthetic", "example.invalid", "registry.example.invalid")


def _strip_python_noise(text: str) -> str:
    """Remove comments and docstrings so documentation mentions are not flagged."""
    # Strip triple-quoted strings
    text = re.sub(r'"""[\s\S]*?"""', '""', text)
    text = re.sub(r"'''[\s\S]*?'''", "''", text)
    lines = []
    for line in text.splitlines():
        if "#" in line:
            code, _, _ = line.partition("#")
            lines.append(code)
        else:
            lines.append(line)
    return "\n".join(lines)


def _iter_py_files(root: Path) -> list[Path]:
    files: list[Path] = []
    if not root.exists():
        return files
    for path in root.rglob("*.py"):
        if any(part in {".venv", "__pycache__", ".git", "dist", "build"} for part in path.parts):
            continue
        files.append(path)
    return files


def _iter_example_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in {"README.md", ".dockerignore"}:
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif"}:
            continue
        if path.suffix.lower() in {
            ".yml",
            ".yaml",
            ".json",
            ".sarif",
            ".patch",
        } or path.name.startswith("Dockerfile"):
            files.append(path)
    return files


def main() -> int:
    errors: list[str] = []

    for dirname in ("src", "scripts", "tests"):
        base = REPO_ROOT / dirname
        for path in _iter_py_files(base):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel in ALLOWLIST_FILES:
                continue
            text = path.read_text(encoding="utf-8")
            scan = _strip_python_noise(text)
            # Also remove string literals that only mention patterns
            for regex, label in FORBIDDEN_CODE:
                if label == "shell=True":
                    if regex.search(scan):
                        errors.append(f"{rel}: forbidden pattern {label}")
                elif regex.search(scan):
                    errors.append(f"{rel}: forbidden pattern {label}")

    # GitHub workflows: fail only on active use, not "NEVER use ..." comments
    workflows = REPO_ROOT / ".github" / "workflows"
    if workflows.is_dir():
        for path in workflows.glob("*.yml"):
            rel = path.relative_to(REPO_ROOT).as_posix()
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "pull_request_target" in stripped:
                    errors.append(f"{rel}: forbidden pull_request_target")
                if re.search(r"runs-on:\s*\[?\s*self-hosted", stripped):
                    errors.append(f"{rel}: forbidden self-hosted runner")

    # Synthetic markers in examples
    examples = REPO_ROOT / "examples"
    if examples.is_dir():
        for path in _iter_example_files(examples):
            rel = path.relative_to(REPO_ROOT).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if path.name.endswith(".patch"):
                continue
            if path.name.startswith("sample-"):
                if "synthetic" not in text.lower() and "SYNTHETIC" not in text:
                    errors.append(f"{rel}: missing synthetic marker")
                continue
            if not any(m in text for m in SYNTHETIC_MARKERS):
                errors.append(f"{rel}: missing synthetic marker")

    # No .env at repo root / tracked locations
    for env_path in REPO_ROOT.rglob(".env"):
        if ".venv" in env_path.parts:
            continue
        try:
            rel = env_path.resolve().relative_to(REPO_ROOT.resolve())
        except ValueError:
            continue
        errors.append(f"tracked or present .env not allowed: {rel.as_posix()}")

    if errors:
        print(f"{len(errors)} repository guard failure(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("Repository guards passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
