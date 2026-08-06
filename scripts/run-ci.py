#!/usr/bin/env python3
"""Local CI runner matching .github/workflows/ci.yml steps.

Uses subprocess with shell disabled. Never invokes Docker or network tools.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _python() -> str:
    venv = REPO_ROOT / ".venv"
    if sys.platform == "win32":
        candidate = venv / "Scripts" / "python.exe"
    else:
        candidate = venv / "bin" / "python"
    if candidate.is_file():
        return str(candidate)
    return sys.executable


def run_step(name: str, argv: list[str]) -> int:
    print(f"\n=== {name} ===")
    print(" ".join(argv))
    result = subprocess.run(argv, cwd=str(REPO_ROOT), check=False)
    print(f"exit={result.returncode}")
    return int(result.returncode)


def main() -> int:
    py = _python()
    steps: list[tuple[str, list[str]]] = [
        ("ruff check", [py, "-m", "ruff", "check", "src", "tests", "scripts"]),
        ("ruff format --check", [py, "-m", "ruff", "format", "--check", "src", "tests", "scripts"]),
        ("mypy", [py, "-m", "mypy"]),
        ("pytest", [py, "-m", "pytest", "--junitxml=test-results/junit.xml"]),
        ("generate-demo-data", [py, "scripts/generate-demo-data.py"]),
        ("generate-sample-reports", [py, "scripts/generate-sample-reports.py"]),
        ("validate-schemas", [py, "scripts/validate-schemas.py"]),
        ("repository-guards", [py, "scripts/repository-guards.py"]),
        ("package build", [py, "-m", "build"]),
    ]

    failures: list[str] = []
    for name, argv in steps:
        code = run_step(name, argv)
        if code != 0:
            failures.append(f"{name} (exit {code})")

    print("\n=== CI SUMMARY ===")
    print(f"steps_total={len(steps)}")
    print(f"steps_failed={len(failures)}")
    print(f"steps_passed={len(steps) - len(failures)}")
    if failures:
        for item in failures:
            print(f"FAIL: {item}")
        return 1
    print("ALL PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
