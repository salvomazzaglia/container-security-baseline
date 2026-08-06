#!/usr/bin/env python3
"""Remove only known generated artifacts. Never deletes examples/, src/, docs, or schemas."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DIR_NAMES = (
    "temp",
    "reports",
    "results",
    "output",
    "local",
    "htmlcov",
    "dist",
    "build",
    "test-results",
)
FILE_NAMES = (".coverage",)
PROTECTED_PREFIXES = ("examples", "docs", "schemas", "config", "tests", ".github")


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def _collect_targets() -> list[Path]:
    targets: list[Path] = []
    for name in DIR_NAMES:
        path = REPO_ROOT / name
        if path.exists():
            targets.append(path)
    for name in FILE_NAMES:
        path = REPO_ROOT / name
        if path.exists():
            targets.append(path)
    for path in REPO_ROOT.rglob("*.egg-info"):
        try:
            rel = path.resolve().relative_to(REPO_ROOT.resolve())
        except ValueError:
            continue
        if any(part in {".venv", "node_modules"} for part in rel.parts):
            continue
        targets.append(path)
    return targets


def _is_protected(path: Path) -> bool:
    try:
        rel = path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return True
    if not rel.parts:
        return True
    top = rel.parts[0]
    if top == "src":
        # Allow removing egg-info under src; protect all other src content
        return not (path.name.endswith(".egg-info") or ".egg-info" in rel.parts)
    return top in PROTECTED_PREFIXES


def main() -> int:
    planned = _collect_targets()
    print("Planned removals:")
    if not planned:
        print("  (none)")
        return 0

    removed = 0
    for path in planned:
        if _is_protected(path):
            print(f"  SKIP protected: {path}")
            continue
        if _is_symlink(path):
            print(f"  REJECT symlink: {path}")
            continue
        rel = path.relative_to(REPO_ROOT)
        print(f"  REMOVE: {rel}")
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed += 1
        except OSError as exc:
            print(f"error: failed to remove {rel}: {exc}", file=sys.stderr)
            return 1

    print(f"Removed {removed} artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
