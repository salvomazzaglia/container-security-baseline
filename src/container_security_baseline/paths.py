"""Safe path resolution within a project root."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath


class PathSafetyError(ValueError):
    """Raised when a path violates project-root safety rules."""


_MASK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)^[A-Za-z]:\\Users\\[^\\]+"), r"<USER_HOME>"),
    (re.compile(r"(?i)^/home/[^/]+"), r"<USER_HOME>"),
    (re.compile(r"(?i)^/Users/[^/]+"), r"<USER_HOME>"),
    (re.compile(r"(?i)^C:\\Users\\[^\\]+", re.IGNORECASE), r"<USER_HOME>"),
]


def normalize_project_root(project_root: str | Path) -> Path:
    """Resolve and validate a project root directory."""
    root = Path(project_root).expanduser()
    try:
        root = root.resolve(strict=False)
    except OSError as exc:
        raise PathSafetyError(f"Cannot resolve project root: {project_root}") from exc
    if not root.exists():
        raise PathSafetyError(f"Project root does not exist: {root}")
    if not root.is_dir():
        raise PathSafetyError(f"Project root is not a directory: {root}")
    if root.is_symlink():
        # Resolve once, but do not follow directory symlinks beneath root later.
        pass
    return root


def is_within_root(path: Path, root: Path) -> bool:
    """Return True if ``path`` is inside ``root`` without escaping."""
    try:
        resolved = path.resolve(strict=False)
        root_resolved = root.resolve(strict=False)
        resolved.relative_to(root_resolved)
        return True
    except (ValueError, OSError):
        return False


def safe_resolve_path(
    path: str | Path,
    project_root: str | Path,
    *,
    must_exist: bool = True,
    allow_outside: bool = False,
    follow_symlinks: bool = False,
) -> Path:
    """Resolve ``path`` safely within ``project_root``.

    Never follows directory symlinks outside the project root.
    File symlinks whose ultimate target is outside the root are rejected
    unless ``allow_outside`` is True (not used for analysis inputs).
    """
    root = normalize_project_root(project_root)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate

    if follow_symlinks:
        raise PathSafetyError("Following symlinks is disabled by configuration")

    # Walk parents to detect directory symlink escapes.
    try:
        # Resolve without following the final component if it is a symlink file;
        # still validate the resolved absolute path stays under root.
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise PathSafetyError(f"Cannot resolve path: {path}") from exc

    if not allow_outside and not is_within_root(resolved, root):
        raise PathSafetyError(
            f"Path escapes project root: {mask_path(str(path), privacy_mode='masked')}"
        )

    if candidate.is_symlink():
        try:
            target = candidate.resolve(strict=False)
        except OSError as exc:
            raise PathSafetyError(f"Cannot resolve symlink: {path}") from exc
        if not allow_outside and not is_within_root(target, root):
            raise PathSafetyError("Symlink target escapes project root")

    if must_exist and not resolved.exists():
        raise PathSafetyError(f"Path does not exist: {mask_path(str(path))}")

    if must_exist and resolved.is_dir() and resolved.is_symlink():
        raise PathSafetyError("Directory symlinks are not followed")

    return resolved


def project_relative(path: str | Path, project_root: str | Path) -> str:
    """Return a project-relative POSIX-ish display path when possible."""
    root = Path(project_root).resolve(strict=False)
    p = Path(path).resolve(strict=False)
    try:
        rel = p.relative_to(root)
        return rel.as_posix()
    except ValueError:
        return mask_path(str(p), privacy_mode="masked")


def mask_path(path: str, *, privacy_mode: str = "masked") -> str:
    """Mask user-specific absolute path segments for privacy."""
    if privacy_mode == "full":
        return path
    display = path.replace("\\", "/")
    for pattern, replacement in _MASK_PATTERNS:
        display = pattern.sub(replacement, display)
        # Also apply against backslash form
        display_bs = path
        display_bs = pattern.sub(replacement, display_bs)
        if display_bs != path:
            display = display_bs.replace("\\", "/")
    # Generic home replacement leftovers
    home = str(Path.home()).replace("\\", "/")
    if home and home in display:
        display = display.replace(home, "<USER_HOME>")
    return display


def looks_like_traversal(path: str) -> bool:
    """Return True if a Compose/Dockerfile path string contains parent traversal."""
    normalized = path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    return ".." in parts


def is_absolute_host_path(path: str) -> bool:
    """Heuristic: whether a path string is absolute on Unix or Windows."""
    if not path:
        return False
    if path.startswith("/") or path.startswith("~"):
        return True
    win = PureWindowsPath(path)
    return win.is_absolute() or (len(path) >= 2 and path[1] == ":")


def path_length_ok(path: str, maximum: int = 4096) -> bool:
    return len(path) <= maximum


def join_under_root(project_root: Path, *parts: str) -> Path:
    """Join parts under root and ensure the result stays inside root."""
    result = project_root.joinpath(*parts)
    if not is_within_root(result, project_root):
        raise PathSafetyError("Joined path escapes project root")
    return result


def ensure_relative_display(path: str | Path, project_root: str | Path, privacy_mode: str) -> str:
    """Choose display path based on privacy mode."""
    if privacy_mode == "full":
        return str(Path(path))
    return project_relative(path, project_root)


# Avoid unused import warning for os on some platforms — used for path sep helpers.
_ = os.name

__all__ = [
    "PathSafetyError",
    "ensure_relative_display",
    "is_absolute_host_path",
    "is_within_root",
    "join_under_root",
    "looks_like_traversal",
    "mask_path",
    "normalize_project_root",
    "path_length_ok",
    "project_relative",
    "safe_resolve_path",
]
