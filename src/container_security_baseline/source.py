"""Safe source-file loading with size, encoding, and NUL checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from container_security_baseline.paths import PathSafetyError, safe_resolve_path


class SourceLoadError(ValueError):
    """Raised when a source file cannot be loaded safely."""


@dataclass(frozen=True)
class SourceFile:
    """Loaded text source with metadata."""

    path: Path
    display_path: str
    content: str
    size_bytes: int
    encoding: str = "utf-8"
    line_count: int = 0

    def lines(self) -> list[str]:
        return self.content.splitlines()


def load_source_file(
    path: str | Path,
    project_root: str | Path,
    *,
    maximum_file_bytes: int = 2_097_152,
    display_path: str | None = None,
    must_be_within_root: bool = True,
) -> SourceFile:
    """Load a UTF-8 text file with safety limits.

    Rejects:
    - Oversized files
    - NUL bytes
    - Invalid UTF-8
    - Paths outside the project root (when required)
    """
    resolved = safe_resolve_path(
        path,
        project_root,
        must_exist=True,
        allow_outside=not must_be_within_root,
        follow_symlinks=False,
    )
    if not resolved.is_file():
        raise SourceLoadError(f"Not a regular file: {path}")

    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise SourceLoadError(f"Cannot stat file: {path}") from exc

    if size > maximum_file_bytes:
        raise SourceLoadError(f"File exceeds maximum size of {maximum_file_bytes} bytes")

    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise SourceLoadError(f"Cannot read file: {path}") from exc

    if b"\x00" in raw:
        raise SourceLoadError("NUL byte rejected in source file")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceLoadError("Source file is not valid UTF-8") from exc

    display = display_path if display_path is not None else str(resolved)
    line_count = len(text.splitlines()) if text else 0
    return SourceFile(
        path=resolved,
        display_path=display,
        content=text,
        size_bytes=len(raw),
        encoding="utf-8",
        line_count=line_count,
    )


def validate_text_blob(text: str, *, label: str = "input") -> None:
    """Validate an in-memory text blob for NUL bytes."""
    if "\x00" in text:
        raise SourceLoadError(f"NUL byte rejected in {label}")


__all__ = [
    "PathSafetyError",
    "SourceFile",
    "SourceLoadError",
    "load_source_file",
    "validate_text_blob",
]
