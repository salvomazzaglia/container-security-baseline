"""Helpers for constructing and comparing source locations."""

from __future__ import annotations

from container_security_baseline.models import SourceLocation


def make_location(
    file: str,
    *,
    line_start: int | None = None,
    line_end: int | None = None,
    column_start: int | None = None,
    column_end: int | None = None,
    property_path: str | None = None,
) -> SourceLocation:
    """Create a SourceLocation with normalized line ranges."""
    start = line_start
    end = line_end if line_end is not None else line_start
    if start is not None and start < 1:
        start = 1
    if end is not None and start is not None and end < start:
        end = start
    return SourceLocation(
        file=file,
        line_start=start,
        line_end=end,
        column_start=column_start,
        column_end=column_end,
        property_path=property_path,
    )


def location_from_dict(data: dict[str, object]) -> SourceLocation:
    """Rebuild a SourceLocation from a plain dict."""
    return SourceLocation(
        file=str(data.get("file", "")),
        line_start=_opt_int(data.get("line_start")),
        line_end=_opt_int(data.get("line_end")),
        column_start=_opt_int(data.get("column_start")),
        column_end=_opt_int(data.get("column_end")),
        property_path=_opt_str(data.get("property_path")),
    )


def format_location(loc: SourceLocation) -> str:
    """Human-readable location string."""
    if loc.line_start is None:
        base = loc.file
    elif loc.line_end is None or loc.line_end == loc.line_start:
        base = f"{loc.file}:{loc.line_start}"
    else:
        base = f"{loc.file}:{loc.line_start}-{loc.line_end}"
    if loc.property_path:
        return f"{base} ({loc.property_path})"
    return base


def _opt_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _opt_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


__all__ = [
    "format_location",
    "location_from_dict",
    "make_location",
]
