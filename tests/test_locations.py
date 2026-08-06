"""Tests for source location helpers."""

from __future__ import annotations

from container_security_baseline.locations import format_location, location_from_dict, make_location


def test_make_location_basic() -> None:
    loc = make_location("compose.yml", line_start=3, property_path="services.web")
    assert loc.file == "compose.yml"
    assert loc.line_start == 3
    assert loc.line_end == 3
    assert loc.property_path == "services.web"


def test_make_location_clamps_low_line() -> None:
    loc = make_location("f", line_start=0)
    assert loc.line_start == 1


def test_make_location_end_before_start() -> None:
    loc = make_location("f", line_start=5, line_end=2)
    assert loc.line_end == 5


def test_location_from_dict() -> None:
    loc = location_from_dict({"file": "a.yml", "line_start": 2, "property_path": "x"})
    assert loc.file == "a.yml"
    assert loc.line_start == 2
    assert loc.property_path == "x"


def test_format_location_range() -> None:
    loc = make_location("d.f", line_start=1, line_end=3, property_path="USER")
    text = format_location(loc)
    assert "d.f:1-3" in text
    assert "USER" in text


def test_format_location_no_line() -> None:
    loc = make_location("only.yml")
    assert format_location(loc) == "only.yml"


def test_to_dict_roundtrip() -> None:
    loc = make_location("x", line_start=4, column_start=1)
    data = loc.to_dict()
    assert data["line_start"] == 4
    assert location_from_dict(data).column_start == 1
