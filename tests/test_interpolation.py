"""Interpolation detection without resolution."""

from __future__ import annotations

from container_security_baseline.interpolation import (
    contains_interpolation,
    detect_interpolations,
    is_interpolation_only,
)


def test_simple_braced() -> None:
    matches = detect_interpolations("image: ${IMAGE}")
    assert len(matches) == 1
    assert matches[0].variable == "IMAGE"
    assert matches[0].kind == "simple"


def test_dollar_simple() -> None:
    matches = detect_interpolations("user: $USER_ID")
    assert matches[0].variable == "USER_ID"


def test_default_value() -> None:
    matches = detect_interpolations("${PORT:-8080}")
    assert matches[0].kind == "default"
    assert matches[0].default_value == "8080"


def test_required_form() -> None:
    matches = detect_interpolations("${SECRET:?missing}")
    assert matches[0].kind == "required"
    assert matches[0].error_message == "missing"


def test_secret_like_default() -> None:
    matches = detect_interpolations("${API_SECRET:-SYNTHETIC_NOT_A_REAL_SECRET}")
    assert matches[0].secret_like_default is True


def test_contains_interpolation() -> None:
    assert contains_interpolation("x ${A} y")
    assert not contains_interpolation("plain text")


def test_is_interpolation_only() -> None:
    assert is_interpolation_only("${FOO}")
    assert not is_interpolation_only("prefix-${FOO}")


def test_multiple_matches() -> None:
    matches = detect_interpolations("${A} and ${B:-1}")
    assert len(matches) == 2
