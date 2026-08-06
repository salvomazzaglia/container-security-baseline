"""Tests for path safety helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from container_security_baseline.paths import (
    PathSafetyError,
    ensure_relative_display,
    is_absolute_host_path,
    is_within_root,
    join_under_root,
    looks_like_traversal,
    mask_path,
    normalize_project_root,
    path_length_ok,
    project_relative,
    safe_resolve_path,
)


def test_normalize_project_root(tmp_path: Path) -> None:
    root = normalize_project_root(tmp_path)
    assert root.is_dir()


def test_normalize_missing_root(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        normalize_project_root(tmp_path / "missing")


def test_normalize_file_not_dir(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(PathSafetyError):
        normalize_project_root(f)


def test_safe_resolve_within_root(tmp_path: Path) -> None:
    child = tmp_path / "a.yml"
    child.write_text("x", encoding="utf-8")
    resolved = safe_resolve_path(child, tmp_path)
    assert resolved == child.resolve()


def test_safe_resolve_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-escape.txt"
    outside.write_text("nope", encoding="utf-8")
    with pytest.raises(PathSafetyError):
        safe_resolve_path(outside, tmp_path, must_exist=True)


def test_is_within_root(tmp_path: Path) -> None:
    child = tmp_path / "sub" / "f"
    child.parent.mkdir()
    child.write_text("x", encoding="utf-8")
    assert is_within_root(child, tmp_path)
    assert not is_within_root(tmp_path.parent, tmp_path)


def test_looks_like_traversal() -> None:
    assert looks_like_traversal("../etc/passwd")
    assert looks_like_traversal("a/../../b")
    assert not looks_like_traversal("app/data")


def test_is_absolute_host_path() -> None:
    assert is_absolute_host_path("/etc")
    assert is_absolute_host_path(r"C:\Windows")
    assert is_absolute_host_path("~/.ssh")
    assert not is_absolute_host_path("./rel")


def test_mask_path_user_home() -> None:
    masked = mask_path(r"C:\Users\alice\project", privacy_mode="masked")
    assert "alice" not in masked or "<USER_HOME>" in masked


def test_mask_path_full_mode() -> None:
    path = "/home/alice/x"
    assert mask_path(path, privacy_mode="full") == path


def test_project_relative(tmp_path: Path) -> None:
    f = tmp_path / "compose.yml"
    f.write_text("x", encoding="utf-8")
    assert project_relative(f, tmp_path) == "compose.yml"


def test_join_under_root(tmp_path: Path) -> None:
    p = join_under_root(tmp_path, "a", "b.yml")
    assert is_within_root(p, tmp_path)


def test_path_length_ok() -> None:
    assert path_length_ok("short")
    assert not path_length_ok("x" * 5000, maximum=100)


def test_ensure_relative_display(tmp_path: Path) -> None:
    f = tmp_path / "f.yml"
    f.write_text("x", encoding="utf-8")
    assert ensure_relative_display(f, tmp_path, "masked") == "f.yml"


def test_safe_resolve_missing(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        safe_resolve_path(tmp_path / "nope.yml", tmp_path, must_exist=True)
