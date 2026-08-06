"""Input safety / source loading tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from container_security_baseline.paths import PathSafetyError
from container_security_baseline.source import SourceLoadError, load_source_file, validate_text_blob


def test_load_utf8_file(tmp_path: Path) -> None:
    path = tmp_path / "a.yml"
    path.write_text("# SYNTHETIC\nservices: {}\n", encoding="utf-8")
    src = load_source_file(path, tmp_path)
    assert "services" in src.content
    assert src.line_count >= 1


def test_reject_nul_bytes(tmp_path: Path) -> None:
    path = tmp_path / "a.yml"
    path.write_bytes(b"services:\n  a: 1\x00\n")
    with pytest.raises(SourceLoadError, match="NUL"):
        load_source_file(path, tmp_path)


def test_reject_oversized(tmp_path: Path) -> None:
    path = tmp_path / "big.yml"
    path.write_bytes(b"x" * 1000)
    with pytest.raises(SourceLoadError, match="maximum size"):
        load_source_file(path, tmp_path, maximum_file_bytes=100)


def test_reject_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_bytes(b"\xff\xfe services")
    with pytest.raises(SourceLoadError, match="UTF-8"):
        load_source_file(path, tmp_path)


def test_reject_directory(tmp_path: Path) -> None:
    with pytest.raises(SourceLoadError, match="regular file"):
        load_source_file(tmp_path, tmp_path)


def test_path_outside_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-input-safety.yml"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises((SourceLoadError, PathSafetyError)):
        load_source_file(outside, tmp_path)


def test_validate_text_blob_nul() -> None:
    with pytest.raises(SourceLoadError):
        validate_text_blob("a\x00b")


def test_display_path_override(tmp_path: Path) -> None:
    path = tmp_path / "compose.yml"
    path.write_text("services: {}\n", encoding="utf-8")
    src = load_source_file(path, tmp_path, display_path="masked/compose.yml")
    assert src.display_path == "masked/compose.yml"
