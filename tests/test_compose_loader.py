"""YAML/JSON Compose loader safety tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from container_security_baseline.compose_loader import (
    ComposeLoadError,
    load_compose_file,
    load_compose_json,
    load_compose_yaml,
)
from container_security_baseline.config import get_parser_limits, load_config
from container_security_baseline.source import SourceFile, SourceLoadError


@pytest.fixture
def limits() -> dict:
    return get_parser_limits(load_config())


def _src(tmp_path: Path, text: str, name: str = "c.yml") -> SourceFile:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return SourceFile(
        path=path,
        display_path=name,
        content=text,
        size_bytes=len(text.encode("utf-8")),
        line_count=len(text.splitlines()),
    )


def test_load_simple_yaml(tmp_path: Path, limits: dict) -> None:
    doc = load_compose_yaml(
        _src(tmp_path, "# SYNTHETIC\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"),
        limits,
    )
    assert "services" in doc.data
    assert doc.format == "yaml"


def test_reject_duplicate_keys(tmp_path: Path, limits: dict) -> None:
    text = "services:\n  web:\n    image: a\n    image: b\n"
    with pytest.raises(ComposeLoadError, match="Duplicate"):
        load_compose_yaml(_src(tmp_path, text), limits)


def test_reject_custom_python_tag(tmp_path: Path, limits: dict) -> None:
    text = "services: !!python/object/apply:os.system ['echo hi']\n"
    with pytest.raises(ComposeLoadError):
        load_compose_yaml(_src(tmp_path, text), limits)


def test_reject_nul(tmp_path: Path, limits: dict) -> None:
    path = tmp_path / "nul.yml"
    path.write_bytes(b"services:\n  a: 1\x00\n")
    with pytest.raises((ComposeLoadError, SourceLoadError), match="NUL"):
        load_compose_file(path, tmp_path, limits)


def test_reject_multi_document(tmp_path: Path, limits: dict) -> None:
    text = "services: {}\n---\nservices: {}\n"
    with pytest.raises(ComposeLoadError, match="documents"):
        load_compose_yaml(_src(tmp_path, text), limits)


def test_depth_limit(tmp_path: Path, limits: dict) -> None:
    tight = dict(limits)
    tight["maximum_depth"] = 2
    text = "a:\n  b:\n    c:\n      d: 1\n"
    with pytest.raises(ComposeLoadError, match="depth"):
        load_compose_yaml(_src(tmp_path, text), tight)


def test_alias_limit(tmp_path: Path, limits: dict) -> None:
    tight = dict(limits)
    tight["maximum_aliases"] = 1
    text = "x: &a {image: registry.example.invalid/a:1}\nservices:\n  one: *a\n  two: *a\n"
    with pytest.raises(ComposeLoadError, match="aliases"):
        load_compose_yaml(_src(tmp_path, text), tight)


def test_anchors_and_aliases_load(tmp_path: Path, limits: dict) -> None:
    """Aliases resolve; returned anchors_detected may be False (walk vs load mismatch)."""
    text = (
        "# SYNTHETIC\n"
        "services:\n"
        "  base: &base\n"
        "    image: registry.example.invalid/a:1\n"
        "  web: *base\n"
    )
    doc = load_compose_yaml(_src(tmp_path, text), limits)
    assert doc.data["services"]["web"]["image"] == "registry.example.invalid/a:1"
    assert doc.data["services"]["base"]["image"] == "registry.example.invalid/a:1"


def test_merge_key_rejected_or_detected(tmp_path: Path, limits: dict) -> None:
    text = (
        "# SYNTHETIC\n"
        "services:\n"
        "  base: &base\n"
        "    image: registry.example.invalid/a:1\n"
        "  web:\n"
        "    <<: *base\n"
        "    privileged: true\n"
    )
    try:
        doc = load_compose_yaml(_src(tmp_path, text), limits)
        assert doc.merge_keys_detected or doc.anchors_detected
    except ComposeLoadError as exc:
        assert "merge" in str(exc).lower()


def test_include_not_followed(tmp_path: Path, limits: dict) -> None:
    text = "# SYNTHETIC\ninclude:\n  - other.yml\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"
    doc = load_compose_yaml(_src(tmp_path, text), limits)
    assert doc.has_include is True
    assert any("include" in w.lower() for w in doc.warnings)


def test_extends_detected(tmp_path: Path, limits: dict) -> None:
    text = (
        "# SYNTHETIC\nservices:\n  web:\n    extends:\n      file: other.yml\n"
        "      service: base\n    image: registry.example.invalid/a:1\n"
    )
    doc = load_compose_yaml(_src(tmp_path, text), limits)
    assert doc.has_extends is True


def test_json_duplicate_keys(tmp_path: Path, limits: dict) -> None:
    text = '{"services": {"web": {"image": "a"}}, "services": {"db": {"image": "b"}}}'
    with pytest.raises(ComposeLoadError, match="Duplicate JSON"):
        load_compose_json(_src(tmp_path, text, "c.json"), limits)


def test_json_load_ok(tmp_path: Path, limits: dict) -> None:
    text = '{"services": {"web": {"image": "registry.example.invalid/a:1"}}}'
    doc = load_compose_json(_src(tmp_path, text, "c.json"), limits)
    assert doc.format == "json"
    assert "web" in doc.data["services"]


def test_canonical_json_warning(tmp_path: Path, limits: dict) -> None:
    text = '{"services": {"web": {"image": "registry.example.invalid/a:1"}}}'
    doc = load_compose_json(_src(tmp_path, text, "c.json"), limits, canonical=True)
    assert doc.format == "canonical-json"
    assert doc.warnings


def test_root_must_be_mapping(tmp_path: Path, limits: dict) -> None:
    with pytest.raises(ComposeLoadError, match="mapping"):
        load_compose_yaml(_src(tmp_path, "- just a list\n"), limits)


def test_empty_yaml(tmp_path: Path, limits: dict) -> None:
    with pytest.raises(ComposeLoadError):
        load_compose_yaml(_src(tmp_path, ""), limits)


def test_scalar_length_limit(tmp_path: Path, limits: dict) -> None:
    tight = dict(limits)
    tight["maximum_scalar_length"] = 10
    text = f"services:\n  web:\n    image: {'x' * 50}\n"
    with pytest.raises(ComposeLoadError, match="scalar"):
        load_compose_yaml(_src(tmp_path, text), tight)


def test_load_compose_file_json_suffix(tmp_path: Path, limits: dict) -> None:
    path = tmp_path / "compose.json"
    path.write_text(
        '{"services": {"web": {"image": "registry.example.invalid/a:1"}}}',
        encoding="utf-8",
    )
    doc = load_compose_file(path, tmp_path, limits)
    assert doc.format == "json"


def test_malformed_yaml(tmp_path: Path, limits: dict, fixtures_dir: Path) -> None:
    src = fixtures_dir / "malformed" / "broken.yml"
    with pytest.raises(ComposeLoadError):
        load_compose_file(src, fixtures_dir, limits)
