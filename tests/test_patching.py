"""Safe proposed patch generation tests."""

from __future__ import annotations

from pathlib import Path

from container_security_baseline.compose_loader import load_compose_yaml
from container_security_baseline.config import get_parser_limits, load_config
from container_security_baseline.findings import fail
from container_security_baseline.patching import PATCH_HEADER, generate_unified_diff
from container_security_baseline.source import SourceFile


def _doc(tmp_path: Path, text: str):
    path = tmp_path / "compose.yml"
    path.write_text(text, encoding="utf-8")
    source = SourceFile(
        path=path,
        display_path="compose.yml",
        content=text,
        size_bytes=len(text.encode("utf-8")),
        line_count=len(text.splitlines()),
    )
    return load_compose_yaml(source, get_parser_limits(load_config()))


def test_patch_privileged_to_false(tmp_path: Path, registry) -> None:
    text = (
        "# SYNTHETIC\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"
        "    privileged: true\n"
    )
    doc = _doc(tmp_path, text)
    rule = registry.get("CSB-CMP-001")
    finding = fail(
        rule,
        evidence_redacted="privileged",
        file="compose.yml",
        service="web",
        property_path="services.web.privileged",
    )
    result = generate_unified_diff(doc, [finding])
    assert "CSB-CMP-001" in result.applied_rules
    assert "privileged: false" in result.text
    assert PATCH_HEADER in result.text


def test_refuse_anchors(tmp_path: Path, registry) -> None:
    text = (
        "# SYNTHETIC\nservices:\n  web:\n"
        "    image: registry.example.invalid/a:1\n    privileged: true\n"
    )
    doc = _doc(tmp_path, text)
    # Force the refuse path used when anchors were detected during load
    doc.anchors_detected = True
    rule = registry.get("CSB-CMP-001")
    finding = fail(rule, evidence_redacted="p", file="compose.yml", service="web")
    result = generate_unified_diff(doc, [finding])
    assert result.refused_reasons
    assert any("anchor" in r.lower() or "alias" in r.lower() for r in result.refused_reasons)
    assert "diff --git" not in result.text


def test_refuse_json_format(tmp_path: Path, registry) -> None:
    from container_security_baseline.compose_loader import load_compose_json

    text = '{"services": {"web": {"image": "registry.example.invalid/a:1", "privileged": true}}}'
    path = tmp_path / "c.json"
    path.write_text(text, encoding="utf-8")
    source = SourceFile(
        path=path,
        display_path="c.json",
        content=text,
        size_bytes=len(text),
        line_count=1,
    )
    doc = load_compose_json(source, get_parser_limits(load_config()))
    rule = registry.get("CSB-CMP-001")
    finding = fail(rule, evidence_redacted="p", file="c.json", service="web")
    result = generate_unified_diff(doc, [finding])
    assert any("JSON" in r or "non-YAML" in r for r in result.refused_reasons)


def test_never_modifies_source_file(tmp_path: Path, registry) -> None:
    text = (
        "# SYNTHETIC\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"
        "    privileged: true\n"
    )
    path = tmp_path / "compose.yml"
    path.write_text(text, encoding="utf-8")
    before = path.read_text(encoding="utf-8")
    doc = _doc(tmp_path, text)
    rule = registry.get("CSB-CMP-001")
    finding = fail(rule, evidence_redacted="p", file="compose.yml", service="web")
    generate_unified_diff(doc, [finding])
    assert path.read_text(encoding="utf-8") == before


def test_add_cap_drop_all(tmp_path: Path, registry) -> None:
    text = "# SYNTHETIC\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"
    doc = _doc(tmp_path, text)
    rule = registry.get("CSB-CMP-022")
    finding = fail(rule, evidence_redacted="cap_drop", file="compose.yml", service="web")
    result = generate_unified_diff(doc, [finding])
    assert "CSB-CMP-022" in result.applied_rules
    assert "cap_drop:" in result.text


def test_add_no_new_privileges(tmp_path: Path, registry) -> None:
    text = "# SYNTHETIC\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"
    doc = _doc(tmp_path, text)
    rule = registry.get("CSB-CMP-026")
    finding = fail(rule, evidence_redacted="nnp", file="compose.yml", service="web")
    result = generate_unified_diff(doc, [finding])
    assert "no-new-privileges" in result.text


def test_read_only_true(tmp_path: Path, registry) -> None:
    text = "# SYNTHETIC\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"
    doc = _doc(tmp_path, text)
    rule = registry.get("CSB-CMP-040")
    finding = fail(rule, evidence_redacted="ro", file="compose.yml", service="web")
    result = generate_unified_diff(doc, [finding])
    assert "read_only: true" in result.text


def test_no_safe_patches_message(tmp_path: Path, registry) -> None:
    text = "# SYNTHETIC\nservices:\n  web:\n    image: registry.example.invalid/a:1\n"
    doc = _doc(tmp_path, text)
    result = generate_unified_diff(doc, [])
    assert "No safe automatic patches" in result.text or PATCH_HEADER in result.text
