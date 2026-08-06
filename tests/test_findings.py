"""Finding builder and fingerprint tests."""

from __future__ import annotations

from container_security_baseline.findings import (
    build_finding,
    dedupe_findings,
    error_finding,
    fail,
    make_fingerprint,
    not_applicable,
    passed,
    unavailable,
    warning_finding,
)
from container_security_baseline.statuses import Status


def test_fingerprint_stable(registry) -> None:
    a = make_fingerprint("CSB-CMP-001", "c.yml", service="web", property_path="p")
    b = make_fingerprint("CSB-CMP-001", "c.yml", service="web", property_path="p")
    assert a == b
    assert len(a) == 16


def test_fingerprint_differs_by_service() -> None:
    a = make_fingerprint("CSB-CMP-001", "c.yml", service="web")
    b = make_fingerprint("CSB-CMP-001", "c.yml", service="api")
    assert a != b


def test_fail_builder(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = fail(rule, evidence_redacted="x", file="c.yml", service="web")
    assert finding.status == Status.FAIL
    assert finding.fingerprint
    assert finding.rule_id == "CSB-CMP-001"


def test_passed_builder(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = passed(rule, file="c.yml")
    assert finding.status == Status.PASS


def test_warning_builder(registry) -> None:
    rule = registry.get("CSB-CMP-040")
    finding = warning_finding(rule, evidence_redacted="x", file="c.yml", service="web")
    assert finding.status == Status.WARNING


def test_na_and_unavailable(registry) -> None:
    rule = registry.get("CSB-CMP-091")
    assert not_applicable(rule, file="c.yml", reason="n/a").status == Status.NOT_APPLICABLE
    assert unavailable(rule, file="c.yml", reason="u").status == Status.UNAVAILABLE


def test_error_finding(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = error_finding(rule, file="c.yml", error_message="boom")
    assert finding.status == Status.ERROR
    assert finding.error_message == "boom"


def test_dedupe_findings(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    a = fail(rule, evidence_redacted="same", file="c.yml", service="web", property_path="p")
    b = fail(rule, evidence_redacted="same", file="c.yml", service="web", property_path="p")
    out = dedupe_findings([a, b])
    assert len(out) == 1


def test_build_finding_to_dict(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = build_finding(rule, status=Status.FAIL, evidence_redacted="x", file="c.yml")
    data = finding.to_dict()
    assert data["severity"] == rule.severity.value
    assert data["status"] == "Fail"


def test_fingerprint_excludes_secret_values() -> None:
    fp = make_fingerprint(
        "CSB-CMP-050",
        "c.yml",
        evidence_token="[REDACTED]",
    )
    assert "SYNTHETIC_NOT_A_REAL_SECRET" not in fp
