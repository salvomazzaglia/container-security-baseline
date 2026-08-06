"""Remediation guidance tests."""

from __future__ import annotations

from container_security_baseline.remediation import (
    SAFE_PATCHABLE_RULES,
    remediation_for_finding,
    remediation_for_rule,
)


def test_remediation_for_rule(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    info = remediation_for_rule(rule)
    assert info["rule_id"] == "CSB-CMP-001"
    assert info["concise"]
    assert info["operational_validation_steps"]
    assert info["may_affect_behavior"] is True


def test_remediation_for_finding(registry, failing_findings) -> None:
    info = remediation_for_finding(failing_findings[0], registry)
    assert info["finding_fingerprint"] == failing_findings[0].fingerprint
    assert "evidence_redacted" in info


def test_safe_patchable_rules() -> None:
    assert "CSB-CMP-001" in SAFE_PATCHABLE_RULES
    assert "CSB-CMP-026" in SAFE_PATCHABLE_RULES


def test_unknown_rule_fallback(registry) -> None:
    from container_security_baseline.models import Finding
    from container_security_baseline.severities import Severity
    from container_security_baseline.statuses import Status

    finding = Finding(
        rule_id="CSB-UNKNOWN-999",
        title="x",
        target_type="compose",
        category="x",
        severity=Severity.LOW,
        status=Status.FAIL,
        summary="s",
        risk="r",
        evidence_redacted="e",
        remediation="fix it",
        fingerprint="abc",
    )
    info = remediation_for_finding(finding, registry)
    assert info["concise"] == "fix it"
