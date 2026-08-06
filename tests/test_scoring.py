"""Scoring model tests."""

from __future__ import annotations

from container_security_baseline.findings import fail, passed
from container_security_baseline.scoring import calculate_score, grade_for_score
from container_security_baseline.severities import Severity
from container_security_baseline.statuses import Status


def test_grade_boundaries() -> None:
    assert grade_for_score(100) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(80) == "B"
    assert grade_for_score(70) == "C"
    assert grade_for_score(50) == "D"
    assert grade_for_score(49) == "F"


def test_perfect_score_no_findings() -> None:
    result = calculate_score([])
    assert result.score == 100
    assert result.grade == "A"
    assert result.deductions == []


def test_critical_deduction(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = fail(
        rule,
        evidence_redacted="privileged",
        file="c.yml",
        service="web",
        severity=Severity.CRITICAL,
    )
    result = calculate_score([finding])
    assert result.score == 75
    assert result.highest_severity == "Critical"


def test_suppressed_does_not_deduct(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = fail(
        rule,
        evidence_redacted="privileged",
        file="c.yml",
        service="web",
        severity=Severity.CRITICAL,
    )
    finding.suppressed = True
    finding.status = Status.SUPPRESSED
    result = calculate_score([finding])
    assert result.score == 100


def test_pass_does_not_deduct(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    result = calculate_score([passed(rule, file="c.yml", service="web")])
    assert result.score == 100


def test_multiple_deductions_clamp(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    findings = [
        fail(
            rule,
            evidence_redacted=f"p{i}",
            file="c.yml",
            service=f"s{i}",
            severity=Severity.CRITICAL,
        )
        for i in range(10)
    ]
    result = calculate_score(findings)
    assert result.score == 0


def test_custom_policy_deductions(registry) -> None:
    rule = registry.get("CSB-CMP-040")
    finding = fail(
        rule,
        evidence_redacted="ro",
        file="c.yml",
        service="web",
        severity=Severity.MEDIUM,
    )
    result = calculate_score(
        [finding],
        policy={"scoring_deductions": {"Medium": 40}, "starting_score": 100},
    )
    assert result.score == 60


def test_partial_flag_on_errors(registry) -> None:
    from container_security_baseline.findings import error_finding

    rule = registry.get("CSB-CMP-001")
    result = calculate_score(
        [error_finding(rule, file="c.yml", error_message="boom")], has_errors=True
    )
    assert result.partial is True


def test_high_deduction(registry) -> None:
    rule = registry.get("CSB-CMP-004")
    finding = fail(
        rule,
        evidence_redacted="sensitive",
        file="c.yml",
        service="web",
        severity=Severity.HIGH,
    )
    result = calculate_score([finding])
    assert result.score == 85
