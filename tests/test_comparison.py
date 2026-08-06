"""Report comparison tests."""

from __future__ import annotations

from container_security_baseline.comparison import compare_findings, compare_reports
from container_security_baseline.findings import fail
from container_security_baseline.models import Report
from container_security_baseline.severities import Severity
from container_security_baseline.statuses import Status


def test_resolved_finding(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    before = [fail(rule, evidence_redacted="p", file="c.yml", service="web", property_path="p")]
    result = compare_findings(before, [], score_before=75, score_after=100)
    assert len(result.resolved) == 1
    assert result.score_delta == 25


def test_new_finding(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    after = [fail(rule, evidence_redacted="p", file="c.yml", service="web", property_path="p")]
    result = compare_findings([], after)
    assert len(result.new) == 1


def test_unchanged_finding(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    f = fail(rule, evidence_redacted="p", file="c.yml", service="web", property_path="p")
    result = compare_findings([f], [f])
    assert len(result.unchanged) == 1


def test_severity_change(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    before = fail(
        rule,
        evidence_redacted="p",
        file="c.yml",
        service="web",
        property_path="p",
        severity=Severity.HIGH,
    )
    after = fail(
        rule,
        evidence_redacted="p",
        file="c.yml",
        service="web",
        property_path="p",
        severity=Severity.CRITICAL,
    )
    # Force same fingerprint
    after.fingerprint = before.fingerprint
    result = compare_findings([before], [after])
    assert result.severity_changes


def test_suppression_change(registry) -> None:
    rule = registry.get("CSB-CMP-040")
    before = fail(rule, evidence_redacted="x", file="c.yml", service="web", property_path="p")
    after = fail(rule, evidence_redacted="x", file="c.yml", service="web", property_path="p")
    after.fingerprint = before.fingerprint
    after.suppressed = True
    after.status = Status.SUPPRESSED
    result = compare_findings([before], [after])
    assert result.suppression_changes


def test_compare_reports_parsing_diff(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    f = fail(rule, evidence_redacted="p", file="c.yml", service="web")
    before = Report(findings=[f], score=75, parsing_status="ok")
    after = Report(findings=[], score=100, parsing_status="partial", parsing_warnings=["w"])
    result = compare_reports(before, after)
    assert result.parsing_differences
    assert result.score_delta == 25


def test_compare_to_dict(registry) -> None:
    result = compare_findings([], [], score_before=1, score_after=2)
    data = result.to_dict()
    assert data["score_delta"] == 1
