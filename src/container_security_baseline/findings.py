"""Finding builders with required fields and stable fingerprints."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime

from container_security_baseline import __version__
from container_security_baseline.models import Finding, RuleDefinition
from container_security_baseline.severities import Severity
from container_security_baseline.statuses import Status


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_fingerprint(
    rule_id: str,
    file: str,
    *,
    service: str | None = None,
    stage: str | None = None,
    property_path: str | None = None,
    evidence_token: str = "",
) -> str:
    """Stable fingerprint for deduplication (never includes secret values)."""
    material = "|".join(
        [
            rule_id,
            file,
            service or "",
            stage or "",
            property_path or "",
            evidence_token,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def build_finding(
    rule: RuleDefinition,
    *,
    status: Status,
    severity: Severity | None = None,
    summary: str | None = None,
    evidence_redacted: str = "",
    file: str = "",
    line_start: int | None = None,
    line_end: int | None = None,
    service: str | None = None,
    stage: str | None = None,
    property_path: str | None = None,
    error_message: str | None = None,
    confidence: str = "high",
) -> Finding:
    sev = severity or rule.severity
    fp = make_fingerprint(
        rule.id,
        file,
        service=service,
        stage=stage,
        property_path=property_path,
        evidence_token=evidence_redacted[:64],
    )
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        target_type=rule.target,
        category=rule.category,
        severity=sev,
        status=status,
        summary=summary or rule.summary,
        risk=rule.risk,
        evidence_redacted=evidence_redacted,
        remediation=rule.remediation,
        detailed_remediation=rule.detailed_remediation,
        references=list(rule.references),
        file=file,
        line_start=line_start,
        line_end=line_end,
        service=service,
        stage=stage,
        property_path=property_path,
        fingerprint=fp,
        evaluated_at_utc=_utc_now(),
        evaluator_version=__version__,
        error_message=error_message,
        patchability=rule.patchability,
        confidence=confidence,
    )


def fail(
    rule: RuleDefinition,
    *,
    evidence_redacted: str,
    file: str,
    severity: Severity | None = None,
    summary: str | None = None,
    service: str | None = None,
    stage: str | None = None,
    property_path: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
) -> Finding:
    return build_finding(
        rule,
        status=Status.FAIL,
        severity=severity,
        summary=summary,
        evidence_redacted=evidence_redacted,
        file=file,
        service=service,
        stage=stage,
        property_path=property_path,
        line_start=line_start,
        line_end=line_end,
    )


def warning_finding(
    rule: RuleDefinition,
    *,
    evidence_redacted: str,
    file: str,
    **kwargs: object,
) -> Finding:
    return build_finding(
        rule,
        status=Status.WARNING,
        evidence_redacted=evidence_redacted,
        file=file,
        **kwargs,  # type: ignore[arg-type]
    )


def passed(
    rule: RuleDefinition,
    *,
    file: str,
    service: str | None = None,
    stage: str | None = None,
    property_path: str | None = None,
) -> Finding:
    return build_finding(
        rule,
        status=Status.PASS,
        summary=f"Passed: {rule.title}",
        evidence_redacted="No issue detected for this rule target.",
        file=file,
        service=service,
        stage=stage,
        property_path=property_path,
    )


def not_applicable(
    rule: RuleDefinition,
    *,
    file: str,
    reason: str,
    service: str | None = None,
) -> Finding:
    return build_finding(
        rule,
        status=Status.NOT_APPLICABLE,
        summary=reason,
        evidence_redacted=reason,
        file=file,
        service=service,
    )


def unavailable(
    rule: RuleDefinition,
    *,
    file: str,
    reason: str,
    service: str | None = None,
) -> Finding:
    return build_finding(
        rule,
        status=Status.UNAVAILABLE,
        summary=reason,
        evidence_redacted=reason,
        file=file,
        service=service,
    )


def error_finding(
    rule: RuleDefinition,
    *,
    file: str,
    error_message: str,
) -> Finding:
    return build_finding(
        rule,
        status=Status.ERROR,
        summary="Rule evaluation error",
        evidence_redacted="[redacted-error]",
        file=file,
        error_message=error_message,
    )


def dedupe_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Deduplicate by fingerprint keeping first occurrence."""
    seen: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        result.append(finding)
    return result


__all__ = [
    "build_finding",
    "dedupe_findings",
    "error_finding",
    "fail",
    "make_fingerprint",
    "not_applicable",
    "passed",
    "unavailable",
    "warning_finding",
]
