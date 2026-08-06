"""Transparent scoring model."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from container_security_baseline.findings import dedupe_findings
from container_security_baseline.models import Finding, ScoreResult
from container_security_baseline.severities import DEFAULT_DEDUCTIONS, Severity
from container_security_baseline.statuses import Status


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def calculate_score(
    findings: Sequence[Finding],
    *,
    policy: dict[str, Any] | None = None,
    has_errors: bool = False,
) -> ScoreResult:
    """Calculate score from findings.

    - Start at 100 (or policy override)
    - Deduct per unique failing/warning finding by severity
    - Suppressed / Pass / N/A / Unavailable do not deduct
    - Clamp 0-100
    """
    policy = policy or {}
    starting = int((policy.get("scoring_deductions") and 100) or 100)
    if "starting_score" in policy:
        starting = int(policy["starting_score"])
    deductions_map = dict(DEFAULT_DEDUCTIONS)
    custom = policy.get("scoring_deductions") or {}
    for key, value in custom.items():
        deductions_map[Severity.from_string(str(key))] = int(value)

    unique = dedupe_findings(list(findings))
    deductions: list[dict[str, Any]] = []
    score = starting
    highest: Severity | None = None

    for finding in unique:
        if finding.status in {
            Status.PASS,
            Status.NOT_APPLICABLE,
            Status.UNAVAILABLE,
            Status.ERROR,
        }:
            continue
        if finding.suppressed or finding.status == Status.SUPPRESSED:
            continue
        if finding.status not in {Status.FAIL, Status.WARNING}:
            continue
        amount = deductions_map.get(finding.severity, 0)
        if amount:
            score -= amount
            deductions.append(
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "amount": amount,
                    "fingerprint": finding.fingerprint,
                    "service": finding.service,
                }
            )
        if highest is None or finding.severity.rank > highest.rank:
            highest = finding.severity

    score = max(0, min(100, score))
    partial = has_errors or any(f.status == Status.ERROR for f in unique)
    grade = grade_for_score(score)
    explanation = (
        f"Started at {starting}. Applied {len(deductions)} finding-based deduction(s). "
        f"Suppressed findings do not reduce the score. "
        f"Grade {grade} is a prioritization aid, not certification."
    )
    if partial:
        explanation += " Score marked partial due to evaluation/parsing errors."

    return ScoreResult(
        score=score,
        grade=grade,
        starting_score=starting,
        deductions=deductions,
        explanation=explanation,
        partial=partial,
        highest_severity=highest.value if highest else None,
    )


__all__ = ["calculate_score", "grade_for_score"]
