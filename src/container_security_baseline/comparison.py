"""Compare two reports or finding sets."""

from __future__ import annotations

from typing import Any

from container_security_baseline.models import ComparisonResult, Finding, Report


def _index_findings(findings: list[Finding]) -> dict[str, Finding]:
    # Prefer fingerprint; fall back to composite key
    index: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint or "|".join(
            [
                finding.rule_id,
                finding.file,
                finding.service or "",
                finding.property_path or "",
            ]
        )
        index[key] = finding
    return index


def compare_findings(
    before: list[Finding],
    after: list[Finding],
    *,
    score_before: int = 0,
    score_after: int = 0,
) -> ComparisonResult:
    b = _index_findings(before)
    a = _index_findings(after)
    resolved: list[dict[str, Any]] = []
    new: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    severity_changes: list[dict[str, Any]] = []

    for key, bf in b.items():
        if key not in a:
            if bf.status.value in {"Fail", "Warning"}:
                resolved.append(bf.to_dict())
        else:
            af = a[key]
            if bf.severity != af.severity:
                severity_changes.append(
                    {
                        "fingerprint": key,
                        "rule_id": bf.rule_id,
                        "before": bf.severity.value,
                        "after": af.severity.value,
                    }
                )
            else:
                unchanged.append(af.to_dict())

    for key, af in a.items():
        if key not in b and af.status.value in {"Fail", "Warning"}:
            new.append(af.to_dict())

    suppression_changes: list[dict[str, Any]] = []
    for key, after_finding in b.items():
        before_finding = a.get(key)
        if before_finding is not None and after_finding.suppressed != before_finding.suppressed:
            suppression_changes.append(
                {
                    "fingerprint": key,
                    "rule_id": after_finding.rule_id,
                    "before_suppressed": before_finding.suppressed,
                    "after_suppressed": after_finding.suppressed,
                }
            )

    return ComparisonResult(
        resolved=resolved,
        new=new,
        unchanged=unchanged,
        severity_changes=severity_changes,
        score_before=score_before,
        score_after=score_after,
        score_delta=score_after - score_before,
        suppression_changes=suppression_changes,
    )


def compare_reports(before: Report, after: Report) -> ComparisonResult:
    result = compare_findings(
        before.findings,
        after.findings,
        score_before=before.score,
        score_after=after.score,
    )
    parsing_differences: list[str] = []
    if before.parsing_status != after.parsing_status:
        parsing_differences.append(
            f"parsing_status {before.parsing_status} -> {after.parsing_status}"
        )
    if before.parsing_warnings != after.parsing_warnings:
        parsing_differences.append("parsing_warnings differ")
    result.parsing_differences = parsing_differences
    return result


__all__ = ["compare_findings", "compare_reports"]
