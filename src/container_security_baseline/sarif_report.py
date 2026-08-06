"""SARIF 2.1.0 report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from container_security_baseline.models import Report
from container_security_baseline.redaction import ensure_no_secret_leak
from container_security_baseline.rule_registry import RuleRegistry, load_rules
from container_security_baseline.statuses import Status

_SEVERITY_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "note",
}


def _sarif_rules(registry: RuleRegistry) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for rule in registry.list_rules():
        rules.append(
            {
                "id": rule.id,
                "name": rule.title,
                "shortDescription": {"text": rule.summary},
                "fullDescription": {"text": rule.risk},
                "help": {"text": rule.remediation},
                "properties": {
                    "category": rule.category,
                    "severity": rule.severity.value,
                    "security-severity": rule.severity.value.lower(),
                },
            }
        )
    return rules


def report_to_sarif(
    report: Report,
    *,
    registry: RuleRegistry | None = None,
    include_passed: bool = False,
) -> dict[str, Any]:
    reg = registry or load_rules()
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.status == Status.PASS and not include_passed:
            continue
        level = _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning")
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {"text": finding.summary},
            "fingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {
                "severity": finding.severity.value,
                "status": finding.status.value,
                "category": finding.category,
                "evidence_redacted": finding.evidence_redacted,
                "remediation": finding.remediation,
                "service": finding.service,
                "stage": finding.stage,
            },
        }
        if finding.suppressed or finding.status == Status.SUPPRESSED:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "justification": finding.suppression_justification or "suppressed",
                }
            ]
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file.replace("\\", "/")},
            }
        }
        if finding.line_start is not None:
            region: dict[str, Any] = {"startLine": finding.line_start}
            if finding.line_end is not None:
                region["endLine"] = finding.line_end
            loc["physicalLocation"]["region"] = region
        result["locations"] = [loc]
        results.append(result)

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool_name,
                        "version": report.tool_version,
                        "informationUri": (
                            "https://github.com/salvomazzaglia/container-security-baseline"
                        ),
                        "rules": _sarif_rules(reg),
                    }
                },
                "results": results,
                "properties": {
                    "score": report.score,
                    "grade": report.grade,
                    "synthetic": report.synthetic,
                    "privacy_mode": report.privacy_mode,
                    "security_notice": report.security_notice,
                },
            }
        ],
    }
    return sarif


def write_sarif_report(
    report: Report,
    path: str | Path,
    *,
    registry: RuleRegistry | None = None,
) -> None:
    payload = json.dumps(
        report_to_sarif(report, registry=registry),
        indent=2,
        ensure_ascii=False,
    )
    Path(path).write_text(ensure_no_secret_leak(payload) + "\n", encoding="utf-8")


__all__ = ["report_to_sarif", "write_sarif_report"]
