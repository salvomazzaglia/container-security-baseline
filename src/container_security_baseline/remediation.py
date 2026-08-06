"""Remediation guidance helpers."""

from __future__ import annotations

from typing import Any

from container_security_baseline.models import Finding, RuleDefinition
from container_security_baseline.rule_registry import RuleRegistry


def remediation_for_rule(rule: RuleDefinition) -> dict[str, Any]:
    return {
        "rule_id": rule.id,
        "title": rule.title,
        "concise": rule.remediation,
        "detailed": rule.detailed_remediation,
        "patchability": rule.patchability,
        "compatibility_considerations": (
            "Remediation may affect application behavior; validate in a non-production environment."
        ),
        "operational_validation_steps": [
            "Apply the proposed change in a review branch.",
            "Re-run container-security-baseline scan.",
            "Deploy to a non-production environment and verify application health.",
            "Confirm runtime permissions still meet operational needs.",
        ],
        "restart_required": True,
        "may_affect_behavior": True,
        "references": list(rule.references),
        "false_positives": rule.false_positives,
        "limitations": rule.limitations,
    }


def remediation_for_finding(finding: Finding, registry: RuleRegistry) -> dict[str, Any]:
    try:
        rule = registry.get(finding.rule_id)
        base = remediation_for_rule(rule)
    except Exception:  # noqa: BLE001
        base = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "concise": finding.remediation,
            "detailed": finding.detailed_remediation or finding.remediation,
            "patchability": finding.patchability,
        }
    base["finding_fingerprint"] = finding.fingerprint
    base["evidence_redacted"] = finding.evidence_redacted
    return base


SAFE_PATCHABLE_RULES = frozenset(
    {
        "CSB-CMP-001",
        "CSB-CMP-004",
        "CSB-CMP-022",
        "CSB-CMP-026",
        "CSB-CMP-040",
    }
)


__all__ = [
    "SAFE_PATCHABLE_RULES",
    "remediation_for_finding",
    "remediation_for_rule",
]
