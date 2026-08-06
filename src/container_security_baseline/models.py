"""Core dataclasses for findings, reports, rules, and related models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from container_security_baseline.severities import Severity
from container_security_baseline.statuses import Status


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SourceLocation:
    """Source location within an analyzed file."""

    file: str
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    property_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "property_path": self.property_path,
        }


@dataclass
class Finding:
    """A single rule evaluation result / finding."""

    rule_id: str
    title: str
    target_type: str
    category: str
    severity: Severity
    status: Status
    summary: str
    risk: str
    evidence_redacted: str
    remediation: str
    references: list[str] = field(default_factory=list)
    file: str = ""
    line_start: int | None = None
    line_end: int | None = None
    service: str | None = None
    stage: str | None = None
    property_path: str | None = None
    fingerprint: str = ""
    suppressed: bool = False
    suppression_id: str | None = None
    suppression_justification: str | None = None
    evaluated_at_utc: str = field(default_factory=_utc_now_iso)
    evaluator_version: str = "1.0.0"
    error_message: str | None = None
    detailed_remediation: str | None = None
    patchability: str = "manual"
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "target_type": self.target_type,
            "category": self.category,
            "severity": self.severity.value,
            "status": self.status.value,
            "summary": self.summary,
            "risk": self.risk,
            "evidence_redacted": self.evidence_redacted,
            "remediation": self.remediation,
            "detailed_remediation": self.detailed_remediation,
            "references": list(self.references),
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "service": self.service,
            "stage": self.stage,
            "property_path": self.property_path,
            "fingerprint": self.fingerprint,
            "suppressed": self.suppressed,
            "suppression_id": self.suppression_id,
            "suppression_justification": self.suppression_justification,
            "evaluated_at_utc": self.evaluated_at_utc,
            "evaluator_version": self.evaluator_version,
            "error_message": self.error_message,
            "patchability": self.patchability,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class RuleDefinition:
    """Metadata for a single security rule."""

    id: str
    title: str
    target: str
    category: str
    severity: Severity
    summary: str
    risk: str
    remediation: str
    detailed_remediation: str
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    patchability: str = "manual"
    false_positives: str = ""
    limitations: str = ""
    detection_logic: str = ""
    profiles: list[str] = field(default_factory=lambda: ["baseline", "strict", "development"])
    severity_overrides: dict[str, str] = field(default_factory=dict)

    def severity_for_profile(self, profile: str) -> Severity:
        override = self.severity_overrides.get(profile)
        if override:
            return Severity.from_string(override)
        return self.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "target": self.target,
            "category": self.category,
            "severity": self.severity.value,
            "summary": self.summary,
            "risk": self.risk,
            "remediation": self.remediation,
            "detailed_remediation": self.detailed_remediation,
            "references": list(self.references),
            "enabled": self.enabled,
            "patchability": self.patchability,
            "false_positives": self.false_positives,
            "limitations": self.limitations,
            "detection_logic": self.detection_logic,
            "profiles": list(self.profiles),
            "severity_overrides": dict(self.severity_overrides),
        }


@dataclass
class Suppression:
    """A documented suppression for a finding."""

    id: str
    rule_id: str
    target: str
    justification: str
    owner_label: str
    created_at_utc: str
    expires_at_utc: str
    review_reference: str
    enabled: bool = True
    property_path: str | None = None
    fingerprint: str | None = None
    service: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScoreResult:
    """Transparent security score outcome."""

    score: int
    grade: str
    starting_score: int = 100
    deductions: list[dict[str, Any]] = field(default_factory=list)
    explanation: str = ""
    partial: bool = False
    highest_severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "starting_score": self.starting_score,
            "deductions": list(self.deductions),
            "explanation": self.explanation,
            "partial": self.partial,
            "highest_severity": self.highest_severity,
        }


@dataclass
class InputSummary:
    """Summary of inputs analyzed in a scan."""

    project_root: str
    compose_files: list[str] = field(default_factory=list)
    dockerfile_files: list[str] = field(default_factory=list)
    compose_json_files: list[str] = field(default_factory=list)
    privacy_mode: str = "masked"
    policy_name: str = "baseline"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    """Complete analysis report."""

    tool_name: str = "container-security-baseline"
    tool_version: str = "1.0.0"
    schema_version: str = "1.0.0"
    generated_at_utc: str = field(default_factory=_utc_now_iso)
    synthetic: bool = False
    input_summary: InputSummary | None = None
    policy: dict[str, Any] = field(default_factory=dict)
    privacy_mode: str = "masked"
    parsing_status: str = "ok"
    files_analyzed: list[str] = field(default_factory=list)
    compose_services: list[str] = field(default_factory=list)
    dockerfile_stages: list[str] = field(default_factory=list)
    result_counts: dict[str, int] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    category_counts: dict[str, int] = field(default_factory=dict)
    score: int = 100
    grade: str = "A"
    score_explanation: str = ""
    highest_severity: str | None = None
    findings: list[Finding] = field(default_factory=list)
    suppressions: list[dict[str, Any]] = field(default_factory=list)
    unavailable_checks: list[dict[str, Any]] = field(default_factory=list)
    parsing_warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    security_notice: str = (
        "This report is the result of offline static configuration analysis only. "
        "It does not inspect image contents, running containers, the Docker daemon, "
        "or host runtime protections. A high score is not a security certification."
    )
    exit_code: int = 0
    score_detail: ScoreResult | None = None
    comparison: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "schema_version": self.schema_version,
            "generated_at_utc": self.generated_at_utc,
            "synthetic": self.synthetic,
            "input_summary": self.input_summary.to_dict() if self.input_summary else None,
            "policy": self.policy,
            "privacy_mode": self.privacy_mode,
            "parsing_status": self.parsing_status,
            "files_analyzed": list(self.files_analyzed),
            "compose_services": list(self.compose_services),
            "dockerfile_stages": list(self.dockerfile_stages),
            "result_counts": dict(self.result_counts),
            "severity_counts": dict(self.severity_counts),
            "category_counts": dict(self.category_counts),
            "score": self.score,
            "grade": self.grade,
            "score_explanation": self.score_explanation,
            "highest_severity": self.highest_severity,
            "findings": [f.to_dict() for f in self.findings],
            "suppressions": list(self.suppressions),
            "unavailable_checks": list(self.unavailable_checks),
            "parsing_warnings": list(self.parsing_warnings),
            "recommendations": list(self.recommendations),
            "limitations": list(self.limitations),
            "security_notice": self.security_notice,
            "exit_code": self.exit_code,
            "score_detail": self.score_detail.to_dict() if self.score_detail else None,
            "comparison": self.comparison,
        }


@dataclass
class ComparisonResult:
    """Result of comparing two reports or scans."""

    resolved: list[dict[str, Any]] = field(default_factory=list)
    new: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    severity_changes: list[dict[str, Any]] = field(default_factory=list)
    score_before: int = 0
    score_after: int = 0
    score_delta: int = 0
    suppression_changes: list[dict[str, Any]] = field(default_factory=list)
    parsing_differences: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = [
    "ComparisonResult",
    "Finding",
    "InputSummary",
    "Report",
    "RuleDefinition",
    "ScoreResult",
    "SourceLocation",
    "Suppression",
]
