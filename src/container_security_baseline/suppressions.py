"""Suppression validation and application."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from container_security_baseline.models import Finding, Suppression
from container_security_baseline.severities import Severity
from container_security_baseline.statuses import Status

REQUIRED_FIELDS = (
    "id",
    "rule_id",
    "target",
    "justification",
    "owner_label",
    "created_at_utc",
    "expires_at_utc",
    "review_reference",
    "enabled",
)


class SuppressionError(ValueError):
    """Invalid suppression document."""


def _parse_utc(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def load_suppressions(path: str | Path | None) -> tuple[list[Suppression], list[str]]:
    """Load suppressions; return (valid, invalid_messages)."""
    if path is None:
        return [], []
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SuppressionError(f"Cannot load suppressions: {exc}") from exc

    items = data.get("suppressions", data if isinstance(data, list) else None)
    if not isinstance(items, list):
        raise SuppressionError("suppressions must be a list")

    seen_ids: set[str] = set()
    valid: list[Suppression] = []
    invalid: list[str] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            invalid.append(f"[{idx}] not an object")
            continue
        try:
            supp = validate_suppression(item, seen_ids=seen_ids)
            valid.append(supp)
            seen_ids.add(supp.id)
        except SuppressionError as exc:
            invalid.append(str(exc))
    return valid, invalid


def validate_suppression(
    item: dict[str, Any],
    *,
    seen_ids: set[str] | None = None,
    known_rule_ids: set[str] | None = None,
) -> Suppression:
    for field in REQUIRED_FIELDS:
        if field not in item:
            raise SuppressionError(f"Suppression missing required field: {field}")
    sid = str(item["id"]).strip()
    if not sid:
        raise SuppressionError("Suppression id must be non-empty")
    if seen_ids is not None and sid in seen_ids:
        raise SuppressionError(f"Duplicate suppression id: {sid}")
    justification = str(item["justification"]).strip()
    if not justification:
        raise SuppressionError(f"{sid}: justification must be non-empty")
    created = _parse_utc(str(item["created_at_utc"]))
    expires = _parse_utc(str(item["expires_at_utc"]))
    if expires <= created:
        raise SuppressionError(f"{sid}: expires_at_utc must be after created_at_utc")
    rule_id = str(item["rule_id"])
    if known_rule_ids is not None and rule_id not in known_rule_ids:
        raise SuppressionError(f"{sid}: unknown rule_id {rule_id}")
    # Wildcard targets disabled by default
    target = str(item["target"])
    if "*" in target or target == "all":
        raise SuppressionError(f"{sid}: wildcard suppressions are disabled by default")

    return Suppression(
        id=sid,
        rule_id=rule_id,
        target=target,
        justification=justification,
        owner_label=str(item["owner_label"]),
        created_at_utc=str(item["created_at_utc"]),
        expires_at_utc=str(item["expires_at_utc"]),
        review_reference=str(item["review_reference"]),
        enabled=bool(item["enabled"]),
        property_path=str(item["property_path"]) if item.get("property_path") else None,
        fingerprint=str(item["fingerprint"]) if item.get("fingerprint") else None,
        service=str(item["service"]) if item.get("service") else None,
    )


def _is_expired(supp: Suppression, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    return _parse_utc(supp.expires_at_utc) <= now


def _matches(finding: Finding, supp: Suppression) -> bool:
    if finding.rule_id != supp.rule_id:
        return False
    if supp.target not in {finding.target_type, "compose", "dockerfile", "project"}:
        # Allow target matching rule target or broader labels
        if supp.target != finding.target_type:
            return False
    if supp.service and finding.service and supp.service != finding.service:
        return False
    if supp.fingerprint and finding.fingerprint != supp.fingerprint:
        return False
    return not (supp.property_path and finding.property_path != supp.property_path)


def apply_suppressions(
    findings: Sequence[Finding],
    suppressions: Sequence[Suppression],
    *,
    policy: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Apply suppressions; Critical requires stronger controls.

    Returns (updated_findings, suppression_audit_entries).
    """
    policy = policy or {}
    now = now or datetime.now(UTC)
    allow_critical = bool(policy.get("allow_critical_suppressions", False))
    audit: list[dict[str, Any]] = []
    result = list(findings)

    for supp in suppressions:
        entry: dict[str, Any] = {
            "id": supp.id,
            "rule_id": supp.rule_id,
            "status": "pending",
            "justification": supp.justification,
        }
        if not supp.enabled:
            entry["status"] = "disabled"
            audit.append(entry)
            continue
        if _is_expired(supp, now):
            entry["status"] = "expired"
            audit.append(entry)
            continue
        if not str(supp.review_reference).strip():
            entry["status"] = "invalid"
            entry["reason"] = "missing review_reference"
            audit.append(entry)
            continue

        matched = False
        for finding in result:
            if not _matches(finding, supp):
                continue
            if finding.status not in {Status.FAIL, Status.WARNING}:
                continue
            if finding.severity == Severity.CRITICAL:
                if not allow_critical:
                    entry["status"] = "rejected"
                    entry["reason"] = "Critical suppressions require policy permission"
                    continue
                if len(supp.justification) < 40:
                    entry["status"] = "rejected"
                    entry["reason"] = "Critical suppressions require stronger justification"
                    continue
                if not supp.expires_at_utc or not supp.review_reference:
                    entry["status"] = "rejected"
                    entry["reason"] = (
                        "Critical suppressions require expiration and review reference"
                    )
                    continue
            finding.suppressed = True
            finding.status = Status.SUPPRESSED
            finding.suppression_id = supp.id
            finding.suppression_justification = supp.justification
            matched = True
        entry["status"] = "applied" if matched else entry.get("status", "unmatched")
        if not matched and entry["status"] == "pending":
            entry["status"] = "unmatched"
        audit.append(entry)

    return result, audit


__all__ = [
    "SuppressionError",
    "apply_suppressions",
    "load_suppressions",
    "validate_suppression",
]
