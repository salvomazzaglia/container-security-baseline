"""Suppression validation and application tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from container_security_baseline.findings import fail
from container_security_baseline.severities import Severity
from container_security_baseline.statuses import Status
from container_security_baseline.suppressions import (
    SuppressionError,
    apply_suppressions,
    load_suppressions,
    validate_suppression,
)


def _base_supp(**overrides):
    data = {
        "id": "s1",
        "rule_id": "CSB-CMP-040",
        "target": "compose",
        "justification": "Documented temporary exception for synthetic demo.",
        "owner_label": "owner",
        "created_at_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "2099-01-01T00:00:00Z",
        "review_reference": "TICKET-1",
        "enabled": True,
        "service": "web",
    }
    data.update(overrides)
    return data


def test_validate_ok() -> None:
    supp = validate_suppression(_base_supp())
    assert supp.id == "s1"


def test_missing_field() -> None:
    data = _base_supp()
    del data["justification"]
    with pytest.raises(SuppressionError, match="justification"):
        validate_suppression(data)


def test_empty_justification() -> None:
    with pytest.raises(SuppressionError):
        validate_suppression(_base_supp(justification="  "))


def test_wildcard_target_rejected() -> None:
    with pytest.raises(SuppressionError, match="wildcard"):
        validate_suppression(_base_supp(target="*"))


def test_expires_before_created() -> None:
    with pytest.raises(SuppressionError, match="expires"):
        validate_suppression(
            _base_supp(created_at_utc="2099-01-01T00:00:00Z", expires_at_utc="2020-01-01T00:00:00Z")
        )


def test_duplicate_ids() -> None:
    with pytest.raises(SuppressionError, match="Duplicate"):
        validate_suppression(_base_supp(), seen_ids={"s1"})


def test_load_valid_file(fixtures_dir: Path) -> None:
    valid, invalid = load_suppressions(fixtures_dir / "suppressions" / "valid.json")
    assert len(valid) == 1
    assert invalid == []


def test_apply_suppression(registry) -> None:
    rule = registry.get("CSB-CMP-040")
    finding = fail(
        rule,
        evidence_redacted="missing read_only",
        file="c.yml",
        service="web",
        property_path="services.web.read_only",
    )
    supp = validate_suppression(_base_supp())
    findings, audit = apply_suppressions([finding], [supp])
    assert findings[0].suppressed is True
    assert findings[0].status == Status.SUPPRESSED
    assert audit[0]["status"] == "applied"


def test_critical_suppression_rejected_by_default(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = fail(
        rule,
        evidence_redacted="privileged",
        file="c.yml",
        service="web",
        severity=Severity.CRITICAL,
    )
    supp = validate_suppression(
        _base_supp(
            rule_id="CSB-CMP-001",
            justification="x" * 50,
        )
    )
    findings, audit = apply_suppressions(
        [finding], [supp], policy={"allow_critical_suppressions": False}
    )
    assert findings[0].suppressed is False
    assert any(a["status"] == "rejected" for a in audit)


def test_critical_allowed_with_strong_justification(registry) -> None:
    rule = registry.get("CSB-CMP-001")
    finding = fail(
        rule,
        evidence_redacted="privileged",
        file="c.yml",
        service="web",
        severity=Severity.CRITICAL,
    )
    supp = validate_suppression(
        _base_supp(rule_id="CSB-CMP-001", justification="x" * 50, service="web")
    )
    findings, audit = apply_suppressions(
        [finding],
        [supp],
        policy={"allow_critical_suppressions": True},
    )
    assert findings[0].suppressed is True
    assert audit[0]["status"] == "applied"


def test_expired_suppression(registry) -> None:
    rule = registry.get("CSB-CMP-040")
    finding = fail(rule, evidence_redacted="x", file="c.yml", service="web")
    supp = validate_suppression(
        _base_supp(
            created_at_utc="2020-01-01T00:00:00Z",
            expires_at_utc="2021-01-01T00:00:00Z",
        )
    )
    _, audit = apply_suppressions(
        [finding],
        [supp],
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert audit[0]["status"] == "expired"


def test_disabled_suppression(registry) -> None:
    rule = registry.get("CSB-CMP-040")
    finding = fail(rule, evidence_redacted="x", file="c.yml", service="web")
    supp = validate_suppression(_base_supp(enabled=False))
    _, audit = apply_suppressions([finding], [supp])
    assert audit[0]["status"] == "disabled"
