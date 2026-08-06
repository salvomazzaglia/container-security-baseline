"""Tests for policy loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from container_security_baseline.policy import (
    PROTECTED_CRITICAL_RULES,
    PolicyError,
    load_policy,
    resolve_policy_path,
    rule_enabled,
    severity_override,
    validate_policy,
)
from container_security_baseline.severities import Severity


def test_load_baseline() -> None:
    pol = load_policy("baseline")
    assert pol["name"] == "baseline"
    assert pol["fail_on"] == "High"


def test_load_strict_and_development() -> None:
    assert load_policy("strict")["name"] == "strict"
    assert load_policy("development")["name"] == "development"


def test_resolve_policy_path() -> None:
    path = resolve_policy_path("baseline")
    assert path.name == "baseline.policy.json"


def test_unknown_policy() -> None:
    with pytest.raises(PolicyError):
        load_policy("does-not-exist-policy")


def test_unknown_key() -> None:
    with pytest.raises(PolicyError, match="Unknown"):
        validate_policy({"name": "x", "weird_key": True})


def test_missing_name() -> None:
    with pytest.raises(PolicyError, match="name"):
        validate_policy({"fail_on": "High"})


def test_rule_enabled_disabled_list() -> None:
    pol = {"disabled_rules": ["CSB-CMP-040"]}
    assert rule_enabled(pol, "CSB-CMP-040") is False
    assert rule_enabled(pol, "CSB-CMP-001") is True


def test_rule_enabled_allowlist() -> None:
    pol = {"enabled_rules": ["CSB-CMP-001"]}
    assert rule_enabled(pol, "CSB-CMP-001") is True
    assert rule_enabled(pol, "CSB-CMP-002") is False


def test_severity_override() -> None:
    pol = {"severity_overrides": {"CSB-CMP-040": "Low"}}
    assert severity_override(pol, "CSB-CMP-040") == Severity.LOW
    assert severity_override(pol, "CSB-CMP-001") is None


def test_development_cannot_downgrade_protected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="protected"):
        validate_policy(
            {
                "name": "development",
                "severity_overrides": {"CSB-CMP-001": "Low"},
            }
        )


def test_protected_critical_rules_nonempty() -> None:
    assert "CSB-CMP-001" in PROTECTED_CRITICAL_RULES


def test_load_policy_from_file(fixtures_dir: Path) -> None:
    path = fixtures_dir / "policies" / "test-baseline.policy.json"
    pol = load_policy(path)
    assert pol["minimum_score"] == 50
