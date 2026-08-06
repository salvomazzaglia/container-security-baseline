"""Policy profile loading and validation."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from container_security_baseline.config import package_config_dir
from container_security_baseline.severities import Severity

KNOWN_POLICY_KEYS = frozenset(
    {
        "name",
        "description",
        "version",
        "fail_on",
        "minimum_score",
        "enabled_rules",
        "disabled_rules",
        "severity_overrides",
        "allow_critical_suppressions",
        "require_digest_pinning",
        "require_non_root",
        "require_read_only",
        "require_cap_drop_all",
        "require_no_new_privileges",
        "require_resource_limits",
        "require_pid_limit",
        "require_healthcheck",
        "require_bounded_logging",
        "disallow_wildcard_ports",
        "disallow_host_namespaces",
        "disallow_external_file_refs",
        "stateful_services",
        "service_secret_expectations",
        "backend_networks",
        "scoring_deductions",
    }
)

PROTECTED_CRITICAL_RULES = frozenset(
    {
        "CSB-CMP-001",
        "CSB-CMP-002",
        "CSB-CMP-003",
        "CSB-CMP-007",
        "CSB-CMP-020",
        "CSB-CMP-024",
        "CSB-CMP-050",
        "CSB-CMP-114",
        "CSB-DF-020",
        "CSB-DF-022",
        "CSB-DF-023",
    }
)


class PolicyError(ValueError):
    """Invalid policy."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Cannot load policy: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("Policy root must be an object")
    return data


def validate_policy(data: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(data) - KNOWN_POLICY_KEYS)
    if unknown:
        raise PolicyError(f"Unknown policy key(s): {', '.join(unknown)}")
    policy = deepcopy(data)
    if "name" not in policy:
        raise PolicyError("Policy requires name")
    if "fail_on" in policy:
        Severity.from_string(str(policy["fail_on"]))
    overrides = policy.get("severity_overrides") or {}
    if not isinstance(overrides, dict):
        raise PolicyError("severity_overrides must be an object")
    for rule_id, sev in overrides.items():
        Severity.from_string(str(sev))
        # Development must not improperly downgrade protected criticals below High
        if (
            str(policy.get("name", "")).lower() == "development"
            and str(rule_id) in PROTECTED_CRITICAL_RULES
        ):
            if Severity.from_string(str(sev)).rank < Severity.HIGH.rank:
                raise PolicyError(
                    f"Development policy cannot downgrade protected rule {rule_id} below High"
                )
    return policy


def resolve_policy_path(policy: str | Path | None) -> Path:
    """Resolve a policy name or path to a file."""
    config_dir = package_config_dir()
    if policy is None:
        return config_dir / "baseline.policy.json"
    p = Path(policy)
    if p.is_file():
        return p
    name = str(policy).lower().removesuffix(".policy.json").removesuffix(".json")
    candidate = config_dir / f"{name}.policy.json"
    if candidate.is_file():
        return candidate
    raise PolicyError(f"Policy not found: {policy}")


def load_policy(policy: str | Path | None = None) -> dict[str, Any]:
    path = resolve_policy_path(policy)
    return validate_policy(_load_json(path))


def rule_enabled(policy: dict[str, Any], rule_id: str, default_enabled: bool = True) -> bool:
    disabled = set(policy.get("disabled_rules") or [])
    enabled = policy.get("enabled_rules")
    if rule_id in disabled:
        return False
    if isinstance(enabled, list) and enabled:
        return rule_id in enabled
    return default_enabled


def severity_override(policy: dict[str, Any], rule_id: str) -> Severity | None:
    overrides = policy.get("severity_overrides") or {}
    if rule_id in overrides:
        return Severity.from_string(str(overrides[rule_id]))
    return None


__all__ = [
    "PROTECTED_CRITICAL_RULES",
    "PolicyError",
    "load_policy",
    "resolve_policy_path",
    "rule_enabled",
    "severity_override",
    "validate_policy",
]
