"""Rule registry — load rules.json and bind check callables."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from container_security_baseline.config import package_config_dir
from container_security_baseline.models import Finding, RuleDefinition
from container_security_baseline.severities import Severity

CheckFn = Callable[..., list[Finding]]


class RuleRegistryError(ValueError):
    """Rule registry problems."""


class RuleRegistry:
    """In-memory rule catalog with optional check callables."""

    def __init__(self) -> None:
        self.rules: dict[str, RuleDefinition] = {}
        self.checks: dict[str, CheckFn] = {}

    def register_definition(self, rule: RuleDefinition) -> None:
        self.rules[rule.id] = rule

    def register_check(self, rule_id: str, fn: CheckFn) -> None:
        if rule_id not in self.rules:
            raise RuleRegistryError(f"Cannot register check for unknown rule {rule_id}")
        self.checks[rule_id] = fn

    def get(self, rule_id: str) -> RuleDefinition:
        if rule_id not in self.rules:
            raise RuleRegistryError(f"Unknown rule: {rule_id}")
        return self.rules[rule_id]

    def list_rules(
        self,
        *,
        target: str | None = None,
        severity: str | None = None,
        category: str | None = None,
    ) -> list[RuleDefinition]:
        items = list(self.rules.values())
        if target:
            items = [r for r in items if r.target == target]
        if severity:
            sev = Severity.from_string(severity)
            items = [r for r in items if r.severity == sev]
        if category:
            items = [r for r in items if r.category.lower() == category.lower()]
        return sorted(items, key=lambda r: r.id)

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [r.to_dict() for r in self.list_rules()]}


def _parse_rule(raw: dict[str, Any]) -> RuleDefinition:
    return RuleDefinition(
        id=str(raw["id"]),
        title=str(raw["title"]),
        target=str(raw["target"]),
        category=str(raw["category"]),
        severity=Severity.from_string(str(raw["severity"])),
        summary=str(raw.get("summary", "")),
        risk=str(raw.get("risk", "")),
        remediation=str(raw.get("remediation", "")),
        detailed_remediation=str(raw.get("detailed_remediation") or raw.get("remediation", "")),
        references=[str(x) for x in (raw.get("references") or [])],
        enabled=bool(raw.get("enabled", True)),
        patchability=str(raw.get("patchability", "manual")),
        false_positives=str(raw.get("false_positives", "")),
        limitations=str(raw.get("limitations", "")),
        detection_logic=str(raw.get("detection_logic", "")),
        profiles=[str(x) for x in (raw.get("profiles") or ["baseline", "strict", "development"])],
        severity_overrides={
            str(k): str(v) for k, v in (raw.get("severity_overrides") or {}).items()
        },
    )


def load_rules(path: str | Path | None = None) -> RuleRegistry:
    """Load rules from config/rules.json."""
    rules_path = Path(path) if path else package_config_dir() / "rules.json"
    try:
        data = json.loads(rules_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuleRegistryError(f"Cannot load rules: {exc}") from exc
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RuleRegistryError("rules.json must contain a rules array")
    registry = RuleRegistry()
    for item in raw_rules:
        if not isinstance(item, dict):
            raise RuleRegistryError("Each rule must be an object")
        registry.register_definition(_parse_rule(item))
    return registry


def build_default_registry() -> RuleRegistry:
    """Load rules and register built-in check callables."""
    from container_security_baseline import compose_rules, dockerfile_rules

    registry = load_rules()
    compose_rules.register_all(registry)
    dockerfile_rules.register_all(registry)
    return registry


__all__ = [
    "CheckFn",
    "RuleRegistry",
    "RuleRegistryError",
    "build_default_registry",
    "load_rules",
]
