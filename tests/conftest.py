"""Shared pytest fixtures for container-security-baseline tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from container_security_baseline.compose_loader import load_compose_yaml
from container_security_baseline.compose_model import normalize_compose
from container_security_baseline.compose_rules import COMPOSE_CHECKS
from container_security_baseline.config import get_parser_limits, load_config
from container_security_baseline.dockerfile_parser import parse_dockerfile
from container_security_baseline.dockerfile_rules import DOCKERFILE_CHECKS
from container_security_baseline.models import Finding
from container_security_baseline.policy import load_policy
from container_security_baseline.rule_registry import build_default_registry
from container_security_baseline.source import SourceFile
from container_security_baseline.statuses import Status


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def fixtures_dir(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures"


@pytest.fixture(scope="session")
def default_config() -> dict[str, Any]:
    return load_config()


@pytest.fixture(scope="session")
def parser_limits(default_config: dict[str, Any]) -> dict[str, Any]:
    return get_parser_limits(default_config)


@pytest.fixture(scope="session")
def baseline_policy() -> dict[str, Any]:
    return load_policy("baseline")


@pytest.fixture(scope="session")
def registry():
    return build_default_registry()


@pytest.fixture
def sample_compose_yaml() -> str:
    return (
        "# SYNTHETIC\n"
        "services:\n"
        "  web:\n"
        "    image: registry.example.invalid/web:1.0\n"
        "    privileged: true\n"
    )


@pytest.fixture
def sample_dockerfile() -> str:
    return "# SYNTHETIC\nFROM registry.example.invalid/app:1.0\nUSER root\nCOPY . /\n"


@pytest.fixture
def make_source(tmp_path: Path):
    def _make(text: str, name: str = "compose.yml") -> SourceFile:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return SourceFile(
            path=path,
            display_path=name,
            content=text,
            size_bytes=len(text.encode("utf-8")),
            line_count=len(text.splitlines()),
        )

    return _make


@pytest.fixture
def evaluate_compose_rule(default_config, baseline_policy, registry, parser_limits, make_source):
    def _eval(rule_id: str, yaml_text: str) -> list[Finding]:
        source = make_source(yaml_text if "SYNTHETIC" in yaml_text else f"# SYNTHETIC\n{yaml_text}")
        doc = load_compose_yaml(source, parser_limits)
        model = normalize_compose(doc.data)
        rule = registry.get(rule_id)
        fn = COMPOSE_CHECKS[rule_id]
        ctx = {
            "document": doc,
            "model": model,
            "config": default_config,
            "policy": baseline_policy,
            "project_root": str(source.path.parent),
            "display_path": source.display_path,
        }
        return fn(rule, ctx)

    return _eval


@pytest.fixture
def evaluate_dockerfile_rule(default_config, baseline_policy, registry):
    def _eval(rule_id: str, df_text: str, **extra: Any) -> list[Finding]:
        text = df_text if "SYNTHETIC" in df_text else f"# SYNTHETIC\n{df_text}"
        doc = parse_dockerfile(text, display_path="Dockerfile")
        rule = registry.get(rule_id)
        fn = DOCKERFILE_CHECKS[rule_id]
        ctx = {
            "document": doc,
            "config": default_config,
            "policy": baseline_policy,
            "project_root": ".",
            "display_path": "Dockerfile",
            "dockerignore_present": extra.get("dockerignore_present", False),
            "dockerignore_content": extra.get("dockerignore_content"),
            "project_analysis": extra.get("project_analysis", False),
        }
        return fn(rule, ctx)

    return _eval


@pytest.fixture
def failing_findings(registry) -> list[Finding]:
    from container_security_baseline.findings import fail
    from container_security_baseline.severities import Severity

    rule = registry.get("CSB-CMP-001")
    return [
        fail(
            rule,
            evidence_redacted="services.web.privileged=true",
            file="compose.yml",
            service="web",
            property_path="services.web.privileged",
            severity=Severity.CRITICAL,
        )
    ]


def assert_has_fail(findings: list[Finding], rule_id: str | None = None) -> Finding:
    fails = [f for f in findings if f.status == Status.FAIL]
    if rule_id:
        fails = [f for f in fails if f.rule_id == rule_id]
    assert fails, f"Expected Fail findings for {rule_id or 'any rule'}, got {findings}"
    return fails[0]


__all__ = ["assert_has_fail"]
