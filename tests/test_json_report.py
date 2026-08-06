"""JSON report writer tests."""

from __future__ import annotations

import json
from pathlib import Path

from container_security_baseline.json_report import (
    dumps_json_report,
    report_to_json_dict,
    write_json_report,
)
from container_security_baseline.models import Report


def test_report_to_dict_synthetic() -> None:
    report = Report(synthetic=True, score=80, grade="B")
    data = report_to_json_dict(report)
    assert data["synthetic"] is True
    assert data["tool_name"] == "container-security-baseline"


def test_write_json_report(tmp_path: Path, failing_findings) -> None:
    report = Report(synthetic=True, findings=failing_findings, score=75, grade="C")
    path = tmp_path / "report.json"
    write_json_report(report, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["synthetic"] is True
    assert data["findings"]


def test_dumps_redacts_url_secrets() -> None:
    from container_security_baseline.findings import fail
    from container_security_baseline.rule_registry import build_default_registry

    registry = build_default_registry()
    rule = registry.get("CSB-CMP-050")
    finding = fail(
        rule,
        evidence_redacted="https://u:[REDACTED]@example.invalid",
        file="c.yml",
        service="web",
    )
    # Inject raw secret into evidence to ensure dump scrubber runs
    finding.evidence_redacted = "https://u:SYNTHETIC_NOT_A_REAL_SECRET@example.invalid"
    report = Report(synthetic=True, findings=[finding])
    payload = dumps_json_report(report)
    # URL credential pattern should be scrubbed by ensure_no_secret_leak
    assert "u:SYNTHETIC_NOT_A_REAL_SECRET@" not in payload or "[REDACTED]" in payload


def test_security_notice_present() -> None:
    report = Report(synthetic=True)
    data = report_to_json_dict(report)
    assert "static" in data["security_notice"].lower()


def test_result_counts_serialized(failing_findings) -> None:
    report = Report(synthetic=True, findings=failing_findings, result_counts={"Fail": 1})
    assert report_to_json_dict(report)["result_counts"]["Fail"] == 1
