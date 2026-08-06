"""SARIF report writer tests."""

from __future__ import annotations

import json
from pathlib import Path

from container_security_baseline.models import Report
from container_security_baseline.sarif_report import report_to_sarif, write_sarif_report


def test_sarif_structure(failing_findings) -> None:
    sarif = report_to_sarif(Report(synthetic=True, findings=failing_findings))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"]
    assert sarif["runs"][0]["results"]


def test_sarif_result_level(failing_findings) -> None:
    sarif = report_to_sarif(Report(synthetic=True, findings=failing_findings))
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == failing_findings[0].rule_id
    assert result["level"] in {"error", "warning", "note"}


def test_write_sarif(tmp_path: Path, failing_findings) -> None:
    path = tmp_path / "report.sarif"
    write_sarif_report(Report(synthetic=True, findings=failing_findings), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "runs" in data


def test_suppressed_finding_in_sarif(registry) -> None:
    from container_security_baseline.findings import fail
    from container_security_baseline.statuses import Status

    rule = registry.get("CSB-CMP-040")
    finding = fail(rule, evidence_redacted="x", file="c.yml", service="web")
    finding.suppressed = True
    finding.status = Status.SUPPRESSED
    finding.suppression_justification = "synthetic"
    sarif = report_to_sarif(Report(synthetic=True, findings=[finding]))
    assert "suppressions" in sarif["runs"][0]["results"][0]


def test_artifact_uri_uses_forward_slashes(registry) -> None:
    from container_security_baseline.findings import fail

    rule = registry.get("CSB-CMP-001")
    finding = fail(rule, evidence_redacted="x", file=r"examples\compose\a.yml", service="web")
    sarif = report_to_sarif(Report(synthetic=True, findings=[finding]))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert "\\" not in uri
