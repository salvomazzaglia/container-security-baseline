"""HTML report writer tests."""

from __future__ import annotations

from pathlib import Path

from container_security_baseline.html_report import render_html_report, write_html_report
from container_security_baseline.models import Report


def test_synthetic_banner(failing_findings) -> None:
    html = render_html_report(
        Report(synthetic=True, findings=failing_findings, score=10, grade="F")
    )
    assert "SYNTHETIC DEMONSTRATION" in html


def test_no_banner_when_not_synthetic(failing_findings) -> None:
    html = render_html_report(Report(synthetic=False, findings=failing_findings))
    assert "SYNTHETIC DEMONSTRATION" not in html


def test_escapes_html_in_evidence(registry) -> None:
    from container_security_baseline.findings import fail

    rule = registry.get("CSB-CMP-001")
    finding = fail(
        rule,
        evidence_redacted="<script>alert(1)</script>",
        file="c.yml",
        service="web",
    )
    html = render_html_report(Report(synthetic=True, findings=[finding]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_write_html_report(tmp_path: Path, failing_findings) -> None:
    path = tmp_path / "report.html"
    write_html_report(Report(synthetic=True, findings=failing_findings), path)
    text = path.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>") or "<html" in text.lower()
    assert "SYNTHETIC" in text.upper()


def test_no_cdn_references(failing_findings) -> None:
    html = render_html_report(Report(synthetic=True, findings=failing_findings))
    assert "cdn.jsdelivr" not in html
    assert "googleapis" not in html


def test_limitations_section() -> None:
    html = render_html_report(Report(synthetic=True, limitations=["offline only"]))
    assert "offline only" in html
