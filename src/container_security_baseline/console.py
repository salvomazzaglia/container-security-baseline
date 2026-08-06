"""Console output helpers (always redacted)."""

from __future__ import annotations

import sys
from typing import TextIO

from container_security_baseline.models import Report
from container_security_baseline.redaction import ensure_no_secret_leak
from container_security_baseline.statuses import Status


def print_report_summary(
    report: Report,
    *,
    stream: TextIO | None = None,
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    out = stream or sys.stdout
    if quiet:
        return
    lines = [
        f"container-security-baseline {report.tool_version}",
        f"Score: {report.score} (Grade {report.grade})",
        f"Policy: {(report.policy or {}).get('name')} | Privacy: {report.privacy_mode}",
        f"Parsing: {report.parsing_status} | Exit: {report.exit_code}",
        f"Findings: {len([f for f in report.findings if f.status != Status.PASS])}",
    ]
    if report.highest_severity:
        lines.append(f"Highest severity: {report.highest_severity}")
    for line in lines:
        print(ensure_no_secret_leak(line), file=out)

    shown = 0
    for finding in report.findings:
        if finding.status == Status.PASS:
            continue
        shown += 1
        if not verbose and shown > 20:
            remaining = len([f for f in report.findings if f.status != Status.PASS]) - 20
            print(f"... {remaining} more finding(s). Use --verbose to show all.", file=out)
            break
        loc = finding.file
        if finding.line_start:
            loc = f"{loc}:{finding.line_start}"
        target = finding.service or finding.stage or "-"
        print(
            ensure_no_secret_leak(
                f"[{finding.severity.value}] {finding.rule_id} ({finding.status.value}) "
                f"{target} @ {loc}"
            ),
            file=out,
        )
        print(ensure_no_secret_leak(f"  {finding.summary}"), file=out)
        if verbose:
            print(ensure_no_secret_leak(f"  Evidence: {finding.evidence_redacted}"), file=out)
            print(ensure_no_secret_leak(f"  Remediation: {finding.remediation}"), file=out)


def print_privacy_warning(*, stream: TextIO | None = None) -> None:
    print(
        "Privacy warning: full mode still never prints detected secret values, "
        "but may include complete non-secret input paths.",
        file=stream or sys.stderr,
    )


__all__ = ["print_privacy_warning", "print_report_summary"]
