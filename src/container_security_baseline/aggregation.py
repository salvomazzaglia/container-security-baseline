"""Project-level aggregation helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from container_security_baseline.models import Finding
from container_security_baseline.statuses import Status


def count_results(findings: Sequence[Finding]) -> dict[str, int]:
    counter: Counter[str] = Counter(f.status.value for f in findings)
    return dict(sorted(counter.items()))


def count_severities(findings: Sequence[Finding]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for finding in findings:
        if finding.status in {Status.FAIL, Status.WARNING} and not finding.suppressed:
            counter[finding.severity.value] += 1
    return dict(sorted(counter.items()))


def count_categories(findings: Sequence[Finding]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for finding in findings:
        if finding.status in {Status.FAIL, Status.WARNING} and not finding.suppressed:
            counter[finding.category] += 1
    return dict(sorted(counter.items()))


def collect_services(findings: Sequence[Finding]) -> list[str]:
    return sorted({f.service for f in findings if f.service})


def collect_stages(findings: Sequence[Finding]) -> list[str]:
    return sorted({f.stage for f in findings if f.stage})


def unavailable_entries(findings: Sequence[Finding]) -> list[dict[str, str]]:
    return [
        {
            "rule_id": f.rule_id,
            "summary": f.summary,
            "file": f.file,
        }
        for f in findings
        if f.status == Status.UNAVAILABLE
    ]


DEFAULT_LIMITATIONS = [
    "Static configuration analysis cannot inspect image contents.",
    "Static analysis cannot determine the effective runtime state.",
    "Static analysis cannot verify the Docker daemon configuration.",
    "Static analysis cannot verify host kernel, AppArmor, SELinux, seccomp, "
    "user-namespace, rootless-mode, or runtime protections unless those values "
    "are explicitly represented in the supplied configuration.",
    "A passing score is not a security certification.",
    "A finding does not prove exploitability.",
    "Referenced env_file/secrets/configs/include/extends targets are not read.",
    "Compose interpolation is detected but never resolved.",
]


def default_recommendations(findings: Sequence[Finding]) -> list[str]:
    recs: list[str] = []
    critical = [f for f in findings if f.severity.value == "Critical" and f.status == Status.FAIL]
    if critical:
        recs.append("Prioritize remediating unsuppressed Critical findings before deployment.")
    if any(f.rule_id.startswith("CSB-CMP-05") for f in findings if f.status == Status.FAIL):
        recs.append(
            "Remove embedded secret literals and migrate to a secret manager or Compose secrets."
        )
    if any(
        f.rule_id in {"CSB-CMP-001", "CSB-CMP-002"} for f in findings if f.status == Status.FAIL
    ):
        recs.append(
            "Eliminate privileged mode and runtime socket mounts unless absolutely required."
        )
    if not recs:
        recs.append("Review remaining Medium/Low findings and document justified suppressions.")
    return recs


__all__ = [
    "DEFAULT_LIMITATIONS",
    "collect_services",
    "collect_stages",
    "count_categories",
    "count_results",
    "count_severities",
    "default_recommendations",
    "unavailable_entries",
]
