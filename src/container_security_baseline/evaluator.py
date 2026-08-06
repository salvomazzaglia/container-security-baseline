"""High-level scan evaluation orchestration."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from container_security_baseline import __version__
from container_security_baseline.aggregation import (
    DEFAULT_LIMITATIONS,
    collect_services,
    collect_stages,
    count_categories,
    count_results,
    count_severities,
    default_recommendations,
    unavailable_entries,
)
from container_security_baseline.compose_loader import ComposeDocument, load_compose_file
from container_security_baseline.compose_rules import evaluate_compose_document
from container_security_baseline.config import get_parser_limits, load_config
from container_security_baseline.dockerfile_parser import parse_dockerfile
from container_security_baseline.dockerfile_rules import evaluate_dockerfile_document
from container_security_baseline.exit_codes import ExitCode
from container_security_baseline.findings import dedupe_findings
from container_security_baseline.models import Finding, InputSummary, Report
from container_security_baseline.paths import (
    PathSafetyError,
    ensure_relative_display,
    is_within_root,
    normalize_project_root,
    project_relative,
    safe_resolve_path,
)
from container_security_baseline.policy import load_policy
from container_security_baseline.rule_registry import RuleRegistry, build_default_registry
from container_security_baseline.scoring import calculate_score
from container_security_baseline.severities import Severity
from container_security_baseline.source import SourceLoadError, load_source_file
from container_security_baseline.statuses import Status
from container_security_baseline.suppressions import apply_suppressions, load_suppressions


class ScanError(Exception):
    """Fatal scan error."""


def _display(path: Path, root: Path, privacy_mode: str) -> str:
    return ensure_relative_display(path, root, privacy_mode)


def resolve_input_path(path: str | Path, root: Path) -> Path:
    """Resolve an operator-supplied input path safely within the project root.

    Accepts paths relative to the current working directory or to the project root.
    """
    raw = Path(path)
    candidates: list[Path] = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.append(Path.cwd() / raw)
        candidates.append(root / raw)
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            continue
        if resolved.exists() and is_within_root(resolved, root):
            return safe_resolve_path(resolved, root, must_exist=True, follow_symlinks=False)
    return safe_resolve_path(path, root, must_exist=True, follow_symlinks=False)


# Backwards-compatible private alias
_resolve_input_path = resolve_input_path


def run_scan(
    compose_paths: Sequence[str | Path] | None = None,
    dockerfile_paths: Sequence[str | Path] | None = None,
    *,
    project_root: str | Path,
    policy: dict[str, Any] | str | Path | None = None,
    config: dict[str, Any] | str | Path | None = None,
    suppressions: str | Path | None = None,
    privacy_mode: str = "masked",
    compose_json_paths: Sequence[str | Path] | None = None,
    include_passed: bool = False,
    fail_on: str | None = None,
    minimum_score: int | None = None,
    synthetic: bool = False,
    registry: RuleRegistry | None = None,
) -> Report:
    """Run a full offline static analysis scan and return a Report."""
    root = normalize_project_root(project_root)
    cfg = config if isinstance(config, dict) else load_config(config)
    pol = policy if isinstance(policy, dict) else load_policy(policy)
    reg = registry or build_default_registry()
    limits = get_parser_limits(cfg)
    privacy = privacy_mode or str((cfg.get("reporting") or {}).get("privacy_mode", "masked"))

    findings: list[Finding] = []
    warnings: list[str] = []
    files_analyzed: list[str] = []
    parsing_status = "ok"
    compose_docs: list[ComposeDocument] = []

    # Compose YAML/files
    for raw_path in list(compose_paths or []):
        try:
            resolved = _resolve_input_path(raw_path, root)
            display = _display(resolved, root, privacy)
            doc = load_compose_file(
                resolved,
                root,
                limits,
                display_path=display,
            )
            compose_docs.append(doc)
            files_analyzed.append(display)
            warnings.extend(doc.warnings)
            findings.extend(
                evaluate_compose_document(
                    doc,
                    reg,
                    config=cfg,
                    policy=pol,
                    project_root=str(root),
                )
            )
        except (PathSafetyError, SourceLoadError, Exception) as exc:
            parsing_status = "error"
            warnings.append(f"Failed to analyze compose {raw_path}: {exc}")

    # Compose JSON / canonical
    for raw_path in list(compose_json_paths or []):
        try:
            resolved = _resolve_input_path(raw_path, root)
            display = _display(resolved, root, privacy)
            doc = load_compose_file(
                resolved,
                root,
                limits,
                display_path=display,
                force_json=True,
                canonical=True,
            )
            compose_docs.append(doc)
            files_analyzed.append(display)
            warnings.extend(doc.warnings)
            findings.extend(
                evaluate_compose_document(
                    doc,
                    reg,
                    config=cfg,
                    policy=pol,
                    project_root=str(root),
                )
            )
        except (PathSafetyError, SourceLoadError, Exception) as exc:
            parsing_status = "error"
            warnings.append(f"Failed to analyze compose-json {raw_path}: {exc}")

    # Dockerfiles
    dockerignore_present = False
    dockerignore_content: str | None = None
    dockerignore_path = root / ".dockerignore"
    project_analysis = bool(
        (root / "Dockerfile").exists()
        or (root / "compose.yml").exists()
        or (root / "compose.yaml").exists()
        or (root / "docker-compose.yml").exists()
        or (root / "docker-compose.yaml").exists()
    )
    if dockerignore_path.is_file():
        try:
            # Only read .dockerignore inside project root (explicit project file)
            di = load_source_file(
                dockerignore_path,
                root,
                maximum_file_bytes=limits["maximum_file_bytes"],
                display_path=".dockerignore",
            )
            dockerignore_present = True
            dockerignore_content = di.content
        except (PathSafetyError, SourceLoadError):
            dockerignore_present = False

    for raw_path in list(dockerfile_paths or []):
        try:
            resolved = _resolve_input_path(raw_path, root)
            display = _display(resolved, root, privacy)
            source = load_source_file(
                resolved,
                root,
                maximum_file_bytes=limits["maximum_file_bytes"],
                display_path=display,
            )
            df_doc = parse_dockerfile(source.content, display_path=display)
            files_analyzed.append(display)
            warnings.extend(df_doc.warnings)
            if df_doc.status.value == "partial" and parsing_status == "ok":
                parsing_status = "partial"
            findings.extend(
                evaluate_dockerfile_document(
                    df_doc,
                    reg,
                    config=cfg,
                    policy=pol,
                    project_root=str(root),
                    dockerignore_present=dockerignore_present,
                    dockerignore_content=dockerignore_content,
                    project_analysis=project_analysis,
                )
            )
        except (PathSafetyError, SourceLoadError, Exception) as exc:
            parsing_status = "error"
            warnings.append(f"Failed to analyze Dockerfile {raw_path}: {exc}")

    findings = dedupe_findings(findings)

    # Suppressions
    supp_list, invalid_supps = load_suppressions(suppressions)
    findings, supp_audit = apply_suppressions(findings, supp_list, policy=pol)
    for msg in invalid_supps:
        warnings.append(f"Invalid suppression: {msg}")

    if not include_passed:
        findings = [f for f in findings if f.status != Status.PASS]

    has_errors = parsing_status == "error" or any(f.status == Status.ERROR for f in findings)
    score_result = calculate_score(findings, policy=pol, has_errors=has_errors)

    fail_threshold = Severity.from_string(fail_on or str(pol.get("fail_on", "High")))
    min_score = int(minimum_score if minimum_score is not None else pol.get("minimum_score", 0))

    exit_code = _compute_exit_code(
        findings,
        score=score_result.score,
        fail_on=fail_threshold,
        minimum_score=min_score,
        parsing_status=parsing_status,
        suppression_audit=supp_audit,
    )

    input_summary = InputSummary(
        project_root=project_relative(root, root) if privacy == "masked" else str(root),
        compose_files=[_display(Path(p), root, privacy) for p in (compose_paths or [])],
        dockerfile_files=[_display(Path(p), root, privacy) for p in (dockerfile_paths or [])],
        compose_json_files=[_display(Path(p), root, privacy) for p in (compose_json_paths or [])],
        privacy_mode=privacy,
        policy_name=str(pol.get("name", "baseline")),
    )

    report = Report(
        tool_version=__version__,
        synthetic=synthetic,
        input_summary=input_summary,
        policy={
            "name": pol.get("name"),
            "fail_on": fail_threshold.value,
            "minimum_score": min_score,
        },
        privacy_mode=privacy,
        parsing_status=parsing_status,
        files_analyzed=files_analyzed,
        compose_services=collect_services(findings),
        dockerfile_stages=collect_stages(findings),
        result_counts=count_results(findings),
        severity_counts=count_severities(findings),
        category_counts=count_categories(findings),
        score=score_result.score,
        grade=score_result.grade,
        score_explanation=score_result.explanation,
        highest_severity=score_result.highest_severity,
        findings=findings,
        suppressions=supp_audit,
        unavailable_checks=unavailable_entries(findings),
        parsing_warnings=warnings,
        recommendations=default_recommendations(findings),
        limitations=list(DEFAULT_LIMITATIONS),
        exit_code=int(exit_code),
        score_detail=score_result,
    )
    return report


def _compute_exit_code(
    findings: list[Finding],
    *,
    score: int,
    fail_on: Severity,
    minimum_score: int,
    parsing_status: str,
    suppression_audit: list[dict[str, Any]],
) -> ExitCode:
    if parsing_status == "error":
        return ExitCode.ERROR
    if any(e.get("status") == "rejected" for e in suppression_audit):
        # Critical invalid suppression policy
        if any("Critical" in str(e.get("reason", "")) for e in suppression_audit):
            return ExitCode.POLICY_FAILURE

    unsuppressed = [
        f for f in findings if f.status in {Status.FAIL, Status.WARNING} and not f.suppressed
    ]
    at_or_above = [f for f in unsuppressed if f.severity.at_or_above(fail_on)]
    if at_or_above or score < minimum_score:
        return ExitCode.POLICY_FAILURE
    if unsuppressed:
        return ExitCode.FINDINGS_BELOW
    return ExitCode.SUCCESS


__all__ = ["ScanError", "resolve_input_path", "run_scan"]
