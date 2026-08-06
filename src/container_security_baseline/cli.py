"""Command-line interface for container-security-baseline."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from container_security_baseline import __version__
from container_security_baseline.comparison import compare_reports
from container_security_baseline.compose_loader import ComposeLoadError, load_compose_file
from container_security_baseline.config import ConfigError, get_parser_limits, load_config
from container_security_baseline.console import print_privacy_warning, print_report_summary
from container_security_baseline.dockerfile_parser import parse_dockerfile
from container_security_baseline.evaluator import resolve_input_path, run_scan
from container_security_baseline.exit_codes import ExitCode
from container_security_baseline.html_report import write_html_report
from container_security_baseline.json_report import write_json_report
from container_security_baseline.models import Finding, Report
from container_security_baseline.patching import generate_unified_diff
from container_security_baseline.paths import PathSafetyError, normalize_project_root
from container_security_baseline.policy import PolicyError, load_policy
from container_security_baseline.remediation import remediation_for_rule
from container_security_baseline.rule_registry import RuleRegistryError, load_rules
from container_security_baseline.sarif_report import write_sarif_report
from container_security_baseline.severities import Severity
from container_security_baseline.source import SourceLoadError, load_source_file
from container_security_baseline.statuses import Status
from container_security_baseline.suppressions import SuppressionError, load_suppressions

_FAIL_ON_MAP = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--compose", action="append", default=[], dest="compose")
    parser.add_argument("--dockerfile", action="append", default=[], dest="dockerfile")
    parser.add_argument("--compose-json", action="append", default=[], dest="compose_json")
    parser.add_argument("--config", default=None)
    parser.add_argument("--policy", default="baseline")
    parser.add_argument("--suppressions", default=None)
    parser.add_argument("--privacy-mode", choices=["masked", "full"], default="masked")
    parser.add_argument(
        "--fail-on",
        choices=list(_FAIL_ON_MAP),
        default=None,
    )
    parser.add_argument("--minimum-score", type=int, default=None)
    parser.add_argument("--include-passed", action="store_true", default=False)
    parser.add_argument("--verbose", action="store_true", default=False)
    parser.add_argument("--quiet", action="store_true", default=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container-security-baseline",
        description=(
            "Offline static analysis for Docker Compose and Dockerfile security baselines. "
            "Never invokes Docker, never resolves secrets, never modifies inputs."
        ),
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Analyze Compose files and/or Dockerfiles")
    _add_common_scan_args(scan)
    scan.add_argument("--output-directory", default="reports")
    scan.add_argument(
        "--format",
        choices=["json", "html", "sarif", "all"],
        default="all",
        dest="fmt",
    )
    scan.add_argument("--synthetic", action="store_true", default=False)

    validate = sub.add_parser("validate", help="Validate config/policy/rules/inputs")
    validate.add_argument("--config", default=None)
    validate.add_argument("--policy", default=None)
    validate.add_argument("--rules", default=None)
    validate.add_argument("--suppressions", default=None)
    validate.add_argument("--compose", action="append", default=[])
    validate.add_argument("--dockerfile", action="append", default=[])
    validate.add_argument("--project-root", default=".")

    list_rules = sub.add_parser("list-rules", help="List rule catalog")
    list_rules.add_argument("--target", choices=["compose", "dockerfile", "project"], default=None)
    list_rules.add_argument("--severity", default=None)
    list_rules.add_argument("--category", default=None)
    list_rules.add_argument("--format", choices=["table", "json"], default="table", dest="fmt")

    explain = sub.add_parser("explain", help="Explain a rule")
    explain.add_argument("rule_id")

    suggest = sub.add_parser("suggest", help="Suggest remediation / proposed patch")
    _add_common_scan_args(suggest)
    suggest.add_argument("--output", default="proposed-remediation.patch")

    compare = sub.add_parser("compare", help="Compare two configs or reports")
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--project-root", default=".")
    compare.add_argument("--policy", default="baseline")
    compare.add_argument("--config", default=None)
    compare.add_argument("--output-directory", default="reports/comparison")
    compare.add_argument(
        "--format",
        choices=["json", "html", "sarif", "all"],
        default="all",
        dest="fmt",
    )
    compare.add_argument("--privacy-mode", choices=["masked", "full"], default="masked")

    demo = sub.add_parser("generate-demo", help="Generate deterministic synthetic demo note")
    demo.add_argument("--output-directory", default="examples")

    sub.add_parser("version", help="Print version")
    return parser


def _write_formats(report: Report, output_dir: Path, fmt: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    formats = ["json", "html", "sarif"] if fmt == "all" else [fmt]
    if "json" in formats:
        write_json_report(report, output_dir / "report.json")
    if "html" in formats:
        write_html_report(report, output_dir / "report.html")
    if "sarif" in formats:
        write_sarif_report(report, output_dir / "report.sarif")


def _normalize_fail_on(value: str | None) -> str | None:
    if value is None:
        return None
    return _FAIL_ON_MAP.get(value.lower(), value)


def cmd_scan(args: argparse.Namespace) -> int:
    if args.privacy_mode == "full":
        print_privacy_warning()
    try:
        report = run_scan(
            compose_paths=args.compose,
            dockerfile_paths=args.dockerfile,
            compose_json_paths=args.compose_json,
            project_root=args.project_root,
            policy=args.policy,
            config=args.config,
            suppressions=args.suppressions,
            privacy_mode=args.privacy_mode,
            include_passed=args.include_passed,
            fail_on=_normalize_fail_on(args.fail_on),
            minimum_score=args.minimum_score,
            synthetic=bool(getattr(args, "synthetic", False)),
        )
    except (ConfigError, PolicyError, PathSafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.ERROR)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.ERROR)

    _write_formats(report, Path(args.output_directory), args.fmt)
    print_report_summary(report, verbose=args.verbose, quiet=args.quiet)
    return int(report.exit_code)


def cmd_validate(args: argparse.Namespace) -> int:
    errors: list[str] = []
    try:
        load_config(args.config)
        print("config: OK")
    except ConfigError as exc:
        errors.append(f"config: {exc}")
    if args.policy:
        try:
            load_policy(args.policy)
            print(f"policy: OK ({args.policy})")
        except PolicyError as exc:
            errors.append(f"policy: {exc}")
    try:
        rules = load_rules(args.rules)
        print(f"rules: OK ({len(rules.rules)} rules)")
    except RuleRegistryError as exc:
        errors.append(f"rules: {exc}")
    if args.suppressions:
        try:
            valid, invalid = load_suppressions(args.suppressions)
            print(f"suppressions: {len(valid)} valid, {len(invalid)} invalid")
            errors.extend(invalid)
        except SuppressionError as exc:
            errors.append(f"suppressions: {exc}")

    root = normalize_project_root(args.project_root)
    try:
        cfg = load_config(args.config)
        limits = get_parser_limits(cfg)
        for path in args.compose:
            resolved = resolve_input_path(path, root)
            load_compose_file(resolved, root, limits)
            print(f"compose OK: {path}")
        for path in args.dockerfile:
            resolved = resolve_input_path(path, root)
            src = load_source_file(resolved, root, maximum_file_bytes=limits["maximum_file_bytes"])
            doc = parse_dockerfile(src.content)
            print(f"dockerfile OK: {path} (status={doc.status.value})")
    except (ComposeLoadError, SourceLoadError, PathSafetyError, ConfigError) as exc:
        errors.append(str(exc))

    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return int(ExitCode.ERROR)
    return int(ExitCode.SUCCESS)


def cmd_list_rules(args: argparse.Namespace) -> int:
    registry = load_rules()
    target = None if args.target == "project" else args.target
    rules = registry.list_rules(
        target=target,
        severity=args.severity,
        category=args.category,
    )
    if args.target == "project":
        rules = [r for r in rules if r.target == "project"]
    if args.fmt == "json":
        print(json.dumps([r.to_dict() for r in rules], indent=2))
        return 0
    print(f"{'ID':<14} {'Sev':<14} {'Target':<11} {'Category':<20} Title")
    print("-" * 100)
    for rule in rules:
        print(
            f"{rule.id:<14} {rule.severity.value:<14} {rule.target:<11} "
            f"{rule.category:<20} {rule.title}"
        )
    print(f"\n{len(rules)} rule(s)")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    try:
        registry = load_rules()
        rule = registry.get(args.rule_id)
    except RuleRegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.ERROR)
    info = remediation_for_rule(rule)
    print(f"Rule: {rule.id}")
    print(f"Title: {rule.title}")
    print(f"Target: {rule.target}")
    print(f"Category: {rule.category}")
    print(f"Severity: {rule.severity.value}")
    print(f"Enabled: {rule.enabled}")
    print(f"Profiles: {', '.join(rule.profiles)}")
    print(f"\nRisk:\n{rule.risk}")
    print(f"\nDetection logic:\n{rule.detection_logic}")
    print(f"\nFalse positives:\n{rule.false_positives}")
    print(f"\nRemediation:\n{rule.remediation}")
    print(f"\nDetailed remediation:\n{rule.detailed_remediation}")
    print(f"\nPatchability: {rule.patchability}")
    print(f"Automatic patch can be proposed: {rule.patchability == 'safe'}")
    print(f"\nLimitations:\n{rule.limitations}")
    print("\nReferences:")
    for ref in rule.references:
        print(f"  - {ref}")
    print("\nOperational validation:")
    for step in info["operational_validation_steps"]:
        print(f"  - {step}")
    return 0


def cmd_suggest(args: argparse.Namespace) -> int:
    if not args.compose and not args.compose_json:
        print("error: --compose or --compose-json required for suggest", file=sys.stderr)
        return int(ExitCode.ERROR)
    try:
        report = run_scan(
            compose_paths=args.compose,
            dockerfile_paths=args.dockerfile,
            compose_json_paths=args.compose_json,
            project_root=args.project_root,
            policy=args.policy,
            config=args.config,
            suppressions=args.suppressions,
            privacy_mode=args.privacy_mode,
            fail_on=_normalize_fail_on(args.fail_on),
            minimum_score=args.minimum_score,
        )
        cfg = load_config(args.config)
        limits = get_parser_limits(cfg)
        root = normalize_project_root(args.project_root)
        patches: list[str] = []
        for path in args.compose:
            doc = load_compose_file(path, root, limits)
            result = generate_unified_diff(doc, report.findings)
            patches.append(result.text)
        output = Path(args.output)
        output.write_text("\n".join(patches), encoding="utf-8")
        print(f"Wrote proposed remediation to {output}")
        print("PROPOSED REMEDIATION ONLY — MANUAL REVIEW REQUIRED")
        for finding in report.findings:
            if finding.status.value in {"Fail", "Warning"} and not finding.suppressed:
                print(f"- {finding.rule_id}: {finding.remediation}")
        return int(ExitCode.SUCCESS)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.ERROR)


def _load_report_or_scan(path: str, args: argparse.Namespace) -> Report:
    p = Path(path)
    if p.suffix.lower() == ".json" and p.is_file():
        data = json.loads(p.read_text(encoding="utf-8"))
        if "findings" in data and "tool_name" in data:
            findings = []
            for raw in data.get("findings") or []:
                findings.append(
                    Finding(
                        rule_id=str(raw["rule_id"]),
                        title=str(raw.get("title", "")),
                        target_type=str(raw.get("target_type", "")),
                        category=str(raw.get("category", "")),
                        severity=Severity.from_string(str(raw.get("severity", "Low"))),
                        status=Status(str(raw.get("status", "Fail"))),
                        summary=str(raw.get("summary", "")),
                        risk=str(raw.get("risk", "")),
                        evidence_redacted=str(raw.get("evidence_redacted", "")),
                        remediation=str(raw.get("remediation", "")),
                        file=str(raw.get("file", "")),
                        service=raw.get("service"),
                        stage=raw.get("stage"),
                        property_path=raw.get("property_path"),
                        fingerprint=str(raw.get("fingerprint", "")),
                        suppressed=bool(raw.get("suppressed", False)),
                    )
                )
            return Report(
                findings=findings,
                score=int(data.get("score", 0)),
                grade=str(data.get("grade", "F")),
                parsing_status=str(data.get("parsing_status", "ok")),
                parsing_warnings=list(data.get("parsing_warnings") or []),
                synthetic=bool(data.get("synthetic", False)),
            )
    return run_scan(
        compose_paths=[path],
        project_root=args.project_root,
        policy=args.policy,
        config=args.config,
        privacy_mode=args.privacy_mode,
    )


def cmd_compare(args: argparse.Namespace) -> int:
    try:
        before = _load_report_or_scan(args.before, args)
        after = _load_report_or_scan(args.after, args)
        result = compare_reports(before, after)
        out_dir = Path(args.output_directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        comparison_report = Report(
            findings=after.findings,
            score=after.score,
            grade=after.grade,
            comparison=result.to_dict(),
            score_explanation=(
                f"Score changed from {result.score_before} to {result.score_after} "
                f"(delta {result.score_delta:+d})"
            ),
            recommendations=[
                f"Resolved: {len(result.resolved)}",
                f"New: {len(result.new)}",
                f"Unchanged: {len(result.unchanged)}",
            ],
            exit_code=0,
        )
        _write_formats(comparison_report, out_dir, args.fmt)
        (out_dir / "comparison.json").write_text(
            json.dumps(result.to_dict(), indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            f"Comparison complete: resolved={len(result.resolved)} "
            f"new={len(result.new)} delta={result.score_delta:+d}"
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.ERROR)


def cmd_generate_demo(args: argparse.Namespace) -> int:
    out = Path(args.output_directory)
    out.mkdir(parents=True, exist_ok=True)
    note = out / "DEMO_NOTE.txt"
    note.write_text(
        "Synthetic demo generation is provided by scripts/generate-demo-data.py "
        "and scripts/generate-sample-reports.py. "
        "This command confirms the CLI entry point is available.\n"
        "All demo data must remain synthetic.\n",
        encoding="utf-8",
    )
    print(f"Wrote {note}")
    return 0


def cmd_version(_: argparse.Namespace | None = None) -> int:
    print(__version__)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if getattr(args, "version", False) and not args.command:
        return cmd_version()
    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "scan": cmd_scan,
        "validate": cmd_validate,
        "list-rules": cmd_list_rules,
        "explain": cmd_explain,
        "suggest": cmd_suggest,
        "compare": cmd_compare,
        "generate-demo": cmd_generate_demo,
        "version": lambda _a: cmd_version(),
    }
    if not args.command:
        parser.print_help()
        return int(ExitCode.ERROR)
    return int(handlers[args.command](args))


__all__ = ["build_parser", "main"]
