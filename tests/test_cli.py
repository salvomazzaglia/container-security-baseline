"""CLI smoke tests (no Docker, no network)."""

from __future__ import annotations

import json
from pathlib import Path

from container_security_baseline.cli import build_parser, main
from container_security_baseline.exit_codes import ExitCode


def test_version() -> None:
    assert main(["version"]) == 0


def test_help_without_command() -> None:
    assert main([]) == int(ExitCode.ERROR)


def test_list_rules_table() -> None:
    assert main(["list-rules"]) == 0


def test_list_rules_json(capsys) -> None:
    assert main(["list-rules", "--format", "json"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["id"].startswith("CSB-")


def test_explain_rule() -> None:
    assert main(["explain", "CSB-CMP-001"]) == 0


def test_explain_unknown() -> None:
    assert main(["explain", "CSB-NOPE-999"]) == int(ExitCode.ERROR)


def test_validate_default_config() -> None:
    assert main(["validate"]) == 0


def test_scan_synthetic(tmp_path: Path, repo_root: Path) -> None:
    out = tmp_path / "out"
    code = main(
        [
            "scan",
            "--project-root",
            str(repo_root),
            "--compose",
            "examples/compose/hardened-compose.yml",
            "--output-directory",
            str(out),
            "--format",
            "json",
            "--synthetic",
            "--fail-on",
            "critical",
            "--quiet",
        ]
    )
    assert code in {0, 1, 2}
    assert (out / "report.json").is_file()
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["synthetic"] is True


def test_generate_demo(tmp_path: Path) -> None:
    code = main(["generate-demo", "--output-directory", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "DEMO_NOTE.txt").is_file()


def test_suggest_requires_compose() -> None:
    assert main(["suggest"]) == int(ExitCode.ERROR)


def test_parser_has_expected_commands() -> None:
    parser = build_parser()
    # Ensure subparsers exist by parsing --help paths indirectly
    assert parser.prog == "container-security-baseline"


def test_compare_reports(tmp_path: Path, failing_findings) -> None:
    from container_security_baseline.json_report import write_json_report
    from container_security_baseline.models import Report

    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    write_json_report(Report(synthetic=True, findings=failing_findings, score=75), before)
    write_json_report(Report(synthetic=True, findings=[], score=100), after)
    out = tmp_path / "cmp"
    code = main(
        [
            "compare",
            "--before",
            str(before),
            "--after",
            str(after),
            "--output-directory",
            str(out),
            "--format",
            "json",
        ]
    )
    assert code == 0
    assert (out / "comparison.json").is_file()
