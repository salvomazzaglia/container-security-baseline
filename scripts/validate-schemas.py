#!/usr/bin/env python3
"""Validate config/*.json and sample reports against schemas/."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = REPO_ROOT / "schemas"
CONFIG = REPO_ROOT / "config"
EXAMPLES = REPO_ROOT / "examples"


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(schema_name: str) -> Draft202012Validator:
    schema = _load(SCHEMAS / schema_name)
    return Draft202012Validator(schema)  # type: ignore[arg-type]


def _validate(label: str, validator: Draft202012Validator, data: object, errors: list[str]) -> None:
    errs = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if not errs:
        print(f"OK {label}")
        return
    for err in errs[:5]:
        path = ".".join(str(p) for p in err.path) or "<root>"
        errors.append(f"{label}: {path}: {err.message}")
    if len(errs) > 5:
        errors.append(f"{label}: ... and {len(errs) - 5} more error(s)")


def main() -> int:
    errors: list[str] = []

    config_validator = _validator("config.schema.json")
    for name in ("default.config.json", "demo.config.json"):
        path = CONFIG / name
        if path.is_file():
            _validate(name, config_validator, _load(path), errors)

    policy_validator = _validator("policy.schema.json")
    for path in sorted(CONFIG.glob("*.policy.json")):
        _validate(path.name, policy_validator, _load(path), errors)

    rules_path = CONFIG / "rules.json"
    if rules_path.is_file() and (SCHEMAS / "rule.schema.json").is_file():
        _validate("rules.json", _validator("rule.schema.json"), _load(rules_path), errors)

    supp_example = CONFIG / "suppressions.example.json"
    if supp_example.is_file() and (SCHEMAS / "suppression.schema.json").is_file():
        _validate(
            "suppressions.example.json",
            _validator("suppression.schema.json"),
            _load(supp_example),
            errors,
        )

    sample_json = EXAMPLES / "sample-report.json"
    if sample_json.is_file():
        _validate(
            "sample-report.json", _validator("report.schema.json"), _load(sample_json), errors
        )
    else:
        print("SKIP sample-report.json (not generated yet)")

    sample_sarif = EXAMPLES / "sample-report.sarif"
    if sample_sarif.is_file() and (SCHEMAS / "sarif-subset.schema.json").is_file():
        _validate(
            "sample-report.sarif",
            _validator("sarif-subset.schema.json"),
            _load(sample_sarif),
            errors,
        )

    if errors:
        print(f"\n{len(errors)} validation error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("All schema validations passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
