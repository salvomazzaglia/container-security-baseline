"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from container_security_baseline.models import Report
from container_security_baseline.redaction import ensure_no_secret_leak


def report_to_json_dict(report: Report) -> dict[str, Any]:
    return report.to_dict()


def write_json_report(report: Report, path: str | Path) -> None:
    payload = json.dumps(report_to_json_dict(report), indent=2, ensure_ascii=False, sort_keys=False)
    payload = ensure_no_secret_leak(payload)
    Path(path).write_text(payload + "\n", encoding="utf-8")


def dumps_json_report(report: Report) -> str:
    payload = json.dumps(report_to_json_dict(report), indent=2, ensure_ascii=False)
    return ensure_no_secret_leak(payload)


__all__ = ["dumps_json_report", "report_to_json_dict", "write_json_report"]
