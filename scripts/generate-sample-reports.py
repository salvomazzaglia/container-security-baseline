#!/usr/bin/env python3
"""Generate sample reports from synthetic examples only.

Never invokes Docker, never uses the network, never reads .env.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from container_security_baseline.compose_loader import load_compose_file  # noqa: E402
from container_security_baseline.config import get_parser_limits, load_config  # noqa: E402
from container_security_baseline.evaluator import run_scan  # noqa: E402
from container_security_baseline.html_report import write_html_report  # noqa: E402
from container_security_baseline.json_report import write_json_report  # noqa: E402
from container_security_baseline.patching import generate_unified_diff  # noqa: E402
from container_security_baseline.redaction import ensure_no_secret_leak  # noqa: E402
from container_security_baseline.sarif_report import write_sarif_report  # noqa: E402

COMPOSE = "examples/compose/insecure-compose.yml"
DOCKERFILE = "examples/dockerfiles/Dockerfile.insecure"
SECRET_LITERAL = "SYNTHETIC_NOT_A_REAL_SECRET"


def _assert_no_secret(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if SECRET_LITERAL in text:
        raise SystemExit(f"error: raw secret literal leaked into {path.name}")


def _assert_synthetic(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".html":
        if "SYNTHETIC DEMONSTRATION" not in text and "SYNTHETIC" not in text.upper():
            raise SystemExit(f"error: missing SYNTHETIC marker in {path.name}")
        return
    compacted = text.replace(" ", "").lower()
    if '"synthetic":true' not in compacted and "SYNTHETIC" not in text.upper():
        raise SystemExit(f"error: missing synthetic flag in {path.name}")


def main() -> int:
    examples = REPO_ROOT / "examples"
    compose_path = REPO_ROOT / COMPOSE
    dockerfile_path = REPO_ROOT / DOCKERFILE
    if not compose_path.is_file() or not dockerfile_path.is_file():
        print(
            "error: required synthetic examples missing; run generate-demo-data.py", file=sys.stderr
        )
        return 1

    report = run_scan(
        compose_paths=[COMPOSE],
        dockerfile_paths=[DOCKERFILE],
        project_root=REPO_ROOT,
        policy="baseline",
        synthetic=True,
    )
    if not report.synthetic:
        print("error: report.synthetic is False", file=sys.stderr)
        return 1

    json_out = examples / "sample-report.json"
    html_out = examples / "sample-report.html"
    sarif_out = examples / "sample-report.sarif"
    patch_out = examples / "sample-remediation.patch"

    write_json_report(report, json_out)
    write_html_report(report, html_out)
    write_sarif_report(report, sarif_out)

    cfg = load_config()
    limits = get_parser_limits(cfg)
    doc = load_compose_file(
        compose_path, REPO_ROOT, limits, display_path=COMPOSE.replace("\\", "/")
    )
    patch = generate_unified_diff(doc, report.findings)
    # Patch is a proposed diff of synthetic sources — scrub secret literals before publish
    scrubbed = ensure_no_secret_leak(patch.text).replace(SECRET_LITERAL, "[REDACTED]")
    patch_out.write_text(scrubbed, encoding="utf-8", newline="\n")

    for path in (json_out, html_out, sarif_out):
        _assert_synthetic(path)
        _assert_no_secret(path)
    _assert_no_secret(patch_out)

    print(f"Wrote {json_out.relative_to(REPO_ROOT)}")
    print(f"Wrote {html_out.relative_to(REPO_ROOT)}")
    print(f"Wrote {sarif_out.relative_to(REPO_ROOT)}")
    print(f"Wrote {patch_out.relative_to(REPO_ROOT)}")
    print(f"findings={len(report.findings)} score={report.score} grade={report.grade}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
