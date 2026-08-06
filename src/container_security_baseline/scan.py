"""Public high-level scan API."""

from __future__ import annotations

from container_security_baseline.evaluator import ScanError, run_scan

__all__ = ["ScanError", "run_scan"]
