"""Rule evaluation status values."""

from __future__ import annotations

from enum import Enum


class Status(str, Enum):
    """Outcome of a single rule evaluation."""

    PASS = "Pass"
    FAIL = "Fail"
    WARNING = "Warning"
    NOT_APPLICABLE = "NotApplicable"
    UNAVAILABLE = "Unavailable"
    ERROR = "Error"
    SUPPRESSED = "Suppressed"

    def __str__(self) -> str:
        return self.value


# Backwards-friendly aliases matching requirements naming.
Pass = Status.PASS
Fail = Status.FAIL
Warning = Status.WARNING
NotApplicable = Status.NOT_APPLICABLE
Unavailable = Status.UNAVAILABLE
Error = Status.ERROR
Suppressed = Status.SUPPRESSED

__all__ = [
    "Error",
    "Fail",
    "NotApplicable",
    "Pass",
    "Status",
    "Suppressed",
    "Unavailable",
    "Warning",
]
