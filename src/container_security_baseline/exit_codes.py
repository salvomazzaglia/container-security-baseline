"""Process exit codes for the CLI."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """CLI exit codes.

    0 — success / no policy failure
    1 — findings present but below fail threshold (and score OK)
    2 — policy failure (threshold/score/critical suppression policy)
    3 — error (invalid input, parse failure, unsafe path, internal error)
    """

    SUCCESS = 0
    FINDINGS_BELOW = 1
    POLICY_FAILURE = 2
    ERROR = 3


SUCCESS = ExitCode.SUCCESS
FINDINGS_BELOW = ExitCode.FINDINGS_BELOW
POLICY_FAILURE = ExitCode.POLICY_FAILURE
ERROR = ExitCode.ERROR

__all__ = [
    "ERROR",
    "FINDINGS_BELOW",
    "POLICY_FAILURE",
    "SUCCESS",
    "ExitCode",
]
