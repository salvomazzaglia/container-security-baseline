"""Tests for exit code enum and semantics."""

from __future__ import annotations

from container_security_baseline.exit_codes import (
    ERROR,
    FINDINGS_BELOW,
    POLICY_FAILURE,
    SUCCESS,
    ExitCode,
)


def test_exit_code_values() -> None:
    assert int(ExitCode.SUCCESS) == 0
    assert int(ExitCode.FINDINGS_BELOW) == 1
    assert int(ExitCode.POLICY_FAILURE) == 2
    assert int(ExitCode.ERROR) == 3


def test_aliases() -> None:
    assert SUCCESS == ExitCode.SUCCESS
    assert FINDINGS_BELOW == ExitCode.FINDINGS_BELOW
    assert POLICY_FAILURE == ExitCode.POLICY_FAILURE
    assert ERROR == ExitCode.ERROR


def test_exit_code_is_intenum() -> None:
    assert isinstance(ExitCode.SUCCESS, int)


def test_ordering_documented() -> None:
    assert ExitCode.SUCCESS < ExitCode.FINDINGS_BELOW < ExitCode.POLICY_FAILURE < ExitCode.ERROR


def test_name_lookup() -> None:
    assert ExitCode["ERROR"] == ExitCode.ERROR
