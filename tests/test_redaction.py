"""Redaction helper tests."""

from __future__ import annotations

from container_security_baseline.redaction import (
    REDACTED,
    apply_privacy_to_path,
    ensure_no_secret_leak,
    redact_command_fragment,
    redact_env_assignment,
    redact_mapping,
    redact_text,
)


def test_redact_env_assignment_secret_key() -> None:
    assert REDACTED in redact_env_assignment("API_SECRET", "SYNTHETIC_NOT_A_REAL_SECRET")


def test_redact_env_assignment_normal() -> None:
    out = redact_env_assignment("LOG_LEVEL", "info")
    assert "LOG_LEVEL" in out
    assert "SYNTHETIC" not in out


def test_redact_mapping_nested() -> None:
    data = {"PASSWORD": "SYNTHETIC_NOT_A_REAL_SECRET", "nested": {"TOKEN": "x"}}
    out = redact_mapping(data)
    assert out["PASSWORD"] == REDACTED
    assert out["nested"]["TOKEN"] == REDACTED


def test_redact_url_credentials() -> None:
    text = "https://user:SYNTHETIC_NOT_A_REAL_SECRET@example.invalid/"
    out = redact_text(text)
    assert "SYNTHETIC_NOT_A_REAL_SECRET" not in out
    assert REDACTED in out


def test_redact_private_key_block() -> None:
    text = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
    out = redact_text(text)
    assert "AAAA" not in out
    assert REDACTED in out


def test_redact_command_fragment() -> None:
    cmd = "export API_SECRET=SYNTHETIC_NOT_A_REAL_SECRET && run"
    out = redact_command_fragment(cmd)
    assert "SYNTHETIC_NOT_A_REAL_SECRET" not in out


def test_ensure_no_secret_leak() -> None:
    payload = '{"url": "https://a:SYNTHETIC_NOT_A_REAL_SECRET@example.invalid"}'
    out = ensure_no_secret_leak(payload)
    assert "SYNTHETIC_NOT_A_REAL_SECRET" not in out


def test_apply_privacy_to_path() -> None:
    masked = apply_privacy_to_path(r"C:\Users\bob\proj", "masked")
    assert "bob" not in masked or "<USER_HOME>" in masked
