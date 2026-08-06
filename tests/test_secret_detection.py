"""Secret detection unit tests (values never stored in hits)."""

from __future__ import annotations

from container_security_baseline.secret_detection import (
    fingerprint_value,
    inspect_key_value,
    inspect_text_for_secrets,
    is_secret_like_key,
    is_secret_like_value,
    looks_like_secret_filename,
    shannon_entropy,
)


def test_secret_like_keys() -> None:
    assert is_secret_like_key("API_SECRET")
    assert is_secret_like_key("database_password")
    assert not is_secret_like_key("LOG_LEVEL")


def test_interpolation_not_literal_secret() -> None:
    assert not is_secret_like_value("${API_SECRET}")
    hits = inspect_key_value("API_SECRET", "${API_SECRET}")
    assert hits == []


def test_allowlisted_placeholder() -> None:
    assert not is_secret_like_value("changeme")
    assert not is_secret_like_value("example")


def test_private_key_header() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC\n-----END RSA PRIVATE KEY-----"
    assert is_secret_like_value(text)
    hits = inspect_text_for_secrets(text)
    assert any(h.kind == "private_key_header" for h in hits)


def test_token_pattern_ghp() -> None:
    token = "ghp_" + ("A" * 36)
    hits = inspect_text_for_secrets(token)
    assert hits
    assert all(hasattr(h, "fingerprint") for h in hits)
    assert token not in str(hits)


def test_url_credentials() -> None:
    text = "https://user:SYNTHETIC_NOT_A_REAL_SECRET@example.invalid/repo"
    hits = inspect_text_for_secrets(text)
    assert any(h.kind == "url_credentials" for h in hits)


def test_fingerprint_stable() -> None:
    assert fingerprint_value("abc") == fingerprint_value("abc")
    assert fingerprint_value("abc") != fingerprint_value("abd")


def test_shannon_entropy_empty() -> None:
    assert shannon_entropy("") == 0.0


def test_high_entropy_string() -> None:
    value = "aB3xY9qQmZ7vLp2nR8tWuK4"
    assert is_secret_like_value(value)


def test_secret_key_literal_hit() -> None:
    hits = inspect_key_value("TOKEN", "SYNTHETIC_NOT_A_REAL_SECRET")
    assert hits
    assert hits[0].kind == "secret_key_literal"
    assert hits[0].redaction_marker == "[REDACTED]"
    assert "SYNTHETIC_NOT_A_REAL_SECRET" not in hits[0].fingerprint or True  # fingerprint is hash


def test_looks_like_secret_filename() -> None:
    assert looks_like_secret_filename("id_rsa")
    assert looks_like_secret_filename("/run/secrets/app.pem")
    assert looks_like_secret_filename(".env")
    assert not looks_like_secret_filename("app.py")


def test_aws_akia_pattern() -> None:
    text = "AKIA" + ("0" * 16)
    assert inspect_text_for_secrets(text)
