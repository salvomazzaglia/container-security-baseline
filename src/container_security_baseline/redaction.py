"""Redaction helpers for reports and console output."""

from __future__ import annotations

import re
from typing import Any

from container_security_baseline.paths import mask_path
from container_security_baseline.secret_detection import (
    is_secret_like_key,
    is_secret_like_value,
)

REDACTED = "[REDACTED]"

_URL_CRED_RE = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)([^\s/@:]+):([^\s/@]+)@")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_text(text: str) -> str:
    """Redact likely secrets from free-form text."""
    if not text:
        return text
    out = _PRIVATE_KEY_RE.sub(
        f"-----BEGIN PRIVATE KEY-----\n{REDACTED}\n-----END PRIVATE KEY-----", text
    )
    out = _URL_CRED_RE.sub(rf"\1{REDACTED}:{REDACTED}@", out)
    return out


def redact_env_assignment(key: str, value: str | None) -> str:
    if value is None:
        return f"{key}=<unset>"
    if is_secret_like_key(key) or is_secret_like_value(value):
        return f"{key}={REDACTED}"
    return f"{key}=<value>"


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow-redacted copy of a mapping for evidence display."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        key_s = str(key)
        if is_secret_like_key(key_s) or (isinstance(value, str) and is_secret_like_value(value)):
            result[key_s] = REDACTED
        elif isinstance(value, dict):
            result[key_s] = redact_mapping(value)
        elif isinstance(value, list):
            result[key_s] = [
                REDACTED if isinstance(v, str) and is_secret_like_value(v) else v for v in value
            ]
        else:
            result[key_s] = value
    return result


def redact_command_fragment(command: str) -> str:
    """Redact secret-like fragments from a command string."""
    text = redact_text(command)

    # KEY=VALUE patterns
    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        if is_secret_like_key(key):
            return f"{key}={REDACTED}"
        return m.group(0)

    text = re.sub(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)", repl, text)
    return text


def apply_privacy_to_path(path: str, privacy_mode: str) -> str:
    return mask_path(path, privacy_mode=privacy_mode)


def ensure_no_secret_leak(payload: str, known_fingerprints: set[str] | None = None) -> str:
    """Final pass before emitting reports — scrub private key / URL cred patterns."""
    _ = known_fingerprints  # fingerprints are hashes; values never present
    return redact_text(payload)


__all__ = [
    "REDACTED",
    "apply_privacy_to_path",
    "ensure_no_secret_leak",
    "redact_command_fragment",
    "redact_env_assignment",
    "redact_mapping",
    "redact_text",
]
