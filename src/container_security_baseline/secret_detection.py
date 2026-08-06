"""Privacy-preserving secret detection (never stores secret values)."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass

# Key-name heuristics (case-insensitive substring match on key)
DEFAULT_SECRET_KEY_PATTERNS: tuple[str, ...] = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "CLIENT_SECRET",
    "ACCESS_KEY",
    "AUTH",
    "CREDENTIAL",
)

_PRIVATE_KEY_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
)

# Conservative token-ish patterns (synthetic-friendly; values never stored)
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)

_URL_CRED_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@")

_ALLOWLIST_VALUES = frozenset(
    {
        "",
        "true",
        "false",
        "yes",
        "no",
        "null",
        "none",
        "changeme",
        "placeholder",
        "example",
        "todo",
        "redacted",
        "${}",
    }
)


@dataclass(frozen=True)
class SecretHit:
    """Redacted secret detection hit — never contains the secret value."""

    kind: str
    field_name: str | None
    fingerprint: str
    confidence: str
    redaction_marker: str = "[REDACTED]"


def fingerprint_value(value: str) -> str:
    """Non-reversible short fingerprint for deduplication only."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return digest[:12]


def is_secret_like_key(key: str, patterns: Iterable[str] | None = None) -> bool:
    upper = key.upper()
    pats = tuple(patterns) if patterns is not None else DEFAULT_SECRET_KEY_PATTERNS
    return any(p.upper() in upper for p in pats)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_secret_like_value(
    value: str,
    *,
    min_length: int = 20,
    entropy_threshold: float = 4.5,
    maximum_value_length: int = 8192,
) -> bool:
    """Conservative high-entropy / token / key-header detection."""
    if value is None:
        return False
    text = str(value)
    if len(text) > maximum_value_length:
        text = text[:maximum_value_length]
    lowered = text.strip().lower()
    if lowered in _ALLOWLIST_VALUES:
        return False
    # Interpolation-only values are not literal secrets
    if text.strip().startswith("${") and text.strip().endswith("}"):
        return False
    if any(h in text for h in _PRIVATE_KEY_HEADERS):
        return True
    if _URL_CRED_RE.search(text):
        return True
    for pat in _TOKEN_PATTERNS:
        if pat.search(text):
            return True
    # High entropy on long-ish strings without spaces
    candidate = text.strip().strip("\"'")
    if len(candidate) >= min_length and " " not in candidate:
        # Prefer base64/hex-ish alphabet
        if re.fullmatch(r"[A-Za-z0-9/+=_-]+", candidate):
            if shannon_entropy(candidate) >= entropy_threshold:
                return True
    return False


def inspect_key_value(
    key: str,
    value: str | None,
    *,
    patterns: Iterable[str] | None = None,
    min_length: int = 20,
    entropy_threshold: float = 4.5,
) -> list[SecretHit]:
    """Inspect a key/value pair; return redacted hits only."""
    hits: list[SecretHit] = []
    if value is None:
        return hits
    key_match = is_secret_like_key(key, patterns)
    value_match = is_secret_like_value(
        value, min_length=min_length, entropy_threshold=entropy_threshold
    )
    if key_match and str(value).strip() and not str(value).strip().startswith("${"):
        hits.append(
            SecretHit(
                kind="secret_key_literal",
                field_name=key,
                fingerprint=fingerprint_value(str(value)),
                confidence="high",
            )
        )
    elif value_match:
        hits.append(
            SecretHit(
                kind="high_entropy_or_token",
                field_name=key,
                fingerprint=fingerprint_value(str(value)),
                confidence="medium",
            )
        )
    return hits


def inspect_text_for_secrets(
    text: str,
    *,
    field_name: str | None = None,
    min_length: int = 20,
    entropy_threshold: float = 4.5,
) -> list[SecretHit]:
    """Inspect free-form text (commands, labels); never store matched values."""
    hits: list[SecretHit] = []
    if any(h in text for h in _PRIVATE_KEY_HEADERS):
        hits.append(
            SecretHit(
                kind="private_key_header",
                field_name=field_name,
                fingerprint=fingerprint_value(text),
                confidence="high",
            )
        )
    if _URL_CRED_RE.search(text):
        hits.append(
            SecretHit(
                kind="url_credentials",
                field_name=field_name,
                fingerprint=fingerprint_value(text),
                confidence="high",
            )
        )
    for pat in _TOKEN_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(
                SecretHit(
                    kind="token_pattern",
                    field_name=field_name,
                    fingerprint=fingerprint_value(m.group(0)),
                    confidence="high",
                )
            )
            break
    if is_secret_like_value(text, min_length=min_length, entropy_threshold=entropy_threshold):
        # Avoid duplicating if already matched
        if not hits:
            hits.append(
                SecretHit(
                    kind="high_entropy_or_token",
                    field_name=field_name,
                    fingerprint=fingerprint_value(text),
                    confidence="medium",
                )
            )
    return hits


def looks_like_secret_filename(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    markers = (
        "id_rsa",
        "id_ed25519",
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".env",
        "credentials",
        "secret",
        "kubeconfig",
        "aws/credentials",
        ".npmrc",
        ".dockercfg",
        "auth.json",
    )
    return any(m in name or name.endswith(m) for m in markers)


__all__ = [
    "DEFAULT_SECRET_KEY_PATTERNS",
    "SecretHit",
    "fingerprint_value",
    "inspect_key_value",
    "inspect_text_for_secrets",
    "is_secret_like_key",
    "is_secret_like_value",
    "looks_like_secret_filename",
    "shannon_entropy",
]
