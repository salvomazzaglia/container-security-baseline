"""Compose interpolation detection without resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass

from container_security_baseline.secret_detection import is_secret_like_key, is_secret_like_value


@dataclass(frozen=True)
class InterpolationMatch:
    """A detected Compose-style interpolation expression."""

    raw: str
    variable: str
    kind: str  # simple | default | required | pattern-other
    default_value: str | None = None
    error_message: str | None = None
    secret_like_default: bool = False
    start: int = 0
    end: int = 0


# ${VAR}, $VAR, ${VAR:-default}, ${VAR-default}, ${VAR:?err}, ${VAR?err}, ${VAR:+alt}
_INTERP_RE = re.compile(r"\$\{(?P<braced>[^}]+)\}|\$(?P<simple>[A-Za-z_][A-Za-z0-9_]*)")


def detect_interpolations(text: str) -> list[InterpolationMatch]:
    """Detect interpolation expressions without resolving them."""
    results: list[InterpolationMatch] = []
    for m in _INTERP_RE.finditer(text):
        if m.group("simple"):
            results.append(
                InterpolationMatch(
                    raw=m.group(0),
                    variable=m.group("simple"),
                    kind="simple",
                    start=m.start(),
                    end=m.end(),
                )
            )
            continue
        braced = m.group("braced") or ""
        variable = ""
        kind = "simple"
        default_value: str | None = None
        error_message: str | None = None

        for sep, sep_kind in (
            (":-", "default"),
            (":?", "required"),
            (":+", "alternate"),
            ("-", "default"),
            ("?", "required"),
            ("+", "alternate"),
        ):
            if sep in braced:
                variable, _, rest = braced.partition(sep)
                kind = sep_kind
                if sep_kind == "default":
                    default_value = rest
                elif sep_kind == "required":
                    error_message = rest
                else:
                    default_value = rest
                break
        else:
            variable = braced
            kind = "simple"

        variable = variable.strip()
        secret_default = False
        if default_value is not None:
            secret_default = is_secret_like_key(variable) or is_secret_like_value(default_value)

        results.append(
            InterpolationMatch(
                raw=m.group(0),
                variable=variable,
                kind=kind,
                default_value=default_value,
                error_message=error_message,
                secret_like_default=secret_default,
                start=m.start(),
                end=m.end(),
            )
        )
    return results


def contains_interpolation(text: str) -> bool:
    return bool(_INTERP_RE.search(text))


def is_interpolation_only(text: str) -> bool:
    stripped = text.strip()
    matches = detect_interpolations(stripped)
    if len(matches) != 1:
        return False
    return matches[0].raw == stripped


__all__ = [
    "InterpolationMatch",
    "contains_interpolation",
    "detect_interpolations",
    "is_interpolation_only",
]
