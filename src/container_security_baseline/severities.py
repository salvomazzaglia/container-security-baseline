"""Finding severity levels with deterministic ranking."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Ordered severity for findings and fail-on thresholds."""

    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        """Numeric rank; higher means more severe."""
        return _SEVERITY_RANK[self]

    def at_or_above(self, threshold: Severity) -> bool:
        """Return True if this severity is at least ``threshold``."""
        return self.rank >= threshold.rank

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Parse a severity string case-insensitively."""
        normalized = value.strip().lower()
        mapping = {item.value.lower(): item for item in cls}
        if normalized not in mapping:
            raise ValueError(f"Unknown severity: {value!r}")
        return mapping[normalized]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Requirement-friendly aliases
Informational = Severity.INFORMATIONAL
Low = Severity.LOW
Medium = Severity.MEDIUM
High = Severity.HIGH
Critical = Severity.CRITICAL

DEFAULT_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 0,
}

__all__ = [
    "DEFAULT_DEDUCTIONS",
    "Critical",
    "High",
    "Informational",
    "Low",
    "Medium",
    "Severity",
]
