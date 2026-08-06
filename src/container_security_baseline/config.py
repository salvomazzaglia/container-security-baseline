"""Configuration loading and validation."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

KNOWN_TOP_LEVEL_KEYS = frozenset(
    {
        "parser",
        "analysis",
        "discovery",
        "secret_detection",
        "scoring",
        "policy",
        "reporting",
        "privacy",
        "path_masks",
        "remediation",
        "logging",
        "sensitive_host_paths",
        "dangerous_capabilities",
        "sensitive_ports",
        "secret_key_patterns",
        "package_debug_tools",
    }
)

KNOWN_PARSER_KEYS = frozenset(
    {
        "maximum_file_bytes",
        "maximum_depth",
        "maximum_nodes",
        "maximum_aliases",
        "maximum_scalar_length",
        "maximum_sequence_length",
        "maximum_mapping_size",
        "maximum_documents",
        "reject_duplicate_keys",
        "reject_custom_tags",
    }
)

KNOWN_ANALYSIS_KEYS = frozenset(
    {
        "follow_symlinks",
        "read_referenced_files",
        "resolve_interpolation",
        "invoke_docker",
        "network_access",
    }
)


class ConfigError(ValueError):
    """Invalid configuration."""


def package_config_dir() -> Path:
    """Return the repository ``config/`` directory relative to this package.

    Looks for ``config/`` adjacent to the installed/source layout:
    ``<repo>/config`` when running from a src checkout, otherwise falls back
    to searching parents of this file.
    """
    here = Path(__file__).resolve()
    # src/container_security_baseline/config.py -> repo root
    candidates = [
        here.parents[2] / "config",
        here.parents[1] / "config",
        Path.cwd() / "config",
    ]
    for candidate in candidates:
        if (candidate / "default.config.json").is_file():
            return candidate
    raise ConfigError("Cannot locate config/default.config.json")


def default_config_path() -> Path:
    return package_config_dir() / "default.config.json"


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration: {path}") from exc
    if "\x00" in raw:
        raise ConfigError("NUL byte in configuration file")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in configuration: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a JSON object")
    return data


def _reject_unknown(section: str, data: dict[str, Any], known: frozenset[str]) -> None:
    unknown = sorted(set(data) - known)
    if unknown:
        raise ConfigError(f"Unknown {section} key(s): {', '.join(unknown)}")


def _validate_positive_int(
    name: str, value: Any, *, minimum: int = 1, maximum: int = 100_000_000
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{name} must be an integer")
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    if value > maximum:
        raise ConfigError(f"{name} exceeds maximum allowed value")
    return value


def validate_config(data: dict[str, Any]) -> dict[str, Any]:
    """Validate configuration keys and types; return a deep copy."""
    _reject_unknown("configuration", data, KNOWN_TOP_LEVEL_KEYS)
    cfg = deepcopy(data)

    parser = cfg.get("parser", {})
    if not isinstance(parser, dict):
        raise ConfigError("parser must be an object")
    _reject_unknown("parser", parser, KNOWN_PARSER_KEYS)
    for key in (
        "maximum_file_bytes",
        "maximum_depth",
        "maximum_nodes",
        "maximum_aliases",
        "maximum_scalar_length",
        "maximum_sequence_length",
        "maximum_mapping_size",
        "maximum_documents",
    ):
        if key in parser:
            parser[key] = _validate_positive_int(key, parser[key])

    analysis = cfg.get("analysis", {})
    if not isinstance(analysis, dict):
        raise ConfigError("analysis must be an object")
    _reject_unknown("analysis", analysis, KNOWN_ANALYSIS_KEYS)
    for key, expected in (
        ("follow_symlinks", False),
        ("read_referenced_files", False),
        ("resolve_interpolation", False),
        ("invoke_docker", False),
        ("network_access", False),
    ):
        if key in analysis and analysis[key] is not expected:
            # Hard safety: these must remain false in v1.0
            if analysis[key] is True:
                raise ConfigError(
                    f"analysis.{key}=true is not permitted; "
                    "container-security-baseline never follows references, "
                    "resolves interpolation, invokes Docker, or uses the network"
                )

    secret = cfg.get("secret_detection", {})
    if secret and not isinstance(secret, dict):
        raise ConfigError("secret_detection must be an object")

    scoring = cfg.get("scoring", {})
    if scoring and not isinstance(scoring, dict):
        raise ConfigError("scoring must be an object")

    reporting = cfg.get("reporting", {})
    if reporting and not isinstance(reporting, dict):
        raise ConfigError("reporting must be an object")

    return cfg


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge override onto base (dicts only)."""
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load default config, optionally merged with a user config file."""
    defaults = validate_config(load_json_object(default_config_path()))
    if path is None:
        return defaults
    user_path = Path(path)
    user = load_json_object(user_path)
    merged = deep_merge(defaults, user)
    return validate_config(merged)


def get_parser_limits(config: dict[str, Any]) -> dict[str, Any]:
    parser = config.get("parser", {})
    return {
        "maximum_file_bytes": int(parser.get("maximum_file_bytes", 2_097_152)),
        "maximum_depth": int(parser.get("maximum_depth", 50)),
        "maximum_nodes": int(parser.get("maximum_nodes", 50_000)),
        "maximum_aliases": int(parser.get("maximum_aliases", 100)),
        "maximum_scalar_length": int(parser.get("maximum_scalar_length", 262_144)),
        "maximum_sequence_length": int(parser.get("maximum_sequence_length", 10_000)),
        "maximum_mapping_size": int(parser.get("maximum_mapping_size", 10_000)),
        "maximum_documents": int(parser.get("maximum_documents", 1)),
        "reject_duplicate_keys": bool(parser.get("reject_duplicate_keys", True)),
        "reject_custom_tags": bool(parser.get("reject_custom_tags", True)),
    }


__all__ = [
    "ConfigError",
    "deep_merge",
    "default_config_path",
    "get_parser_limits",
    "load_config",
    "package_config_dir",
    "validate_config",
]
