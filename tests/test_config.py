"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from container_security_baseline.config import (
    ConfigError,
    deep_merge,
    default_config_path,
    get_parser_limits,
    load_config,
    load_json_object,
    package_config_dir,
    validate_config,
)


def test_package_config_dir_exists() -> None:
    assert (package_config_dir() / "default.config.json").is_file()


def test_load_default_config() -> None:
    cfg = load_config()
    assert cfg["analysis"]["invoke_docker"] is False
    assert cfg["analysis"]["network_access"] is False


def test_get_parser_limits() -> None:
    limits = get_parser_limits(load_config())
    assert limits["maximum_depth"] >= 1
    assert limits["reject_duplicate_keys"] is True


def test_reject_unknown_top_level() -> None:
    with pytest.raises(ConfigError, match="Unknown"):
        validate_config({"not_a_real_section": {}})


def test_reject_invoke_docker_true() -> None:
    base = load_config()
    base["analysis"]["invoke_docker"] = True
    with pytest.raises(ConfigError, match="invoke_docker"):
        validate_config(base)


def test_reject_network_access_true() -> None:
    base = load_config()
    base["analysis"]["network_access"] = True
    with pytest.raises(ConfigError, match="network_access"):
        validate_config(base)


def test_deep_merge() -> None:
    merged = deep_merge({"a": {"x": 1, "y": 2}}, {"a": {"y": 9}, "b": 3})
    assert merged == {"a": {"x": 1, "y": 9}, "b": 3}


def test_load_user_override(tmp_path: Path) -> None:
    path = tmp_path / "user.json"
    path.write_text('{"reporting": {"privacy_mode": "masked"}}', encoding="utf-8")
    cfg = load_config(path)
    assert cfg["reporting"]["privacy_mode"] == "masked"


def test_nul_in_config(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(b'{"parser": {"maximum_depth": 1}\x00}')
    with pytest.raises(ConfigError, match="NUL"):
        load_json_object(path)


def test_non_object_root(tmp_path: Path) -> None:
    path = tmp_path / "arr.json"
    path.write_text("[1,2]", encoding="utf-8")
    with pytest.raises(ConfigError, match="object"):
        load_json_object(path)


def test_invalid_parser_int() -> None:
    with pytest.raises(ConfigError):
        validate_config({"parser": {"maximum_depth": 0}})


def test_default_config_path() -> None:
    assert default_config_path().name == "default.config.json"
