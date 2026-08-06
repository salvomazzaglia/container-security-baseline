"""Tests for normalized Compose model helpers."""

from __future__ import annotations

from container_security_baseline.compose_model import (
    normalize_compose,
    normalize_service,
    parse_environment,
    parse_labels,
    parse_port,
    parse_volume,
)


def test_parse_environment_dict() -> None:
    env = parse_environment({"A": "1", "B": None})
    assert env["A"] == "1"
    assert env["B"] is None


def test_parse_environment_list() -> None:
    env = parse_environment(["FOO=bar", "BAZ"])
    assert env["FOO"] == "bar"
    assert env["BAZ"] is None


def test_parse_labels_list() -> None:
    labels = parse_labels(["a=b", "c=d"])
    assert labels["a"] == "b"


def test_parse_port_short() -> None:
    port = parse_port("8080:80")
    assert port.short_syntax is True
    assert port.published == 8080 or port.published == "8080" or port.target == 80


def test_parse_port_long() -> None:
    port = parse_port({"target": 80, "published": 8080, "protocol": "tcp"})
    assert port.target == 80
    assert port.published == 8080


def test_parse_volume_short_rw() -> None:
    vol = parse_volume("/etc:/etc:rw")
    assert vol.source == "/etc"
    assert vol.target == "/etc"
    assert vol.read_only is False


def test_parse_volume_short_ro() -> None:
    vol = parse_volume("/etc:/etc:ro")
    assert vol.read_only is True


def test_parse_volume_long() -> None:
    vol = parse_volume(
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
    )
    assert vol.type == "bind"
    assert vol.source is not None


def test_normalize_service_privileged() -> None:
    svc = normalize_service(
        "web",
        {"image": "registry.example.invalid/a:1", "privileged": True, "user": "root"},
    )
    assert svc.privileged is True
    assert svc.user == "root"
    assert svc.name == "web"


def test_normalize_compose_services() -> None:
    model = normalize_compose(
        {
            "services": {
                "web": {"image": "registry.example.invalid/a:1", "cap_add": ["NET_ADMIN"]},
            },
            "networks": {"front": {}},
        }
    )
    assert "web" in model.services
    assert model.services["web"].cap_add == ["NET_ADMIN"]
    assert "front" in model.networks


def test_normalize_env_file_list() -> None:
    svc = normalize_service("web", {"image": "a", "env_file": [".env", "other.env"]})
    assert len(svc.env_file) == 2


def test_normalize_security_opt() -> None:
    svc = normalize_service(
        "web",
        {"image": "a", "security_opt": ["no-new-privileges:true", "seccomp:unconfined"]},
    )
    assert "seccomp:unconfined" in svc.security_opt
