"""Normalized Compose model helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PortBinding:
    """Normalized published port binding."""

    raw: str | dict[str, Any]
    target: int | None = None
    published: str | int | None = None
    host_ip: str | None = None
    protocol: str = "tcp"
    mode: str | None = None
    short_syntax: bool = False
    ambiguous: bool = False


@dataclass
class VolumeMount:
    """Normalized volume / bind mount."""

    raw: str | dict[str, Any]
    type: str | None = None  # bind, volume, tmpfs, npipe, ...
    source: str | None = None
    target: str | None = None
    read_only: bool | None = None
    short_syntax: bool = False
    ambiguous: bool = False


@dataclass
class BuildConfig:
    context: str | None = None
    dockerfile: str | None = None
    args: dict[str, str | None] = field(default_factory=dict)
    target: str | None = None
    network: str | None = None
    privileged: bool | None = None
    ssh: Any = None
    secrets: list[Any] = field(default_factory=list)
    raw: Any = None


@dataclass
class ServiceModel:
    """Normalized view of a single Compose service."""

    name: str
    raw: dict[str, Any]
    image: str | None = None
    build: BuildConfig | None = None
    privileged: bool = False
    user: str | None = None
    working_dir: str | None = None
    read_only: bool = False
    network_mode: str | None = None
    pid: str | None = None
    ipc: str | None = None
    userns_mode: str | None = None
    cap_add: list[str] = field(default_factory=list)
    cap_drop: list[str] = field(default_factory=list)
    security_opt: list[str] = field(default_factory=list)
    devices: list[Any] = field(default_factory=list)
    device_cgroup_rules: list[str] = field(default_factory=list)
    volumes: list[VolumeMount] = field(default_factory=list)
    volumes_from: list[Any] = field(default_factory=list)
    ports: list[PortBinding] = field(default_factory=list)
    expose: list[Any] = field(default_factory=list)
    environment: dict[str, str | None] = field(default_factory=dict)
    env_file: list[str] = field(default_factory=list)
    secrets: list[Any] = field(default_factory=list)
    configs: list[Any] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    command: Any = None
    entrypoint: Any = None
    healthcheck: dict[str, Any] | None = None
    logging: dict[str, Any] | None = None
    deploy: dict[str, Any] | None = None
    mem_limit: Any = None
    cpus: Any = None
    pids_limit: Any = None
    restart: str | None = None
    stop_grace_period: str | None = None
    depends_on: Any = None
    sysctls: dict[str, Any] = field(default_factory=dict)
    tmpfs: list[str] = field(default_factory=list)
    extra_hosts: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    mac_address: str | None = None
    group_add: list[Any] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)
    extends: Any = None
    init: bool | None = None


@dataclass
class ComposeModel:
    """Normalized Compose project."""

    services: dict[str, ServiceModel] = field(default_factory=dict)
    networks: dict[str, Any] = field(default_factory=dict)
    volumes: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, Any] = field(default_factory=dict)
    configs: dict[str, Any] = field(default_factory=dict)
    include: Any = None
    name: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    extension_fields: dict[str, Any] = field(default_factory=dict)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_str_list(value: Any) -> list[str]:
    return [str(v) for v in _as_list(value)]


def parse_environment(value: Any) -> dict[str, str | None]:
    """Normalize environment map or list into a dict."""
    result: dict[str, str | None] = {}
    if value is None:
        return result
    if isinstance(value, dict):
        for key, val in value.items():
            result[str(key)] = None if val is None else str(val)
        return result
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                if "=" in item:
                    key, _, val = item.partition("=")
                    result[key] = val
                else:
                    result[item] = None
            elif isinstance(item, dict):
                for key, val in item.items():
                    result[str(key)] = None if val is None else str(val)
    return result


def parse_labels(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if value is None:
        return result
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and "=" in item:
                key, _, val = item.partition("=")
                result[key] = val
            elif isinstance(item, str):
                result[item] = ""
    return result


def parse_port(entry: Any) -> PortBinding:
    """Parse short or long port syntax."""
    if isinstance(entry, dict):
        target_val = entry.get("target")
        published_val = entry.get("published")
        host_ip_val = entry.get("host_ip")
        return PortBinding(
            raw=entry,
            target=int(target_val)
            if target_val is not None and str(target_val).isdigit()
            else None,
            published=published_val,
            host_ip=str(host_ip_val) if host_ip_val is not None else None,
            protocol=str(entry.get("protocol", "tcp")),
            mode=str(entry["mode"]) if "mode" in entry else None,
            short_syntax=False,
        )

    raw = str(entry)
    protocol = "tcp"
    core = raw
    if "/" in raw:
        core, _, protocol = raw.rpartition("/")

    host_ip: str | None = None
    published: str | int | None = None
    target: int | None = None
    ambiguous = False

    # IPv6 in brackets: [2001:db8::1]:80:80
    if core.startswith("["):
        end = core.find("]")
        if end != -1:
            host_ip = core[1:end]
            rest = core[end + 1 :]
            if rest.startswith(":"):
                rest = rest[1:]
            parts = rest.split(":")
            if len(parts) == 2:
                published, target_s = parts
                target = int(target_s) if target_s.isdigit() else None
            elif len(parts) == 1 and parts[0].isdigit():
                target = int(parts[0])
            else:
                ambiguous = True
        else:
            ambiguous = True
    else:
        parts = core.split(":")
        if len(parts) == 1:
            if parts[0].isdigit():
                target = int(parts[0])
            else:
                ambiguous = True
        elif len(parts) == 2:
            # host:container OR ip:container (ambiguous without context)
            left, right = parts
            if right.isdigit():
                target = int(right)
                published = left
                # If left looks like IPv4, treat as host_ip with same published?
                if left.count(".") == 3:
                    host_ip = left
                    published = left  # published unspecified — container port only on that IP? Actually ip:container means publish container on that IP with same port
                    published = right
                ambiguous = left.isdigit()  # port:port is clear; name:port ambiguous
            else:
                ambiguous = True
        elif len(parts) == 3:
            host_ip, published_s, target_s = parts
            published = published_s
            target = int(target_s) if target_s.isdigit() else None
        else:
            ambiguous = True

    return PortBinding(
        raw=raw,
        target=target,
        published=published,
        host_ip=host_ip,
        protocol=protocol,
        short_syntax=True,
        ambiguous=ambiguous,
    )


def parse_volume(entry: Any) -> VolumeMount:
    if isinstance(entry, dict):
        return VolumeMount(
            raw=entry,
            type=str(entry["type"]) if "type" in entry else None,
            source=str(entry["source"]) if entry.get("source") is not None else None,
            target=str(entry["target"]) if entry.get("target") is not None else None,
            read_only=bool(entry["read_only"]) if "read_only" in entry else None,
            short_syntax=False,
        )

    raw = str(entry)
    # tmpfs short? uncommon — treat as short volume
    parts = raw.split(":")
    if len(parts) == 1:
        return VolumeMount(
            raw=raw,
            type="volume",
            source=None,
            target=parts[0],
            short_syntax=True,
            ambiguous=True,
        )
    if len(parts) == 2:
        source, target = parts
        return VolumeMount(
            raw=raw,
            type="bind"
            if ("/" in source or "\\" in source or source.startswith("."))
            else "volume",
            source=source,
            target=target,
            read_only=None,
            short_syntax=True,
            ambiguous=True,
        )
    if len(parts) >= 3:
        source = parts[0]
        target = parts[1]
        mode = parts[2]
        read_only = "ro" in mode.split(",")
        # Windows drive letters: C:\path:/container — already split wrong; mark ambiguous
        ambiguous = len(parts) > 3
        vol_type = (
            "bind" if ("/" in source or "\\" in source or source.startswith(".")) else "volume"
        )
        return VolumeMount(
            raw=raw,
            type=vol_type,
            source=source,
            target=target,
            read_only=read_only,
            short_syntax=True,
            ambiguous=ambiguous,
        )
    return VolumeMount(raw=raw, short_syntax=True, ambiguous=True)


def parse_build(value: Any) -> BuildConfig | None:
    if value is None:
        return None
    if isinstance(value, str):
        return BuildConfig(context=value, raw=value)
    if isinstance(value, dict):
        args_raw = value.get("args") or {}
        args: dict[str, str | None] = {}
        if isinstance(args_raw, dict):
            args = {str(k): (None if v is None else str(v)) for k, v in args_raw.items()}
        elif isinstance(args_raw, list):
            for item in args_raw:
                if isinstance(item, str) and "=" in item:
                    k, _, v = item.partition("=")
                    args[k] = v
                elif isinstance(item, str):
                    args[item] = None
        return BuildConfig(
            context=str(value["context"]) if value.get("context") is not None else None,
            dockerfile=str(value["dockerfile"]) if value.get("dockerfile") is not None else None,
            args=args,
            target=str(value["target"]) if value.get("target") is not None else None,
            network=str(value["network"]) if value.get("network") is not None else None,
            privileged=bool(value["privileged"]) if "privileged" in value else None,
            ssh=value.get("ssh"),
            secrets=_as_list(value.get("secrets")),
            raw=value,
        )
    return BuildConfig(raw=value)


def _parse_sysctls(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    result: dict[str, Any] = {}
    for item in _as_list(value):
        if isinstance(item, str) and "=" in item:
            k, _, v = item.partition("=")
            result[k] = v
        elif isinstance(item, str):
            result[item] = None
    return result


def normalize_service(name: str, raw: dict[str, Any]) -> ServiceModel:
    networks_raw = raw.get("networks")
    networks: list[str] = []
    if isinstance(networks_raw, dict):
        networks = [str(k) for k in networks_raw]
    elif isinstance(networks_raw, list):
        networks = [str(x) for x in networks_raw]

    return ServiceModel(
        name=name,
        raw=raw,
        image=str(raw["image"]) if raw.get("image") is not None else None,
        build=parse_build(raw.get("build")),
        privileged=bool(raw.get("privileged", False)),
        user=str(raw["user"]) if raw.get("user") is not None else None,
        working_dir=str(raw["working_dir"]) if raw.get("working_dir") is not None else None,
        read_only=bool(raw.get("read_only", False)),
        network_mode=str(raw["network_mode"]) if raw.get("network_mode") is not None else None,
        pid=str(raw["pid"]) if raw.get("pid") is not None else None,
        ipc=str(raw["ipc"]) if raw.get("ipc") is not None else None,
        userns_mode=str(raw["userns_mode"]) if raw.get("userns_mode") is not None else None,
        cap_add=_as_str_list(raw.get("cap_add")),
        cap_drop=_as_str_list(raw.get("cap_drop")),
        security_opt=_as_str_list(raw.get("security_opt")),
        devices=_as_list(raw.get("devices")),
        device_cgroup_rules=_as_str_list(raw.get("device_cgroup_rules")),
        volumes=[parse_volume(v) for v in _as_list(raw.get("volumes"))],
        volumes_from=_as_list(raw.get("volumes_from")),
        ports=[parse_port(p) for p in _as_list(raw.get("ports"))],
        expose=_as_list(raw.get("expose")),
        environment=parse_environment(raw.get("environment")),
        env_file=_as_str_list(raw.get("env_file")),
        secrets=_as_list(raw.get("secrets")),
        configs=_as_list(raw.get("configs")),
        networks=networks,
        labels=parse_labels(raw.get("labels")),
        command=raw.get("command"),
        entrypoint=raw.get("entrypoint"),
        healthcheck=raw.get("healthcheck")
        if isinstance(raw.get("healthcheck"), dict)
        else ({"disable": True} if raw.get("healthcheck") is False else None),
        logging=raw.get("logging") if isinstance(raw.get("logging"), dict) else None,
        deploy=raw.get("deploy") if isinstance(raw.get("deploy"), dict) else None,
        mem_limit=raw.get("mem_limit") or raw.get("memory"),
        cpus=raw.get("cpus") or raw.get("cpu_count"),
        pids_limit=raw.get("pids_limit"),
        restart=str(raw["restart"]) if raw.get("restart") is not None else None,
        stop_grace_period=str(raw["stop_grace_period"])
        if raw.get("stop_grace_period") is not None
        else None,
        depends_on=raw.get("depends_on"),
        sysctls=_parse_sysctls(raw.get("sysctls")),
        tmpfs=_as_str_list(raw.get("tmpfs")),
        extra_hosts=_as_str_list(raw.get("extra_hosts")),
        dns=_as_str_list(raw.get("dns")),
        mac_address=str(raw["mac_address"]) if raw.get("mac_address") is not None else None,
        group_add=_as_list(raw.get("group_add")),
        links=_as_str_list(raw.get("links")),
        external_links=_as_str_list(raw.get("external_links")),
        extends=raw.get("extends"),
        init=bool(raw["init"]) if "init" in raw else None,
    )


def normalize_compose(data: dict[str, Any]) -> ComposeModel:
    """Build a normalized ComposeModel from raw parsed data."""
    services_raw = data.get("services") or {}
    services: dict[str, ServiceModel] = {}
    if isinstance(services_raw, dict):
        for name, svc in services_raw.items():
            if isinstance(svc, dict):
                services[str(name)] = normalize_service(str(name), svc)

    extensions = {k: v for k, v in data.items() if k.startswith("x-")}

    return ComposeModel(
        services=services,
        networks=dict(data["networks"]) if isinstance(data.get("networks"), dict) else {},
        volumes=dict(data["volumes"]) if isinstance(data.get("volumes"), dict) else {},
        secrets=dict(data["secrets"]) if isinstance(data.get("secrets"), dict) else {},
        configs=dict(data["configs"]) if isinstance(data.get("configs"), dict) else {},
        include=data.get("include"),
        name=str(data["name"]) if data.get("name") is not None else None,
        raw=data,
        extension_fields=extensions,
    )


def deploy_resources(service: ServiceModel) -> dict[str, Any]:
    """Extract deploy.resources limits if present."""
    if not service.deploy or not isinstance(service.deploy, dict):
        return {}
    resources = service.deploy.get("resources")
    if not isinstance(resources, dict):
        return {}
    limits = resources.get("limits")
    return limits if isinstance(limits, dict) else {}


__all__ = [
    "BuildConfig",
    "ComposeModel",
    "PortBinding",
    "ServiceModel",
    "VolumeMount",
    "deploy_resources",
    "normalize_compose",
    "normalize_service",
    "parse_build",
    "parse_environment",
    "parse_labels",
    "parse_port",
    "parse_volume",
]
