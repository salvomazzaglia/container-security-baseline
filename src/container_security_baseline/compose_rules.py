"""Compose rule check implementations."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from container_security_baseline.compose_loader import ComposeDocument
from container_security_baseline.compose_model import (
    ComposeModel,
    ServiceModel,
    deploy_resources,
    normalize_compose,
)
from container_security_baseline.findings import fail, not_applicable, unavailable
from container_security_baseline.interpolation import detect_interpolations, is_interpolation_only
from container_security_baseline.models import Finding, RuleDefinition
from container_security_baseline.paths import is_absolute_host_path, looks_like_traversal
from container_security_baseline.redaction import REDACTED, redact_command_fragment
from container_security_baseline.secret_detection import (
    inspect_key_value,
    inspect_text_for_secrets,
    is_secret_like_key,
    looks_like_secret_filename,
)
from container_security_baseline.severities import Severity

CheckContext = dict[str, Any]
CheckFn = Callable[[RuleDefinition, CheckContext], list[Finding]]

_SOCKET_RE = re.compile(
    r"(?i)(docker\.sock|podman\.sock|/var/run/docker\.sock|/run/docker\.sock|"
    r"/run/user/\d+/docker\.sock|/run/user/\d+/podman/podman\.sock)"
)
_ROOT_BIND_RE = re.compile(r"^(?:/|[A-Za-z]:[\\/]?)$")
_SYSCTL_ALLOW = frozenset(
    {
        "net.core.somaxconn",
        "net.ipv4.tcp_keepalive_time",
        "net.ipv4.ip_local_port_range",
    }
)
_UNSAFE_SYSCTL_PREFIXES = ("kernel.", "fs.protected", "net.ipv4.conf.all.forwarding")


def _sev(rule: RuleDefinition, ctx: CheckContext) -> Severity:
    policy = ctx.get("policy") or {}
    profile = str(policy.get("name", "baseline"))
    overrides = policy.get("severity_overrides") or {}
    if rule.id in overrides:
        return Severity.from_string(str(overrides[rule.id]))
    return rule.severity_for_profile(profile)


def _file(ctx: CheckContext) -> str:
    return str(ctx.get("display_path") or "")


def _sensitive_paths(ctx: CheckContext) -> list[str]:
    cfg = ctx.get("config") or {}
    return [str(p) for p in (cfg.get("sensitive_host_paths") or [])]


def _dangerous_caps(ctx: CheckContext) -> dict[str, list[str]]:
    cfg = ctx.get("config") or {}
    raw = cfg.get("dangerous_capabilities") or {}
    return {str(k): [str(x) for x in v] for k, v in raw.items()}


def _sensitive_ports(ctx: CheckContext) -> set[int]:
    cfg = ctx.get("config") or {}
    return {int(p) for p in (cfg.get("sensitive_ports") or [])}


def _norm_cap(cap: str) -> str:
    c = cap.upper().removeprefix("CAP_")
    return c


def _is_root_user(user: str | None) -> bool:
    if user is None:
        return False
    u = user.strip().strip("\"'")
    if u.lower() == "root":
        return True
    if u in {"0", "0:0"}:
        return True
    return bool(re.fullmatch(r"0(?::\d+)?", u))


def _volume_source(vol_source: str | None) -> str:
    return (vol_source or "").replace("\\", "/")


def _is_sensitive_source(source: str, sensitive: list[str]) -> bool:
    src = _volume_source(source).rstrip("/")
    if not src:
        return False
    for path in sensitive:
        p = path.rstrip("/")
        if src == p or src.startswith(p + "/"):
            return True
    return False


def _has_nnp(security_opt: list[str]) -> bool:
    for opt in security_opt:
        normalized = opt.lower().replace(" ", "")
        if normalized in {
            "no-new-privileges:true",
            "no-new-privileges=true",
            "no-new-privileges",
        }:
            return True
    return False


def _image_parts(image: str) -> tuple[str, str | None, bool]:
    """Return (name, tag_or_none, has_digest)."""
    if "@sha256:" in image or "@sha512:" in image:
        name = image.split("@", 1)[0]
        tag = None
        if ":" in name.rsplit("/", 1)[-1]:
            # registry.com/foo:tag@sha256
            pass
        return image, None, True
    # strip credentials for analysis later
    ref = image
    if "://" in ref:
        ref = ref.split("://", 1)[-1]
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[-1]
        return ref, tag, False
    return ref, None, False


def check_001(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.privileged:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.privileged=true",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.privileged",
                )
            )
    return out


def check_002(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            source = _volume_source(vol.source)
            if source and _SOCKET_RE.search(source):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name} mounts a path matching a runtime socket pattern"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_003(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            source = _volume_source(vol.source)
            if not source:
                continue
            if _ROOT_BIND_RE.match(source) or source in {"/", "C:/", "C:\\", "c:/", "c:\\"}:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} bind-mounts host root",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_004(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    sensitive = _sensitive_paths(ctx)
    for svc in model.services.values():
        for vol in svc.volumes:
            source = vol.source
            if not source or not _is_sensitive_source(source, sensitive):
                continue
            if vol.read_only is True:
                continue
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"services.{svc.name} mounts sensitive path read-write "
                        f"(target={vol.target or 'unknown'})"
                    ),
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.volumes",
                )
            )
    return out


def check_005(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    sensitive = _sensitive_paths(ctx)
    for svc in model.services.values():
        for vol in svc.volumes:
            if not vol.source or not _is_sensitive_source(vol.source, sensitive):
                continue
            if vol.read_only is True:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name} mounts sensitive path read-only "
                            f"(target={vol.target or 'unknown'})"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_006(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _namespace_host(rule, ctx, "network_mode")


def check_007(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _namespace_host(rule, ctx, "pid")


def check_008(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _namespace_host(rule, ctx, "ipc")


def check_009(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.userns_mode and str(svc.userns_mode).lower() == "host":
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.userns_mode=host",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.userns_mode",
                )
            )
    return out


def _namespace_host(rule: RuleDefinition, ctx: CheckContext, field: str) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        value = getattr(svc, field, None)
        if value is not None and str(value).lower() == "host":
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.{field}=host",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.{field}",
                )
            )
    return out


def check_010(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.devices:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.devices present ({len(svc.devices)} entries)",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.devices",
                )
            )
    return out


def check_011(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for rule_s in svc.device_cgroup_rules:
            if "a *:* rwm" in rule_s.replace(" ", "") or "*:*" in rule_s:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} has broad device_cgroup_rules",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.device_cgroup_rules",
                    )
                )
    return out


def check_012(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.volumes_from:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.volumes_from is set",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.volumes_from",
                )
            )
    return out


def check_013(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.links or svc.external_links:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} uses links/external_links",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.links",
                )
            )
    return out


def check_020(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        caps = {_norm_cap(c) for c in svc.cap_add}
        if "ALL" in caps:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.cap_add includes ALL",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.cap_add",
                )
            )
    return out


def check_021(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    dangerous = _dangerous_caps(ctx)
    flat: dict[str, str] = {}
    for sev_name, caps in dangerous.items():
        for cap in caps:
            flat[_norm_cap(cap)] = sev_name
    for svc in model.services.values():
        for cap in svc.cap_add:
            nc = _norm_cap(cap)
            if nc == "ALL":
                continue
            if nc in flat:
                sev = Severity.from_string(flat[nc])
                # Use max of rule default and capability severity
                chosen = sev if sev.rank >= _sev(rule, ctx).rank else _sev(rule, ctx)
                out.append(
                    fail(
                        rule,
                        severity=chosen,
                        evidence_redacted=f"services.{svc.name}.cap_add includes {nc}",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.cap_add",
                    )
                )
    return out


def check_022(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not svc.cap_drop:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.cap_drop is missing",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.cap_drop",
                )
            )
    return out


def check_023(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.cap_drop and "ALL" not in {_norm_cap(c) for c in svc.cap_drop}:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.cap_drop does not include ALL",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.cap_drop",
                )
            )
    return out


def check_024(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for opt in svc.security_opt:
            if "seccomp" in opt.lower() and "unconfined" in opt.lower():
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} disables seccomp",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.security_opt",
                    )
                )
    return out


def check_025(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for opt in svc.security_opt:
            low = opt.lower()
            if "apparmor" in low and "unconfined" in low:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} sets AppArmor unconfined",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.security_opt",
                    )
                )
    return out


def check_026(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not _has_nnp(svc.security_opt):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} missing no-new-privileges",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.security_opt",
                )
            )
    return out


def check_027(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            src = _volume_source(vol.source)
            tgt = (vol.target or "").replace("\\", "/")
            if (src.startswith("/proc") or src.startswith("/sys") or tgt in {"/proc", "/sys"}) and (
                vol.read_only is not True
            ):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} has writable proc/sys related mount",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
        for key in svc.sysctls:
            if any(key.startswith(p) for p in _UNSAFE_SYSCTL_PREFIXES):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} sets potentially unsafe sysctl {key}",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.sysctls",
                    )
                )
    return out


def check_028(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for key in svc.sysctls:
            if key not in _SYSCTL_ALLOW and not any(
                key.startswith(p) for p in _UNSAFE_SYSCTL_PREFIXES
            ):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} sysctl {key} outside allowlist",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.sysctls",
                    )
                )
    return out


def check_030(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.user is None:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.user is not set",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.user",
                )
            )
    return out


def check_031(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if _is_root_user(svc.user):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.user is root/UID 0",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.user",
                )
            )
    return out


def check_032(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    privileged_groups = {"docker", "root", "wheel", "0"}
    for svc in model.services.values():
        for g in svc.group_add:
            if str(g).lower() in privileged_groups:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name}.group_add includes privileged group label",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.group_add",
                    )
                )
    return out


def check_033(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    cred_markers = ("/.ssh", "/.aws", "/.azure", "/.kube", "/home", "/root")
    for svc in model.services.values():
        is_root = svc.user is None or _is_root_user(svc.user)
        if not is_root:
            continue
        for vol in svc.volumes:
            src = _volume_source(vol.source)
            if any(m in src for m in cred_markers) and vol.read_only is not True:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name} root-like user with writable credential/home mount"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_040(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not svc.read_only:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.read_only is not true",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.read_only",
                )
            )
    return out


def check_041(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    # Similar to 040 but advisory wording already in rule — flag when writable
    return check_040(rule, ctx)


def check_042(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.read_only and not svc.tmpfs:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"services.{svc.name} is read_only without tmpfs; "
                        "confirm writable paths are covered"
                    ),
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.tmpfs",
                )
            )
    return out


def check_043(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            if vol.source and looks_like_traversal(vol.source):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} volume source uses parent traversal",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_044(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            if vol.source and is_absolute_host_path(vol.source) and vol.type in {None, "bind"}:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} uses absolute host bind path",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_045(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    project_root = str(ctx.get("project_root") or "").replace("\\", "/").lower()
    for svc in model.services.values():
        for vol in svc.volumes:
            src = vol.source
            if not src or not is_absolute_host_path(src):
                continue
            if looks_like_traversal(src):
                continue
            src_n = src.replace("\\", "/").lower()
            if project_root and not src_n.startswith(project_root):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} bind source appears outside project root",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_046(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            if vol.short_syntax and vol.ambiguous:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} uses ambiguous short volume syntax",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_047(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            if vol.read_only is None and vol.source:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} volume missing explicit read_only/mode",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_050(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    patterns = (ctx.get("config") or {}).get("secret_key_patterns")
    for svc in model.services.values():
        for key, value in svc.environment.items():
            hits = inspect_key_value(key, value, patterns=patterns)
            for hit in hits:
                if hit.kind == "secret_key_literal":
                    out.append(
                        fail(
                            rule,
                            severity=_sev(rule, ctx),
                            evidence_redacted=(
                                f"services.{svc.name}.environment.{key}={REDACTED} "
                                f"(fingerprint={hit.fingerprint})"
                            ),
                            file=_file(ctx),
                            service=svc.name,
                            property_path=f"services.{svc.name}.environment.{key}",
                        )
                    )
    return out


def check_051(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for key, value in svc.environment.items():
            if value is None or is_secret_like_key(key):
                continue
            hits = inspect_key_value(key, value)
            for hit in hits:
                if hit.kind == "high_entropy_or_token":
                    out.append(
                        fail(
                            rule,
                            severity=_sev(rule, ctx),
                            evidence_redacted=(
                                f"services.{svc.name}.environment.{key}={REDACTED} "
                                f"(fingerprint={hit.fingerprint})"
                            ),
                            file=_file(ctx),
                            service=svc.name,
                            property_path=f"services.{svc.name}.environment.{key}",
                        )
                    )
    return out


def _stringify_cmd(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(str(x) for x in value)
    return str(value)


def check_052(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for field, value in (("command", svc.command), ("entrypoint", svc.entrypoint)):
            text = _stringify_cmd(value)
            if not text:
                continue
            hits = inspect_text_for_secrets(text, field_name=field)
            if hits or any(
                is_secret_like_key(tok) for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
            ):
                # Only fail on actual secret-like content
                if hits or re.search(r"(?i)(password|secret|token|api_key)\s*=\s*\S+", text):
                    out.append(
                        fail(
                            rule,
                            severity=_sev(rule, ctx),
                            evidence_redacted=(
                                f"services.{svc.name}.{field} contains secret-like material: "
                                f"{redact_command_fragment(text)[:120]}"
                            ),
                            file=_file(ctx),
                            service=svc.name,
                            property_path=f"services.{svc.name}.{field}",
                        )
                    )
    return out


def check_053(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for key, value in svc.labels.items():
            hits = inspect_key_value(key, value)
            if hits:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name}.labels.{key}={REDACTED} "
                            f"(fingerprint={hits[0].fingerprint})"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.labels.{key}",
                    )
                )
    return out


def check_054(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not svc.build:
            continue
        for key, value in svc.build.args.items():
            hits = inspect_key_value(key, value)
            if hits or is_secret_like_key(key):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name}.build.args.{key} is secret-like "
                            f"(value={REDACTED})"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.build.args.{key}",
                    )
                )
    return out


def check_055(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.env_file:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"services.{svc.name}.env_file referenced "
                        f"({len(svc.env_file)} entries); contents not read"
                    ),
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.env_file",
                )
            )
    return out


def check_056(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for vol in svc.volumes:
            if vol.source and looks_like_secret_filename(vol.source):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name} mounts secret-like path as a volume "
                            "(prefer Compose secrets)"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.volumes",
                    )
                )
    return out


def check_057(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    used: set[str] = set()
    for svc in model.services.values():
        for sec in svc.secrets:
            if isinstance(sec, str):
                used.add(sec)
            elif isinstance(sec, dict) and "source" in sec:
                used.add(str(sec["source"]))
    for name in model.secrets:
        if name not in used:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"secrets.{name} declared but not granted to any service",
                    file=_file(ctx),
                    property_path=f"secrets.{name}",
                )
            )
    return out


def check_058(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    policy = ctx.get("policy") or {}
    expectations = policy.get("service_secret_expectations") or {}
    if not expectations:
        return [
            not_applicable(
                rule,
                file=_file(ctx),
                reason="No service_secret_expectations declared in policy",
            )
        ]
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc_name, expected in expectations.items():
        svc = model.services.get(str(svc_name))
        if not svc:
            continue
        granted: set[str] = set()
        for sec in svc.secrets:
            if isinstance(sec, str):
                granted.add(sec)
            elif isinstance(sec, dict) and "source" in sec:
                granted.add(str(sec["source"]))
        expected_set = {str(x) for x in expected}
        if granted != expected_set:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc_name} secrets differ from policy expectations",
                    file=_file(ctx),
                    service=svc_name,
                    property_path=f"services.{svc_name}.secrets",
                )
            )
    return out


def check_059(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for name, spec in model.secrets.items():
        if not isinstance(spec, dict):
            continue
        fpath = spec.get("file")
        if not isinstance(fpath, str):
            continue
        if is_absolute_host_path(fpath) or looks_like_traversal(fpath):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"secrets.{name}.file path is absolute or traversing",
                    file=_file(ctx),
                    property_path=f"secrets.{name}.file",
                )
            )
    return out


def check_060(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    doc: ComposeDocument = ctx["document"]
    # Scan environment values and raw text for insecure defaults
    for svc in model.services.values():
        for key, value in svc.environment.items():
            if value is None:
                continue
            for match in detect_interpolations(value):
                if match.secret_like_default:
                    out.append(
                        fail(
                            rule,
                            severity=_sev(rule, ctx),
                            evidence_redacted=(
                                f"services.{svc.name}.environment.{key} has secret-like "
                                f"interpolation default for ${{{match.variable}}} (value={REDACTED})"
                            ),
                            file=_file(ctx),
                            service=svc.name,
                            property_path=f"services.{svc.name}.environment.{key}",
                        )
                    )
    for match in detect_interpolations(doc.original_text):
        if match.secret_like_default and match.kind == "default":
            # Avoid flooding — only if not already covered heavily
            pass
    return out


def check_070(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for port in svc.ports:
            host_ip = (port.host_ip or "").strip()
            # Short syntax without host_ip typically binds all interfaces
            wildcard = host_ip in {"", "0.0.0.0", "::", "*"}
            if wildcard and port.published is not None:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name} publishes port on wildcard/all interfaces "
                            f"(target={port.target})"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.ports",
                    )
                )
    return out


def check_071(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    sensitive = _sensitive_ports(ctx)
    for svc in model.services.values():
        for port in svc.ports:
            candidates = []
            if port.target is not None:
                candidates.append(port.target)
            if isinstance(port.published, int):
                candidates.append(port.published)
            elif isinstance(port.published, str) and port.published.isdigit():
                candidates.append(int(port.published))
            if any(c in sensitive for c in candidates):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            f"services.{svc.name} publishes sensitive port (target={port.target})"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.ports",
                    )
                )
    return out


def check_072(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if str(svc.network_mode or "").lower() != "host":
            continue
        if svc.ports or svc.privileged or "ALL" in {_norm_cap(c) for c in svc.cap_add}:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"services.{svc.name} combines host networking with ports/privileges"
                    ),
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.network_mode",
                )
            )
    return out


def check_073(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    policy = ctx.get("policy") or {}
    backends = [str(x) for x in (policy.get("backend_networks") or [])]
    if not backends:
        return [
            not_applicable(
                rule,
                file=_file(ctx),
                reason="No backend_networks declared in policy",
            )
        ]
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for name in backends:
        net = model.networks.get(name)
        if isinstance(net, dict) and not net.get("internal"):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"networks.{name}.internal is not true",
                    file=_file(ctx),
                    property_path=f"networks.{name}.internal",
                )
            )
    return out


def check_074(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    policy = ctx.get("policy") or {}
    if not policy.get("service_secret_expectations") and not policy.get("backend_networks"):
        # Only when explicit expectations — use network attachment policy if present
        return [
            not_applicable(
                rule,
                file=_file(ctx),
                reason="No explicit network attachment expectations in policy",
            )
        ]
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    all_nets = set(model.networks)
    if len(all_nets) < 2:
        return out
    for svc in model.services.values():
        if set(svc.networks) == all_nets and all_nets:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} attached to every declared network",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.networks",
                )
            )
    return out


def check_075(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for host in svc.extra_hosts:
            if "host-gateway" in host:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name}.extra_hosts maps host-gateway",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.extra_hosts",
                    )
                )
    return out


def check_076(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    public_dns = {"8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9"}
    for svc in model.services.values():
        if any(d in public_dns for d in svc.dns):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} uses public DNS servers",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.dns",
                )
            )
    return out


def check_077(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.mac_address:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.mac_address is statically set",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.mac_address",
                )
            )
    return out


def _has_memory_limit(svc: ServiceModel) -> bool:
    if svc.mem_limit is not None:
        return True
    limits = deploy_resources(svc)
    return "memory" in limits


def _has_cpu_limit(svc: ServiceModel) -> bool:
    if svc.cpus is not None:
        return True
    limits = deploy_resources(svc)
    return "cpus" in limits or "cpu" in limits


def _has_pid_limit(svc: ServiceModel) -> bool:
    if svc.pids_limit is not None:
        return True
    limits = deploy_resources(svc)
    return "pids" in limits


def check_080(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not _has_memory_limit(svc):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} has no memory limit",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.mem_limit",
                )
            )
    return out


def check_081(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not _has_cpu_limit(svc):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} has no CPU limit",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.cpus",
                )
            )
    return out


def check_082(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not _has_pid_limit(svc):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} has no PID limit",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.pids_limit",
                )
            )
    return out


def check_083(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.pids_limit in {0, -1, "0", "-1", "unlimited"}:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.pids_limit is unlimited/disabled",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.pids_limit",
                )
            )
    return out


def check_084(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        limits = deploy_resources(svc)
        if svc.mem_limit is not None and "memory" in limits:
            if str(svc.mem_limit) != str(limits.get("memory")):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name} memory limits inconsistent",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.mem_limit",
                    )
                )
    return out


def check_085(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        # Skip one-shot restart policies as short-lived heuristic
        if svc.restart in {"no", "on-failure"} and svc.command:
            # still check — policy decides severity
            pass
        if svc.healthcheck is None:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name} has no healthcheck",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.healthcheck",
                )
            )
    return out


def check_086(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        hc = svc.healthcheck
        if isinstance(hc, dict) and (
            hc.get("disable") is True or str(hc.get("test", "")).upper() == "NONE"
        ):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.healthcheck is disabled",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.healthcheck",
                )
            )
    return out


def check_087(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        hc = svc.healthcheck
        if not isinstance(hc, dict):
            continue
        test = hc.get("test")
        text = _stringify_cmd(test)
        if inspect_text_for_secrets(text) or re.search(r"(?i)(password|secret|token)=", text):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"services.{svc.name}.healthcheck appears to include secrets: "
                        f"{redact_command_fragment(text)[:120]}"
                    ),
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.healthcheck",
                )
            )
    return out


def check_088(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        deps = svc.depends_on
        if not isinstance(deps, dict):
            continue
        for dep_name, spec in deps.items():
            cond = None
            if isinstance(spec, dict):
                cond = spec.get("condition")
            if cond == "service_started":
                dep = model.services.get(str(dep_name))
                if dep and dep.healthcheck:
                    out.append(
                        fail(
                            rule,
                            severity=_sev(rule, ctx),
                            evidence_redacted=(
                                f"services.{svc.name} depends on {dep_name} with "
                                "service_started while dependency defines healthcheck"
                            ),
                            file=_file(ctx),
                            service=svc.name,
                            property_path=f"services.{svc.name}.depends_on",
                        )
                    )
    return out


def check_089(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.restart is None:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.restart is absent",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.restart",
                )
            )
    return out


def check_090(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.restart in {"always", "unless-stopped"}:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.restart={svc.restart} may be unbounded",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.restart",
                )
            )
    return out


def check_091(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    policy = ctx.get("policy") or {}
    stateful = {str(x) for x in (policy.get("stateful_services") or [])}
    if not stateful:
        return [
            not_applicable(
                rule,
                file=_file(ctx),
                reason="No stateful_services declared in policy",
            )
        ]
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for name in stateful:
        svc = model.services.get(name)
        if svc and svc.stop_grace_period is None:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{name}.stop_grace_period missing for stateful service",
                    file=_file(ctx),
                    service=name,
                    property_path=f"services.{name}.stop_grace_period",
                )
            )
    return out


def check_100(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.logging is None:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.logging absent",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.logging",
                )
            )
    return out


def check_101(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _json_file_option(rule, ctx, "max-size")


def check_102(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _json_file_option(rule, ctx, "max-file")


def _json_file_option(rule: RuleDefinition, ctx: CheckContext, option: str) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        logging = svc.logging
        if not isinstance(logging, dict):
            continue
        driver = str(logging.get("driver", "json-file"))
        if driver != "json-file":
            continue
        options = logging.get("options") or {}
        if not isinstance(options, dict) or option not in options:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.logging missing {option}",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.logging.options",
                )
            )
    return out


def check_103(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        logging = svc.logging
        if isinstance(logging, dict) and str(logging.get("driver", "")).lower() in {
            "none",
            "null",
        }:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.logging driver disabled",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.logging",
                )
            )
    return out


def check_104(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    remote_drivers = {"syslog", "fluentd", "gelf", "awslogs", "gcplogs", "splunk"}
    for svc in model.services.values():
        logging = svc.logging
        if isinstance(logging, dict):
            driver = str(logging.get("driver", "")).lower()
            if driver in remote_drivers:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name}.logging driver appears remote ({driver})",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.logging",
                    )
                )
    return out


def check_110(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not svc.image:
            continue
        if is_interpolation_only(svc.image):
            continue
        _, tag, has_digest = _image_parts(svc.image)
        if not has_digest and tag == "latest":
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.image uses latest tag",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.image",
                )
            )
    return out


def check_111(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not svc.image:
            continue
        if is_interpolation_only(svc.image):
            continue
        _, tag, has_digest = _image_parts(svc.image)
        if not has_digest and tag is None:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.image has no explicit tag",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.image",
                )
            )
    return out


def check_112(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not svc.image:
            continue
        if is_interpolation_only(svc.image):
            continue
        _, _, has_digest = _image_parts(svc.image)
        if not has_digest:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.image is not digest-pinned",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.image",
                )
            )
    return out


def check_113(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.image and re.match(r"(?i)^https?://", svc.image) is None:
            # Detect http://registry/...
            if svc.image.lower().startswith("http://"):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name}.image uses HTTP registry URL",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.image",
                    )
                )
        elif svc.image and svc.image.lower().startswith("http://"):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.image uses HTTP registry URL",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.image",
                )
            )
    return out


def check_114(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    cred_re = re.compile(r"(?i)^(?:https?://)?[^/\s]+:[^/\s]+@")
    for svc in model.services.values():
        if svc.image and cred_re.search(svc.image):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"services.{svc.name}.image contains embedded credentials ({REDACTED})"
                    ),
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.image",
                )
            )
    return out


def check_115(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.image and is_interpolation_only(svc.image):
            out.append(
                unavailable(
                    rule,
                    file=_file(ctx),
                    reason=(
                        f"services.{svc.name}.image is interpolation-only and cannot be evaluated"
                    ),
                    service=svc.name,
                )
            )
    return out


def check_120(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.build and svc.build.context in {".", "./", ""}:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.build.context is broad (.)",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.build.context",
                )
            )
    return out


def check_121(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.build and svc.build.context and looks_like_traversal(svc.build.context):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.build.context uses parent traversal",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.build.context",
                )
            )
    return out


def check_122(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.build and svc.build.context and is_absolute_host_path(svc.build.context):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.build.context is absolute",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.build.context",
                )
            )
    return out


def check_123(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.build and svc.build.dockerfile and looks_like_traversal(svc.build.dockerfile):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.build.dockerfile escapes context",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.build.dockerfile",
                )
            )
    return out


def check_124(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return check_054(rule, ctx)


def check_125(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.build and svc.build.privileged:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.build.privileged is true",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.build.privileged",
                )
            )
    return out


def check_126(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if svc.build and svc.build.ssh:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.build.ssh is configured",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.build.ssh",
                )
            )
    return out


def check_127(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if not svc.build:
            continue
        secret_args = [k for k in svc.build.args if is_secret_like_key(k)]
        if secret_args and not svc.build.secrets:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"services.{svc.name} has secret-like build args without build secrets"
                    ),
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.build",
                )
            )
    return out


def check_130(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    model: ComposeModel = ctx["model"]
    doc: ComposeDocument = ctx["document"]
    if model.include is not None or doc.has_include:
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="Compose include present; referenced files were not followed",
                file=_file(ctx),
                property_path="include",
            )
        ]
    return []


def check_131(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if isinstance(svc.extends, dict) and "file" in svc.extends:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.extends.file present; not read",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.extends.file",
                )
            )
    return out


def check_132(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _outside_ref(rule, ctx, "env_file", lambda s: s.env_file)


def check_133(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for name, spec in model.configs.items():
        if isinstance(spec, dict) and isinstance(spec.get("file"), str):
            fpath = str(spec["file"])
            if is_absolute_host_path(fpath) or looks_like_traversal(fpath):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"configs.{name}.file outside/unsafe path",
                        file=_file(ctx),
                        property_path=f"configs.{name}.file",
                    )
                )
    return out


def check_134(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return check_059(rule, ctx)


def _outside_ref(
    rule: RuleDefinition,
    ctx: CheckContext,
    field: str,
    getter: Callable[[ServiceModel], list[str]],
) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for path in getter(svc):
            if is_absolute_host_path(path) or looks_like_traversal(path):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"services.{svc.name}.{field} path is absolute/traversing",
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.{field}",
                    )
                )
    return out


def check_135(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        if "label_file" in svc.raw:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.label_file present; not read",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.label_file",
                )
            )
    return out


def check_136(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        cred = svc.raw.get("credential_spec")
        if isinstance(cred, dict) and "file" in cred:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"services.{svc.name}.credential_spec.file present; not read",
                    file=_file(ctx),
                    service=svc.name,
                    property_path=f"services.{svc.name}.credential_spec.file",
                )
            )
    return out


def check_137(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    model: ComposeModel = ctx["model"]
    security_ext = ("x-security", "x-privileged", "x-cap", "x-seccomp")
    for key in model.extension_fields:
        if any(key.lower().startswith(s) for s in security_ext):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"Security-related extension field {key} present",
                    file=_file(ctx),
                    property_path=key,
                )
            )
    return out


def check_138(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: ComposeDocument = ctx["document"]
    if doc.anchors_detected or doc.merge_keys_detected:
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="YAML anchors and/or merge keys detected",
                file=_file(ctx),
                property_path="<anchors>",
            )
        ]
    return []


def check_139(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: ComposeDocument = ctx["document"]
    if not (doc.anchors_detected or doc.merge_keys_detected):
        return []
    # If anchors present and secret-like env exists, flag potential propagation
    model: ComposeModel = ctx["model"]
    for svc in model.services.values():
        for key, value in svc.environment.items():
            if is_secret_like_key(key) and value is not None:
                return [
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=(
                            "Anchors present with secret-like environment values "
                            f"(values={REDACTED})"
                        ),
                        file=_file(ctx),
                        service=svc.name,
                        property_path=f"services.{svc.name}.environment",
                    )
                ]
    return []


COMPOSE_CHECKS: dict[str, CheckFn] = {
    "CSB-CMP-001": check_001,
    "CSB-CMP-002": check_002,
    "CSB-CMP-003": check_003,
    "CSB-CMP-004": check_004,
    "CSB-CMP-005": check_005,
    "CSB-CMP-006": check_006,
    "CSB-CMP-007": check_007,
    "CSB-CMP-008": check_008,
    "CSB-CMP-009": check_009,
    "CSB-CMP-010": check_010,
    "CSB-CMP-011": check_011,
    "CSB-CMP-012": check_012,
    "CSB-CMP-013": check_013,
    "CSB-CMP-020": check_020,
    "CSB-CMP-021": check_021,
    "CSB-CMP-022": check_022,
    "CSB-CMP-023": check_023,
    "CSB-CMP-024": check_024,
    "CSB-CMP-025": check_025,
    "CSB-CMP-026": check_026,
    "CSB-CMP-027": check_027,
    "CSB-CMP-028": check_028,
    "CSB-CMP-030": check_030,
    "CSB-CMP-031": check_031,
    "CSB-CMP-032": check_032,
    "CSB-CMP-033": check_033,
    "CSB-CMP-040": check_040,
    "CSB-CMP-041": check_041,
    "CSB-CMP-042": check_042,
    "CSB-CMP-043": check_043,
    "CSB-CMP-044": check_044,
    "CSB-CMP-045": check_045,
    "CSB-CMP-046": check_046,
    "CSB-CMP-047": check_047,
    "CSB-CMP-050": check_050,
    "CSB-CMP-051": check_051,
    "CSB-CMP-052": check_052,
    "CSB-CMP-053": check_053,
    "CSB-CMP-054": check_054,
    "CSB-CMP-055": check_055,
    "CSB-CMP-056": check_056,
    "CSB-CMP-057": check_057,
    "CSB-CMP-058": check_058,
    "CSB-CMP-059": check_059,
    "CSB-CMP-060": check_060,
    "CSB-CMP-070": check_070,
    "CSB-CMP-071": check_071,
    "CSB-CMP-072": check_072,
    "CSB-CMP-073": check_073,
    "CSB-CMP-074": check_074,
    "CSB-CMP-075": check_075,
    "CSB-CMP-076": check_076,
    "CSB-CMP-077": check_077,
    "CSB-CMP-080": check_080,
    "CSB-CMP-081": check_081,
    "CSB-CMP-082": check_082,
    "CSB-CMP-083": check_083,
    "CSB-CMP-084": check_084,
    "CSB-CMP-085": check_085,
    "CSB-CMP-086": check_086,
    "CSB-CMP-087": check_087,
    "CSB-CMP-088": check_088,
    "CSB-CMP-089": check_089,
    "CSB-CMP-090": check_090,
    "CSB-CMP-091": check_091,
    "CSB-CMP-100": check_100,
    "CSB-CMP-101": check_101,
    "CSB-CMP-102": check_102,
    "CSB-CMP-103": check_103,
    "CSB-CMP-104": check_104,
    "CSB-CMP-110": check_110,
    "CSB-CMP-111": check_111,
    "CSB-CMP-112": check_112,
    "CSB-CMP-113": check_113,
    "CSB-CMP-114": check_114,
    "CSB-CMP-115": check_115,
    "CSB-CMP-120": check_120,
    "CSB-CMP-121": check_121,
    "CSB-CMP-122": check_122,
    "CSB-CMP-123": check_123,
    "CSB-CMP-124": check_124,
    "CSB-CMP-125": check_125,
    "CSB-CMP-126": check_126,
    "CSB-CMP-127": check_127,
    "CSB-CMP-130": check_130,
    "CSB-CMP-131": check_131,
    "CSB-CMP-132": check_132,
    "CSB-CMP-133": check_133,
    "CSB-CMP-134": check_134,
    "CSB-CMP-135": check_135,
    "CSB-CMP-136": check_136,
    "CSB-CMP-137": check_137,
    "CSB-CMP-138": check_138,
    "CSB-CMP-139": check_139,
}


def register_all(registry: Any) -> None:
    for rule_id, fn in COMPOSE_CHECKS.items():
        if rule_id in registry.rules:
            registry.register_check(rule_id, fn)


def evaluate_compose_document(
    document: ComposeDocument,
    registry: Any,
    *,
    config: dict[str, Any],
    policy: dict[str, Any],
    project_root: str,
) -> list[Finding]:
    model = normalize_compose(document.data)
    ctx: CheckContext = {
        "document": document,
        "model": model,
        "config": config,
        "policy": policy,
        "project_root": project_root,
        "display_path": document.display_path,
    }
    findings: list[Finding] = []
    from container_security_baseline.policy import rule_enabled

    for rule in registry.list_rules(target="compose"):
        if not rule.enabled or not rule_enabled(policy, rule.id, rule.enabled):
            continue
        fn = registry.checks.get(rule.id)
        if not fn:
            continue
        try:
            findings.extend(fn(rule, ctx))
        except Exception as exc:  # noqa: BLE001 — convert to finding
            from container_security_baseline.findings import error_finding

            findings.append(error_finding(rule, file=document.display_path, error_message=str(exc)))
    return findings


__all__ = [
    "COMPOSE_CHECKS",
    "evaluate_compose_document",
    "normalize_compose",
    "register_all",
]
