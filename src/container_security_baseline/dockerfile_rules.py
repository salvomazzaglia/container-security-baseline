"""Dockerfile rule check implementations."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from container_security_baseline.dockerfile_parser import DockerfileDocument, final_user
from container_security_baseline.findings import error_finding, fail, not_applicable
from container_security_baseline.models import Finding, RuleDefinition
from container_security_baseline.paths import looks_like_traversal
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


def _sev(rule: RuleDefinition, ctx: CheckContext) -> Severity:
    policy = ctx.get("policy") or {}
    profile = str(policy.get("name", "baseline"))
    overrides = policy.get("severity_overrides") or {}
    if rule.id in overrides:
        return Severity.from_string(str(overrides[rule.id]))
    return rule.severity_for_profile(profile)


def _file(ctx: CheckContext) -> str:
    return str(ctx.get("display_path") or "")


def _from_image(image: str | None) -> tuple[str | None, str | None, bool, bool]:
    """name, tag, has_digest, is_scratch."""
    if not image:
        return None, None, False, False
    if image == "scratch":
        return "scratch", None, False, True
    has_digest = "@sha256:" in image or "@sha512:" in image
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    tag = last.rsplit(":", 1)[-1] if ":" in last else None
    return ref, tag, has_digest, False


def check_df_001(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for stage in doc.stages:
        img = stage.from_image
        if not img or img.startswith("$"):
            continue
        _, tag, has_digest, is_scratch = _from_image(img)
        if is_scratch or has_digest:
            continue
        if tag == "latest":
            instr = stage.from_instruction
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"FROM uses latest ({img.split('@')[0]})",
                    file=_file(ctx),
                    stage=stage.name,
                    property_path="FROM",
                    line_start=instr.line_start if instr else None,
                    line_end=instr.line_end if instr else None,
                )
            )
    return out


def check_df_002(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for stage in doc.stages:
        img = stage.from_image
        if not img or img.startswith("$"):
            continue
        _, tag, has_digest, is_scratch = _from_image(img)
        if is_scratch or has_digest:
            continue
        if tag is None:
            instr = stage.from_instruction
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="FROM has no explicit tag",
                    file=_file(ctx),
                    stage=stage.name,
                    property_path="FROM",
                    line_start=instr.line_start if instr else None,
                    line_end=instr.line_end if instr else None,
                )
            )
    return out


def check_df_003(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for stage in doc.stages:
        img = stage.from_image
        if not img or img.startswith("$"):
            continue
        _, _, has_digest, is_scratch = _from_image(img)
        if is_scratch:
            continue
        if not has_digest:
            instr = stage.from_instruction
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="FROM is not digest-pinned",
                    file=_file(ctx),
                    stage=stage.name,
                    property_path="FROM",
                    line_start=instr.line_start if instr else None,
                    line_end=instr.line_end if instr else None,
                )
            )
    return out


def check_df_004(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for stage in doc.stages:
        if stage.from_image == "scratch":
            instr = stage.from_instruction
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="FROM scratch (informational; often desirable)",
                    file=_file(ctx),
                    stage=stage.name,
                    property_path="FROM",
                    line_start=instr.line_start if instr else None,
                    line_end=instr.line_end if instr else None,
                )
            )
    return out


def check_df_005(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for stage in doc.stages:
        img = stage.from_image or ""
        if "${" in img or img.startswith("$"):
            instr = stage.from_instruction
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="FROM uses unresolved ARG/variable",
                    file=_file(ctx),
                    stage=stage.name,
                    property_path="FROM",
                    line_start=instr.line_start if instr else None,
                    line_end=instr.line_end if instr else None,
                )
            )
    return out


def check_df_006(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for stage in doc.stages:
        img = stage.from_image or ""
        if re.search(r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0):\d+", img):
            instr = stage.from_instruction
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="FROM references a local/suspicious registry host",
                    file=_file(ctx),
                    stage=stage.name,
                    property_path="FROM",
                    line_start=instr.line_start if instr else None,
                    line_end=instr.line_end if instr else None,
                )
            )
    return out


def _is_root_user(user: str) -> bool:
    u = user.strip().strip("\"'")
    return u.lower() in {"root", "0", "0:0"} or bool(re.fullmatch(r"0(?::\d+)?", u))


def check_df_010(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    if not doc.final_stage:
        return []
    if final_user(doc) is None:
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="Final stage has no USER instruction",
                file=_file(ctx),
                stage=doc.final_stage.name,
                property_path="USER",
            )
        ]
    return []


def check_df_011(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    user = final_user(doc)
    if user and _is_root_user(user):
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="Final USER is root or UID 0",
                file=_file(ctx),
                stage=doc.final_stage.name if doc.final_stage else None,
                property_path="USER",
            )
        ]
    return []


def check_df_012(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    if not doc.final_stage:
        return []
    users = [
        (i.line_start, i.args_raw.strip()) for i in doc.final_stage.instructions if i.name == "USER"
    ]
    saw_non_root = False
    for line, user in users:
        if not _is_root_user(user):
            saw_non_root = True
        elif saw_non_root and _is_root_user(user):
            return [
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="USER switched back to root in final stage",
                    file=_file(ctx),
                    stage=doc.final_stage.name,
                    property_path="USER",
                    line_start=line,
                    line_end=line,
                )
            ]
    return []


def check_df_013(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    user = final_user(doc)
    if user and re.fullmatch(r"\d+(?::\d+)?", user.strip()) and not _is_root_user(user):
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="Numeric non-root USER without documented ownership considerations",
                file=_file(ctx),
                stage=doc.final_stage.name if doc.final_stage else None,
                property_path="USER",
            )
        ]
    return []


def _parse_env_args(args: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for k, v in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=(\S+)", args):
        result[k] = v
    if not result:
        parts = args.split(None, 1)
        if len(parts) == 2:
            result[parts[0]] = parts[1]
    return result


def check_df_020(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name != "ENV":
            continue
        for key, value in _parse_env_args(instr.args_raw).items():
            if is_secret_like_key(key):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"ENV {key}={REDACTED}",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path=f"ENV.{key}",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
            _ = value
    return out


def check_df_021(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name != "ARG":
            continue
        key = instr.args_raw.split("=", 1)[0].strip()
        if is_secret_like_key(key):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"ARG {key} is secret-like",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path=f"ARG.{key}",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_022(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name not in {"ENV", "ARG", "RUN", "CMD", "ENTRYPOINT"}:
            continue
        text = instr.args_raw
        hits = inspect_text_for_secrets(text)
        for key, value in _parse_env_args(text).items():
            hits.extend(inspect_key_value(key, value))
        if hits:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        f"{instr.name} contains secret-like literal "
                        f"(fingerprint={hits[0].fingerprint}, value={REDACTED})"
                    ),
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path=instr.name,
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_023(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name not in {"COPY", "ADD"}:
            continue
        args = instr.args_raw
        for token in args.split():
            if looks_like_secret_filename(token) or any(
                x in token.lower()
                for x in (".ssh/", "id_rsa", ".env", "credentials", ".pem", ".key")
            ):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"{instr.name} appears to include credential/secret files",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path=instr.name,
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
                break
    return out


def check_df_024(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    has_secret_mount = any(
        "type=secret" in i.args_raw or i.flags.get("mount", "").find("secret") >= 0
        for i in doc.instructions
        if i.name == "RUN"
    )
    for instr in doc.instructions:
        if instr.name != "ARG":
            continue
        key = instr.args_raw.split("=", 1)[0].strip()
        if is_secret_like_key(key) and not has_secret_mount:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"Secret-like ARG {key} without BuildKit secret mount",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path=f"ARG.{key}",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_025(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    introduced = False
    removed = False
    for instr in doc.instructions:
        if instr.name in {"ENV", "ARG"} and any(
            is_secret_like_key(k) for k in _parse_env_args(instr.args_raw)
        ):
            introduced = True
        if (
            introduced
            and instr.name == "RUN"
            and re.search(
                r"(?i)(unset|rm\s+.*secret|sed\s+-i.*(password|secret|token))",
                instr.args_raw,
            )
        ):
            removed = True
    if introduced and removed:
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted=(
                    "Secret-like value appears introduced then removed; "
                    "layer history may still retain it"
                ),
                file=_file(ctx),
                property_path="ENV/ARG/RUN",
            )
        ]
    return []


def check_df_030(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "ADD" and re.search(r"(?i)https?://", instr.args_raw):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="ADD fetches a remote URL",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="ADD",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_031(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name != "ADD":
            continue
        if re.search(r"(?i)https?://", instr.args_raw):
            continue
        # Flag local ADD (prefer COPY) unless archive extension present
        if not re.search(r"(?i)\.(tar|tar\.gz|tgz|tar\.bz2|zip)\b", instr.args_raw):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="ADD used where COPY would be clearer",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="ADD",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_032(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    pipe_re = re.compile(r"(?i)(curl|wget)\b[^\n|]*\|\s*(ba)?sh")
    for instr in doc.instructions:
        if instr.name == "RUN" and pipe_re.search(instr.args_raw):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="curl/wget piped directly to a shell",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_033(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name != "RUN":
            continue
        if re.search(r"(?i)(curl|wget)\b", instr.args_raw) and not re.search(
            r"(?i)(sha256sum|sha512sum|md5sum|gpg\s+--verify)",
            instr.args_raw,
        ):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="Download without visible checksum verification in same step",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_034(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    markers = (
        "allow-unauthenticated",
        "--nogpgcheck",
        "trusted=yes",
        "APT::Get::AllowUnauthenticated",
    )
    for instr in doc.instructions:
        if instr.name == "RUN" and any(m.lower() in instr.args_raw.lower() for m in markers):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="Package repository verification appears disabled",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_035(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    markers = ("--insecure", "CURLOPT_SSL_VERIFYPEER", "NODE_TLS_REJECT_UNAUTHORIZED=0", "-k ")
    for instr in doc.instructions:
        text = instr.args_raw
        if instr.name in {"RUN", "ENV"} and any(m in text for m in markers):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="TLS verification explicitly disabled",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path=instr.name,
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_036(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "RUN" and re.search(r"(?i)\bgit\s+clone\b", instr.args_raw):
            if not re.search(r"(?i)(--branch|--checkout|\b[0-9a-f]{7,40}\b)", instr.args_raw):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted="git clone without visible pin to commit/tag",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path="RUN",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


def check_df_040(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name != "RUN":
            continue
        has_update = "apt-get update" in instr.args_raw or "apt update" in instr.args_raw
        has_install = "apt-get install" in instr.args_raw or "apt install" in instr.args_raw
        if has_update and not has_install:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="apt-get update separated from install in this layer",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_041(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "RUN" and re.search(r"(?i)apt(-get)?\s+install", instr.args_raw):
            if "--no-install-recommends" not in instr.args_raw:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted="apt install lacks --no-install-recommends",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path="RUN",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


def check_df_042(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name != "RUN":
            continue
        if re.search(r"(?i)apt(-get)?\s+install", instr.args_raw):
            if not re.search(r"(?i)rm\s+-rf\s+/var/lib/apt/lists", instr.args_raw):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted="apt cache not cleaned in the same layer",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path="RUN",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


def check_df_043(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "RUN" and re.search(
            r"(?i)(apt(-get)?\s+upgrade|apk\s+upgrade|yum\s+update\s+-y\s*$)",
            instr.args_raw,
        ):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="Unbounded system upgrade detected",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_044(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "RUN" and re.search(
            r"(?i)(apt(-get)?\s+install|apk\s+add)", instr.args_raw
        ):
            # Heuristic: packages without =version
            pkgs = re.findall(r"(?i)(?:install|add)\s+[^=\n]*", instr.args_raw)
            if pkgs and "=" not in instr.args_raw:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted="Packages installed without visible version constraints",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path="RUN",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


def check_df_045(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "RUN" and re.search(r"(?i)\bapk\s+add\b", instr.args_raw):
            if "--no-cache" not in instr.args_raw:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted="apk add lacks --no-cache",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path="RUN",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


def check_df_046(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    tools = [str(t) for t in ((ctx.get("config") or {}).get("package_debug_tools") or [])]
    if not doc.final_stage:
        return []
    out: list[Finding] = []
    for instr in doc.final_stage.instructions:
        if instr.name != "RUN":
            continue
        for tool in tools:
            if re.search(rf"(?i)\b{re.escape(tool)}\b", instr.args_raw) and re.search(
                r"(?i)(apt(-get)?\s+install|apk\s+add|yum\s+install)",
                instr.args_raw,
            ):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"Debug/admin tool '{tool}' installed in final stage",
                        file=_file(ctx),
                        stage=doc.final_stage.name,
                        property_path="RUN",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
                break
    return out


def check_df_050(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "RUN" and re.search(
            r"(?i)chmod\s+(?:-R\s+)?([0-7]*777|a\+rwx)", instr.args_raw
        ):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="chmod 777 or equivalent broad writable permission",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_051(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "RUN" and re.search(
            r"(?i)(chmod|chown)\s+-R\s+[^\n]*\s/(?:\s|$)",
            instr.args_raw,
        ):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="Recursive chmod/chown on broad filesystem paths",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_052(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    user = final_user(doc)
    if not user or _is_root_user(user):
        return []
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "COPY" and "chown" not in instr.flags:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="COPY --chown absent while final USER is non-root",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="COPY",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_053(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    if not any(i.name == "WORKDIR" for i in doc.instructions):
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="WORKDIR is absent",
                file=_file(ctx),
                property_path="WORKDIR",
            )
        ]
    return []


def check_df_054(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    sensitive = {"/", "/etc", "/root", "/var/run", "/proc", "/sys"}
    for instr in doc.instructions:
        if instr.name == "WORKDIR" and instr.args_raw.strip() in sensitive:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"WORKDIR is sensitive path {instr.args_raw.strip()}",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="WORKDIR",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_055(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    sensitive = ("/etc", "/root", "/home", "/var/run", "/proc")
    for instr in doc.instructions:
        if instr.name != "VOLUME":
            continue
        for marker in sensitive:
            if marker in instr.args_raw:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted="VOLUME declares a sensitive host-like path",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path="VOLUME",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
                break
    return out


def check_df_056(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    if len(doc.stages) < 2 or not doc.final_stage:
        return []
    # Heuristic: final stage installs compilers/package managers heavily
    out: list[Finding] = []
    for instr in doc.final_stage.instructions:
        if instr.name == "RUN" and re.search(
            r"(?i)(gcc|make|build-essential|maven|gradle)",
            instr.args_raw,
        ):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="Build tooling appears present in final stage",
                    file=_file(ctx),
                    stage=doc.final_stage.name,
                    property_path="RUN",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_060(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _shell_form(rule, ctx, "ENTRYPOINT")


def check_df_061(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    return _shell_form(rule, ctx, "CMD")


def _shell_form(rule: RuleDefinition, ctx: CheckContext, name: str) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == name and instr.args_raw and not instr.is_json_form:
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=f"Shell-form {name} used",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path=name,
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_062(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    markers = ("sshd", "systemd", "supervisord", "/usr/sbin/sshd")
    for instr in doc.instructions:
        if instr.name in {"CMD", "ENTRYPOINT"}:
            text = instr.args_raw.lower()
            if any(m in text for m in markers):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"{instr.name} appears to start SSH/systemd/supervisor",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path=instr.name,
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


def check_df_063(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    if not any(i.name in {"CMD", "ENTRYPOINT"} for i in doc.instructions):
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="No ENTRYPOINT or CMD defined",
                file=_file(ctx),
                property_path="CMD/ENTRYPOINT",
            )
        ]
    return []


def check_df_064(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    if not any(i.name == "HEALTHCHECK" for i in doc.instructions):
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted="HEALTHCHECK missing",
                file=_file(ctx),
                property_path="HEALTHCHECK",
            )
        ]
    return []


def check_df_065(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name == "HEALTHCHECK" and instr.args_raw.strip().upper().startswith("NONE"):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted="HEALTHCHECK NONE",
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="HEALTHCHECK",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_066(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name != "HEALTHCHECK":
            continue
        hits = inspect_text_for_secrets(instr.args_raw)
        if hits or re.search(r"(?i)(password|secret|token)=", instr.args_raw):
            out.append(
                fail(
                    rule,
                    severity=_sev(rule, ctx),
                    evidence_redacted=(
                        "HEALTHCHECK includes secret-like fragments: "
                        f"{redact_command_fragment(instr.args_raw)[:120]}"
                    ),
                    file=_file(ctx),
                    stage=instr.stage,
                    property_path="HEALTHCHECK",
                    line_start=instr.line_start,
                    line_end=instr.line_end,
                )
            )
    return out


def check_df_070(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    dockerignore_present = bool(ctx.get("dockerignore_present"))
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name in {"COPY", "ADD"} and re.search(r"(^|\s)\.\s+\.(\s|$)", instr.args_raw):
            if not dockerignore_present:
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted=f"{instr.name} . . without supplied .dockerignore",
                        file=_file(ctx),
                        stage=instr.stage,
                        property_path=instr.name,
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


def check_df_071(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    if ctx.get("project_analysis") and not ctx.get("dockerignore_present"):
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted=".dockerignore missing from analyzed project",
                file=_file(ctx),
                property_path=".dockerignore",
            )
        ]
    return [
        not_applicable(
            rule,
            file=_file(ctx),
            reason="Project-directory analysis not requested",
        )
    ]


def check_df_072(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    content = ctx.get("dockerignore_content")
    if not content:
        return [
            not_applicable(
                rule,
                file=_file(ctx),
                reason=".dockerignore not available for inspection",
            )
        ]
    required = [".env", "*.pem", "*.key", ".git", "id_rsa", "credentials"]
    missing = [r for r in required if r not in content]
    if missing:
        return [
            fail(
                rule,
                severity=_sev(rule, ctx),
                evidence_redacted=f".dockerignore missing common exclusions: {', '.join(missing[:4])}",
                file=".dockerignore",
                property_path=".dockerignore",
            )
        ]
    return []


def check_df_073(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    out: list[Finding] = []
    for instr in doc.instructions:
        if instr.name in {"COPY", "ADD"}:
            for token in instr.args_raw.split():
                if looks_like_traversal(token):
                    out.append(
                        fail(
                            rule,
                            severity=_sev(rule, ctx),
                            evidence_redacted=f"{instr.name} uses parent traversal path",
                            file=_file(ctx),
                            stage=instr.stage,
                            property_path=instr.name,
                            line_start=instr.line_start,
                            line_end=instr.line_end,
                        )
                    )
                    break
    return out


def check_df_074(rule: RuleDefinition, ctx: CheckContext) -> list[Finding]:
    doc: DockerfileDocument = ctx["document"]
    if len(doc.stages) < 2 or not doc.final_stage:
        return []
    out: list[Finding] = []
    for instr in doc.final_stage.instructions:
        if instr.name == "COPY" and "from" in instr.flags:
            if (
                re.search(r"(^|\s)/\s*$|(^|\s)/\s+/", instr.args_raw)
                or instr.args_raw.strip().endswith("/ .")
                or "/ /" in instr.args_raw
                or instr.args_raw.strip() in {". .", "/ ."}
            ):
                out.append(
                    fail(
                        rule,
                        severity=_sev(rule, ctx),
                        evidence_redacted="Final stage copies broad content from build stage",
                        file=_file(ctx),
                        stage=doc.final_stage.name,
                        property_path="COPY",
                        line_start=instr.line_start,
                        line_end=instr.line_end,
                    )
                )
    return out


DOCKERFILE_CHECKS: dict[str, CheckFn] = {
    "CSB-DF-001": check_df_001,
    "CSB-DF-002": check_df_002,
    "CSB-DF-003": check_df_003,
    "CSB-DF-004": check_df_004,
    "CSB-DF-005": check_df_005,
    "CSB-DF-006": check_df_006,
    "CSB-DF-010": check_df_010,
    "CSB-DF-011": check_df_011,
    "CSB-DF-012": check_df_012,
    "CSB-DF-013": check_df_013,
    "CSB-DF-020": check_df_020,
    "CSB-DF-021": check_df_021,
    "CSB-DF-022": check_df_022,
    "CSB-DF-023": check_df_023,
    "CSB-DF-024": check_df_024,
    "CSB-DF-025": check_df_025,
    "CSB-DF-030": check_df_030,
    "CSB-DF-031": check_df_031,
    "CSB-DF-032": check_df_032,
    "CSB-DF-033": check_df_033,
    "CSB-DF-034": check_df_034,
    "CSB-DF-035": check_df_035,
    "CSB-DF-036": check_df_036,
    "CSB-DF-040": check_df_040,
    "CSB-DF-041": check_df_041,
    "CSB-DF-042": check_df_042,
    "CSB-DF-043": check_df_043,
    "CSB-DF-044": check_df_044,
    "CSB-DF-045": check_df_045,
    "CSB-DF-046": check_df_046,
    "CSB-DF-050": check_df_050,
    "CSB-DF-051": check_df_051,
    "CSB-DF-052": check_df_052,
    "CSB-DF-053": check_df_053,
    "CSB-DF-054": check_df_054,
    "CSB-DF-055": check_df_055,
    "CSB-DF-056": check_df_056,
    "CSB-DF-060": check_df_060,
    "CSB-DF-061": check_df_061,
    "CSB-DF-062": check_df_062,
    "CSB-DF-063": check_df_063,
    "CSB-DF-064": check_df_064,
    "CSB-DF-065": check_df_065,
    "CSB-DF-066": check_df_066,
    "CSB-DF-070": check_df_070,
    "CSB-DF-071": check_df_071,
    "CSB-DF-072": check_df_072,
    "CSB-DF-073": check_df_073,
    "CSB-DF-074": check_df_074,
}


def register_all(registry: Any) -> None:
    for rule_id, fn in DOCKERFILE_CHECKS.items():
        if rule_id in registry.rules:
            registry.register_check(rule_id, fn)


def evaluate_dockerfile_document(
    document: DockerfileDocument,
    registry: Any,
    *,
    config: dict[str, Any],
    policy: dict[str, Any],
    project_root: str,
    dockerignore_present: bool = False,
    dockerignore_content: str | None = None,
    project_analysis: bool = False,
) -> list[Finding]:
    from container_security_baseline.policy import rule_enabled

    ctx: CheckContext = {
        "document": document,
        "config": config,
        "policy": policy,
        "project_root": project_root,
        "display_path": document.display_path,
        "dockerignore_present": dockerignore_present,
        "dockerignore_content": dockerignore_content,
        "project_analysis": project_analysis,
    }
    findings: list[Finding] = []
    for rule in registry.list_rules(target="dockerfile"):
        if not rule.enabled or not rule_enabled(policy, rule.id, rule.enabled):
            continue
        fn = registry.checks.get(rule.id)
        if not fn:
            continue
        try:
            findings.extend(fn(rule, ctx))
        except Exception as exc:  # noqa: BLE001
            findings.append(error_finding(rule, file=document.display_path, error_message=str(exc)))
    return findings


__all__ = [
    "DOCKERFILE_CHECKS",
    "evaluate_dockerfile_document",
    "register_all",
]
