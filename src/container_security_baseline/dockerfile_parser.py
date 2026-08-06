"""Conservative Dockerfile static parser (no shell execution)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ParseStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"


INSTRUCTION_NAMES = frozenset(
    {
        "FROM",
        "ARG",
        "ENV",
        "RUN",
        "COPY",
        "ADD",
        "USER",
        "WORKDIR",
        "VOLUME",
        "EXPOSE",
        "CMD",
        "ENTRYPOINT",
        "HEALTHCHECK",
        "SHELL",
        "LABEL",
        "STOPSIGNAL",
        "ONBUILD",
        "MAINTAINER",  # legacy
    }
)


@dataclass
class Instruction:
    name: str
    args_raw: str
    line_start: int
    line_end: int
    original_text: str
    is_json_form: bool = False
    json_value: Any = None
    flags: dict[str, str] = field(default_factory=dict)
    stage: str | None = None
    partial: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class Stage:
    name: str | None
    index: int
    from_image: str | None
    from_instruction: Instruction | None
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class DockerfileDocument:
    instructions: list[Instruction]
    stages: list[Stage]
    final_stage: Stage | None
    status: ParseStatus
    warnings: list[str] = field(default_factory=list)
    parser_directives: dict[str, str] = field(default_factory=dict)
    original_text: str = ""
    display_path: str = ""


_CONTINUATION = re.compile(r"\\\s*$")
_DIRECTIVE = re.compile(r"^#\s*([a-z]+)\s*=\s*(.*)$", re.IGNORECASE)
_FROM_RE = re.compile(r"^(?P<img>\S+)(?:\s+[Aa][Ss]\s+(?P<as>\S+))?$")
_FLAG_RE = re.compile(r"^--([A-Za-z0-9][A-Za-z0-9_-]*)(?:=(\S+))?")


def _split_logical_lines(text: str) -> list[tuple[int, int, str]]:
    """Return (start_line, end_line, logical_text) 1-based."""
    raw_lines = text.splitlines()
    result: list[tuple[int, int, str]] = []
    i = 0
    while i < len(raw_lines):
        line_no = i + 1
        line = raw_lines[i]
        if not line.strip() or (
            line.lstrip().startswith("#") and not line.lstrip().startswith("# ")
        ):
            # Keep directive comments handled separately; blank/comments skipped as instructions
            if line.lstrip().startswith("#"):
                result.append((line_no, line_no, line))
            i += 1
            continue
        buf = line
        start = line_no
        end = line_no
        while _CONTINUATION.search(raw_lines[i]) and i + 1 < len(raw_lines):
            # Remove trailing backslash continuation
            buf = _CONTINUATION.sub("", buf) + raw_lines[i + 1]
            i += 1
            end = i + 1
        result.append((start, end, buf))
        i += 1
    return result


def _try_parse_json_array(text: str) -> tuple[bool, Any]:
    stripped = text.strip()
    if not stripped.startswith("["):
        return False, None
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        return False, None
    if isinstance(value, list):
        return True, value
    return False, None


def _parse_flags_and_rest(rest: str) -> tuple[dict[str, str], str]:
    flags: dict[str, str] = {}
    tokens = rest.split()
    idx = 0
    while idx < len(tokens):
        m = _FLAG_RE.match(tokens[idx])
        if not m:
            break
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else "true"
        flags[key] = val
        idx += 1
    remainder = " ".join(tokens[idx:])
    return flags, remainder


def _parse_env(args: str) -> tuple[dict[str, str], bool]:
    """Return env mapping and whether parsing was partial."""
    # KEY=VALUE KEY2=VALUE2 or KEY VALUE
    if "=" in args.split(None, 1)[0] if args.strip() else "":
        result: dict[str, str] = {}
        # crude split respecting simple form
        parts = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=(\S+)", args)
        if not parts:
            return {}, True
        for k, v in parts:
            result[k] = v
        return result, False
    tokens = args.split(None, 1)
    if len(tokens) == 2:
        return {tokens[0]: tokens[1]}, False
    return {}, True


def parse_dockerfile(text: str, *, display_path: str = "") -> DockerfileDocument:
    """Parse Dockerfile text conservatively."""
    warnings: list[str] = []
    directives: dict[str, str] = {}
    instructions: list[Instruction] = []
    stages: list[Stage] = []
    current_stage: Stage | None = None
    status = ParseStatus.OK
    stage_index = -1
    saw_from = False

    logical = _split_logical_lines(text)
    for start, end, raw in logical:
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            # Parser directive only before first FROM
            if not saw_from:
                dm = _DIRECTIVE.match(stripped)
                if dm:
                    directives[dm.group(1).lower()] = dm.group(2).strip()
            continue

        # ONBUILD wraps another instruction
        onbuild = False
        work = stripped
        if work.upper().startswith("ONBUILD "):
            onbuild = True
            work = work[8:].lstrip()

        parts = work.split(None, 1)
        if not parts:
            continue
        name = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

        if name not in INSTRUCTION_NAMES:
            warnings.append(f"Unrecognized instruction at line {start}: {name}")
            status = ParseStatus.PARTIAL
            instructions.append(
                Instruction(
                    name=name,
                    args_raw=args,
                    line_start=start,
                    line_end=end,
                    original_text=raw,
                    partial=True,
                    notes=["unrecognized instruction"],
                )
            )
            continue

        flags: dict[str, str] = {}
        is_json = False
        json_value: Any = None
        partial = False
        notes: list[str] = []
        args_for_store = args

        if name in {"RUN", "CMD", "ENTRYPOINT", "SHELL", "VOLUME", "HEALTHCHECK"}:
            # HEALTHCHECK has options before CMD/NONE
            if name == "HEALTHCHECK":
                upper = args.strip().upper()
                if upper == "NONE" or upper.startswith("NONE"):
                    args_for_store = args.strip()
                else:
                    flags, remainder = _parse_flags_and_rest(args)
                    is_json, json_value = _try_parse_json_array(remainder)
                    if remainder.upper().startswith("CMD"):
                        cmd_part = remainder[3:].strip()
                        is_json, json_value = _try_parse_json_array(cmd_part)
                        args_for_store = remainder
                    else:
                        args_for_store = remainder
                        partial = True
                        notes.append("complex HEALTHCHECK form")
            elif name in {"CMD", "ENTRYPOINT", "SHELL", "VOLUME"}:
                is_json, json_value = _try_parse_json_array(args)
                args_for_store = args
            elif name == "RUN":
                flags, remainder = _parse_flags_and_rest(args)
                is_json, json_value = _try_parse_json_array(remainder)
                args_for_store = remainder
                if any(c in remainder for c in ["$(", "`"]) and not is_json:
                    notes.append("complex shell syntax; not fully interpreted")
                    partial = True
                    status = ParseStatus.PARTIAL

        if name in {"COPY", "ADD"}:
            flags, remainder = _parse_flags_and_rest(args)
            args_for_store = remainder
            is_json, json_value = _try_parse_json_array(remainder)

        if name == "ENV":
            _, env_partial = _parse_env(args)
            if env_partial:
                partial = True
                notes.append("ENV form partially parsed")
                status = ParseStatus.PARTIAL

        if onbuild:
            notes.append("ONBUILD wrapper")

        instr = Instruction(
            name=name,
            args_raw=args_for_store,
            line_start=start,
            line_end=end,
            original_text=raw,
            is_json_form=is_json,
            json_value=json_value,
            flags=flags,
            stage=current_stage.name if current_stage else None,
            partial=partial,
            notes=notes,
        )

        if name == "FROM":
            saw_from = True
            stage_index += 1
            m = _FROM_RE.match(args.strip())
            image = None
            stage_name = None
            if m:
                image = m.group("img")
                stage_name = m.group("as")
            else:
                partial = True
                status = ParseStatus.PARTIAL
                warnings.append(f"Complex FROM at line {start}; marked partial")
                image = args.strip().split()[0] if args.strip() else None
            instr.partial = partial
            instr.stage = stage_name
            current_stage = Stage(
                name=stage_name,
                index=stage_index,
                from_image=image,
                from_instruction=instr,
            )
            stages.append(current_stage)
            instructions.append(instr)
            current_stage.instructions.append(instr)
            continue

        if current_stage is None:
            # ARG before FROM is allowed
            instructions.append(instr)
            continue

        instr.stage = current_stage.name
        instructions.append(instr)
        current_stage.instructions.append(instr)

    final_stage = stages[-1] if stages else None
    if status == ParseStatus.OK and any(i.partial for i in instructions):
        status = ParseStatus.PARTIAL

    return DockerfileDocument(
        instructions=instructions,
        stages=stages,
        final_stage=final_stage,
        status=status,
        warnings=warnings,
        parser_directives=directives,
        original_text=text,
        display_path=display_path,
    )


def final_user(doc: DockerfileDocument) -> str | None:
    """Return the last USER in the final stage, if any."""
    if not doc.final_stage:
        return None
    user: str | None = None
    for instr in doc.final_stage.instructions:
        if instr.name == "USER":
            user = instr.args_raw.strip()
    return user


def stage_users(stage: Stage) -> list[tuple[int, str]]:
    return [(i.line_start, i.args_raw.strip()) for i in stage.instructions if i.name == "USER"]


__all__ = [
    "INSTRUCTION_NAMES",
    "DockerfileDocument",
    "Instruction",
    "ParseStatus",
    "Stage",
    "final_user",
    "parse_dockerfile",
    "stage_users",
]
