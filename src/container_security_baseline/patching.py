"""Safe proposed unified-diff generation (never modifies source files)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from container_security_baseline.compose_loader import ComposeDocument
from container_security_baseline.models import Finding
from container_security_baseline.redaction import REDACTED, redact_text
from container_security_baseline.remediation import SAFE_PATCHABLE_RULES
from container_security_baseline.statuses import Status

PATCH_HEADER = "PROPOSED REMEDIATION ONLY — MANUAL REVIEW REQUIRED"


@dataclass
class PatchResult:
    text: str
    refused_reasons: list[str]
    applied_rules: list[str]


_SECRET_VALUE_LINE_RE = re.compile(
    r"(?i)^([+\-\s].{0,80}?(?:password|passwd|secret|token|api[_-]?key|"
    r"private[_-]?key|client[_-]?secret|access[_-]?key|credential)\s*[:=]\s*)(.+)$"
)


def _scrub_patch_body(text: str) -> str:
    """Ensure proposed patches never contain secret values."""
    scrubbed = redact_text(text)
    lines: list[str] = []
    for line in scrubbed.splitlines():
        match = _SECRET_VALUE_LINE_RE.match(line)
        if match:
            lines.append(f"{match.group(1)}{REDACTED}")
        else:
            lines.append(line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _refuse_document(doc: ComposeDocument) -> list[str]:
    reasons: list[str] = []
    if doc.format != "yaml":
        reasons.append("Patch generation refused for non-YAML / canonical JSON inputs")
    if doc.anchors_detected:
        reasons.append("YAML anchors/aliases present")
    if doc.merge_keys_detected:
        reasons.append("YAML merge keys present")
    if doc.has_include:
        reasons.append("Compose include present")
    if doc.has_extends:
        reasons.append("Compose extends present")
    if doc.custom_tags_rejected:
        reasons.append("Custom YAML tags present")
    return reasons


def _secrets_nearby(text: str, line_no: int, window: int = 3) -> bool:
    lines = text.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    chunk = "\n".join(lines[start:end])
    return bool(
        re.search(
            r"(?i)(password|secret|token|api_key|private_key)\s*[:=]",
            chunk,
        )
    )


def _propose_line_changes(
    original: str,
    finding: Finding,
) -> list[str] | None:
    """Return new file lines or None if refused/ambiguous."""
    lines = original.splitlines()
    service = finding.service
    if not service:
        return None

    if finding.rule_id == "CSB-CMP-001":
        # privileged: true -> false
        pattern = re.compile(r"(^\s*privileged:\s*)true(\s*)$", re.IGNORECASE)
        # Only within service block — heuristic: find service then privileged
        in_service = False
        result = list(lines)
        for idx, line in enumerate(result):
            if re.match(rf"^\s*{re.escape(service)}\s*:", line):
                in_service = True
                continue
            if in_service and re.match(r"^\S", line) and not line.startswith(" "):
                in_service = False
            if in_service and pattern.search(line):
                if _secrets_nearby(original, idx + 1):
                    return None
                result[idx] = pattern.sub(r"\1false\2", line)
                return result
        return None

    if finding.rule_id == "CSB-CMP-026":
        # Add no-new-privileges under service if security_opt missing/present
        in_service = False
        service_indent = "    "
        result = list(lines)
        insert_at: int | None = None
        has_security_opt = False
        for idx, line in enumerate(result):
            if re.match(rf"^(\s*){re.escape(service)}\s*:", line):
                in_service = True
                indent_match = re.match(r"^(\s*)", line)
                service_indent = (indent_match.group(1) if indent_match else "") + "  "
                continue
            if in_service and re.match(r"^[^\s#]", line):
                if insert_at is None:
                    insert_at = idx
                in_service = False
            if in_service and line.strip().startswith("security_opt:"):
                has_security_opt = True
                # Insert item after this line if list empty-ish
                insert_at = idx + 1
        if insert_at is None:
            # end of file while still in service
            insert_at = len(result)
        if has_security_opt:
            result.insert(
                insert_at,
                f"{service_indent}- no-new-privileges:true",
            )
        else:
            result.insert(insert_at, f"{service_indent}security_opt:")
            result.insert(insert_at + 1, f"{service_indent}  - no-new-privileges:true")
        return result

    if finding.rule_id == "CSB-CMP-022":
        in_service = False
        service_indent = "    "
        result = list(lines)
        insert_pos: int | None = None
        for idx, line in enumerate(result):
            if re.match(rf"^(\s*){re.escape(service)}\s*:", line):
                in_service = True
                m = re.match(r"^(\s*)", line)
                service_indent = (m.group(1) if m else "") + "  "
                continue
            if in_service and re.match(r"^[^\s#]", line):
                insert_pos = idx
                break
            if in_service and line.strip().startswith("cap_drop:"):
                return None  # already present but incomplete — ambiguous
        if insert_pos is None:
            insert_pos = len(result)
        result.insert(insert_pos, f"{service_indent}cap_drop:")
        result.insert(insert_pos + 1, f"{service_indent}  - ALL")
        return result

    if finding.rule_id == "CSB-CMP-040":
        in_service = False
        service_indent = "    "
        result = list(lines)
        for idx, line in enumerate(result):
            if re.match(rf"^(\s*){re.escape(service)}\s*:", line):
                in_service = True
                m = re.match(r"^(\s*)", line)
                service_indent = (m.group(1) if m else "") + "  "
                continue
            if in_service and re.match(r"^[^\s#]", line):
                result.insert(idx, f"{service_indent}read_only: true")
                return result
            if in_service and line.strip().startswith("read_only:"):
                result[idx] = f"{service_indent}read_only: true"
                return result
        result.append(f"{service_indent}read_only: true")
        return result

    if finding.rule_id == "CSB-CMP-004":
        # Change :rw to :ro on sensitive mounts — only when short syntax ends with rw
        result = list(lines)
        changed = False
        for idx, line in enumerate(result):
            if ":rw" in line or ":Rw" in line:
                if _secrets_nearby(original, idx + 1):
                    return None
                result[idx] = re.sub(r":[Rr][Ww]\b", ":ro", line)
                changed = True
        return result if changed else None

    return None


def generate_unified_diff(
    doc: ComposeDocument,
    findings: Sequence[Finding],
) -> PatchResult:
    """Generate a proposed unified diff for safe findings only."""
    refused = _refuse_document(doc)
    if refused:
        guidance = "\n".join(f"# REFUSED: {r}" for r in refused)
        text = (
            f"# {PATCH_HEADER}\n"
            f"# No unified diff generated. Manual remediation required.\n"
            f"{guidance}\n"
        )
        return PatchResult(text=text, refused_reasons=refused, applied_rules=[])

    original = doc.original_text
    current_lines = original.splitlines()
    applied: list[str] = []
    working = "\n".join(current_lines)
    if original.endswith("\n"):
        # preserve later
        pass

    for finding in findings:
        if finding.status not in {Status.FAIL, Status.WARNING}:
            continue
        if finding.suppressed:
            continue
        if finding.rule_id not in SAFE_PATCHABLE_RULES:
            continue
        if (
            finding.patchability not in {"safe", "manual"}
            and finding.rule_id not in SAFE_PATCHABLE_RULES
        ):
            continue
        new_lines = _propose_line_changes(working, finding)
        if new_lines is None:
            refused.append(
                f"Ambiguous or unsafe to patch {finding.rule_id} for service={finding.service}"
            )
            continue
        working = "\n".join(new_lines)
        if not working.endswith("\n") and original.endswith("\n"):
            working += "\n"
        applied.append(finding.rule_id)

    if not applied:
        text = (
            f"# {PATCH_HEADER}\n"
            "# No safe automatic patches were generated.\n"
            "# Review findings and apply manual remediation guidance.\n"
        )
        if refused:
            text += "\n".join(f"# NOTE: {r}" for r in refused) + "\n"
        return PatchResult(text=text, refused_reasons=refused, applied_rules=[])

    # Build unified diff
    import difflib

    old = original.splitlines(keepends=True)
    new = working.splitlines(keepends=True)
    if not old or not old[-1].endswith("\n"):
        # normalize
        old = [ln if ln.endswith("\n") else ln + "\n" for ln in original.splitlines()]
        new = [ln if ln.endswith("\n") else ln + "\n" for ln in working.splitlines()]
    path = doc.display_path.replace("\\", "/")
    diff = difflib.unified_diff(
        old,
        new,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="\n",
    )
    body = "".join(diff)
    text = (
        f"# {PATCH_HEADER}\n"
        f"# Rules applied: {', '.join(sorted(set(applied)))}\n"
        f"# Do not apply blindly. Validate application behavior.\n"
        f"{body}"
    )
    return PatchResult(
        text=_scrub_patch_body(text),
        refused_reasons=refused,
        applied_rules=sorted(set(applied)),
    )


__all__ = ["PATCH_HEADER", "PatchResult", "generate_unified_diff"]
