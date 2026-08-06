"""Safe Compose YAML/JSON loading with resource limits and duplicate-key rejection."""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from container_security_baseline.source import SourceFile, SourceLoadError, load_source_file


class ComposeLoadError(ValueError):
    """Raised when Compose input cannot be loaded safely."""


@dataclass
class ComposeDocument:
    """Loaded Compose document (YAML or JSON)."""

    data: dict[str, Any]
    source: SourceFile
    format: str  # yaml | json | canonical-json
    anchors_detected: bool = False
    merge_keys_detected: bool = False
    alias_count: int = 0
    warnings: list[str] = field(default_factory=list)
    has_include: bool = False
    has_extends: bool = False
    custom_tags_rejected: bool = False
    original_text: str = ""

    @property
    def display_path(self) -> str:
        return self.source.display_path


_CUSTOM_TAG_RE = re.compile(r"(?m)^\s*\S+\s+!!?\w+")
_EXPLICIT_TAG_RE = re.compile(r"!!?[A-Za-z0-9_:/.-]+")


class _SafeLimitedLoader(yaml.SafeLoader):
    """SafeLoader with duplicate-key rejection and resource counters."""

    def __init__(self, stream: Any, limits: dict[str, Any]) -> None:
        super().__init__(stream)
        self._limits = limits
        self.node_count = 0
        self.alias_count = 0
        self.anchors_detected = False
        self.merge_keys_detected = False
        self.max_depth_seen = 0


def _check_custom_tags(text: str) -> None:
    # Reject non-core YAML tags that could construct objects.
    for match in _EXPLICIT_TAG_RE.finditer(text):
        tag = match.group(0)
        # Allow implicit !!str/!!int/!!float/!!bool/!!null/!!map/!!seq only if needed;
        # safer to reject all explicit !! tags for untrusted Compose.
        if tag.startswith("!!") and tag not in {
            "!!str",
            "!!int",
            "!!float",
            "!!bool",
            "!!null",
            "!!map",
            "!!seq",
            "!!binary",  # still reject binary below
        }:
            raise ComposeLoadError(f"Custom YAML tag rejected: {tag}")
        if tag in {"!!python/object", "!!python/name", "!!python/module", "!!binary"}:
            raise ComposeLoadError(f"Unsafe YAML tag rejected: {tag}")
        if "python" in tag.lower():
            raise ComposeLoadError(f"Python YAML tag rejected: {tag}")


def _merge_into(mapping: dict[str, Any], merge_value: Any, *, overwrite: bool = False) -> None:
    """Apply YAML merge-key semantics without executing arbitrary constructors."""
    if isinstance(merge_value, dict):
        for key, value in merge_value.items():
            if overwrite or key not in mapping:
                mapping[key] = value
        return
    if isinstance(merge_value, list):
        for item in merge_value:
            _merge_into(mapping, item, overwrite=overwrite)
        return
    raise ComposeLoadError("Invalid YAML merge key value; expected mapping or list")


def _construct_mapping_no_duplicates(
    loader: _SafeLimitedLoader, node: MappingNode, deep: bool = False
) -> dict[str, Any]:
    if not isinstance(node, MappingNode):
        raise ComposeLoadError("Expected mapping node")
    mapping: dict[str, Any] = {}
    merges: list[Any] = []
    max_map = int(loader._limits.get("maximum_mapping_size", 10_000))
    if len(node.value) > max_map:
        raise ComposeLoadError("YAML mapping exceeds maximum_mapping_size")
    for key_node, value_node in node.value:
        if getattr(key_node, "anchor", None):
            loader.anchors_detected = True
        if getattr(value_node, "anchor", None):
            loader.anchors_detected = True
        # Merge keys use tag:yaml.org,2002:merge (scalar value "<<").
        is_merge = isinstance(key_node, ScalarNode) and (
            key_node.tag == "tag:yaml.org,2002:merge" or key_node.value == "<<"
        )
        if is_merge:
            loader.merge_keys_detected = True
            merges.append(loader.construct_object(value_node, deep=deep))
            continue
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ComposeLoadError(f"Duplicate YAML key rejected: {key!r}")
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    # Explicit keys already present take precedence over merged values.
    for merge_value in merges:
        _merge_into(mapping, merge_value, overwrite=False)
    return mapping


def _walk_count(
    loader: _SafeLimitedLoader,
    node: Node,
    depth: int,
) -> None:
    loader.node_count += 1
    loader.max_depth_seen = max(loader.max_depth_seen, depth)
    max_nodes = int(loader._limits.get("maximum_nodes", 50_000))
    max_depth = int(loader._limits.get("maximum_depth", 50))
    max_scalar = int(loader._limits.get("maximum_scalar_length", 262_144))
    max_seq = int(loader._limits.get("maximum_sequence_length", 10_000))
    max_map = int(loader._limits.get("maximum_mapping_size", 10_000))
    max_aliases = int(loader._limits.get("maximum_aliases", 100))

    if loader.node_count > max_nodes:
        raise ComposeLoadError("YAML exceeds maximum_nodes")
    if depth > max_depth:
        raise ComposeLoadError("YAML exceeds maximum_depth")
    if loader.alias_count > max_aliases:
        raise ComposeLoadError("YAML exceeds maximum_aliases")

    if getattr(node, "anchor", None):
        loader.anchors_detected = True

    if isinstance(node, ScalarNode):
        if isinstance(node.value, str) and len(node.value) > max_scalar:
            raise ComposeLoadError("YAML scalar exceeds maximum_scalar_length")
        if node.tag and not node.tag.startswith("tag:yaml.org,2002:"):
            if loader._limits.get("reject_custom_tags", True):
                raise ComposeLoadError(f"Custom YAML tag rejected: {node.tag}")
        return

    if isinstance(node, SequenceNode):
        if len(node.value) > max_seq:
            raise ComposeLoadError("YAML sequence exceeds maximum_sequence_length")
        for child in node.value:
            _walk_count(loader, child, depth + 1)
        return

    if isinstance(node, MappingNode):
        if len(node.value) > max_map:
            raise ComposeLoadError("YAML mapping exceeds maximum_mapping_size")
        for key_node, value_node in node.value:
            if isinstance(key_node, ScalarNode) and (
                key_node.value == "<<" or key_node.tag == "tag:yaml.org,2002:merge"
            ):
                loader.merge_keys_detected = True
            _walk_count(loader, key_node, depth + 1)
            _walk_count(loader, value_node, depth + 1)
        return


def _patch_loader(loader: _SafeLimitedLoader) -> None:
    def _mapping(node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        return _construct_mapping_no_duplicates(loader, node, deep=deep)

    loader.construct_mapping = _mapping  # type: ignore[method-assign]
    original_compose_node = loader.compose_node

    def compose_node(parent: Any, index: Any) -> Node:
        event = loader.peek_event()  # type: ignore[no-untyped-call]
        if getattr(event, "anchor", None):
            loader.anchors_detected = True
        from yaml.events import AliasEvent

        if isinstance(event, AliasEvent):
            loader.alias_count += 1
            max_aliases = int(loader._limits.get("maximum_aliases", 100))
            if loader.alias_count > max_aliases:
                raise ComposeLoadError("YAML exceeds maximum_aliases")
        node = original_compose_node(parent, index)
        if node is None:
            raise ComposeLoadError("YAML compose produced an empty node")
        return node

    loader.compose_node = compose_node  # type: ignore[method-assign]


def load_compose_yaml(
    source: SourceFile,
    limits: dict[str, Any],
) -> ComposeDocument:
    """Parse Compose YAML using SafeLoader with safeguards."""
    text = source.content
    if "\x00" in text:
        raise ComposeLoadError("NUL byte rejected in YAML")
    if limits.get("reject_custom_tags", True):
        _check_custom_tags(text)

    # Multi-document check
    max_docs = int(limits.get("maximum_documents", 1))
    try:
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        raise ComposeLoadError(f"YAML parse error: {exc}") from exc

    if len(documents) > max_docs:
        raise ComposeLoadError(
            f"YAML contains {len(documents)} documents; maximum_documents={max_docs}"
        )
    if not documents:
        raise ComposeLoadError("YAML document is empty")

    root_node = documents[0]
    walk_loader = _SafeLimitedLoader(text, limits)
    try:
        _walk_count(walk_loader, root_node, 0)
        data, load_loader = _safe_load_with_limits(text, limits)
    except ComposeLoadError:
        raise
    except yaml.YAMLError as exc:
        raise ComposeLoadError(f"YAML parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise ComposeLoadError("Compose root must be a mapping/object")

    anchors_detected = walk_loader.anchors_detected or load_loader.anchors_detected
    merge_keys_detected = walk_loader.merge_keys_detected or load_loader.merge_keys_detected
    alias_count = max(walk_loader.alias_count, load_loader.alias_count)
    # Anchors imply alias usage is possible; also detect via text for reporting.
    if re.search(r"(?m)&[A-Za-z0-9_-]+", text) or re.search(r"(?m)\*[A-Za-z0-9_-]+", text):
        anchors_detected = True
    if re.search(r"(?m)^\s*<<\s*:", text):
        merge_keys_detected = True

    warnings: list[str] = []
    if anchors_detected:
        warnings.append("YAML anchors or aliases detected; patching may be refused")
    if merge_keys_detected:
        warnings.append("YAML merge keys (<<) detected; patching may be refused")

    has_include = "include" in data
    has_extends = _detect_extends(data)
    if has_include:
        warnings.append(
            "Compose 'include' is present but was not followed; referenced files were not read"
        )
    if has_extends:
        warnings.append("Compose 'extends' is present but referenced files were not read")

    return ComposeDocument(
        data=data,
        source=source,
        format="yaml",
        anchors_detected=anchors_detected,
        merge_keys_detected=merge_keys_detected,
        alias_count=alias_count,
        warnings=warnings,
        has_include=has_include,
        has_extends=has_extends,
        original_text=text,
    )


def _safe_load_with_limits(text: str, limits: dict[str, Any]) -> tuple[Any, _SafeLimitedLoader]:
    """Load YAML via SafeLoader subclass instance (never FullLoader/unsafe)."""
    loader = _SafeLimitedLoader(text, limits)
    _patch_loader(loader)
    try:
        data = loader.get_single_data()
    except Exception:
        loader.dispose()  # type: ignore[no-untyped-call]
        raise
    # Keep loader counters for the caller; dispose stream resources only.
    with contextlib.suppress(Exception):
        loader.dispose()  # type: ignore[no-untyped-call]
    return data, loader


def _detect_extends(data: dict[str, Any]) -> bool:
    services = data.get("services")
    if not isinstance(services, dict):
        return False
    return any(isinstance(svc, dict) and "extends" in svc for svc in services.values())


class _DuplicateKeyRejectingDecoder(json.JSONDecoder):
    def __init__(self, limits: dict[str, Any]) -> None:
        self._limits = limits
        self._depth = 0
        self._nodes = 0
        super().__init__(object_pairs_hook=self._pairs_hook)

    def _pairs_hook(self, pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        self._nodes += 1
        max_nodes = int(self._limits.get("maximum_nodes", 50_000))
        max_map = int(self._limits.get("maximum_mapping_size", 10_000))
        if self._nodes > max_nodes:
            raise ComposeLoadError("JSON exceeds maximum_nodes")
        if len(pairs) > max_map:
            raise ComposeLoadError("JSON mapping exceeds maximum_mapping_size")
        mapping: dict[str, Any] = {}
        for key, value in pairs:
            if key in mapping:
                raise ComposeLoadError(f"Duplicate JSON key rejected: {key!r}")
            if isinstance(value, str):
                max_scalar = int(self._limits.get("maximum_scalar_length", 262_144))
                if len(value) > max_scalar:
                    raise ComposeLoadError("JSON scalar exceeds maximum_scalar_length")
            mapping[key] = value
        return mapping


def _check_json_depth(obj: Any, depth: int, limits: dict[str, Any]) -> None:
    max_depth = int(limits.get("maximum_depth", 50))
    if depth > max_depth:
        raise ComposeLoadError("JSON exceeds maximum_depth")
    if isinstance(obj, dict):
        for value in obj.values():
            _check_json_depth(value, depth + 1, limits)
    elif isinstance(obj, list):
        max_seq = int(limits.get("maximum_sequence_length", 10_000))
        if len(obj) > max_seq:
            raise ComposeLoadError("JSON sequence exceeds maximum_sequence_length")
        for item in obj:
            _check_json_depth(item, depth + 1, limits)


def load_compose_json(
    source: SourceFile,
    limits: dict[str, Any],
    *,
    canonical: bool = False,
) -> ComposeDocument:
    """Parse Compose JSON with duplicate-key rejection."""
    text = source.content
    if "\x00" in text:
        raise ComposeLoadError("NUL byte rejected in JSON")
    decoder = _DuplicateKeyRejectingDecoder(limits)
    try:
        data = decoder.decode(text)
    except ComposeLoadError:
        raise
    except json.JSONDecodeError as exc:
        raise ComposeLoadError(f"JSON parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise ComposeLoadError("Compose JSON root must be an object")
    _check_json_depth(data, 0, limits)

    warnings: list[str] = []
    if canonical:
        warnings.append(
            "Pre-resolved Compose JSON may already contain interpolated sensitive values; "
            "secrets are redacted but original interpolation state cannot be reconstructed"
        )

    return ComposeDocument(
        data=data,
        source=source,
        format="canonical-json" if canonical else "json",
        warnings=warnings,
        has_include="include" in data,
        has_extends=_detect_extends(data),
        original_text=text,
    )


def load_compose_file(
    path: str | Path,
    project_root: str | Path,
    limits: dict[str, Any],
    *,
    display_path: str | None = None,
    force_json: bool = False,
    canonical: bool = False,
) -> ComposeDocument:
    """Load a Compose file from disk (YAML or JSON)."""
    source = load_source_file(
        path,
        project_root,
        maximum_file_bytes=int(limits.get("maximum_file_bytes", 2_097_152)),
        display_path=display_path,
    )
    suffix = source.path.suffix.lower()
    name = source.path.name.lower()
    if force_json or canonical or suffix == ".json" or name.endswith(".json"):
        return load_compose_json(source, limits, canonical=canonical)
    return load_compose_yaml(source, limits)


__all__ = [
    "ComposeDocument",
    "ComposeLoadError",
    "SourceLoadError",
    "load_compose_file",
    "load_compose_json",
    "load_compose_yaml",
]
