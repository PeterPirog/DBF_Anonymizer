"""Policy resolution and fingerprint for REQ-P1-005 read-only planning.

Validates a versioned JSON policy dictionary with strict fail-closed
nested-key allowlists and computes a deterministic SHA-256 fingerprint.
No transformation is performed at planning time.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from dbf_anonymizer.errors import PolicyError, ErrorCode, ErrorContext

KNOWN_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "profile", "text", "memo", "temporal", "numeric", "relationships", "indexes"}
)

KNOWN_PROFILES = frozenset({"SAFE_TRANSFER", "DATA_ONLY"})

TEXT_ACTIONS = frozenset({"PSEUDONYMIZE_REVERSIBLE", "KEEP"})
MEMO_ACTIONS = frozenset({"MASK_REVERSIBLE", "KEEP"})
TEMPORAL_ACTIONS = frozenset({"SHIFT_REVERSIBLE", "KEEP"})
NUMERIC_ACTIONS = frozenset({"KEEP", "PSEUDONYMIZE_REVERSIBLE"})

TEXT_ALLOWED_KEYS = frozenset({"default_action", "domain"})
MEMO_ALLOWED_KEYS = frozenset({"text", "binary"})
TEMPORAL_ALLOWED_KEYS = frozenset({"date", "datetime"})
NUMERIC_ALLOWED_KEYS = frozenset({"default_action"})
RELATIONSHIPS_ALLOWED_KEYS = frozenset({"metadata_file"})
INDEXES_ALLOWED_KEYS = frozenset({"profile"})

SUPPORTED_INDEX_PROFILES = frozenset({"DATA_ONLY", "VFP_INDEXED"})

SUPPORTED_SCHEMA_VERSION = 1

DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": 1,
    "profile": "SAFE_TRANSFER",
    "text": {"default_action": "PSEUDONYMIZE_REVERSIBLE", "domain": "GLOBAL_TEXT"},
    "memo": {"text": "MASK_REVERSIBLE", "binary": "MASK_REVERSIBLE"},
    "temporal": {"date": "SHIFT_REVERSIBLE", "datetime": "SHIFT_REVERSIBLE"},
    "numeric": {"default_action": "KEEP"},
    "relationships": {"metadata_file": None},
    "indexes": {"profile": "DATA_ONLY"},
}


def _reject(detail_code: str) -> None:
    raise PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


def _reject_unsupported(detail_code: str) -> None:
    raise PolicyError(
        ErrorCode.POLICY_UNSUPPORTED,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


def _validate_nested(
    section: Any,
    allowed_keys: frozenset[str],
    section_name: str,
) -> None:
    if not isinstance(section, dict):
        _reject(f"{section_name}_not_object")
        return
    unknown = set(section.keys()) - allowed_keys
    if unknown:
        _reject(f"unknown_{section_name}_keys")


def _validate_policy(policy: Mapping[str, Any]) -> None:
    """Validate the policy structure. Raises PolicyError on any violation."""

    if "schema_version" not in policy:
        _reject("missing_schema_version")

    sv = policy["schema_version"]
    if isinstance(sv, bool) or not isinstance(sv, int):
        _reject("invalid_schema_version_type")
    if sv != SUPPORTED_SCHEMA_VERSION:
        _reject("unsupported_schema_version")

    unknown_top = set(policy.keys()) - KNOWN_TOP_LEVEL_KEYS
    if unknown_top:
        _reject("unknown_top_level_keys")

    if "profile" in policy and policy["profile"] not in KNOWN_PROFILES:
        _reject_unsupported("unknown_profile")

    if "text" in policy:
        _validate_nested(policy["text"], TEXT_ALLOWED_KEYS, "text")
        text = policy["text"]
        if "default_action" in text and text["default_action"] not in TEXT_ACTIONS:
            _reject_unsupported("unknown_text_action")

    if "memo" in policy:
        _validate_nested(policy["memo"], MEMO_ALLOWED_KEYS, "memo")
        memo = policy["memo"]
        for key in ("text", "binary"):
            if key in memo and memo[key] not in MEMO_ACTIONS:
                _reject_unsupported("unknown_memo_action")

    if "temporal" in policy:
        _validate_nested(policy["temporal"], TEMPORAL_ALLOWED_KEYS, "temporal")
        temporal = policy["temporal"]
        for key in ("date", "datetime"):
            if key in temporal and temporal[key] not in TEMPORAL_ACTIONS:
                _reject_unsupported("unknown_temporal_action")

    if "numeric" in policy:
        _validate_nested(policy["numeric"], NUMERIC_ALLOWED_KEYS, "numeric")
        numeric = policy["numeric"]
        if "default_action" in numeric and numeric["default_action"] not in NUMERIC_ACTIONS:
            _reject_unsupported("unknown_numeric_action")

    if "relationships" in policy:
        _validate_nested(policy["relationships"], RELATIONSHIPS_ALLOWED_KEYS, "relationships")
        rel = policy["relationships"]
        if rel.get("metadata_file") is not None:
            _reject_unsupported("metadata_file_not_implemented")

    if "indexes" in policy:
        _validate_nested(policy["indexes"], INDEXES_ALLOWED_KEYS, "indexes")
        idx = policy["indexes"]
        if "profile" in idx and idx["profile"] not in SUPPORTED_INDEX_PROFILES:
            _reject_unsupported("unknown_index_profile")


def _merge_with_defaults(policy: Mapping[str, Any] | None) -> dict[str, Any]:
    """Merge user policy over documented defaults (explicit args > JSON > defaults)."""
    if policy is None:
        return dict(DEFAULT_POLICY)
    merged: dict[str, Any] = json.loads(json.dumps(DEFAULT_POLICY))
    _deep_merge(merged, dict(policy))
    return merged


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def compute_policy_fingerprint(policy: Mapping[str, Any]) -> str:
    """Compute a deterministic SHA-256 fingerprint from canonical policy JSON."""
    try:
        canonical = json.dumps(dict(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise PolicyError(
            ErrorCode.POLICY_INVALID,
            context=ErrorContext(operation="build_plan", detail_code="non_serializable_policy"),
        ) from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resolve_policy(
    policy: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], str]:
    """Validate and resolve the policy. Returns (merged_policy, fingerprint)."""
    if policy is not None:
        for value in _iter_leaves(policy):
            if not isinstance(value, (type(None), bool, int, float, str)):
                raise PolicyError(
                    ErrorCode.POLICY_INVALID,
                    context=ErrorContext(operation="build_plan", detail_code="non_json_policy_value"),
                )
    merged = _merge_with_defaults(policy)
    _validate_policy(merged)
    fingerprint = compute_policy_fingerprint(merged)
    return merged, fingerprint


def _iter_leaves(obj: Any) -> Any:
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_leaves(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _iter_leaves(item)
    else:
        yield obj


def classify_field_transform(
    dbf_type: str,
    is_binary: bool,
    merged_policy: Mapping[str, Any],
) -> str | None:
    """Determine if a field type is transformed and which action applies.

    Returns the action code (e.g. "PSEUDONYMIZE_REVERSIBLE") or None if KEEP.
    Uses the DBF type code and the binary flag from FieldInfo.
    """
    upper_type = dbf_type.upper()

    if upper_type in ("C", "V"):
        text_section = merged_policy.get("text")
        if isinstance(text_section, dict):
            action: str = text_section.get("default_action", "PSEUDONYMIZE_REVERSIBLE")
        else:
            action = "PSEUDONYMIZE_REVERSIBLE"
    elif upper_type == "M":
        memo_section = merged_policy.get("memo")
        if isinstance(memo_section, dict):
            action = memo_section.get("text", "MASK_REVERSIBLE")
        else:
            action = "MASK_REVERSIBLE"
    elif upper_type in ("G", "P"):
        memo_section = merged_policy.get("memo")
        if isinstance(memo_section, dict):
            action = memo_section.get("binary", "MASK_REVERSIBLE")
        else:
            action = "MASK_REVERSIBLE"
    elif upper_type == "D":
        temporal_section = merged_policy.get("temporal")
        if isinstance(temporal_section, dict):
            action = temporal_section.get("date", "SHIFT_REVERSIBLE")
        else:
            action = "SHIFT_REVERSIBLE"
    elif upper_type == "T":
        temporal_section = merged_policy.get("temporal")
        if isinstance(temporal_section, dict):
            action = temporal_section.get("datetime", "SHIFT_REVERSIBLE")
        else:
            action = "SHIFT_REVERSIBLE"
    elif upper_type in ("N", "I", "F", "Y", "B", "L"):
        numeric_section = merged_policy.get("numeric")
        if isinstance(numeric_section, dict):
            action = numeric_section.get("default_action", "KEEP")
        else:
            action = "KEEP"
    else:
        action = "KEEP"

    if action == "KEEP":
        return None
    return action
