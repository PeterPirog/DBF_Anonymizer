"""Policy resolution and fingerprint for REQ-P1-005 read-only planning.

Validates a versioned JSON policy dictionary with strict fail-closed
nested-key allowlists and computes a deterministic SHA-256 fingerprint.
No transformation is performed at planning time.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from dbf_anonymizer.errors import PolicyError, ErrorCode, ErrorContext

KNOWN_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "profile", "text", "memo", "temporal", "numeric", "relationships", "indexes"}
)

SUPPORTED_TOP_LEVEL_PROFILES = frozenset({"SAFE_TRANSFER"})
SUPPORTED_TEXT_DOMAINS = frozenset({"GLOBAL_TEXT"})

TEXT_ACTIONS = frozenset({"PSEUDONYMIZE_REVERSIBLE", "KEEP"})
MEMO_ACTIONS = frozenset({"MASK_REVERSIBLE", "KEEP"})
TEMPORAL_ACTIONS = frozenset({"SHIFT_REVERSIBLE", "KEEP"})
NUMERIC_ACTIONS = frozenset({"KEEP"})

TEXT_ALLOWED_KEYS = frozenset({"default_action", "domain"})
MEMO_ALLOWED_KEYS = frozenset({"text", "binary"})
TEMPORAL_ALLOWED_KEYS = frozenset({"date", "datetime"})
NUMERIC_ALLOWED_KEYS = frozenset({"default_action"})
RELATIONSHIPS_ALLOWED_KEYS = frozenset({"metadata_file"})
INDEXES_ALLOWED_KEYS = frozenset({"profile"})

SUPPORTED_INDEX_PROFILES = frozenset({"DATA_ONLY", "VFP_INDEXED"})

SUPPORTED_SCHEMA_VERSION = 1

FIELD_CAPABILITY_MATRIX_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class FieldCapabilityRule:
    """One immutable row in the authoritative field capability matrix."""

    dbf_types: tuple[str, ...]
    logical_class: str
    disposition: str
    default_action: str | None
    policy_section: str | None
    policy_key: str | None
    binary_descriptor_allowed: bool
    nocptrans_allowed: bool


# Matrix order is part of the deterministic versioned snapshot.  Every
# planning, preflight and execution consumer delegates field classification to
# ``classify_field_capability`` below rather than maintaining a type switch.
FIELD_CAPABILITY_MATRIX: tuple[FieldCapabilityRule, ...] = (
    FieldCapabilityRule(
        ("C", "V"),
        "TEXT",
        "TRANSFORM",
        "PSEUDONYMIZE_REVERSIBLE",
        "text",
        "default_action",
        False,
        False,
    ),
    FieldCapabilityRule(
        ("M",),
        "MEMO_TEXT_OR_BINARY_PAYLOAD",
        "TRANSFORM",
        "MASK_REVERSIBLE",
        "memo",
        "text",
        False,
        False,
    ),
    FieldCapabilityRule(
        ("G", "P"),
        "BINARY_MEMO",
        "TRANSFORM",
        "MASK_REVERSIBLE",
        "memo",
        "binary",
        True,
        True,
    ),
    FieldCapabilityRule(
        ("D",),
        "DATE",
        "TRANSFORM",
        "SHIFT_REVERSIBLE",
        "temporal",
        "date",
        False,
        True,
    ),
    FieldCapabilityRule(
        ("T",),
        "DATETIME",
        "TRANSFORM",
        "SHIFT_REVERSIBLE",
        "temporal",
        "datetime",
        False,
        True,
    ),
    FieldCapabilityRule(
        ("N", "F", "I", "Y", "B", "L"),
        "SCALAR_IDENTITY",
        "IDENTITY",
        None,
        None,
        None,
        False,
        True,
    ),
)

_RULE_BY_DBF_TYPE = {
    dbf_type: rule
    for rule in FIELD_CAPABILITY_MATRIX
    for dbf_type in rule.dbf_types
}


def field_capability_matrix_snapshot() -> dict[str, object]:
    """Return the deterministic JSON-safe identity of the matrix contract."""

    return {
        "schema_version": FIELD_CAPABILITY_MATRIX_VERSION,
        "trusted_system_field": {
            "dbf_type": "0",
            "name": "_NULLFLAGS",
            "system": True,
            "disposition": "WRITER_MANAGED",
        },
        "fallback_disposition": "UNSAFE",
        "rules": [
            {
                "dbf_types": list(rule.dbf_types),
                "logical_class": rule.logical_class,
                "disposition": rule.disposition,
                "default_action": rule.default_action,
                "policy_section": rule.policy_section,
                "policy_key": rule.policy_key,
                "binary_descriptor_allowed": rule.binary_descriptor_allowed,
                "nocptrans_allowed": rule.nocptrans_allowed,
            }
            for rule in FIELD_CAPABILITY_MATRIX
        ],
    }

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

    if "profile" in policy and policy["profile"] not in SUPPORTED_TOP_LEVEL_PROFILES:
        _reject_unsupported("unsupported_top_level_profile")

    if "text" in policy:
        _validate_nested(policy["text"], TEXT_ALLOWED_KEYS, "text")
        text = policy["text"]
        if "default_action" in text and text["default_action"] not in TEXT_ACTIONS:
            _reject_unsupported("unknown_text_action")
        if "domain" in text and text["domain"] not in SUPPORTED_TEXT_DOMAINS:
            _reject_unsupported("unsupported_text_domain")

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
            _reject_unsupported("unsupported_numeric_action")

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


def classify_field_capability(
    dbf_type: str,
    field_name: str,
    is_supported: bool,
    is_binary: bool,
    is_system: bool,
    nocptrans: bool,
    merged_policy: Mapping[str, Any],
) -> tuple[str | None, bool, bool]:
    """Classify a field's planning capability.

    Returns (action_or_None, is_unsafe, is_system):
    - (action, False, False) = SAFE_TRANSFORM
    - (None, False, False) = IDENTITY (KEEP)
    - (None, True, False) = UNSAFE (requires future preflight rejection)
    - (None, False, True) = SYSTEM (writer-managed, not user data)
    """
    # The descriptor system bit alone does not establish writer ownership.
    # Only the known VFP NULL bitmap is trusted from public FieldInfo facts.
    if dbf_type == "0" and is_system and field_name.upper() == "_NULLFLAGS":
        return (None, False, True)

    if is_system or not is_supported:
        return (None, True, False)

    rule = _RULE_BY_DBF_TYPE.get(dbf_type.upper())
    if rule is None:
        return (None, True, False)
    if is_binary and not rule.binary_descriptor_allowed:
        return (None, True, False)
    if nocptrans and not rule.nocptrans_allowed:
        return (None, True, False)
    if rule.disposition == "IDENTITY":
        return (None, False, False)

    assert rule.default_action is not None
    assert rule.policy_section is not None
    assert rule.policy_key is not None
    section = merged_policy.get(rule.policy_section)
    action = (
        str(section.get(rule.policy_key, rule.default_action))
        if isinstance(section, dict)
        else rule.default_action
    )
    if action == "KEEP":
        return (None, False, False)
    return (action, False, False)
