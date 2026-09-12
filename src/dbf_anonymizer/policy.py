"""Policy resolution and fingerprint for REQ-P1-005 read-only planning.

Validates a versioned JSON policy dictionary and computes a deterministic
SHA-256 fingerprint. No transformation is performed at planning time.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from dbf_anonymizer.errors import PolicyError, ErrorCode, ErrorContext

KNOWN_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "profile", "text", "memo", "temporal", "numeric", "relationships", "indexes"}
)

KNOWN_ACTIONS = frozenset(
    {
        "PSEUDONYMIZE_REVERSIBLE",
        "MASK_REVERSIBLE",
        "SHIFT_REVERSIBLE",
        "KEEP",
    }
)

KNOWN_PROFILES = frozenset({"SAFE_TRANSFER", "DATA_ONLY"})

TEXT_ACTIONS = frozenset({"PSEUDONYMIZE_REVERSIBLE", "KEEP"})
MEMO_ACTIONS = frozenset({"MASK_REVERSIBLE", "KEEP"})
TEMPORAL_ACTIONS = frozenset({"SHIFT_REVERSIBLE", "KEEP"})
NUMERIC_ACTIONS = frozenset({"KEEP", "PSEUDONYMIZE_REVERSIBLE"})

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


def _validate_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the policy structure. Raises PolicyError on any violation."""
    ctx = ErrorContext(operation="build_plan", detail_code="policy_validation")

    if "schema_version" not in policy:
        raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx, )

    sv = policy["schema_version"]
    if not isinstance(sv, int) or isinstance(sv, bool) or sv < 1:
        raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx)

    unknown_top = set(policy.keys()) - KNOWN_TOP_LEVEL_KEYS
    if unknown_top:
        raise PolicyError(
            ErrorCode.POLICY_INVALID,
            context=ErrorContext(operation="build_plan", detail_code="unknown_policy_keys"),
        )

    if "profile" in policy:
        if policy["profile"] not in KNOWN_PROFILES:
            raise PolicyError(
                ErrorCode.POLICY_UNSUPPORTED,
                context=ErrorContext(operation="build_plan", detail_code="unknown_profile"),
            )

    if "text" in policy:
        text = policy["text"]
        if not isinstance(text, dict):
            raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx)
        if "default_action" in text and text["default_action"] not in TEXT_ACTIONS:
            raise PolicyError(
                ErrorCode.POLICY_UNSUPPORTED,
                context=ErrorContext(operation="build_plan", detail_code="unknown_text_action"),
            )

    if "memo" in policy:
        memo = policy["memo"]
        if not isinstance(memo, dict):
            raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx)
        for key in ("text", "binary"):
            if key in memo and memo[key] not in MEMO_ACTIONS:
                raise PolicyError(
                    ErrorCode.POLICY_UNSUPPORTED,
                    context=ErrorContext(operation="build_plan", detail_code="unknown_memo_action"),
                )

    if "temporal" in policy:
        temporal = policy["temporal"]
        if not isinstance(temporal, dict):
            raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx)
        for key in ("date", "datetime"):
            if key in temporal and temporal[key] not in TEMPORAL_ACTIONS:
                raise PolicyError(
                    ErrorCode.POLICY_UNSUPPORTED,
                    context=ErrorContext(operation="build_plan", detail_code="unknown_temporal_action"),
                )

    if "numeric" in policy:
        numeric = policy["numeric"]
        if not isinstance(numeric, dict):
            raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx)
        if "default_action" in numeric and numeric["default_action"] not in NUMERIC_ACTIONS:
            raise PolicyError(
                ErrorCode.POLICY_UNSUPPORTED,
                context=ErrorContext(operation="build_plan", detail_code="unknown_numeric_action"),
            )

    if "relationships" in policy:
        rel = policy["relationships"]
        if not isinstance(rel, dict):
            raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx)

    if "indexes" in policy:
        idx = policy["indexes"]
        if not isinstance(idx, dict):
            raise PolicyError(ErrorCode.POLICY_INVALID, context=ctx)

    return dict(policy)


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
    canonical = json.dumps(dict(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resolve_policy(
    policy: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], str]:
    """Validate and resolve the policy. Returns (merged_policy, fingerprint)."""
    merged = _merge_with_defaults(policy)
    _validate_policy(merged)
    fingerprint = compute_policy_fingerprint(merged)
    return merged, fingerprint


def classify_field_transform(dbf_type: str, merged_policy: Mapping[str, Any]) -> str | None:
    """Determine if a field type is transformed and which action applies.

    Returns the action code (e.g. "PSEUDONYMIZE_REVERSIBLE") or None if KEEP.
    """
    upper_type = dbf_type.upper()

    if upper_type in ("C", "M"):
        if upper_type == "C":
            text_section = merged_policy.get("text")
            action: str = text_section.get("default_action", "PSEUDONYMIZE_REVERSIBLE") if isinstance(text_section, dict) else "PSEUDONYMIZE_REVERSIBLE"
        else:
            memo_section = merged_policy.get("memo")
            action = memo_section.get("text", "MASK_REVERSIBLE") if isinstance(memo_section, dict) else "MASK_REVERSIBLE"
    elif upper_type == "D":
        temporal_section = merged_policy.get("temporal")
        action = temporal_section.get("date", "SHIFT_REVERSIBLE") if isinstance(temporal_section, dict) else "SHIFT_REVERSIBLE"
    elif upper_type == "T":
        temporal_section = merged_policy.get("temporal")
        action = temporal_section.get("datetime", "SHIFT_REVERSIBLE") if isinstance(temporal_section, dict) else "SHIFT_REVERSIBLE"
    elif upper_type in ("N", "I", "F", "B"):
        numeric_section = merged_policy.get("numeric")
        action = numeric_section.get("default_action", "KEEP") if isinstance(numeric_section, dict) else "KEEP"
    else:
        action = "KEEP"

    if action == "KEEP":
        return None
    return action
