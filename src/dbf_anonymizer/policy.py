"""Strict data-only privacy-policy model for DBF_Anonymizer 1.0.

The policy format is versioned JSON.  It contains no executable hooks and is
parsed fail-closed: unknown keys, profiles and actions are rejected with a
stable typed policy error.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

from .errors import ErrorCode, ErrorContext, PolicyError
from .models import JsonDict, TransferProfile

POLICY_SCHEMA_VERSION = 1
DEFAULT_PROFILE = "SAFE_TRANSFER"

_TEXT_ACTIONS = frozenset({"PSEUDONYMIZE_REVERSIBLE", "KEEP"})
_MEMO_ACTIONS = frozenset({"MASK_REVERSIBLE", "KEEP"})
_TEMPORAL_ACTIONS = frozenset({"SHIFT_REVERSIBLE", "KEEP"})
_NUMERIC_ACTIONS = frozenset({"KEEP"})


def _policy_error(detail_code: str, *, unsupported: bool = False) -> PolicyError:
    return PolicyError(
        ErrorCode.POLICY_UNSUPPORTED if unsupported else ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


def _expect_keys(value: Mapping[str, object], allowed: frozenset[str], *, code: str) -> None:
    if not set(value).issubset(allowed):
        raise _policy_error(code)


def _object(value: object, *, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _policy_error(code)
    return cast(Mapping[str, object], value)


def _string(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise _policy_error(code)
    return value


def _action(value: object, allowed: frozenset[str], *, code: str) -> str:
    action = _string(value, code=code)
    if action not in allowed:
        raise _policy_error(code, unsupported=True)
    return action


@dataclass(frozen=True, slots=True)
class PrivacyPolicy:
    """Resolved immutable 1.0 policy used by planning and later execution."""

    schema_version: int = POLICY_SCHEMA_VERSION
    profile: str = DEFAULT_PROFILE
    text_default_action: str = "PSEUDONYMIZE_REVERSIBLE"
    text_domain: str = "GLOBAL_TEXT"
    memo_text_action: str = "MASK_REVERSIBLE"
    memo_binary_action: str = "MASK_REVERSIBLE"
    date_action: str = "SHIFT_REVERSIBLE"
    datetime_action: str = "SHIFT_REVERSIBLE"
    numeric_default_action: str = "KEEP"
    relationship_metadata_file: str | None = None
    index_profile: TransferProfile = TransferProfile.DATA_ONLY

    def __post_init__(self) -> None:
        if self.schema_version != POLICY_SCHEMA_VERSION:
            raise _policy_error("POLICY_SCHEMA_VERSION")
        if self.profile != DEFAULT_PROFILE:
            raise _policy_error("POLICY_PROFILE", unsupported=True)
        if self.text_default_action not in _TEXT_ACTIONS:
            raise _policy_error("TEXT_DEFAULT_ACTION", unsupported=True)
        if not self.text_domain or any(ch.isspace() for ch in self.text_domain):
            raise _policy_error("TEXT_DOMAIN")
        if self.memo_text_action not in _MEMO_ACTIONS:
            raise _policy_error("MEMO_TEXT_ACTION", unsupported=True)
        if self.memo_binary_action not in _MEMO_ACTIONS:
            raise _policy_error("MEMO_BINARY_ACTION", unsupported=True)
        if self.date_action not in _TEMPORAL_ACTIONS:
            raise _policy_error("DATE_ACTION", unsupported=True)
        if self.datetime_action not in _TEMPORAL_ACTIONS:
            raise _policy_error("DATETIME_ACTION", unsupported=True)
        if self.numeric_default_action not in _NUMERIC_ACTIONS:
            raise _policy_error("NUMERIC_DEFAULT_ACTION", unsupported=True)
        if self.relationship_metadata_file is not None:
            candidate = Path(self.relationship_metadata_file)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise _policy_error("RELATIONSHIP_METADATA_PATH")

    def to_dict(self) -> JsonDict:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "text": {
                "default_action": self.text_default_action,
                "domain": self.text_domain,
            },
            "memo": {
                "text": self.memo_text_action,
                "binary": self.memo_binary_action,
            },
            "temporal": {
                "date": self.date_action,
                "datetime": self.datetime_action,
            },
            "numeric": {"default_action": self.numeric_default_action},
            "relationships": {"metadata_file": self.relationship_metadata_file},
            "indexes": {"profile": self.index_profile.value},
        }

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


PolicyInput: TypeAlias = PrivacyPolicy | Mapping[str, object] | str | Path | None


def policy_from_mapping(raw: Mapping[str, object]) -> PrivacyPolicy:
    """Strictly parse one versioned policy mapping."""

    _expect_keys(
        raw,
        frozenset(
            {
                "schema_version",
                "profile",
                "text",
                "memo",
                "temporal",
                "numeric",
                "relationships",
                "indexes",
            }
        ),
        code="UNKNOWN_TOP_LEVEL_KEY",
    )
    schema_version = raw.get("schema_version", POLICY_SCHEMA_VERSION)
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise _policy_error("POLICY_SCHEMA_VERSION")
    profile = _string(raw.get("profile", DEFAULT_PROFILE), code="POLICY_PROFILE")

    text = _object(raw.get("text", {}), code="TEXT_OBJECT")
    _expect_keys(text, frozenset({"default_action", "domain"}), code="UNKNOWN_TEXT_KEY")
    text_action = _action(
        text.get("default_action", "PSEUDONYMIZE_REVERSIBLE"),
        _TEXT_ACTIONS,
        code="TEXT_DEFAULT_ACTION",
    )
    text_domain = _string(text.get("domain", "GLOBAL_TEXT"), code="TEXT_DOMAIN")

    memo = _object(raw.get("memo", {}), code="MEMO_OBJECT")
    _expect_keys(memo, frozenset({"text", "binary"}), code="UNKNOWN_MEMO_KEY")
    memo_text = _action(memo.get("text", "MASK_REVERSIBLE"), _MEMO_ACTIONS, code="MEMO_TEXT_ACTION")
    memo_binary = _action(
        memo.get("binary", "MASK_REVERSIBLE"), _MEMO_ACTIONS, code="MEMO_BINARY_ACTION"
    )

    temporal = _object(raw.get("temporal", {}), code="TEMPORAL_OBJECT")
    _expect_keys(temporal, frozenset({"date", "datetime"}), code="UNKNOWN_TEMPORAL_KEY")
    date_action = _action(
        temporal.get("date", "SHIFT_REVERSIBLE"), _TEMPORAL_ACTIONS, code="DATE_ACTION"
    )
    datetime_action = _action(
        temporal.get("datetime", "SHIFT_REVERSIBLE"),
        _TEMPORAL_ACTIONS,
        code="DATETIME_ACTION",
    )

    numeric = _object(raw.get("numeric", {}), code="NUMERIC_OBJECT")
    _expect_keys(numeric, frozenset({"default_action"}), code="UNKNOWN_NUMERIC_KEY")
    numeric_action = _action(
        numeric.get("default_action", "KEEP"), _NUMERIC_ACTIONS, code="NUMERIC_DEFAULT_ACTION"
    )

    relationships = _object(raw.get("relationships", {}), code="RELATIONSHIPS_OBJECT")
    _expect_keys(
        relationships,
        frozenset({"metadata_file"}),
        code="UNKNOWN_RELATIONSHIPS_KEY",
    )
    metadata_file_raw = relationships.get("metadata_file")
    if metadata_file_raw is not None and not isinstance(metadata_file_raw, str):
        raise _policy_error("RELATIONSHIP_METADATA_PATH")

    indexes = _object(raw.get("indexes", {}), code="INDEXES_OBJECT")
    _expect_keys(indexes, frozenset({"profile"}), code="UNKNOWN_INDEXES_KEY")
    index_profile_raw = _string(indexes.get("profile", "DATA_ONLY"), code="INDEX_PROFILE")
    try:
        index_profile = TransferProfile(index_profile_raw)
    except ValueError as exc:
        raise _policy_error("INDEX_PROFILE", unsupported=True) from exc

    return PrivacyPolicy(
        schema_version=schema_version,
        profile=profile,
        text_default_action=text_action,
        text_domain=text_domain,
        memo_text_action=memo_text,
        memo_binary_action=memo_binary,
        date_action=date_action,
        datetime_action=datetime_action,
        numeric_default_action=numeric_action,
        relationship_metadata_file=metadata_file_raw,
        index_profile=index_profile,
    )


def load_policy(value: PolicyInput) -> PrivacyPolicy:
    """Resolve a policy object, mapping, JSON file, or the safe default."""

    if value is None:
        return PrivacyPolicy()
    if isinstance(value, PrivacyPolicy):
        return value
    if isinstance(value, Mapping):
        return policy_from_mapping(cast(Mapping[str, object], value))

    path = Path(value)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise _policy_error("POLICY_FILE_UNREADABLE") from exc
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise _policy_error("POLICY_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise _policy_error("POLICY_ROOT_OBJECT")
    return policy_from_mapping(cast(Mapping[str, object], payload))


__all__ = [
    "POLICY_SCHEMA_VERSION",
    "DEFAULT_PROFILE",
    "PrivacyPolicy",
    "PolicyInput",
    "load_policy",
    "policy_from_mapping",
]
