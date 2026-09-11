"""Immutable typed public models (REQ-P1-002).

Every model in this module is a frozen, strictly-typed value object with a
strict, versioned, JSON-safe serialization contract:

- ``PUBLIC_MODEL_SCHEMA_VERSION`` is the single supported serialization
  schema version; EVERY public model's ``to_dict()`` embeds
  ``"schema_version"`` plus a ``"model"`` discriminator and every
  ``from_dict()`` validates both (strictly: integer only — ``True``, floats
  and future versions are rejected);
- construction-time invariants: path-bearing fields are normalized to
  relative POSIX form in ``__post_init__`` (``north\\t.dbf`` is stored as
  ``north/t.dbf``) and absolute, drive, UNC, traversal and NUL paths are
  rejected; collection fields canonicalize accepted sequences to immutable
  tuples and reject strings, sets and mappings, so a successfully
  constructed public model can never serialize an absolute/private path or
  retain mutable collection state;
- strict parsing: JSON arrays are validated element-by-element with no
  silent filtering and no scalar-to-string path coercion;
- parser errors echo fixed schema key names only — never caller-controlled
  unknown key names, unknown values or rejected paths;
- no field name in this module can carry an original source value
  (``raw_value``, ``original_value``, ``sample``, ``record``, free-form
  ``metadata``/``context``/``details`` mapping bags and similar channels are
  deliberately absent).

The enums and ``comparison_semantics`` strings carry architecture vocabulary
only; defining them does not implement REQ-P3-007, REQ-P3-001 processing,
REQ-P5-001, REQ-P1-005 or any other later requirement.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar

PUBLIC_MODEL_SCHEMA_VERSION = 1

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_NUL = "\x00"
_EnumT = TypeVar("_EnumT", bound=Enum)
_SubmodelT = TypeVar("_SubmodelT")

#: Field names that must never appear on a public model (original-value or
#: open-ended payload channels).  Enforced by the privacy contract tests.
FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "raw_value",
        "original_value",
        "source_value",
        "sample",
        "record",
        "memo_payload",
        "binary_payload",
        "arbitrary_data",
        "metadata",
        "context",
        "details",
    }
)

#: Declared logical comparison semantics for relation groups (REQ-P3-001
#: data-contract vocabulary, typed as a stable string constant).
COMPARISON_SEMANTICS_EXACT = "exact-logical-value"


class RelationalAssurance(str, Enum):
    """Architecture assurance vocabulary (REQ-P3-007 semantics, typed only)."""

    GLOBAL_EXACT_VALUE = "GLOBAL_EXACT_VALUE"
    DECLARED_RELATIONS_VERIFIED = "DECLARED_RELATIONS_VERIFIED"
    VFP_METADATA_VERIFIED = "VFP_METADATA_VERIFIED"
    INCOMPLETE = "INCOMPLETE"


class VerificationStatus(str, Enum):
    """Verification vocabulary (REQ-P5-001 semantics, typed only)."""

    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"


class ResultStatus(str, Enum):
    """Operational outcome status of result models (model-level only)."""

    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


def _normalize_relative_path(path: str) -> str:
    """Validate and normalize one public relative path.

    Normalization is deterministic on Windows and Linux: backslashes become
    forward slashes and the result is a POSIX-style relative path with no
    empty, dot or dot-dot components.  Rejection messages never echo the
    rejected value.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("a path field requires a non-empty relative path")
    if _NUL in path:
        raise ValueError("path fields must not contain NUL")
    if path.startswith("/") or path.startswith("\\"):
        raise ValueError("path fields must be relative, not rooted")
    if _DRIVE_PREFIX.match(path):
        raise ValueError("path fields must not contain a drive prefix")
    normalized = path.replace("\\", "/")
    if normalized.startswith("//"):
        raise ValueError("path fields must not be UNC paths")
    for component in normalized.split("/"):
        if component == "":
            raise ValueError("path fields must not contain empty components")
        if component == ".":
            raise ValueError("path fields must not contain dot components")
        if component == "..":
            raise ValueError("path fields must not contain parent traversal")
    return normalized


def _optional_path(path: str | None) -> str | None:
    return None if path is None else _normalize_relative_path(path)


def _canonical_path_sequence(items: object, key: str) -> tuple[str, ...]:
    """Construction-time canonicalization of a path collection.

    Accepts lists/tuples of plain strings (each backslash-relative path is
    normalized); rejects strings (no character splitting), sets, mappings and
    any non-string member without coercion.
    """
    if isinstance(items, (str, bytes, bytearray, Mapping, set, frozenset)) or not isinstance(
        items, (list, tuple)
    ):
        raise ValueError(f"key {key!r} must be a list or tuple of relative paths")
    return tuple(_normalize_relative_path(item) for item in items)


def _canonical_submodel_sequence(
    items: object, expected: type, key: str
) -> tuple[object, ...]:
    """Construction-time canonicalization of a frozen-model collection.

    Every member must already be an instance of the expected frozen public
    model; strings, mappings and other types are rejected (no implicit
    conversion).  Mutable list input is canonicalized to an immutable tuple.
    """
    if isinstance(items, (str, bytes, bytearray, Mapping, set, frozenset)) or not isinstance(
        items, (list, tuple)
    ):
        raise ValueError(f"key {key!r} must be a list or tuple of {expected.__name__} values")
    for item in items:
        if not isinstance(item, expected):
            raise ValueError(f"key {key!r} members must be {expected.__name__} instances")
    return tuple(items)


def _canonical_enum(value: object, enum_type: type[_EnumT], key: str) -> _EnumT:
    """Construction-time canonicalization of a status/assurance field."""
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError:
            raise ValueError(
                f"key {key!r} must be one of {[member.value for member in enum_type]}"
            ) from None
    raise ValueError(f"key {key!r} must be a valid {enum_type.__name__} value")


def _canonical_index(value: object, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"key {key!r} must be a zero-based non-negative integer")
    return value


# ---------------------------------------------------------------------------
# strict, privacy-safe deserialization helpers (stdlib exceptions only)
# ---------------------------------------------------------------------------


def _fail(key: str, expectation: str) -> ValueError:
    return ValueError(f"invalid public model payload: key {key!r} {expectation}")


def _require_str(data: Mapping[str, object], key: str) -> str:
    value = data[key]
    if not isinstance(value, str):
        raise _fail(key, "must be a string")
    return value


def _require_optional_str(data: Mapping[str, object], key: str) -> str | None:
    value = data[key]
    if value is None:
        return None
    if not isinstance(value, str):
        raise _fail(key, "must be a string or null")
    return value


def _require_bool(data: Mapping[str, object], key: str) -> bool:
    value = data[key]
    if not isinstance(value, bool):
        raise _fail(key, "must be a boolean")
    return value


def _require_int(data: Mapping[str, object], key: str) -> int:
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(key, "must be an integer")
    return value


def _require_optional_int(data: Mapping[str, object], key: str) -> int | None:
    value = data[key]
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(key, "must be an integer or null")
    return value


def _require_path(data: Mapping[str, object], key: str) -> str:
    value = data[key]
    if not isinstance(value, str):
        raise _fail(key, "must be a relative path string")
    return _normalize_relative_path(value)


def _require_optional_path(data: Mapping[str, object], key: str) -> str | None:
    value = data[key]
    if value is None:
        return None
    if not isinstance(value, str):
        raise _fail(key, "must be a relative path string or null")
    return _normalize_relative_path(value)


def _require_string_tuple(data: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = data[key]
    if isinstance(value, (str, bytes, bytearray, Mapping, set, frozenset)) or not isinstance(
        value, (list, tuple)
    ):
        raise _fail(key, "must be an array of strings")
    for item in value:
        if not isinstance(item, str):
            raise _fail(key, "must be an array of strings")
    return tuple(value)


def _require_path_tuple(data: Mapping[str, object], key: str) -> tuple[str, ...]:
    """Strict path-array parsing: every member must already be a plain string
    (no coercion from int/bool/float/object); the array itself must be a list
    or tuple, not a string/set/mapping."""
    value = data[key]
    if isinstance(value, (str, bytes, bytearray, Mapping, set, frozenset)) or not isinstance(
        value, (list, tuple)
    ):
        raise _fail(key, "must be an array of relative path strings")
    for item in value:
        if not isinstance(item, str):
            raise _fail(key, "must be an array of relative path strings")
    return tuple(_normalize_relative_path(item) for item in value)


def _require_enum(enum_type: type[_EnumT], data: Mapping[str, object], key: str) -> _EnumT:
    value = data[key]
    if not isinstance(value, str):
        raise _fail(key, "must be a string enum value")
    try:
        return enum_type(value)
    except ValueError:
        raise _fail(key, f"must be one of {[member.value for member in enum_type]}") from None


def _require_submodel(
    parse: Callable[[Mapping[str, object]], _SubmodelT],
    data: Mapping[str, object],
    key: str,
) -> _SubmodelT:
    value = data[key]
    if not isinstance(value, Mapping):
        raise _fail(key, "must be an object")
    return parse(value)


def _require_submodel_sequence(
    parse: Callable[[Mapping[str, object]], _SubmodelT],
    data: Mapping[str, object],
    key: str,
) -> tuple[_SubmodelT, ...]:
    """Strict child-array parsing: EVERY element must be a mapping of the
    expected child model; one malformed element rejects the whole payload
    (no silent filtering)."""
    value = data[key]
    if isinstance(value, (str, bytes, bytearray, Mapping, set, frozenset)) or not isinstance(
        value, (list, tuple)
    ):
        raise _fail(key, "must be an array of objects")
    for item in value:
        if not isinstance(item, Mapping):
            raise _fail(key, "must be an array of objects")
    return tuple(parse(item) for item in value)


def _validate_keys(data: Mapping[str, object], allowed: frozenset[str]) -> None:
    """Strict key validation.

    Unknown keys are caller-controlled strings; the error must not echo them.
    Missing mandatory keys are fixed schema identifiers and may be named.
    """
    if set(data) - allowed:
        raise ValueError(
            f"unknown public model keys: {len(set(data) - allowed)} unknown key(s)"
        )
    missing = sorted(allowed - set(data))
    if missing:
        raise ValueError(f"missing mandatory public model keys: {missing}")


def _validated_discriminator(data: Mapping[str, object], model: str) -> None:
    if data.get("model") != model:
        raise ValueError(f"wrong public model discriminator: expected {model!r}")
    version = data.get("schema_version")
    if type(version) is not int or version != PUBLIC_MODEL_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported public model schema version: expected integer "
            f"{PUBLIC_MODEL_SCHEMA_VERSION!r}"
        )


def _top_level_keys(model: str, *fields: str) -> frozenset[str]:
    return frozenset({"model", "schema_version", *fields})


# ---------------------------------------------------------------------------
# nested public models (all versioned; all construction-time canonicalized)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldPlan:
    """Per-field plan identifiers (no record values)."""

    field_name: str
    dbf_type: str
    action: str
    domain: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.field_name, str) or not self.field_name:
            raise ValueError("key 'field_name' must be a non-empty string")
        if not isinstance(self.dbf_type, str) or not self.dbf_type:
            raise ValueError("key 'dbf_type' must be a non-empty string")
        if not isinstance(self.action, str) or not self.action:
            raise ValueError("key 'action' must be a non-empty string")
        if self.domain is not None and not isinstance(self.domain, str):
            raise ValueError("key 'domain' must be a string or null")

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "FieldPlan",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "field_name": self.field_name,
            "dbf_type": self.dbf_type,
            "action": self.action,
            "domain": self.domain,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> FieldPlan:
        _validate_keys(
            data, _top_level_keys("FieldPlan", "field_name", "dbf_type", "action", "domain")
        )
        _validated_discriminator(data, "FieldPlan")
        return cls(
            field_name=_require_str(data, "field_name"),
            dbf_type=_require_str(data, "dbf_type"),
            action=_require_str(data, "action"),
            domain=_require_optional_str(data, "domain"),
        )


@dataclass(frozen=True, slots=True)
class TablePlan:
    relative_path: str
    schema_fingerprint: str
    fields: tuple[FieldPlan, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", _normalize_relative_path(self.relative_path))
        object.__setattr__(
            self, "fields", _canonical_submodel_sequence(self.fields, FieldPlan, "fields")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "TablePlan",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "relative_path": self.relative_path,
            "schema_fingerprint": self.schema_fingerprint,
            "fields": [field.to_dict() for field in self.fields],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> TablePlan:
        _validate_keys(
            data, _top_level_keys("TablePlan", "relative_path", "schema_fingerprint", "fields")
        )
        _validated_discriminator(data, "TablePlan")
        return cls(
            relative_path=_require_path(data, "relative_path"),
            schema_fingerprint=_require_str(data, "schema_fingerprint"),
            fields=_require_submodel_sequence(FieldPlan.from_dict, data, "fields"),
        )


@dataclass(frozen=True, slots=True)
class RelationshipMember:
    """One member of a typed relation group.

    ``component_index`` is a zero-based non-negative composite component
    number; it explicitly pairs components across primary-key and foreign-key
    members in different tables (index 0 pairs the first composite
    components, index 1 the second, and so on).
    """

    relative_path: str
    field_name: str
    role: str
    component_index: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", _normalize_relative_path(self.relative_path))
        object.__setattr__(
            self, "component_index", _canonical_index(self.component_index, "component_index")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "RelationshipMember",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "relative_path": self.relative_path,
            "field_name": self.field_name,
            "role": self.role,
            "component_index": self.component_index,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RelationshipMember:
        _validate_keys(
            data,
            _top_level_keys(
                "RelationshipMember", "relative_path", "field_name", "role", "component_index"
            ),
        )
        _validated_discriminator(data, "RelationshipMember")
        return cls(
            relative_path=_require_path(data, "relative_path"),
            field_name=_require_str(data, "field_name"),
            role=_require_str(data, "role"),
            component_index=_require_int(data, "component_index"),
        )


@dataclass(frozen=True, slots=True)
class RelationshipGroup:
    """A typed relation group (REQ-P3-001 data contract, typed only).

    ``comparison_semantics`` carries the declared logical comparison
    vocabulary (``COMPARISON_SEMANTICS_EXACT``); composite-key ordering is
    unambiguous through each member's zero-based ``component_index``.
    """

    group_id: str
    provenance: str
    comparison_semantics: str
    members: tuple[RelationshipMember, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.comparison_semantics, str) or not self.comparison_semantics:
            raise ValueError("key 'comparison_semantics' must be a non-empty string")
        object.__setattr__(
            self,
            "members",
            _canonical_submodel_sequence(self.members, RelationshipMember, "members"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "RelationshipGroup",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "group_id": self.group_id,
            "provenance": self.provenance,
            "comparison_semantics": self.comparison_semantics,
            "members": [member.to_dict() for member in self.members],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RelationshipGroup:
        _validate_keys(
            data,
            _top_level_keys(
                "RelationshipGroup", "group_id", "provenance", "comparison_semantics", "members"
            ),
        )
        _validated_discriminator(data, "RelationshipGroup")
        return cls(
            group_id=_require_str(data, "group_id"),
            provenance=_require_str(data, "provenance"),
            comparison_semantics=_require_str(data, "comparison_semantics"),
            members=_require_submodel_sequence(RelationshipMember.from_dict, data, "members"),
        )


@dataclass(frozen=True, slots=True)
class RelationshipMetadata:
    """Typed relationship metadata with a stable relationship fingerprint."""

    relationship_fingerprint: str
    provenance: str
    groups: tuple[RelationshipGroup, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "groups", _canonical_submodel_sequence(self.groups, RelationshipGroup, "groups")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "RelationshipMetadata",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "relationship_fingerprint": self.relationship_fingerprint,
            "provenance": self.provenance,
            "groups": [group.to_dict() for group in self.groups],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RelationshipMetadata:
        _validate_keys(
            data,
            _top_level_keys(
                "RelationshipMetadata", "relationship_fingerprint", "provenance", "groups"
            ),
        )
        _validated_discriminator(data, "RelationshipMetadata")
        return cls(
            relationship_fingerprint=_require_str(data, "relationship_fingerprint"),
            provenance=_require_str(data, "provenance"),
            groups=_require_submodel_sequence(RelationshipGroup.from_dict, data, "groups"),
        )


@dataclass(frozen=True, slots=True)
class PolicySummary:
    profile: str
    policy_fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "PolicySummary",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "profile": self.profile,
            "policy_fingerprint": self.policy_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PolicySummary:
        _validate_keys(data, _top_level_keys("PolicySummary", "profile", "policy_fingerprint"))
        _validated_discriminator(data, "PolicySummary")
        return cls(
            profile=_require_str(data, "profile"),
            policy_fingerprint=_require_str(data, "policy_fingerprint"),
        )


@dataclass(frozen=True, slots=True)
class PreflightIssue:
    """One typed preflight issue (code plus optional normalized identifiers)."""

    code: str
    table: str | None
    field_name: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "table", _optional_path(self.table))
        if self.field_name is not None and not isinstance(self.field_name, str):
            raise ValueError("key 'field_name' must be a string or null")

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "PreflightIssue",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "code": self.code,
            "table": self.table,
            "field_name": self.field_name,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PreflightIssue:
        _validate_keys(data, _top_level_keys("PreflightIssue", "code", "table", "field_name"))
        _validated_discriminator(data, "PreflightIssue")
        return cls(
            code=_require_str(data, "code"),
            table=_require_optional_path(data, "table"),
            field_name=_require_optional_str(data, "field_name"),
        )


# ---------------------------------------------------------------------------
# top-level public models (all versioned; all construction-time canonicalized)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Capabilities:
    product_version: str
    dbfbridge_version: str
    supported_profiles: tuple[str, ...]
    features: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "supported_profiles",
            _string_sequence(self.supported_profiles, "supported_profiles"),
        )
        object.__setattr__(self, "features", _string_sequence(self.features, "features"))

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "Capabilities",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "product_version": self.product_version,
            "dbfbridge_version": self.dbfbridge_version,
            "supported_profiles": list(self.supported_profiles),
            "features": list(self.features),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Capabilities:
        _validate_keys(
            data,
            _top_level_keys(
                "Capabilities",
                "product_version",
                "dbfbridge_version",
                "supported_profiles",
                "features",
            ),
        )
        _validated_discriminator(data, "Capabilities")
        return cls(
            product_version=_require_str(data, "product_version"),
            dbfbridge_version=_require_str(data, "dbfbridge_version"),
            supported_profiles=_require_string_tuple(data, "supported_profiles"),
            features=_require_string_tuple(data, "features"),
        )


def _string_sequence(items: object, key: str) -> tuple[str, ...]:
    if isinstance(items, (str, bytes, bytearray, Mapping, set, frozenset)) or not isinstance(
        items, (list, tuple)
    ):
        raise ValueError(f"key {key!r} must be a list or tuple of strings")
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"key {key!r} must be a list or tuple of strings")
    return tuple(items)


@dataclass(frozen=True, slots=True)
class DatasetIdentity:
    dataset_fingerprint: str
    tables: tuple[str, ...]
    table_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "tables", _canonical_path_sequence(self.tables, "tables"))

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "DatasetIdentity",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "dataset_fingerprint": self.dataset_fingerprint,
            "tables": list(self.tables),
            "table_count": self.table_count,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> DatasetIdentity:
        _validate_keys(
            data,
            _top_level_keys("DatasetIdentity", "dataset_fingerprint", "tables", "table_count"),
        )
        _validated_discriminator(data, "DatasetIdentity")
        return cls(
            dataset_fingerprint=_require_str(data, "dataset_fingerprint"),
            tables=_require_path_tuple(data, "tables"),
            table_count=_require_int(data, "table_count"),
        )


@dataclass(frozen=True, slots=True)
class Plan:
    """The public plan data contract (REQ-P1-002 only; no planning engine).

    ``dataset_identity`` carries the stable source/dataset fingerprint;
    ``policy_summary`` the policy fingerprint; ``relationships`` the
    relationship fingerprint; ``output_strategy``/``vault_strategy``/
    ``index_strategy`` identify the future P1-005 output/vault/index strategy
    by identifier only — never by filesystem path.
    """

    dataset_identity: DatasetIdentity
    policy_summary: PolicySummary
    relationships: RelationshipMetadata
    table_plans: tuple[TablePlan, ...]
    output_strategy: str
    vault_strategy: str
    index_strategy: str
    plan_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "dataset_identity",
            _require_frozen_model(self.dataset_identity, DatasetIdentity, "dataset_identity"),
        )
        object.__setattr__(
            self, "policy_summary", _require_frozen_model(self.policy_summary, PolicySummary, "policy_summary")
        )
        object.__setattr__(
            self,
            "relationships",
            _require_frozen_model(self.relationships, RelationshipMetadata, "relationships"),
        )
        object.__setattr__(
            self, "table_plans", _canonical_submodel_sequence(self.table_plans, TablePlan, "table_plans")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "Plan",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "dataset_identity": self.dataset_identity.to_dict(),
            "policy_summary": self.policy_summary.to_dict(),
            "relationships": self.relationships.to_dict(),
            "table_plans": [table.to_dict() for table in self.table_plans],
            "output_strategy": self.output_strategy,
            "vault_strategy": self.vault_strategy,
            "index_strategy": self.index_strategy,
            "plan_fingerprint": self.plan_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Plan:
        _validate_keys(
            data,
            _top_level_keys(
                "Plan",
                "dataset_identity",
                "policy_summary",
                "relationships",
                "table_plans",
                "output_strategy",
                "vault_strategy",
                "index_strategy",
                "plan_fingerprint",
            ),
        )
        _validated_discriminator(data, "Plan")
        return cls(
            dataset_identity=_require_submodel(DatasetIdentity.from_dict, data, "dataset_identity"),
            policy_summary=_require_submodel(PolicySummary.from_dict, data, "policy_summary"),
            relationships=_require_submodel(
                RelationshipMetadata.from_dict, data, "relationships"
            ),
            table_plans=_require_submodel_sequence(TablePlan.from_dict, data, "table_plans"),
            output_strategy=_require_str(data, "output_strategy"),
            vault_strategy=_require_str(data, "vault_strategy"),
            index_strategy=_require_str(data, "index_strategy"),
            plan_fingerprint=_require_str(data, "plan_fingerprint"),
        )


def _require_frozen_model(value: object, expected: type, key: str) -> object:
    if not isinstance(value, expected):
        raise ValueError(f"key {key!r} must be an {expected.__name__} instance")
    return value


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    operation_id: str
    phase: str
    completed: int
    total: int | None
    unit: str | None
    table: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "table", _optional_path(self.table))

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "ProgressEvent",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "phase": self.phase,
            "completed": self.completed,
            "total": self.total,
            "unit": self.unit,
            "table": self.table,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> ProgressEvent:
        _validate_keys(
            data,
            _top_level_keys(
                "ProgressEvent", "operation_id", "phase", "completed", "total", "unit", "table"
            ),
        )
        _validated_discriminator(data, "ProgressEvent")
        return cls(
            operation_id=_require_str(data, "operation_id"),
            phase=_require_str(data, "phase"),
            completed=_require_int(data, "completed"),
            total=_require_optional_int(data, "total"),
            unit=_require_optional_str(data, "unit"),
            table=_require_optional_path(data, "table"),
        )


@dataclass(frozen=True, slots=True)
class PreflightResult:
    ready: bool
    issues: tuple[PreflightIssue, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "issues", _canonical_submodel_sequence(self.issues, PreflightIssue, "issues")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "PreflightResult",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "ready": self.ready,
            "issues": [issue.to_dict() for issue in self.issues],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PreflightResult:
        _validate_keys(data, _top_level_keys("PreflightResult", "ready", "issues"))
        _validated_discriminator(data, "PreflightResult")
        return cls(
            ready=_require_bool(data, "ready"),
            issues=_require_submodel_sequence(PreflightIssue.from_dict, data, "issues"),
        )


@dataclass(frozen=True, slots=True)
class PseudonymizationResult:
    operation_id: str
    status: ResultStatus
    dataset_fingerprint: str
    artifact_paths: tuple[str, ...]
    tables_processed: int
    records_processed: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _canonical_enum(self.status, ResultStatus, "status"))
        object.__setattr__(
            self, "artifact_paths", _canonical_path_sequence(self.artifact_paths, "artifact_paths")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "PseudonymizationResult",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "status": self.status.value,
            "dataset_fingerprint": self.dataset_fingerprint,
            "artifact_paths": list(self.artifact_paths),
            "tables_processed": self.tables_processed,
            "records_processed": self.records_processed,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PseudonymizationResult:
        _validate_keys(
            data,
            _top_level_keys(
                "PseudonymizationResult",
                "operation_id",
                "status",
                "dataset_fingerprint",
                "artifact_paths",
                "tables_processed",
                "records_processed",
            ),
        )
        _validated_discriminator(data, "PseudonymizationResult")
        return cls(
            operation_id=_require_str(data, "operation_id"),
            status=_require_enum(ResultStatus, data, "status"),
            dataset_fingerprint=_require_str(data, "dataset_fingerprint"),
            artifact_paths=_require_path_tuple(data, "artifact_paths"),
            tables_processed=_require_int(data, "tables_processed"),
            records_processed=_require_int(data, "records_processed"),
        )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    operation_id: str
    status: VerificationStatus
    dataset_fingerprint: str
    tables_verified: int
    records_verified: int
    mismatches: int
    assurance: RelationalAssurance

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "status", _canonical_enum(self.status, VerificationStatus, "status")
        )
        object.__setattr__(
            self,
            "assurance",
            _canonical_enum(self.assurance, RelationalAssurance, "assurance"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "VerificationResult",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "status": self.status.value,
            "dataset_fingerprint": self.dataset_fingerprint,
            "tables_verified": self.tables_verified,
            "records_verified": self.records_verified,
            "mismatches": self.mismatches,
            "assurance": self.assurance.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> VerificationResult:
        _validate_keys(
            data,
            _top_level_keys(
                "VerificationResult",
                "operation_id",
                "status",
                "dataset_fingerprint",
                "tables_verified",
                "records_verified",
                "mismatches",
                "assurance",
            ),
        )
        _validated_discriminator(data, "VerificationResult")
        return cls(
            operation_id=_require_str(data, "operation_id"),
            status=_require_enum(VerificationStatus, data, "status"),
            dataset_fingerprint=_require_str(data, "dataset_fingerprint"),
            tables_verified=_require_int(data, "tables_verified"),
            records_verified=_require_int(data, "records_verified"),
            mismatches=_require_int(data, "mismatches"),
            assurance=_require_enum(RelationalAssurance, data, "assurance"),
        )


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    operation_id: str
    status: ResultStatus
    restored_artifact_paths: tuple[str, ...]
    records_restored: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _canonical_enum(self.status, ResultStatus, "status"))
        object.__setattr__(
            self,
            "restored_artifact_paths",
            _canonical_path_sequence(
                self.restored_artifact_paths, "restored_artifact_paths"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "RecoveryResult",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "status": self.status.value,
            "restored_artifact_paths": list(self.restored_artifact_paths),
            "records_restored": self.records_restored,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RecoveryResult:
        _validate_keys(
            data,
            _top_level_keys(
                "RecoveryResult",
                "operation_id",
                "status",
                "restored_artifact_paths",
                "records_restored",
            ),
        )
        _validated_discriminator(data, "RecoveryResult")
        return cls(
            operation_id=_require_str(data, "operation_id"),
            status=_require_enum(ResultStatus, data, "status"),
            restored_artifact_paths=_require_path_tuple(
                data, "restored_artifact_paths"
            ),
            records_restored=_require_int(data, "records_restored"),
        )


@dataclass(frozen=True, slots=True)
class TransferBundleResult:
    operation_id: str
    status: ResultStatus
    bundle_id: str
    bundle_fingerprint: str
    artifact_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _canonical_enum(self.status, ResultStatus, "status"))
        object.__setattr__(
            self, "artifact_paths", _canonical_path_sequence(self.artifact_paths, "artifact_paths")
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "TransferBundleResult",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "status": self.status.value,
            "bundle_id": self.bundle_id,
            "bundle_fingerprint": self.bundle_fingerprint,
            "artifact_paths": list(self.artifact_paths),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> TransferBundleResult:
        _validate_keys(
            data,
            _top_level_keys(
                "TransferBundleResult",
                "operation_id",
                "status",
                "bundle_id",
                "bundle_fingerprint",
                "artifact_paths",
            ),
        )
        _validated_discriminator(data, "TransferBundleResult")
        return cls(
            operation_id=_require_str(data, "operation_id"),
            status=_require_enum(ResultStatus, data, "status"),
            bundle_id=_require_str(data, "bundle_id"),
            bundle_fingerprint=_require_str(data, "bundle_fingerprint"),
            artifact_paths=_require_path_tuple(data, "artifact_paths"),
        )