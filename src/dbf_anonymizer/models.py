"""Immutable typed public models (REQ-P1-002).

Every model in this module is a frozen, strictly-typed value object with an
explicit, versioned, JSON-safe serialization contract:

- ``PUBLIC_MODEL_SCHEMA_VERSION`` is the single supported serialization
  schema version;
- top-level models embed ``"schema_version"`` and a ``"model"``
  discriminator in ``to_dict()`` and validate both in ``from_dict()``;
- nested models serialize as plain JSON objects and validate keys strictly
  in ``from_dict()``;
- every path-bearing serialized field carries a normalized relative POSIX
  path (``a/b.dbf``); absolute paths, drive/UNC paths, ``..`` traversal and
  NUL are rejected with messages that echo the offending key name only —
  never the rejected value;
- no field name in this module can carry an original source value
  (``raw_value``, ``original_value``, ``sample``, ``record``, free-form
  ``metadata``/``context``/``details`` mapping bags and similar channels are
  deliberately absent);
- all collection fields are immutable tuples.

The enums in this module carry the architecture vocabulary only; defining
them does not implement REQ-P3-007, REQ-P5-001 or any other later
requirement.
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
    if path.startswith("/") or path.startswith("\\") or path.startswith("\\\\"):
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


def _require_path(data: Mapping[str, object], key: str) -> str:
    return _normalize_relative_path(_require_str(data, key))


def _require_optional_path(data: Mapping[str, object], key: str) -> str | None:
    value = data[key]
    if value is None:
        return None
    if not isinstance(value, str):
        raise _fail(key, "must be a relative path string or null")
    return _normalize_relative_path(value)


def _require_string_tuple(data: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = data[key]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _fail(key, "must be an array of strings")
    return tuple(value)


def _require_path_tuple(data: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = data[key]
    if not isinstance(value, list):
        raise _fail(key, "must be an array of relative paths")
    return tuple(_normalize_relative_path(str(item)) for item in value)


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


def _validate_keys(data: Mapping[str, object], allowed: frozenset[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"unknown public model keys: {unknown}")
    missing = sorted(allowed - set(data))
    if missing:
        raise ValueError(f"missing mandatory public model keys: {missing}")


def _validated_discriminator(data: Mapping[str, object], model: str) -> None:
    if data.get("model") != model:
        raise ValueError(
            f"wrong public model discriminator: expected {model!r}"
        )
    if data.get("schema_version") != PUBLIC_MODEL_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported public model schema version: expected "
            f"{PUBLIC_MODEL_SCHEMA_VERSION!r}"
        )


def _top_level_keys(model: str, *fields: str) -> frozenset[str]:
    return frozenset({"model", "schema_version", *fields})


# ---------------------------------------------------------------------------
# nested public models (serialized as plain JSON objects)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldPlan:
    """Per-field plan identifiers (no record values)."""

    field_name: str
    dbf_type: str
    action: str
    domain: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "field_name": self.field_name,
            "dbf_type": self.dbf_type,
            "action": self.action,
            "domain": self.domain,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> FieldPlan:
        _validate_keys(data, frozenset({"field_name", "dbf_type", "action", "domain"}))
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

    def to_dict(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "schema_fingerprint": self.schema_fingerprint,
            "fields": [field.to_dict() for field in self.fields],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> TablePlan:
        _validate_keys(data, frozenset({"relative_path", "schema_fingerprint", "fields"}))
        fields = data["fields"]
        if not isinstance(fields, list):
            raise _fail("fields", "must be an array of field plans")
        return cls(
            relative_path=_require_path(data, "relative_path"),
            schema_fingerprint=_require_str(data, "schema_fingerprint"),
            fields=tuple(
                FieldPlan.from_dict(dict(item)) for item in fields if isinstance(item, Mapping)
            ),
        )


@dataclass(frozen=True, slots=True)
class RelationshipMember:
    relative_path: str
    field_name: str
    role: str

    def to_dict(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "field_name": self.field_name,
            "role": self.role,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RelationshipMember:
        _validate_keys(data, frozenset({"relative_path", "field_name", "role"}))
        return cls(
            relative_path=_require_path(data, "relative_path"),
            field_name=_require_str(data, "field_name"),
            role=_require_str(data, "role"),
        )


@dataclass(frozen=True, slots=True)
class RelationshipGroup:
    group_id: str
    provenance: str
    members: tuple[RelationshipMember, ...]
    composite_ordering: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "provenance": self.provenance,
            "members": [member.to_dict() for member in self.members],
            "composite_ordering": list(self.composite_ordering),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RelationshipGroup:
        _validate_keys(
            data,
            frozenset({"group_id", "provenance", "members", "composite_ordering"}),
        )
        return cls(
            group_id=_require_str(data, "group_id"),
            provenance=_require_str(data, "provenance"),
            members=_require_member_tuple(data, "members"),
            composite_ordering=_require_string_tuple(data, "composite_ordering"),
        )


def _require_member_tuple(
    data: Mapping[str, object], key: str
) -> tuple[RelationshipMember, ...]:
    value = data[key]
    if not isinstance(value, list):
        raise _fail(key, "must be an array of relationship members")
    return tuple(RelationshipMember.from_dict(dict(item)) for item in value if isinstance(item, Mapping))


@dataclass(frozen=True, slots=True)
class RelationshipMetadata:
    provenance: str
    groups: tuple[RelationshipGroup, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "provenance": self.provenance,
            "groups": [group.to_dict() for group in self.groups],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RelationshipMetadata:
        _validate_keys(data, frozenset({"provenance", "groups"}))
        value = data["groups"]
        if not isinstance(value, list):
            raise _fail("groups", "must be an array of relationship groups")
        return cls(
            provenance=_require_str(data, "provenance"),
            groups=tuple(
                RelationshipGroup.from_dict(dict(item)) for item in value if isinstance(item, Mapping)
            ),
        )


@dataclass(frozen=True, slots=True)
class PreflightIssue:
    """One typed preflight issue (code plus optional normalized identifiers)."""

    code: str
    table: str | None
    field_name: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "table": self.table,
            "field_name": self.field_name,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PreflightIssue:
        _validate_keys(data, frozenset({"code", "table", "field_name"}))
        return cls(
            code=_require_str(data, "code"),
            table=_require_optional_path(data, "table"),
            field_name=_require_optional_str(data, "field_name"),
        )


# ---------------------------------------------------------------------------
# top-level public models (discriminator + schema version)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Capabilities:
    product_version: str
    dbfbridge_version: str
    supported_profiles: tuple[str, ...]
    features: tuple[str, ...]

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
        keys = _top_level_keys("Capabilities", "product_version", "dbfbridge_version", "supported_profiles", "features")
        _validate_keys(data, keys)
        _validated_discriminator(data, "Capabilities")
        return cls(
            product_version=_require_str(data, "product_version"),
            dbfbridge_version=_require_str(data, "dbfbridge_version"),
            supported_profiles=_require_string_tuple(data, "supported_profiles"),
            features=_require_string_tuple(data, "features"),
        )


@dataclass(frozen=True, slots=True)
class DatasetIdentity:
    dataset_fingerprint: str
    tables: tuple[str, ...]
    table_count: int

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
class PolicySummary:
    profile: str
    policy_fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "policy_fingerprint": self.policy_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PolicySummary:
        _validate_keys(data, frozenset({"profile", "policy_fingerprint"}))
        return cls(
            profile=_require_str(data, "profile"),
            policy_fingerprint=_require_str(data, "policy_fingerprint"),
        )


@dataclass(frozen=True, slots=True)
class Plan:
    dataset_identity: DatasetIdentity
    policy_summary: PolicySummary
    relationships: RelationshipMetadata
    table_plans: tuple[TablePlan, ...]
    strategy: str
    plan_fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "Plan",
            "schema_version": PUBLIC_MODEL_SCHEMA_VERSION,
            "dataset_identity": self.dataset_identity.to_dict(),
            "policy_summary": self.policy_summary.to_dict(),
            "relationships": self.relationships.to_dict(),
            "table_plans": [table.to_dict() for table in self.table_plans],
            "strategy": self.strategy,
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
                "strategy",
                "plan_fingerprint",
            ),
        )
        _validated_discriminator(data, "Plan")
        table_plans = data["table_plans"]
        if not isinstance(table_plans, list):
            raise _fail("table_plans", "must be an array of table plans")
        return cls(
            dataset_identity=_require_submodel(DatasetIdentity.from_dict, data, "dataset_identity"),
            policy_summary=_require_submodel(PolicySummary.from_dict, data, "policy_summary"),
            relationships=_require_submodel(
                RelationshipMetadata.from_dict, data, "relationships"
            ),
            table_plans=tuple(
                TablePlan.from_dict(dict(item)) for item in table_plans if isinstance(item, Mapping)
            ),
            strategy=_require_str(data, "strategy"),
            plan_fingerprint=_require_str(data, "plan_fingerprint"),
        )


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    operation_id: str
    phase: str
    completed: int
    total: int | None
    unit: str | None
    table: str | None

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


def _require_optional_int(data: Mapping[str, object], key: str) -> int | None:
    value = data[key]
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(key, "must be an integer or null")
    return value


@dataclass(frozen=True, slots=True)
class PreflightResult:
    ready: bool
    issues: tuple[PreflightIssue, ...]

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
        issues = data["issues"]
        if not isinstance(issues, list):
            raise _fail("issues", "must be an array of preflight issues")
        return cls(
            ready=_require_bool(data, "ready"),
            issues=tuple(
                PreflightIssue.from_dict(dict(item)) for item in issues if isinstance(item, Mapping)
            ),
        )


@dataclass(frozen=True, slots=True)
class PseudonymizationResult:
    operation_id: str
    status: ResultStatus
    dataset_fingerprint: str
    artifact_paths: tuple[str, ...]
    tables_processed: int
    records_processed: int

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
                "RecoveryResult", "operation_id", "status", "restored_artifact_paths", "records_restored"
            ),
        )
        _validated_discriminator(data, "RecoveryResult")
        return cls(
            operation_id=_require_str(data, "operation_id"),
            status=_require_enum(ResultStatus, data, "status"),
            restored_artifact_paths=_require_path_tuple(data, "restored_artifact_paths"),
            records_restored=_require_int(data, "records_restored"),
        )


@dataclass(frozen=True, slots=True)
class TransferBundleResult:
    operation_id: str
    status: ResultStatus
    bundle_id: str
    bundle_fingerprint: str
    artifact_paths: tuple[str, ...]

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