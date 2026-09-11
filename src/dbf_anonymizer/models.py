"""Immutable public result/planning models for the clean-slate 1.0 API.

Public serialization is deliberately privacy-safe. Operational objects may
carry local execution roots required to perform work, but those roots are
kept out of ``repr`` and ``to_dict()``. Transport payloads contain only
normalized relative paths, fingerprints, counts and machine codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import ClassVar, TypeAlias

MODEL_SCHEMA_VERSION = "1.0"

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonDict: TypeAlias = dict[str, JsonValue]


class PublicModel:
    """Base class for immutable public models with a JSON-safe boundary."""

    schema_version: ClassVar[str] = MODEL_SCHEMA_VERSION

    def to_dict(self) -> JsonDict:
        raise NotImplementedError


class RelationalAssuranceLevel(str, Enum):
    """Truthful relationship-assurance levels required by REQ-P3-007."""

    GLOBAL_EXACT_VALUE = "GLOBAL_EXACT_VALUE"
    DECLARED_RELATIONS_VERIFIED = "DECLARED_RELATIONS_VERIFIED"
    VFP_METADATA_VERIFIED = "VFP_METADATA_VERIFIED"
    INCOMPLETE = "INCOMPLETE"


class TransferProfile(str, Enum):
    """Supported output/transfer profiles known at the public boundary."""

    DATA_ONLY = "DATA_ONLY"
    VFP_INDEXED = "VFP_INDEXED"


def _normalized_relative_path(value: str) -> str:
    if not value or "\x00" in value:
        raise ValueError("relative path must be a non-empty text path")
    windows = PureWindowsPath(value)
    if windows.is_absolute() or windows.drive or windows.root:
        raise ValueError("public model paths must be relative")
    normalized = PurePosixPath(value.replace("\\", "/"))
    if normalized.is_absolute():
        raise ValueError("public model paths must be relative")
    if any(part == ".." for part in normalized.parts):
        raise ValueError("public model paths must not contain parent traversal")
    text = normalized.as_posix()
    if text in {"", "."}:
        raise ValueError("relative path must identify a dataset artifact")
    return text


def _validated_code(value: str, *, field_name: str) -> str:
    if not value or value.strip() != value or any(ch.isspace() for ch in value):
        raise ValueError(f"{field_name} must be a non-empty whitespace-free code")
    return value


def _validated_text(value: str, *, field_name: str) -> str:
    if not value or value.strip() != value:
        raise ValueError(f"{field_name} must be non-empty text")
    return value


def _non_negative(value: int, *, field_name: str) -> int:
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return value


def _json_value(value: object) -> JsonValue:
    if isinstance(value, Enum):
        raw = value.value
        if not isinstance(raw, str):
            raise TypeError("public enum values must serialize to strings")
        return raw
    if isinstance(value, PublicModel):
        return value.to_dict()
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    raise TypeError(f"unsupported public JSON value type: {type(value).__name__}")


def _payload(model_type: str, **values: object) -> JsonDict:
    payload: JsonDict = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "model_type": model_type,
    }
    for key, value in values.items():
        payload[key] = _json_value(value)
    return payload


@dataclass(frozen=True, slots=True)
class Capabilities(PublicModel):
    direct_read: bool
    direct_write: bool
    planning: bool
    preflight: bool
    pseudonymization: bool
    verification: bool
    recovery: bool
    transfer_bundle: bool
    vfp_index_backend: bool
    dbfbridge_version: str

    def __post_init__(self) -> None:
        _validated_code(self.dbfbridge_version, field_name="dbfbridge_version")

    def to_dict(self) -> JsonDict:
        return _payload(
            "Capabilities",
            direct_read=self.direct_read,
            direct_write=self.direct_write,
            planning=self.planning,
            preflight=self.preflight,
            pseudonymization=self.pseudonymization,
            verification=self.verification,
            recovery=self.recovery,
            transfer_bundle=self.transfer_bundle,
            vfp_index_backend=self.vfp_index_backend,
            dbfbridge_version=self.dbfbridge_version,
        )


@dataclass(frozen=True, slots=True)
class DatasetIdentity(PublicModel):
    dataset_id: str
    source_fingerprint: str
    table_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        _validated_code(self.dataset_id, field_name="dataset_id")
        _validated_code(self.source_fingerprint, field_name="source_fingerprint")
        normalized = tuple(_normalized_relative_path(path) for path in self.table_paths)
        if len(set(normalized)) != len(normalized):
            raise ValueError("table_paths must be unique")
        object.__setattr__(self, "table_paths", normalized)

    def to_dict(self) -> JsonDict:
        return _payload(
            "DatasetIdentity",
            dataset_id=self.dataset_id,
            source_fingerprint=self.source_fingerprint,
            table_paths=self.table_paths,
        )


@dataclass(frozen=True, slots=True)
class FieldPlan(PublicModel):
    """Safe physical schema facts plus the policy action for one field."""

    ordinal: int
    name: str
    dbf_type: str
    length: int
    decimal_count: int
    nullable: bool
    nocptrans: bool
    autoincrement: bool
    memo: bool
    binary: bool
    supported: bool
    transform_action: str
    mapping_domain: str | None = None

    def __post_init__(self) -> None:
        _non_negative(self.ordinal, field_name="ordinal")
        _validated_code(self.name, field_name="name")
        _validated_code(self.dbf_type, field_name="dbf_type")
        _non_negative(self.length, field_name="length")
        _non_negative(self.decimal_count, field_name="decimal_count")
        _validated_code(self.transform_action, field_name="transform_action")
        if self.mapping_domain is not None:
            _validated_code(self.mapping_domain, field_name="mapping_domain")

    def to_dict(self) -> JsonDict:
        return _payload(
            "FieldPlan",
            ordinal=self.ordinal,
            name=self.name,
            dbf_type=self.dbf_type,
            length=self.length,
            decimal_count=self.decimal_count,
            nullable=self.nullable,
            nocptrans=self.nocptrans,
            autoincrement=self.autoincrement,
            memo=self.memo,
            binary=self.binary,
            supported=self.supported,
            transform_action=self.transform_action,
            mapping_domain=self.mapping_domain,
        )


@dataclass(frozen=True, slots=True)
class TablePlan(PublicModel):
    table_path: str
    schema_fingerprint: str
    dbf_version_name: str
    encoding: str
    record_count: int
    header_length: int
    record_length: int
    fields: tuple[FieldPlan, ...]
    transform_field_count: int
    memo_required: bool
    memo_present: bool
    memo_path: str | None
    structural_cdx: bool
    cdx_present: bool
    cdx_path: str | None
    standalone_idx_paths: tuple[str, ...]
    dbc_bound: bool
    incomplete_transaction: bool
    encryption_flag: bool
    index_strategy: str
    warning_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))
        _validated_code(self.schema_fingerprint, field_name="schema_fingerprint")
        _validated_text(self.dbf_version_name, field_name="dbf_version_name")
        _validated_code(self.encoding, field_name="encoding")
        _non_negative(self.record_count, field_name="record_count")
        _non_negative(self.header_length, field_name="header_length")
        _non_negative(self.record_length, field_name="record_length")
        _non_negative(self.transform_field_count, field_name="transform_field_count")
        if self.transform_field_count > len(self.fields):
            raise ValueError("transform_field_count cannot exceed field count")
        if self.memo_path is not None:
            object.__setattr__(self, "memo_path", _normalized_relative_path(self.memo_path))
        if self.cdx_path is not None:
            object.__setattr__(self, "cdx_path", _normalized_relative_path(self.cdx_path))
        object.__setattr__(
            self,
            "standalone_idx_paths",
            tuple(_normalized_relative_path(path) for path in self.standalone_idx_paths),
        )
        if self.memo_present != (self.memo_path is not None):
            raise ValueError("memo_present must match memo_path presence")
        if self.cdx_present != (self.cdx_path is not None):
            raise ValueError("cdx_present must match cdx_path presence")
        _validated_code(self.index_strategy, field_name="index_strategy")
        for code in self.warning_codes:
            _validated_code(code, field_name="warning_codes item")

    @property
    def field_count(self) -> int:
        return len(self.fields)

    def to_dict(self) -> JsonDict:
        return _payload(
            "TablePlan",
            table_path=self.table_path,
            schema_fingerprint=self.schema_fingerprint,
            dbf_version_name=self.dbf_version_name,
            encoding=self.encoding,
            record_count=self.record_count,
            header_length=self.header_length,
            record_length=self.record_length,
            field_count=self.field_count,
            fields=self.fields,
            transform_field_count=self.transform_field_count,
            memo_required=self.memo_required,
            memo_present=self.memo_present,
            memo_path=self.memo_path,
            structural_cdx=self.structural_cdx,
            cdx_present=self.cdx_present,
            cdx_path=self.cdx_path,
            standalone_idx_paths=self.standalone_idx_paths,
            dbc_bound=self.dbc_bound,
            incomplete_transaction=self.incomplete_transaction,
            encryption_flag=self.encryption_flag,
            index_strategy=self.index_strategy,
            warning_codes=self.warning_codes,
        )


@dataclass(frozen=True, slots=True)
class PolicySummary(PublicModel):
    policy_schema_version: str
    profile: str
    policy_fingerprint: str
    transformed_field_count: int
    relationship_count: int
    recovery_enabled: bool
    transformation_classes: tuple[str, ...]
    index_profile: TransferProfile

    def __post_init__(self) -> None:
        _validated_code(self.policy_schema_version, field_name="policy_schema_version")
        _validated_code(self.profile, field_name="profile")
        _validated_code(self.policy_fingerprint, field_name="policy_fingerprint")
        _non_negative(self.transformed_field_count, field_name="transformed_field_count")
        _non_negative(self.relationship_count, field_name="relationship_count")
        for item in self.transformation_classes:
            _validated_code(item, field_name="transformation_classes item")

    def to_dict(self) -> JsonDict:
        return _payload(
            "PolicySummary",
            policy_schema_version=self.policy_schema_version,
            profile=self.profile,
            policy_fingerprint=self.policy_fingerprint,
            transformed_field_count=self.transformed_field_count,
            relationship_count=self.relationship_count,
            recovery_enabled=self.recovery_enabled,
            transformation_classes=self.transformation_classes,
            index_profile=self.index_profile,
        )


@dataclass(frozen=True, slots=True)
class RelationshipMetadata(PublicModel):
    metadata_schema_version: str
    provenance: str
    relationship_fingerprint: str
    relation_count: int
    authoritative: bool
    metadata_path: str | None = None

    def __post_init__(self) -> None:
        _validated_code(self.metadata_schema_version, field_name="metadata_schema_version")
        _validated_code(self.provenance, field_name="provenance")
        _validated_code(self.relationship_fingerprint, field_name="relationship_fingerprint")
        _non_negative(self.relation_count, field_name="relation_count")
        if self.metadata_path is not None:
            object.__setattr__(self, "metadata_path", _normalized_relative_path(self.metadata_path))

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationshipMetadata",
            metadata_schema_version=self.metadata_schema_version,
            provenance=self.provenance,
            relationship_fingerprint=self.relationship_fingerprint,
            relation_count=self.relation_count,
            authoritative=self.authoritative,
            metadata_path=self.metadata_path,
        )


@dataclass(frozen=True, slots=True)
class RelationalAssurance(PublicModel):
    level: RelationalAssuranceLevel
    declared_relations: int
    verified_relations: int
    failed_relations: int
    evidence_fingerprint: str

    def __post_init__(self) -> None:
        _non_negative(self.declared_relations, field_name="declared_relations")
        _non_negative(self.verified_relations, field_name="verified_relations")
        _non_negative(self.failed_relations, field_name="failed_relations")
        if self.verified_relations + self.failed_relations > self.declared_relations:
            raise ValueError("verified + failed relations cannot exceed declared relations")
        _validated_code(self.evidence_fingerprint, field_name="evidence_fingerprint")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationalAssurance",
            level=self.level,
            declared_relations=self.declared_relations,
            verified_relations=self.verified_relations,
            failed_relations=self.failed_relations,
            evidence_fingerprint=self.evidence_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class ExecutionPaths:
    """Trusted local roots required for execution, never serialized publicly."""

    source_root: Path = field(repr=False)
    output_root: Path = field(repr=False)
    vault_root: Path = field(repr=False)

    def __post_init__(self) -> None:
        for name in ("source_root", "output_root", "vault_root"):
            value = Path(getattr(self, name))
            if not value.is_absolute():
                raise ValueError(f"{name} must be absolute inside an execution plan")
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class Plan(PublicModel):
    plan_id: str
    dataset: DatasetIdentity
    tables: tuple[TablePlan, ...]
    policy: PolicySummary
    relationships: RelationshipMetadata
    capabilities: Capabilities
    output_profile: TransferProfile
    relationship_assurance_target: RelationalAssuranceLevel
    engine_strategy: str
    vault_strategy: str
    execution: ExecutionPaths = field(repr=False, compare=True)

    def __post_init__(self) -> None:
        _validated_code(self.plan_id, field_name="plan_id")
        _validated_code(self.engine_strategy, field_name="engine_strategy")
        _validated_code(self.vault_strategy, field_name="vault_strategy")
        planned_paths = tuple(table.table_path for table in self.tables)
        if planned_paths != self.dataset.table_paths:
            raise ValueError("plan table order must exactly match dataset.table_paths")

    def to_dict(self) -> JsonDict:
        return _payload(
            "Plan",
            plan_id=self.plan_id,
            dataset=self.dataset,
            tables=self.tables,
            policy=self.policy,
            relationships=self.relationships,
            capabilities=self.capabilities,
            output_profile=self.output_profile,
            relationship_assurance_target=self.relationship_assurance_target,
            engine_strategy=self.engine_strategy,
            vault_strategy=self.vault_strategy,
        )


@dataclass(frozen=True, slots=True)
class ProgressEvent(PublicModel):
    operation_id: str
    phase_code: str
    event_code: str
    completed_units: int
    total_units: int | None = None
    table_path: str | None = None

    def __post_init__(self) -> None:
        _validated_code(self.operation_id, field_name="operation_id")
        _validated_code(self.phase_code, field_name="phase_code")
        _validated_code(self.event_code, field_name="event_code")
        _non_negative(self.completed_units, field_name="completed_units")
        if self.total_units is not None:
            _non_negative(self.total_units, field_name="total_units")
            if self.completed_units > self.total_units:
                raise ValueError("completed_units cannot exceed total_units")
        if self.table_path is not None:
            object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))

    def to_dict(self) -> JsonDict:
        return _payload(
            "ProgressEvent",
            operation_id=self.operation_id,
            phase_code=self.phase_code,
            event_code=self.event_code,
            completed_units=self.completed_units,
            total_units=self.total_units,
            table_path=self.table_path,
        )


@dataclass(frozen=True, slots=True)
class PreflightResult(PublicModel):
    ready: bool
    plan_id: str
    capabilities: Capabilities
    check_codes: tuple[str, ...]
    warning_codes: tuple[str, ...]
    error_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _validated_code(self.plan_id, field_name="plan_id")
        for field_name, codes in (
            ("check_codes", self.check_codes),
            ("warning_codes", self.warning_codes),
            ("error_codes", self.error_codes),
        ):
            for code in codes:
                _validated_code(code, field_name=f"{field_name} item")
        if self.ready and self.error_codes:
            raise ValueError("ready preflight cannot contain error_codes")

    def to_dict(self) -> JsonDict:
        return _payload(
            "PreflightResult",
            ready=self.ready,
            plan_id=self.plan_id,
            capabilities=self.capabilities,
            check_codes=self.check_codes,
            warning_codes=self.warning_codes,
            error_codes=self.error_codes,
        )


@dataclass(frozen=True, slots=True)
class PseudonymizationResult(PublicModel):
    operation_id: str
    dataset: DatasetIdentity
    output_path: str
    table_count: int
    record_count: int
    vault_created: bool
    output_fingerprint: str
    assurance: RelationalAssurance

    def __post_init__(self) -> None:
        _validated_code(self.operation_id, field_name="operation_id")
        object.__setattr__(self, "output_path", _normalized_relative_path(self.output_path))
        _non_negative(self.table_count, field_name="table_count")
        _non_negative(self.record_count, field_name="record_count")
        _validated_code(self.output_fingerprint, field_name="output_fingerprint")

    def to_dict(self) -> JsonDict:
        return _payload(
            "PseudonymizationResult",
            operation_id=self.operation_id,
            dataset=self.dataset,
            output_path=self.output_path,
            table_count=self.table_count,
            record_count=self.record_count,
            vault_created=self.vault_created,
            output_fingerprint=self.output_fingerprint,
            assurance=self.assurance,
        )


@dataclass(frozen=True, slots=True)
class VerificationResult(PublicModel):
    verified: bool
    dataset: DatasetIdentity
    table_count: int
    record_count: int
    check_codes: tuple[str, ...]
    assurance: RelationalAssurance

    def __post_init__(self) -> None:
        _non_negative(self.table_count, field_name="table_count")
        _non_negative(self.record_count, field_name="record_count")
        for code in self.check_codes:
            _validated_code(code, field_name="check_codes item")

    def to_dict(self) -> JsonDict:
        return _payload(
            "VerificationResult",
            verified=self.verified,
            dataset=self.dataset,
            table_count=self.table_count,
            record_count=self.record_count,
            check_codes=self.check_codes,
            assurance=self.assurance,
        )


@dataclass(frozen=True, slots=True)
class RecoveryResult(PublicModel):
    operation_id: str
    dataset: DatasetIdentity
    output_path: str
    table_count: int
    record_count: int
    verified: bool

    def __post_init__(self) -> None:
        _validated_code(self.operation_id, field_name="operation_id")
        object.__setattr__(self, "output_path", _normalized_relative_path(self.output_path))
        _non_negative(self.table_count, field_name="table_count")
        _non_negative(self.record_count, field_name="record_count")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RecoveryResult",
            operation_id=self.operation_id,
            dataset=self.dataset,
            output_path=self.output_path,
            table_count=self.table_count,
            record_count=self.record_count,
            verified=self.verified,
        )


@dataclass(frozen=True, slots=True)
class TransferBundleResult(PublicModel):
    bundle_path: str
    profile: TransferProfile
    file_count: int
    manifest_fingerprint: str
    verified: bool
    assurance: RelationalAssurance

    def __post_init__(self) -> None:
        object.__setattr__(self, "bundle_path", _normalized_relative_path(self.bundle_path))
        _non_negative(self.file_count, field_name="file_count")
        _validated_code(self.manifest_fingerprint, field_name="manifest_fingerprint")

    def to_dict(self) -> JsonDict:
        return _payload(
            "TransferBundleResult",
            bundle_path=self.bundle_path,
            profile=self.profile,
            file_count=self.file_count,
            manifest_fingerprint=self.manifest_fingerprint,
            verified=self.verified,
            assurance=self.assurance,
        )


PUBLIC_MODEL_TYPES: tuple[type[PublicModel], ...] = (
    Capabilities,
    DatasetIdentity,
    FieldPlan,
    Plan,
    TablePlan,
    PolicySummary,
    RelationshipMetadata,
    RelationalAssurance,
    ProgressEvent,
    PreflightResult,
    PseudonymizationResult,
    VerificationResult,
    RecoveryResult,
    TransferBundleResult,
)

__all__ = [
    "MODEL_SCHEMA_VERSION",
    "JsonDict",
    "JsonValue",
    "Capabilities",
    "DatasetIdentity",
    "ExecutionPaths",
    "FieldPlan",
    "Plan",
    "TablePlan",
    "PolicySummary",
    "RelationshipMetadata",
    "RelationalAssurance",
    "RelationalAssuranceLevel",
    "ProgressEvent",
    "PreflightResult",
    "PseudonymizationResult",
    "VerificationResult",
    "RecoveryResult",
    "TransferBundleResult",
    "TransferProfile",
]
