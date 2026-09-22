"""Immutable public result/planning models for the clean-slate 1.0 API.

REQ-P1-002 owns this module. The models intentionally contain only
privacy-safe operational metadata. They never accept arbitrary original field
values, memo payloads, absolute source paths, vault contents or secrets.

Every public model serializes through :meth:`to_dict` to a deterministic,
JSON-safe dictionary carrying an explicit schema version and model type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, ClassVar, TypeAlias

MODEL_SCHEMA_VERSION = "1.3"

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


class VaultStrategy(str, Enum):
    """Explicit vault strategy identified during planning."""

    NONE = "NONE"
    SINGLE_DATASET_SQLITE = "SINGLE_DATASET_SQLITE"


class RawByteEquivalence(str, Enum):
    """The truthful raw DBF/FPT byte-equivalence fact (REQ-P5-003).

    Recovery success is CANONICAL LOGICAL DATA + SCHEMA EQUIVALENCE, never
    universal byte-for-byte identity. Raw physical equivalence is reported
    only when objectively proven (``PROVEN_EQUAL``), explicitly measured to
    differ (``PROVEN_DIFFERENT``) or truthfully ``NOT_EVALUATED`` where the
    public fresh writer does not promise byte reconstruction and no
    comparison oracle exists.
    """

    PROVEN_EQUAL = "PROVEN_EQUAL"
    PROVEN_DIFFERENT = "PROVEN_DIFFERENT"
    NOT_EVALUATED = "NOT_EVALUATED"


class VerificationStatus(str, Enum):
    """The ONE authoritative overall dataset verification verdict (REQ-P5-001).

    ``PASS``  — every verification dimension that was required by the dataset
    was independently verified; no unavailable-dimension claim is involved.
    ``PARTIAL`` — every verified dimension held, but at least one required
    verification dimension was truthfully unavailable (stable bounded check
    code in ``check_codes``); PARTIAL is never silently promoted to PASS.
    ``FAIL`` — at least one verified dimension detected corruption, tampering
    or a broken contract; the stable finding codes name the dimension(s).
    """

    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"


#: The single review status of unchanged numeric identifiers (REQ-P3-004).
IDENTITY_PRIVACY_REVIEW_REQUIRED = "IDENTITY_PRIVACY_REVIEW_REQUIRED"


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
class TablePlan(PublicModel):
    table_path: str
    memo_path: str | None
    record_count: int
    field_count: int
    transform_field_count: int
    structural_cdx: bool
    dbc_bound: bool
    index_strategy: str
    memo_required: bool
    memo_companion_present: bool
    structural_cdx_companion_present: bool
    unsupported_field_count: int
    unsafe_field_count: int
    system_field_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))
        if self.memo_path is not None:
            object.__setattr__(self, "memo_path", _normalized_relative_path(self.memo_path))
        _non_negative(self.record_count, field_name="record_count")
        _non_negative(self.field_count, field_name="field_count")
        _non_negative(self.transform_field_count, field_name="transform_field_count")
        if self.transform_field_count > self.field_count:
            raise ValueError("transform_field_count cannot exceed field_count")
        _validated_code(self.index_strategy, field_name="index_strategy")
        _non_negative(self.unsupported_field_count, field_name="unsupported_field_count")
        _non_negative(self.unsafe_field_count, field_name="unsafe_field_count")
        _non_negative(self.system_field_count, field_name="system_field_count")
        if self.unsupported_field_count > self.field_count:
            raise ValueError("unsupported_field_count cannot exceed field_count")
        if self.unsupported_field_count > self.unsafe_field_count:
            raise ValueError("unsupported_field_count cannot exceed unsafe_field_count")
        if self.unsafe_field_count > self.field_count:
            raise ValueError("unsafe_field_count cannot exceed field_count")
        if self.system_field_count > self.field_count:
            raise ValueError("system_field_count cannot exceed field_count")
        if (
            self.transform_field_count
            + self.unsafe_field_count
            + self.system_field_count
        ) > self.field_count:
            raise ValueError("transformed + unsafe + system cannot exceed field_count")

    def to_dict(self) -> JsonDict:
        return _payload(
            "TablePlan",
            table_path=self.table_path,
            memo_path=self.memo_path,
            record_count=self.record_count,
            field_count=self.field_count,
            transform_field_count=self.transform_field_count,
            structural_cdx=self.structural_cdx,
            dbc_bound=self.dbc_bound,
            index_strategy=self.index_strategy,
            memo_required=self.memo_required,
            memo_companion_present=self.memo_companion_present,
            structural_cdx_companion_present=self.structural_cdx_companion_present,
            unsupported_field_count=self.unsupported_field_count,
            unsafe_field_count=self.unsafe_field_count,
            system_field_count=self.system_field_count,
        )


@dataclass(frozen=True, slots=True)
class PolicySummary(PublicModel):
    policy_schema_version: str
    policy_fingerprint: str
    transformed_field_count: int
    relationship_count: int
    recovery_enabled: bool
    transformation_classes: tuple[str, ...]
    vault_strategy: VaultStrategy

    def __post_init__(self) -> None:
        _validated_code(self.policy_schema_version, field_name="policy_schema_version")
        _validated_code(self.policy_fingerprint, field_name="policy_fingerprint")
        _non_negative(self.transformed_field_count, field_name="transformed_field_count")
        _non_negative(self.relationship_count, field_name="relationship_count")
        for item in self.transformation_classes:
            _validated_code(item, field_name="transformation_classes item")

    def to_dict(self) -> JsonDict:
        return _payload(
            "PolicySummary",
            policy_schema_version=self.policy_schema_version,
            policy_fingerprint=self.policy_fingerprint,
            transformed_field_count=self.transformed_field_count,
            relationship_count=self.relationship_count,
            recovery_enabled=self.recovery_enabled,
            transformation_classes=self.transformation_classes,
            vault_strategy=self.vault_strategy,
        )


@dataclass(frozen=True, slots=True)
class RelationshipMetadata(PublicModel):
    """Bounded descriptive relationship-metadata facts (REQ-P1-002/P3-001).

    ``metadata_schema_version`` is a validated bounded code (non-empty,
    whitespace-free string; hostile non-string input is refused with the
    established runtime type convention).  ``authoritative`` is a DESCRIPTIVE
    boolean fact about the metadata the caller presents; it is a genuine
    ``bool`` and never a truthy shortcut.  It is NOT the authority
    credential: the in-process trust proof for ``VFP_METADATA_VERIFIED`` is
    the internal non-public binding minted ONLY by the validated
    authoritative ingestion adapter (REQ-P3-007), never the public boolean or
    the provenance label.
    """

    metadata_schema_version: str
    provenance: str
    relationship_fingerprint: str
    relation_count: int
    authoritative: bool
    metadata_path: str | None = None

    def __post_init__(self) -> None:
        # REQ-P1-002: the public model is typed AND versioned — the declared
        # metadata schema version is a validated bounded code, never silently
        # accepted malformed public input.
        if not isinstance(self.metadata_schema_version, str):
            raise TypeError("metadata_schema_version must be a string")
        _validated_code(
            self.metadata_schema_version, field_name="metadata_schema_version"
        )
        _validated_code(self.provenance, field_name="provenance")
        _validated_code(self.relationship_fingerprint, field_name="relationship_fingerprint")
        _non_negative(self.relation_count, field_name="relation_count")
        if not isinstance(self.authoritative, bool):
            # Authority is a genuine boolean FACT, never a truthy string, a
            # number or an arbitrary object (no Python-truthiness shortcut).
            raise ValueError("authoritative must be a genuine boolean")
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
    """The ONE canonical public relational-assurance model (REQ-P1-002/P3-007).

    Count-only, value-free and deterministic: the derived
    :class:`RelationalAssuranceLevel`, the declared/verified/failed/incomplete
    relation counts, the stable evidence binding (the canonical report
    fingerprint, the relationship-document fingerprint the evidence is bound
    to and the evidence schema version) and the stable machine scope note.

    The counts always satisfy
    ``verified + failed + incomplete <= declared``; a complete derivation
    satisfies equality.  The scope note token is a stable constant carried by
    every derived payload so no level can be mistaken for full database
    relational correctness.
    """

    level: RelationalAssuranceLevel
    declared_relations: int
    verified_relations: int
    failed_relations: int
    incomplete_relations: int = 0
    evidence_fingerprint: str | None = None
    relationship_fingerprint: str | None = None
    evidence_schema_version: str | None = None
    scope_note: str | None = None

    def __post_init__(self) -> None:
        _non_negative(self.declared_relations, field_name="declared_relations")
        _non_negative(self.verified_relations, field_name="verified_relations")
        _non_negative(self.failed_relations, field_name="failed_relations")
        _non_negative(self.incomplete_relations, field_name="incomplete_relations")
        if (
            self.verified_relations
            + self.failed_relations
            + self.incomplete_relations
            > self.declared_relations
        ):
            raise ValueError(
                "verified + failed + incomplete relations cannot exceed declared relations"
            )
        if self.evidence_fingerprint is not None:
            _validated_code(self.evidence_fingerprint, field_name="evidence_fingerprint")
        if self.relationship_fingerprint is not None:
            _validated_code(
                self.relationship_fingerprint, field_name="relationship_fingerprint"
            )
        if self.evidence_schema_version is not None:
            _validated_code(
                self.evidence_schema_version, field_name="evidence_schema_version"
            )
        if self.scope_note is not None:
            _validated_code(self.scope_note, field_name="scope_note")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationalAssurance",
            level=self.level,
            declared_relations=self.declared_relations,
            verified_relations=self.verified_relations,
            failed_relations=self.failed_relations,
            incomplete_relations=self.incomplete_relations,
            evidence_fingerprint=self.evidence_fingerprint,
            relationship_fingerprint=self.relationship_fingerprint,
            evidence_schema_version=self.evidence_schema_version,
            scope_note=self.scope_note,
        )


@dataclass(frozen=True, slots=True)
class _PlanExecutionContext:
    """Runtime-only execution context carried by the in-memory Plan.

    This is intentionally NOT a PublicModel: it is never serialized through
    ``to_dict``, excluded from ``repr``, and excluded from equality
    comparisons. It stores the absolute filesystem roots that a future
    ``pseudonymize(plan)`` call needs to locate source, write output and
    manage the vault, without leaking them into any public JSON boundary.

    ``relationship_document`` and ``relationship_bindings`` carry the parsed
    REQ-P3-001 typed relationship document and its source-schema binding
    facts for the preflight relationship-domain validation.  They are typed
    as ``Any`` because the relationship package consumes models (this module)
    — importing it here would create an import cycle — and BOTH stay
    strictly outside every public serialization.
    """

    source_root: str
    output_root: str
    vault_path: str
    relationship_document: Any = None
    relationship_bindings: Any = None
    resolved_policy: Any = None

    def __repr__(self) -> str:
        return "<_PlanExecutionContext>"


@dataclass(frozen=True, slots=True)
class NumericIdentityReview(PublicModel):
    """One unchanged numeric identifier marked for privacy review (P3-004).

    Bounded, deterministic, structural facts ONLY: the normalized relative
    table path, the field name, the logical DBF type and the review status
    token.  It never carries an actual key value, a min/max or sampled value
    derived from records, a vault path, a reverse mapping or an absolute
    local path.
    """

    table_path: str
    field_name: str
    dbf_type: str
    status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))
        _validated_code(self.field_name, field_name="field_name")
        _validated_code(self.dbf_type, field_name="dbf_type")
        _validated_code(self.status, field_name="status")

    def to_dict(self) -> JsonDict:
        return _payload(
            "NumericIdentityReview",
            table_path=self.table_path,
            field_name=self.field_name,
            dbf_type=self.dbf_type,
            status=self.status,
        )


@dataclass(frozen=True, slots=True)
class Plan(PublicModel):
    plan_id: str
    dataset: DatasetIdentity
    tables: tuple[TablePlan, ...]
    policy: PolicySummary
    relationships: RelationshipMetadata
    output_profile: TransferProfile
    relationship_assurance_target: RelationalAssuranceLevel
    numeric_identity_review: tuple[NumericIdentityReview, ...] = ()
    execution_context: _PlanExecutionContext | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        _validated_code(self.plan_id, field_name="plan_id")
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
            output_profile=self.output_profile,
            relationship_assurance_target=self.relationship_assurance_target,
            numeric_identity_review=self.numeric_identity_review,
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
class _PseudonymizationExecutionContext:
    """Runtime-only location of one published pseudonymized dataset.

    The absolute paths are retained only in memory for later service
    operations in the SAME trusted environment (the internal REQ-P5-004
    verified-dataset precondition of bundle creation reuses them; recovery
    is path-based and needs nothing). Everything is excluded from public
    serialization, representation and equality.
    """

    output_root: str
    source_root: str
    vault_path: str

    def __repr__(self) -> str:
        return "<_PseudonymizationExecutionContext>"


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
    execution_context: _PseudonymizationExecutionContext | None = field(
        default=None, repr=False, compare=False
    )

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
    """The ONE authoritative dataset verification verdict (REQ-P5-001).

    ``status`` is the single authoritative PASS/PARTIAL/FAIL state; the
    convenience ``verified`` property is DERIVED (PASS only) and never an
    independent truth field. ``operation_id`` is the canonical durable
    operation id of the verified pseudonymization operation (shared with
    every ProgressEvent of the verification and the public pseudonymize
    result). ``check_codes`` carries the stable, versioned finding codes of
    failed/unavailable dimensions; a clean PASS carries none.
    """

    status: VerificationStatus
    dataset: DatasetIdentity
    operation_id: str
    table_count: int
    record_count: int
    check_codes: tuple[str, ...]
    assurance: RelationalAssurance

    @property
    def verified(self) -> bool:
        """Derived convenience truth: exactly the PASS status."""
        return self.status is VerificationStatus.PASS

    def __post_init__(self) -> None:
        _validated_code(self.operation_id, field_name="operation_id")
        _non_negative(self.table_count, field_name="table_count")
        _non_negative(self.record_count, field_name="record_count")
        for code in self.check_codes:
            _validated_code(code, field_name="check_codes item")

    def to_dict(self) -> JsonDict:
        return _payload(
            "VerificationResult",
            status=self.status,
            dataset=self.dataset,
            operation_id=self.operation_id,
            table_count=self.table_count,
            record_count=self.record_count,
            check_codes=self.check_codes,
            assurance=self.assurance,
        )


@dataclass(frozen=True, slots=True)
class RecoveryResult(PublicModel):
    """The public canonical recovery verdict (REQ-P5-002/REQ-P5-003).

    ``canonical_verified`` is the authoritative success criterion: the
    recovered dataset is canonical LOGICAL data + schema equivalent to the
    original (proven by the internal staged self-verification against the
    protected durable recovery state — never by a successful DBF write
    alone). ``raw_byte_equivalence`` reports the SEPARATE raw DBF/FPT byte
    fact truthfully; production recovery never claims raw equivalence
    without an objective comparison oracle. The recovery ``operation_id``
    is clearly distinct from the pseudonymization operation it recovers.
    """

    operation_id: str
    dataset: DatasetIdentity
    output_path: str
    table_count: int
    record_count: int
    canonical_verified: bool
    raw_byte_equivalence: RawByteEquivalence

    def __post_init__(self) -> None:
        _validated_code(self.operation_id, field_name="operation_id")
        object.__setattr__(self, "output_path", _normalized_relative_path(self.output_path))
        _non_negative(self.table_count, field_name="table_count")
        _non_negative(self.record_count, field_name="record_count")
        if not isinstance(self.canonical_verified, bool):
            raise TypeError("canonical_verified must be a genuine bool")
        if not isinstance(self.raw_byte_equivalence, RawByteEquivalence):
            raise TypeError("raw_byte_equivalence must be a RawByteEquivalence")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RecoveryResult",
            operation_id=self.operation_id,
            dataset=self.dataset,
            output_path=self.output_path,
            table_count=self.table_count,
            record_count=self.record_count,
            canonical_verified=self.canonical_verified,
            raw_byte_equivalence=self.raw_byte_equivalence,
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
    Plan,
    TablePlan,
    PolicySummary,
    RelationshipMetadata,
    RelationalAssurance,
    NumericIdentityReview,
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
    "IDENTITY_PRIVACY_REVIEW_REQUIRED",
    "Capabilities",
    "DatasetIdentity",
    "Plan",
    "TablePlan",
    "PolicySummary",
    "RelationshipMetadata",
    "RelationalAssurance",
    "RelationalAssuranceLevel",
    "NumericIdentityReview",
    "ProgressEvent",
    "PreflightResult",
    "PseudonymizationResult",
    "VerificationStatus",
    "VerificationResult",
    "RawByteEquivalence",
    "RecoveryResult",
    "TransferBundleResult",
    "TransferProfile",
    "VaultStrategy",
]
