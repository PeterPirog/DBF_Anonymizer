"""Immutable public result/planning models for the clean-slate 1.0 API.

REQ-P1-002 owns this module. The models intentionally contain only
privacy-safe operational metadata. They never accept arbitrary original field
values, memo payloads, absolute source paths, vault contents or secrets.

Every public model serializes through :meth:`to_dict` to a deterministic,
JSON-safe dictionary carrying an explicit schema version and model type.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable, ClassVar, TypeAlias

#: Additive REQ-P6-005 source/output truthfulness schema.
MODEL_SCHEMA_VERSION = "1.7"

#: Versioned identity of the injected index-backend protocol (REQ-P6-001).
#: Version 1.2 adds authoritative standalone-IDX association plus exact
#: process-local source/staging artifact identity. Foreign versions fail closed.
INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION = "1.2"

# REQ-P7-002 public JSON bounds. These limits apply before serialization, so
# every accepted model has an objective maximum shape rather than relying on a
# representative small payload. Counts use signed 64-bit range for portable
# consumers; collection limits keep even path-heavy planning payloads finite.
PUBLIC_JSON_MAX_TOKEN_LENGTH = 128
PUBLIC_JSON_MAX_OPERATION_ID_LENGTH = 64
PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH = 512
PUBLIC_JSON_MAX_DATASET_TABLES = 256
PUBLIC_JSON_MAX_INDEX_ARTIFACTS = 256
PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS = 1024
PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES = 64
PUBLIC_JSON_MAX_FINDING_CODES = 64
PUBLIC_JSON_MAX_COUNT = (1 << 63) - 1

PROGRESS_PHASE_CODES: tuple[str, ...] = (
    "OPERATION",
    "DISCOVERY",
    "FINGERPRINT",
    "TABLE_EVALUATION",
    "SOURCE_VERIFICATION",
    "SOURCE_REVALIDATION",
    "CAPACITY_SCAN",
    "SCAN",
    "WRITE",
    "VERIFICATION",
    "VAULT_VERIFICATION",
    "OUTPUT_VERIFICATION",
    "RECOVERY_SCAN",
    "TRANSFER_SCAN",
    "PUBLICATION",
    "PASS1_SCAN",
    "PASS1_FINALIZE",
    "PASS2_WRITE",
    "INDEX_REBUILD",
)
PROGRESS_EVENT_CODES: tuple[str, ...] = ("STARTED", "PROGRESS", "COMPLETED")

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


class OutputDataState(str, Enum):
    """Truthful semantics of freshly written DBF/FPT output (REQ-P6-005)."""

    STANDALONE_REDUCED_SEMANTICS = "STANDALONE_REDUCED_SEMANTICS"


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
    if not isinstance(value, str):
        raise TypeError("relative path must be a string")
    if (
        not value
        or len(value) > PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH
        or "\x00" in value
        or any(not character.isprintable() for character in value)
    ):
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


def _validated_code(
    value: str,
    *,
    field_name: str,
    max_length: int = PUBLIC_JSON_MAX_TOKEN_LENGTH,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if (
        not value
        or len(value) > max_length
        or value.strip() != value
        or any(ch.isspace() or not ch.isprintable() for ch in value)
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"{field_name} must be a non-empty whitespace-free code")
    return value


def _validated_operation_id(value: str, *, field_name: str = "operation_id") -> str:
    return _validated_code(
        value,
        field_name=field_name,
        max_length=PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
    )


def _bounded_tuple(
    value: object, *, field_name: str, max_items: int
) -> tuple[Any, ...]:
    if not isinstance(value, tuple):
        raise TypeError(f"{field_name} must be a tuple")
    if len(value) > max_items:
        raise ValueError(f"{field_name} must contain at most {max_items} items")
    return value


#: The ONE canonical relationship-fingerprint contract, shared by the
#: public :class:`RelationshipMetadata` producer boundary and the
#: REQ-P5-005..P5-007 standalone transfer verifier (single definition, no
#: producer/verifier drift). The contract accepts every legitimate
#: bounded stable token the public P3 model accepts — canonical
#: 64-lowercase-hex relationship-document digests AND ordinary stable
#: non-hex tokens such as ``relationship-token-v1`` — and refuses
#: hostile unbounded/path-bearing forms at the PUBLIC typed input
#: boundary so they can never survive into a later transfer stage.
_RELATIONSHIP_FINGERPRINT_MAX_LENGTH = 128


def validate_relationship_fingerprint(
    value: object,
    *,
    field_name: str,
    failure: Callable[[str], Exception] | None = None,
) -> str:
    """The canonical relationship-fingerprint validator (REQ-P3-001,
    REQ-P5-005/006).

    Contract: actual ``str``; non-empty; at most 128 characters; no
    leading/trailing whitespace; no whitespace anywhere; no NUL; only
    printable characters; no Windows drive/root/absolute path, no POSIX
    absolute path, no parent traversal and no backslash form capable of
    carrying a private Windows path. Ordinary stable non-hex tokens and
    canonical 64-lowercase-hex document digests are both accepted.

    ``failure`` converts the refusal into the caller's typed error
    family (the public producer raises ``ValueError`` with the field
    name; the transfer verifier raises its privacy-safe
    ``TransferError``) — the hostile value itself NEVER appears in the
    message.
    """

    def refuse() -> Exception:
        if failure is not None:
            error: Exception = failure("TRANSFER_MANIFEST_VALUE_INVALID")
            return error
        return ValueError(
            f"{field_name} must be a non-empty bounded "
            f"relationship-fingerprint token"
        )

    if not isinstance(value, str):
        raise refuse()
    if (
        not value
        or len(value) > _RELATIONSHIP_FINGERPRINT_MAX_LENGTH
        or value.strip() != value
        or any(character.isspace() for character in value)
        or "\x00" in value
        or any(character.isprintable() is False for character in value)
        or "\\" in value
        or value.startswith("/")
        or PurePosixPath(value.lower()).is_absolute()
        or any(
            part == ".."
            for part in PurePosixPath(value.lower()).parts
        )
        or PureWindowsPath(value).drive
        or PureWindowsPath(value).root
        or PureWindowsPath(value).is_absolute()
    ):
        raise refuse()
    return value


def _non_negative(value: int, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    if value < 0 or value > PUBLIC_JSON_MAX_COUNT:
        raise ValueError(
            f"{field_name} must be from 0 to {PUBLIC_JSON_MAX_COUNT}"
        )
    return value


def _json_value(value: object) -> JsonValue:
    if isinstance(value, Enum):
        raw = value.value
        if not isinstance(raw, str):
            raise TypeError("public enum values must serialize to strings")
        return raw
    if isinstance(value, PublicModel):
        return value.to_dict()
    if isinstance(value, float) and not math.isfinite(value):
        raise TypeError("public JSON floats must be finite")
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
        for field_name in (
            "direct_read",
            "direct_write",
            "recovery",
            "transfer_bundle",
            "vfp_index_backend",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be a genuine bool")
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
    standalone_idx_paths: tuple[str, ...] = ()
    dbc_bound_table_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validated_code(self.dataset_id, field_name="dataset_id")
        _validated_code(self.source_fingerprint, field_name="source_fingerprint")
        table_paths = _bounded_tuple(
            self.table_paths,
            field_name="table_paths",
            max_items=PUBLIC_JSON_MAX_DATASET_TABLES,
        )
        normalized = tuple(_normalized_relative_path(path) for path in table_paths)
        if len(set(normalized)) != len(normalized):
            raise ValueError("table_paths must be unique")
        object.__setattr__(self, "table_paths", normalized)
        standalone_idx_paths = _bounded_tuple(
            self.standalone_idx_paths,
            field_name="standalone_idx_paths",
            max_items=PUBLIC_JSON_MAX_INDEX_ARTIFACTS,
        )
        idx_paths = tuple(
            sorted(
                (_normalized_relative_path(path) for path in standalone_idx_paths),
                key=lambda path: (path.casefold(), path),
            )
        )
        if len(set(idx_paths)) != len(idx_paths):
            raise ValueError("standalone_idx_paths must be unique")
        if any(PurePosixPath(path).suffix.lower() != ".idx" for path in idx_paths):
            raise ValueError("standalone_idx_paths must identify IDX artifacts")
        object.__setattr__(self, "standalone_idx_paths", idx_paths)
        dbc_bound_table_paths = _bounded_tuple(
            self.dbc_bound_table_paths,
            field_name="dbc_bound_table_paths",
            max_items=PUBLIC_JSON_MAX_DATASET_TABLES,
        )
        dbc_paths = tuple(
            sorted(
                (
                    _normalized_relative_path(path)
                    for path in dbc_bound_table_paths
                ),
                key=lambda path: (path.casefold(), path),
            )
        )
        if len(set(dbc_paths)) != len(dbc_paths):
            raise ValueError("dbc_bound_table_paths must be unique")
        if any(path not in normalized for path in dbc_paths):
            raise ValueError("dbc_bound_table_paths must identify dataset tables")
        object.__setattr__(self, "dbc_bound_table_paths", dbc_paths)

    def to_dict(self) -> JsonDict:
        return _payload(
            "DatasetIdentity",
            dataset_id=self.dataset_id,
            source_fingerprint=self.source_fingerprint,
            table_paths=self.table_paths,
            standalone_idx_paths=self.standalone_idx_paths,
            dbc_bound_table_paths=self.dbc_bound_table_paths,
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
        for field_name in (
            "structural_cdx",
            "dbc_bound",
            "memo_required",
            "memo_companion_present",
            "structural_cdx_companion_present",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be a genuine bool")
        if self.transform_field_count > self.field_count:
            raise ValueError("transform_field_count cannot exceed field_count")
        _validated_code(self.index_strategy, field_name="index_strategy")
        if self.index_strategy not in {profile.value for profile in TransferProfile}:
            raise ValueError("index_strategy must identify a supported transfer profile")
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
        if not isinstance(self.recovery_enabled, bool):
            raise TypeError("recovery_enabled must be a genuine bool")
        transformation_classes = _bounded_tuple(
            self.transformation_classes,
            field_name="transformation_classes",
            max_items=PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES,
        )
        for item in transformation_classes:
            _validated_code(item, field_name="transformation_classes item")
        if not isinstance(self.vault_strategy, VaultStrategy):
            raise TypeError("vault_strategy must be a VaultStrategy")

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
        # REQ-P5-005/006 producer/verifier coherence: the canonical
        # relationship-fingerprint contract is enforced at the PUBLIC typed
        # input boundary (shared with the transfer verifier) so hostile
        # unbounded/path-bearing values can never survive into a later
        # transfer stage.
        validate_relationship_fingerprint(
            self.relationship_fingerprint, field_name="relationship_fingerprint"
        )
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
        if not isinstance(self.level, RelationalAssuranceLevel):
            raise TypeError("level must be a RelationalAssuranceLevel")
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
    output_data_state: OutputDataState
    numeric_identity_review: tuple[NumericIdentityReview, ...] = ()
    execution_context: _PlanExecutionContext | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        _validated_code(self.plan_id, field_name="plan_id")
        if not isinstance(self.dataset, DatasetIdentity):
            raise TypeError("dataset must be a DatasetIdentity")
        tables = _bounded_tuple(
            self.tables,
            field_name="tables",
            max_items=PUBLIC_JSON_MAX_DATASET_TABLES,
        )
        if not all(isinstance(table, TablePlan) for table in tables):
            raise TypeError("tables must contain only TablePlan values")
        if not isinstance(self.policy, PolicySummary):
            raise TypeError("policy must be a PolicySummary")
        if not isinstance(self.relationships, RelationshipMetadata):
            raise TypeError("relationships must be RelationshipMetadata")
        if not isinstance(self.output_profile, TransferProfile):
            raise TypeError("output_profile must be a TransferProfile")
        if not isinstance(
            self.relationship_assurance_target, RelationalAssuranceLevel
        ):
            raise TypeError(
                "relationship_assurance_target must be a RelationalAssuranceLevel"
            )
        numeric_identity_review = _bounded_tuple(
            self.numeric_identity_review,
            field_name="numeric_identity_review",
            max_items=PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS,
        )
        if not all(
            isinstance(review, NumericIdentityReview)
            for review in numeric_identity_review
        ):
            raise TypeError(
                "numeric_identity_review must contain only NumericIdentityReview values"
            )
        planned_paths = tuple(table.table_path for table in tables)
        if planned_paths != self.dataset.table_paths:
            raise ValueError("plan table order must exactly match dataset.table_paths")
        observed_dbc_paths = tuple(
            sorted(
                (table.table_path for table in self.tables if table.dbc_bound),
                key=lambda path: (path.casefold(), path),
            )
        )
        if observed_dbc_paths != self.dataset.dbc_bound_table_paths:
            raise ValueError(
                "dataset dbc_bound_table_paths must match source table facts"
            )
        if not isinstance(self.output_data_state, OutputDataState):
            raise TypeError("output_data_state must be an OutputDataState")

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
            output_data_state=self.output_data_state,
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
        _validated_operation_id(self.operation_id)
        _validated_code(self.phase_code, field_name="phase_code")
        _validated_code(self.event_code, field_name="event_code")
        if self.phase_code not in PROGRESS_PHASE_CODES:
            raise ValueError("phase_code is not in the public progress vocabulary")
        if self.event_code not in PROGRESS_EVENT_CODES:
            raise ValueError("event_code is not in the public progress vocabulary")
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
        if not isinstance(self.ready, bool):
            raise TypeError("ready must be a genuine bool")
        _validated_code(self.plan_id, field_name="plan_id")
        if not isinstance(self.capabilities, Capabilities):
            raise TypeError("capabilities must be Capabilities")
        for field_name, codes in (
            ("check_codes", self.check_codes),
            ("warning_codes", self.warning_codes),
            ("error_codes", self.error_codes),
        ):
            bounded_codes = _bounded_tuple(
                codes,
                field_name=field_name,
                max_items=PUBLIC_JSON_MAX_FINDING_CODES,
            )
            for code in bounded_codes:
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


#: Per-artifact standalone-IDX outcomes carried by the durable receipt and
#: public result/verification boundaries (REQ-P6-004).
STANDALONE_IDX_EVIDENCE_STATUSES: tuple[str, ...] = (
    "OMITTED_DATA_ONLY",
    "OMITTED_UNVERIFIED",
    "REBUILT_VERIFIED",
)


def standalone_idx_artifact_id(artifact_path: str) -> str:
    """Return the stable identity of one normalized dataset-relative IDX."""
    normalized = _normalized_relative_path(artifact_path)
    if PurePosixPath(normalized).suffix.lower() != ".idx":
        raise ValueError("artifact_path must identify an IDX artifact")
    return "idx-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _sha256_hex(value: str, *, field_name: str) -> str:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class StandaloneIdxEvidence(PublicModel):
    """Bounded per-IDX provenance without definitions or private paths."""

    artifact_id: str
    artifact_path: str
    status: str
    source_sha256: str
    backend_id: str | None = None
    table_path: str | None = None
    output_sha256: str | None = None

    def __post_init__(self) -> None:
        normalized = _normalized_relative_path(self.artifact_path)
        object.__setattr__(self, "artifact_path", normalized)
        expected_id = standalone_idx_artifact_id(normalized)
        if self.artifact_id != expected_id:
            raise ValueError("artifact_id must match artifact_path")
        if self.status not in STANDALONE_IDX_EVIDENCE_STATUSES:
            raise ValueError(
                "status must be one of "
                + ", ".join(STANDALONE_IDX_EVIDENCE_STATUSES)
            )
        _sha256_hex(self.source_sha256, field_name="source_sha256")
        if self.backend_id is not None:
            _validated_code(self.backend_id, field_name="backend_id")
        if self.table_path is not None:
            object.__setattr__(
                self, "table_path", _normalized_relative_path(self.table_path)
            )
        if self.output_sha256 is not None:
            _sha256_hex(self.output_sha256, field_name="output_sha256")
        if self.status == "OMITTED_DATA_ONLY":
            if any(
                item is not None
                for item in (self.backend_id, self.table_path, self.output_sha256)
            ):
                raise ValueError("OMITTED_DATA_ONLY cannot claim backend or output")
        elif self.status == "OMITTED_UNVERIFIED":
            if self.backend_id is None or self.output_sha256 is not None:
                raise ValueError(
                    "OMITTED_UNVERIFIED requires backend_id and no output claim"
                )
        else:
            if (
                self.backend_id is None
                or self.table_path is None
                or self.output_sha256 is None
            ):
                raise ValueError(
                    "REBUILT_VERIFIED requires backend, table and output evidence"
                )

    def to_dict(self) -> JsonDict:
        return _payload(
            "StandaloneIdxEvidence",
            artifact_id=self.artifact_id,
            artifact_path=self.artifact_path,
            status=self.status,
            source_sha256=self.source_sha256,
            backend_id=self.backend_id,
            table_path=self.table_path,
            output_sha256=self.output_sha256,
        )


def _validate_idx_evidence(
    dataset: DatasetIdentity, evidence: tuple[StandaloneIdxEvidence, ...]
) -> None:
    bounded_evidence = _bounded_tuple(
        evidence,
        field_name="index_artifacts",
        max_items=PUBLIC_JSON_MAX_INDEX_ARTIFACTS,
    )
    if not all(isinstance(item, StandaloneIdxEvidence) for item in bounded_evidence):
        raise TypeError("index_artifacts must contain only StandaloneIdxEvidence")
    paths = tuple(item.artifact_path for item in bounded_evidence)
    if paths != dataset.standalone_idx_paths:
        raise ValueError(
            "index_artifacts must exactly match dataset standalone_idx_paths"
        )
    if len({item.artifact_id for item in evidence}) != len(evidence):
        raise ValueError("index_artifacts must have distinct artifact identities")


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
    output_data_state: OutputDataState
    index_artifacts: tuple[StandaloneIdxEvidence, ...] = ()
    execution_context: _PseudonymizationExecutionContext | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        _validated_operation_id(self.operation_id)
        if not isinstance(self.dataset, DatasetIdentity):
            raise TypeError("dataset must be a DatasetIdentity")
        object.__setattr__(self, "output_path", _normalized_relative_path(self.output_path))
        _non_negative(self.table_count, field_name="table_count")
        _non_negative(self.record_count, field_name="record_count")
        if not isinstance(self.vault_created, bool):
            raise TypeError("vault_created must be a genuine bool")
        _validated_code(self.output_fingerprint, field_name="output_fingerprint")
        if not isinstance(self.assurance, RelationalAssurance):
            raise TypeError("assurance must be RelationalAssurance")
        if not isinstance(self.output_data_state, OutputDataState):
            raise TypeError("output_data_state must be an OutputDataState")
        _validate_idx_evidence(self.dataset, self.index_artifacts)

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
            output_data_state=self.output_data_state,
            index_artifacts=self.index_artifacts,
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
    output_data_state: OutputDataState
    index_artifacts: tuple[StandaloneIdxEvidence, ...] = ()

    @property
    def verified(self) -> bool:
        """Derived convenience truth: exactly the PASS status."""
        return self.status is VerificationStatus.PASS

    def __post_init__(self) -> None:
        if not isinstance(self.status, VerificationStatus):
            raise TypeError("status must be a VerificationStatus")
        if not isinstance(self.dataset, DatasetIdentity):
            raise TypeError("dataset must be a DatasetIdentity")
        _validated_operation_id(self.operation_id)
        _non_negative(self.table_count, field_name="table_count")
        _non_negative(self.record_count, field_name="record_count")
        check_codes = _bounded_tuple(
            self.check_codes,
            field_name="check_codes",
            max_items=PUBLIC_JSON_MAX_FINDING_CODES,
        )
        for code in check_codes:
            _validated_code(code, field_name="check_codes item")
        if not isinstance(self.assurance, RelationalAssurance):
            raise TypeError("assurance must be RelationalAssurance")
        if not isinstance(self.output_data_state, OutputDataState):
            raise TypeError("output_data_state must be an OutputDataState")
        _validate_idx_evidence(self.dataset, self.index_artifacts)
        if self.status is VerificationStatus.PASS and any(
            item.status == "OMITTED_UNVERIFIED" for item in self.index_artifacts
        ):
            raise ValueError("PASS cannot contain unverified standalone IDX evidence")

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
            output_data_state=self.output_data_state,
            index_artifacts=self.index_artifacts,
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
        _validated_operation_id(self.operation_id)
        if not isinstance(self.dataset, DatasetIdentity):
            raise TypeError("dataset must be a DatasetIdentity")
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
        if not isinstance(self.profile, TransferProfile):
            raise TypeError("profile must be a TransferProfile")
        _non_negative(self.file_count, field_name="file_count")
        _validated_code(self.manifest_fingerprint, field_name="manifest_fingerprint")
        if not isinstance(self.verified, bool):
            raise TypeError("verified must be a genuine bool")
        if not isinstance(self.assurance, RelationalAssurance):
            raise TypeError("assurance must be RelationalAssurance")

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


# ---------------------------------------------------------------------------
# Injected Windows/VFP index-backend protocol models (REQ-P6-001)
# ---------------------------------------------------------------------------
#: Bounded artifact classes one index backend may be asked to work on.
INDEX_ARTIFACT_CLASSES: tuple[str, ...] = ("STRUCTURAL_CDX", "STANDALONE_IDX")

#: Bounded truthful rebuild outcomes.
INDEX_BACKEND_RESULT_STATUSES: tuple[str, ...] = (
    "REBUILT",
    "REFUSED",
    "FAILED",
)

#: Bounded rebuild detail codes and their closed status pairing.
INDEX_BACKEND_RESULT_DETAIL_CODES: tuple[str, ...] = (
    "REBUILT_OK",
    "REFUSED",
    "INTERNAL_ERROR",
)

#: Bounded truthful verification outcomes.
INDEX_VERIFICATION_STATUSES: tuple[str, ...] = (
    "VERIFIED",
    "MISMATCH",
    "FAILED",
)

#: Bounded verification detail codes.
INDEX_VERIFICATION_DETAIL_CODES: tuple[str, ...] = (
    "VERIFIED_OK",
    "OPEN_FAILED",
    "RECORD_COUNT_MISMATCH",
    "TAG_INVENTORY_MISMATCH",
    "INTERNAL_ERROR",
)

#: Bounded authoritative association outcomes for one inventoried IDX.
STANDALONE_IDX_ASSOCIATION_STATUSES: tuple[str, ...] = (
    "ASSOCIATED",
    "UNAVAILABLE",
)

STANDALONE_IDX_ASSOCIATION_DETAIL_CODES: tuple[str, ...] = (
    "ASSOCIATED_OK",
    "DEFINITION_UNAVAILABLE",
)


@dataclass(frozen=True, slots=True)
class IndexBackendCapability(PublicModel):
    """JSON-safe capability statement of ONE injected backend (REQ-P6-001).

    The bounded, closed vocabulary lets the pipeline fail closed on unknown
    or malformed backend contracts: an unknown ``protocol_schema_version`` or
    unsupported ``backend_schema_version`` shape is a typed failure, never a
    silent best-effort downgrade.
    """

    backend_id: str
    backend_schema_version: str
    protocol_schema_version: str
    supports_structural_cdx_rebuild: bool
    supports_standalone_idx_rebuild: bool
    supports_verification: bool
    vfp_runtime_available: bool

    def __post_init__(self) -> None:
        _validated_code(self.backend_id, field_name="backend_id")
        _validated_code(
            self.backend_schema_version, field_name="backend_schema_version"
        )
        if self.protocol_schema_version != INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION:
            raise ValueError(
                "protocol_schema_version must be "
                f"{INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION}"
            )
        for name in (
            "supports_structural_cdx_rebuild",
            "supports_standalone_idx_rebuild",
            "supports_verification",
            "vfp_runtime_available",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a genuine bool")

    def to_dict(self) -> JsonDict:
        return _payload(
            "IndexBackendCapability",
            backend_id=self.backend_id,
            backend_schema_version=self.backend_schema_version,
            protocol_schema_version=self.protocol_schema_version,
            supports_structural_cdx_rebuild=self.supports_structural_cdx_rebuild,
            supports_standalone_idx_rebuild=self.supports_standalone_idx_rebuild,
            supports_verification=self.supports_verification,
            vfp_runtime_available=self.vfp_runtime_available,
        )


@dataclass(frozen=True, slots=True)
class IndexBackendResult(PublicModel):
    """JSON-safe verdict of one authoritative index operation (REQ-P6-001)."""

    backend_id: str
    protocol_schema_version: str
    artifact_class: str
    table_path: str
    status: str
    detail_code: str
    artifact_path: str | None = None

    def __post_init__(self) -> None:
        _validated_code(self.backend_id, field_name="backend_id")
        if self.protocol_schema_version != INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION:
            raise ValueError(
                "protocol_schema_version must be "
                f"{INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION}"
            )
        if self.artifact_class not in INDEX_ARTIFACT_CLASSES:
            raise ValueError(
                "artifact_class must be one of " + ", ".join(INDEX_ARTIFACT_CLASSES)
            )
        object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))
        if self.status not in INDEX_BACKEND_RESULT_STATUSES:
            raise ValueError(
                "status must be one of " + ", ".join(INDEX_BACKEND_RESULT_STATUSES)
            )
        expected_detail = {
            "REBUILT": "REBUILT_OK",
            "REFUSED": "REFUSED",
            "FAILED": "INTERNAL_ERROR",
        }[self.status]
        if self.detail_code != expected_detail:
            raise ValueError(
                f"detail_code must be {expected_detail} when status is {self.status}"
            )
        if self.artifact_class == "STANDALONE_IDX":
            if self.artifact_path is None:
                raise ValueError("STANDALONE_IDX result requires artifact_path")
            object.__setattr__(
                self, "artifact_path", _normalized_relative_path(self.artifact_path)
            )
        elif self.artifact_path is not None:
            raise ValueError("artifact_path is only valid for STANDALONE_IDX")

    def to_dict(self) -> JsonDict:
        return _payload(
            "IndexBackendResult",
            backend_id=self.backend_id,
            protocol_schema_version=self.protocol_schema_version,
            artifact_class=self.artifact_class,
            table_path=self.table_path,
            status=self.status,
            detail_code=self.detail_code,
            artifact_path=self.artifact_path,
        )


@dataclass(frozen=True, slots=True)
class IndexVerificationResult(PublicModel):
    """JSON-safe verdict of one authoritative index verification (REQ-P6-003).

    Objective record/tag evidence remains in the process-local backend
    outcome. This public verdict contains no protected paths or tag names.
    """

    backend_id: str
    protocol_schema_version: str
    artifact_class: str
    table_path: str
    status: str
    detail_code: str
    artifact_path: str | None = None

    def __post_init__(self) -> None:
        _validated_code(self.backend_id, field_name="backend_id")
        if self.protocol_schema_version != INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION:
            raise ValueError(
                "protocol_schema_version must be "
                f"{INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION}"
            )
        if self.artifact_class not in INDEX_ARTIFACT_CLASSES:
            raise ValueError(
                "artifact_class must be one of " + ", ".join(INDEX_ARTIFACT_CLASSES)
            )
        object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))
        if self.status not in INDEX_VERIFICATION_STATUSES:
            raise ValueError(
                "status must be one of " + ", ".join(INDEX_VERIFICATION_STATUSES)
            )
        if self.detail_code not in INDEX_VERIFICATION_DETAIL_CODES:
            raise ValueError(
                "detail_code must be one of " + ", ".join(INDEX_VERIFICATION_DETAIL_CODES)
            )
        allowed_details = {
            "VERIFIED": frozenset(("VERIFIED_OK",)),
            "MISMATCH": frozenset(
                ("RECORD_COUNT_MISMATCH", "TAG_INVENTORY_MISMATCH")
            ),
            "FAILED": frozenset(("OPEN_FAILED", "INTERNAL_ERROR")),
        }[self.status]
        if self.detail_code not in allowed_details:
            raise ValueError(
                f"detail_code {self.detail_code} is invalid for status {self.status}"
            )
        if self.artifact_class == "STANDALONE_IDX":
            if self.artifact_path is None:
                raise ValueError("STANDALONE_IDX result requires artifact_path")
            object.__setattr__(
                self, "artifact_path", _normalized_relative_path(self.artifact_path)
            )
        elif self.artifact_path is not None:
            raise ValueError("artifact_path is only valid for STANDALONE_IDX")

    def to_dict(self) -> JsonDict:
        return _payload(
            "IndexVerificationResult",
            backend_id=self.backend_id,
            protocol_schema_version=self.protocol_schema_version,
            artifact_class=self.artifact_class,
            table_path=self.table_path,
            status=self.status,
            detail_code=self.detail_code,
            artifact_path=self.artifact_path,
        )


@dataclass(frozen=True, slots=True)
class StandaloneIdxAssociationResult(PublicModel):
    """Authoritative backend association verdict for one source IDX."""

    backend_id: str
    protocol_schema_version: str
    artifact_path: str
    status: str
    detail_code: str
    table_path: str | None = None

    def __post_init__(self) -> None:
        _validated_code(self.backend_id, field_name="backend_id")
        if self.protocol_schema_version != INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION:
            raise ValueError(
                "protocol_schema_version must be "
                f"{INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION}"
            )
        object.__setattr__(
            self, "artifact_path", _normalized_relative_path(self.artifact_path)
        )
        standalone_idx_artifact_id(self.artifact_path)
        if self.status not in STANDALONE_IDX_ASSOCIATION_STATUSES:
            raise ValueError(
                "status must be one of "
                + ", ".join(STANDALONE_IDX_ASSOCIATION_STATUSES)
            )
        expected_detail = {
            "ASSOCIATED": "ASSOCIATED_OK",
            "UNAVAILABLE": "DEFINITION_UNAVAILABLE",
        }[self.status]
        if self.detail_code != expected_detail:
            raise ValueError(
                f"detail_code must be {expected_detail} when status is {self.status}"
            )
        if self.status == "ASSOCIATED":
            if self.table_path is None:
                raise ValueError("ASSOCIATED requires table_path")
            object.__setattr__(
                self, "table_path", _normalized_relative_path(self.table_path)
            )
        elif self.table_path is not None:
            raise ValueError("UNAVAILABLE cannot claim table_path")

    def to_dict(self) -> JsonDict:
        return _payload(
            "StandaloneIdxAssociationResult",
            backend_id=self.backend_id,
            protocol_schema_version=self.protocol_schema_version,
            artifact_path=self.artifact_path,
            status=self.status,
            detail_code=self.detail_code,
            table_path=self.table_path,
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
    StandaloneIdxEvidence,
    IndexBackendCapability,
    IndexBackendResult,
    IndexVerificationResult,
    StandaloneIdxAssociationResult,
)

__all__ = [
    "MODEL_SCHEMA_VERSION",
    "PUBLIC_JSON_MAX_TOKEN_LENGTH",
    "PUBLIC_JSON_MAX_OPERATION_ID_LENGTH",
    "PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH",
    "PUBLIC_JSON_MAX_DATASET_TABLES",
    "PUBLIC_JSON_MAX_INDEX_ARTIFACTS",
    "PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS",
    "PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES",
    "PUBLIC_JSON_MAX_FINDING_CODES",
    "PUBLIC_JSON_MAX_COUNT",
    "PROGRESS_PHASE_CODES",
    "PROGRESS_EVENT_CODES",
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
    "OutputDataState",
    "NumericIdentityReview",
    "ProgressEvent",
    "PreflightResult",
    "PseudonymizationResult",
    "VerificationStatus",
    "VerificationResult",
    "RawByteEquivalence",
    "RecoveryResult",
    "TransferBundleResult",
    "StandaloneIdxEvidence",
    "STANDALONE_IDX_EVIDENCE_STATUSES",
    "standalone_idx_artifact_id",
    "TransferProfile",
    "VaultStrategy",
    "INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION",
    "INDEX_ARTIFACT_CLASSES",
    "INDEX_BACKEND_RESULT_STATUSES",
    "INDEX_BACKEND_RESULT_DETAIL_CODES",
    "INDEX_VERIFICATION_STATUSES",
    "INDEX_VERIFICATION_DETAIL_CODES",
    "STANDALONE_IDX_ASSOCIATION_STATUSES",
    "STANDALONE_IDX_ASSOCIATION_DETAIL_CODES",
    "IndexBackendCapability",
    "IndexBackendResult",
    "IndexVerificationResult",
    "StandaloneIdxAssociationResult",
]
