"""The Phase 4 two-pass engine coordinator (REQ-P4-001 through P4-007).

This module binds the immutable typed plan, the resolved policy and the
declared relationship document into the engine's INTERNAL field directives
(:mod:`dbf_anonymizer.engine.directives`) and runs the bounded two-pass
production pipeline:

* PASS 1 (:mod:`dbf_anonymizer.engine.pass1`) — one deterministic Direct
  Read scan that observes mapping constraints and relationship evidence
  into the protected ephemeral SQLite spool, then finalizes the vault
  allocations;
* PASS 2 (:mod:`dbf_anonymizer.engine.pass2`) — a second Direct Read pass
  that resolves the finalized mappings from the protected vault state,
  transforms one record at a time and feeds the ONE public Direct Write
  boundary, followed by the streaming before/after evidence comparison.

The engine is an INTERNAL implementation boundary used by the public
``pseudonymize`` service; it is not itself part of the root public API.
Supported records are freshly
reconstructed from transformed typed values with deleted markers and physical
order preserved.  The versioned field matrix in :mod:`dbf_anonymizer.policy`
is shared with planning/preflight and execution.
Unsupported execution fails CLOSED before any output is produced — the engine never publishes a
partially transformed dataset: every table written by THIS run is removed
again when the run fails or is cancelled (full crash-resilient publication
state belongs to P4-009).
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Callable, Sequence

import dbfbridge

from dbf_anonymizer.engine import direct_io
from dbf_anonymizer.engine.directives import (
    ACTION_MEMO,
    ACTION_TEMPORAL,
    ACTION_TEXT,
    EnginePlan,
    FieldDirective,
    RelationDirective,
    RelationPassSummary,
    TableDirective,
    TwoPassResult,
)
from dbf_anonymizer.engine.pass1 import (
    PassOneOutcome,
    run_pass_one,
    run_pass_one_finalize,
)
from dbf_anonymizer.engine.pass2 import run_pass_two
from dbf_anonymizer.engine.locking import DestinationLock
from dbf_anonymizer.engine.publication import (
    DatasetStaging,
    FaultInjector,
    PublicationIdentity,
    build_publication_identity,
    fingerprint_dataset,
    reconcile_completed_staging_residual,
    result_from_receipt,
    result_receipt,
)
from dbf_anonymizer.engine.state import (
    MAX_RECORD_BATCH,
    PassOneSpool,
    cleanup_evidence_root,
    create_evidence_root,
    refuse_evidence_leftovers,
    refuse_spool_leftovers,
)
from dbf_anonymizer.errors import (
    ErrorCode,
    ErrorContext,
    MappingError,
    PathError,
    PublicationError,
    VaultError,
)
from dbf_anonymizer.index_backend import (
    IndexBackendContract,
    IndexRebuildRequest,
    IndexVerificationRequest,
    index_backend_failure,
    require_backend_runtime,
    run_backend_rebuild,
    run_backend_verification,
    require_backend_support,
    require_backend_verification,
)
from dbf_anonymizer.models import Plan, TransferProfile
from dbf_anonymizer.policy import classify_field_capability, resolve_policy
from dbf_anonymizer.relationships.models import (
    RelationGroup,
    RelationshipDocument,
)
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)
from dbf_anonymizer.transforms.numeric_keys import (
    NumericKeyDomain,
    NumericKeyMemberRange,
    integer_member,
    integral_numeric_member,
    numeric_key_domain_for,
)
from dbf_anonymizer.vault.numeric_allocation import numeric_key_domain_id
from dbf_anonymizer.vault.store import VaultDatabase, new_writer_token
from dbf_anonymizer.vault.schema import (
    VAULT_OPERATION_STATE_COMPLETED,
    VAULT_OPERATION_STATE_STARTED,
)
from dbf_anonymizer.vault.temporal_allocation import TemporalShiftDomain

__all__ = [
    "EnginePlan",
    "TwoPassResult",
    "run_two_pass",
    "build_engine_plan",
]


def _path_failure(detail_code: str) -> PathError:
    return PathError(
        ErrorCode.PATH_INVALID,
        context=ErrorContext(operation="engine", detail_code=detail_code),
    )


def _mapping_failure(detail_code: str) -> MappingError:
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(operation="engine", detail_code=detail_code),
    )


def _identity_failure(detail_code: str) -> VaultError:
    """A typed execution-identity refusal (same family as the P2-010
    vault fingerprint checks): value-free, path-free, stable."""
    return VaultError(
        ErrorCode.VAULT_IDENTITY_MISMATCH,
        context=ErrorContext(operation="engine", detail_code=detail_code),
    )


def _publication_failure(detail_code: str) -> PublicationError:
    return PublicationError(
        ErrorCode.PUBLICATION_INCOMPLETE,
        context=ErrorContext(operation="publication", detail_code=detail_code),
    )


def _destination_conflict(detail_code: str) -> PathError:
    return PathError(
        ErrorCode.DESTINATION_CONFLICT,
        context=ErrorContext(operation="publication", detail_code=detail_code),
    )


def _existing_completed_result(
    identity: PublicationIdentity,
    vault: VaultDatabase,
    *,
    control: ProgressController,
) -> TwoPassResult | None:
    """Recognize an exact completed retry or refuse every conflicting state."""
    operation = vault.operation_record(identity.operation_id)
    destination_operation = vault.operation_for_destination(
        identity.destination_identity
    )
    if operation is None:
        if destination_operation is not None:
            raise _destination_conflict("DESTINATION_BOUND_TO_OTHER_OPERATION")
        if identity.staging_root.exists():
            raise _publication_failure("STALE_STAGING_DETECTED")
        if identity.destination.exists():
            raise _destination_conflict("UNOWNED_TARGET_EXISTS")
        return None

    expected = {
        "source_fingerprint": vault.source_fingerprint,
        "policy_fingerprint": vault.policy_fingerprint,
        "relationship_fingerprint": vault.relationship_fingerprint,
        "vault_fingerprint": identity.vault_fingerprint,
        "destination_identity": identity.destination_identity,
        "binding_fingerprint": identity.binding_fingerprint,
    }
    if any(operation.get(key) != value for key, value in expected.items()):
        raise _identity_failure("ENGINE_OPERATION_BINDING_MISMATCH")
    if (
        destination_operation is None
        or destination_operation.get("operation_id") != identity.operation_id
    ):
        raise _publication_failure("DESTINATION_OPERATION_MISSING")
    if operation.get("state") == VAULT_OPERATION_STATE_STARTED:
        raise _publication_failure("STALE_OPERATION_DETECTED")
    if operation.get("state") != VAULT_OPERATION_STATE_COMPLETED:
        raise _publication_failure("OPERATION_STATE_UNKNOWN")
    # The completed operation is classified ONLY from complete evidence:
    # the durable receipt must exist, parse under the expected schema and
    # match the stored authoritative fingerprint, and the final destination
    # must exist and match that same authoritative fingerprint — ALL of
    # that BEFORE any residual private staging metadata is removed.
    stored_fingerprint = operation.get("output_fingerprint")
    receipt = operation.get("result_json")
    if stored_fingerprint is None or receipt is None:
        raise _publication_failure("COMPLETED_OPERATION_INCOMPLETE")
    actual_fingerprint = fingerprint_dataset(
        identity.destination, checkpoint=control.check_cancelled
    )
    if actual_fingerprint != stored_fingerprint:
        raise _publication_failure("COMPLETED_OUTPUT_MISMATCH")
    result = result_from_receipt(receipt)
    if (
        result.operation_id != identity.operation_id
        or result.output_fingerprint != stored_fingerprint
    ):
        raise _publication_failure("OPERATION_RECEIPT_MISMATCH")
    if identity.staging_root.exists():
        # REQ-P5-008 case C: a crash after the durable completion receipt
        # but before private metadata cleanup. The completed output is now
        # FULLY proven (receipt schema, receipt/operation identity and the
        # destination fingerprint) — only now may the residual private
        # metadata be reconciled, and only when the crash state itself is
        # objectively owned and coherent (exact schema version, PROMOTED
        # phase, matching operation/destination/binding identities and an
        # output fingerprint equal to the authoritative completed one).
        # Any missing, malformed or mismatched element fails CLOSED: the
        # ambiguous crash state is kept and the completed output is not
        # modified.
        reconcile_completed_staging_residual(
            identity,
            identity.operation_id,
            identity.destination_identity,
            output_fingerprint=stored_fingerprint,
        )
    return result


def _numeric_member_of(
    numeric_groups: Sequence[tuple[RelationGroup, str]],
    table_path: str,
    field_name: str,
) -> tuple[RelationGroup, str] | None:
    """The reversible numeric group binding of one field, or ``None``."""
    for group, domain_id in numeric_groups:
        for member in group.members:
            if (
                member.is_numeric_member
                and member.table_path == table_path
                and member.field_name == field_name
            ):
                return (group, domain_id)
    return None


def _member_range_of(group: RelationGroup, field_name: str) -> NumericKeyMemberRange:
    """The origin-member representation facts of one numeric member."""
    for member in group.members:
        if member.field_name == field_name:
            if member.dbf_type == "I":
                return integer_member()
            if member.dbf_type == "N":
                return integral_numeric_member(int(member.byte_width))
    raise _path_failure("ENGINE_NUMERIC_MEMBER_UNKNOWN")


def build_engine_plan(
    plan: Plan,
    *,
    source_root: Path,
    policy: object,
    relationship_document: RelationshipDocument | None,
) -> EnginePlan:
    """Bind the immutable Plan to the engine's internal directives.

    The directives are derived from the SAME authoritative sources the
    planner used: the resolved policy, the public schema facts of every
    planned table and the declared relationship document.  Unsupported
    execution fails closed BEFORE any pass runs.
    """
    merged_policy, _policy_fp = resolve_policy(policy)  # type: ignore[arg-type]
    tables: list[TableDirective] = []
    relations: list[RelationDirective] = []
    text_present = False
    numeric_present = False
    temporal_present = False

    structural_cdx_tables: list[str] = []
    numeric_groups: list[tuple[RelationGroup, str]] = []
    if relationship_document is not None:
        from dbf_anonymizer.relationships.models import (
            NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
        )

        for group in relationship_document.groups:
            if group.numeric_strategy == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE:
                numeric_groups.append(
                    (
                        group,
                        numeric_key_domain_id(
                            plan.relationships.relationship_fingerprint,
                            group.relation_id,
                        ),
                    )
                )

    for table_plan in plan.tables:
        relative_path = str(table_plan.table_path)
        table = direct_io.read_source_table(Path(source_root), relative_path)
        schema = table.schema
        transformed: list[FieldDirective] = []
        memo_fields: list[str] = []
        temporal_fields: list[str] = []
        for field_info in schema.fields:
            name = str(field_info.name)
            dbf_type = str(field_info.dbf_type).upper()
            action, is_unsafe, is_system = classify_field_capability(
                dbf_type,
                name,
                bool(field_info.supported),
                bool(field_info.is_binary),
                bool(field_info.system),
                bool(field_info.nocptrans),
                merged_policy,
            )
            if is_system:
                continue
            if is_unsafe:
                raise _path_failure("ENGINE_FIELD_UNSUPPORTED")
            numeric_binding = _numeric_member_of(
                numeric_groups, relative_path, field_name=name
            )
            if numeric_binding is not None:
                group, domain_id = numeric_binding
                transformed.append(
                    FieldDirective(
                        field_name=name,
                        action=ACTION_TEXT,
                        dbf_type=dbf_type,
                        encoding=str(schema.encoding),
                        byte_width=int(field_info.length),
                        numeric_domain_id=domain_id,
                        numeric_member_range=_member_range_of(group, name),
                    )
                )
                numeric_present = True
                continue
            if action is None:
                continue
            if action == ACTION_TEXT:
                transformed.append(
                    FieldDirective(
                        field_name=name,
                        action=action,
                        dbf_type=dbf_type,
                        encoding=str(schema.encoding),
                        byte_width=int(field_info.length),
                    )
                )
                text_present = True
            elif action == ACTION_MEMO:
                transformed.append(
                    FieldDirective(
                        field_name=name,
                        action=action,
                        dbf_type=dbf_type,
                        encoding=str(schema.encoding),
                        byte_width=int(field_info.length),
                    )
                )
                memo_fields.append(name)
            elif action == ACTION_TEMPORAL:
                transformed.append(
                    FieldDirective(
                        field_name=name,
                        action=action,
                        dbf_type=dbf_type,
                        encoding=str(schema.encoding),
                        byte_width=int(field_info.length),
                    )
                )
                temporal_fields.append(name)
                temporal_present = True
            else:
                raise _path_failure("ENGINE_ACTION_UNSUPPORTED")
        tables.append(
            TableDirective(
                relative_path=relative_path,
                transformed=tuple(transformed),
                memo_fields=tuple(memo_fields),
                temporal_fields=tuple(temporal_fields),
                structural_cdx=schema.has_structural_cdx,
                record_count=int(schema.record_count),
            )
        )
        if schema.has_structural_cdx:
            structural_cdx_tables.append(relative_path)

    if relationship_document is not None:
        # EVERY declared relation is tracked for the verification evidence —
        # declared text relations and reversible numeric relations alike.
        # BLOCKER 2 fix: the relation member fields of EVERY table are
        # collected so the pass-1 projection reads every declared member
        # (identity members included) — a missing member would otherwise be
        # misread as NULL in the BEFORE evidence.
        numeric_by_group: dict[RelationGroup, str] = dict(numeric_groups)
        relation_fields_by_table: dict[str, set[str]] = {}
        for group in relationship_document.groups:
            group_domain: str | None = numeric_by_group.get(group)
            domain: NumericKeyDomain | None = None
            if group_domain is not None:
                numeric_member_list = [
                    member for member in group.members if member.is_numeric_member
                ]
                ranges = []
                for member in numeric_member_list:
                    if member.dbf_type == "I":
                        ranges.append(integer_member())
                    elif member.dbf_type == "N":
                        ranges.append(integral_numeric_member(int(member.byte_width)))
                    else:  # pragma: no cover - the planner refuses others
                        raise _path_failure("ENGINE_FIELD_UNSUPPORTED")
                domain = numeric_key_domain_for(ranges)
            parent_members = group.members_for_role(
                "PRIMARY"
            ) or group.members_for_role("CANDIDATE")
            foreign_members = group.members_for_role("FOREIGN")
            parent_table = str(parent_members[0].table_path)
            foreign_table = str(foreign_members[0].table_path)
            relation_fields_by_table.setdefault(parent_table, set()).update(
                str(member.field_name) for member in parent_members
            )
            relation_fields_by_table.setdefault(foreign_table, set()).update(
                str(member.field_name) for member in foreign_members
            )
            relations.append(
                RelationDirective(
                    relation_id=str(group.relation_id),
                    composite_arity=len(parent_members),
                    parent_table=parent_table,
                    foreign_table=foreign_table,
                    parent_fields=tuple(
                        str(member.field_name) for member in parent_members
                    ),
                    foreign_fields=tuple(
                        str(member.field_name) for member in foreign_members
                    ),
                    numeric_domain_id=group_domain,
                    numeric_domain=domain,
                )
            )
        updated_tables: list[TableDirective] = []
        for directive in tables:
            updated_tables.append(
                TableDirective(
                    relative_path=directive.relative_path,
                    transformed=directive.transformed,
                    memo_fields=directive.memo_fields,
                    temporal_fields=directive.temporal_fields,
                    relation_fields=tuple(
                        sorted(
                            relation_fields_by_table.get(directive.relative_path, set())
                        )
                    ),
                    structural_cdx=directive.structural_cdx,
                    record_count=directive.record_count,
                )
            )
        tables = updated_tables
    return EnginePlan(
        plan=plan,
        tables=tuple(tables),
        relations=tuple(relations),
        text_present=text_present,
        numeric_present=numeric_present,
        temporal_present=temporal_present,
        structural_cdx_tables=tuple(structural_cdx_tables),
    )


def _revalidate_execution_identity(
    plan: Plan,
    *,
    source_root: Path,
    output_root: Path,
    vault_path: Path,
    resolved_policy: object,
    relationship_document: RelationshipDocument | None,
    cancel_probe: Callable[[], None] | None = None,
    progress_probe: Callable[[int, int, str], None] | None = None,
) -> None:
    """The pre-execution trust revalidation (zero side effects on refusal).

    Re-runs the EXISTING canonical kernels — the source fingerprint kernel
    of :func:`build_plan`, the preflight overlap semantics and the policy
    fingerprint — instead of inventing a divergent second implementation.
    Every refusal happens BEFORE the vault, the spool or any output
    artifact is created.

    REQ-P1-008: the source refingerprint is a potentially long scan inside
    a public long-running operation, so the caller's cooperative
    cancellation probe (the SAME controller probe used everywhere else —
    a returning-true check raises the typed ``CancellationError`` and a
    raising callback stays contained as ``CANCEL_CALLBACK_FAILED``) is
    polled at the kernel's scan safe points, and the optional progress
    probe (the SAME controller, ``SOURCE_REVALIDATION`` phase) reports
    bounded per-artifact scan progress — reusing the existing fingerprint
    kernel hooks and quanta, never a per-byte callback flood.
    """
    from dbf_anonymizer.discovery import (
        collect_fingerprint_entries,
        compute_source_fingerprint,
    )
    from dbf_anonymizer.policy import compute_policy_fingerprint
    from dbf_anonymizer.preflight import _paths_overlap
    from dbf_anonymizer.relationships.document import relationship_fingerprint

    entries = collect_fingerprint_entries(
        source_root, cancel_probe=cancel_probe, progress_probe=progress_probe
    )
    current_source = compute_source_fingerprint(entries)
    if current_source != plan.dataset.source_fingerprint:
        raise _identity_failure("ENGINE_SOURCE_FINGERPRINT_MISMATCH")
    if _paths_overlap(source_root, output_root, vault_path):
        raise _path_failure("ENGINE_PATH_OVERLAP")
    current_policy = compute_policy_fingerprint(resolved_policy)  # type: ignore[arg-type]
    if current_policy != plan.policy.policy_fingerprint:
        raise _identity_failure("ENGINE_POLICY_IDENTITY_MISMATCH")
    declared = plan.relationships
    if relationship_document is not None:
        if relationship_fingerprint(relationship_document) != (
            declared.relationship_fingerprint
        ):
            raise _identity_failure("ENGINE_RELATIONSHIP_IDENTITY_MISMATCH")
        if len(relationship_document.groups) != declared.relation_count:
            raise _identity_failure("ENGINE_RELATIONSHIP_COUNT_MISMATCH")
    elif declared.relation_count > 0:
        raise _identity_failure("ENGINE_RELATIONSHIP_DOCUMENT_MISSING")


class _WriterLease:
    """The production writer-lease context of the engine (P2 policy)."""

    __slots__ = ("_vault", "_token")

    def __init__(self, vault: VaultDatabase) -> None:
        self._vault = vault
        self._token = new_writer_token()

    def __enter__(self) -> VaultDatabase:
        self._vault.acquire_writer_lease(self._token)
        return self._vault

    def __exit__(self, *exc_info: object) -> None:
        self._vault.release_writer_lease(self._token)


def _register_memo_structure(
    engine_plan: EnginePlan, vault: VaultDatabase
) -> dict[tuple[str, str], tuple[str, str]]:
    """Register stable vault identities for every transformed memo field.

    Memo identities must exist BEFORE pass 1 (the recovery rows reference
    the stable field identity while records are observed). The complete
    per-field policy application (text/numeric/temporal actions and their
    mapping domains) is registered AFTER pass 1 finalize by
    :func:`_register_transform_fields`, once the durable mapping-domain
    rows exist.
    """

    bindings: dict[tuple[str, str], tuple[str, str]] = {}
    if not any(table.memo_fields for table in engine_plan.tables):
        return bindings
    with vault.transaction():
        existing_tables = {
            str(row["relative_path"]): str(row["table_id"]) for row in vault.tables()
        }
        for table in engine_plan.tables:
            if not table.memo_fields:
                continue
            table_id = existing_tables.get(table.relative_path)
            if table_id is None:
                table_id = vault.register_table(table.relative_path)
                existing_tables[table.relative_path] = table_id
            for field in table.transformed:
                if field.action != ACTION_MEMO:
                    continue
                existing = (
                    vault._internal_connection()
                    .execute(
                        "SELECT field_id, dbf_type, width, encoding, transform_action "
                        "FROM fields WHERE table_id = ? AND name = ?",
                        (table_id, field.field_name),
                    )
                    .fetchone()
                )
                if existing is None:
                    field_id = vault.register_field(
                        table_id,
                        field.field_name,
                        dbf_type=field.dbf_type,
                        width=field.byte_width,
                        encoding=field.encoding,
                        transform_action=field.action,
                    )
                else:
                    if tuple(existing[1:]) != (
                        field.dbf_type,
                        field.byte_width,
                        field.encoding,
                        field.action,
                    ):
                        raise _identity_failure("ENGINE_MEMO_STRUCTURE_MISMATCH")
                    field_id = str(existing[0])
                bindings[(table.relative_path, field.field_name)] = (
                    table_id,
                    field_id,
                )
    return bindings


#: The explicit KEEP action of the durable field-policy ledger: every
#: non-system application field carries an explicit resolved action, so
#: "missing row" can never masquerade as an identity decision (REQ-P5-001).
ACTION_KEEP = "KEEP"


def _register_transform_fields(
    engine_plan: EnginePlan,
    vault: VaultDatabase,
    outcome: PassOneOutcome,
    temporal_domain: TemporalShiftDomain | None,
    *,
    source_root: Path,
) -> None:
    """Register the COMPLETE durable per-field policy ledger (REQ-P5-001).

    Every non-system application field of every planned table is recorded
    with its EXPLICIT resolved action and mapping domain so the public
    dataset verification can independently check the applied policy without
    the private plan — absence of a row can never mean KEEP. The ledger is
    derived from the SAME authoritative field capability/policy logic used
    by planning/preflight/P4 (``build_engine_plan``): transformed fields
    carry their directive action and mapping domain, every other supported
    application field carries the explicit ``KEEP`` action with no mapping
    domain, and the writer-managed ``_NullFlags`` system column is never a
    privacy-mapping field.

    Memo fields are registered earlier (recovery-row FK order); their rows
    are revalidated here. Domain FKs require the mapping-domain rows, which
    exist only after pass 1 finalize; re-registration on a resumed run
    reuses and revalidates existing rows deterministically.
    """
    if not engine_plan.tables:
        return
    text_domain_id = outcome.text_domain_id
    with vault.transaction():
        existing_tables = {
            str(row["relative_path"]): str(row["table_id"]) for row in vault.tables()
        }
        for table in engine_plan.tables:
            source_table = direct_io.read_source_table(
                source_root, table.relative_path
            )
            transformed_by_name = {
                field.field_name: field for field in table.transformed
            }
            table_id = existing_tables.get(table.relative_path)
            if table_id is None:
                table_id = vault.register_table(table.relative_path)
                existing_tables[table.relative_path] = table_id
            for field_info in source_table.schema.fields:
                name = str(field_info.name)
                if str(field_info.dbf_type).upper() == "0":
                    continue  # writer-managed system state (_NullFlags)
                directive = transformed_by_name.get(name)
                if directive is not None:
                    domain_id: str | None = None
                    if directive.numeric_domain_id is not None:
                        domain_id = directive.numeric_domain_id
                    elif directive.action == ACTION_TEXT and text_domain_id is not None:
                        domain_id = text_domain_id
                    elif (
                        directive.action == ACTION_TEMPORAL
                        and temporal_domain is not None
                    ):
                        domain_id = (
                            temporal_domain.domain_id
                            if vault._internal_connection()
                            .execute(
                                "SELECT 1 FROM mapping_domains WHERE domain_id = ?",
                                (temporal_domain.domain_id,),
                            )
                            .fetchone()
                            is not None
                            else None
                        )
                    expected = (
                        directive.dbf_type,
                        str(directive.byte_width),
                        directive.encoding,
                        directive.action,
                        domain_id,
                    )
                else:
                    expected = (
                        str(field_info.dbf_type).upper(),
                        str(int(field_info.length)),
                        str(source_table.schema.encoding),
                        ACTION_KEEP,
                        None,
                    )
                existing = (
                    vault._internal_connection()
                    .execute(
                        "SELECT field_id, dbf_type, width, encoding, transform_action, "
                        "mapping_domain_id FROM fields WHERE table_id = ? AND name = ?",
                        (table_id, name),
                    )
                    .fetchone()
                )
                if existing is None:
                    vault.register_field(
                        table_id,
                        name,
                        dbf_type=expected[0],
                        width=int(expected[1]),
                        encoding=expected[2],
                        transform_action=expected[3],
                        mapping_domain_id=expected[4],
                    )
                elif tuple(
                    None if value is None else str(value) for value in existing[1:]
                ) != expected:
                    raise _identity_failure("ENGINE_FIELD_STRUCTURE_MISMATCH")


def _cleanup_engine_resources(
    spool: PassOneSpool | None,
    vault: VaultDatabase | None,
) -> VaultError | None:
    """Attempt every acquired cleanup and return one safe typed failure.

    The ephemeral original-bearing spool is cleaned first, then the durable
    vault handle is closed.  A failure in either attempt never prevents the
    other.  Underlying failures remain available for internal diagnostics but
    are excluded from the public error serialization.
    """
    failures: list[tuple[str, BaseException]] = []
    if spool is not None:
        try:
            spool.cleanup()
        except BaseException as error:
            failures.append(("spool", error))
    if vault is not None:
        try:
            vault.close()
        except BaseException as error:
            failures.append(("vault", error))
    if not failures:
        return None
    failed_resources = {resource for resource, _error in failures}
    if failed_resources == {"spool", "vault"}:
        detail_code = "ENGINE_MULTIPLE_RESOURCE_CLEANUP_FAILED"
    elif "spool" in failed_resources:
        detail_code = "ENGINE_SPOOL_CLEANUP_FAILED"
    else:
        detail_code = "ENGINE_VAULT_CLOSE_FAILED"
    failure = VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="two_pass", detail_code=detail_code),
    )
    # Private diagnostic evidence only: AnonymizerError.to_dict() deliberately
    # exposes neither these exceptions nor their potentially unsafe messages.
    setattr(failure, "_resource_cleanup_failures", tuple(failures))
    return failure


def _run_vfp_indexed_rebuild_and_verify(
    engine_plan: EnginePlan,
    *,
    source_root: Path,
    staging: DatasetStaging,
    backend_contract: IndexBackendContract,
    control: ProgressController,
    fault_inject: FaultInjector | None = None,
) -> None:
    """Run authoritative structural index rebuild and verification for VFP_INDEXED profile.

    This function runs inside protected staging after fresh DBF/FPT are written
    but before the dataset fingerprint is computed and staging is promoted.

    For each table with structural CDX:
    1. Rebuild the structural index through the injected backend
    2. Verify the rebuilt index (table open, record count, tag inventory)

    Any failure fails closed with no publication.
    """
    try:
        dataset_root = staging.dataset_root.resolve(strict=True)
    except OSError:
        raise _path_failure("ENGINE_VFP_INDEXED_STAGING_UNAVAILABLE") from None
    capability = backend_contract.capability
    require_backend_support(capability, "STRUCTURAL_CDX")
    require_backend_verification(capability, "STRUCTURAL_CDX")
    require_backend_runtime(capability)

    directives = {table.relative_path: table for table in engine_plan.tables}

    for table_path in engine_plan.structural_cdx_tables:
        control.check_cancelled()
        control.progress(
            ProgressPhase.INDEX_REBUILD,
            completed=0,
            total=2,
            table_path=table_path,
        )

        try:
            source_table_path = (source_root / table_path).resolve(strict=True)
            staged_table_path = (dataset_root / table_path).resolve(strict=True)
        except OSError:
            raise _path_failure("ENGINE_VFP_INDEXED_TABLE_UNAVAILABLE") from None
        try:
            staged_table_path.relative_to(dataset_root)
        except ValueError:
            raise _path_failure("ENGINE_VFP_INDEXED_STAGED_TARGET_INVALID") from None
        if source_table_path == staged_table_path:
            raise _path_failure("ENGINE_VFP_INDEXED_STAGED_TARGET_INVALID")
        directive = directives.get(table_path)
        if directive is None:
            raise index_backend_failure(
                "INDEX_BACKEND_TABLE_DIRECTIVE_MISSING", table_path=table_path
            )

        rebuild_request = IndexRebuildRequest(
            protocol_schema_version=backend_contract.capability.protocol_schema_version,
            artifact_class="STRUCTURAL_CDX",
            table_path=table_path,
            source_table_path=source_table_path,
            staged_table_path=staged_table_path,
        )
        rebuild_outcome = run_backend_rebuild(
            backend_contract.backend, rebuild_request
        )
        rebuild_result = rebuild_outcome.result

        if rebuild_result.backend_id != backend_contract.backend_id:
            raise index_backend_failure(
                "INDEX_BACKEND_ID_MISMATCH", table_path=table_path
            )
        if rebuild_result.status != "REBUILT":
            detail_code = (
                "INDEX_BACKEND_REBUILD_REFUSED"
                if rebuild_result.status == "REFUSED"
                else "INDEX_BACKEND_REBUILD_FAILED"
            )
            raise index_backend_failure(detail_code, table_path=table_path)

        staged_cdx_path = staged_table_path.with_suffix(".cdx")
        if not staged_cdx_path.is_file():
            raise index_backend_failure(
                "INDEX_BACKEND_REBUILT_ARTIFACT_MISSING", table_path=table_path
            )

        control.check_cancelled()
        control.progress(
            ProgressPhase.INDEX_REBUILD,
            completed=1,
            total=2,
            table_path=table_path,
        )

        verification_request = IndexVerificationRequest(
            protocol_schema_version=backend_contract.capability.protocol_schema_version,
            artifact_class="STRUCTURAL_CDX",
            table_path=table_path,
            staged_table_path=staged_table_path,
        )
        verification_outcome = run_backend_verification(
            backend_contract.backend, verification_request
        )
        verification_result = verification_outcome.result

        if verification_result.backend_id != backend_contract.backend_id:
            raise index_backend_failure(
                "INDEX_BACKEND_ID_MISMATCH", table_path=table_path
            )
        if verification_result.status != "VERIFIED":
            detail_code = {
                "OPEN_FAILED": "INDEX_BACKEND_TABLE_NOT_OPENED",
                "RECORD_COUNT_MISMATCH": "INDEX_BACKEND_RECORD_COUNT_MISMATCH",
                "TAG_INVENTORY_MISMATCH": "INDEX_BACKEND_TAG_INVENTORY_MISMATCH",
            }.get(verification_result.detail_code, "INDEX_BACKEND_VERIFY_FAILED")
            raise index_backend_failure(detail_code, table_path=table_path)
        if not verification_outcome.table_opened:
            raise index_backend_failure(
                "INDEX_BACKEND_TABLE_NOT_OPENED", table_path=table_path
            )
        if verification_outcome.actual_record_count != directive.record_count:
            raise index_backend_failure(
                "INDEX_BACKEND_RECORD_COUNT_MISMATCH", table_path=table_path
            )
        if (
            verification_outcome.actual_tag_inventory
            != rebuild_outcome.expected_tag_inventory
        ):
            raise index_backend_failure(
                "INDEX_BACKEND_TAG_INVENTORY_MISMATCH", table_path=table_path
            )

        control.check_cancelled()
        control.progress(
            ProgressPhase.INDEX_REBUILD,
            completed=2,
            total=2,
            table_path=table_path,
        )

        if fault_inject is not None:
            fault_inject(f"VFP_INDEXED_REBUILD_VERIFY_COMPLETE:{table_path}")


def run_two_pass(
    plan: Plan,
    *,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
    workers: int = 1,
    operation_id: str | None = None,
    fault_inject: FaultInjector | None = None,
    control: ProgressController | None = None,
    backend_contract: IndexBackendContract | None = None,
) -> TwoPassResult:
    """The bounded two-pass production run bound to ONE execution identity.

    The Plan and its PRIVATE execution context are the ONLY source of truth:
    source/output/vault roots, the resolved policy snapshot and the parsed
    relationship document are resolved from the retained context — the
    engine accepts NO runtime path/policy/metadata overrides (there are no
    released users and no duplicate inputs).

    INTERNAL control injection (PRIVATE, never part of the root public API):
    the public ``pseudonymize`` service supplies its OWN
    :class:`~dbf_anonymizer.progress.ProgressController` via ``control`` so
    one public invocation keeps ONE controller, ONE operation id and ONE
    terminal completion across its shared preflight evaluation and the
    engine passes. Without ``control`` the engine creates its own internal
    controller from ``progress``/``cancel_check`` (the pre-existing
    behavior every direct engine test relies on); supplying ``control``
    together with separate callbacks is a fail-closed contract error.

    The ``backend_contract`` (REQ-P6-003) is the validated index backend
    contract for VFP_INDEXED profile operations. When the plan's output
    profile is VFP_INDEXED, this contract MUST be provided and will be used
    for authoritative structural index rebuild and verification after pass 2.

    PRE-EXECUTION REVALIDATION (before the vault, the spool or any output
    artifact is created — zero transformation-equivalent side effects on
    refusal):

    1. SOURCE IDENTITY — the source fingerprint is RECOMPUTED with the SAME
       canonical kernel :func:`build_plan` used and must equal
       ``plan.dataset.source_fingerprint`` exactly (a source changed after
       planning fails before any side effect). The re-scan reports bounded
       ``SOURCE_REVALIDATION`` progress through the SAME controller.
    2. PATH / TRUST ZONES — the existing preflight overlap semantics
       (resolved aliases) reject any source/output/vault nesting.
    3. POLICY — the context's resolved policy fingerprint must equal
       ``plan.policy.policy_fingerprint`` (no caller-supplied policy).
    4. RELATIONSHIPS — the retained parsed document's canonical fingerprint
       must equal ``plan.relationships.relationship_fingerprint``.
    5. VAULT — the existing P2-010 fingerprint checks run unchanged at open.

    Cancellation and progress follow REQ-P1-008: the cooperative check is
    polled between tables, per record and before every finalize/write safe
    point; the typed :class:`~dbf_anonymizer.errors.CancellationError`
    leaves the source untouched and removes everything this run wrote (no
    published partial output).  The single authoritative recovery vault is
    the only durable mapping truth; the ephemeral evidence spool is
    protected Zone B state that is cleaned up explicitly after the run.

    TERMINAL COMPLETION OWNERSHIP: with a SELF-created controller the engine
    owns its single terminal completion event exactly as before. With an
    EXTERNALLY supplied controller (the public ``pseudonymize`` service) the
    engine emits NO terminal completion — the public service derives the
    relational assurance and constructs the public result first, then owns
    the invocation's single COMPLETED event (never a late cancellation poll
    after an already committed publication).
    """
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    external_control = control is not None
    if control is not None:
        if not isinstance(control, ProgressController):
            raise TypeError("control must be a ProgressController")
        if progress is not None or cancel_check is not None:
            raise ValueError(
                "an injected controller excludes separate progress/cancel callbacks"
            )
        if operation_id is not None and control.operation_id != operation_id:
            raise ValueError(
                "an injected controller and the operation id must match"
            )
    context = plan.execution_context
    if context is None:
        raise _path_failure("ENGINE_PLAN_CONTEXT_MISSING")
    source = Path(context.source_root)
    output = Path(context.output_root)
    vault_path = Path(context.vault_path)
    resolved_policy = context.resolved_policy
    if resolved_policy is None:
        raise _path_failure("ENGINE_PLAN_POLICY_MISSING")
    if control is None:
        control = ProgressController(
            operation="two_pass", progress=progress, cancel_check=cancel_check
        )
    control.start_phase(ProgressPhase.SOURCE_REVALIDATION)
    _revalidate_execution_identity(
        plan,
        source_root=source,
        output_root=output,
        vault_path=vault_path,
        resolved_policy=resolved_policy,
        relationship_document=context.relationship_document,
        cancel_probe=control.check_cancelled,
        progress_probe=lambda done, total, rel: control.progress(
            ProgressPhase.SOURCE_REVALIDATION,
            completed=done,
            total=total,
            table_path=rel,
        ),
    )
    engine_plan = build_engine_plan(
        plan,
        source_root=source,
        policy=resolved_policy,
        relationship_document=context.relationship_document,
    )
    vault: VaultDatabase | None = None
    spool: PassOneSpool | None = None
    protected_state_created = not vault_path.exists()
    try:
        # Refuse known sensitive residue before creating a fresh durable vault.
        # Existing vaults are inspected first below so a crash-owned STARTED
        # operation produces the more specific stale-transaction diagnosis.
        if not vault_path.exists():
            refuse_spool_leftovers(vault_path.parent)
            refuse_evidence_leftovers(vault_path.parent)
        vault = VaultDatabase.open(
            vault_path,
            create=protected_state_created,
            expected_source_fingerprint=plan.dataset.source_fingerprint,
            expected_policy_fingerprint=plan.policy.policy_fingerprint,
            expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
            dbfbridge_version=str(dbfbridge.__version__),
        )
        identity = build_publication_identity(
            destination=output,
            vault=vault,
            source_fingerprint=plan.dataset.source_fingerprint,
            policy_fingerprint=plan.policy.policy_fingerprint,
            relationship_fingerprint=plan.relationships.relationship_fingerprint,
            operation_id=operation_id,
        )
        with DestinationLock(identity.lock_path):
            if fault_inject is not None:
                fault_inject("LOCK_ACQUIRED")
            existing = _existing_completed_result(identity, vault, control=control)
            if existing is not None:
                refuse_spool_leftovers(vault_path.parent)
                refuse_evidence_leftovers(vault_path.parent)
                if not external_control:
                    control.complete(completed=len(existing.tables_written))
                return existing

            # Stale sensitive SQLite state is checked only after a matching
            # STARTED operation had the opportunity to produce the more useful
            # transaction-stale diagnosis above.
            refuse_spool_leftovers(vault_path.parent)
            refuse_evidence_leftovers(vault_path.parent)

            with _WriterLease(vault) as writer_vault:
                staging = DatasetStaging(identity)
                evidence_root: Path | None = None
                operation_started = False
                try:
                    if fault_inject is not None:
                        fault_inject("BEFORE_OPERATION_START")
                    with writer_vault.transaction():
                        writer_vault.begin_operation(
                            identity.operation_id,
                            source_fingerprint=plan.dataset.source_fingerprint,
                            policy_fingerprint=plan.policy.policy_fingerprint,
                            relationship_fingerprint=(
                                plan.relationships.relationship_fingerprint
                            ),
                            vault_fingerprint=identity.vault_fingerprint,
                            destination_identity=identity.destination_identity,
                            binding_fingerprint=identity.binding_fingerprint,
                        )
                    operation_started = True
                    if fault_inject is not None:
                        fault_inject("AFTER_OPERATION_START")
                    staging.create()
                    spool = PassOneSpool(vault_directory=vault_path.parent)
                    outcome = PassOneOutcome()
                    temporal_domain = (
                        TemporalShiftDomain(writer_vault, domain_name=None)
                        if engine_plan.temporal_present
                        else None
                    )
                    memo_bindings = _register_memo_structure(engine_plan, writer_vault)
                    control.start_phase(
                        ProgressPhase.PASS1_SCAN, total=len(engine_plan.tables)
                    )
                    run_pass_one(
                        engine_plan,
                        source_root=source,
                        vault=writer_vault,
                        spool=spool,
                        control=control,
                        outcome=outcome,
                        temporal_domain=temporal_domain,
                        memo_bindings=memo_bindings,
                    )
                    control.check_cancelled()
                    control.start_phase(ProgressPhase.PASS1_FINALIZE)
                    run_pass_one_finalize(
                        engine_plan,
                        vault=writer_vault,
                        spool=spool,
                        control=control,
                        outcome=outcome,
                        temporal_domain=temporal_domain,
                    )
                    _register_transform_fields(
                        engine_plan,
                        writer_vault,
                        outcome,
                        temporal_domain,
                        source_root=source,
                    )
                    evidence_root = create_evidence_root(
                        vault_path.parent, identity.operation_id
                    )
                    result = run_pass_two(
                        engine_plan,
                        source_root=source,
                        staging=staging,
                        vault=writer_vault,
                        spool=spool,
                        control=control,
                        outcome=outcome,
                        workers=workers,
                        evidence_root=evidence_root,
                        fault_inject=fault_inject,
                    )
                    # VFP_INDEXED profile: authoritative structural index rebuild
                    # and verification (REQ-P6-003). Runs inside protected staging
                    # after fresh DBF/FPT are written, before final publication.
                    if (
                        plan.output_profile is TransferProfile.VFP_INDEXED
                        and engine_plan.structural_cdx_tables
                    ):
                        if backend_contract is None:
                            raise index_backend_failure("INDEX_BACKEND_MISSING")
                        control.start_phase(ProgressPhase.INDEX_REBUILD)
                        _run_vfp_indexed_rebuild_and_verify(
                            engine_plan,
                            source_root=source,
                            staging=staging,
                            backend_contract=backend_contract,
                            control=control,
                            fault_inject=fault_inject,
                        )
                    output_fingerprint = fingerprint_dataset(
                        staging.dataset_root, checkpoint=control.check_cancelled
                    )
                    result = replace(
                        result,
                        operation_id=identity.operation_id,
                        output_fingerprint=output_fingerprint,
                        protected_state_created=protected_state_created,
                    )
                    with writer_vault.transaction():
                        writer_vault.record_publication(
                            identity.operation_id,
                            "STAGED",
                            output_fingerprint=output_fingerprint,
                            vault_fingerprint=identity.vault_fingerprint,
                        )
                    # REQ-P5-008 step 5/6: flush + fsync every staged file
                    # and persist directory entries where supported, with
                    # cooperative cancellation checkpoints between files
                    # and directories (REQ-P1-008 — never an uncancellable
                    # durability region).
                    staging.persist_payload(checkpoint=control.check_cancelled)
                    staging.record_staged_fingerprint(output_fingerprint)
                    if fault_inject is not None:
                        fault_inject("AFTER_PAYLOAD_FSYNC")
                    if fault_inject is not None:
                        fault_inject("AFTER_STAGED_STATE")
                    # REQ-P5-008 step 8: durable READY_TO_PROMOTE state.
                    if fault_inject is not None:
                        fault_inject("BEFORE_READY_TO_PROMOTE")
                    staging.mark_ready_to_promote(
                        payload_fingerprint=output_fingerprint
                    )
                    if fault_inject is not None:
                        fault_inject("AFTER_READY_TO_PROMOTE")
                    control.check_cancelled()
                    if fault_inject is not None:
                        fault_inject("BEFORE_STAGING_PROMOTION")
                    # REQ-P5-008 step 10: atomic promotion.
                    if fault_inject is not None:
                        fault_inject("DURING_PROMOTION")
                    staging.promote()
                    if fault_inject is not None:
                        fault_inject("AFTER_STAGING_PROMOTION")
                    # REQ-P5-008 step 11: persist the PROMOTED crash state
                    # (private staging namespace) so reconciliation can
                    # classify a crash after replace.
                    staging.mark_promoted()
                    if fault_inject is not None:
                        fault_inject("AFTER_PROMOTED_STATE")
                    # REQ-P5-008 step 9: the durable completion receipt
                    # below is authoritative; step 13 (private metadata
                    # cleanup) follows AFTER the receipt so a genuinely
                    # completed operation can never appear incomplete
                    # merely because cleanup was interrupted.
                    with writer_vault.transaction():
                        writer_vault.record_publication(
                            identity.operation_id,
                            "PUBLISHED",
                            output_fingerprint=output_fingerprint,
                            vault_fingerprint=identity.vault_fingerprint,
                        )
                        writer_vault.complete_operation(
                            identity.operation_id,
                            output_fingerprint=output_fingerprint,
                            result_json=result_receipt(result),
                        )
                    if fault_inject is not None:
                        fault_inject("AFTER_OPERATION_COMPLETE")
                    # REQ-P5-008 step 13: private metadata cleanup AFTER
                    # the receipt.
                    staging.remove_metadata_after_promotion()
                    if fault_inject is not None:
                        fault_inject("AFTER_METADATA_CLEANUP")
                except BaseException as original:
                    # Pre-promotion cleanup only: once the atomic rename HAS
                    # occurred (staging.renamed) the final destination exists
                    # and the residual staging carries the crash-state
                    # evidence required to classify the interrupted
                    # publication deterministically — it must never be
                    # removed and the vault operation must not be abandoned
                    # (the STARTED row plus READY_TO_PROMOTE/PROMOTED crash
                    # state is what makes the state deterministically stale
                    # instead of unowned).
                    if operation_started and not staging.renamed:
                        try:
                            staging.cleanup_owned()
                            if evidence_root is not None:
                                cleanup_evidence_root(evidence_root)
                            with writer_vault.transaction():
                                writer_vault.abandon_operation(identity.operation_id)
                        except BaseException:
                            raise PublicationError(
                                ErrorCode.PUBLICATION_INCOMPLETE,
                                context=ErrorContext(
                                    operation="publication",
                                    detail_code="ENGINE_OUTPUT_CLEANUP_FAILED",
                                ),
                            ) from original
                    raise
            # Cancellation is no longer observed after atomic promotion; this
            # terminal event cannot turn a committed dataset into cancellation.
            if not external_control:
                control.complete(
                    completed=len(result.tables_written), check_cancel=False
                )
            return result
    finally:
        operation_error = sys.exc_info()[1]
        cleanup_failure = _cleanup_engine_resources(spool, vault)
        if cleanup_failure is not None:
            if operation_error is not None:
                raise cleanup_failure from operation_error
            underlying = getattr(cleanup_failure, "_resource_cleanup_failures")[0][1]
            raise cleanup_failure from underlying
