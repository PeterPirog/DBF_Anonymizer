"""Read-only deterministic build planning for REQ-P1-005.

Orchestrates source discovery, policy resolution, relationship resolution,
fingerprint computation and Plan assembly. Side-effect-free by design.

REQ-P1-008 adds optional bounded structured progress and cooperative
cancellation callbacks (``progress`` / ``cancel_check`` keyword-only
arguments) driven through the shared :mod:`dbf_anonymizer.progress` control
layer.  With both callbacks omitted the deterministic behavior and the public
``Plan`` serialization are byte-identical to the pre-P1-008 contract; the
invocation ``operation_id`` never enters the ``Plan``.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Mapping

from dbf_anonymizer.discovery import (
    collect_fingerprint_entries,
    compute_source_fingerprint,
    discover_tables,
)
from dbf_anonymizer.errors import (
    CancellationError,
    CallbackError,
    DBFBridgeError,
    PathError,
    ErrorCode,
    ErrorContext,
)
from dbf_anonymizer.models import (
    DatasetIdentity,
    Plan,
    PolicySummary,
    RelationalAssuranceLevel,
    RelationshipMetadata,
    TablePlan,
    TransferProfile,
    VaultStrategy,
    _PlanExecutionContext,
)
from dbf_anonymizer.policy import classify_field_capability, resolve_policy
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)


def _resolve_index_strategy(
    structural_cdx: bool, output_profile: TransferProfile
) -> str:
    if output_profile is TransferProfile.VFP_INDEXED and structural_cdx:
        return "VFP_INDEXED"
    return "DATA_ONLY"


def _resolve_vault_strategy(
    recovery_enabled: bool,
) -> VaultStrategy:
    if recovery_enabled:
        return VaultStrategy.SINGLE_DATASET_SQLITE
    return VaultStrategy.NONE


def _default_relationships() -> RelationshipMetadata:
    """Create a deterministic empty relationship metadata for the None case."""
    empty_fp = hashlib.sha256(b"no-relationships").hexdigest()
    return RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint=empty_fp,
        relation_count=0,
        authoritative=False,
    )


def _assure_target(relationships: RelationshipMetadata) -> RelationalAssuranceLevel:
    if relationships.relation_count == 0:
        return RelationalAssuranceLevel.INCOMPLETE
    if relationships.authoritative:
        return RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    return RelationalAssuranceLevel.INCOMPLETE


def build_plan(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    vault: str | os.PathLike[str],
    policy: Mapping[str, Any] | None = None,
    relationships: RelationshipMetadata | None = None,
    *,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> Plan:
    """Build a deterministic, read-only, side-effect-free pseudonymization plan.

    This function only reads the source filesystem (bounded reads for
    schema and fingerprint computation). It creates no files, directories,
    locks, logs, vaults or staging areas.

    REQ-P1-008: the optional keyword-only ``progress`` callback receives
    bounded structured :class:`~dbf_anonymizer.models.ProgressEvent` updates
    and ``cancel_check`` is polled at scan safe points (phase boundaries,
    between discovered tables, per fingerprinted artifact and at bounded
    chunk intervals while hashing).  Cancellation raises the typed
    :class:`~dbf_anonymizer.errors.CancellationError`; callback failures are
    contained into the classified
    :class:`~dbf_anonymizer.errors.CallbackError`.  With both callbacks
    omitted the deterministic result is unchanged and no callback work
    happens at all.
    """
    control = ProgressController(
        operation="build_plan", progress=progress, cancel_check=cancel_check
    )
    control.start_phase(ProgressPhase.OPERATION)

    source_root = Path(source).resolve()
    output_root = Path(output).resolve()
    vault_path = Path(vault).resolve()

    if not source_root.is_dir():
        raise PathError(
            ErrorCode.PATH_NOT_FOUND,
            context=ErrorContext(
                operation="build_plan",
                detail_code="source_root_not_found",
            ),
        )

    # 1. Discover tables (wraps dbfbridge errors); scan safe points between
    #    discovered tables are provided through the private probes.
    control.start_phase(ProgressPhase.DISCOVERY)
    discovered = discover_tables(
        source_root,
        cancel_probe=control.check_cancelled,
        progress_probe=lambda rel: control.bump(
            ProgressPhase.DISCOVERY, table_path=rel
        ),
    )

    if not discovered:
        raise PathError(
            ErrorCode.PATH_NOT_FOUND,
            context=ErrorContext(
                operation="build_plan",
                detail_code="no_tables_found",
            ),
        )

    # 2. Compute source fingerprint (scan safe points per artifact and at
    #    bounded chunk intervals inside large artifacts).
    control.start_phase(ProgressPhase.FINGERPRINT)

    def _on_fingerprint_artifact(done: int, total: int, rel: str) -> None:
        control.progress(
            ProgressPhase.FINGERPRINT,
            completed=done,
            total=total,
            table_path=rel,
        )

    fp_entries = collect_fingerprint_entries(
        source_root,
        cancel_probe=control.check_cancelled,
        progress_probe=_on_fingerprint_artifact,
    )
    source_fp = compute_source_fingerprint(fp_entries)

    # 3. Resolve policy
    merged_policy, policy_fp = resolve_policy(policy)

    # 4. Resolve relationships
    if relationships is None:
        rel_meta = _default_relationships()
    else:
        rel_meta = relationships

    # 5. Determine output profile from policy
    indexes_profile = merged_policy.get("indexes", {}).get("profile", "DATA_ONLY")
    if indexes_profile == "VFP_INDEXED":
        output_profile = TransferProfile.VFP_INDEXED
    else:
        output_profile = TransferProfile.DATA_ONLY

    # 6. Build per-table plans with capability classification
    import dbfbridge

    tables: list[TablePlan] = []
    total_transformed_fields = 0
    transformation_classes_set: set[str] = set()

    control.start_phase(ProgressPhase.TABLE_EVALUATION, total=len(discovered))

    for table in discovered:
        control.check_cancelled()
        dbf_full_path = source_root / table.relative_path

        try:
            schema = dbfbridge.read_schema(dbf_full_path)  # type: ignore[attr-defined]
        except (CancellationError, CallbackError):
            raise
        except Exception as exc:
            raise DBFBridgeError.from_exception(
                exc,
                context=ErrorContext(
                    operation="build_plan",
                    table_path=table.relative_path,
                    detail_code="read_schema_failed",
                ),
            ) from None

        transform_count = 0
        unsupported_count = 0
        unsafe_count = 0
        system_count = 0

        for field_info in schema.fields:
            action, is_unsafe, is_system = classify_field_capability(
                field_info.dbf_type,
                field_info.name,
                field_info.supported,
                field_info.is_binary,
                field_info.system,
                field_info.nocptrans,
                merged_policy,
            )
            if action is not None:
                transform_count += 1
                transformation_classes_set.add(action)
            elif is_unsafe:
                unsafe_count += 1
            if is_system:
                system_count += 1
            # Unsupported user fields are unsafe; the trusted bitmap is system state.
            if not field_info.supported and not is_system:
                unsupported_count += 1

        total_transformed_fields += transform_count
        index_strategy = _resolve_index_strategy(table.structural_cdx, output_profile)

        tables.append(
            TablePlan(
                table_path=table.relative_path,
                memo_path=table.memo_relative_path,
                record_count=table.record_count,
                field_count=table.field_count,
                transform_field_count=transform_count,
                structural_cdx=table.structural_cdx,
                dbc_bound=table.dbc_bound,
                index_strategy=index_strategy,
                memo_required=(schema.has_memo or schema.has_memo_flag),
                memo_companion_present=schema.memo_companion_present,
                structural_cdx_companion_present=schema.companion_cdx_present,
                unsupported_field_count=unsupported_count,
                unsafe_field_count=unsafe_count,
                system_field_count=system_count,
            )
        )
        control.bump(ProgressPhase.TABLE_EVALUATION, table_path=table.relative_path)

    tables.sort(key=lambda t: t.table_path)

    # 7. Recovery enabled if any reversible transformation is planned
    recovery_enabled = bool(transformation_classes_set)

    # 8. Vault strategy
    vault_strategy = _resolve_vault_strategy(recovery_enabled)

    # 9. Build PolicySummary
    policy_summary = PolicySummary(
        policy_schema_version=str(merged_policy.get("schema_version", "1")),
        policy_fingerprint=policy_fp,
        transformed_field_count=total_transformed_fields,
        relationship_count=rel_meta.relation_count,
        recovery_enabled=recovery_enabled,
        transformation_classes=tuple(sorted(transformation_classes_set)),
        vault_strategy=vault_strategy,
    )

    # 10. Build DatasetIdentity
    dataset_id = "ds-" + source_fp[:16]
    table_paths = tuple(t.relative_path for t in discovered)
    dataset = DatasetIdentity(
        dataset_id=dataset_id,
        source_fingerprint=source_fp,
        table_paths=table_paths,
    )

    # 11. Compute plan ID (deterministic from all inputs)
    plan_id_material = (
        source_fp
        + policy_fp
        + rel_meta.relationship_fingerprint
        + output_profile.value
        + vault_strategy.value
    )
    plan_id = "plan-" + hashlib.sha256(plan_id_material.encode("utf-8")).hexdigest()[:24]

    # 12. Assemble Plan
    execution_ctx = _PlanExecutionContext(
        source_root=str(source_root),
        output_root=str(output_root),
        vault_path=str(vault_path),
    )

    plan = Plan(
        plan_id=plan_id,
        dataset=dataset,
        tables=tuple(tables),
        policy=policy_summary,
        relationships=rel_meta,
        output_profile=output_profile,
        relationship_assurance_target=_assure_target(rel_meta),
        execution_context=execution_ctx,
    )

    # The single terminal completion event is emitted only now — after the
    # public Plan object genuinely exists (never after cancellation).
    control.complete(completed=len(tables))

    return plan
