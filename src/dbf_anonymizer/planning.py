"""Read-only deterministic build planning for REQ-P1-005.

Orchestrates source discovery, policy resolution, relationship resolution,
fingerprint computation and Plan assembly. Side-effect-free by design.
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
from dbf_anonymizer.errors import PathError, ErrorCode, ErrorContext
from dbf_anonymizer.models import (
    DatasetIdentity,
    Plan,
    PlanExecutionContext,
    PolicySummary,
    RelationalAssuranceLevel,
    RelationshipMetadata,
    TablePlan,
    TransferProfile,
)
from dbf_anonymizer.policy import classify_field_transform, resolve_policy


def _resolve_index_strategy(
    structural_cdx: bool, output_profile: TransferProfile
) -> str:
    if output_profile is TransferProfile.VFP_INDEXED and structural_cdx:
        return "VFP_INDEXED"
    return "DATA_ONLY"


def _default_relationships() -> RelationshipMetadata:
    """Create a deterministic empty relationship metadata for the None case."""
    empty_fp = hashlib.sha256(b"no-relationships").hexdigest()
    return RelationshipMetadata(
        metadata_schema_version="1.0",
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
) -> Plan:
    """Build a deterministic, read-only, side-effect-free pseudonymization plan.

    This function only reads the source filesystem (bounded reads for
    schema and fingerprint computation). It creates no files, directories,
    locks, logs, vaults or staging areas.
    """
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

    # 1. Discover tables
    discovered = discover_tables(source_root)

    if not discovered:
        raise PathError(
            ErrorCode.PATH_NOT_FOUND,
            context=ErrorContext(
                operation="build_plan",
                detail_code="no_tables_found",
            ),
        )

    # 2. Compute source fingerprint
    fp_entries = collect_fingerprint_entries(source_root, discovered)
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

    # 6. Build per-table plans and count transformations
    tables: list[TablePlan] = []
    total_transformed_fields = 0
    transformation_classes_set: set[str] = set()

    for table in discovered:
        import dbfbridge

        dbf_full_path = source_root / table.relative_path
        schema = dbfbridge.read_schema(dbf_full_path)  # type: ignore[attr-defined]

        transform_count = 0
        for field_info in schema.fields:
            action = classify_field_transform(field_info.dbf_type, merged_policy)
            if action is not None:
                transform_count += 1
                transformation_classes_set.add(action)

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
            )
        )

    tables.sort(key=lambda t: t.table_path)

    # 7. Recovery enabled if any reversible transformation is in the policy
    recovery_enabled = bool(transformation_classes_set)

    # 8. Build PolicySummary
    policy_summary = PolicySummary(
        policy_schema_version=str(merged_policy.get("schema_version", "1")),
        policy_fingerprint=policy_fp,
        transformed_field_count=total_transformed_fields,
        relationship_count=rel_meta.relation_count,
        recovery_enabled=recovery_enabled,
        transformation_classes=tuple(sorted(transformation_classes_set)),
    )

    # 9. Build DatasetIdentity
    dataset_id = "ds-" + source_fp[:16]
    table_paths = tuple(t.relative_path for t in discovered)
    dataset = DatasetIdentity(
        dataset_id=dataset_id,
        source_fingerprint=source_fp,
        table_paths=table_paths,
    )

    # 10. Compute plan ID (deterministic from all inputs)
    plan_id_material = (
        source_fp
        + policy_fp
        + rel_meta.relationship_fingerprint
        + output_profile.value
    )
    plan_id = "plan-" + hashlib.sha256(plan_id_material.encode("utf-8")).hexdigest()[:24]

    # 11. Assemble Plan
    execution_ctx = PlanExecutionContext(
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

    return plan
