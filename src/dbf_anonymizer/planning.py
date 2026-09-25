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
    derive_dataset_id,
    discover_tables,
    enumerate_in_scope_paths,
)
from dbf_anonymizer.errors import (
    CancellationError,
    CallbackError,
    DBFBridgeError,
    PathError,
    ErrorCode,
    ErrorContext,
    PolicyError,
)
from dbf_anonymizer.models import (
    IDENTITY_PRIVACY_REVIEW_REQUIRED,
    DatasetIdentity,
    NumericIdentityReview,
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


def _relationship_binding_error(detail_code: str) -> PolicyError:
    """Typed, privacy-safe refusal for a declared-member schema mismatch."""
    return PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


def _record_identity_review(
    review: list[NumericIdentityReview],
    reviewed_identities: set[tuple[str, str]],
    table_path: str,
    field_name: str,
    dbf_type: str,
) -> None:
    """Record one unchanged numeric identifier for privacy review (P3-004).

    Bounded structural facts only — table path, field name, logical DBF type
    and the fixed review status token.  The collection is deduplicated and
    deterministically ordered before it enters the public Plan.
    """
    identity = (table_path, field_name)
    if identity in reviewed_identities:
        return
    reviewed_identities.add(identity)
    review.append(
        NumericIdentityReview(
            table_path=table_path,
            field_name=field_name,
            dbf_type=dbf_type,
            status=IDENTITY_PRIVACY_REVIEW_REQUIRED,
        )
    )


def build_plan(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    vault: str | os.PathLike[str],
    policy: Mapping[str, Any] | None = None,
    relationships: RelationshipMetadata | None = None,
    *,
    relationship_document: Mapping[str, Any] | None = None,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> Plan:
    """Build a deterministic, read-only, side-effect-free pseudonymization plan.

    This function only reads the source filesystem (bounded reads for
    schema and fingerprint computation). It creates no files, directories,
    locks, logs, vaults or staging areas.

    REQ-P3-001: the optional keyword-only ``relationship_document`` accepts
    the real versioned relationship metadata as a source-neutral in-memory
    mapping — content loaded from a policy file or emitted by
    ``mcp-vfp9sp2-toolchain`` (adapter boundary only; no transport exists).
    It is parsed through the ONE authoritative P3 document parser, its
    canonical fingerprint becomes the dataset's relationship fingerprint and
    the parsed document is bound to the DISCOVERED DBF schema facts
    (fail-closed, before any plan) and retained only inside the non-public
    execution context for the preflight relationship-domain validation.

    REQ-P1-008: the optional keyword-only ``progress`` callback receives
    bounded structured :class:`~dbf_anonymizer.models.ProgressEvent` updates
    and ``cancel_check`` is polled at scan safe points (phase boundaries,
    once per visited directory during source traversal, between discovered
    tables, per fingerprinted artifact and at bounded chunk intervals while
    hashing).  Cancellation raises the typed
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

    # Enumerate all in-scope source files (DBF, FPT, CDX, IDX) for standalone
    # IDX association with tables.
    source_files = enumerate_in_scope_paths(
        source_root,
        cancel_probe=control.check_cancelled,
    )

    discovered = discover_tables(
        source_root,
        source_files,
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
    parsed_relationship_document = None
    relationship_bindings: dict[tuple[str, str], tuple[str, int, str, int, bool, bool]] = {}
    field_facts: dict[tuple[str, str], tuple[str, int, str, int, bool, bool]] = {}
    numeric_identity_review: list[NumericIdentityReview] = []
    reviewed_identities: set[tuple[str, str]] = set()
    #: REQ-P3-005 planning truthfulness: the explicitly declared reversible
    #: numeric key member fields.  They ARE reversible pseudonymization
    #: targets (they consume vault mappings), so they count as transformed
    #: fields and make the plan recovery-enabled — unrelated numeric fields
    #: are never marked.
    numeric_reversible_fields: set[tuple[str, str]] = set()
    if relationship_document is not None:
        from dbf_anonymizer.relationships.document import (
            parse_relationship_document,
            relationship_metadata_from_document,
        )
        from dbf_anonymizer.relationships.models import (
            NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
        )

        # ONE authoritative parser: the typed document is parsed, its
        # canonical fingerprint becomes the dataset identity and the parsed
        # document is retained for the preflight compatibility validation.
        # The SEMANTIC compatibility validation runs in PREFLIGHT (before any
        # transformation-equivalent action) — see _check_relationships.
        parsed_relationship_document = parse_relationship_document(
            relationship_document
        )
        rel_meta = relationship_metadata_from_document(parsed_relationship_document)
        for group in parsed_relationship_document.groups:
            if group.numeric_strategy == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE:
                for member in group.members:
                    if member.is_numeric_member:
                        numeric_reversible_fields.add(
                            (member.table_path, member.field_name)
                        )
    elif relationships is None:
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
            # REQ-P3-003/REQ-P3-005 source-schema facts: collect the
            # authoritative field facts (public dbfbridge schema) for the
            # relationship binding — including the numeric representation
            # facts (decimal count/scale, autoincrement status and the
            # NULLable descriptor bit).
            fact: tuple[str, int, str, int, bool, bool] = (
                str(field_info.dbf_type),
                int(field_info.length),
                str(schema.encoding),
                int(field_info.decimal_count),
                bool(field_info.is_autoincrement),
                bool(field_info.nullable),
            )
            field_facts[(table.relative_path, str(field_info.name))] = fact
            # REQ-P3-004: a VFP autoincrement identifier stays value-identical
            # by default and is truthfully marked for privacy review.
            if field_info.is_autoincrement:
                _record_identity_review(
                    numeric_identity_review,
                    reviewed_identities,
                    table.relative_path,
                    str(field_info.name),
                    "I",
                )
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
            elif (table.relative_path, str(field_info.name)) in numeric_reversible_fields:
                # REQ-P3-005 planning truthfulness: an explicitly declared
                # reversible numeric key member IS a reversible pseudonymization
                # target even though the ordinary capability matrix keeps the
                # numeric/logical classes identity by default.  Only the
                # DECLARED reversible numeric members count — unrelated
                # N/F/I/Y/B/L fields are never marked transformed.
                transform_count += 1
                transformation_classes_set.add("PSEUDONYMIZE_REVERSIBLE")
            if is_system:
                system_count += 1
            # Unsupported user fields are unsafe; the trusted bitmap is system state.
            if not field_info.supported and not is_system:
                unsupported_count += 1

        total_transformed_fields += transform_count
        index_strategy = _resolve_index_strategy(table.structural_cdx, output_profile)
        standalone_idx_present = bool(table.standalone_idx_relative_paths)

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
                standalone_idx_paths=table.standalone_idx_relative_paths,
                standalone_idx_present=standalone_idx_present,
                unsupported_field_count=unsupported_count,
                unsafe_field_count=unsafe_count,
                system_field_count=system_count,
            )
        )
        control.bump(ProgressPhase.TABLE_EVALUATION, table_path=table.relative_path)

    tables.sort(key=lambda t: t.table_path)

    # 6b. REQ-P3-003/REQ-P3-005 schema binding: every declared member is
    # verified against the DISCOVERED public dbfbridge schema facts — table
    # exists, field exists, logical type matches the declared C/V or I/N
    # member vocabulary, byte width matches reality and (for text members)
    # the declared encoding admits the proven safe shared alphabet together
    # with the table encoding.  Numeric key members are additionally bound
    # to their verified representation facts: an integral Numeric domain
    # (decimal count/scale zero) and a NON-autoincrement field are required
    # for explicit reversible numeric pseudonymization, and the declared
    # NULL policy must match the actual descriptor bit.  A required safety
    # fact that public dbfbridge cannot provide FAILS CLOSED for explicit
    # numeric pseudonymization.  Mismatch FAILS CLOSED before any plan; the
    # binding runs BEFORE the semantic compatibility validation so a
    # member-level source mismatch is reported with its MEMBER detail code.
    if parsed_relationship_document is not None:
        from dbf_anonymizer.transforms.text import candidate_alphabet
        from dbf_anonymizer.relationships.compatibility import (
            validate_document_compatibility,
        )
        from dbf_anonymizer.relationships.models import (
            NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
        )

        discovered_paths = {table.relative_path for table in discovered}
        for group in parsed_relationship_document.groups:
            for member in group.members:
                if member.table_path not in discovered_paths:
                    raise _relationship_binding_error(
                        "RELATIONSHIP_MEMBER_TABLE_UNKNOWN"
                    )
                bound_fact = field_facts.get((member.table_path, member.field_name))
                if bound_fact is None:
                    raise _relationship_binding_error(
                        "RELATIONSHIP_MEMBER_FIELD_UNKNOWN"
                    )
                actual_type, actual_length, actual_encoding, actual_decimals, actual_autoincrement, actual_nullable = bound_fact
                if member.dbf_type != actual_type:
                    raise _relationship_binding_error(
                        "RELATIONSHIP_MEMBER_TYPE_MISMATCH"
                    )
                if member.byte_width != actual_length:
                    raise _relationship_binding_error(
                        "RELATIONSHIP_MEMBER_WIDTH_MISMATCH"
                    )
                if member.is_numeric_member:
                    # REQ-P3-005 numeric binding (public schema facts only):
                    if (
                        group.numeric_strategy
                        == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE
                    ):
                        if member.dbf_type == "N" and actual_decimals != 0:
                            # A non-integral Numeric domain is never silently
                            # rounded: fail closed before any allocation.
                            raise _relationship_binding_error(
                                "NUMERIC_MEMBER_DECIMALS_UNSUPPORTED"
                            )
                        if actual_autoincrement:
                            # VFP autoincrement keys are never a supported
                            # numeric-key pseudonymizer target in this
                            # release: fail closed before allocation.
                            raise _relationship_binding_error(
                                "NUMERIC_MEMBER_AUTOINCREMENT_UNSUPPORTED"
                            )
                        if member.nullable != actual_nullable:
                            raise _relationship_binding_error(
                                "NUMERIC_MEMBER_NULLABILITY_MISMATCH"
                            )
                        relationship_bindings[
                            (member.table_path, member.field_name)
                        ] = bound_fact
                        continue
                    # REQ-P3-004: a numeric key member that stays
                    # value-identical (IDENTITY) is truthfully marked for
                    # privacy review.
                    _record_identity_review(
                        numeric_identity_review,
                        reviewed_identities,
                        member.table_path,
                        member.field_name,
                        member.dbf_type,
                    )
                    relationship_bindings[(member.table_path, member.field_name)] = bound_fact
                    continue
                if not candidate_alphabet(
                    [member.encoding, actual_encoding]
                ):
                    raise _relationship_binding_error(
                        "RELATIONSHIP_MEMBER_ENCODING_INCOMPATIBLE"
                    )
                relationship_bindings[(member.table_path, member.field_name)] = bound_fact
        # A C/V NULL-policy binding fact is NOT exposed by the public
        # dbfbridge schema; the declared NULL policy stays relationship
        # semantics (truthfully documented, not invented from source bytes).
        # For declared numeric key members the descriptor NULL bit IS a
        # public schema fact and is bound truthfully (see above).
        # Semantic compatibility is validated by the preflight gate.

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

    # 10. Build DatasetIdentity (the ONE shared canonical identity kernel)
    dataset_id = derive_dataset_id(source_fp)
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
        relationship_document=parsed_relationship_document,
        relationship_bindings=(
            dict(relationship_bindings) if relationship_bindings else None
        ),
        resolved_policy=dict(merged_policy),
    )

    plan = Plan(
        plan_id=plan_id,
        dataset=dataset,
        tables=tuple(tables),
        policy=policy_summary,
        relationships=rel_meta,
        output_profile=output_profile,
        relationship_assurance_target=_assure_target(rel_meta),
        numeric_identity_review=tuple(sorted(numeric_identity_review, key=lambda r: (r.table_path, r.field_name, r.dbf_type))),
        execution_context=execution_ctx,
    )

    # The single terminal completion event is emitted only now — after the
    # public Plan object genuinely exists (never after cancellation).
    control.complete(completed=len(tables))

    return plan
