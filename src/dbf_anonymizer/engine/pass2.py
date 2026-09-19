"""Pass 2 of the bounded two-pass engine (REQ-P4-001/P4-002).

PASS 2 re-reads the source through the SAME public Direct Read boundary,
resolves the already-finalized mappings and parameters from the protected
vault state, transforms ONE record at a time and feeds the ONE public Direct
Write boundary (fresh DBF/FPT creation from a lazily consumed record
stream).  The final field-by-field reconstruction semantics remain owned by
P4-003/004: this pass applies the P2/P3-verified value-level transforms for
the classes the engine supports and FAILS CLOSED on anything else — a
missing mapping, an unsupported field class or an unresolvable original is
a typed, value-free refusal, never a silent skip.

After the last table the declared relationship evidence is compared by
STREAMING SQL aggregation (bounded counts plus streaming multiplicity
equality) — the O(distinct keys) multiplicity profile tuple is never
materialized in production RAM; the P3 in-memory evidence kernel remains the
small-fixture oracle and the equivalence is cross-checked by the test suite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Sequence

from dbfbridge import DirectRecord  # type: ignore[attr-defined]

from dbf_anonymizer.engine.direct_io import (
    DirectSourceTable,
    read_source_table,
    stream_table_records,
    write_fresh_table,
)
from dbf_anonymizer.engine.directives import (
    EnginePlan,
    RelationDirective,
    RelationPassSummary,
    TableDirective,
    TwoPassResult,
)
from dbf_anonymizer.engine.pass1 import PassOneOutcome
from dbf_anonymizer.engine.state import PassOneSpool, canonical_composite_identity
from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError
from dbf_anonymizer.progress import ProgressController, ProgressPhase
from dbf_anonymizer.transforms.memo import memo_safe_mask
from dbf_anonymizer.transforms.numeric_keys import (
    canonical_integer_text,
    parse_canonical_integer_text,
)
from dbf_anonymizer.transforms.temporal import temporal_shift
from dbf_anonymizer.vault.mappings import (
    get_numeric_pseudonym,
    get_text_pseudonym,
    temporal_parameter,
)
from dbf_anonymizer.vault.store import VaultDatabase
from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID
from dbf_anonymizer.vault.temporal_allocation import TemporalShiftDomain

__all__ = ["run_pass_two"]


def _mapping_failure(detail_code: str) -> MappingError:
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(operation="engine", detail_code=detail_code),
    )


def run_pass_two(
    engine_plan: EnginePlan,
    *,
    source_root: Path,
    output_root: Path,
    vault: VaultDatabase,
    spool: PassOneSpool,
    control: ProgressController,
    outcome: PassOneOutcome,
    written: list[str],
) -> TwoPassResult:
    """The write pass: resolve, transform, direct-write, then compare."""
    control.start_phase(ProgressPhase.PASS2_WRITE, total=len(engine_plan.tables))
    records_written = 0
    read_streams: list[tuple[str, str]] = []
    for directive in engine_plan.tables:
        assert isinstance(directive, TableDirective)
        control.check_cancelled()
        table = read_source_table(
            source_root,
            directive.relative_path,
            cancel_check=control.check_cancelled,
        )
        destination = output_root / directive.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        written.append(directive.relative_path)
        text_domain_id = (
            outcome.text_domain_id if engine_plan.text_present else None
        )
        temporal_offset = (
            _persisted_temporal_offset(vault) if engine_plan.temporal_present else None
        )
        result = write_fresh_table(
            destination,
            table.schema,
            _transform_stream(
                engine_plan,
                directive,
                table,
                vault,
                spool,
                control,
                text_domain_id,
                temporal_offset,
                read_streams,
            ),
            cancel_check=control.check_cancelled,
        )
        records_written += int(result.records_written)
        control.bump(ProgressPhase.PASS2_WRITE, table_path=directive.relative_path)
    spool.flush()
    summaries = _compare_relations(engine_plan, spool)
    return TwoPassResult(
        tables_written=tuple(written),
        pass1_records_scanned=outcome.records_scanned,
        pass1_deleted_scanned=outcome.deleted_scanned,
        pass2_records_written=records_written,
        text_allocated=outcome.text_allocated,
        text_reused=outcome.text_reused,
        numeric_allocated=dict(outcome.numeric_allocated),
        temporal_offset_allocated=outcome.temporal_offset is not None,
        relations=tuple(summaries),
        evidence_spool_bytes=spool.size_bytes(),
        read_streams=tuple(outcome.read_streams) + tuple(read_streams),
    )


def _text_domain_id(outcome: PassOneOutcome) -> str:
    if outcome.text_domain_id is None:  # pragma: no cover - plan checked
        raise _mapping_failure("ENGINE_TEXT_DOMAIN_MISSING")
    return outcome.text_domain_id


def _persisted_temporal_offset(vault: VaultDatabase) -> int:
    """The authoritative persisted offset (REUSE: no randomness in pass 2)."""
    probe = TemporalShiftDomain(vault, domain_name=None)
    offset = temporal_parameter(vault, probe.domain_id)
    if offset is None:
        raise _mapping_failure("ENGINE_TEMPORAL_OFFSET_MISSING")
    return int(offset)


def _transform_stream(
    engine_plan: EnginePlan,
    directive: TableDirective,
    table: DirectSourceTable,
    vault: VaultDatabase,
    spool: PassOneSpool,
    control: ProgressController,
    text_domain_id: str | None,
    temporal_offset: int | None,
    read_streams: list[tuple[str, str]],
    ) -> Iterator[DirectRecord]:
    """The lazy transformed record stream feeding the Direct Write boundary."""
    memo_policy = "inline" if table.has_memo_fields else "skip"
    read_streams.append(("pass2", directive.relative_path))
    records = stream_table_records(
        table,
        include_deleted=True,
        memo_policy=memo_policy,
        cancel_check=control.check_cancelled,
    )
    system_fields = {
        str(field.name)
        for field in table.schema.fields
        if str(field.dbf_type).upper() == "0"
    }
    for record in records:
        control.check_cancelled()
        # Type-0 fields (notably VFP _NullFlags) are writer-owned system
        # state.  Supply only logical application values and let dbfbridge
        # derive the output bitmap from None/non-None values.
        values = {
            name: value
            for name, value in record.values.items()
            if name not in system_fields
        }
        for field_directive in directive.transformed:
            name = field_directive.field_name
            value = values.get(name)
            if field_directive.numeric_domain_id is not None:
                if value is None:
                    continue  # NULL stays NULL (public reader representation)
                if isinstance(value, bool) or not isinstance(value, int):
                    raise _mapping_failure("ENGINE_NUMERIC_VALUE_UNSUPPORTED")
                mapped = get_numeric_pseudonym(
                    vault, field_directive.numeric_domain_id, canonical_integer_text(value)
                )
                if mapped is None:
                    raise _mapping_failure("ENGINE_NUMERIC_MAPPING_MISSING")
                values[name] = parse_canonical_integer_text(mapped)
            elif field_directive.action == "PSEUDONYMIZE_REVERSIBLE":
                if value is None or value == "":
                    continue  # NULL and empty stay preserved identities
                assert text_domain_id is not None
                mapped = get_text_pseudonym(vault, text_domain_id, str(value))
                if mapped is None:
                    raise _mapping_failure("ENGINE_TEXT_MAPPING_MISSING")
                values[name] = mapped
            elif field_directive.action == "MASK_REVERSIBLE":
                values[name] = memo_safe_mask(value)
            elif field_directive.action == "SHIFT_REVERSIBLE":
                if temporal_offset is None:  # pragma: no cover - plan checked
                    raise _mapping_failure("ENGINE_TEMPORAL_OFFSET_MISSING")
                values[name] = temporal_shift(value, temporal_offset)
            # identity fields keep their exact values
        for relation in engine_plan.relations:
            assert isinstance(relation, RelationDirective)
            if relation.parent_table == directive.relative_path:
                _observe_after_side(
                    relation, "parent", relation.parent_fields, values, spool
                )
            if relation.foreign_table == directive.relative_path:
                _observe_after_side(
                    relation, "foreign", relation.foreign_fields, values, spool
                )
        yield DirectRecord(
            physical_index=record.physical_index,
            deleted=record.deleted,
            values=values,
        )


def _observe_after_side(
    relation: RelationDirective,
    role: str,
    fields: Sequence[str],
    values: dict[str, object],
    spool: PassOneSpool,
) -> None:
    """The P3 NULL semantics on the TRANSFORMED (after) side."""
    components: list[object] = []
    null_tuple = False
    for field_name in fields:
        value = values.get(field_name)
        if value is None:
            null_tuple = True
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise _mapping_failure("ENGINE_RELATION_MEMBER_UNSUPPORTED")
        components.append(int(value) if isinstance(value, int) else str(value))
    spool.observe_relation_side(
        "after", relation.relation_id, role, rows=1, nulls=1 if null_tuple else 0
    )
    if not null_tuple:
        spool.observe_relation_key(
            "after",
            relation.relation_id,
            role,
            canonical_composite_identity(tuple(components)),
        )


def _compare_relations(
    engine_plan: EnginePlan, spool: PassOneSpool
) -> Sequence[RelationPassSummary]:
    """The streaming before/after evidence comparison (the P3 invariant rule).

    THE ONE invariant rule of REQ-P3-006, evaluated with bounded SQL
    aggregates and streamed multiplicity histograms:

    * parent-key uniqueness preserved (the parent multiplicity multiset is
      equal by streaming comparison);
    * the FK orphan count preserved;
    * the matched-row count preserved;
    * both NULL counts preserved;
    * the composite FK tuple multiplicity profile preserved.
    """
    summaries: list[RelationPassSummary] = []
    for relation in engine_plan.relations:
        assert isinstance(relation, RelationDirective)
        relation_id = relation.relation_id
        before_parent = spool.relation_side_facts("before", relation_id, "parent")
        after_parent = spool.relation_side_facts("after", relation_id, "parent")
        before_foreign = spool.relation_side_facts("before", relation_id, "foreign")
        after_foreign = spool.relation_side_facts("after", relation_id, "foreign")
        before_unique = spool.relation_unique_count("before", relation_id, "parent")
        after_unique = spool.relation_unique_count("after", relation_id, "parent")
        before_matched = spool.relation_matched_count(
            "before", relation_id, "parent", "foreign"
        )
        after_matched = spool.relation_matched_count(
            "after", relation_id, "parent", "foreign"
        )
        before_orphan = (before_foreign[0] - before_foreign[1]) - before_matched
        after_orphan = (after_foreign[0] - after_foreign[1]) - after_matched
        parent_profile_equal = spool.relation_profile_equal(
            relation_id, "before", "after", "parent"
        )
        foreign_profile_equal = spool.relation_profile_equal(
            relation_id, "before", "after", "foreign"
        )
        verified = (
            parent_profile_equal
            and foreign_profile_equal
            and before_matched == after_matched
            and before_orphan == after_orphan
            and before_parent[1] == after_parent[1]
            and before_foreign[1] == after_foreign[1]
        )
        summaries.append(
            RelationPassSummary(
                relation_id=relation_id,
                verified=verified,
                before_rows=before_parent[0] + before_foreign[0],
                after_rows=after_parent[0] + after_foreign[0],
                before_nulls=before_foreign[1],
                after_nulls=after_foreign[1],
                before_unique=before_unique,
                after_unique=after_unique,
                matched_rows=after_matched,
                orphan_count=after_orphan,
                parent_profile_equal=parent_profile_equal,
                foreign_profile_equal=foreign_profile_equal,
            )
        )
    return summaries


_UNUSED_TEXT_DOMAIN = GLOBAL_TEXT_DOMAIN_ID
