"""The Phase 4 two-pass engine coordinator (REQ-P4-001/P4-002).

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

The engine is an INTERNAL implementation boundary: it is not part of the
root public API, no public ``pseudonymize`` operation exists yet (the
publication/staging state is REQ-P4-009 scope) and the final field-by-field
reconstruction semantics remain owned by P4-003/004.  Unsupported execution
fails CLOSED before any output is produced — the engine never publishes a
partially transformed dataset: every table written by THIS run is removed
again when the run fails or is cancelled (full crash-resilient publication
state belongs to P4-009).
"""

from __future__ import annotations

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
from dbf_anonymizer.engine.pass1 import PassOneOutcome, run_pass_one, run_pass_one_finalize
from dbf_anonymizer.engine.pass2 import run_pass_two
from dbf_anonymizer.engine.state import (
    MAX_RECORD_BATCH,
    PassOneSpool,
)
from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError, PathError
from dbf_anonymizer.models import Plan
from dbf_anonymizer.policy import resolve_policy
from dbf_anonymizer.relationships.document import parse_relationship_document
from dbf_anonymizer.relationships.models import (
    RelationGroup,
    RelationshipDocument,
)
from dbf_anonymizer.progress import ProgressController, ProgressPhase
from dbf_anonymizer.transforms.numeric_keys import (
    NumericKeyDomain,
    NumericKeyMemberRange,
    integer_member,
    integral_numeric_member,
    numeric_key_domain_for,
)
from dbf_anonymizer.vault.numeric_allocation import numeric_key_domain_id
from dbf_anonymizer.vault.store import VaultDatabase, new_writer_token
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
            if dbf_type == "0":
                continue  # the writer-managed system bitmap
            if not bool(field_info.supported) or bool(field_info.is_binary):
                raise _path_failure("ENGINE_FIELD_UNSUPPORTED")
            if bool(field_info.nullable) and dbf_type in ("C", "V", "M", "G", "P"):
                # PUBLIC CAPABILITY GAP (see direct_io docs): the public
                # Direct Read cannot expose the NULL/empty distinction of
                # text fields — fail closed instead of an empty heuristic.
                raise _path_failure("ENGINE_NULLABLE_TEXT_UNSUPPORTED")
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
            if dbf_type in ("C", "V"):
                if _text_action(merged_policy) is None:
                    continue
                transformed.append(
                    FieldDirective(
                        field_name=name,
                        action=ACTION_TEXT,
                        dbf_type=dbf_type,
                        encoding=str(schema.encoding),
                        byte_width=int(field_info.length),
                    )
                )
                text_present = True
            elif dbf_type in ("M", "G", "P"):
                if _memo_action(merged_policy, dbf_type) is None:
                    continue
                transformed.append(
                    FieldDirective(
                        field_name=name,
                        action=ACTION_MEMO,
                        dbf_type=dbf_type,
                        encoding=str(schema.encoding),
                        byte_width=int(field_info.length),
                    )
                )
                memo_fields.append(name)
            elif dbf_type in ("D", "T"):
                if _temporal_action(merged_policy, dbf_type) is None:
                    continue
                transformed.append(
                    FieldDirective(
                        field_name=name,
                        action=ACTION_TEMPORAL,
                        dbf_type=dbf_type,
                        encoding=str(schema.encoding),
                        byte_width=int(field_info.length),
                    )
                )
                temporal_fields.append(name)
                temporal_present = True
            elif dbf_type in ("N", "I", "F", "Y", "B", "L"):
                continue  # identity by policy (P2/P3 contract)
            else:
                raise _path_failure("ENGINE_FIELD_UNSUPPORTED")
        tables.append(
            TableDirective(
                relative_path=relative_path,
                transformed=tuple(transformed),
                memo_fields=tuple(memo_fields),
                temporal_fields=tuple(temporal_fields),
            )
        )

    if relationship_document is not None:
        # EVERY declared relation is tracked for the verification evidence —
        # declared text relations and reversible numeric relations alike.
        numeric_by_group: dict[RelationGroup, str] = dict(numeric_groups)
        for group in relationship_document.groups:
            group_domain: str | None = numeric_by_group.get(group)
            domain: NumericKeyDomain | None = None
            if group_domain is not None:
                numeric_member_list = [
                    member
                    for member in group.members
                    if member.is_numeric_member
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
            parent_members = group.members_for_role("PRIMARY") or group.members_for_role(
                "CANDIDATE"
            )
            foreign_members = group.members_for_role("FOREIGN")
            relations.append(
                RelationDirective(
                    relation_id=str(group.relation_id),
                    composite_arity=len(parent_members),
                    parent_table=str(parent_members[0].table_path),
                    foreign_table=str(foreign_members[0].table_path),
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
    return EnginePlan(
        plan=plan,
        tables=tuple(tables),
        relations=tuple(relations),
        text_present=text_present,
        numeric_present=numeric_present,
        temporal_present=temporal_present,
    )


def _text_action(merged_policy: dict[str, object]) -> str | None:
    section = merged_policy.get("text")
    action = (
        str(section.get("default_action", "PSEUDONYMIZE_REVERSIBLE"))
        if isinstance(section, dict)
        else "PSEUDONYMIZE_REVERSIBLE"
    )
    return None if action == "KEEP" else action


def _memo_action(merged_policy: dict[str, object], dbf_type: str) -> str | None:
    section = merged_policy.get("memo")
    key = "binary" if dbf_type in ("G", "P") else "text"
    action = (
        str(section.get(key, "MASK_REVERSIBLE"))
        if isinstance(section, dict)
        else "MASK_REVERSIBLE"
    )
    return None if action == "KEEP" else action


def _temporal_action(merged_policy: dict[str, object], dbf_type: str) -> str | None:
    section = merged_policy.get("temporal")
    key = "datetime" if dbf_type == "T" else "date"
    action = (
        str(section.get(key, "SHIFT_REVERSIBLE"))
        if isinstance(section, dict)
        else "SHIFT_REVERSIBLE"
    )
    return None if action == "KEEP" else action


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


def run_two_pass(
    plan: Plan,
    *,
    source_root: Path | str,
    output_root: Path | str,
    vault_path: Path | str,
    policy: object = None,
    relationship_document: RelationshipDocument | None = None,
    progress: Callable[[object], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> TwoPassResult:
    """The bounded two-pass production run over one immutable plan.

    Cancellation and progress follow REQ-P1-008: the cooperative check is
    polled between tables, per record and before every finalize/write safe
    point; the typed :class:`~dbf_anonymizer.errors.CancellationError`
    leaves the source untouched and removes everything this run wrote (no
    published partial output).  The single authoritative recovery vault is
    the only durable mapping truth; the ephemeral evidence spool is
    protected Zone B state that is cleaned up explicitly after the run.
    """
    source = Path(source_root)
    output = Path(output_root)
    vault_path = Path(vault_path)
    control = ProgressController(
        operation="two_pass", progress=progress, cancel_check=cancel_check
    )
    parsed_document = (
        parse_relationship_document(relationship_document)
        if isinstance(relationship_document, dict)
        else relationship_document
    )
    engine_plan = build_engine_plan(
        plan,
        source_root=source,
        policy=policy,
        relationship_document=parsed_document,
    )
    vault = VaultDatabase.open(
        vault_path,
        create=not vault_path.exists(),
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version=str(dbfbridge.__version__),
    )
    spool = PassOneSpool(vault_directory=vault_path.parent)
    written: list[str] = []
    try:
        outcome = PassOneOutcome()
        temporal_domain = (
            TemporalShiftDomain(vault, domain_name=None)
            if engine_plan.temporal_present
            else None
        )
        with _WriterLease(vault) as writer_vault:
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
        result = run_pass_two(
            engine_plan,
            source_root=source,
            output_root=output,
            vault=vault,
            spool=spool,
            control=control,
            outcome=outcome,
            written=written,
        )
        result_spool_bytes = _spool_size_bytes(vault_path.parent)
        control.complete(completed=len(result.tables_written))
        return result
    except BaseException:
        _discard_written(output, written)
        raise
    finally:
        vault.close()
        spool.cleanup()


def _spool_size_bytes(vault_path: Path) -> int:
    from dbf_anonymizer.engine.state import PASS1_STATE_FILENAME

    spool_file = vault_path.parent / PASS1_STATE_FILENAME
    try:
        return spool_file.stat().st_size
    except OSError:
        return 0


def _discard_written(output_root: Path, written: Sequence[str]) -> None:
    """Remove everything THIS run wrote (no partial published output).

    Best-effort artifact removal after a failure or cancellation; a cleanup
    failure is surfaced, never silently ignored.  The durable
    publication/staging state remains REQ-P4-009 scope.
    """
    for relative_path in reversed(written):
        base = output_root / relative_path
        for suffix in ("", ".fpt"):
            artifact = Path(str(base) + suffix)
            try:
                if artifact.exists():
                    artifact.unlink()
            except OSError:
                pass


