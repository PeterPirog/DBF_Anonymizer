"""The INTERNAL engine directives of the two-pass coordinator.

These frozen dataclasses bind the immutable typed Plan, the resolved policy
and the declared relationship document to the engine's execution directives.
They are NOT public models: no original value, pseudonym, path or secret is
ever part of a directive — only normalized relative identities, structural
facts and the typed numeric member descriptors already established by the
P3 planner.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dbf_anonymizer.models import Plan
from dbf_anonymizer.transforms.numeric_keys import (
    NumericKeyDomain,
    NumericKeyMemberRange,
)

__all__ = [
    "FieldDirective",
    "TableDirective",
    "RelationDirective",
    "EnginePlan",
    "RelationPassSummary",
    "TwoPassResult",
    "ACTION_TEXT",
    "ACTION_MEMO",
    "ACTION_TEMPORAL",
]

ACTION_TEXT = "PSEUDONYMIZE_REVERSIBLE"
ACTION_MEMO = "MASK_REVERSIBLE"
ACTION_TEMPORAL = "SHIFT_REVERSIBLE"


@dataclass(frozen=True)
class FieldDirective:
    """The INTERNAL engine directive for one transformed field."""

    field_name: str
    action: str
    dbf_type: str
    encoding: str
    byte_width: int
    numeric_domain_id: str | None = None
    numeric_member_range: NumericKeyMemberRange | None = None


@dataclass(frozen=True)
class TableDirective:
    """The INTERNAL per-table execution plan of one source table."""

    relative_path: str
    transformed: tuple[FieldDirective, ...]
    memo_fields: tuple[str, ...]
    temporal_fields: tuple[str, ...]
    relation_fields: tuple[str, ...] = ()
    structural_cdx: bool = False
    record_count: int = 0


@dataclass(frozen=True)
class RelationDirective:
    """The INTERNAL execution plan of one declared relation."""

    relation_id: str
    composite_arity: int
    parent_table: str
    foreign_table: str
    parent_fields: tuple[str, ...]
    foreign_fields: tuple[str, ...]
    numeric_domain_id: str | None
    numeric_domain: NumericKeyDomain | None


@dataclass(frozen=True)
class EnginePlan:
    """The INTERNAL binding of one immutable Plan to engine directives."""

    plan: Plan
    tables: tuple[TableDirective, ...]
    relations: tuple[RelationDirective, ...]
    text_present: bool
    numeric_present: bool
    temporal_present: bool
    structural_cdx_tables: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelationPassSummary:
    """The bounded before/after verification summary of one relation."""

    relation_id: str
    verified: bool
    before_rows: int
    after_rows: int
    before_nulls: int
    after_nulls: int
    before_unique: int
    after_unique: int
    matched_rows: int
    orphan_count: int
    parent_profile_equal: bool
    foreign_profile_equal: bool


@dataclass(frozen=True)
class TwoPassResult:
    """The bounded INTERNAL result of one two-pass engine run.

    Counts, identities and digests only — never a key value, pseudonym,
    memo payload, absolute path or secret.
    """

    tables_written: tuple[str, ...]
    pass1_records_scanned: int
    pass1_deleted_scanned: int
    pass2_records_written: int
    text_allocated: int
    text_reused: int
    numeric_allocated: dict[str, int]
    temporal_offset_allocated: bool
    relations: tuple[RelationPassSummary, ...]
    evidence_spool_bytes: int
    #: One-shot per-pass instrumentation (REQ-P4-002): every Direct Read
    #: stream opened during the run, in order ("pass1"/"pass2", path).
    read_streams: tuple[tuple[str, str], ...] = ()
    operation_id: str | None = None
    output_fingerprint: str | None = None
    reused_existing: bool = False
    #: Whether the run created a fresh durable protected-state store (the
    #: neutral internal fact; the protected-state name itself must never
    #: enter the engine boundary serialization — see the P4 canary rules).
    protected_state_created: bool = False

    @property
    def all_relations_verified(self) -> bool:
        return all(summary.verified for summary in self.relations)
