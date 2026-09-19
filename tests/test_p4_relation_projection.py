"""BLOCKER 2 regressions: pass-1 projection covers EVERY relation member.

The pass-1 field projection must be the union of the transformed fields and
ALL declared relationship member fields of the table — INCLUDING members
that remain identity (an identity I/N relation, a C/V relation under a KEEP
policy, the identity component of a composite relation and NULLable numeric
members).  A projected member that pass 1 skips would be misread as NULL in
the BEFORE evidence while pass 2 (which reads the full record) sees the real
value — every regression here FAILS under that old behavior (typed evidence
mismatch instead of a verified relation) and PASSES with the union.
"""

from __future__ import annotations

from pathlib import Path

from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import run_two_pass
from support.memo_tables import write_memo_table
from support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table,
)

_KEEP_TEXT_POLICY = {"text": {"default_action": "KEEP"}}


def _member(
    table: str,
    field_name: str,
    role: str,
    dbf_type: str,
    byte_width: int,
    *,
    ordinal: int = 1,
    nullable: bool = False,
) -> dict[str, object]:
    encoding = "none" if dbf_type in ("I", "N") else "cp1250"
    return {
        "table": table,
        "field": field_name,
        "role": role,
        "ordinal": ordinal,
        "dbf_type": dbf_type,
        "byte_width": byte_width,
        "encoding": encoding,
        "nullable": nullable,
    }


def _document(relation_id: str, members: list[dict[str, object]]) -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": relation_id,
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": members,
            }
        ],
    }


def _summary(result, relation_id: str):
    summaries = {summary.relation_id: summary for summary in result.relations}
    return summaries[relation_id]


# ---------------------------------------------------------------------------
# A. Identity Integer relation plus unrelated transformed text
# ---------------------------------------------------------------------------
def test_identity_integer_relation_before_evidence_has_actual_keys(
    tmp_path: Path,
) -> None:
    """An I/N IDENTITY relation member is never transformed — but its ACTUAL
    values must still appear in the BEFORE evidence (the old projection read
    only the transformed text field and recorded every key as NULL)."""
    document = _document(
        "rel-key",
        [
            _member("north/customers.dbf", "CUST_NUM", "PRIMARY", "I", 4),
            _member("south/orders.dbf", "CUST_NUM", "FOREIGN", "I", 4),
        ],
    )
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_NUM", "I", 4), numeric_field("NAME", "C", 8)),
        [
            {"CUST_NUM": 11, "NAME": "ALFA"},
            {"CUST_NUM": 22, "NAME": "BETA"},
        ],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_NUM", "I", 4), numeric_field("NAME", "C", 8)),
        [
            {"CUST_NUM": 11, "NAME": "O1"},
            {"CUST_NUM": 22, "NAME": "O2"},
            {"CUST_NUM": 99, "NAME": "ORPHAN"},
        ],
    )
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
    )
    result = run_two_pass(plan)
    summary = _summary(result, "rel-key")
    # The BEFORE evidence carries the ACTUAL numeric keys (2 distinct parent
    # keys, zero NULL tuples) — not the all-NULL projection of the old code.
    assert summary.before_rows >= 2
    assert summary.before_unique == 2
    assert summary.before_nulls == 0
    assert summary.verified
    assert summary.matched_rows == 2
    assert summary.orphan_count == 1
    assert result.all_relations_verified


# ---------------------------------------------------------------------------
# B. C/V relation under a KEEP policy plus an unrelated transformed memo
# ---------------------------------------------------------------------------
def test_text_keep_relation_verifies_unchanged_beside_transformed_memo(
    tmp_path: Path,
) -> None:
    """A C/V relation member under a KEEP policy stays identity, but pass 1
    must still project it: the relation verifies unchanged while the
    unrelated memo field is masked (old projection -> all-NULL BEFORE)."""
    document = _document(
        "rel-keep",
        [
            _member("north/customers.dbf", "CUST_ID", "PRIMARY", "C", 8),
            _member("south/orders.dbf", "CUST_ID", "FOREIGN", "C", 8),
        ],
    )
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": "KEY-01"}, {"CUST_ID": "KEY-02"}],
    )
    write_memo_table(
        source_root,
        "south/orders.dbf",
        (
            write_memo_table_field("CUST_ID", "C", 8),
            write_memo_table_field("NOTE", "M", 4),
        ),
        [{"CUST_ID": "KEY-01", "NOTE": "alpha-note"}, {"CUST_ID": "KEY-02", "NOTE": "beta-note"}],
    )
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
        policy=_KEEP_TEXT_POLICY,
    )
    result = run_two_pass(plan)
    summary = _summary(result, "rel-keep")
    assert summary.verified
    assert summary.before_unique == 2
    assert summary.before_nulls == 0
    assert summary.matched_rows == 2
    assert result.all_relations_verified


def write_memo_table_field(name: str, dbf_type: str, width: int):
    from support.memo_tables import field

    return field(name, dbf_type, width)


# ---------------------------------------------------------------------------
# C. Composite relation: one transformed member + one identity member
# ---------------------------------------------------------------------------
def test_composite_relation_projects_transformed_and_identity_members(
    tmp_path: Path,
) -> None:
    """A composite key with a pseudonymized C member AND an identity I member
    needs BOTH fields in the pass-1 projection (old projection read only the
    transformed one and misread the identity component as NULL)."""
    document = _document(
        "rel-composite",
        [
            _member("north/customers.dbf", "CUST_ID", "PRIMARY", "C", 8, ordinal=1),
            _member("north/customers.dbf", "CUST_NUM", "PRIMARY", "I", 4, ordinal=2),
            _member("south/orders.dbf", "CUST_ID", "FOREIGN", "C", 8, ordinal=1),
            _member("south/orders.dbf", "CUST_NUM", "FOREIGN", "I", 4, ordinal=2),
        ],
    )
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 8), numeric_field("CUST_NUM", "I", 4)),
        [
            {"CUST_ID": "KEY-01", "CUST_NUM": 5},
            {"CUST_ID": "KEY-02", "CUST_NUM": 6},
        ],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 8), numeric_field("CUST_NUM", "I", 4)),
        [
            {"CUST_ID": "KEY-01", "CUST_NUM": 5},
            {"CUST_ID": "KEY-02", "CUST_NUM": 6},
            {"CUST_ID": "KEY-0X", "CUST_NUM": 7},  # orphan tuple
        ],
    )
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
    )
    result = run_two_pass(plan)
    summary = _summary(result, "rel-composite")
    # The composite BEFORE profile carries real (transformed+identity) tuple
    # keys on both sides, so the multiplicity profile equality holds.
    assert summary.verified
    assert summary.before_nulls == 0
    assert summary.matched_rows == 2
    assert summary.orphan_count == 1
    assert summary.parent_profile_equal
    assert summary.foreign_profile_equal
    assert result.all_relations_verified


# ---------------------------------------------------------------------------
# D. Nullable numeric identity relation: non-NULL values are never synthetic
#    NULLs just because their field was omitted from the projection
# ---------------------------------------------------------------------------
def test_nullable_numeric_relation_preserves_non_null_evidence(
    tmp_path: Path,
) -> None:
    """A NULLable I relation member is projected too: the one real NULL row
    is counted as NULL, every non-NULL row contributes its actual key to the
    BEFORE histogram (the old projection turned ALL rows into NULLs)."""
    document = _document(
        "rel-null",
        [
            _member(
                "north/customers.dbf",
                "CUST_NUM",
                "PRIMARY",
                "I",
                4,
                nullable=True,
            ),
            _member(
                "south/orders.dbf",
                "CUST_NUM",
                "FOREIGN",
                "I",
                4,
                nullable=True,
            ),
        ],
    )
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_NUM", "I", 4, flags=NULLABLE_FLAG),),
        [{"CUST_NUM": 1}, {"CUST_NUM": 2}, {"CUST_NUM": None}],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_NUM", "I", 4, flags=NULLABLE_FLAG),),
        [{"CUST_NUM": 1}, {"CUST_NUM": None}],
    )
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
    )
    result = run_two_pass(plan)
    summary = _summary(result, "rel-null")
    # BEFORE: 3 parent rows (1 NULL tuple), 2 foreign rows (1 NULL tuple),
    # with the REAL non-NULL keys histogrammed — not a synthetic all-NULL.
    assert summary.before_rows >= 3
    assert summary.before_unique == 2
    assert summary.after_unique == 2
    assert summary.before_nulls == 1
    assert summary.after_nulls == 1
    assert summary.verified
    assert summary.matched_rows == 1
    assert result.all_relations_verified