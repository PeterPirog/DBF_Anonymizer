"""Deterministic relationship-verification evidence (REQ-P3-006).

The before/after evidence for EVERY declared relation is computed with the
ONE shared count kernel over REAL public dbfbridge fixtures and the REAL
existing transform allocators (the P2 global text domain and the REQ-P3-005
numeric key domains): PK uniqueness, FK orphan count, matched-row count,
NULL counts and composite-key tuple multiplicity — preserved exactly, with
deleted records in scope and no actual key value ever reaching a report,
error or progress boundary.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Hashable, Sequence

import pytest

from dbf_anonymizer import VerificationError
from dbf_anonymizer.models import RelationshipMetadata
from dbf_anonymizer.relationships import (
    EVIDENCE_SCHEMA_VERSION,
    NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
    PROVENANCE_POLICY_FILE,
    RELATIONSHIP_INVARIANTS,
    RelationshipVerificationReport,
    VerificationStatus,
    parse_relationship_document,
    relationship_fingerprint,
    verify_relationships,
)
from dbf_anonymizer.relationships.assurance import (
    RelationalAssuranceSummary,
    derive_relational_assurance,
)
from dbf_anonymizer.relationships.evidence import relation_metrics
from dbf_anonymizer.relationships.verification import (
    INVARIANT_FOREIGN_MULTIPLICITY,
    INVARIANT_MATCHED_ROWS,
    INVARIANT_NULL_COUNTS,
    INVARIANT_ORPHAN_COUNT,
    INVARIANT_PARENT_UNIQUENESS,
    RelationEvidenceCounts,
    RelationshipEvidenceAccumulator,
    compare_relation_metrics,
)
from dbf_anonymizer.transforms.numeric_keys import (
    integer_member,
    integral_numeric_member,
    numeric_key_domain_for,
)
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
    VaultDatabase,
    numeric_key_domain_id,
)
from dbf_anonymizer.vault.mappings import create_domain
from dbf_anonymizer.vault.numeric_allocation import NumericKeyDomainMapping
from dbf_anonymizer.vault.text_allocation import (
    GLOBAL_TEXT_DOMAIN_ID,
    GlobalTextDomainMapping,
)
from support.vault_sessions import writer_session
from tests.support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    read_numeric_records,
    write_numeric_table,
    write_numeric_table_with_deleted,
)

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60

#: Canaries — these actual key values must never reach a public boundary.
CANARY_TEXT = "KUND-CANARY-SECRET"
CANARY_NUMERIC = 2147483646


def _open_vault(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version="1.1.0",
    )


def _document(payload: object):
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    return document, relationship_fingerprint(document)


def _counts(
    primary: Sequence[tuple[Hashable, ...]],
    foreign: Sequence[tuple[Hashable, ...]],
    *,
    foreign_nulls: Sequence[bool] | None = None,
) -> RelationEvidenceCounts:
    """One side-pair evidence build through the SHARED count kernel."""
    accumulator = RelationshipEvidenceAccumulator(
        composite_arity=len(primary[0]) if primary else 1
    )
    for key in primary:
        if key == ():
            accumulator.observe_parent((), null=True)
        else:
            accumulator.observe_parent(key)
    if foreign_nulls is None:
        for key in foreign:
            if key == ():
                accumulator.observe_foreign((), null=True)
            else:
                accumulator.observe_foreign(key)
    else:
        for key, null in zip(foreign, foreign_nulls):
            if null:
                accumulator.observe_foreign((), null=True)
            else:
                accumulator.observe_foreign(key)
    return accumulator.build()


def _metadata(fingerprint: str, *, authoritative: bool = False) -> RelationshipMetadata:
    return RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_POLICY_FILE,
        relationship_fingerprint=fingerprint,
        relation_count=1,
        authoritative=authoritative,
    )


# ---------------------------------------------------------------------------
# text fixtures through the REAL public writer + REAL P2 allocation service
# ---------------------------------------------------------------------------
def _text_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer-key",
                "provenance": PROVENANCE_POLICY_FILE,
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "north/customers.dbf",
                        "field": "customer_id",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "customer_id",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }


def _write_text_relation(root: Path) -> tuple[list[str], list[str]]:
    """Real C-key DBF tables: repeated FK, an orphan, a NULL-free join."""
    from tests.support.memo_tables import field, read_memo_records, write_memo_table

    write_memo_table(
        root,
        "north/customers.dbf",
        (field("CUST_ID", "C", 8),),
        [{"CUST_ID": "KUND-01"}, {"CUST_ID": "KUND-02"}, {"CUST_ID": "KUND-03"}],
    )
    write_memo_table(
        root,
        "south/orders.dbf",
        (field("CUST_ID", "C", 8),),
        [
            {"CUST_ID": "KUND-02"},
            {"CUST_ID": "KUND-02"},
            {"CUST_ID": "KUND-01"},
            {"CUST_ID": "KUND-99"},  # deliberate orphan
        ],
    )
    pk_rows = [record.values for record in read_memo_records(root / "north/customers.dbf")]
    fk_rows = [record.values for record in read_memo_records(root / "south/orders.dbf")]
    return [row["CUST_ID"] for row in pk_rows], [row["CUST_ID"] for row in fk_rows]


def _shift_text(
    allocator: GlobalTextDomainMapping, values: Sequence[str | None]
) -> list[str | None]:
    def shift(value: str | None) -> str | None:
        if value is None:
            return None  # NULL: preserved, never mapped (P2 contract)
        return allocator.pseudonym_for(value)

    return [shift(value) for value in values]


def _numeric_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-numeric-key",
                "provenance": PROVENANCE_POLICY_FILE,
                "comparison": "EXACT_VALUE",
                "numeric_strategy": NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
                "members": [
                    {
                        "table": "north/customers.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": True,
                    },
                ],
            }
        ],
    }


def _numeric_report(
    tmp_path: Path,
    document,
    pk_values: Sequence[int | None],
    fk_values: Sequence[int | None],
) -> RelationshipVerificationReport:
    """The REAL numeric allocator transforms one single-column relation."""
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
                    domain_id=numeric_key_domain_id(
                        relationship_fingerprint(
                            parse_relationship_document(_numeric_document())  # type: ignore[arg-type]
                        ),
                        "rel-numeric-key",
                    ),
                )
            domain = numeric_key_domain_for([integer_member()])
            allocator = NumericKeyDomainMapping(
                vault,
                domain_id=numeric_key_domain_id(
                    relationship_fingerprint(
                        parse_relationship_document(_numeric_document())  # type: ignore[arg-type]
                    ),
                    "rel-numeric-key",
                ),
                domain=domain,
            )
            for value in sorted({v for v in list(pk_values) + list(fk_values) if v is not None}):
                allocator.observe_original(value, member=integer_member())
            allocator.finalize()
            primary_before = [(value,) for value in pk_values]
            foreign_before = [(value,) for value in fk_values]
            primary_after = [
                () if value is None else (allocator.pseudonym_for(value),)
                for value in pk_values
            ]
            foreign_after = [
                () if value is None else (allocator.pseudonym_for(value),)
                for value in fk_values
            ]
            nulls = [value is None for value in fk_values]
            before = _counts(
                [() if v is None else (v,) for v in pk_values],  # type: ignore[misc]
                foreign_before,
                foreign_nulls=nulls,
            )
            after = _counts(primary_after, foreign_after, foreign_nulls=nulls)
            return verify_relationships(
                document,
                before={"rel-numeric-key": before},
                after={"rel-numeric-key": after},
            )


# ---------------------------------------------------------------------------
# 1. single C relation — all invariants preserved (+ repeats/orphans)
# ---------------------------------------------------------------------------
def test_single_c_relation_all_invariants_preserved(tmp_path: Path) -> None:
    document, fingerprint = _document(_text_document())
    primary_before, foreign_before = _write_text_relation(tmp_path / "src")
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("north/customers.dbf")
                vault.register_table("south/orders.dbf")
            allocator = GlobalTextDomainMapping(vault)
            for original in sorted(set(primary_before) | {v for v in foreign_before if v}):
                allocator.observe(original, encoding="cp1250", byte_width=8)
            allocator.finalize()
            primary_after = _shift_text(allocator, primary_before)
            foreign_after = _shift_text(allocator, foreign_before)
            before = _counts([(v,) for v in primary_before], [(v,) for v in foreign_before])
            after = _counts(
                [(v,) for v in primary_after], [(v,) for v in foreign_after]
            )
            report = verify_relationships(
                document,
                before={"rel-customer-key": before},
                after={"rel-customer-key": after},
            )
            assert report.complete is True
            assert [entry.status for entry in report.relations] == [
                VerificationStatus.VERIFIED
            ]
            assert [
                result.invariant for result in report.relations[0].invariants
            ] == list(RELATIONSHIP_INVARIANTS)
            assert all(result.preserved for result in report.relations[0].invariants)
            assert report.relationship_fingerprint == fingerprint
            assert report.evidence_schema_version == EVIDENCE_SCHEMA_VERSION
            # Repeated FK multiplicity and the deliberate orphan are preserved.
            assert before.foreign.multiplicity_profile == (2, 1, 1)
            assert before.orphan_count == after.orphan_count == 1
            assert before.matched_row_count == after.matched_row_count == 3
            # PK uniqueness: 3 distinct parents, no duplicate parent rows.
            assert before.parent.duplicate_row_count == after.parent.duplicate_row_count == 0
            assert before.parent.multiplicity_profile == (1, 1, 1)
            # The assurance derives from this complete verified evidence.
            summary = derive_relational_assurance(
                _metadata(fingerprint), report
            )
            assert summary.level.value == "DECLARED_RELATIONS_VERIFIED"


# ---------------------------------------------------------------------------
# 2. composite C relation — ordered tuple semantics preserved
# ---------------------------------------------------------------------------
def test_composite_c_relation_ordered_tuple_evidence(tmp_path: Path) -> None:
    document, _fingerprint = _document(
        {
            "metadata_schema_version": "1.0",
            "relations": [
                {
                    "relation_id": "rel-device",
                    "provenance": PROVENANCE_POLICY_FILE,
                    "comparison": "EXACT_VALUE",
                    "members": [
                        {"table": "site/devices.dbf", "field": "site_code", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                        {"table": "site/devices.dbf", "field": "device_code", "role": "PRIMARY", "ordinal": 2, "dbf_type": "C", "byte_width": 6, "encoding": "cp1250", "nullable": False},
                        {"table": "logs/jobs.dbf", "field": "parent_site_code", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                        {"table": "logs/jobs.dbf", "field": "parent_device_code", "role": "FOREIGN", "ordinal": 2, "dbf_type": "C", "byte_width": 6, "encoding": "cp1250", "nullable": False},
                    ],
                }
            ],
        }
    )
    pk_tuples = [("S1", "DEV-A"), ("S1", "DEV-B"), ("S2", "DEV-A")]
    fk_tuples = [("S1", "DEV-A"), ("S1", "DEV-A"), ("S2", "DEV-A"), ("S2", "ZZZ")]
    before = _counts(pk_tuples, fk_tuples)
    assert before.composite_arity == 2
    assert before.orphan_count == 1
    # Ordered tuple semantics: (A, B) is NOT (B, A).
    assert _counts(pk_tuples, [("DEV-A", "S1")]).orphan_count == 1
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("site/devices.dbf")
                vault.register_table("logs/jobs.dbf")
            allocator = GlobalTextDomainMapping(vault)
            for original in sorted(
                {value for pair in pk_tuples + fk_tuples for value in pair}
            ):
                allocator.observe(original, encoding="cp1250", byte_width=6)
            allocator.finalize()
            pk_after = [tuple(allocator.pseudonym_for(v) for v in pair) for pair in pk_tuples]
            fk_after = [tuple(allocator.pseudonym_for(v) for v in pair) for pair in fk_tuples]
            after = _counts(pk_after, fk_after)
            report = verify_relationships(
                document, before={"rel-device": before}, after={"rel-device": after}
            )
            assert report.complete is True
            assert report.relations[0].status is VerificationStatus.VERIFIED
            assert all(result.preserved for result in report.relations[0].invariants)


# ---------------------------------------------------------------------------
# 3. single V relation with trailing-space-distinct values
# ---------------------------------------------------------------------------
def test_v_relation_trailing_space_distinct_values_preserved(tmp_path: Path) -> None:
    document, _fingerprint = _document(
        {
            "metadata_schema_version": "1.0",
            "relations": [
                {
                    "relation_id": "rel-v-key",
                    "provenance": PROVENANCE_POLICY_FILE,
                    "comparison": "EXACT_VALUE",
                    "members": [
                        {"table": "a/parents.dbf", "field": "K", "role": "PRIMARY", "ordinal": 1, "dbf_type": "V", "byte_width": 6, "encoding": "cp1250", "nullable": False},
                        {"table": "b/children.dbf", "field": "K", "role": "FOREIGN", "ordinal": 1, "dbf_type": "V", "byte_width": 6, "encoding": "cp1250", "nullable": False},
                    ],
                }
            ],
        }
    )
    write_numeric_table(
        tmp_path,
        "a/parents.dbf",
        (numeric_field("K", "V", 6),),
        [{"K": "KEY"}, {"K": "KEY "}],
    )
    write_numeric_table(
        tmp_path,
        "b/children.dbf",
        (numeric_field("K", "V", 6),),
        [{"K": "KEY "}, {"K": "KEY"}, {"K": "KEY"}],
    )
    pk_rows = [record.values for record in read_numeric_records(tmp_path / "a/parents.dbf")]
    fk_rows = [record.values for record in read_numeric_records(tmp_path / "b/children.dbf")]
    primary_before = [row["K"] for row in pk_rows]
    foreign_before = [row["K"] for row in fk_rows]
    assert "KEY" in primary_before and "KEY " in primary_before
    before = _counts([(v,) for v in primary_before], [(v,) for v in foreign_before])
    # Trailing-space-distinct values are DISTINCT composite keys: two unique
    # parent tuples; the join evidence knows both spellings.
    assert before.parent.unique_tuple_count == 2
    assert before.orphan_count == 0
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("a/parents.dbf")
                vault.register_table("b/children.dbf")
            allocator = GlobalTextDomainMapping(vault)
            for original in set(primary_before + foreign_before):
                allocator.observe(original, encoding="cp1250", byte_width=6)
            allocator.finalize()
            # The exact-value bijection keeps the distinction: two pseudonyms.
            assert allocator.pseudonym_for("KEY") != allocator.pseudonym_for("KEY ")
            primary_after = _shift_text(allocator, primary_before)
            foreign_after = _shift_text(allocator, foreign_before)
            after = _counts(
                [(v,) for v in primary_after], [(v,) for v in foreign_after]
            )
            report = verify_relationships(
                document, before={"rel-v-key": before}, after={"rel-v-key": after}
            )
            assert report.complete is True
            assert report.relations[0].status is VerificationStatus.VERIFIED


# ---------------------------------------------------------------------------
# 4/5. numeric reversible relations: I and N (origin-member observation)
# ---------------------------------------------------------------------------
def test_i_reversible_relation_evidence_round_trip(tmp_path: Path) -> None:
    document, fingerprint = _document(_numeric_document())
    write_numeric_table(
        tmp_path,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": -5}, {"CUST_ID": 0}, {"CUST_ID": 7}, {"CUST_ID": 2147483646}],
    )
    write_numeric_table(
        tmp_path,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "I", 4, flags=NULLABLE_FLAG),),
        [
            {"CUST_ID": 7},
            {"CUST_ID": 7},
            {"CUST_ID": -5},
            {"CUST_ID": 0},
            {"CUST_ID": 2147483646},
            {"CUST_ID": 99},  # orphan
            {"CUST_ID": None},  # NULL FK
        ],
    )
    pk_rows = [record.values for record in read_numeric_records(tmp_path / "north/customers.dbf")]
    fk_rows = [record.values for record in read_numeric_records(tmp_path / "south/orders.dbf")]
    pk_values = [row["CUST_ID"] for row in pk_rows]
    fk_values = [row["CUST_ID"] for row in fk_rows]
    report = _numeric_report(tmp_path, document, pk_values, fk_values)
    entry = report.relations[0]
    assert entry.status is VerificationStatus.VERIFIED
    assert report.complete is True
    assert report.relationship_fingerprint == fingerprint
    before = entry.before
    after = entry.after
    assert before is not None and after is not None
    assert before.parent.multiplicity_profile == (1, 1, 1, 1)
    assert before.foreign.multiplicity_profile == (2, 1, 1, 1, 1)
    assert before.orphan_count == after.orphan_count == 1
    assert before.matched_row_count == after.matched_row_count == 5
    assert before.parent.null_tuple_count == 0
    assert before.foreign.null_tuple_count == after.foreign.null_tuple_count == 1


def test_n_reversible_relation_evidence_round_trip(tmp_path: Path) -> None:
    payload = _numeric_document()
    payload["relations"][0]["members"][0]["dbf_type"] = "N"  # type: ignore[index,union-attr]
    payload["relations"][0]["members"][0]["byte_width"] = 8  # type: ignore[index,union-attr]
    payload["relations"][0]["members"][1]["dbf_type"] = "N"  # type: ignore[index,union-attr]
    payload["relations"][0]["members"][1]["byte_width"] = 5  # type: ignore[index,union-attr]
    document, fingerprint = _document(payload)
    write_numeric_table(
        tmp_path,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "N", 8),),
        [{"CUST_ID": 101}, {"CUST_ID": 202}, {"CUST_ID": 303}],
    )
    write_numeric_table(
        tmp_path,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "N", 5),),
        [
            {"CUST_ID": 303},
            {"CUST_ID": 303},
            {"CUST_ID": 101},
            {"CUST_ID": 99999},  # orphan (fits N(5))
        ],
    )
    pk_rows = [record.values for record in read_numeric_records(tmp_path / "north/customers.dbf")]
    fk_rows = [record.values for record in read_numeric_records(tmp_path / "south/orders.dbf")]
    pk_values = [row["CUST_ID"] for row in pk_rows]
    fk_values = [row["CUST_ID"] for row in fk_rows]
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
                    domain_id=numeric_key_domain_id(fingerprint, "rel-numeric-key"),
                )
            domain = numeric_key_domain_for(
                [integral_numeric_member(8), integral_numeric_member(5)]
            )
            allocator = NumericKeyDomainMapping(
                vault,
                domain_id=numeric_key_domain_id(fingerprint, "rel-numeric-key"),
                domain=domain,
            )
            # Origin-member truthfulness: each occurrence under ITS OWN member.
            for value in sorted({v for v in pk_values if v is not None}):
                allocator.observe_original(value, member=integral_numeric_member(8))
            for value in sorted({v for v in fk_values if v is not None}):
                allocator.observe_original(value, member=integral_numeric_member(5))
            allocator.finalize()
            before = _counts([(v,) for v in pk_values], [(v,) for v in fk_values])
            pk_after = [(allocator.pseudonym_for(v),) for v in pk_values]
            fk_after = [(allocator.pseudonym_for(v),) for v in fk_values]
            after = _counts(pk_after, fk_after)
            report = verify_relationships(
                document, before={"rel-numeric-key": before}, after={"rel-numeric-key": after}
            )
            assert report.relations[0].status is VerificationStatus.VERIFIED
            # Pseudonyms fit the SHARED pseudonym domain; the reverse lookup
            # returns the exact original.
            assert domain.contains_pseudonym(allocator.pseudonym_for(101))
            assert allocator.original_for(allocator.pseudonym_for(101)) == 101
            assert before.foreign.multiplicity_profile == (2, 1, 1)
            assert before.orphan_count == after.orphan_count == 1


# ---------------------------------------------------------------------------
# 6. mixed composite I/N reversible relation
# ---------------------------------------------------------------------------
def test_mixed_composite_i_n_relation_evidence(tmp_path: Path) -> None:
    payload = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-mixed",
                "provenance": PROVENANCE_POLICY_FILE,
                "comparison": "EXACT_VALUE",
                "numeric_strategy": NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
                "members": [
                    {"table": "p/devices.dbf", "field": "SITE", "role": "PRIMARY", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": False},
                    {"table": "p/devices.dbf", "field": "DEVICE", "role": "PRIMARY", "ordinal": 2, "dbf_type": "N", "byte_width": 5, "encoding": "none", "nullable": False},
                    {"table": "c/jobs.dbf", "field": "SITE", "role": "FOREIGN", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": False},
                    {"table": "c/jobs.dbf", "field": "DEVICE", "role": "FOREIGN", "ordinal": 2, "dbf_type": "N", "byte_width": 5, "encoding": "none", "nullable": False},
                ],
            }
        ],
    }
    document, fingerprint = _document(payload)
    write_numeric_table(
        tmp_path,
        "p/devices.dbf",
        (numeric_field("SITE", "I", 4), numeric_field("DEVICE", "N", 5)),
        [
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 1, "DEVICE": 102},
            {"SITE": 2, "DEVICE": 101},
        ],
    )
    write_numeric_table(
        tmp_path,
        "c/jobs.dbf",
        (numeric_field("SITE", "I", 4), numeric_field("DEVICE", "N", 5)),
        [
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 2, "DEVICE": 101},
            {"SITE": 9, "DEVICE": 999},  # orphan
        ],
    )
    pk_rows = [record.values for record in read_numeric_records(tmp_path / "p/devices.dbf")]
    fk_rows = [record.values for record in read_numeric_records(tmp_path / "c/jobs.dbf")]
    pk_tuples = [(row["SITE"], row["DEVICE"]) for row in pk_rows]
    fk_tuples = [(row["SITE"], row["DEVICE"]) for row in fk_rows]
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
                    domain_id=numeric_key_domain_id(fingerprint, "rel-mixed"),
                )
            domain = numeric_key_domain_for(
                [integer_member(), integral_numeric_member(5)]
            )
            allocator = NumericKeyDomainMapping(
                vault,
                domain_id=numeric_key_domain_id(fingerprint, "rel-mixed"),
                domain=domain,
            )
            for value in sorted({v for pair in pk_tuples + fk_tuples for v in pair}):
                if value < 10:  # the SITE column originates from the I member
                    allocator.observe_original(value, member=integer_member())
                else:  # the DEVICE column originates from the N(5) member
                    allocator.observe_original(value, member=integral_numeric_member(5))
            allocator.finalize()
            before = _counts(pk_tuples, fk_tuples)
            pk_after = [tuple(allocator.pseudonym_for(v) for v in pair) for pair in pk_tuples]
            fk_after = [tuple(allocator.pseudonym_for(v) for v in pair) for pair in fk_tuples]
            after = _counts(pk_after, fk_after)
            report = verify_relationships(
                document, before={"rel-mixed": before}, after={"rel-mixed": after}
            )
            entry = report.relations[0]
            assert entry.status is VerificationStatus.VERIFIED
            assert entry.composite_arity == 2
            assert before.foreign.multiplicity_profile == (2, 1, 1)
            assert before.orphan_count == after.orphan_count == 1
            # The pseudonym tuples still fit the shared pseudonym domain.
            assert all(domain.contains_pseudonym(v) for pair in pk_after for v in pair)


# ---------------------------------------------------------------------------
# 8/9/10. orphan, matched-row and NULL-count preservation in detail
# ---------------------------------------------------------------------------
def test_orphan_matched_and_null_counts_preserved(tmp_path: Path) -> None:
    document, _fingerprint = _document(_numeric_document())
    report = _numeric_report(
        tmp_path, document, [-5, 0, 7], [7, 7, -5, 123456, None]
    )
    entry = report.relations[0]
    before = entry.before
    after = entry.after
    assert before is not None and after is not None
    assert before.orphan_count == after.orphan_count == 1
    assert before.matched_row_count == after.matched_row_count == 3
    assert before.foreign.null_tuple_count == after.foreign.null_tuple_count == 1
    assert before.parent.null_tuple_count == after.parent.null_tuple_count == 0
    invariants = {
        result.invariant: result.preserved for result in entry.invariants
    }
    assert invariants == {
        INVARIANT_PARENT_UNIQUENESS: True,
        INVARIANT_ORPHAN_COUNT: True,
        INVARIANT_MATCHED_ROWS: True,
        INVARIANT_NULL_COUNTS: True,
        INVARIANT_FOREIGN_MULTIPLICITY: True,
    }
    assert report.complete is True


# ---------------------------------------------------------------------------
# 11. duplicate parent key detected (BEFORE evidence shows it, never values)
# ---------------------------------------------------------------------------
def test_duplicate_parent_key_detected(tmp_path: Path) -> None:
    document, _fingerprint = _document(_numeric_document())
    report = _numeric_report(tmp_path, document, [7, 7, -5], [7, -5])
    before = report.relations[0].before
    after = report.relations[0].after
    assert before is not None and after is not None
    # The duplicate parent key is DETECTED by the evidence — counts only.
    assert before.parent.duplicate_row_count == 1
    assert before.parent.multiplicity_profile == (2, 1)
    assert after.parent.multiplicity_profile == (2, 1)
    assert report.complete is True


# ---------------------------------------------------------------------------
# 12/13/14. changed orphan / multiplicity / ordinal semantics FAIL
# ---------------------------------------------------------------------------
def test_changed_orphan_count_fails_verification(tmp_path: Path) -> None:
    document, fingerprint = _document(_numeric_document())
    report = _numeric_report(tmp_path, document, [-5, 7], [7, -5])
    entry = report.relations[0]
    before = entry.before
    assert before is not None
    # Corrupt AFTER evidence: one matched FK tuple becomes an orphan.
    broken = _counts([(-5,), (7,)], [(-5,), (999999,)])
    corrupt = verify_relationships(
        document, before={"rel-numeric-key": before}, after={"rel-numeric-key": broken}
    )
    assert corrupt.relations[0].status is VerificationStatus.FAILED
    results = {
        result.invariant: result.preserved
        for result in corrupt.relations[0].invariants
    }
    assert results[INVARIANT_ORPHAN_COUNT] is False
    assert results[INVARIANT_MATCHED_ROWS] is False
    assert results[INVARIANT_PARENT_UNIQUENESS] is True
    assert corrupt.complete is True  # the evidence itself was complete
    # The assurance derived from a failed relation is INCOMPLETE.
    summary = derive_relational_assurance(_metadata(fingerprint), corrupt)
    assert summary.level.value == "INCOMPLETE"


def test_changed_foreign_multiplicity_fails_verification() -> None:
    document, _fingerprint = _document(_numeric_document())
    before = _counts([(-5,), (7,)], [(7,), (7,), (7,), (-5,)])
    # A transform that collapses repeated FK values changes the profile.
    after = _counts([(-5,), (7,)], [(7,), (-5,)])
    corrupt = verify_relationships(
        document, before={"rel-numeric-key": before}, after={"rel-numeric-key": after}
    )
    results = {
        result.invariant: result.preserved
        for result in corrupt.relations[0].invariants
    }
    assert results[INVARIANT_FOREIGN_MULTIPLICITY] is False
    assert corrupt.relations[0].status is VerificationStatus.FAILED


def test_changed_composite_ordinal_semantics_fail() -> None:
    """Component order is significant: swapping FK components breaks joins."""
    document, _fingerprint = _document(
        {
            "metadata_schema_version": "1.0",
            "relations": [
                {
                    "relation_id": "rel-composite",
                    "provenance": PROVENANCE_POLICY_FILE,
                    "comparison": "EXACT_VALUE",
                    "members": [
                        {"table": "p/x.dbf", "field": "A", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                        {"table": "p/x.dbf", "field": "B", "role": "PRIMARY", "ordinal": 2, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                        {"table": "c/y.dbf", "field": "A", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                        {"table": "c/y.dbf", "field": "B", "role": "FOREIGN", "ordinal": 2, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                    ],
                }
            ],
        }
    )
    pk_tuples = [("A", "B"), ("C", "D")]
    fk_tuples = [("A", "B"), ("C", "D"), ("C", "B")]
    before = _counts(pk_tuples, fk_tuples)
    assert before.matched_row_count == 2
    assert before.orphan_count == 1
    # A transform that swaps the FK component order produces tuples that no
    # longer join the parent side: the ordinal semantics fail loudly.
    fk_after = [("B", "A"), ("D", "C"), ("B", "C")]
    after = _counts(pk_tuples, fk_after)
    corrupt = verify_relationships(
        document, before={"rel-composite": before}, after={"rel-composite": after}
    )
    results = {
        result.invariant: result.preserved
        for result in corrupt.relations[0].invariants
    }
    assert results[INVARIANT_MATCHED_ROWS] is False
    assert results[INVARIANT_ORPHAN_COUNT] is False
    assert corrupt.relations[0].status is VerificationStatus.FAILED


# ---------------------------------------------------------------------------
# 15. missing AFTER evidence => incomplete/fail-closed
# ---------------------------------------------------------------------------
def test_missing_after_evidence_is_incomplete() -> None:
    document, fingerprint = _document(_numeric_document())
    before = _counts([(-5,), (7,)], [(7,), (-5,)])
    report = verify_relationships(
        document, before={"rel-numeric-key": before}, after={}
    )
    entry = report.relations[0]
    assert entry.status is VerificationStatus.INCOMPLETE
    assert entry.before is not None and entry.after is None
    assert entry.invariants == ()
    assert report.complete is False
    # NOT a zero-count relation that would accidentally compare equal.
    assert entry.before.parent.rows_considered == 2
    summary = derive_relational_assurance(_metadata(fingerprint), report)
    assert summary.level.value == "INCOMPLETE"
    assert summary.verified_relation_count == 0
    assert summary.incomplete_relation_count == 1


def test_missing_relation_is_not_a_zero_count_relation() -> None:
    """A MISSING side can never accidentally compare equal to zero counts."""
    document, _fingerprint = _document(_numeric_document())
    empty = _counts([], [])
    incomplete = verify_relationships(
        document, before={"rel-numeric-key": empty}, after={}
    )
    assert incomplete.relations[0].status is VerificationStatus.INCOMPLETE
    # A fully-evaluated EMPTY relation (both sides supplied, zero rows) is a
    # legitimate VERIFIED zero-count relation — the two states differ.
    complete_empty = verify_relationships(
        document, before={"rel-numeric-key": empty}, after={"rel-numeric-key": empty}
    )
    assert complete_empty.relations[0].status is VerificationStatus.VERIFIED
    assert complete_empty.complete is True


# ---------------------------------------------------------------------------
# 16. evidence deterministic across runs and hash seeds
# ---------------------------------------------------------------------------
_DETERMINISM_PROBE = '''
import json, sys
sys.path.insert(0, "{src}")
from dbf_anonymizer.relationships import (
    parse_relationship_document,
    verify_relationships,
    RelationEvidenceCounts,
    RelationSideMetrics,
)

document = parse_relationship_document(json.load(sys.stdin))
side = RelationEvidenceCounts(
    composite_arity=1,
    parent=RelationSideMetrics(rows_considered=3, null_tuple_count=0, unique_tuple_count=2, duplicate_row_count=1, multiplicity_profile=(2, 1)),
    foreign=RelationSideMetrics(rows_considered=4, null_tuple_count=1, unique_tuple_count=2, duplicate_row_count=1, multiplicity_profile=(2, 1)),
    matched_row_count=2,
    orphan_count=1,
)
report = verify_relationships(document, before={{"rel-customer-key": side}}, after={{"rel-customer-key": side}})
print(json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")))
'''


def test_report_serialization_is_deterministic(tmp_path: Path) -> None:
    document, _fingerprint = _document(_text_document())
    before = _counts([("A",), ("B",), ("B",)], [("B",), ("B",), ("A",)])
    after = _counts([("X",), ("Y",), ("Y",)], [("Y",), ("Y",), ("X",)])
    first = verify_relationships(
        document, before={"rel-customer-key": before}, after={"rel-customer-key": after}
    )
    second = verify_relationships(
        document, before={"rel-customer-key": after}, after={"rel-customer-key": before}
    )
    assert first.to_dict() == second.to_dict()
    assert first.evidence_fingerprint == second.evidence_fingerprint
    # Subprocess evidence across two PYTHONHASHSEED values.
    src_root = Path(__file__).resolve().parents[1] / "src"
    script = tmp_path / "probe.py"
    script.write_text(_DETERMINISM_PROBE.format(src=src_root.as_posix()), encoding="utf-8")
    payload = json.dumps(_text_document())
    outputs = set()
    for hash_seed in ("0", "42"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = hash_seed
        completed = subprocess.run(
            [sys.executable, str(script)],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.add(completed.stdout.strip())
    assert len(outputs) == 1


def test_canonical_relation_ordering_is_declaration_order_independent() -> None:
    document, _fingerprint = _document(
        {
            "metadata_schema_version": "1.0",
            "relations": [
                {
                    "relation_id": "rel-b",
                    "provenance": PROVENANCE_POLICY_FILE,
                    "comparison": "EXACT_VALUE",
                    "members": [
                        {"table": "p/x.dbf", "field": "A", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                        {"table": "c/y.dbf", "field": "A", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                    ],
                },
                {
                    "relation_id": "rel-a",
                    "provenance": PROVENANCE_POLICY_FILE,
                    "comparison": "EXACT_VALUE",
                    "members": [
                        {"table": "p/x.dbf", "field": "B", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                        {"table": "c/y.dbf", "field": "B", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                    ],
                },
            ],
        }
    )
    evidence = _counts([("A",)], [("A",)])
    report = verify_relationships(
        document,
        before={"rel-b": evidence, "rel-a": evidence},
        after={"rel-a": evidence, "rel-b": evidence},
    )
    assert [entry.relation_id for entry in report.relations] == ["rel-a", "rel-b"]
    assert report.complete is True


# ---------------------------------------------------------------------------
# 17. actual key canaries absent from the report boundary
# ---------------------------------------------------------------------------
def test_report_boundary_never_leaks_key_values(tmp_path: Path) -> None:
    document, _fingerprint = _document(_numeric_document())
    report = _numeric_report(
        tmp_path, document, [-5, 7], [7, -5, 2147483646]
    )
    boundary = (
        str(report)
        + "|"
        + repr(report)
        + "|"
        + json.dumps(report.to_dict(), sort_keys=True)
    )
    assert str(CANARY_NUMERIC) not in boundary
    assert CANARY_TEXT not in boundary
    assert "-5" not in boundary and "987654321" not in boundary
    assert "C:\\" not in boundary and "vault" not in boundary.lower()


# ---------------------------------------------------------------------------
# fail-closed structural contract
# ---------------------------------------------------------------------------
def test_unknown_relation_evidence_fails_closed() -> None:
    document, _fingerprint = _document(_text_document())
    evidence = _counts([("A",)], [("A",)])
    with pytest.raises(VerificationError) as excinfo:
        verify_relationships(
            document,
            before={"rel-undeclared": evidence},
            after={"rel-undeclared": evidence},
        )
    assert "RELATIONSHIP_VERIFICATION_UNKNOWN_RELATION" in str(
        excinfo.value.to_dict()
    )


def test_arity_mismatch_between_sides_and_declaration_fails_closed() -> None:
    document, _fingerprint = _document(_text_document())
    evidence = _counts([("A",)], [("A",)])
    composite = _counts([("A", "B")], [("A", "B")])
    with pytest.raises(VerificationError) as declared:
        verify_relationships(
            document,
            before={"rel-customer-key": composite},
            after={"rel-customer-key": composite},
        )
    assert "RELATIONSHIP_VERIFICATION_ARITY_MISMATCH" in str(declared.value.to_dict())
    with pytest.raises(VerificationError) as sides:
        verify_relationships(
            document,
            before={"rel-customer-key": evidence},
            after={"rel-customer-key": composite},
        )
    assert "RELATIONSHIP_VERIFICATION_ARITY_MISMATCH" in str(sides.value.to_dict())
    with pytest.raises(VerificationError):
        compare_relation_metrics(evidence, composite)


def test_accumulator_fail_closed_inputs() -> None:
    accumulator = RelationshipEvidenceAccumulator(composite_arity=2)
    with pytest.raises(ValueError):
        accumulator.observe_parent(("A",))  # wrong arity
    with pytest.raises(ValueError):
        accumulator.observe_parent(("A", "B"), null=True)  # NULL key not empty
    with pytest.raises(TypeError):
        accumulator.observe_parent("AB")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RelationshipEvidenceAccumulator(composite_arity=0)
    null_accumulator = RelationshipEvidenceAccumulator(composite_arity=2)
    null_accumulator.observe_parent((), null=True)
    null_accumulator.observe_foreign((), null=True)
    counts = null_accumulator.build()
    assert counts.parent.rows_considered == counts.foreign.rows_considered == 1
    assert counts.parent.null_tuple_count == counts.foreign.null_tuple_count == 1
    assert counts.matched_row_count == counts.orphan_count == 0
    assert counts.parent.multiplicity_profile == ()
    # build() is a repeatable frozen snapshot (no consumption).
    assert counts == null_accumulator.build()


# ---------------------------------------------------------------------------
# deleted records: the same physical records the production pipeline gets
# ---------------------------------------------------------------------------
def test_deleted_key_rows_are_counted_and_preserved(tmp_path: Path) -> None:
    """Deleted key rows cannot silently disappear from the evidence model.

    The evidence counts every physical record the production pipeline
    transforms (active AND deleted); a deleted FK row referencing nothing is
    an orphan exactly like an active one.  The model counts rows and never
    deletion state — the deleted-record scope is reported truthfully by the
    rows/multiplicity equality, not by a deletion-state claim.
    """
    document, _fingerprint = _document(_numeric_document())
    write_numeric_table_with_deleted(
        tmp_path,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "I", 4),),
        [
            ({"CUST_ID": -5}, False),
            ({"CUST_ID": 7}, True),  # deleted parent (still transformed)
        ],
    )
    write_numeric_table_with_deleted(
        tmp_path,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "I", 4, flags=NULLABLE_FLAG),),
        [
            ({"CUST_ID": 7}, False),
            ({"CUST_ID": -5}, True),  # deleted matched FK
            ({"CUST_ID": 555}, True),  # deleted orphan FK
        ],
    )
    pk_rows = [record.values for record in read_numeric_records(tmp_path / "north/customers.dbf")]
    fk_rows = [record.values for record in read_numeric_records(tmp_path / "south/orders.dbf")]
    pk_values = [row["CUST_ID"] for row in pk_rows]
    fk_values = [row["CUST_ID"] for row in fk_rows]
    assert pk_values == [-5, 7] and fk_values == [7, -5, 555]
    report = _numeric_report(tmp_path, document, pk_values, fk_values)
    entry = report.relations[0]
    before = entry.before
    after = entry.after
    assert before is not None and after is not None
    # Deleted rows are IN the evidence: the parent side counts the deleted
    # parent row, the foreign side counts both deleted FK rows.
    assert before.parent.rows_considered == 2
    assert before.foreign.rows_considered == 3
    assert before.orphan_count == after.orphan_count == 1
    assert before.matched_row_count == after.matched_row_count == 2
    assert entry.status is VerificationStatus.VERIFIED
    assert report.complete is True


# ---------------------------------------------------------------------------
# shared kernel: the established relation_metrics uses the SAME semantics
# ---------------------------------------------------------------------------
def test_relation_metrics_and_accumulator_agree() -> None:
    primary = [("A",), ("B",), ("B",)]
    foreign = [("B",), ("B",), ("A",), ("Z",), ()]
    mask = [False, False, False, False, True]
    legacy = relation_metrics(primary, foreign, foreign_null_mask=mask)
    counts = _counts(primary, foreign, foreign_nulls=mask)
    assert legacy.primary_multiplicity_profile == counts.parent.multiplicity_profile
    assert legacy.foreign_multiplicity_profile == counts.foreign.multiplicity_profile
    assert legacy.matched_row_count == counts.matched_row_count
    assert legacy.orphan_count == counts.orphan_count
    assert legacy.key_null_count == counts.parent.null_tuple_count
    assert legacy.foreign_null_count == counts.foreign.null_tuple_count
    assert legacy.key_unique_count == counts.parent.unique_tuple_count
    assert legacy.max_duplicate_multiplicity == counts.parent.multiplicity_profile[0]
    # compare_relation_metrics is the ONE invariant rule (no second definition).
    same = _counts(
        [("X",), ("Y",), ("Y",)], [("Y",), ("Y",), ("X",), ("W",), ()],
        foreign_nulls=[False, False, False, False, True],
    )
    invariants = compare_relation_metrics(counts, same)
    assert [result.invariant for result in invariants] == list(RELATIONSHIP_INVARIANTS)
    assert all(result.preserved for result in invariants)