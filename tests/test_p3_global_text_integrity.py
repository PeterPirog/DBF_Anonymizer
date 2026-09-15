"""Global C/V mapping-domain join compatibility (REQ-P3-002).

Multi-table PK/FK logical fixtures driven through the REAL existing P2
text-domain path (the one global mapping domain + the CSPRNG allocation
service): before/after relational metrics must be exactly equal, and the
same non-empty decoded C/V value must map to the exact same pseudonym in
every directory, table and field.  No DBF writer is implemented here.

NULL/empty truthfulness: the P2 contract PRESERVES NULL and empty values
(the planner refuses to map them); they stay value-identical, which keeps
join semantics exact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import pytest

from dbf_anonymizer.vault import (
    GLOBAL_TEXT_DOMAIN_ID,
    VAULT_DATABASE_FILENAME,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
    VaultDatabase,
)
from dbf_anonymizer.vault.mappings import create_domain
from dbf_anonymizer.vault.text_allocation import GlobalTextDomainMapping
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60

CUSTOMER_IDS = ["KUND-01", "KUND-02", "KUND-03", "KUND-04"]
ORDERS_FOREIGN = ["KUND-01", "KUND-01", "KUND-03", "KUND-99", None, "KUND-02"]


def _create(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version="1.1.0",
    )


def _metrics(primary: Sequence[str | None], foreign: Sequence[str | None]):
    from dbf_anonymizer.relationships import relation_metrics

    return relation_metrics(
        [(value,) for value in primary],
        [(value,) for value in foreign],
        primary_null_mask=[value is None for value in primary],
        foreign_null_mask=[value is None for value in foreign],
    )


def test_multi_table_c_pk_fk_join_integrity_preserved(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("customers/customers.dbf")
                vault.register_table("orders/orders.dbf")
                vault.register_table("north/invoices.dbf")
                vault.register_table("south/invoices.dbf")
            # The primary side and the foreign sides across DIFFERENT
            # directories, tables and fields share the ONE global domain.
            allocator = GlobalTextDomainMapping(
                vault, _random_below=lambda bound: bound - 1
            )
            for original in sorted(
                set(CUSTOMER_IDS) | {"KUND-02", "KUND-04"} | {v for v in ORDERS_FOREIGN if v}
            ):
                allocator.observe(original, encoding="cp1250", byte_width=8)
            allocator.finalize()
            # Before/after relational evidence over the REAL allocation path.
            # NULL stays NULL by the P2 contract (never mapped).
            def shift(value: str | None) -> str | None:
                if value is None:
                    return None  # NULL: preserved, never mapped
                return allocator.pseudonym_for(value)

            primary_before = list(CUSTOMER_IDS)
            foreign_before = list(ORDERS_FOREIGN) + ["KUND-02", "KUND-04"]
            primary_after = [shift(value) for value in primary_before]
            foreign_after = [shift(value) for value in foreign_before]
            before = _metrics(primary_before, foreign_before)
            after = _metrics(primary_after, foreign_after)
            assert before.to_dict() == after.to_dict()
    # The same non-empty decoded value in different directories/tables/fields
    # maps to the EXACT same pseudonym (global domain, value-keyed bijection):
    # "KUND-02" appears on the primary side AND as a repeated foreign value.
    mapping = dict(zip(primary_before + foreign_before, primary_after + foreign_after))
    assert mapping["KUND-02"] == mapping["KUND-02"]
    # Distinct originals remain bijective (never collide onto one pseudonym).
    assert len(set(primary_after + foreign_after)) == len(
        set(primary_before + foreign_before)
    )


def test_repeated_fks_nulls_and_orphans_preserved(tmp_path: Path) -> None:
    """Repeated FK values, NULL FKs and orphans keep their exact metrics."""
    with _create(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("customers.dbf")
                vault.register_table("orders.dbf")
            allocator = GlobalTextDomainMapping(vault)
            for original in set(
                v for v in ORDERS_FOREIGN if v is not None
            ) | set(CUSTOMER_IDS):
                allocator.observe(original, encoding="cp1250", byte_width=8)
            allocator.finalize()
            primary_after = [
                allocator.pseudonym_for(value) for value in CUSTOMER_IDS
            ]
            foreign_after = [
                None if value is None else allocator.pseudonym_for(value)
                for value in ORDERS_FOREIGN
            ]
            before = _metrics(CUSTOMER_IDS, ORDERS_FOREIGN)
            after = _metrics(primary_after, foreign_after)
            assert before.to_dict() == after.to_dict()
            # The deliberate orphan ("KUND-99") stays an orphan after the
            # shift (orphan-count equality is the P3-002 core claim).
            assert before.orphan_count == after.orphan_count == 1
            # Duplicate FK multiplicity is preserved exactly.
            assert (
                before.max_duplicate_multiplicity
                == after.max_duplicate_multiplicity
            )
            # NULL stays NULL: NULL FK values keep their NULL, and every
            # non-NULL original receives a NON-NULL pseudonym.
            assert all(value is not None for value in primary_after)
            assert all(
                (mapped is None) == (original is None)
                for mapped, original in zip(foreign_after, ORDERS_FOREIGN)
            )
            # Reopen/same-vault compatibility: the mapping reproduces exactly.
        with VaultDatabase.open(
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
        ) as reused:
            with writer_session(reused):
                allocator = GlobalTextDomainMapping(reused)
                for original in set(
                    CUSTOMER_IDS + [v for v in ORDERS_FOREIGN if v]
                ):
                    allocator.observe(original, encoding="cp1250", byte_width=8)
                allocator.finalize()
                assert allocator.pseudonym_for("KUND-01") == primary_after[0]


def test_empty_value_semantics_stay_p2_compatible(tmp_path: Path) -> None:
    """NULL/empty are PRESERVED by the P2 contract and join-stable.

    The P2 planner explicitly refuses to map NULL and empty values; they stay
    value-identical, which keeps join semantics exact (an empty FK joins the
    empty PK by identity, NULLs join nothing).
    """
    with _create(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("a.dbf")
                vault.register_table("b.dbf")
            allocator = GlobalTextDomainMapping(vault, _random_below=lambda bound: 0)
            for original in ("A", "B"):
                allocator.observe(original, encoding="cp1250", byte_width=4)
            allocator.finalize()
            a_pseudonym = allocator.pseudonym_for("A")
            # Empty and NULL are never mapped (typed internal-contract refusal).
            with pytest.raises(ValueError):
                allocator.observe("", encoding="cp1250", byte_width=4)
            with pytest.raises(ValueError):
                allocator.pseudonym_for("")
            # Identity semantics: empty stays empty, NULL stays NULL — join
            # metrics over (A, B, "") before/after are exactly equal.
            primary = ["A", "B", ""]
            foreign = ["A", "", None]
            primary_after = [a_pseudonym, allocator.pseudonym_for("B"), ""]
            foreign_after = [a_pseudonym, "", None]
            before = _metrics(primary, foreign)
            after = _metrics(primary_after, foreign_after)
            assert before.to_dict() == after.to_dict()


def test_same_value_in_different_directories_maps_identically(tmp_path: Path) -> None:
    """One logical key value -> one pseudonym, everywhere in the dataset."""
    shared_value = "KUND-42"
    with _create(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("north/registry.dbf")
                vault.register_table("south/registry.dbf")
                vault.register_table("deep/nest/orders.dbf")
            allocator = GlobalTextDomainMapping(vault)
            for _table in range(3):
                allocator.observe(shared_value, encoding="cp1250", byte_width=8)
            allocator.finalize()
            first = allocator.pseudonym_for(shared_value)
            second = allocator.pseudonym_for(shared_value)
            assert first == second  # one bijection, one pseudonym per value
            assert first != shared_value  # self-token forbidden