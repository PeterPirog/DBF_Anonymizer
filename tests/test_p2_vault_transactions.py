"""REQ-P2-003 — vault constraint/transaction consistency (foundation evidence).

Covers: real SQLite enforcement of both bijection directions per mapping
domain (text and numeric-key), independence of different domains, the
deterministic ``BEGIN IMMEDIATE`` transaction unit with proven before/after
rollback state, deterministic failure/crash injection at transaction-safe
seams, reopen-after-interruption integrity, the no-hidden-autocommit contract
and the authoritative writer lease that gates all ordinary mutations.

Mapping values are synthetic canaries; originals live ONLY inside the
protected vault and never appear in public errors.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dbf_anonymizer import ErrorCode, MappingError, VaultError
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    mappings,
)
from support.vault_sessions import error_boundary_payload, writer_session

SOURCE_FP = "src-" + "7" * 60
POLICY_FP = "pol-" + "8" * 60
RELATIONSHIP_FP = "rel-" + "9" * 60
DBFBRIDGE_VERSION = "1.1.0"

ORIGINAL_A = "CANARY_ORIGINAL_ALPHA"
ORIGINAL_B = "CANARY_ORIGINAL_BETA"
PSEUDONYM_A = "PSEUDO_ALPHA"
PSEUDONYM_B = "PSEUDO_BETA"


def _create(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version=DBFBRIDGE_VERSION,
    )


def _reopen(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


# ---------------------------------------------------------------------------
# Database-enforced bijection (independent of any future allocator)
# ---------------------------------------------------------------------------
def test_duplicate_original_with_conflicting_pseudonym_is_rejected(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            domain = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=22)
            # Same original -> conflicting pseudonym: UNIQUE(domain, original).
            with pytest.raises(MappingError) as excinfo:
                mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_B, logical_byte_length=10)
            assert excinfo.value.code is ErrorCode.MAPPING_CONFLICT
            assert excinfo.value.context.detail_code == "MAPPING_BIJECTION_REJECTED"
            # Duplicate pseudonym -> conflicting original: UNIQUE(domain, pseudonym).
            with pytest.raises(MappingError):
                mappings.add_text_mapping(vault, domain, ORIGINAL_B, PSEUDONYM_A, logical_byte_length=17)
            # The identical duplicate pair is likewise a database conflict.
            with pytest.raises(MappingError):
                mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=19)


def test_identical_pairs_in_different_domains_are_independent(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            domain_one = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            domain_two = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            mappings.add_text_mapping(vault, domain_one, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=22)
            # The same original in a DIFFERENT domain is a separate mapping.
            mappings.add_text_mapping(vault, domain_two, ORIGINAL_A, PSEUDONYM_B, logical_byte_length=22)
        vault.verify()
        assert mappings.get_text_pseudonym(vault, domain_one, ORIGINAL_A) == PSEUDONYM_A
        assert mappings.get_text_pseudonym(vault, domain_two, ORIGINAL_A) == PSEUDONYM_B


def test_numeric_key_bijection_is_bidirectionally_unique(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            domain = mappings.create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY
            )
            mappings.add_numeric_key_mapping(vault, domain, "101", "90001")
            mappings.add_numeric_key_mapping(vault, domain, "102", "90002")
            # Duplicate original (different pseudonym) -> rejected.
            with pytest.raises(MappingError):
                mappings.add_numeric_key_mapping(vault, domain, "101", "90002")
            # Duplicate pseudonym (different original) -> rejected.
            with pytest.raises(MappingError):
                mappings.add_numeric_key_mapping(vault, domain, "102", "90001")
        vault.verify()
        assert mappings.numeric_mapping_rows(vault, domain) == (
            ("101", "90001"),
            ("102", "90002"),
        )


def test_reverse_lookup_roundtrip_is_exact(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            domain = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=22)
        assert mappings.get_text_pseudonym(vault, domain, ORIGINAL_A) == PSEUDONYM_A
        assert mappings.get_text_original(vault, domain, PSEUDONYM_A) == ORIGINAL_A
        assert mappings.get_text_pseudonym(vault, domain, "absent") is None
        assert mappings.get_text_original(vault, domain, "absent") is None


def test_memo_and_temporal_rows_are_stored_in_the_protected_zone(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            table_id = vault.register_table("memo/table.dbf", schema_fingerprint="fp-memo")
            domain = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            field_id = vault.register_field(
                table_id, "NOTES", dbf_type="M", width=10, mapping_domain_id=domain
            )
            mappings.add_memo_recovery(
                vault, table_id, 3, field_id, "CANARY_MEMO_PAYLOAD",
                payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
            )
            temporal = mappings.create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT
            )
            mappings.set_temporal_parameter(vault, temporal, offset_days=-7)
        vault.verify()
        rows = mappings.memo_recovery_rows(vault, table_id)
        assert len(rows) == 1
        assert rows[0]["physical_record_index"] == 3
        assert rows[0]["payload_kind"] == "TEXT"
        assert mappings.temporal_parameter(vault, temporal) == -7
        # Duplicated memo identity is refused.
        with pytest.raises(VaultError):
            with writer_session(vault), vault.transaction():
                mappings.add_memo_recovery(
                    vault, table_id, 3, field_id, "again",
                    payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
                )


# ---------------------------------------------------------------------------
# Deterministic transaction boundary / crash injection
# ---------------------------------------------------------------------------
def test_transaction_rollback_leaves_no_partial_rows(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        # BEFORE: the domain/mapping state is empty.
        assert mappings.mapping_domains(vault) == ()
        with pytest.raises(ValueError):
            with writer_session(vault), vault.transaction():
                domain = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
                mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=22)
                # Dependent second insert fails mid-transaction (duplicate
                # original in the same domain) -> the WHOLE unit must roll back.
                with pytest.raises(MappingError):
                    mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_B, logical_byte_length=10)
                raise ValueError("injected failure before commit")
        # AFTER the rollback: no domain, no mapping row (proven, not implied).
        assert mappings.mapping_domains(vault) == ()
        assert vault.connection.execute("SELECT COUNT(*) FROM text_mappings").fetchone()[0] == 0
        vault.verify()

    with _reopen(tmp_path) as reopened:
        assert reopened.verify() is None
        assert mappings.mapping_domains(reopened) == ()
        assert mappings.text_mapping_rows(reopened, "dom-none") == ()


def test_failure_after_dependent_inserts_rolls_back_everything(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with pytest.raises(RuntimeError):
            with writer_session(vault), vault.transaction():
                table_id = vault.register_table("orders/data.dbf", schema_fingerprint="fp-x")
                domain = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
                field_id = vault.register_field(
                    table_id, "NAME", dbf_type="C", width=10, mapping_domain_id=domain
                )
                mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=22)
                assert mappings.get_text_pseudonym(vault, domain, ORIGINAL_A) == PSEUDONYM_A
                raise RuntimeError("crash injection between inserts and commit")
        # Uncommitted dependent inserts are all gone.
        assert vault.tables() == ()
        assert mappings.mapping_domains(vault) == ()
        assert vault.connection.execute("SELECT COUNT(*) FROM fields").fetchone()[0] == 0

    # Reopening after the simulated interruption passes integrity and shows
    # only committed state.
    with _reopen(tmp_path) as reopened:
        reopened.verify(full=True)
        assert reopened.tables() == ()
        assert reopened.operations() == ()


def test_committed_transaction_survives_reopen(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            domain = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=22)
    with _reopen(tmp_path) as reopened:
        reopened.verify(full=True)
        assert mappings.text_mapping_rows(reopened, domain) == ((ORIGINAL_A, PSEUDONYM_A, 22),)


def test_multi_step_mutation_cannot_autocommit_outside_a_transaction(
    tmp_path: Path,
) -> None:
    # No hidden autocommit: vault mutations require the explicit AUTHORIZED
    # transaction unit; calling them outside one (or without the lease) is a
    # refused programmer/caller error and writes nothing.
    with _create(tmp_path) as vault:
        with pytest.raises(ValueError, match="requires an active"):
            vault.begin_operation()
        with pytest.raises(ValueError, match="requires an active"):
            mappings.add_text_mapping(vault, "dom-x", "o", "p", logical_byte_length=1)
        # Nothing was written by the refused calls.
        assert vault.tables() == ()
        assert mappings.mapping_domains(vault) == ()


def test_mutation_transaction_without_lease_is_rejected_first(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with pytest.raises(VaultError) as excinfo:
            with vault.transaction():
                mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert excinfo.value.context.detail_code == "WRITER_LEASE_REQUIRED"
        assert mappings.mapping_domains(vault) == ()


def test_nested_transaction_use_is_refused(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            with pytest.raises(ValueError):
                with vault.transaction():
                    pass


def test_failed_mutation_never_exposes_mapping_values(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            domain = mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_A, logical_byte_length=22)
            with pytest.raises(MappingError) as excinfo:
                mappings.add_text_mapping(vault, domain, ORIGINAL_A, PSEUDONYM_B, logical_byte_length=10)
            error = excinfo.value
            blob = error_boundary_payload(error)
            assert ORIGINAL_A not in blob
            assert ORIGINAL_B not in blob
            assert PSEUDONYM_A not in blob
            assert PSEUDONYM_B not in blob
            assert "UNIQUE" not in blob
