"""REQ-P2-001 — one authoritative dataset vault (foundation evidence).

Covers: exactly one dictionary for a synthetic multi-directory/multi-table
dataset, stable vault identity and stored operation IDs across reopen,
dataset-wide table/field/mapping identity, absence of table-local SQLite
databases, the authoritative writer lease gating ALL ordinary mutations,
explicit WAL journal lifecycle with clean-close sidecar removal, and the
source/output side-effect discipline of the vault subsystem itself.

Synthetic data only; the vault and the source live in separate directories.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from dbf_anonymizer import ErrorCode, VaultError
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VAULT_SCHEMA_VERSION,
    VaultDatabase,
    default_dictionary_path,
    mappings,
    new_writer_token,
)
from support.vault_sessions import (
    error_boundary_payload,
    sidecar_inventory,
    writer_session,
)

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60
DBFBRIDGE_VERSION = "1.1.0"

CANARY = "CANARY_ORIGINAL_VALUE"


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


def _sqlite_files(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".sqlite", ".sqlite3"}
    )


def _tree_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            snapshot[path.relative_to(root).as_posix()] = path.read_bytes().hex()
    return snapshot


# ---------------------------------------------------------------------------
# One dataset -> one authoritative dictionary
# ---------------------------------------------------------------------------
def test_multi_directory_multi_table_dataset_uses_one_dictionary(
    tmp_path: Path,
) -> None:
    # Synthetic multi-directory/multi-table dataset identity: duplicate
    # basenames in different source directories MUST stay one dictionary.
    source = tmp_path / "src"
    (source / "north" / "registry").mkdir(parents=True)
    (source / "south" / "registry").mkdir(parents=True)
    (source / "north" / "registry" / "orders.dbf").write_bytes(b"synthetic")
    (source / "south" / "registry" / "orders.dbf").write_bytes(b"placeholder")

    with _create(tmp_path) as vault:
        vault_id = vault.vault_id
        with writer_session(vault), vault.transaction():
            table_ids = [
                vault.register_table("north/registry/orders.dbf", schema_fingerprint="fp-north"),
                vault.register_table("south/registry/orders.dbf", schema_fingerprint="fp-south"),
                vault.register_table("west/inventory.dbf", schema_fingerprint="fp-west"),
            ]
            operation_id = vault.begin_operation()
            assert len(set(table_ids)) == 3
            for table_id in table_ids:
                domain = mappings.create_domain(
                    vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT
                )
                field_id = vault.register_field(
                    table_id,
                    "NAME",
                    dbf_type="C",
                    width=20,
                    transform_action="PSEUDONYMIZE_REVERSIBLE",
                    mapping_domain_id=domain,
                )
                mappings.add_text_mapping(
                    vault, domain, f"CANARY_VALUE_{table_id}", f"PSEUDO_{table_id}",
                    logical_byte_length=16,
                )
                mappings.add_memo_recovery(
                    vault, table_id, 0, field_id, "CANARY_MEMO_PAYLOAD",
                    payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
                )
            vault.complete_operation(operation_id, output_fingerprint="out-" + "f" * 32)
        vault.verify(full=True)

    # One authoritative dictionary; NO per-table or stray SQLite copies.
    with _reopen(tmp_path) as reopened:
        assert reopened.vault_id == vault_id
        registered = reopened.tables()
        assert [entry["relative_path"] for entry in registered] == [
            "north/registry/orders.dbf",
            "south/registry/orders.dbf",
            "west/inventory.dbf",
        ]
        assert len({entry["table_id"] for entry in registered}) == 3
        stored = reopened.operations()
        assert len(stored) == 1
        assert stored[0]["state"] == "COMPLETED"
        assert stored[0]["operation_id"] == operation_id
        # Every registered table/field/mapping belongs to the SAME vault.
        assert all(
            entry["table_id"] in {t["table_id"] for t in registered}
            for entry in reopened.tables()
        )

    files = _sqlite_files(tmp_path)
    assert files == [f"vault/{VAULT_DATABASE_FILENAME}"], files


def test_duplicate_basenames_share_the_dataset_vault(tmp_path: Path) -> None:
    # Two source directories carrying the same basename map into the same
    # dictionary with distinct stable table identities; re-registering the
    # same relative path is refused by the database constraint.
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            first = vault.register_table("a/data.dbf")
            second = vault.register_table("b/data.dbf")
        assert first != second
        with pytest.raises(VaultError):
            with writer_session(vault), vault.transaction():
                vault.register_table("a/data.dbf")


def test_default_dictionary_path_is_the_single_database_file() -> None:
    assert default_dictionary_path(Path("protected")) == Path("protected") / VAULT_DATABASE_FILENAME
    assert VAULT_DATABASE_FILENAME == "dictionary.sqlite3"
    assert VAULT_SCHEMA_VERSION == "1.0"


def test_operation_ids_are_stable_stored_and_bounded(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            first = vault.begin_operation(source_fingerprint=SOURCE_FP)
            second = vault.begin_operation()
            vault.complete_operation(first)
    with _reopen(tmp_path) as reopened:
        stored = reopened.operations()
        assert len(stored) == 2
        by_id = {entry["operation_id"]: entry for entry in stored}
        assert set(by_id) == {first, second}
        assert by_id[first]["state"] == "COMPLETED"
        assert by_id[second]["state"] == "STARTED"
        assert by_id[first]["source_fingerprint"] == SOURCE_FP
        for entry in stored:
            identifier = entry["operation_id"]
            assert isinstance(identifier, str) and identifier.startswith("vop-")
            assert len(identifier) <= 64


def test_completed_operation_cannot_be_completed_twice(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            operation_id = vault.begin_operation()
            vault.complete_operation(operation_id)
            with pytest.raises(VaultError):
                vault.complete_operation(operation_id)
        stored = vault.operations()
        assert len(stored) == 1 and stored[0]["state"] == "COMPLETED"


def test_publication_rows_bind_to_persisted_operations(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            operation_id = vault.begin_operation()
            vault.record_publication(operation_id, "PUBLISH", output_fingerprint="out-" + "0" * 16)
        with pytest.raises(VaultError):
            with writer_session(vault), vault.transaction():
                vault.record_publication("vop-absent", "PUBLISH")
    with _reopen(tmp_path) as reopened:
        publication = reopened.connection.execute(
            "SELECT operation_id, phase, output_fingerprint FROM publication"
        ).fetchone()
        assert tuple(publication) == (operation_id, "PUBLISH", "out-" + "0" * 16)


# ---------------------------------------------------------------------------
# Authoritative writer lease gates EVERY ordinary mutation (REQ-P2-003)
# ---------------------------------------------------------------------------
def test_no_lease_mutation_transaction_is_rejected_before_mutation(
    tmp_path: Path,
) -> None:
    with _create(tmp_path) as vault:
        # No lease: the ordinary transaction entry is refused BEFORE any
        # database access, so nothing can be mutated.
        with pytest.raises(VaultError) as excinfo:
            with vault.transaction():
                vault.begin_operation()
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert excinfo.value.context.detail_code == "WRITER_LEASE_REQUIRED"
        assert vault.stale_writer_lease() is None
        assert vault.operations() == ()
        assert vault.tables() == ()
    with _reopen(tmp_path) as reopened:
        assert reopened.operations() == ()
        assert reopened.tables() == ()


def test_lease_holder_can_perform_every_mutation_class(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            table_id = vault.register_table("data/table.dbf", schema_fingerprint="fp")
            domain_text = mappings.create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT
            )
            domain_numeric = mappings.create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY
            )
            field_id = vault.register_field(
                table_id, "NAME", dbf_type="C", width=10,
                mapping_domain_id=domain_text,
            )
            mappings.add_text_mapping(
                vault, domain_text, "CANARY_ORIGINAL", "PSEUDO_1",
                logical_byte_length=14,
            )
            mappings.add_numeric_key_mapping(vault, domain_numeric, "42", "90042")
            mappings.add_memo_recovery(
                vault, table_id, 0, field_id, "CANARY_MEMO",
                payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
            )
            mappings.set_temporal_parameter(vault, domain_text, offset_days=-5)
            operation_id = vault.begin_operation()
            vault.complete_operation(operation_id)
            vault.record_publication(operation_id, "PUBLISH")
        assert vault.stale_writer_lease() is None  # released cleanly
    with _reopen(tmp_path) as reopened:
        assert len(reopened.tables()) == 1
        assert len(reopened.operations()) == 1
        assert len(mappings.mapping_domains(reopened)) == 2
        assert len(mappings.memo_recovery_rows(reopened, table_id)) == 1
        assert mappings.temporal_parameter(reopened, domain_text) == -5
        publication = reopened.connection.execute(
            "SELECT phase FROM publication"
        ).fetchone()
        assert tuple(publication) == ("PUBLISH",)


def test_second_connection_cannot_mutate_while_lease_is_held(
    tmp_path: Path,
) -> None:
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    with _create(tmp_path) as creator:
        with writer_session(creator), creator.transaction():
            creator.begin_operation()
    holder = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    non_holder = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    try:
        holder.acquire_writer_lease(new_writer_token())
        # Even with SQLite's physical write lock free, the non-holder has no
        # durable authority and cannot mutate.
        operations_before = len(non_holder.operations())
        assert operations_before == 1  # committed by the creator setup
        with pytest.raises(VaultError) as excinfo:
            with non_holder.transaction():
                non_holder.begin_operation()
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert excinfo.value.context.detail_code == "WRITER_LEASE_REQUIRED"
        # The rejected attempt added nothing.
        assert len(non_holder.operations()) == operations_before
    finally:
        holder.close()
        non_holder.close()


def test_authority_handoff_after_release(tmp_path: Path) -> None:
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    with _create(tmp_path) as creator:
        with writer_session(creator), creator.transaction():
            creator.begin_operation()
    first = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    second = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    try:
        token = new_writer_token()
        first.acquire_writer_lease(token)
        with pytest.raises(VaultError):
            with second.transaction():
                second.begin_operation()
        first.release_writer_lease(token)
        # After the release the second connection can acquire and mutate.
        with writer_session(second), second.transaction():
            second.begin_operation()
        # Both connections see the same durable dataset state (creator's row
        # plus the second connection's new row).
        assert len(first.operations()) == 2
        assert len(second.operations()) == 2
    finally:
        first.close()
        second.close()


def test_lease_holder_loses_authority_after_a_takeover(tmp_path: Path) -> None:
    # The durable authority, not the in-memory binding, decides: after the
    # lease is transferred away, the former holder cannot mutate.
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    with _create(tmp_path) as creator:
        with writer_session(creator), creator.transaction():
            creator.begin_operation()
    holder = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    successor = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    try:
        stale_token = new_writer_token()
        holder.acquire_writer_lease(stale_token)
        # Explicit reclaim path: name the stored stale token, then take over.
        successor.release_writer_lease(stale_token)
        successor.acquire_writer_lease(new_writer_token())
        with pytest.raises(VaultError) as excinfo:
            with holder.transaction():
                holder.begin_operation()
        assert excinfo.value.context.detail_code == "WRITER_LEASE_REQUIRED"
    finally:
        holder.close()
        successor.close()


# ---------------------------------------------------------------------------
# Journal lifecycle (explicit WAL policy)
# ---------------------------------------------------------------------------
def test_journal_lifecycle_is_explicit_wal_with_clean_close_sidecar_removal(
    tmp_path: Path,
) -> None:
    vault_dir = tmp_path / "vault"
    holder_token = new_writer_token()
    with _create(tmp_path) as vault:
        assert vault.journal_mode() == "wal"
        # While the connection is open the WAL sidecars are internal SQLite
        # lifecycle state; they never persist after the clean close.
        with writer_session(vault), vault.transaction():
            vault.begin_operation()
        vault.acquire_writer_lease(holder_token)
        with pytest.raises(VaultError) as excinfo:
            vault.acquire_writer_lease(new_writer_token())
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        vault.release_writer_lease(holder_token)
        vault.close()
        # Idempotent close.
        vault.close()
    assert (vault_dir / VAULT_DATABASE_FILENAME).is_file()
    assert sidecar_inventory(vault_dir) == []

    # A competing writer's failed acquire must not break the clean close.
    with _reopen(tmp_path) as reopened:
        assert reopened.journal_mode() == "wal"


def test_sidecars_never_persist_after_crash_rollback_and_close(tmp_path: Path) -> None:
    vault_dir = tmp_path / "vault"
    with _create(tmp_path) as vault:
        with pytest.raises(ValueError):
            with writer_session(vault), vault.transaction():
                mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
                raise ValueError("simulated interruption")
        # The lease was released by the session helper; the interrupted
        # transaction was rolled back and the close was clean.
        assert vault.stale_writer_lease() is None
    assert sidecar_inventory(vault_dir) == []
    with _reopen(tmp_path) as reopened:
        assert mappings.mapping_domains(reopened) == ()
        reopened.verify()


# ---------------------------------------------------------------------------
# Vault-zone side-effect discipline
# ---------------------------------------------------------------------------
def test_vault_creation_touches_only_its_own_zone(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "t").mkdir(parents=True)
    (source / "t" / "table.dbf").write_bytes(b"synthetic")
    output = tmp_path / "output"
    before = _tree_snapshot(tmp_path)

    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            vault.register_table("t/table.dbf", schema_fingerprint="fp-table")

    after = _tree_snapshot(tmp_path)
    # Only the dictionary (inside tmp_path/vault) appeared; source/output
    # trees are untouched.
    added = set(after) - set(before)
    assert added == {f"vault/{VAULT_DATABASE_FILENAME}"}
    assert not output.exists()
    source_after = {key: value for key, value in after.items() if key.startswith("source/")}
    assert source_after == {key: value for key, value in before.items() if key.startswith("source/")}


def test_real_writer_conflict_stays_privacy_safe(tmp_path: Path) -> None:
    # REQ-P2-003 conflict evidence with REAL contention: connection A holds
    # the authority, connection B's acquire is rejected; the resulting typed
    # error must not leak the holder token, the attempted canary token,
    # private paths or raw SQLite text.
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    with _create(tmp_path) as creator:
        with writer_session(creator), creator.transaction():
            creator.begin_operation()
    holder_token = new_writer_token()
    canary_token = "wauth-" + "d" * 32
    holder = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    competitor = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    try:
        holder.acquire_writer_lease(holder_token)
        with pytest.raises(VaultError) as excinfo:
            competitor.acquire_writer_lease(canary_token)
        error = excinfo.value
        assert error.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert error.context.detail_code == "WRITER_LEASE_HELD"
        payload = error_boundary_payload(error)
        assert canary_token not in payload
        assert holder_token not in payload
        assert str(tmp_path) not in payload
        assert "database is locked" not in payload
    finally:
        holder.close()
        competitor.close()


def test_vault_id_and_operation_ids_are_not_source_derived(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        identifier = vault.vault_id
        with writer_session(vault), vault.transaction():
            operation_id = vault.begin_operation()
    assert SOURCE_FP not in identifier
    assert POLICY_FP not in operation_id
    assert POLICY_FP not in identifier
    assert "vault" == identifier[:5]
    assert identifier != f"vault{SOURCE_FP}"
