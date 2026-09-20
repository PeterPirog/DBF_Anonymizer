"""REQ-P2-002 — explicit versioned SQLite vault schema (foundation evidence).

Covers: schema-version snapshot, table/index/FK/constraint snapshot, the
composite memo table/field identity, exact supported-version reopen,
unsupported-version fail-closed, dataset identity binding (source/policy/
relationship fingerprints), the NON-MUTATING two-stage open of existing
vaults, journal-mode verification, integrity boundary, deliberate corruption
fail-closed, real foreign-key enforcement, fail-closed raw path probing and
the static purity of the committed package tree.

Synthetic data only; no production data. The vault files live exclusively in
``tmp_path`` (the protected zone), never inside source fixtures or public
output trees.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from dbf_anonymizer import ErrorCode, MappingError, VaultError
from dbf_anonymizer.vault import (
    DDL_STATEMENTS,
    EXPECTED_VAULT_TABLES,
    EXPECTED_VAULT_UNIQUE_INDEXES,
    VAULT_DATABASE_FILENAME,
    VAULT_ID_PREFIX,
    VAULT_SCHEMA_VERSION,
    VaultDatabase,
    mappings,
)
from support.vault_sessions import (
    FailingExecuteConnection,
    error_boundary_payload,
    file_sha256,
    sidecar_inventory,
    writer_session,
)

SOURCE_FP = "src-" + "a" * 60
POLICY_FP = "pol-" + "b" * 60
RELATIONSHIP_FP = "rel-" + "c" * 60
DBFBRIDGE_VERSION = "1.1.0"


def _open_create(tmp_path: Path, name: str = "vault") -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / name / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version=DBFBRIDGE_VERSION,
    )


def _reopen(tmp_path: Path, name: str = "vault", **kwargs: str) -> VaultDatabase:
    return VaultDatabase.open(tmp_path / name / VAULT_DATABASE_FILENAME, **kwargs)  # type: ignore[arg-type]


def _dictionary(tmp_path: Path, name: str = "vault") -> Path:
    return tmp_path / name / VAULT_DATABASE_FILENAME


@contextmanager
def _raw_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    """Open a RAW sqlite3 probe connection that is explicitly CLOSED.

    The sqlite3 connection context manager commits/rolls back transactions;
    it does NOT close the connection. Foreign-database probes must own their
    closure so no test-side ``ResourceWarning`` (unclosed database) can leak
    out of the vault evidence suite.
    """
    connection = sqlite3.connect(str(path))
    try:
        yield connection
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Frozen schema 1.1 snapshot (REQ-P2-002/P4-009): explicit expectation
# ---------------------------------------------------------------------------
#: Column tuple: (name, declared_type, notnull, default, pk_position).
#: FK entry: (parent_table, ((child_column, parent_column), ...)) in declared
#: FK order. Index entry: (name, unique, origin, (columns...)) sorted by name.
#: This expectation is written BY HAND — it is NOT generated from the DDL
#: under test, so any silent column removal/rename/reorder/nullability/PK/FK/
#: UNIQUE change fails this snapshot.
EXPECTED_SCHEMA_SNAPSHOT: dict[str, dict[str, object]] = {
    "meta": {
        "columns": (
            ("singleton", "INTEGER", 0, None, 1),
            ("schema_version", "TEXT", 1, None, 0),
            ("vault_id", "TEXT", 1, None, 0),
            ("created_at", "TEXT", 1, None, 0),
            ("package_version", "TEXT", 1, None, 0),
            ("dbfbridge_version", "TEXT", 1, None, 0),
        ),
        "foreign_keys": (),
        "indexes": (),
    },
    "dataset": {
        "columns": (
            ("singleton", "INTEGER", 0, None, 1),
            ("source_fingerprint", "TEXT", 1, None, 0),
            ("policy_fingerprint", "TEXT", 1, None, 0),
            ("relationship_fingerprint", "TEXT", 1, None, 0),
        ),
        "foreign_keys": (),
        "indexes": (),
    },
    "writer_authority": {
        "columns": (
            ("singleton", "INTEGER", 0, None, 1),
            ("owner_token", "TEXT", 0, None, 0),
            ("acquire_tick", "INTEGER", 1, "0", 0),
        ),
        "foreign_keys": (),
        "indexes": (),
    },
    "operations": {
        "columns": (
            ("operation_id", "TEXT", 0, None, 1),
            ("state", "TEXT", 1, None, 0),
            ("source_fingerprint", "TEXT", 0, None, 0),
            ("policy_fingerprint", "TEXT", 0, None, 0),
            ("relationship_fingerprint", "TEXT", 0, None, 0),
            ("vault_fingerprint", "TEXT", 0, None, 0),
            ("destination_identity", "TEXT", 0, None, 0),
            ("binding_fingerprint", "TEXT", 0, None, 0),
            ("output_fingerprint", "TEXT", 0, None, 0),
            ("result_json", "TEXT", 0, None, 0),
            ("started_at", "TEXT", 0, None, 0),
            ("completed_at", "TEXT", 0, None, 0),
        ),
        "foreign_keys": (),
        "indexes": (
            ("sqlite_autoindex_operations_1", 1, "pk", ("operation_id",)),
            ("uq_operations_destination", 1, "c", ("destination_identity",)),
        ),
    },
    "publication": {
        "columns": (
            ("operation_id", "TEXT", 1, None, 1),
            ("phase", "TEXT", 1, None, 2),
            ("output_fingerprint", "TEXT", 0, None, 0),
            ("vault_fingerprint", "TEXT", 0, None, 0),
        ),
        "foreign_keys": (
            ("operations", (("operation_id", "operation_id"),)),
        ),
        "indexes": (
            ("sqlite_autoindex_publication_1", 1, "pk", ("operation_id", "phase")),
        ),
    },
    "mapping_domains": {
        "columns": (
            ("domain_id", "TEXT", 0, None, 1),
            ("domain_kind", "TEXT", 1, None, 0),
            ("normalization", "TEXT", 0, None, 0),
            ("relational_role", "TEXT", 0, None, 0),
        ),
        "foreign_keys": (),
        "indexes": (
            ("sqlite_autoindex_mapping_domains_1", 1, "pk", ("domain_id",)),
        ),
    },
    "tables": {
        "columns": (
            ("table_id", "TEXT", 0, None, 1),
            ("relative_path", "TEXT", 1, None, 0),
            ("schema_fingerprint", "TEXT", 0, None, 0),
            ("source_fingerprint", "TEXT", 0, None, 0),
        ),
        "foreign_keys": (),
        "indexes": (
            ("sqlite_autoindex_tables_1", 1, "pk", ("table_id",)),
            ("sqlite_autoindex_tables_2", 1, "u", ("relative_path",)),
        ),
    },
    "fields": {
        "columns": (
            ("field_id", "TEXT", 0, None, 1),
            ("table_id", "TEXT", 1, None, 0),
            ("name", "TEXT", 1, None, 0),
            ("dbf_type", "TEXT", 1, None, 0),
            ("encoding", "TEXT", 0, None, 0),
            ("width", "INTEGER", 1, None, 0),
            ("transform_action", "TEXT", 0, None, 0),
            ("mapping_domain_id", "TEXT", 0, None, 0),
        ),
        "foreign_keys": (
            ("mapping_domains", (("mapping_domain_id", "domain_id"),)),
            ("tables", (("table_id", "table_id"),)),
        ),
        "indexes": (
            ("idx_fields_domain", 0, "c", ("mapping_domain_id",)),
            ("idx_fields_table", 0, "c", ("table_id",)),
            ("sqlite_autoindex_fields_1", 1, "pk", ("field_id",)),
            ("sqlite_autoindex_fields_2", 1, "u", ("table_id", "name")),
            ("sqlite_autoindex_fields_3", 1, "u", ("field_id", "table_id")),
        ),
    },
    "text_mappings": {
        "columns": (
            ("domain_id", "TEXT", 1, None, 0),
            ("original_value", "TEXT", 1, None, 0),
            ("pseudonym_value", "TEXT", 1, None, 0),
            ("logical_byte_length", "INTEGER", 1, None, 0),
        ),
        "foreign_keys": (
            ("mapping_domains", (("domain_id", "domain_id"),)),
        ),
        "indexes": (
            ("uq_text_mappings_domain_original", 1, "c", ("domain_id", "original_value")),
            ("uq_text_mappings_domain_pseudonym", 1, "c", ("domain_id", "pseudonym_value")),
        ),
    },
    "numeric_key_mappings": {
        "columns": (
            ("domain_id", "TEXT", 1, None, 0),
            ("original_value", "TEXT", 1, None, 0),
            ("pseudonym_value", "TEXT", 1, None, 0),
        ),
        "foreign_keys": (
            ("mapping_domains", (("domain_id", "domain_id"),)),
        ),
        "indexes": (
            ("uq_numeric_key_mappings_domain_original", 1, "c", ("domain_id", "original_value")),
            ("uq_numeric_key_mappings_domain_pseudonym", 1, "c", ("domain_id", "pseudonym_value")),
        ),
    },
    "memo_recovery": {
        "columns": (
            ("table_id", "TEXT", 1, None, 1),
            ("physical_record_index", "INTEGER", 1, None, 2),
            ("field_id", "TEXT", 1, None, 3),
            ("original_payload", "BLOB", 1, None, 0),
            ("payload_kind", "TEXT", 1, None, 0),
        ),
        "foreign_keys": (
            ("fields", (("field_id", "field_id"), ("table_id", "table_id"))),
            ("tables", (("table_id", "table_id"),)),
        ),
        "indexes": (
            ("idx_memo_recovery_field", 0, "c", ("field_id",)),
            (
                "sqlite_autoindex_memo_recovery_1",
                1,
                "pk",
                ("table_id", "physical_record_index", "field_id"),
            ),
        ),
    },
    "temporal_parameters": {
        "columns": (
            ("domain_id", "TEXT", 0, None, 1),
            ("offset_days", "INTEGER", 1, None, 0),
        ),
        "foreign_keys": (
            ("mapping_domains", (("domain_id", "domain_id"),)),
        ),
        "indexes": (
            ("sqlite_autoindex_temporal_parameters_1", 1, "pk", ("domain_id",)),
        ),
    },
}


def _live_schema_snapshot(vault: VaultDatabase) -> dict[str, dict[str, object]]:
    connection = vault._internal_connection()
    snapshot: dict[str, dict[str, object]] = {}
    for table in EXPECTED_SCHEMA_SNAPSHOT:
        columns = tuple(
            (str(row[1]), str(row[2]), int(row[3]), row[4], int(row[5]))
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        )
        grouped: dict[int, tuple[str, list[tuple[str, str]]]] = {}
        for row in connection.execute(f"PRAGMA foreign_key_list({table})").fetchall():
            entry = grouped.setdefault(int(row[0]), (str(row[2]), []))
            entry[1].append((str(row[3]), str(row[4])))
        foreign_keys = tuple(
            (grouped[key][0], tuple(grouped[key][1])) for key in sorted(grouped)
        )
        indexes = []
        for row in connection.execute(f"PRAGMA index_list({table})").fetchall():
            name = str(row[1])
            index_columns = tuple(
                str(index_row[2])
                for index_row in connection.execute(f"PRAGMA index_info({name})").fetchall()
            )
            indexes.append((name, int(row[2]), str(row[3]), index_columns))
        snapshot[table] = {
            "columns": columns,
            "foreign_keys": tuple(
                (parent, tuple(columns)) for parent, columns in (
                    grouped[key] for key in sorted(grouped)
                )
            ),
            "indexes": tuple(sorted(indexes, key=lambda item: item[0])),
        }
    return snapshot


def test_full_schema_1_1_snapshot_is_frozen(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        live = _live_schema_snapshot(vault)
        assert set(live) == set(EXPECTED_SCHEMA_SNAPSHOT)
        for table, expected in EXPECTED_SCHEMA_SNAPSHOT.items():
            assert live[table] == expected, f"schema drift in table {table!r}"
        vault.verify(full=True)


# ---------------------------------------------------------------------------
# Schema snapshot (tables, columns, indexes, FKs, pragmas)
# ---------------------------------------------------------------------------
def test_schema_snapshot_is_explicit_and_versioned(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        assert vault.schema_version == VAULT_SCHEMA_VERSION == "1.1"
        tables = {
            row[0]
            for row in vault._internal_connection().execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        assert set(tables) == set(EXPECTED_VAULT_TABLES)

        indexes = {
            row[0]
            for row in vault._internal_connection().execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'uq_%'"
            ).fetchall()
        }
        assert indexes == set(EXPECTED_VAULT_UNIQUE_INDEXES) | {
            "uq_operations_destination"
        }

        # The bijection constraints are real named UNIQUE indexes.
        for index_name in EXPECTED_VAULT_UNIQUE_INDEXES:
            columns = [
                row[2]
                for row in vault._internal_connection().execute(f"PRAGMA index_info({index_name})")
            ]
            assert columns == ["domain_id", "original_value" if "original" in index_name else "pseudonym_value"]

        # The enforced per-connection pragmas are ON (WAL + foreign keys).
        assert vault.foreign_keys_enabled() is True
        assert vault.journal_mode() == "wal"

        # Every declared FK of every table is registered in sqlite_master.
        fk_tables = {
            "fields": "tables",
            "text_mappings": "mapping_domains",
            "numeric_key_mappings": "mapping_domains",
            # The composite memo identity proves the field belongs to the
            # same table (parent: fields, columns: field_id + table_id).
            "memo_recovery": "fields",
            "temporal_parameters": "mapping_domains",
            "publication": "operations",
        }
        for child, parent in fk_tables.items():
            rows = vault._internal_connection().execute(f"PRAGMA foreign_key_list({child})").fetchall()
            targets = {str(row[2]) for row in rows}
            assert parent in targets, (child, parent, targets)

        # The composite FK of memo_recovery pairs field_id AND table_id.
        memo_fks = [
            (str(row[3]), str(row[4]))
            for row in vault._internal_connection().execute("PRAGMA foreign_key_list(memo_recovery)")
        ]
        assert ("field_id", "field_id") in memo_fks
        assert ("table_id", "table_id") in memo_fks

    # Creation never leaves journal sidecars behind after the clean close.
    vault_dir = tmp_path / "vault"
    assert (vault_dir / VAULT_DATABASE_FILENAME).is_file()
    assert sidecar_inventory(vault_dir) == []


def test_meta_and_dataset_rows_carry_the_bound_identity(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        meta = vault._internal_connection().execute(
            "SELECT schema_version, vault_id, package_version, dbfbridge_version "
            "FROM meta WHERE singleton = 1"
        ).fetchone()
        assert meta is not None
        assert meta[0] == VAULT_SCHEMA_VERSION
        assert str(meta[1]) == vault.vault_id
        assert str(meta[2]) == "1.0.0.dev0"
        assert meta[3] == DBFBRIDGE_VERSION

        dataset = vault._internal_connection().execute(
            "SELECT source_fingerprint, policy_fingerprint, relationship_fingerprint "
            "FROM dataset WHERE singleton = 1"
        ).fetchone()
        assert tuple(dataset) == (SOURCE_FP, POLICY_FP, RELATIONSHIP_FP)


def test_expected_tables_match_the_ddl_module(tmp_path: Path) -> None:
    # Every DDL statement creates exactly the documented snapshot tables.
    created = {name for name in EXPECTED_VAULT_TABLES}
    assert len(created) == len(EXPECTED_VAULT_TABLES)
    assert len(DDL_STATEMENTS) >= len(EXPECTED_VAULT_TABLES)


# ---------------------------------------------------------------------------
# Composite memo table/field identity (database-enforced)
# ---------------------------------------------------------------------------
def test_memo_field_must_belong_to_the_same_table(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            table_a = vault.register_table("memo/table_a.dbf", schema_fingerprint="fp-a")
            table_b = vault.register_table("memo/table_b.dbf", schema_fingerprint="fp-b")
            field_a = vault.register_field(table_a, "NOTES", dbf_type="M", width=10)
            field_b = vault.register_field(table_b, "NOTES", dbf_type="M", width=10)
            # table A + field A (owned by table A) -> accepted.
            mappings.add_memo_recovery(
                vault, table_a, 1, field_a, "CANARY_MEMO_A",
                payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
            )
            # table A + field B owned by table B -> SQLite rejects.
            with pytest.raises(VaultError) as excinfo:
                mappings.add_memo_recovery(
                    vault, table_a, 2, field_b, "cross",
                    payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
                )
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
            # unknown field -> rejects; unknown table -> rejects.
            with pytest.raises(VaultError):
                mappings.add_memo_recovery(
                    vault, table_a, 3, "fld-unknown", "x",
                    payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
                )
            with pytest.raises(VaultError):
                mappings.add_memo_recovery(
                    vault, "tbl-unknown", 4, field_a, "x",
                    payload_kind=mappings.VAULT_PAYLOAD_KIND_TEXT,
                )
    with _reopen(tmp_path) as reopened:
        # The valid row survives reopen and foreign_key_check stays empty.
        reopened.verify(full=True)
        rows = mappings.memo_recovery_rows(reopened, table_a)
        assert len(rows) == 1
        assert rows[0]["field_id"] == field_a
        assert rows[0]["physical_record_index"] == 1
        assert reopened._internal_connection().execute(
            "PRAGMA foreign_key_check"
        ).fetchall() == []


# ---------------------------------------------------------------------------
# Reopen / identity binding / migration policy
# ---------------------------------------------------------------------------
def test_reopen_keeps_stable_vault_id_and_identity(tmp_path: Path) -> None:
    with _open_create(tmp_path) as first:
        vault_id = first.vault_id
        assert vault_id.startswith(VAULT_ID_PREFIX)
        assert len(vault_id) == len(VAULT_ID_PREFIX) + 32

    with _reopen(
        tmp_path,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as second:
        assert second.vault_id == vault_id
        assert second.schema_version == VAULT_SCHEMA_VERSION
        assert second.source_fingerprint == SOURCE_FP
        assert second.policy_fingerprint == POLICY_FP
        assert second.relationship_fingerprint == RELATIONSHIP_FP
        second.verify(full=True)
        # A supported vault stays in the explicitly verified WAL mode.
        assert second.journal_mode() == "wal"


def test_unsupported_schema_version_fails_closed(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            vault.begin_operation()
        vault._internal_connection().execute("UPDATE meta SET schema_version = '9.9' WHERE singleton = 1")

    dictionary = _dictionary(tmp_path)
    hash_before = file_sha256(dictionary)
    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path)
    assert excinfo.value.code is ErrorCode.VAULT_SCHEMA_UNSUPPORTED
    payload = json.dumps(excinfo.value.to_dict(), sort_keys=True)
    assert "9.9" not in payload
    # The rejected vault was NOT mutated by the validation stage.
    assert file_sha256(dictionary) == hash_before
    assert sidecar_inventory(dictionary.parent) == []


def test_older_schema_version_fails_closed_without_migration(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        vault._internal_connection().execute("UPDATE meta SET schema_version = '0.9' WHERE singleton = 1")

    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path)
    assert excinfo.value.code is ErrorCode.VAULT_SCHEMA_UNSUPPORTED

    # The unknown database was NOT dropped, recreated or migrated: a raw
    # sqlite3 reader (not the vault) still sees the original tampered meta.
    with _raw_sqlite(_dictionary(tmp_path)) as raw:
        version = raw.execute(
            "SELECT schema_version FROM meta WHERE singleton = 1"
        ).fetchone()
        assert version is not None and version[0] == "0.9"
        tables = {
            row[0]
            for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "text_mappings" in tables


def test_creation_over_existing_file_is_refused(tmp_path: Path) -> None:
    with _open_create(tmp_path):
        pass
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path)
    assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
    payload = json.dumps(excinfo.value.to_dict(), sort_keys=True)
    assert VAULT_ID_PREFIX not in payload


def test_missing_dictionary_fails_closed_as_unavailable(tmp_path: Path) -> None:
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(tmp_path / "absent" / VAULT_DATABASE_FILENAME)
    assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE


# ---------------------------------------------------------------------------
# Non-mutating rejection evidence (hash + sidecar inventory)
# ---------------------------------------------------------------------------
def _rejected_open_leaves_database_untouched(
    tmp_path: Path, **bad_kwargs: str
) -> None:
    """Assert the rejection leaves the dictionary byte-identical/sidecar-free.

    The typed rejection is re-raised so the caller can assert code/detail.
    """
    dictionary = _dictionary(tmp_path)
    hash_before = file_sha256(dictionary)
    try:
        _reopen(tmp_path, **bad_kwargs)
    except VaultError:
        assert file_sha256(dictionary) == hash_before
        assert sidecar_inventory(dictionary.parent) == []
        raise
    raise AssertionError("expected the incompatible vault to be rejected")


def test_rejected_source_fingerprint_leaves_database_untouched(tmp_path: Path) -> None:
    with _open_create(tmp_path):
        pass
    with pytest.raises(VaultError) as excinfo:
        _rejected_open_leaves_database_untouched(
            tmp_path, expected_source_fingerprint="other-" + "a" * 60
        )
    assert excinfo.value.code is ErrorCode.VAULT_IDENTITY_MISMATCH
    assert excinfo.value.context.detail_code == "SOURCE_FINGERPRINT"


def test_rejected_policy_fingerprint_leaves_database_untouched(tmp_path: Path) -> None:
    with _open_create(tmp_path):
        pass
    with pytest.raises(VaultError) as excinfo:
        _rejected_open_leaves_database_untouched(
            tmp_path, expected_policy_fingerprint="other-" + "b" * 60
        )
    assert excinfo.value.code is ErrorCode.VAULT_IDENTITY_MISMATCH
    assert excinfo.value.context.detail_code == "POLICY_FINGERPRINT"


def test_rejected_relationship_fingerprint_leaves_database_untouched(
    tmp_path: Path,
) -> None:
    with _open_create(tmp_path):
        pass
    with pytest.raises(VaultError) as excinfo:
        _rejected_open_leaves_database_untouched(
            tmp_path, expected_relationship_fingerprint="other-" + "c" * 60
        )
    assert excinfo.value.code is ErrorCode.VAULT_IDENTITY_MISMATCH


def test_rejected_schema_version_leaves_database_untouched(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        vault._internal_connection().execute("UPDATE meta SET schema_version = '9.9' WHERE singleton = 1")
    dictionary = _dictionary(tmp_path)
    hash_before = file_sha256(dictionary)
    with pytest.raises(VaultError):
        _reopen(tmp_path)
    assert file_sha256(dictionary) == hash_before
    assert sidecar_inventory(dictionary.parent) == []


def test_rejected_compatible_identity_reopens_normally(tmp_path: Path) -> None:
    with _open_create(tmp_path):
        pass
    with _reopen(
        tmp_path,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as vault:
        vault.verify()
        vault.verify(full=True)


# ---------------------------------------------------------------------------
# STAGE-2 binding owns the operational connection (failed bind closes it)
# ---------------------------------------------------------------------------
def test_stage2_bind_failure_closes_the_operational_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    with _open_create(tmp_path) as vault:
        vault.close()
    dictionary = _dictionary(tmp_path)
    vault_dir = dictionary.parent

    # STAGE 1 (read-only validation) passes; the STAGE-2 identity read raises
    # a TYPED validation failure AFTER the operational connection has opened —
    # simulating a file replacement/race between the two open stages.
    real_read_identity = store_module.VaultDatabase._read_identity
    calls = {"count": 0}

    def _failing_read_identity(cls: type, connection: sqlite3.Connection) -> object:
        calls["count"] += 1
        if calls["count"] == 1:
            return real_read_identity(connection)
        raise store_module._vault_failure(  # noqa: SLF001 - typed injection seam
            store_module.ErrorCode.VAULT_SCHEMA_UNSUPPORTED,
            "SCHEMA_VERSION_UNSUPPORTED",
        )

    monkeypatch.setattr(
        store_module.VaultDatabase,
        "_read_identity",
        classmethod(_failing_read_identity),
    )

    captured: list[sqlite3.Connection] = []
    real_connect_operational = store_module.VaultDatabase._connect_operational

    def _capturing_connect(path: Path) -> sqlite3.Connection:
        connection = real_connect_operational(path)
        captured.append(connection)
        return connection

    monkeypatch.setattr(
        store_module.VaultDatabase,
        "_connect_operational",
        staticmethod(_capturing_connect),
    )

    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(
            dictionary,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
        )
    # The original typed validation error is preserved.
    assert excinfo.value.code is ErrorCode.VAULT_SCHEMA_UNSUPPORTED
    assert excinfo.value.context.detail_code == "SCHEMA_VERSION_UNSUPPORTED"
    payload = error_boundary_payload(excinfo.value)
    assert str(tmp_path) not in payload
    # The failed binding CLOSED the raw operational connection: no handle
    # remains usable.
    with pytest.raises(sqlite3.ProgrammingError):
        captured[0].execute("PRAGMA quick_check")
    # No persistent sidecar residue is left by the failed stage-2 binding.
    assert sidecar_inventory(vault_dir) == []
    # The rejected vault was not modified: after the injected failure is
    # removed, the same dictionary reopens cleanly and passes full validation.
    monkeypatch.undo()
    with _reopen(tmp_path) as reopened:
        reopened.verify(full=True)


# ---------------------------------------------------------------------------
# Foreign / wrong-journal databases fail closed WITHOUT mutation
# ---------------------------------------------------------------------------
def test_foreign_sqlite_database_is_rejected_byte_identical(
    tmp_path: Path,
) -> None:
    # A valid SQLite database in DELETE mode with a sentinel table: the vault
    # must reject it, leave every byte and its journal mode untouched and
    # never create WAL/SHM sidecars.
    foreign_dir = tmp_path / "foreign"
    foreign_dir.mkdir()
    foreign = foreign_dir / VAULT_DATABASE_FILENAME
    with _raw_sqlite(foreign) as raw:
        raw.execute("CREATE TABLE sentinel_secret_marker (value TEXT NOT NULL)")
        raw.execute("INSERT INTO sentinel_secret_marker VALUES ('KEEP_ME')")
        raw.commit()
    assert file_sha256(foreign) != ""
    hash_before = file_sha256(foreign)
    with _raw_sqlite(foreign) as probe:
        mode_before = probe.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]

    with pytest.raises(VaultError):
        VaultDatabase.open(foreign)

    assert file_sha256(foreign) == hash_before
    assert sidecar_inventory(foreign_dir) == []
    with _raw_sqlite(foreign) as probe:
        mode_after = probe.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]
    assert mode_after == mode_before
    # The sentinel data is intact (no reconstruction/overwrite happened).
    with _raw_sqlite(foreign) as raw:
        kept = raw.execute(
            "SELECT value FROM sentinel_secret_marker"
        ).fetchone()
        assert tuple(kept) == ("KEEP_ME",)


def test_wrong_journal_mode_fails_closed_without_conversion(tmp_path: Path) -> None:
    # A structurally valid schema-1.0 dictionary that was switched to legacy
    # rollback-journal mode must be REJECTED, not silently converted.
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            vault.begin_operation()
        vault.close()
    dictionary = _dictionary(tmp_path)
    raw = bytearray(dictionary.read_bytes())
    # SQLite header: byte 18 = write version, byte 19 = read version
    # (2 = WAL, 1 = legacy rollback journal).
    assert raw[18] == 2 and raw[19] == 2
    raw[18] = 1
    raw[19] = 1
    dictionary.write_bytes(bytes(raw))

    hash_before = file_sha256(dictionary)
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(dictionary)
    assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
    assert excinfo.value.context.detail_code == "JOURNAL_MODE_UNEXPECTED"
    assert file_sha256(dictionary) == hash_before
    assert sidecar_inventory(dictionary.parent) == []


def test_wal_pragma_result_must_be_wal_on_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    monkeypatch.setattr(
        store_module.VaultDatabase, "_apply_journal_mode", lambda connection: "delete"
    )
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, name="wal_refused")
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "JOURNAL_MODE_UNAVAILABLE"
    # Nothing was left behind by the refused creation.
    assert not (tmp_path / "wal_refused" / VAULT_DATABASE_FILENAME).exists()


# ---------------------------------------------------------------------------
# Integrity / corruption
# ---------------------------------------------------------------------------
def test_corrupted_database_fails_closed_as_vault_corrupt(tmp_path: Path) -> None:
    operation_id = "vop-" + "0" * 32
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            vault.begin_operation(operation_id)
    with _reopen(tmp_path) as check:
        check.verify()
        check.verify(full=True)

    # Tamper with a COPY of the dictionary (never with committed fixtures):
    # clobber the SQLite header and page bytes. The vault must fail closed
    # without exposing raw SQLite text or stored operation identifiers.
    corrupted = tmp_path / "vault_corrupt" / VAULT_DATABASE_FILENAME
    corrupted.parent.mkdir()
    raw = bytearray((_dictionary(tmp_path)).read_bytes())
    for offset in range(0, len(raw), 512):
        raw[offset] = 0x7F
    corrupted.write_bytes(bytes(raw))

    hash_before = file_sha256(corrupted)
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(corrupted)
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    payload = json.dumps(excinfo.value.to_dict(), sort_keys=True)
    assert operation_id not in payload
    # The corrupt foreign file was not reconstructed or overwritten.
    assert file_sha256(corrupted) == hash_before
    assert sidecar_inventory(corrupted.parent) == []


def test_garbage_file_fails_closed_as_vault_corrupt(tmp_path: Path) -> None:
    garbage = tmp_path / "garbage" / VAULT_DATABASE_FILENAME
    garbage.parent.mkdir(parents=True)
    garbage.write_bytes(b"this is not a sqlite database at all" * 16)
    hash_before = file_sha256(garbage)
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(garbage)
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert file_sha256(garbage) == hash_before


def test_truncated_database_fails_closed(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        vault.close()
    truncated = tmp_path / "truncated" / VAULT_DATABASE_FILENAME
    truncated.parent.mkdir(parents=True)
    data = _dictionary(tmp_path).read_bytes()
    truncated.write_bytes(data[: len(data) // 3])
    with pytest.raises(VaultError):
        VaultDatabase.open(truncated)


def test_corrupted_metadata_is_tamper_evident(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        vault._internal_connection().execute("DELETE FROM dataset")
    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path)
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "DATASET_MISSING"


# ---------------------------------------------------------------------------
# Real foreign-key enforcement (per-connection pragma, verified)
# ---------------------------------------------------------------------------
def test_foreign_keys_are_actually_enforced(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        assert vault.foreign_keys_enabled() is True
        with writer_session(vault), vault.transaction():
            mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            # A statement-level FK violation is typed, leaves the transaction
            # usable, and inserts nothing.
            with pytest.raises(MappingError) as excinfo:
                mappings.add_text_mapping(
                    vault, "dom-unknown", "ORIGINAL", "PSEUDO", logical_byte_length=7
                )
            assert excinfo.value.code is ErrorCode.MAPPING_CONFLICT
            count = vault._internal_connection().execute(
                "SELECT COUNT(*) FROM text_mappings"
            ).fetchone()
            assert int(count[0]) == 0
        # The clean exit commits only the valid domain row.
        vault.verify()
        assert len(mappings.mapping_domains(vault)) == 1


def test_structural_foreign_keys_reject_unknown_parents(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            with pytest.raises(VaultError) as excinfo:
                vault.register_field("tbl-unknown", "NAME", dbf_type="C", width=10)
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
            with pytest.raises(VaultError):
                vault.record_publication("vop-unknown", "STAGE")


# ---------------------------------------------------------------------------
# Fail-closed raw path probing (pathlib 3.14 fail-open regression)
# ---------------------------------------------------------------------------
def test_vault_open_and_create_survive_poisoned_pathlib_predicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # REQ-P1-006 regression: modern pathlib predicates can suppress OSError.
    # The vault must not depend on Path.exists/is_file/is_dir at all.
    def _poison(self: Path) -> bool:
        raise AssertionError("poisoned pathlib predicate")

    monkeypatch.setattr(Path, "exists", _poison, raising=False)
    monkeypatch.setattr(Path, "is_file", _poison, raising=False)
    monkeypatch.setattr(Path, "is_dir", _poison, raising=False)
    with _open_create(tmp_path) as vault:
        assert vault.journal_mode() == "wal"
    with _reopen(tmp_path) as reopened:
        reopened.verify()


def test_stat_permission_error_on_dictionary_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    dictionary = _dictionary(tmp_path)

    def _denied(path: object) -> None:
        raise PermissionError(13, f"stat secrets under {path}")

    monkeypatch.setattr(store_module.os, "stat", _denied)
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(dictionary)
    assert excinfo.value.code is ErrorCode.VAULT_ACCESS_DENIED
    payload = error_boundary_payload(excinfo.value)
    assert "secrets" not in payload
    assert str(tmp_path) not in payload


def test_permission_error_on_parent_creation_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    def _denied(self: Path, parents: bool = False, exist_ok: bool = False) -> None:
        raise PermissionError(13, "mkdir secrets")

    monkeypatch.setattr(Path, "mkdir", _denied)
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, name="denied_parent")
    assert excinfo.value.code is ErrorCode.VAULT_ACCESS_DENIED
    assert excinfo.value.context.detail_code == "PARENT_CREATE_DENIED"
    payload = error_boundary_payload(excinfo.value)
    assert "mkdir secrets" not in payload
    assert str(tmp_path) not in payload


def test_non_regular_target_is_refused(tmp_path: Path) -> None:
    directory_target = tmp_path / "as_dir" / VAULT_DATABASE_FILENAME
    directory_target.parent.mkdir(parents=True)
    directory_target.mkdir()  # a directory where the dictionary must be
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(directory_target)
    assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
    assert excinfo.value.context.detail_code == "TARGET_NOT_A_FILE"
    with pytest.raises(VaultError) as excinfo_create:
        VaultDatabase.open(
            directory_target,
            create=True,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
            dbfbridge_version=DBFBRIDGE_VERSION,
        )
    assert excinfo_create.value.code is ErrorCode.VAULT_UNAVAILABLE
    assert excinfo_create.value.context.detail_code == "TARGET_NOT_A_FILE"


def test_deep_missing_parent_is_created(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c" / "vault" / VAULT_DATABASE_FILENAME
    with VaultDatabase.open(
        deep,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version=DBFBRIDGE_VERSION,
    ) as vault:
        assert vault.journal_mode() == "wal"
    assert deep.is_file()


def test_parent_that_is_a_file_fails_closed(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"not a directory")
    target = blocker / VAULT_DATABASE_FILENAME
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(
            target,
            create=True,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
            dbfbridge_version=DBFBRIDGE_VERSION,
        )
    assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
    payload = error_boundary_payload(excinfo.value)
    assert str(tmp_path) not in payload


def test_directory_target_stat_refuses_open(tmp_path: Path) -> None:
    directory_target = tmp_path / "plain_directory"
    directory_target.mkdir()
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(directory_target)
    assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
    assert excinfo.value.context.detail_code == "TARGET_NOT_A_FILE"


# ---------------------------------------------------------------------------
# Cleanup failures surface as typed, privacy-safe vault failures
# ---------------------------------------------------------------------------
def test_checkpoint_failure_on_explicit_close_is_surfaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _open_create(tmp_path) as vault:
        def _boom() -> None:
            raise sqlite3.OperationalError("injected checkpoint failure")

        monkeypatch.setattr(vault, "_checkpoint_wal", _boom, raising=False)
        with pytest.raises(VaultError) as excinfo:
            vault.close()
        assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
        assert excinfo.value.context.detail_code == "CLOSE_CHECKPOINT_FAILED"
        payload = error_boundary_payload(excinfo.value)
        assert "injected checkpoint failure" not in payload
        assert str(tmp_path) not in payload


def test_checkpoint_failure_during_with_exit_is_recorded_not_replacing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deterministic Python-3.10-compatible policy: a with-block exit that
    # already carries an operation exception records the cleanup failure on
    # the instance instead of replacing the original exception.
    with _open_create(tmp_path) as vault:
        def _boom() -> None:
            raise sqlite3.OperationalError("injected checkpoint failure")

        monkeypatch.setattr(vault, "_checkpoint_wal", _boom, raising=False)
        with pytest.raises(ValueError, match="original failure"):
            with vault:
                raise ValueError("original failure")
        assert vault.cleanup_failure is not None
        assert vault.cleanup_failure.code is ErrorCode.VAULT_UNAVAILABLE
        assert vault.cleanup_failure.context.detail_code == "CLOSE_CHECKPOINT_FAILED"


def test_successful_close_still_leaves_expected_sidecar_state(
    tmp_path: Path,
) -> None:
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            vault.begin_operation()
        vault.close()
        assert vault.cleanup_failure is None
    assert sidecar_inventory((_dictionary(tmp_path)).parent) == []


def test_creation_failure_cleanup_failure_is_surfaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    # Force the creation DDL to fail, then force the partial-file cleanup to
    # fail as well: BOTH must surface as one typed privacy-safe error.
    monkeypatch.setattr(
        store_module, "DDL_STATEMENTS", ("CREATE TABLE broken (",)
    )

    def _denied(self: Path) -> None:
        raise PermissionError(13, "unlink secrets")

    monkeypatch.setattr(Path, "unlink", _denied)
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, name="cleanup_failure")
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "CREATION_CLEANUP_FAILED"
    payload = error_boundary_payload(excinfo.value)
    assert "unlink secrets" not in payload
    assert str(tmp_path) not in payload


def test_creation_failure_with_successful_cleanup_removes_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    monkeypatch.setattr(store_module, "DDL_STATEMENTS", ("CREATE TABLE broken (",))
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, name="creation_failure")
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "CREATION_FAILED"
    assert not (tmp_path / "creation_failure" / VAULT_DATABASE_FILENAME).exists()


# ---------------------------------------------------------------------------
# Atomic creator reservation (TOCTOU: concurrent create can never destroy
# the winner's dictionary)
# ---------------------------------------------------------------------------
def test_cleanup_never_deletes_a_replaced_reservation(tmp_path: Path) -> None:
    # Adversarial ownership evidence: a failed creator whose reservation was
    # replaced by a DIFFERENT file must never unlink that file.
    with _open_create(tmp_path) as vault:
        dictionary = _dictionary(tmp_path)
        winner_hash = file_sha256(dictionary)
        status = os.stat(dictionary)
        foreign_identity = (status.st_dev + 1, status.st_ino)
        with pytest.raises(VaultError) as excinfo:
            VaultDatabase._remove_partial_dictionary(  # noqa: SLF001
                dictionary, foreign_identity
            )
        assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
        assert excinfo.value.context.detail_code == "CREATION_CLEANUP_FAILED"
        # The winner's dictionary was NOT deleted and stays integral.
        assert file_sha256(dictionary) == winner_hash
        vault.verify(full=True)


def test_failed_creator_cleans_only_its_own_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    # Force the creation DDL to fail: the reservation file IS the failed
    # creator's own file and must be removed by its owner.
    monkeypatch.setattr(store_module, "DDL_STATEMENTS", ("CREATE TABLE broken (",))
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, name="cleanup_own")
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "CREATION_FAILED"
    assert not (tmp_path / "cleanup_own" / VAULT_DATABASE_FILENAME).exists()


def test_creation_reservation_refuses_competing_creator(tmp_path: Path) -> None:
    # A reserved dictionary file already exists -> the competing creator is
    # refused WITHOUT opening, truncating, converting or deleting anything.
    target = _dictionary(tmp_path, "reservation")
    target.parent.mkdir(parents=True)
    placeholder = b"\x00" * 16
    target.write_bytes(placeholder)
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, "reservation")
    assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
    assert excinfo.value.context.detail_code == "ALREADY_EXISTS"
    # The placeholder file was never truncated or rewritten.
    assert file_sha256(target) == file_sha256(target)


# ---------------------------------------------------------------------------
# Exception-complete creation lifecycle (every post-reservation failure
# closes and cleans ONLY its own partial vault)
# ---------------------------------------------------------------------------
def test_connect_failure_after_reservation_cleans_up_and_preserves_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module
    from dbf_anonymizer.errors import ErrorContext

    dictionary = _dictionary(tmp_path, "connect_failure")
    injected = VaultError(
        ErrorCode.VAULT_UNAVAILABLE,
        context=ErrorContext(operation="vault", detail_code="OPEN_FAILED"),
    )

    def _failing_connect(path: Path) -> sqlite3.Connection:
        raise injected

    monkeypatch.setattr(
        store_module.VaultDatabase, "_connect", staticmethod(_failing_connect)
    )
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, "connect_failure")
    # The ORIGINAL typed error is preserved — cleanup never replaces it.
    assert excinfo.value is injected
    payload = error_boundary_payload(excinfo.value)
    assert str(tmp_path) not in payload
    # The reserved dictionary was removed: no file, no sidecar residue.
    assert not dictionary.exists()
    assert sidecar_inventory(dictionary.parent) == []
    # A retry starts deterministically from a clean slate and succeeds.
    monkeypatch.undo()
    with _open_create(tmp_path, "connect_failure") as vault:
        vault.verify(full=True)


def test_wal_pragma_failure_after_reservation_closes_and_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    dictionary = _dictionary(tmp_path, "wal_pragma_failure")
    real_connect = store_module.VaultDatabase._connect
    captured: list[sqlite3.Connection] = []

    def _capturing_connect(path: Path) -> sqlite3.Connection:
        connection = real_connect(path)
        captured.append(connection)
        return connection

    def _failing_journal_mode(connection: sqlite3.Connection) -> str:
        raise sqlite3.OperationalError("injected journal failure")

    monkeypatch.setattr(
        store_module.VaultDatabase, "_connect", staticmethod(_capturing_connect)
    )
    monkeypatch.setattr(
        store_module.VaultDatabase, "_apply_journal_mode", _failing_journal_mode
    )
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, "wal_pragma_failure")
    # The existing truthful classification for a failing WAL PRAGMA.
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "DATABASE_UNREADABLE"
    payload = error_boundary_payload(excinfo.value)
    assert "injected journal failure" not in payload
    assert str(tmp_path) not in payload
    # The opened connection was closed: no usable handle remains.
    with pytest.raises(sqlite3.ProgrammingError):
        captured[0].execute("PRAGMA journal_mode")
    # The owned reservation was removed; no sidecars remain.
    assert not dictionary.exists()
    assert sidecar_inventory(dictionary.parent) == []


def test_creation_begin_failure_cleans_up_and_retry_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    dictionary = _dictionary(tmp_path, "begin_failure")

    class _FailingBeginCreateTransaction(store_module.VaultTransaction):
        def __init__(self, connection: sqlite3.Connection, **kwargs: Any) -> None:
            super().__init__(
                FailingExecuteConnection(
                    connection, lambda sql: "BEGIN IMMEDIATE" in sql
                ),
                **kwargs,
            )

    monkeypatch.setattr(
        store_module, "VaultTransaction", _FailingBeginCreateTransaction
    )
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, "begin_failure")
    # The typed BEGIN control failure is preserved (not replaced/reclassified).
    assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
    assert excinfo.value.context.detail_code == "TRANSACTION_BEGIN_FAILED"
    payload = error_boundary_payload(excinfo.value)
    assert "injected storage failure" not in payload
    assert str(tmp_path) not in payload
    # The owned partial dictionary was removed; no sidecars remain.
    assert not dictionary.exists()
    assert sidecar_inventory(dictionary.parent) == []
    # A retry create succeeds deterministically.
    monkeypatch.undo()
    with _open_create(tmp_path, "begin_failure") as vault:
        vault.verify(full=True)


def test_creation_commit_failure_cleans_up_and_retry_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    dictionary = _dictionary(tmp_path, "commit_failure")

    class _FailingCommitCreateTransaction(store_module.VaultTransaction):
        def __init__(self, connection: sqlite3.Connection, **kwargs: Any) -> None:
            super().__init__(
                FailingExecuteConnection(connection, lambda sql: "COMMIT" in sql),
                **kwargs,
            )

    monkeypatch.setattr(
        store_module, "VaultTransaction", _FailingCommitCreateTransaction
    )
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, "commit_failure")
    # The typed COMMIT control failure is preserved.
    assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
    assert excinfo.value.context.detail_code == "TRANSACTION_COMMIT_FAILED"
    payload = error_boundary_payload(excinfo.value)
    assert "injected storage failure" not in payload
    assert str(tmp_path) not in payload
    # The owned partial dictionary was removed while still owned.
    assert not dictionary.exists()
    assert sidecar_inventory(dictionary.parent) == []
    # A retry create succeeds deterministically.
    monkeypatch.undo()
    with _open_create(tmp_path, "commit_failure") as vault:
        vault.verify(full=True)


def test_creation_cleanup_never_unlinks_an_unprovable_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    dictionary = _dictionary(tmp_path, "unprovable")
    real_reserve = store_module.VaultDatabase._reserve_dictionary_file

    def _foreign_identity_reserve(path: Path) -> tuple[int, int]:
        real_reserve(path)  # the real reservation file is created
        # Simulate that the reservation was REPLACED before cleanup: the
        # captured ownership identity can never match the file again.
        return (-1, -1)

    monkeypatch.setattr(store_module, "DDL_STATEMENTS", ("CREATE TABLE broken (",))
    monkeypatch.setattr(
        store_module.VaultDatabase,
        "_reserve_dictionary_file",
        staticmethod(_foreign_identity_reserve),
    )
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, "unprovable")
    # The unprovable-ownership cleanup failure SURFACES (never success, never
    # the raw creation classification of a cleanup that was refused).
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "CREATION_CLEANUP_FAILED"
    payload = error_boundary_payload(excinfo.value)
    assert str(tmp_path) not in payload
    # The file at the dictionary path was NEVER unlinked: the owner guard held.
    assert dictionary.is_file()
    assert sidecar_inventory(dictionary.parent) == []


def test_creation_connection_close_failure_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    dictionary = _dictionary(tmp_path, "close_failure")
    inner_connections: list[sqlite3.Connection] = []

    class _FailingCloseConnection:
        def __init__(self, inner: sqlite3.Connection) -> None:
            self._inner = inner
            inner_connections.append(inner)

        def execute(self, sql: str, *parameters: Any) -> object:
            return self._inner.execute(sql, *parameters)

        def close(self) -> None:
            raise sqlite3.OperationalError("injected close failure")

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    real_connect = store_module.VaultDatabase._connect
    unlink_attempts: list[Path] = []
    real_unlink = Path.unlink

    def _recording_unlink(self: Path) -> None:
        unlink_attempts.append(self)
        real_unlink(self)

    def _failing_close_connect(path: Path) -> sqlite3.Connection:
        return _FailingCloseConnection(real_connect(path))

    monkeypatch.setattr(store_module, "DDL_STATEMENTS", ("CREATE TABLE broken (",))
    monkeypatch.setattr(Path, "unlink", _recording_unlink)
    monkeypatch.setattr(
        store_module.VaultDatabase, "_connect", staticmethod(_failing_close_connect)
    )
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path, "close_failure")
    # A cleanup problem can never turn a failed creation into a success.
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    assert excinfo.value.context.detail_code == "CREATION_CLEANUP_FAILED"
    payload = error_boundary_payload(excinfo.value)
    assert "injected close failure" not in payload
    assert str(tmp_path) not in payload
    # The owner-scoped cleanup still ATTEMPTED the unlink of its own
    # reservation (whether that unlink can complete is platform-dependent
    # while the un-closable connection holds the file handle).
    assert unlink_attempts == [dictionary]
    # Test hygiene: release the deliberately un-closable real connection.
    for connection in inner_connections:
        connection.close()


# ---------------------------------------------------------------------------
# WAL checkpoint completion is verified (structured status row)
# ---------------------------------------------------------------------------
class _StubCursor:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...]:
        return self._row

    def fetchall(self) -> list[tuple[object, ...]]:
        return [self._row]


class _BusyCheckpointConnection:
    """Delegating proxy whose wal_checkpoint reports BUSY (1, 0, 0)."""

    def __init__(self, inner: sqlite3.Connection) -> None:
        self._inner = inner

    def execute(self, sql: str, *parameters: Any) -> object:
        if "PRAGMA wal_checkpoint" in sql:
            return _StubCursor((1, 3, 0))
        return self._inner.execute(sql, *parameters)

    def close(self) -> None:
        self._inner.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_busy_checkpoint_status_is_typed_and_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            vault.begin_operation()
        monkeypatch.setattr(vault, "_connection", _BusyCheckpointConnection(
            vault._internal_connection()
        ))
        with pytest.raises(VaultError) as excinfo:
            vault.close()
        assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
        assert excinfo.value.context.detail_code == "CLOSE_CHECKPOINT_INCOMPLETE"
        payload = error_boundary_payload(excinfo.value)
        assert str(tmp_path) not in payload


def test_real_busy_reader_blocks_checkpoint_until_released(
    tmp_path: Path,
) -> None:
    # REAL two-connection evidence: an open reader snapshot prevents the
    # TRUNCATE checkpoint from completing (busy row, no exception) — the close
    # must report the typed incomplete classification, never fake success.
    with _open_create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            vault.begin_operation()
        reader = sqlite3.connect(str(_dictionary(tmp_path)))
        try:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM operations").fetchone()
            # While the reader snapshot is held, the clean close checkpoint
            # cannot truncate: the close surfaces the typed failure.
            with pytest.raises(VaultError) as excinfo:
                vault.close()
            assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
            assert (
                excinfo.value.context.detail_code == "CLOSE_CHECKPOINT_INCOMPLETE"
            )
        finally:
            reader.execute("ROLLBACK")
            reader.close()

    # After the reader is released, a fresh reopen closes cleanly: the full
    # WAL lifecycle recovers without any lost committed state.
    with _reopen(tmp_path) as reopened:
        reopened.verify(full=True)
        assert len(reopened.operations()) == 1
        reopened.close()
    assert sidecar_inventory((_dictionary(tmp_path)).parent) == []


# ---------------------------------------------------------------------------
# The ordinary vault interface offers NO writable raw-connection bypass
# ---------------------------------------------------------------------------
def test_public_vault_interface_has_no_writable_connection_bypass(
    tmp_path: Path,
) -> None:
    with _open_create(tmp_path) as vault:
        # The named writable bypass is gone from the supported interface.
        assert not hasattr(vault, "connection")
        with pytest.raises(AttributeError):
            getattr(vault, "connection")  # type: ignore[attr-defined]
        # Public attribute scan: no property exposes a raw sqlite3.Connection.
        for name in dir(VaultDatabase):
            if name.startswith("_"):
                continue
            attribute = getattr(VaultDatabase, name)
            if isinstance(attribute, property):
                assert name != "connection"
    source = (Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer" / "vault" / "store.py").read_text(encoding="utf-8")
    assert "def connection(" not in source


# ---------------------------------------------------------------------------
# Package-tree purity: no SQLite artifacts committed anywhere in the package
# ---------------------------------------------------------------------------
def test_no_sqlite_artifacts_inside_the_package_tree() -> None:
    package_root = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer"
    offending = [
        str(path.relative_to(package_root))
        for path in package_root.rglob("*")
        if path.is_file()
        and (
            path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}
            or path.name.endswith(("-wal", "-shm", ".journal"))
        )
    ]
    assert not offending, f"SQLite artifacts committed in the package: {offending}"


def test_vault_module_is_not_reachable_from_the_public_root() -> None:
    root_init = (
        Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer" / "__init__.py"
    )
    source = root_init.read_text(encoding="utf-8")
    # The root package must not wire the vault subsystem into the public API
    # (VaultStrategy, the existing public model, is unrelated).
    assert "from .vault" not in source
    assert "dbf_anonymizer.vault" not in source
    import dbf_anonymizer

    assert "VaultDatabase" not in dbf_anonymizer.__all__
    assert "VaultTransaction" not in dbf_anonymizer.__all__
