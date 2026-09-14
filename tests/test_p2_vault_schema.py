"""REQ-P2-002 — explicit versioned SQLite vault schema (foundation evidence).

Covers: schema-version snapshot, table/index/FK/constraint snapshot, exact
supported-version reopen, unsupported-version fail-closed, dataset identity
binding (source/policy/relationship fingerprints), integrity boundary,
deliberate corruption fail-closed, real foreign-key enforcement and the
static purity of the committed package tree (no SQLite artifacts inside
``src``/fixtures; no vault import from the read-only public operations).

Synthetic data only; no production data. The vault files live exclusively in
``tmp_path`` (the protected zone), never inside source fixtures or public
output trees.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Schema snapshot (tables, columns, indexes, FKs, pragmas)
# ---------------------------------------------------------------------------
def test_schema_snapshot_is_explicit_and_versioned(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        assert vault.schema_version == VAULT_SCHEMA_VERSION == "1.0"
        tables = {
            row[0]
            for row in vault.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        assert set(tables) == set(EXPECTED_VAULT_TABLES)

        indexes = {
            row[0]
            for row in vault.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'uq_%'"
            ).fetchall()
        }
        assert indexes == set(EXPECTED_VAULT_UNIQUE_INDEXES)

        # The bijection constraints are real named UNIQUE indexes.
        for index_name in EXPECTED_VAULT_UNIQUE_INDEXES:
            columns = [
                row[2]
                for row in vault.connection.execute(f"PRAGMA index_info({index_name})")
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
            "memo_recovery": "tables",
            "temporal_parameters": "mapping_domains",
            "publication": "operations",
        }
        for child, parent in fk_tables.items():
            rows = vault.connection.execute(f"PRAGMA foreign_key_list({child})").fetchall()
            targets = {str(row[2]) for row in rows}
            assert parent in targets, (child, parent, targets)

    # Creation never leaves journal sidecars behind after the clean close.
    vault_dir = tmp_path / "vault"
    assert (vault_dir / VAULT_DATABASE_FILENAME).is_file()
    assert not (vault_dir / "dictionary.sqlite3-wal").exists()
    assert not (vault_dir / "dictionary.sqlite3-shm").exists()


def test_meta_and_dataset_rows_carry_the_bound_identity(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        meta = vault.connection.execute(
            "SELECT schema_version, vault_id, package_version, dbfbridge_version "
            "FROM meta WHERE singleton = 1"
        ).fetchone()
        assert meta is not None
        assert meta[0] == VAULT_SCHEMA_VERSION
        assert str(meta[1]) == vault.vault_id
        assert str(meta[2]) == "1.0.0.dev0"
        assert meta[3] == DBFBRIDGE_VERSION

        dataset = vault.connection.execute(
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


def test_unsupported_schema_version_fails_closed(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        vault.connection.execute("UPDATE meta SET schema_version = '9.9' WHERE singleton = 1")

    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path)
    assert excinfo.value.code is ErrorCode.VAULT_SCHEMA_UNSUPPORTED
    payload = json.dumps(excinfo.value.to_dict(), sort_keys=True)
    assert "9.9" not in payload


def test_older_schema_version_fails_closed_without_migration(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        vault.connection.execute("UPDATE meta SET schema_version = '0.9' WHERE singleton = 1")

    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path)
    assert excinfo.value.code is ErrorCode.VAULT_SCHEMA_UNSUPPORTED

    # The unknown database was NOT dropped, recreated or migrated: a raw
    # sqlite3 reader (not the vault) still sees the original tampered meta.
    with sqlite3.connect(str(tmp_path / "vault" / VAULT_DATABASE_FILENAME)) as raw:
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


def test_mismatched_source_fingerprint_fails_closed(tmp_path: Path) -> None:
    with _open_create(tmp_path):
        pass
    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path, expected_source_fingerprint="other-" + "a" * 60)
    assert excinfo.value.code is ErrorCode.VAULT_IDENTITY_MISMATCH
    payload = json.dumps(excinfo.value.to_dict(), sort_keys=True)
    assert SOURCE_FP not in payload
    assert "other-" not in payload


def test_mismatched_policy_fingerprint_fails_closed(tmp_path: Path) -> None:
    with _open_create(tmp_path):
        pass
    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path, expected_policy_fingerprint="other-" + "b" * 60)
    assert excinfo.value.code is ErrorCode.VAULT_IDENTITY_MISMATCH


def test_mismatched_relationship_fingerprint_fails_closed(tmp_path: Path) -> None:
    with _open_create(tmp_path):
        pass
    with pytest.raises(VaultError) as excinfo:
        _reopen(tmp_path, expected_relationship_fingerprint="other-" + "c" * 60)
    assert excinfo.value.code is ErrorCode.VAULT_IDENTITY_MISMATCH


def test_compatible_identity_reopens_normally(tmp_path: Path) -> None:
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
# Integrity / corruption
# ---------------------------------------------------------------------------
def test_corrupted_database_fails_closed_as_vault_corrupt(tmp_path: Path) -> None:
    operation_id = "vop-" + "0" * 32
    with _open_create(tmp_path) as vault:
        vault.connection.execute(
            "INSERT INTO operations (operation_id, state, started_at) VALUES (?, 'STARTED', ?)",
            (operation_id, "2026-01-01T00:00:00+00:00"),
        )
    with _reopen(tmp_path) as check:
        check.verify()
        check.verify(full=True)

    # Tamper with a COPY of the dictionary (never with committed fixtures):
    # clobber the SQLite header and page bytes. The vault must fail closed
    # without exposing raw SQLite text or stored operation identifiers.
    corrupted = tmp_path / "vault_corrupt" / VAULT_DATABASE_FILENAME
    corrupted.parent.mkdir()
    raw = bytearray((tmp_path / "vault" / VAULT_DATABASE_FILENAME).read_bytes())
    for offset in range(0, len(raw), 512):
        raw[offset] = 0x7F
    corrupted.write_bytes(bytes(raw))

    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(corrupted)
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT
    payload = json.dumps(excinfo.value.to_dict(), sort_keys=True)
    assert operation_id not in payload


def test_garbage_file_fails_closed_as_vault_corrupt(tmp_path: Path) -> None:
    garbage = tmp_path / "garbage" / VAULT_DATABASE_FILENAME
    garbage.parent.mkdir(parents=True)
    garbage.write_bytes(b"this is not a sqlite database at all" * 16)
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(garbage)
    assert excinfo.value.code is ErrorCode.VAULT_CORRUPT


def test_truncated_database_fails_closed(tmp_path: Path) -> None:
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    with _open_create(tmp_path) as vault:
        vault.close()
    truncated = tmp_path / "truncated" / VAULT_DATABASE_FILENAME
    truncated.parent.mkdir(parents=True)
    data = dictionary.read_bytes()
    truncated.write_bytes(data[: len(data) // 3])
    with pytest.raises(VaultError):
        VaultDatabase.open(truncated)


def test_corrupted_metadata_is_tamper_evident(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        vault.connection.execute("DELETE FROM dataset")
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
        with vault.transaction():
            mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT)
            # A statement-level FK violation is typed, leaves the transaction
            # usable, and inserts nothing.
            with pytest.raises(MappingError) as excinfo:
                mappings.add_text_mapping(
                    vault, "dom-unknown", "ORIGINAL", "PSEUDO", logical_byte_length=7
                )
            assert excinfo.value.code is ErrorCode.MAPPING_CONFLICT
            count = vault.connection.execute(
                "SELECT COUNT(*) FROM text_mappings"
            ).fetchone()
            assert int(count[0]) == 0
        # The clean exit commits only the valid domain row.
        vault.verify()
        assert len(mappings.mapping_domains(vault)) == 1


def test_structural_foreign_keys_reject_unknown_parents(tmp_path: Path) -> None:
    with _open_create(tmp_path) as vault:
        with vault.transaction():
            with pytest.raises(VaultError) as excinfo:
                vault.register_field("tbl-unknown", "NAME", dbf_type="C", width=10)
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
            with pytest.raises(VaultError):
                vault.record_publication("vop-unknown", "STAGE")
            with pytest.raises(VaultError):
                mappings.add_memo_recovery(
                    vault, "tbl-unknown", 0, "fld-unknown", b"payload",
                    payload_kind=mappings.VAULT_PAYLOAD_KIND_BINARY,
                )


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