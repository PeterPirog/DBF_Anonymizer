"""REQ-P5-004..P5-007 — safe standalone DATA_ONLY transfer bundle evidence.

Proves the transfer-bundle security cluster end to end: allowlisted creation
from a verified pseudonymized dataset, the sanitized versioned manifest with
per-artifact hashes, hostile-artifact/smuggling exclusion, standalone
verification of a COPIED bundle without source/vault/recovery material, the
complete tamper matrix, REQ-P1-008 progress/cancellation/callback
containment under ONE controller, privacy redaction canaries and truthful
capabilities. Only approved synthetic fixtures and disposable tmp_path data
created through the public ``dbfbridge`` writer are used; no production data
is accessed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import threading
from datetime import date, datetime
from pathlib import Path
from typing import Any

import dbfbridge
import pytest

import dbf_anonymizer
from dbf_anonymizer import (
    CallbackError,
    CancellationError,
    ErrorCode,
    ProgressEvent,
    PseudonymizationResult,
    RawByteEquivalence,
    TransferBundleResult,
    TransferError,
    TransferProfile,
    VerificationStatus,
    build_plan,
    create_transfer_bundle,
    preflight,
    pseudonymize,
    recover,
    verify_dataset,
    verify_transfer_bundle,
)
from dbf_anonymizer.transfer_bundle import (
    TRANSFER_MANIFEST_FILENAME,
    TRANSFER_MANIFEST_SCHEMA_VERSION,
    _forbidden_artifact_class,
)
from support.numeric_tables import NULLABLE_FLAG, numeric_field

_PATH_CANARY = "C:\\private\\canary\\source.dbf"
_VAULT_PATH_CANARY = "C:\\protected\\canary\\vault\\dictionary.sqlite3"
_VALUE_CANARY = "PARENT-CONFIDENTIAL-42"
_BINARY_CANARY = b"PROTECTED-BINARY-CANARY-\x00\x42"


# ---------------------------------------------------------------------------
# Synthetic fixture (public dbfbridge writer only)
# ---------------------------------------------------------------------------
def _relationship_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-text",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "north/data.dbf",
                        "field": "CODE",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "CODE",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                ],
            },
        ],
    }


def _binary_memo(name: str, dbf_type: str) -> dbfbridge.FieldInfo:  # type: ignore[attr-defined]
    return dbfbridge.FieldInfo(  # type: ignore[attr-defined]
        ordinal=0,
        name=name,
        dbf_type=dbf_type,
        length=4,
        decimal_count=0,
        address=0,
        flags=0,
        index_field_flag=0,
        autoincrement_next_value=0,
        autoincrement_step=1,
        is_memo=True,
        is_binary=True,
        supported=True,
        dbversion_byte=0x30,
    )


def _main_fields() -> tuple[object, ...]:
    return (
        numeric_field("CODE", "C", 12, flags=NULLABLE_FLAG),
        numeric_field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
        numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
        numeric_field("KEEP_N", "N", 6),
        numeric_field("KEEP_L", "L", 1),
    )



def _write_dataset(source: Path) -> None:
    from support.numeric_tables import schema as _schema

    def write(relative: str, fields: tuple[object, ...], entries: list[tuple[dict[str, object], bool]]) -> None:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        dbfbridge.write_table(  # type: ignore[attr-defined]
            path,
            schema=_schema(fields),
            records=[
                dbfbridge.DirectRecord(  # type: ignore[attr-defined]
                    physical_index=0, deleted=deleted, values=values
                )
                for values, deleted in entries
            ],
        )

    write(
        "north/data.dbf",
        _main_fields() + (_binary_memo("GEN", "G"),),
        [
            (
                {
                    "CODE": "PARENT-1",
                    "WHEN_D": date(2026, 3, 1),
                    "NOTE": "MEMO-N-1",
                    "KEEP_N": 11,
                    "KEEP_L": True,
                    "GEN": b"\x89SYNTHETIC-BINARY-\x00\x01",
                },
                False,
            ),
            (
                {
                    "CODE": "PARENT-2",
                    "WHEN_D": None,
                    "NOTE": None,
                    "KEEP_N": 22,
                    "KEEP_L": False,
                    "GEN": None,
                },
                True,
            ),
            (
                {
                    "CODE": "",
                    "WHEN_D": date(2026, 5, 20),
                    "NOTE": "",
                    "KEEP_N": 33,
                    "KEEP_L": None,
                    "GEN": b"",
                },
                False,
            ),
        ],
    )
    write(
        "south/data.dbf",
        _main_fields(),
        [
            (
                {
                    "CODE": "PARENT-1",
                    "WHEN_D": date(2026, 3, 2),
                    "NOTE": "MEMO-S-1",
                    "KEEP_N": 44,
                    "KEEP_L": False,
                },
                True,
            ),
            (
                {
                    "CODE": None,
                    "WHEN_D": None,
                    "NOTE": "MEMO-DUP-1",
                    "KEEP_N": 55,
                    "KEEP_L": None,
                },
                False,
            ),
        ],
    )
    # Duplicate basename in a separate directory + Varchar trailing spaces.
    write(
        "archive/data.dbf",
        (
            numeric_field("VCHAR", "V", 20, flags=NULLABLE_FLAG),
            numeric_field("PICTURE", "P", 4, flags=NULLABLE_FLAG),
            numeric_field("KEEP_I", "I", 4),
        ),
        [
            (
                {
                    "VCHAR": "TRAILING   ",
                    "PICTURE": b"PICTURE-BYTES-\x02",
                    "KEEP_I": 42,
                },
                False,
            ),
            (
                {"VCHAR": None, "PICTURE": None, "KEEP_I": -1},
                True,
            ),
        ],
    )


def _schema(fields: tuple[object, ...]) -> dbfbridge.TableSchema:  # type: ignore[attr-defined]
    from support.numeric_tables import schema as _schema_kernel

    return _schema(fields)  # type: ignore[return-value]


def _records(entries: list[tuple[dict[str, object], bool]]) -> list[dbfbridge.DirectRecord]:  # type: ignore[attr-defined]
    return [
        dbfbridge.DirectRecord(physical_index=0, deleted=deleted, values=values)  # type: ignore[attr-defined]
        for values, deleted in entries
    ]


def _prepare(tmp_path: Path) -> tuple[PseudonymizationResult, Path, Path, Path]:
    source = tmp_path / "source"
    _write_dataset(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(
        source, output, vault, relationship_document=_relationship_document()
    )
    assert preflight(plan).ready is True
    result = pseudonymize(plan)
    assert isinstance(result, dbf_anonymizer.PseudonymizationResult)
    return result, source, output, vault


def _hash_tree(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _create(
    result: PseudonymizationResult, tmp_path: Path
) -> TransferBundleResult:
    return create_transfer_bundle(
        result, destination=tmp_path / "bundle", profile="DATA_ONLY"
    )


def _read_manifest(bundle_root: Path) -> dict[str, object]:
    return json.loads(
        (bundle_root / "transfer-manifest.json").read_text(encoding="ascii")
    )

# ---------------------------------------------------------------------------
# Positive creation + standalone verification (copied bundle, no source/vault)
# ---------------------------------------------------------------------------
def test_clean_data_only_bundle_creation_and_standalone_pass(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    assert verify_dataset(result, source=source, vault=vault).status is (
        VerificationStatus.PASS
    )
    before_bundle = _hash_tree(tmp_path)
    bundle = _create(result, tmp_path)

    assert isinstance(bundle, TransferBundleResult)
    assert bundle.profile is TransferProfile.DATA_ONLY
    assert bundle.verified is True
    assert bundle.file_count == 6  # 3 DBF + 3 FPT
    manifest = _read_manifest(tmp_path / "bundle")
    assert manifest["schema_version"] == TRANSFER_MANIFEST_SCHEMA_VERSION
    assert manifest["profile"] == "DATA_ONLY"
    assert manifest["classification"] == "PSEUDONYMIZED"
    assert manifest["index_state"] == "DATA_ONLY_INDEX_OMITTED"
    paths = sorted(entry["path"] for entry in manifest["artifacts"])  # type: ignore[union-attr]
    assert paths == [
        "archive/data.dbf",
        "archive/data.fpt",
        "north/data.dbf",
        "north/data.fpt",
        "south/data.dbf",
        "south/data.fpt",
    ]
    # Strict allowlist: the bundle tree is exactly payload + manifest.
    inventory = sorted(_hash_tree(tmp_path / "bundle"))
    assert inventory == paths + ["transfer-manifest.json"]
    # The bundle creation left the working dataset and the vault untouched;
    # the only new artifacts are the bundle payload, the manifest, the
    # transient engine-owned lock artifact and the engine-owned
    # non-payload transaction marker of the P4 staging lifecycle (no
    # DBF/FPT/manifest payload remains inside staging after promotion).
    created = set(_hash_tree(tmp_path)) - set(before_bundle)
    bundle_files = {
        relative for relative in created if relative.startswith("bundle/")
    }
    lock_files = {name for name in created if name.endswith(".lock")}
    staging_residue = {name for name in created if ".staging" in name}
    assert created == bundle_files | lock_files | staging_residue
    for name in staging_residue:
        assert name.endswith("transaction.json")

    # Standalone verification of the COPIED bundle with source AND vault gone.
    copied = tmp_path / "copied"
    shutil.copytree(tmp_path / "bundle", copied)
    shutil.rmtree(source)
    shutil.rmtree(vault.parent)
    verification = verify_transfer_bundle(copied)
    assert verification.verified is True
    assert verification.profile is TransferProfile.DATA_ONLY
    assert verification.file_count == 6
    assert verification.manifest_fingerprint == bundle.manifest_fingerprint
    assert verification.assurance == result.assurance
    # The bundle itself stays byte-identical after verification.
    assert _hash_tree(copied) == _hash_tree(tmp_path / "bundle")


def test_bundle_verification_after_copy_to_another_directory(
    tmp_path: Path,
) -> None:
    """The bundle path is sufficient for standalone verification: the bundle
    is copied to a DIFFERENT directory tree (no source, no vault)."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    moved = tmp_path / "moved-elsewhere" / "bundle-copy"
    moved.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(tmp_path / "bundle", moved)
    shutil.rmtree(source)
    shutil.rmtree(vault.parent)
    verification = verify_transfer_bundle(moved)
    assert verification.verified is True


def test_manifest_never_carries_private_or_protected_data(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_text = (tmp_path / "bundle" / "transfer-manifest.json").read_text(
        encoding="ascii"
    )
    for canary in (
        "PARENT-1",
        "MEMO-N-1",
        "TRAILING   ",
        "offset",
        "recovery",
        "salt",
        str(source),
        str(output),
        str(vault),
        _PATH_CANARY,
        _VAULT_PATH_CANARY,
        _VALUE_CANARY,
    ):
        assert canary.lower() not in manifest_text.lower()
    # The bundle payload carries the PSEUDONYMIZED data only: the original
    # values survive nowhere outside the intentionally transformed DBF/FPT.
    for relative in _hash_tree(tmp_path / "bundle"):
        payload = (tmp_path / "bundle" / relative).read_bytes()
        for canary in ("PARENT-1", "MEMO-N-1", "TRAILING   ", "SUB-1"):
            assert canary not in payload.decode("latin-1")
        assert _BINARY_CANARY not in payload


def test_hostile_working_dataset_extra_artifacts_fail_closed(
    tmp_path: Path,
) -> None:
    """Injected hostile NON-PAYLOAD files invalidate the durable
    working-dataset fingerprint contract and are handled truthfully (no
    silent rewriting of the P4 identity model)."""
    result, source, output, vault = _prepare(tmp_path)
    (output / "dictionary.sqlite3").write_bytes(b"sqlite")
    (output / "debug.log").write_bytes(b"log")
    (output / "leftover.tmp").write_bytes(b"tmp")
    (output / "stale.cdx").write_bytes(b"cdx")
    (output / "stale.IDX").write_bytes(b"idx")
    (output / "container.DBC").write_bytes(b"dbc")
    (output / "north" / "unknown.bin").write_bytes(b"unknown")
    with pytest.raises(TransferError) as caught:
        _create(result, tmp_path)
    assert caught.value.context.detail_code == "TRANSFER_WORKING_DATASET_MISMATCH"
    assert caught.value.context.operation == "create_transfer_bundle"
    assert not (tmp_path / "bundle").exists()
    assert not any(tmp_path.glob("*.staging*"))


# ---------------------------------------------------------------------------
# Manifest schema/key-vocabulary pinning (REQ-P5-006)
# ---------------------------------------------------------------------------
def test_manifest_schema_vocabulary_is_pinned(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest = _read_manifest(tmp_path / "bundle")
    assert TRANSFER_MANIFEST_SCHEMA_VERSION == "1.0"
    assert set(manifest) == {
        "schema_version",
        "package_version",
        "dbfbridge_version",
        "profile",
        "classification",
        "dataset_id",
        "index_state",
        "verification_status",
        "artifacts",
        "assurance",
    }
    for entry in manifest["artifacts"]:  # type: ignore[union-attr]
        assert set(entry) == {
            "path",
            "artifact_type",
            "size_bytes",
            "sha256",
            "record_count",
            "schema_fingerprint",
        }
    assert set(manifest["assurance"]) == {  # type: ignore[union-attr]
        "level",
        "declared_relations",
        "verified_relations",
        "failed_relations",
        "incomplete_relations",
        "evidence_fingerprint",
        "relationship_fingerprint",
        "evidence_schema_version",
        "scope_note",
    }


# ---------------------------------------------------------------------------
# Tamper / smuggling matrix (no malicious fixture may accidentally PASS)
# ---------------------------------------------------------------------------
def _tamper(bundle_root: Path, relative: str, payload: bytes) -> None:
    target = bundle_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)


def _assert_standalone_fails(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(bundle_root)
    assert caught.value.context.operation == "verify_transfer_bundle"
    assert caught.value.code is ErrorCode.TRANSFER_FAILED
    # The rejected bundle must never be reported complete.
    assert not (tmp_path / "recovered").exists()


def test_missing_dbf_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    (tmp_path / "bundle" / "north" / "data.dbf").unlink()
    _assert_standalone_fails(tmp_path)


def test_missing_required_fpt_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    (tmp_path / "bundle" / "north" / "data.fpt").unlink()
    _assert_standalone_fails(tmp_path)


def test_unexpected_extra_fpt_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    (tmp_path / "bundle" / "south" / "data.fpt").unlink()
    (tmp_path / "bundle" / "south" / "data.fpt").write_bytes(
        (tmp_path / "bundle" / "north" / "data.fpt").read_bytes()
    )
    _assert_standalone_fails(tmp_path)


def test_modified_dbf_byte_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    with (tmp_path / "bundle" / "north" / "data.dbf").open("ab") as tampered:
        tampered.write(b"x")
    _assert_standalone_fails(tmp_path)


def test_modified_fpt_byte_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    with (tmp_path / "bundle" / "north" / "data.fpt").open("r+b") as tampered:
        tampered.seek(10)
        tampered.write(b"\xff")
    _assert_standalone_fails(tmp_path)


def test_manifest_hash_mismatch_fails_standalone(tmp_path: Path) -> None:
    import sqlite3  # noqa: F401

    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["artifacts"][0]["sha256"] = "0" * 64  # type: ignore[index]
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_manifest_size_mismatch_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["artifacts"][0]["size_bytes"] = 1  # type: ignore[index]
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_record_count_mismatch_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    for entry in manifest["artifacts"]:  # type: ignore[union-attr]
        if entry["artifact_type"] == "DBF":  # type: ignore[index]
            entry["record_count"] = 99  # type: ignore[index]
            break
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_schema_mismatch_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    for entry in manifest["artifacts"]:  # type: ignore[union-attr]
        if entry.get("schema_fingerprint"):
            entry["schema_fingerprint"] = "sch-tampered"  # type: ignore[index]
            break
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_unlisted_extra_file_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    (tmp_path / "bundle" / "smuggled.dbf").write_bytes(b"smuggled")
    _assert_standalone_fails(tmp_path)


def test_listed_missing_file_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["artifacts"].append(  # type: ignore[union-attr]
        {
            "path": "ghost/data.dbf",
            "artifact_type": "DBF",
            "size_bytes": 1,
            "sha256": "0" * 64,
            "record_count": 1,
            "schema_fingerprint": "sch-0",
        }
    )
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


@pytest.mark.parametrize(
    "smuggled_relative",
    [
        "DICTIONARY.SQLITE3",
        "nested/dictionary.sqlite3",
        "vault.sqlite3",
        "vault.sqlite3-wal",
        "vault.sqlite3-shm",
        "rollback.journal",
        "backup.db",
        "debug.log",
        "leftover.tmp",
        "private-manifest.json",
        "recovery-params.json",
        "reverse-mapping.txt",
        "stale.cdx",
        "standalone.idx",
        "container.dbc",
        "container.dct",
        "container.dcx",
        "unknown.bin",
        "payload.dll",
        "run.bat",
        "data.dbf.tmp",
    ],
)
def test_smuggled_artifacts_fail_standalone(
    tmp_path: Path, smuggled_relative: str
) -> None:
    """Hostile casing/nesting/name smuggling (allowlist + denylist)."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    smuggled = tmp_path / "bundle" / smuggled_relative
    smuggled.parent.mkdir(parents=True, exist_ok=True)
    smuggled.write_bytes(b"SMUGGLED-ARTIFACT")
    _assert_standalone_fails(tmp_path)


def test_duplicate_manifest_path_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    duplicate = dict(manifest["artifacts"][0])  # type: ignore[index]
    manifest["artifacts"].append(duplicate)  # type: ignore[union-attr]
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


@pytest.mark.parametrize(
    "unsafe_path",
    ["../escape.dbf", "north/../../escape.dbf", "C:/evil.dbf", "\\\\host\\evil.dbf"],
)
def test_unsafe_manifest_path_fails_standalone(
    tmp_path: Path, unsafe_path: str
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["artifacts"][0]["path"] = unsafe_path  # type: ignore[index]
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_case_collision_manifest_path_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    collision = dict(manifest["artifacts"][0])  # type: ignore[index]
    collision["path"] = str(collision["path"]).upper()  # type: ignore[index]
    manifest["artifacts"].append(collision)  # type: ignore[union-attr]
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_missing_manifest_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    (tmp_path / "bundle" / "transfer-manifest.json").unlink()
    _assert_standalone_fails(tmp_path)


def test_missing_bundle_directory_fails_standalone(tmp_path: Path) -> None:
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "missing-bundle")
    assert caught.value.context.detail_code == "TRANSFER_BUNDLE_MISSING"


def test_unsupported_manifest_schema_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["schema_version"] = "9.9"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_anonymous_classification_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["classification"] = "ANONYMOUS"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_false_index_state_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["index_state"] = "VFP_INDEX_VERIFIED"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_transfer_bundle_denies_forbidden_artifact_classes() -> None:
    """The denylist is CLASSIFICATION-based (hostile names/casing/nesting
    cannot bypass it); the allowlist stays authoritative."""
    for hostile in (
        "DICTIONARY.SQLITE3",
        "nested/dictionary.sqlite3",
        "foo.sqlite3-wal",
        "foo.sqlite-wal",
        "x.sqlite-shm",
        "rollback.journal",
        "backup.sqlite",
        "backup.sqlite3",
        "debug.log",
        "private-manifest.json",
        "source-manifest.json",
        "reverse-mapping.txt",
        "recovery-params.json",
        "data.dbf.tmp",
        "data.dbf.lock",
        "stale.cdx",
        "STALE.IDX",
        "container.dbc",
        "container.DCT",
        "container.dcx",
        "unknown.bin",
        "payload.exe",
        "payload.dll",
        "script.py",
        "run.bat",
        "run.cmd",
        "run.ps1",
        "run.sh",
        ".hidden",
        "~$lockfile",
        "keyfile.txt",
        "salt.txt",
        "temp-state.json",
    ):
        assert _forbidden_artifact_class(hostile) is not None, hostile
    for transferable in (
        "north/data.dbf",
        "north/data.fpt",
        "transfer-manifest.json",
        "archive/data.dbf",
    ):
        assert _forbidden_artifact_class(transferable) is None, transferable


def test_transfer_bundle_rejects_invalid_contracts(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    with pytest.raises(TypeError):
        create_transfer_bundle(  # type: ignore[arg-type]
            object(),
            destination=tmp_path / "bundle",
        )
    with pytest.raises(TransferError) as unsupported:
        create_transfer_bundle(
            result,
            destination=tmp_path / "bundle-vfp",
            profile="VFP_INDEXED",
        )
    assert unsupported.value.context.detail_code == "TRANSFER_PROFILE_UNSUPPORTED"
    with pytest.raises(TransferError) as missing:
        verify_transfer_bundle(tmp_path / "missing-bundle")
    assert missing.value.context.detail_code == "TRANSFER_BUNDLE_MISSING"
    with pytest.raises(TypeError):
        verify_transfer_bundle(object())  # type: ignore[arg-type]
    (tmp_path / "bundle-dir").mkdir()
    with pytest.raises(TransferError) as no_manifest:
        verify_transfer_bundle(tmp_path / "bundle-dir")
    assert no_manifest.value.context.detail_code == "TRANSFER_MANIFEST_MISSING"


# ---------------------------------------------------------------------------
# Progress / cancellation / callback containment (REQ-P1-008)
# ---------------------------------------------------------------------------
class _Recorder:
    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []
        self.threads: list[int] = []

    def __call__(self, event: ProgressEvent) -> None:
        self.events.append(event)
        self.threads.append(threading.get_ident())

    def phase(self, phase_code: str, event_code: str) -> list[ProgressEvent]:
        return [
            event
            for event in self.events
            if event.phase_code == phase_code and event.event_code == event_code
        ]

    def completed(self) -> list[ProgressEvent]:
        return [event for event in self.events if event.event_code == "COMPLETED"]


def test_creation_progress_is_one_operation_with_bounded_phases(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    recorder = _Recorder()
    bundle = create_transfer_bundle(
        result,
        destination=tmp_path / "bundle",
        progress=recorder,
    )
    assert bundle.verified is True
    events = recorder.events
    assert events
    # ONE operation id across all events of the creation operation.
    ids = {event.operation_id for event in events}
    assert len(ids) == 1
    for phase_code in (
        "OPERATION",
        "SOURCE_VERIFICATION",
        "TRANSFER_SCAN",
        "PUBLICATION",
    ):
        started = recorder.phase(phase_code, "STARTED")
        assert started, phase_code
    order = [
        events.index(recorder.phase(phase, "STARTED")[0])
        for phase in ("OPERATION", "SOURCE_VERIFICATION", "TRANSFER_SCAN", "PUBLICATION")
    ]
    assert order == sorted(order)
    completed = recorder.completed()
    assert len(completed) == 1
    assert events[-1] is completed[0]
    assert set(recorder.threads) == {threading.get_ident()}
    # Privacy-safe events.
    serialized = json.dumps([event.to_dict() for event in events], sort_keys=True)
    for canary in ("PARENT-1", str(source), str(vault), _PATH_CANARY, _VAULT_PATH_CANARY):
        assert canary not in serialized


def test_verification_progress_is_one_operation_with_bounded_phases(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    recorder = _Recorder()
    verification = verify_transfer_bundle(
        tmp_path / "bundle", progress=recorder
    )
    assert verification.verified is True
    events = recorder.events
    ids = {event.operation_id for event in events}
    assert len(ids) == 1
    assert recorder.phase("OPERATION", "STARTED")
    assert recorder.phase("SOURCE_VERIFICATION", "STARTED")
    assert recorder.phase("TABLE_EVALUATION", "STARTED")
    assert recorder.phase("VERIFICATION", "STARTED")
    completed = recorder.completed()
    assert len(completed) == 1
    assert events[-1] is completed[0]
    assert set(recorder.threads) == {threading.get_ident()}


@pytest.mark.parametrize(
    "phase_code", ["SOURCE_VERIFICATION", "TRANSFER_SCAN", "PUBLICATION"]
)
def test_cancellation_during_bundle_creation_is_typed_and_side_effect_free(
    tmp_path: Path, phase_code: str
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    events: list[ProgressEvent] = []
    state = {"cancel": False}

    def progress(event: ProgressEvent) -> None:
        events.append(event)
        if event.phase_code == phase_code and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(CancellationError) as caught:
        create_transfer_bundle(
            result,
            destination=tmp_path / "bundle",
            progress=progress,
            cancel_check=lambda: state["cancel"],
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "create_transfer_bundle"
    assert not any(event.event_code == "COMPLETED" for event in events)
    assert not (tmp_path / "bundle").exists()
    after = _hash_tree(tmp_path)
    created = set(after) - set(before)
    assert not any(name.endswith(".staging") for name in created) or all(
        name.endswith("transaction.json") for name in created if ".staging" in name
    )
    assert _hash_tree(output) == {
        key[len("output/"):]: value
        for key, value in before.items()
        if key.startswith("output/")
    }
    assert _hash_tree(vault.parent) == {
        key[len("vault/"):]: value
        for key, value in before.items()
        if key.startswith("vault/")
    }


def test_cancellation_during_standalone_verification_is_typed(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    bundle_state = _hash_tree(tmp_path / "bundle")
    events: list[ProgressEvent] = []
    state = {"cancel": False}

    def progress(event: ProgressEvent) -> None:
        events.append(event)
        if event.phase_code == "VERIFICATION" and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(CancellationError) as caught:
        verify_transfer_bundle(
            tmp_path / "bundle",
            progress=progress,
            cancel_check=lambda: state["cancel"],
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "verify_transfer_bundle"
    assert not any(event.event_code == "COMPLETED" for event in events)
    # Standalone verification mutates nothing.
    assert _hash_tree(tmp_path / "bundle") == bundle_state


@pytest.mark.parametrize("operation", ["create", "verify"])
def test_transfer_callback_failures_are_contained_and_typed(
    tmp_path: Path, operation: str
) -> None:
    canary = "PRIVATE-TRANSFER-CALLBACK-CANARY-" + _PATH_CANARY
    received: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        received.append(event)
        if (
            event.phase_code
            in ("TRANSFER_SCAN", "VERIFICATION", "SOURCE_VERIFICATION")
            and event.event_code == "STARTED"
        ):
            raise RuntimeError(canary)

    if operation == "create":
        result, source, output, vault = _prepare(tmp_path)
        with pytest.raises(CallbackError) as caught:
            create_transfer_bundle(
                result, destination=tmp_path / "bundle", progress=progress
            )
        assert not (tmp_path / "bundle").exists()
    else:
        result, source, output, vault = _prepare(tmp_path)
        _create(result, tmp_path)
        bundle_state = _hash_tree(tmp_path / "bundle")
        with pytest.raises(CallbackError) as caught:
            verify_transfer_bundle(tmp_path / "bundle", progress=progress)
        assert _hash_tree(tmp_path / "bundle") == bundle_state
    assert caught.value.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert caught.value.context.operation in (
        "create_transfer_bundle",
        "verify_transfer_bundle",
    )
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.to_dict())
    assert received


def test_public_result_serialization_stays_privacy_safe(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    bundle = _create(result, tmp_path)
    serialized = json.dumps(bundle.to_dict(), sort_keys=True)
    for canary in (
        "PARENT-1",
        "MEMO-N-1",
        str(source),
        str(output),
        str(vault),
        _PATH_CANARY,
        _VAULT_PATH_CANARY,
    ):
        assert canary not in serialized
    assert bundle.bundle_path == "bundle"
    verification = verify_transfer_bundle(tmp_path / "bundle")
    verification_serialized = json.dumps(verification.to_dict(), sort_keys=True)
    for canary in ("PARENT-1", "MEMO-N-1", str(source), str(vault), _PATH_CANARY):
        assert canary not in verification_serialized
