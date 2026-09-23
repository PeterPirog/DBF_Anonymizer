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
import sys
import threading
from datetime import date, datetime
from pathlib import Path
from typing import Any

import dbfbridge
import pytest

import dbf_anonymizer
from dbf_anonymizer import (
    CallbackError,
    ErrorContext as _ErrorContext,
    CancellationError,
    ErrorCode,
    PathError,
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
    # the only new artifacts are the bundle payload and the transient
    # engine-owned lock artifact. The successful private staging lifecycle
    # leaves NO residue at all (REQ-P5-008 step 13: the staging root with
    # its crash-state record is removed after the genuine promotion).
    created = set(_hash_tree(tmp_path)) - set(before_bundle)
    bundle_files = {
        relative for relative in created if relative.startswith("bundle/")
    }
    lock_files = {name for name in created if name.endswith(".lock")}
    assert created == bundle_files | lock_files
    assert not any(".staging" in name for name in created)

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
    # The internal P5-001 verification precondition fires FIRST: the
    # injected hostile artifacts are classified as unexpected output
    # artifacts by the authoritative verifier, so the working dataset is no
    # longer an objectively verified publication (no silent rewriting of
    # the P4 identity model, no bundle, no staging residue).
    assert caught.value.context.detail_code == "TRANSFER_DATASET_NOT_VERIFIED"
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
    # Cancellation before the atomic promotion publishes nothing and leaves
    # NO private staging residue: only owned pre-promotion staging was
    # created and it is fully cleaned by the typed cancellation path.
    assert not any(name.endswith(".staging") for name in created)
    assert not any(".staging" in name for name in created)
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


# ---------------------------------------------------------------------------
# Strict closed manifest schema (REQ-P5-005/REQ-P5-006 blockers)
# ---------------------------------------------------------------------------
def _tamper_manifest(bundle_root: Path, mutate: Callable[[dict], None]) -> None:
    manifest_path = bundle_root / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    mutate(manifest)
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )


@pytest.mark.parametrize(
    "extra_key,extra_value",
    [
        ("vault_path", "C:\\protected\\dictionary.sqlite3"),
        ("original_value", "PARENT-CONFIDENTIAL-42"),
        ("temporal_offset", 1234),
        ("reverse_mapping", {"CODE": "SECRET"}),
        ("debug", {"trace": True}),
        ("private_metadata", "x"),
    ],
)
def test_top_level_unknown_manifest_keys_fail_standalone(
    tmp_path: Path, extra_key: str, extra_value: object
) -> None:
    """A hostile transferred manifest can NEVER add private fields and still
    verify: schema 1.0 requires EXACTLY the allowed top-level keys."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest[extra_key] = extra_value

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_SCHEMA_INVALID"
    assert caught.value.context.operation == "verify_transfer_bundle"
    serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    for canary in (
        "PARENT-CONFIDENTIAL-42",
        "SECRET",
        "dictionary.sqlite3",
    ):
        assert canary not in serialized
        assert canary not in repr(caught.value)


@pytest.mark.parametrize(
    "extra_key,extra_value",
    [
        ("original_value", "SECRET"),
        ("private_path", "C:\\secret\\x"),
        ("vault_path", "C:\\protected\\dictionary.sqlite3"),
        ("mapping", {"a": "b"}),
        ("offset", 1234),
        ("debug", True),
    ],
)
def test_artifact_entry_unknown_keys_fail_standalone(
    tmp_path: Path, extra_key: str, extra_value: object
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["artifacts"][0][extra_key] = extra_value  # type: ignore[index]

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_SCHEMA_INVALID"
    serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    assert "SECRET" not in serialized


def test_assurance_unknown_key_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["assurance"]["reverse_mapping"] = "SECRET"

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_SCHEMA_INVALID"
    assert "SECRET" not in json.dumps(caught.value.to_dict(), sort_keys=True)


def test_missing_top_level_key_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest.pop("dataset_id")

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_SCHEMA_INVALID"


def test_missing_artifact_key_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["artifacts"][0].pop("sha256")  # type: ignore[index]

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_SCHEMA_INVALID"


def test_missing_assurance_key_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["assurance"].pop("declared_relations")

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_SCHEMA_INVALID"


def test_wrong_verification_status_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["verification_status"] = "UNVERIFIED"

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_VERIFICATION_STATUS_INVALID"


def test_wrong_scalar_types_fail_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["package_version"] = 1
        manifest["dbfbridge_version"] = ["1.1.1"]
        manifest["dataset_id"] = None

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_VALUE_INVALID"


def test_absolute_path_in_dataset_id_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["dataset_id"] = "C:\\evil\\dataset"

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError):
        verify_transfer_bundle(tmp_path / "bundle")


def test_renamed_dbf_payload_with_dbf_type_fails_standalone(tmp_path: Path) -> None:
    """The bidirectional artifact-type/extension binding (REQ-P5-005): a
    valid DBF renamed to an arbitrary extension can never be accepted merely
    because dbfbridge can parse its bytes — DATA_ONLY allows DBF/FPT by
    artifact CLASS, not by parseability."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    bundle_root = tmp_path / "bundle"
    renamed = bundle_root / "north" / "payload.db"
    (bundle_root / "north" / "data.dbf").rename(renamed)
    manifest = _read_manifest(bundle_root)
    for entry in manifest["artifacts"]:  # type: ignore[union-attr]
        if entry["path"] == "north/data.dbf":  # type: ignore[index]
            entry["path"] = "north/payload.db"  # type: ignore[index]
    (bundle_root / "transfer-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


def test_fpt_extension_type_mismatch_fails_standalone(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    bundle_root = tmp_path / "bundle"
    manifest = _read_manifest(bundle_root)
    for entry in manifest["artifacts"]:  # type: ignore[union-attr]
        if entry["path"] == "north/data.fpt":  # type: ignore[index]
            entry["artifact_type"] = "DBF"  # type: ignore[index]
    (bundle_root / "transfer-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    _assert_standalone_fails(tmp_path)


# ---------------------------------------------------------------------------
# Malformed assurance stays typed (no raw ValueError/TypeError escapes)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "mutate",
    [
        lambda manifest: manifest["assurance"].update(
            {"level": "TOTALLY_UNKNOWN_LEVEL"}
        ),
        lambda manifest: manifest["assurance"].update({"declared_relations": -3}),
        lambda manifest: manifest["assurance"].update({"verified_relations": True}),
        lambda manifest: manifest["assurance"].update({"verified_relations": 99}),
        lambda manifest: manifest["assurance"].update({"evidence_fingerprint": 12345}),
        lambda manifest: manifest["assurance"].update({"scope_note": "x\x00y"}),
        lambda manifest: manifest["assurance"].update({"level": None}),
    ],
    ids=[
        "unknown-level",
        "negative-count",
        "boolean-count",
        "inconsistent-totals",
        "malformed-fingerprint",
        "malformed-scope-note",
        "non-string-level",
    ],
)
def test_malformed_assurance_is_typed_not_raw(
    tmp_path: Path, mutate: Callable[[dict], None]
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.code is ErrorCode.TRANSFER_FAILED
    assert caught.value.context.detail_code in {
        "TRANSFER_MANIFEST_VALUE_INVALID",
        "TRANSFER_MANIFEST_UNREADABLE",
    }
    assert caught.value.context.operation == "verify_transfer_bundle"


def test_oversized_manifest_fails_before_parsing(tmp_path: Path) -> None:
    """The untrusted manifest input boundary: a huge hostile manifest is
    rejected by the bounded byte limit BEFORE json parsing."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    padding = "x" * 1_100_000
    manifest_path.write_bytes(('{"padding": "' + padding + '"}').encode("ascii"))
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_TOO_LARGE"


# ---------------------------------------------------------------------------
# Verified-dataset precondition (create enforces P5-001 itself)
# ---------------------------------------------------------------------------
def test_creation_refuses_when_output_dbf_is_corrupted(tmp_path: Path) -> None:
    """Deliberate pseudonymized output corruption: create refuses BEFORE any
    final bundle publication (the internal P5-001 verification detects the
    tampering)."""
    result, source, output, vault = _prepare(tmp_path)
    with (output / "north" / "data.fpt").open("r+b") as tampered:
        tampered.seek(20)
        tampered.write(b"\xff\xfe")
    with pytest.raises(TransferError) as caught:
        _create(result, tmp_path)
    assert caught.value.context.detail_code == "TRANSFER_DATASET_NOT_VERIFIED"
    assert not (tmp_path / "bundle").exists()
    assert not any(tmp_path.glob("*.staging*"))


def test_creation_refuses_after_vault_mapping_corruption(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "DELETE FROM text_mappings WHERE original_value = 'PARENT-1'"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(TransferError) as caught:
        _create(result, tmp_path)
    # The internal P5-001 verification detects the mapping/privacy violation.
    assert caught.value.context.detail_code == "TRANSFER_DATASET_NOT_VERIFIED"
    assert not (tmp_path / "bundle").exists()
    assert not any(tmp_path.glob("*.staging*"))


def test_creation_refuses_after_source_change(tmp_path: Path) -> None:
    """Source changed since pseudonymization: the P5-001 source-immutability
    verification refuses the export (create itself enforces the
    precondition, not just the test setup)."""
    result, source, output, vault = _prepare(tmp_path)
    with (source / "north" / "data.dbf").open("ab") as changed:
        changed.write(b"changed-after-pseudonymization")
    with pytest.raises(TransferError) as caught:
        _create(result, tmp_path)
    assert caught.value.context.detail_code == "TRANSFER_DATASET_NOT_VERIFIED"
    assert not (tmp_path / "bundle").exists()


def test_cancellation_during_internal_verification_is_create_owned(
    tmp_path: Path,
) -> None:
    """Cancellation during create's INTERNAL P5-001 verification surfaces as
    OPERATION_CANCELLED with operation=create_transfer_bundle (never
    verify_dataset), no final bundle and no COMPLETED event."""
    result, source, output, vault = _prepare(tmp_path)
    events: list[ProgressEvent] = []
    state = {"cancel": False}

    def progress(event: ProgressEvent) -> None:
        events.append(event)
        if event.phase_code == "VAULT_VERIFICATION" and event.event_code == "STARTED":
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
    assert not any(tmp_path.glob("*.staging*"))


# ---------------------------------------------------------------------------
# Staged bundle self-verification (verified=True is bundle-evidenced)
# ---------------------------------------------------------------------------
def _inject_staged_fault(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deterministic fault injection AFTER payload copy but BEFORE promotion:
    corrupt the staged tree, then run the REAL standalone validation core so
    creation must detect the fault through bundle evidence."""
    import dbf_anonymizer.transfer_bundle as transfer_module

    original_verify = transfer_module._verify_bundle_core

    def corrupting_then_verifying(bundle_root: Path, **kwargs: object) -> object:
        if kind == "dbf-byte":
            with (bundle_root / "north" / "data.dbf").open("ab") as tampered:
                tampered.write(b"tampered")
        elif kind == "fpt-byte":
            with (bundle_root / "north" / "data.fpt").open("r+b") as tampered:
                tampered.seek(12)
                tampered.write(b"\xff")
        elif kind == "manifest":
            manifest_path = bundle_root / "transfer-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="ascii"))
            manifest["artifacts"][0]["sha256"] = "0" * 64  # type: ignore[index]
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
        elif kind == "extra":
            (bundle_root / "smuggled.dbf").write_bytes(b"smuggled")
        elif kind == "missing-fpt":
            (bundle_root / "north" / "data.fpt").unlink()
        else:
            raise AssertionError(kind)
        return original_verify(bundle_root, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        transfer_module, "_verify_bundle_core", corrupting_then_verifying
    )


@pytest.mark.parametrize(
    "kind", ["dbf-byte", "fpt-byte", "manifest", "extra", "missing-fpt"]
)
def test_staged_fault_refuses_promotion_and_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    _inject_staged_fault(kind, monkeypatch)
    with pytest.raises(TransferError):
        create_transfer_bundle(
            result, destination=tmp_path / "bundle", profile="DATA_ONLY"
        )
    # The staged verification detected the corruption: nothing was promoted.
    assert not (tmp_path / "bundle").exists()
    after = _hash_tree(tmp_path)
    created = set(after) - set(before)
    assert not any(name.startswith("bundle/") for name in created)
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


# ---------------------------------------------------------------------------
# Actual-filesystem case-collision protection + portable path validation
# ---------------------------------------------------------------------------
def test_casefold_inventory_helper_detects_collisions() -> None:
    """Pure-helper regression (platform-independent): two actual names that
    differ only by case are an explicit collision, never silently
    collapsed."""
    from dbf_anonymizer.transfer_bundle import _casefold_inventory

    assert _casefold_inventory(
        ["north/data.dbf", "south/data.fpt"], failure=_standalone_probe
    ) == {
        "north/data.dbf": "north/data.dbf",
        "south/data.fpt": "south/data.fpt",
    }
    for hostile in (
        ["north/data.dbf", "NORTH/DATA.DBF"],
        ["transfer-manifest.json", "TRANSFER-MANIFEST.JSON"],
        ["north/data.fpt", "NORTH/DATA.FPT"],
    ):
        with pytest.raises(TransferError) as caught:
            _casefold_inventory(hostile, failure=_standalone_probe)
        assert caught.value.context.detail_code == "TRANSFER_INVENTORY_CASE_COLLISION"
        assert caught.value.context.operation == "verify_transfer_bundle"


def _standalone_probe(detail_code: str) -> TransferError:
    return TransferError(
        ErrorCode.TRANSFER_FAILED,
        context=_ErrorContext(
            operation="verify_transfer_bundle", detail_code=detail_code
        ),
    )


def test_normalized_artifact_path_rejects_cross_platform_forms() -> None:
    """Direct pure-helper regression: the normalizer itself (not an
    inventory side effect) refuses drive-qualified/rooted/absolute/UNC and
    traversal forms under BOTH path grammars."""
    from dbf_anonymizer.transfer_bundle import _normalized_artifact_path

    for hostile in (
        "C:/evil.dbf",
        "C:\\evil.dbf",
        "\\\\host\\\\share\\\\evil.dbf",
        "/absolute/evil.dbf",
        "../evil.dbf",
        "north/../../evil.dbf",
        "//server/share/evil.dbf",
        "north/../../../x.dbf",
    ):
        with pytest.raises(TransferError) as caught:
            _normalized_artifact_path(hostile, failure=_standalone_probe)
        assert (
            caught.value.context.detail_code == "TRANSFER_MANIFEST_PATH_INVALID"
        ), hostile
    for valid in ("north/data.dbf", "archive/data.fpt", "transfer-manifest.json"):
        assert (
            _normalized_artifact_path(valid, failure=_standalone_probe) == valid
        )


def test_posix_drive_qualified_actual_path_fails_standalone(
    tmp_path: Path,
) -> None:
    """Where the platform permits a physical ``C:`` directory component, the
    manifest entry is refused by path normalization BEFORE payload checks."""
    if sys.platform == "win32":
        pytest.skip("Windows cannot create a 'C:' directory component")
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    bundle_root = tmp_path / "bundle"
    hostile_dir = bundle_root / "C:"
    hostile_dir.mkdir()
    (hostile_dir / "evil.dbf").write_bytes(b"evil")
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(bundle_root)
    assert caught.value.context.detail_code in {
        "TRANSFER_MANIFEST_PATH_INVALID",
        "TRANSFER_FORBIDDEN_ARTIFACT",
    }


def test_fpt_case_collision_synthetic_fails(tmp_path: Path) -> None:
    """FPT case collision (synthetic evidence on every platform)."""
    from dbf_anonymizer.transfer_bundle import _casefold_inventory

    with pytest.raises(TransferError) as caught:
        _casefold_inventory(
            ["north/data.fpt", "NORTH/DATA.FPT"], failure=_standalone_probe
        )
    assert caught.value.context.detail_code == "TRANSFER_INVENTORY_CASE_COLLISION"


# ---------------------------------------------------------------------------
# TRUE readability: corruption with RECOMPUTED manifest hashes (blocker C)
# ---------------------------------------------------------------------------
def _recompute_manifest(bundle_root: Path) -> None:
    """Attacker upgrade: corrupt a payload AND refresh its manifest
    hash/size so hashes PASS — only logical readability can detect it."""
    manifest_path = bundle_root / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    for entry in manifest["artifacts"]:  # type: ignore[union-attr]
        payload = bundle_root / str(entry["path"])
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        entry["sha256"] = digest
        entry["size_bytes"] = payload.stat().st_size
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )


def test_truncated_dbf_with_recomputed_hash_fails_standalone(
    tmp_path: Path,
) -> None:
    """A DBF whose record area is truncated (header still readable) with a
    RECOMPUTED manifest hash/size: hashes PASS and only the streamed record
    read/count detects the defect."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    bundle_root = tmp_path / "bundle"
    payload = (bundle_root / "north" / "data.dbf").read_bytes()
    (bundle_root / "north" / "data.dbf").write_bytes(payload[: len(payload) // 2])
    _recompute_manifest(bundle_root)
    with pytest.raises((TransferError, dbf_anonymizer.DBFBridgeError)):
        verify_transfer_bundle(bundle_root)
    # The typed classification covers the structured dependency refusal
    # (an unreadable/truncated table) as well as the streamed count defect;
    # the bundle was never reported complete either way.
    assert not (tmp_path / "bundle" / "smuggled.dbf").exists()


def test_corrupted_fpt_with_recomputed_hash_fails_standalone(
    tmp_path: Path,
) -> None:
    """An FPT used by a live memo record is corrupted/truncated and the
    manifest hash/size recomputed: the DBF schema remains readable and only
    the INLINE memo payload read detects the defect."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    bundle_root = tmp_path / "bundle"
    payload = (bundle_root / "north" / "data.fpt").read_bytes()
    (bundle_root / "north" / "data.fpt").write_bytes(payload[:12])
    _recompute_manifest(bundle_root)
    with pytest.raises((TransferError, dbf_anonymizer.DBFBridgeError)):
        verify_transfer_bundle(bundle_root)
    # The typed refusal covers the structured dependency failure (an
    # unreadable memo companion) as well as the streamed-count defect; the
    # bundle was never reported complete either way.


def test_staged_fpt_corruption_with_consistent_manifest_refuses_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Staged creation fault: after copy + manifest generation but BEFORE
    promotion, an FPT is corrupted AND its manifest hash/size updated
    consistently — the staged self-verification must STILL refuse promotion
    because the FPT logical read fails inside the streamed verification."""
    import dbf_anonymizer.transfer_bundle as transfer_module

    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    original_verify = transfer_module._verify_bundle_core

    def corrupting_then_verifying(bundle_root: Path, **kwargs: object) -> object:
        payload = (bundle_root / "north" / "data.fpt").read_bytes()
        (bundle_root / "north" / "data.fpt").write_bytes(payload[:10])
        # The attacker updates the manifest hash/size consistently.
        manifest_path = bundle_root / "transfer-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        for entry in manifest["artifacts"]:  # type: ignore[union-attr]
            if entry["path"] == "north/data.fpt":  # type: ignore[index]
                entry["sha256"] = hashlib.sha256(
                    (bundle_root / "north" / "data.fpt").read_bytes()
                ).hexdigest()
                entry["size_bytes"] = 12
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        return original_verify(bundle_root, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        transfer_module, "_verify_bundle_core", corrupting_then_verifying
    )
    with pytest.raises((TransferError, dbf_anonymizer.DBFBridgeError)):
        create_transfer_bundle(
            result, destination=tmp_path / "bundle", profile="DATA_ONLY"
        )
    assert not (tmp_path / "bundle").exists()
    after = _hash_tree(tmp_path)
    assert not any(name.startswith("bundle/") for name in set(after) - set(before))
    assert _hash_tree(output) == {
        key[len("output/"):]: value
        for key, value in before.items()
        if key.startswith("output/")
    }


# ---------------------------------------------------------------------------
# Strict assurance value sanitization (blocker D)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "mutate,canary",
    [
        (
            lambda manifest: manifest["assurance"].update(
                {"scope_note": "C:\\private\\canary\\vault"}
            ),
            "C:\\private\\canary\\vault",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {"evidence_fingerprint": "z" * 64}
            ),
            "z" * 64,
        ),
        # NOTE: the relationship_fingerprint is deliberately NOT held to the
        # hex contract (round-5 blocker A): the public P3 RelationshipMetadata
        # contract accepts bounded non-hex tokens; hostile non-hex forms are
        # covered by test_hostile_relationship_fingerprint_tokens_fail_...
        (
            lambda manifest: manifest["assurance"].update(
                {"evidence_schema_version": "PRIVATE_PATH_CANARY"}
            ),
            "PRIVATE_PATH_CANARY",
        ),
    ],
    ids=["scope-note", "evidence-fp", "evidence-version"],
)
def test_hostile_assurance_values_fail_and_stay_redacted(
    tmp_path: Path, mutate: Callable[[dict], None], canary: str
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_VALUE_INVALID"
    serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    assert canary not in serialized
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


def test_assurance_counts_must_be_complete(tmp_path: Path) -> None:
    """declared=5 with the three counters summing to 4: a declared relation
    may never disappear from the accounting."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["assurance"]["declared_relations"] = 5
        manifest["assurance"]["verified_relations"] = 4
        manifest["assurance"]["failed_relations"] = 0
        manifest["assurance"]["incomplete_relations"] = 0

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_VALUE_INVALID"


def test_duplicate_json_keys_fail_standalone(tmp_path: Path) -> None:
    """Duplicate JSON object keys are rejected BEFORE they are collapsed by
    json.loads (an ANONYMOUS/PSEUDONYMIZED duplicate must never be
    interpreted as last-value-wins)."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    duplicated = (
        '{"classification": "ANONYMOUS", "classification": "PSEUDONYMIZED",'
        ' "schema_version": "1.0", "package_version": "1.0.0.dev0",'
        ' "dbfbridge_version": "1.1.1", "profile": "DATA_ONLY",'
        ' "dataset_id": "ds-0000000000000000", "index_state":'
        ' "DATA_ONLY_INDEX_OMITTED", "verification_status":'
        ' "CREATION_SELF_VERIFIED", "artifacts": [{"path": "x.dbf",'
        ' "artifact_type": "DBF", "size_bytes": 1, "sha256": "0",'
        ' "record_count": 1, "schema_fingerprint": "sch-0"}], "assurance":'
        ' {"level": "INCOMPLETE", "declared_relations": 0,'
        ' "verified_relations": 0, "failed_relations": 0,'
        ' "incomplete_relations": 0, "evidence_fingerprint": null,'
        ' "relationship_fingerprint": null, "evidence_schema_version":'
        ' "1.0", "scope_note": "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"}}'
    )
    (tmp_path / "bundle" / "transfer-manifest.json").write_text(
        duplicated, encoding="ascii"
    )
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_DUPLICATE_KEY"
    assert "ANONYMOUS" not in json.dumps(caught.value.to_dict(), sort_keys=True)


def test_public_error_attribution_create_vs_verify(tmp_path: Path) -> None:
    """The shared private bundle verifier core attributes every typed
    failure to the OWNING public operation: standalone verification failures
    say verify_transfer_bundle; staged self-verification failures inside
    creation say create_transfer_bundle."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    _tamper_manifest(
        tmp_path / "bundle",
        lambda manifest: manifest.update({"extra": 1}),
    )
    with pytest.raises(TransferError) as verify_failure:
        verify_transfer_bundle(tmp_path / "bundle")
    assert verify_failure.value.context.operation == "verify_transfer_bundle"

    import dbf_anonymizer.transfer_bundle as transfer_module

    original_verify = transfer_module._verify_bundle_core

    def corrupting_then_verifying(bundle_root: Path, **kwargs: object) -> object:
        manifest_path = bundle_root / "transfer-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["extra"] = 1
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        return original_verify(bundle_root, **kwargs)  # type: ignore[arg-type]

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            transfer_module, "_verify_bundle_core", corrupting_then_verifying
        )
        with pytest.raises(TransferError) as create_failure:
            create_transfer_bundle(
                result, destination=tmp_path / "bundle2", profile="DATA_ONLY"
            )
    finally:
        monkeypatch.undo()
    # The staged self-verification failure is attributed to the OWNING
    # create_transfer_bundle operation (never verify_transfer_bundle).
    assert create_failure.value.context.operation == "create_transfer_bundle"
    assert create_failure.value.context.detail_code == "TRANSFER_MANIFEST_SCHEMA_INVALID"


def test_complete_public_workflow_without_private_imports(tmp_path: Path) -> None:
    """REQ-P1-004 consumer evidence: the COMPLETE workflow executes through
    PUBLIC imports only (no private implementation module is imported):
    build_plan -> preflight -> pseudonymize -> verify_dataset ->
    create_transfer_bundle -> verify_transfer_bundle -> recover."""
    import dbf_anonymizer as public

    source = tmp_path / "source"
    _write_dataset(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan = public.build_plan(
        source, output, vault, relationship_document=_relationship_document()
    )
    assert public.preflight(plan).ready is True
    result = public.pseudonymize(plan)
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS
    bundle = public.create_transfer_bundle(
        result, destination=tmp_path / "bundle", profile="DATA_ONLY"
    )
    assert bundle.verified is True
    standalone = public.verify_transfer_bundle(tmp_path / "bundle")
    assert standalone.verified is True
    recovery = public.recover(
        pseudonymized=output, vault=vault, output=tmp_path / "recovered"
    )
    assert recovery.canonical_verified is True
    # Truthful capability facts for the complete surface.
    caps = public.capabilities()
    assert caps.recovery is True
    assert caps.transfer_bundle is True
    assert caps.vfp_index_backend is False
    # The recovered dataset is canonically equal to the original oracle:
    # public dbfbridge logical reads compare topology/schema/records.
    assert sorted(_hash_tree(source)) == sorted(_hash_tree(tmp_path / "recovered"))
    for relative in _hash_tree(source):
        if not relative.endswith(".dbf"):
            continue
        original = tuple(
            (
                record.physical_index,
                record.deleted,
                tuple(sorted(record.values.items())),
            )
            for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
                source / relative, include_deleted=True, memo="inline"
            )
        )
        recovered = tuple(
            (
                record.physical_index,
                record.deleted,
                tuple(sorted(record.values.items())),
            )
            for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
                tmp_path / "recovered" / relative,
                include_deleted=True,
                memo="inline",
            )
        )
        assert original == recovered


# ---------------------------------------------------------------------------
# POSIX drive-qualified manifest entry (path normalization, not inventory)
# ---------------------------------------------------------------------------
def test_posix_drive_qualified_manifest_entry_fails_by_path_normalization(
    tmp_path: Path,
) -> None:
    """The test proves the PATH-NORMALIZATION contract, not an inventory
    side effect: a manifest entry whose path is drive-qualified under the
    Windows grammar is refused by _normalized_artifact_path BEFORE payload
    verification, even when a matching physical artifact exists on POSIX."""
    if sys.platform == "win32":
        pytest.skip("Windows cannot create a 'C:' directory component")
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    bundle_root = tmp_path / "bundle"
    hostile_dir = bundle_root / "C:"
    hostile_dir.mkdir()
    evil_payload = (bundle_root / "north" / "data.dbf").read_bytes()
    (hostile_dir / "evil.dbf").write_bytes(evil_payload)
    # Add the matching manifest entry with TRUTHFUL size/hash/count/schema
    # fields so the manifest/inventory equality PASSES and only the portable
    # path normalization can refuse the bundle.
    manifest_path = bundle_root / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    payload_digest = hashlib.sha256(evil_payload).hexdigest()
    schema_digest = None
    for entry in manifest["artifacts"]:  # type: ignore[union-attr]
        if entry["path"] == "north/data.dbf":  # type: ignore[index]
            schema_digest = entry["schema_fingerprint"]
    manifest["artifacts"].append(  # type: ignore[union-attr]
        {
            "path": "C:/evil.dbf",
            "artifact_type": "DBF",
            "size_bytes": len(evil_payload),
            "sha256": payload_digest,
            "record_count": 1,
            "schema_fingerprint": schema_digest,
        }
    )
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(bundle_root)
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_PATH_INVALID"
    assert caught.value.context.operation == "verify_transfer_bundle"


# ---------------------------------------------------------------------------
# Strict assurance EXACT value/level-count contracts (blocker D round 4)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "mutate,description",
    [
        (
            lambda manifest: manifest["assurance"].update({"scope_note": None}),
            "scope-note-null",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {"evidence_schema_version": None}
            ),
            "evidence-version-null",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {
                    "level": "GLOBAL_EXACT_VALUE",
                    "declared_relations": 1,
                    "verified_relations": 1,
                    "failed_relations": 0,
                    "incomplete_relations": 0,
                }
            ),
            "global-exact-with-declared-1",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {
                    "level": "DECLARED_RELATIONS_VERIFIED",
                    "declared_relations": 3,
                    "verified_relations": 3,
                    "failed_relations": 0,
                    "incomplete_relations": 1,
                }
            ),
            "declared-verified-with-incomplete-1",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {
                    "level": "VFP_METADATA_VERIFIED",
                    "declared_relations": 0,
                    "verified_relations": 0,
                    "failed_relations": 0,
                    "incomplete_relations": 0,
                }
            ),
            "vfp-metadata-with-declared-0",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {
                    "level": "INCOMPLETE",
                    "declared_relations": 3,
                    "verified_relations": 3,
                    "failed_relations": 0,
                    "incomplete_relations": 0,
                }
            ),
            "incomplete-carrying-complete-pattern",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {"evidence_fingerprint": "g" * 64}
            ),
            "nonhex-fingerprint",
        ),
        (
            lambda manifest: manifest["assurance"].update(
                {"scope_note": "C:\\private\\canary\\vault"}
            ),
            "private-path-canary",
        ),
    ],
    ids=[
        "scope-note-null",
        "evidence-version-null",
        "global-exact-with-declared-1",
        "declared-verified-with-incomplete-1",
        "vfp-metadata-with-declared-0",
        "incomplete-carrying-complete-pattern",
        "nonhex-fingerprint",
        "private-path-canary",
    ],
)
def test_strict_assurance_contracts_fail_standalone(
    tmp_path: Path, mutate: Callable[[dict], None], description: str
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_VALUE_INVALID"
    serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    assert "PRIVATE_PATH_CANARY" not in serialized
    assert "C:\\private" not in serialized


# ---------------------------------------------------------------------------
# Concurrency regression: no cross-call operation attribution contamination
# ---------------------------------------------------------------------------
def test_concurrent_create_and_verify_error_attribution_is_isolated(
    tmp_path: Path,
) -> None:
    """Deterministic concurrency regression (threading.Barrier
    interleaving, no sleep as the correctness mechanism): a CREATE-owned
    staged self-verification failure and a VERIFY-owned standalone
    failure running SIMULTANEOUSLY through one dispatcher wrapper must
    NEVER cross-contaminate their operation contexts. Also asserts the
    module carries no shared mutable operation-routing symbol."""
    import dbf_anonymizer.transfer_bundle as transfer_module

    # No shared mutable operation-routing symbol may exist in the module.
    module_source = Path(transfer_module.__file__ or ".").read_text(
        encoding="utf-8"
    )
    assert "_OWNING_OPERATION" not in module_source
    assert "_owning_failure" not in module_source

    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)
    verify_bundle = tmp_path / "bundle-verify"
    shutil.copytree(tmp_path / "bundle", verify_bundle)
    original_verify = transfer_module._verify_bundle_core

    def hostile_dispatcher(bundle_root: Path, **kwargs: object) -> object:
        # Dispatch on the CALLER's bundle root: the create-owned staged
        # verification runs against bundle-create; the standalone
        # verification runs against bundle-verify. Each injects a
        # DIFFERENT typed manifest defect, then runs the REAL core.
        # Dispatch on the OWNING failure factory the caller injected: the
        # create-owned staged verification passes _transfer_failure; the
        # standalone verifier passes _standalone_failure. Deterministic
        # and race-free.
        if kwargs.get("failure") is transfer_module._transfer_failure:
            hostile_manifest(bundle_root, "smuggled_field")
        else:
            hostile_manifest(bundle_root, "other_field")
        return original_verify(bundle_root, **kwargs)  # type: ignore[arg-type]

    def hostile_manifest(bundle_root: Path, marker: str) -> None:
        manifest_path = bundle_root / "transfer-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest[marker] = 1
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            transfer_module, "_verify_bundle_core", hostile_dispatcher
        )
        outcomes: dict[str, str] = {}
        errors: dict[str, BaseException] = {}
        barrier = threading.Barrier(2)

        def run_create() -> None:
            try:
                barrier.wait(timeout=30)
                with pytest.raises(TransferError) as caught:
                    create_transfer_bundle(
                        result,
                        destination=tmp_path / "bundle-create",
                        profile="DATA_ONLY",
                    )
                outcomes["create"] = caught.value.context.operation
            except BaseException as error:  # pragma: no cover - surfaced
                errors["create"] = error

        def run_verify() -> None:
            try:
                barrier.wait(timeout=30)
                with pytest.raises(TransferError) as caught:
                    verify_transfer_bundle(verify_bundle)
                outcomes["verify"] = caught.value.context.operation
            except BaseException as error:  # pragma: no cover - surfaced
                errors["verify"] = error

        threads = (
            threading.Thread(target=run_verify),
            threading.Thread(target=run_create),
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        assert not errors, errors
        # NO cross-call contamination: each public operation keeps its own
        # context identity even while the SHARED private core is active in
        # both threads simultaneously.
        assert outcomes["create"] == "create_transfer_bundle"
        assert outcomes["verify"] == "verify_transfer_bundle"

        # Repeating the interleaving proves the isolation is deterministic
        # (no residual state from the previous round can flip ownership).
        for _round in range(3):
            shutil.rmtree(tmp_path / "bundle-create", ignore_errors=True)
            if verify_bundle.exists():
                shutil.rmtree(verify_bundle)
            shutil.copytree(tmp_path / "bundle", verify_bundle)
            round_outcomes: dict[str, str] = {}
            round_errors: dict[str, BaseException] = {}
            round_barrier = threading.Barrier(2)

            def run_create_round() -> None:
                try:
                    round_barrier.wait(timeout=30)
                    with pytest.raises(TransferError) as caught:
                        create_transfer_bundle(
                            result,
                            destination=tmp_path / "bundle-create",
                            profile="DATA_ONLY",
                        )
                    round_outcomes["create"] = caught.value.context.operation
                except BaseException as error:  # pragma: no cover - surfaced
                    round_errors["create"] = error

            def run_verify_round() -> None:
                try:
                    round_barrier.wait(timeout=30)
                    with pytest.raises(TransferError) as caught:
                        verify_transfer_bundle(verify_bundle)
                    round_outcomes["verify"] = caught.value.context.operation
                except BaseException as error:  # pragma: no cover - surfaced
                    round_errors["verify"] = error

            threads = (
                threading.Thread(target=run_verify_round),
                threading.Thread(target=run_create_round),
            )
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
            assert not round_errors, round_errors
            assert round_outcomes["create"] == "create_transfer_bundle"
            assert round_outcomes["verify"] == "verify_transfer_bundle"
    finally:
        monkeypatch.undo()

# ---------------------------------------------------------------------------
# Separate relationship/evidence fingerprint contracts (round-5 blocker A)
# ---------------------------------------------------------------------------
def test_relationship_fingerprint_accepts_nonhex_public_token(tmp_path: Path) -> None:
    """The transfer boundary accepts every fingerprint the PUBLIC P3
    RelationshipMetadata contract accepts: the non-hex bounded token
    round-trips end to end (never narrowed to raw 64-hex)."""
    import dbf_anonymizer as public

    result, source, output, vault = _prepare(tmp_path)
    metadata = public.RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint="relationship-token-v1",
        relation_count=0,
        authoritative=False,
    )
    plan = public.build_plan(
        source,
        tmp_path / "output-nh",
        tmp_path / "vault-nh" / "dictionary.sqlite3",
        relationships=metadata,
    )
    assert preflight(plan).ready is True
    producer_result = pseudonymize(plan)
    assert producer_result.assurance.relationship_fingerprint == (
        "relationship-token-v1"
    )
    bundle = create_transfer_bundle(
        producer_result, destination=tmp_path / "bundle-nh", profile="DATA_ONLY"
    )
    standalone = verify_transfer_bundle(tmp_path / "bundle-nh")
    assert standalone.verified is True
    assert standalone.assurance.relationship_fingerprint == "relationship-token-v1"


def test_document_derived_cryptographic_fingerprint_still_passes(
    tmp_path: Path,
) -> None:
    """The canonical document-digest kernel's 64-lowercase-hex cryptographic
    relationship fingerprint continues to pass unchanged."""
    result, source, output, vault = _prepare(tmp_path)
    bundle = _create(result, tmp_path)
    standalone = verify_transfer_bundle(tmp_path / "bundle")
    assert standalone.verified is True
    fingerprint = standalone.assurance.relationship_fingerprint or ""
    assert len(fingerprint) == 64
    assert all(character in "0123456789abcdef" for character in fingerprint)


@pytest.mark.parametrize(
    "hostile_token",
    [
        "",
        " leading-space",
        "trailing-space ",
        "internal space",
        "with-nul\x00",
        "with-control\x07char",
        "C:\\private\\vault",
        "/absolute/path/token",
        "../../relative/token",
        "x" * 129,
        "C:\\private\\canary\\vault\\token",
    ],
    ids=[
        "empty",
        "leading-space",
        "trailing-space",
        "internal-space",
        "nul",
        "control-char",
        "windows-absolute",
        "posix-absolute",
        "traversal",
        "over-limit",
        "private-path-canary",
    ],
)
def test_hostile_relationship_fingerprint_tokens_fail_standalone(
    tmp_path: Path, hostile_token: str
) -> None:
    """Hostile relationship_fingerprint values fail closed WITHOUT the
    64-hex shortcut: the bounded-token contract itself rejects them."""
    result, source, output, vault = _prepare(tmp_path)
    _create(result, tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["assurance"]["relationship_fingerprint"] = hostile_token

    _tamper_manifest(tmp_path / "bundle", mutate)
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(tmp_path / "bundle")
    assert caught.value.context.detail_code == "TRANSFER_MANIFEST_VALUE_INVALID"
    serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    assert "C:\\private\\canary" not in serialized


# ---------------------------------------------------------------------------
# REQ-P5-008 durability window: controller checkpoint wiring + typed
# cancellation inside the staged-payload fsync region (REQ-P1-008).
# ---------------------------------------------------------------------------
def test_bundle_payload_fsync_passes_controller_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REQ-P1-008 regression: create_transfer_bundle passes ITS controller
    cancellation probe into the staged-payload durability scan."""
    from dbf_anonymizer.engine import publication as publication_module

    result, source, output, vault = _prepare(tmp_path)
    captured: dict[str, object] = {}
    real_fsync_tree = publication_module.fsync_tree

    def spy(directory: object, **kwargs: object) -> object:
        captured["checkpoint"] = kwargs.get("checkpoint")
        return real_fsync_tree(directory, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(publication_module, "fsync_tree", spy)
    bundle = _create(result, tmp_path)
    assert bundle.verified is True
    assert callable(captured["checkpoint"])


def test_cancellation_inside_payload_fsync_is_typed_and_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancellation raised at a durability checkpoint BEFORE the atomic
    promotion publishes nothing, cleans the owned staging and keeps the
    typed OPERATION_CANCELLED semantics."""
    from dbf_anonymizer.engine import publication as publication_module

    result, source, output, vault = _prepare(tmp_path)
    output_before = _hash_tree(output)
    vault_before = _hash_tree(vault.parent)
    events: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        events.append(event)

    def cancelled_fsync(directory: object, **kwargs: object) -> int:
        raise CancellationError(
            ErrorCode.OPERATION_CANCELLED,
            context=_ErrorContext(
                operation="create_transfer_bundle", detail_code="CANCELLED_BY_CHECK"
            ),
        )

    monkeypatch.setattr(publication_module, "fsync_tree", cancelled_fsync)
    with pytest.raises(CancellationError) as caught:
        create_transfer_bundle(
            result,
            destination=tmp_path / "bundle",
            progress=progress,
        )
    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "create_transfer_bundle"
    assert not any(event.event_code == "COMPLETED" for event in events)
    assert not (tmp_path / "bundle").exists()
    assert not any(tmp_path.glob("*.staging*"))
    assert _hash_tree(output) == output_before
    assert _hash_tree(vault.parent) == vault_before


# ---------------------------------------------------------------------------
# REQ-P5-008 publication transition boundaries for the bundle flow:
# the atomic rename fact is never collapsed into "nothing was promoted".
# ---------------------------------------------------------------------------
def _fail_destination_parent_sync(
    monkeypatch: pytest.MonkeyPatch, destination_parent: Path
) -> None:
    """Deterministically inject a genuine directory-sync failure for exactly
    the destination parent directory (AFTER the real atomic rename)."""
    from dbf_anonymizer import durability as durability_module
    from dbf_anonymizer.errors import ErrorContext, PublicationError

    real_sync = durability_module.sync_directory

    def failing_sync(path: object) -> bool:
        if Path(str(path)) == destination_parent:
            raise PublicationError(
                ErrorCode.PUBLICATION_INCOMPLETE,
                context=ErrorContext(
                    operation="durability",
                    detail_code="DURABILITY_DIRECTORY_SYNC_FAILED",
                ),
            )
        return real_sync(path)  # type: ignore[arg-type]

    monkeypatch.setattr(durability_module, "sync_directory", failing_sync)


_BUNDLE_INVENTORY = [
    "archive/data.dbf",
    "archive/data.fpt",
    "north/data.dbf",
    "north/data.fpt",
    "south/data.dbf",
    "south/data.fpt",
    "transfer-manifest.json",
]


def test_bundle_replace_failure_never_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Boundary B: a failure OF os.replace itself means nothing was renamed
    and nothing was published; owned pre-rename staging is cleaned and the
    typed failure carries no rename fact."""
    import os as os_module

    from dbf_anonymizer.errors import PublicationError

    result, source, output, vault = _prepare(tmp_path)
    output_before = _hash_tree(output)
    vault_before = _hash_tree(vault.parent)
    events: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        events.append(event)

    real_replace = os_module.replace
    destination_root = tmp_path / "bundle"

    def failing_replace(source_path: object, destination_path: object) -> None:
        if Path(str(destination_path)) == destination_root:
            raise OSError("simulated bundle rename failure")
        real_replace(source_path, destination_path)  # type: ignore[arg-type]

    monkeypatch.setattr(os_module, "replace", failing_replace)
    with pytest.raises(PublicationError) as caught:
        create_transfer_bundle(
            result,
            destination=destination_root,
            progress=progress,
        )
    assert caught.value.context.detail_code == "STAGING_PROMOTION_FAILED"
    assert not destination_root.exists()
    assert not any(tmp_path.glob("*.staging*"))
    assert not any(event.event_code == "COMPLETED" for event in events)
    assert _hash_tree(output) == output_before
    assert _hash_tree(vault.parent) == vault_before


def test_bundle_sync_failure_after_rename_is_never_pre_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Boundary C for the bundle flow: the real atomic os.replace succeeds
    and the destination-parent directory sync then genuinely fails. The
    public API returns the typed post-rename failure (never a false
    completion), the renamed destination exists with EXACTLY the allowlisted
    bundle payload, and the private crash state stays objectively
    classifiable."""
    from dbf_anonymizer.durability import PostRenameDurabilityError
    from dbf_anonymizer.errors import PublicationError

    result, source, output, vault = _prepare(tmp_path)
    output_before = _hash_tree(output)
    vault_before = _hash_tree(vault.parent)
    events: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        events.append(event)

    destination_root = tmp_path / "bundle"
    _fail_destination_parent_sync(monkeypatch, tmp_path)
    with pytest.raises(PublicationError) as caught:
        create_transfer_bundle(
            result,
            destination=destination_root,
            progress=progress,
        )
    assert isinstance(caught.value, PostRenameDurabilityError)
    assert caught.value.renamed is True
    assert caught.value.context.detail_code == (
        "DURABILITY_DIRECTORY_SYNC_FAILED_AFTER_RENAME"
    )
    # The rename HAS occurred: the final bundle destination exists.
    assert destination_root.is_dir()
    # The renamed bundle contains EXACTLY the allowlisted payload plus the
    # sanitized manifest — no vault/recovery material, no staging residue.
    inventory = sorted(_hash_tree(destination_root))
    assert inventory == _BUNDLE_INVENTORY
    for name in inventory:
        lowered = name.lower()
        assert "dictionary" not in lowered
        assert not lowered.endswith((".sqlite3", "-wal", "-shm", ".journal"))
    # The crash/publication state stays objectively classifiable: the
    # private staging root with its READY_TO_PROMOTE record was NOT removed.
    staging_roots = tuple(tmp_path.glob("*.staging"))
    assert len(staging_roots) == 1
    crash_state = json.loads(
        (staging_roots[0] / "transaction.json").read_text(encoding="ascii")
    )
    assert crash_state["phase"] == "READY_TO_PROMOTE"
    assert crash_state["schema_version"] == "1.1"
    # No false COMPLETED event was emitted; source-side state is untouched.
    assert not any(event.event_code == "COMPLETED" for event in events)
    assert _hash_tree(output) == output_before
    assert _hash_tree(vault.parent) == vault_before
    serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    assert str(tmp_path) not in serialized
    # Subsequent handling is deterministic and fail-closed.
    with pytest.raises(PathError) as subsequent:
        create_transfer_bundle(result, destination=destination_root)
    assert subsequent.value.context.detail_code == "TRANSFER_TARGET_EXISTS"
    assert destination_root.is_dir()


def test_bundle_crash_after_rename_before_promoted_state_is_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Boundary D for the bundle flow: the rename succeeded, the durable
    PROMOTED crash state was not yet written. The destination exists, the
    evidence is preserved and a subsequent invocation is deterministic and
    fail-closed."""
    from dbf_anonymizer.engine import publication as publication_module

    result, source, output, vault = _prepare(tmp_path)
    output_before = _hash_tree(output)
    vault_before = _hash_tree(vault.parent)
    events: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        events.append(event)

    destination_root = tmp_path / "bundle"

    def interrupted_mark(self: object) -> None:
        raise RuntimeError("simulated crash before the PROMOTED state")

    monkeypatch.setattr(
        publication_module.DatasetStaging, "mark_promoted", interrupted_mark
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        create_transfer_bundle(
            result,
            destination=destination_root,
            progress=progress,
        )
    assert destination_root.is_dir()
    staging_roots = tuple(tmp_path.glob("*.staging"))
    assert len(staging_roots) == 1
    crash_state = json.loads(
        (staging_roots[0] / "transaction.json").read_text(encoding="ascii")
    )
    assert crash_state["phase"] == "READY_TO_PROMOTE"
    assert not any(event.event_code == "COMPLETED" for event in events)
    assert _hash_tree(output) == output_before
    assert _hash_tree(vault.parent) == vault_before
    with pytest.raises(PathError) as subsequent:
        create_transfer_bundle(result, destination=destination_root)
    assert subsequent.value.context.detail_code == "TRANSFER_TARGET_EXISTS"
    assert destination_root.is_dir()
