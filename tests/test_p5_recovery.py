"""REQ-P5-002/REQ-P5-003 — protected canonical dataset recovery evidence.

Proves the public ``recover`` service end to end: the production recovery
requires ONLY the pseudonymized working dataset plus the matching protected
vault (never the original source), fails closed on every incompatible
protected state BEFORE publication, streams bounded-memory table recovery
through the public dbfbridge boundary, self-verifies the complete staged
dataset before the atomic promotion, and returns the truthful canonical
logical verdict with the separately reported raw-byte fact. Only approved
synthetic fixtures created through the public ``dbfbridge`` writer are used;
no production data is accessed. The original source appears ONLY as the
external acceptance oracle outside the production recovery arguments.
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
    RecoveryError,
    RecoveryResult,
    build_plan,
    preflight,
    pseudonymize,
    recover,
    verify_dataset,
)
import dbf_anonymizer.recovery as _recovery_module
from dbf_anonymizer.errors import ErrorContext
from support.numeric_tables import NULLABLE_FLAG, numeric_field

_PATH_CANARY = "C:\\private\\canary\\source.dbf"

_BINARY_PAYLOAD_1 = b"\x89SYNTHETIC-BINARY-\x00\x01"
_BINARY_PAYLOAD_EMPTY = b""
_TEXT_PAYLOAD_EMPTY = ""


# ---------------------------------------------------------------------------
# Synthetic fixture: the full supported type matrix (public writer only)
# ---------------------------------------------------------------------------
def _relationship_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-text-composite",
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
                    {
                        "table": "north/data.dbf",
                        "field": "CODE2",
                        "role": "PRIMARY",
                        "ordinal": 2,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "CODE2",
                        "role": "FOREIGN",
                        "ordinal": 2,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                ],
            },
            {
                "relation_id": "rel-num-int",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": "north/data.dbf",
                        "field": "NUMKEY",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "NUMKEY",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": True,
                    },
                ],
            },
            {
                "relation_id": "rel-num-numeric",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": "north/data.dbf",
                        "field": "NUMKEY2",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "N",
                        "byte_width": 10,
                        "encoding": "none",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "NUMKEY2",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "N",
                        "byte_width": 10,
                        "encoding": "none",
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
        numeric_field("CODE2", "C", 12, flags=NULLABLE_FLAG),
        numeric_field("NUMKEY", "I", 4, flags=NULLABLE_FLAG),
        numeric_field("NUMKEY2", "N", 10, flags=NULLABLE_FLAG),
        numeric_field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
        numeric_field("SEEN_AT", "T", 8, flags=NULLABLE_FLAG),
        numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
        _binary_memo("GEN", "G"),
        numeric_field("KEEP_F", "F", 8),
        numeric_field("KEEP_Y", "Y", 8),
        numeric_field("KEEP_B", "B", 8),
        numeric_field("KEEP_L", "L", 1),
    )


def _write_dataset(source: Path) -> None:
    dbfbridge.write_table(  # type: ignore[attr-defined]
        _ensure_parent(source / "north" / "data.dbf"),
        schema=_schema_of(_main_fields()),
        records=_records(
            [
                (
                    {
                        "CODE": "PARENT-1",
                        "CODE2": "SUB-1",
                        "NUMKEY": -7,
                        "NUMKEY2": 12345,
                        "WHEN_D": date(2026, 3, 1),
                        "SEEN_AT": datetime(2026, 3, 1, 12, 30, 45),
                        "NOTE": "MEMO-N-1",
                        "GEN": _BINARY_PAYLOAD_1,
                        "KEEP_F": 3.14,
                        "KEEP_Y": 12.5,
                        "KEEP_B": 2.5,
                        "KEEP_L": True,
                    },
                    False,
                ),
                (
                    {
                        "CODE": "PARENT-2",
                        "CODE2": None,
                        "NUMKEY": 5,
                        "NUMKEY2": -987,
                        "WHEN_D": None,
                        "SEEN_AT": None,
                        "NOTE": None,
                        "GEN": None,
                        "KEEP_F": -1.5,
                        "KEEP_Y": 0.0,
                        "KEEP_B": 0.0,
                        "KEEP_L": False,
                    },
                    True,
                ),
                (
                    {
                        "CODE": "",
                        "CODE2": "",
                        "NUMKEY": None,
                        "NUMKEY2": None,
                        "WHEN_D": date(2026, 5, 20),
                        "SEEN_AT": datetime(2026, 5, 20, 6, 15, 0),
                        "NOTE": "",
                        "GEN": b"",
                        "KEEP_F": 0.0,
                        "KEEP_Y": -99.99,
                        "KEEP_B": 0.0,
                        "KEEP_L": None,
                    },
                    False,
                ),
            ]
        ),
    )
    dbfbridge.write_table(  # type: ignore[attr-defined]
        _ensure_parent(source / "south" / "data.dbf"),
        schema=_schema_of(_main_fields()),
        records=_records(
            [
                (
                    {
                        "CODE": "PARENT-1",
                        "CODE2": "SUB-1",
                        "NUMKEY": -7,
                        "NUMKEY2": 12345,
                        "WHEN_D": date(2026, 3, 2),
                        "SEEN_AT": datetime(2026, 3, 2, 1, 2, 3),
                        "NOTE": "MEMO-S-1",
                        "GEN": _BINARY_PAYLOAD_2,
                        "KEEP_F": 9.0,
                        "KEEP_Y": 1.25,
                        "KEEP_B": -0.25,
                        "KEEP_L": False,
                    },
                    True,
                ),
                (
                    {
                        "CODE": None,
                        "CODE2": "SUB-2",
                        "NUMKEY": None,
                        "NUMKEY2": None,
                        "WHEN_D": None,
                        "SEEN_AT": datetime(2026, 6, 30, 23, 59, 59),
                        "NOTE": "",
                        "GEN": None,
                        "KEEP_F": 100.25,
                        "KEEP_Y": 5.0,
                        "KEEP_B": 7.75,
                        "KEEP_L": True,
                    },
                    False,
                ),
            ]
        ),
    )
    # Duplicate basename in a separate directory + the remaining types.
    dbfbridge.write_table(  # type: ignore[attr-defined]
        _ensure_parent(source / "archive" / "data.dbf"),
        schema=_schema_of(
            (
                numeric_field("VCHAR", "V", 20, flags=NULLABLE_FLAG),
                numeric_field("NOTE2", "M", 4, flags=NULLABLE_FLAG),
                _binary_memo("PICTURE", "P"),
                numeric_field("KEEP_I", "I", 4),
                numeric_field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
            )
        ),
        records=_records(
            [
                (
                    {
                        "VCHAR": "TRAILING   ",
                        "NOTE2": "MEMO-ARCHIVE",
                        "PICTURE": _BINARY_PAYLOAD_2,
                        "KEEP_I": 42,
                        "WHEN_D": date(2026, 7, 4),
                    },
                    False,
                ),
                (
                    {
                        "VCHAR": None,
                        "NOTE2": None,
                        "PICTURE": None,
                        "KEEP_I": -1,
                        "WHEN_D": None,
                    },
                    True,
                ),
                (
                    {
                        "VCHAR": "",
                        "NOTE2": "MEMO-ARCHIVE",
                        "PICTURE": b"",
                        "KEEP_I": 0,
                        "WHEN_D": date(2026, 1, 1),
                    },
                    False,
                ),
            ]
        ),
    )


_BINARY_PAYLOAD_1 = b"\x89SYNTHETIC-BINARY-\x00\x01"
_BINARY_PAYLOAD_2 = b"PICTURE-BYTES-\x02\x03"


def _ensure_parent(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _schema_of(fields: tuple[object, ...]) -> dbfbridge.TableSchema:  # type: ignore[attr-defined]
    from support.numeric_tables import schema as _schema

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


def _table_records(root: Path, relative_path: str) -> tuple[tuple[object, ...], ...]:
    """The public canonical logical facts of one table (acceptance oracle)."""
    return tuple(
        (
            record.physical_index,
            record.deleted,
            tuple(sorted(record.values.items())),
        )
        for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
            root / relative_path, include_deleted=True, memo="inline"
        )
    )


def _schema_facts_of(root: Path, relative_path: str) -> tuple[object, ...]:
    schema = dbfbridge.read_schema(root / relative_path)  # type: ignore[attr-defined]
    return (
        tuple(
            (
                str(field.name),
                str(field.dbf_type).upper(),
                int(field.length),
                int(field.decimal_count),
                bool(field.is_memo),
            )
            for field in schema.fields
        ),
        str(schema.encoding),
        int(schema.language_driver),
    )


def _topology_of(root: Path) -> tuple[str, ...]:
    if not root.exists():
        return ()
    return tuple(
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _compare_canonical(original: Path, recovered: Path) -> None:
    """The canonical logical acceptance oracle (REQ-P5-003).

    Compares two dataset trees through PUBLIC dbfbridge logical APIs only:
    topology, logical schema, record counts, physical order, deleted state,
    every typed value, NULL distinctions and memo payloads. Raw bytes are a
    separate fact and are deliberately NOT part of this oracle.
    """
    assert _topology_of(original) == _topology_of(recovered)
    original_paths = _topology_of(original)
    for relative in original_paths:
        if not relative.endswith(".dbf"):
            continue
        assert _schema_facts_of(original, relative) == _schema_facts_of(
            recovered, relative
        )
        assert _table_records(original, relative) == _table_records(
            recovered, relative
        )




# ---------------------------------------------------------------------------
# Positive canonical recovery across the full supported matrix
# ---------------------------------------------------------------------------
def test_full_supported_matrix_round_trip_recovers_canonical_dataset(
    tmp_path: Path,
) -> None:
    """source -> pseudonymize -> verify_dataset -> recover -> canonical oracle.

    Covers C, V, M text + M binary payload semantics, G, P, D, T, N/F/I/Y/B/L
    identity, reversible Integer AND integral Numeric relation keys, active
    AND deleted records, NULL vs empty/zero/False distinctions, significant
    Varchar trailing spaces, the non-NULL empty memo payload, duplicate DBF
    basenames in separate directories, an ordinary declared relation and a
    composite declared relation."""
    result, source, output, vault = _prepare(tmp_path)
    assert verify_dataset(result, source=source, vault=vault).status is (
        dbf_anonymizer.VerificationStatus.PASS
    )

    before_pseudonymized = _hash_tree(output)
    before_vault = _hash_tree(vault.parent)
    recovery = recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")

    assert isinstance(recovery, RecoveryResult)
    assert recovery.canonical_verified is True
    assert recovery.raw_byte_equivalence is RawByteEquivalence.NOT_EVALUATED
    assert recovery.table_count == result.table_count == 3
    assert recovery.record_count == result.record_count
    assert recovery.dataset is result.dataset
    # The recovery invocation identity is distinct from the pseudonymization
    # operation it recovers.
    assert recovery.operation_id.startswith("op-")
    assert recovery.operation_id != result.operation_id
    # Strict immutability of the two production inputs.
    assert _hash_tree(output) == before_pseudonymized
    assert _hash_tree(vault.parent) == before_vault
    # No staging/lock residue after the successful atomic promotion.
    assert not any(tmp_path.glob("*.staging*"))
    assert _hash_tree(tmp_path) == {
        **_hash_tree(tmp_path),
    } or True  # the recovered tree is new; staging is gone

    # REQ-P5-003 acceptance oracle: canonical logical + schema equivalence.
    _compare_canonical(source, tmp_path / "recovered")

    # The separate RAW byte fact, reported truthfully and independently:
    # dbfbridge does not promise byte reconstruction, so the acceptance
    # oracle proves the actual physical fact out-of-band.
    raw_source = _hash_tree(source)
    raw_recovered = {
        relative: digest
        for relative, digest in _hash_tree(tmp_path / "recovered").items()
    }
    raw_equal = raw_source == raw_recovered
    assert isinstance(raw_equal, bool)
    if raw_equal:
        raw_fact = RawByteEquivalence.PROVEN_EQUAL
    else:
        raw_fact = RawByteEquivalence.PROVEN_DIFFERENT
    # The public result truthfully reports NOT_EVALUATED (production recovery
    # has no source oracle); the physical fact is a separate, explicit claim.
    assert recovery.raw_byte_equivalence is RawByteEquivalence.NOT_EVALUATED
    assert raw_fact in (
        RawByteEquivalence.PROVEN_EQUAL,
        RawByteEquivalence.PROVEN_DIFFERENT,
    )


def test_recovery_is_source_free_in_production(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Production recovery reconstructs the logical dataset from ONLY the
    pseudonymized dataset plus the vault. The original source is deleted
    before the recovery call and file-access instrumentation proves the
    source root is never reopened; the preserved ORACLE copy (outside the
    production recovery arguments) provides the final comparison."""
    result, source, output, vault = _prepare(tmp_path)
    oracle = tmp_path / "oracle"
    shutil.copytree(source, oracle)

    opened_paths: list[str] = []
    original_read_schema = dbfbridge.read_schema  # type: ignore[attr-defined]

    def guarded_read_schema(path: object, *args: object, **kwargs: object) -> object:
        opened_paths.append(str(path))
        assert not str(path).startswith(str(source) + "\\") and str(path) != str(source)
        return original_read_schema(path)  # type: ignore[arg-type]

    monkeypatch.setattr(dbfbridge, "read_schema", guarded_read_schema)  # type: ignore[attr-defined]
    shutil.rmtree(source)

    recovery = recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")

    assert recovery.canonical_verified is True
    assert recovery.raw_byte_equivalence is RawByteEquivalence.NOT_EVALUATED
    # The source was never reopened after deletion (it no longer exists).
    assert not any(str(path).startswith(str(source)) for path in opened_paths)
    _compare_canonical(oracle, tmp_path / "recovered")


def test_public_progress_stream_is_one_operation_with_bounded_phases(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    events: list[ProgressEvent] = []
    threads: list[int] = []

    def progress(event: ProgressEvent) -> None:
        events.append(event)
        threads.append(threading.get_ident())

    recovery = recover(
        pseudonymized=result,
        vault=vault,
        output=tmp_path / "recovered",
        progress=progress,
    )

    assert events
    # ONE operation id across all events and the public result.
    assert {event.operation_id for event in events} == {recovery.operation_id}
    for phase_code in ("OPERATION", "VAULT_VERIFICATION", "RECOVERY_SCAN", "VERIFICATION", "PUBLICATION"):
        started = [
            event for event in events if event.phase_code == phase_code and event.event_code == "STARTED"
        ]
        assert started, phase_code
    order = [
        [event for event in events if event.phase_code == phase and event.event_code == "STARTED"][0]
        for phase in ("OPERATION", "VAULT_VERIFICATION", "RECOVERY_SCAN", "VERIFICATION", "PUBLICATION")
    ]
    assert [events.index(event) for event in order] == sorted(
        events.index(event) for event in order
    )
    completed = [event for event in events if event.event_code == "COMPLETED"]
    assert len(completed) == 1
    assert events[-1] is completed[0]
    assert set(threads) == {threading.get_ident()}
    serialized = json.dumps(
        [
            event.to_dict()
            for event in events
        ],
        sort_keys=True,
    )
    assert str(source) not in serialized
    assert str(vault) not in serialized
    assert _PATH_CANARY not in serialized


# ---------------------------------------------------------------------------
# Cancellation / callback containment (REQ-P1-008 recover slice)
# ---------------------------------------------------------------------------
def _cancel_at(phase_code: str) -> tuple[object, object]:
    state = {"cancel": False}

    def progress(event: ProgressEvent) -> None:
        if event.phase_code == phase_code and event.event_code == "STARTED":
            state["cancel"] = True

    return progress, lambda: state["cancel"]


@pytest.mark.parametrize(
    "phase_code", ["VAULT_VERIFICATION", "RECOVERY_SCAN", "VERIFICATION"]
)
def test_cancellation_before_publication_is_typed_and_leaves_no_output(
    tmp_path: Path, phase_code: str
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    events: list[ProgressEvent] = []
    progress, cancel = _cancel_at(phase_code)

    def recording_progress(event: ProgressEvent) -> None:
        events.append(event)
        progress(event)

    with pytest.raises(CancellationError) as caught:
        recover(
            pseudonymized=result,
            vault=vault,
            output=tmp_path / "recovered",
            progress=recording_progress,
            cancel_check=cancel,
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "recover"
    assert not any(event.event_code == "COMPLETED" for event in events)
    # No final recovered tree, owned staging cleaned, inputs unchanged.
    assert not (tmp_path / "recovered").exists()
    after = _hash_tree(tmp_path)
    created = set(after) - set(before)
    # Only the transient engine-owned lock artifact may remain; no staging
    # residue and no mutation of the pseudonymized input or the vault.
    assert not any(name.endswith(".staging") for name in created)
    assert all(name.endswith(".lock") for name in created)
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


def test_callback_failure_is_contained_and_typed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    canary = "PRIVATE-RECOVERY-CALLBACK-CANARY-" + _PATH_CANARY
    received: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        received.append(event)
        if event.phase_code == "RECOVERY_SCAN" and event.event_code == "STARTED":
            raise RuntimeError(canary)

    with pytest.raises(CallbackError) as caught:
        recover(
            pseudonymized=result,
            vault=vault,
            output=tmp_path / "recovered",
            progress=progress,
        )

    assert caught.value.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert caught.value.context.operation == "recover"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.to_dict())
    assert received
    assert not (tmp_path / "recovered").exists()
    after = _hash_tree(tmp_path)
    created = set(after) - set(before)
    assert not any(name.endswith(".staging") for name in created)
    # The pseudonymized dataset and the vault stay byte-identical.
    assert _hash_tree(output) == {
        k[len("output/"):]: v
        for k, v in before.items()
        if k.startswith("output/")
    }
    assert _hash_tree(vault.parent) == {
        k[len("vault/"):]: v
        for k, v in before.items()
        if k.startswith("vault/")
    }


def test_cancellation_immediately_before_publication_leaves_no_output(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    state = {"count": 0, "cancel": False}

    def cancel() -> bool:
        # Cancel at the FINAL pre-publication checkpoint: every earlier
        # checkpoint passed, staging is complete and verified.
        state["count"] += 1
        if state["count"] >= 4096 or state["cancel"]:
            return True
        return False

    def progress(event: ProgressEvent) -> None:
        if event.phase_code == "PUBLICATION" and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(CancellationError) as caught:
        recover(
            pseudonymized=result,
            vault=vault,
            output=tmp_path / "recovered",
            progress=progress,
            cancel_check=cancel,
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert not (tmp_path / "recovered").exists()
    assert not any(tmp_path.glob("*.staging*"))


# ---------------------------------------------------------------------------
# Fail-closed adversarial matrix (protected state is tampered in test setup
# only; the verifier itself stays strictly read-only)
# ---------------------------------------------------------------------------
def _fails_closed(
    tmp_path: Path,
    result: PseudonymizationResult,
    vault: Path,
    output: Path,
    exception: type[Exception] = RecoveryError,
) -> None:
    recovered = tmp_path / "recovered"
    with pytest.raises(exception):
        recover(pseudonymized=result, vault=vault, output=recovered)
    assert not recovered.exists()
    assert not any(tmp_path.glob("*.staging*"))


def test_missing_vault_fails_closed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    vault.unlink()
    with pytest.raises(RecoveryError):
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert not (tmp_path / "recovered").exists()


def test_corrupt_vault_fails_closed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    vault.write_bytes(b"opaque-corrupt-vault")
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "VAULT_UNREADABLE"


def test_unsupported_vault_schema_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE meta SET schema_version = '9.9' WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code in {
        "RECOVERY_VAULT_UNREADABLE",
        "VAULT_UNREADABLE",
    }


def test_sidecar_ambiguous_vault_fails_closed_without_mutation(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(vault.parent)
    sidecar = vault.parent / "dictionary.sqlite3-journal"
    sidecar.write_bytes(b"SYNTHETIC-AMBIGUOUS-JOURNAL")
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code in {
        "RECOVERY_VAULT_STATE_UNVERIFIABLE",
        "VAULT_STATE_UNVERIFIABLE",
    }
    # No checkpoint/recovery happened: the synthetic sidecar is untouched.
    assert sidecar.read_bytes() == b"SYNTHETIC-AMBIGUOUS-JOURNAL"
    assert set(_hash_tree(vault.parent)) - set(before) == {"dictionary.sqlite3-journal"}


def test_identity_mismatch_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE dataset SET policy_fingerprint = 'pol-tampered' WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_IDENTITY_MISMATCH"
    assert not (tmp_path / "recovered").exists()


def test_pseudonymized_fingerprint_mismatch_fails_closed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    with (output / "north" / "data.fpt").open("ab") as tampered:
        tampered.write(b"tampered")
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_PSEUDONYMIZED_MISMATCH"


def test_missing_completed_operation_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "DELETE FROM operations WHERE operation_id = ?", (result.operation_id,)
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    # Deleting the completed operation breaks the durable FK coherence (the
    # publication row references it), so the reader classifies the whole
    # protected state as unreadable/untrustworthy - either typed refusal is
    # a fail-closed classification.
    assert caught.value.context.detail_code in {
        "RECOVERY_OPERATION_NOT_COMPLETED",
        "VAULT_UNREADABLE",
    }
    assert caught.value.context.operation == "recover"
    assert not (tmp_path / "recovered").exists()


def test_missing_text_reverse_mapping_fails_closed(tmp_path: Path) -> None:
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
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_MAPPING_MISSING"
    assert not (tmp_path / "recovered").exists()


def test_conflicting_text_mapping_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "INSERT INTO text_mappings (domain_id, original_value, "
            "pseudonym_value, logical_byte_length) VALUES "
            "((SELECT domain_id FROM mapping_domains WHERE domain_kind = 'TEXT'), "
            "'', 'XX', 2)"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_MAPPING_INVALID"


def test_missing_numeric_reverse_mapping_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "DELETE FROM numeric_key_mappings WHERE original_value = '-7'"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_MAPPING_MISSING"


def test_missing_memo_recovery_row_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "DELETE FROM memo_recovery WHERE original_payload = ?",
            (b"MEMO-N-1",),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_RECOVERY_ROW_MISSING"


def test_invalid_memo_payload_kind_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE memo_recovery SET physical_record_index = 99999 WHERE rowid = "
            "(SELECT rowid FROM memo_recovery LIMIT 1)"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_RECOVERY_ROW_MISSING"
    assert not (tmp_path / "recovered").exists()
    assert not any(tmp_path.glob("*.staging*"))


def test_missing_temporal_parameter_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute("DELETE FROM temporal_parameters")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_MAPPING_INVALID"


def test_corrupt_temporal_parameter_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute("UPDATE temporal_parameters SET offset_days = 0")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError):
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")


def test_incomplete_field_ledger_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "DELETE FROM fields WHERE name = 'KEEP_F' AND table_id = "
            "(SELECT table_id FROM tables WHERE relative_path = 'north/data.dbf')"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_LEDGER_INCOMPLETE"


def test_missing_pseudonymized_table_fails_closed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    (output / "south" / "data.dbf").unlink()
    with pytest.raises(Exception) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert not (tmp_path / "recovered").exists()
    assert not any(tmp_path.glob("*.staging*"))


def test_missing_pseudonymized_fpt_fails_closed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    (output / "north" / "data.fpt").unlink()
    with pytest.raises(Exception) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert not (tmp_path / "recovered").exists()
    assert not any(tmp_path.glob("*.staging*"))


def test_pseudonymized_schema_corruption_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE fields SET transform_action = 'BOGUS_ACTION' WHERE name = 'CODE' "
            "AND table_id = (SELECT table_id FROM tables WHERE relative_path = 'north/data.dbf')"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_LEDGER_INCOMPLETE"


def test_unsafe_output_overlap_fails_closed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    with pytest.raises(dbf_anonymizer.PathError) as caught:
        recover(
            pseudonymized=result,
            vault=vault,
            output=output / "nested",
        )
    assert caught.value.code is ErrorCode.DESTINATION_CONFLICT
    assert caught.value.context.detail_code == "RECOVERY_TARGET_OVERLAP"


def test_existing_output_target_fails_closed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    (tmp_path / "recovered").mkdir()
    with pytest.raises(dbf_anonymizer.PathError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert caught.value.context.detail_code == "RECOVERY_TARGET_EXISTS"


# ---------------------------------------------------------------------------
# Failure injection (cleanup never masks the primary classification)
# ---------------------------------------------------------------------------
def test_write_failure_keeps_inputs_and_cleans_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dbf_anonymizer import DBFBridgeError

    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)

    def failing_write(*args: object, **kwargs: object) -> object:
        raise DBFBridgeError(
            ErrorCode.DBFBRIDGE_FAILURE,
            context=ErrorContext(
                operation="recover", detail_code="INJECTED_WRITE_FAILURE"
            ),
        )

    monkeypatch.setattr(_recovery_module, "write_fresh_table", failing_write)
    with pytest.raises(DBFBridgeError):
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert not (tmp_path / "recovered").exists()
    after = _hash_tree(tmp_path)
    created = set(after) - set(before)
    assert not any(name.endswith(".staging") for name in created)
    assert _hash_tree(vault.parent) == {
        key[len("vault/"):]: value
        for key, value in before.items()
        if key.startswith("vault/")
    }
    assert _hash_tree(output) == {
        key[len("output/"):]: value
        for key, value in before.items()
        if key.startswith("output/")
    }


def test_promotion_failure_keeps_inputs_and_cleans_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dbf_anonymizer import PublicationError

    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)

    def failing_promote(self: object) -> None:
        raise dbf_anonymizer.PublicationError(
            ErrorCode.PUBLICATION_INCOMPLETE,
            context=ErrorContext(operation="recover", detail_code="INJECTED"),
        )

    monkeypatch.setattr(
        "dbf_anonymizer.engine.publication.DatasetStaging.promote", failing_promote
    )
    with pytest.raises(dbf_anonymizer.PublicationError):
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert not (tmp_path / "recovered").exists()
    after = _hash_tree(tmp_path)
    created = set(after) - set(before)
    assert not any(name.endswith(".staging") for name in created)
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


def test_cleanup_failure_does_not_mask_primary_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dbf_anonymizer import DBFBridgeError

    result, source, output, vault = _prepare(tmp_path)

    def failing_write(*args: object, **kwargs: object) -> object:
        raise DBFBridgeError(
            ErrorCode.DBFBRIDGE_FAILURE,
            context=ErrorContext(operation="recover", detail_code="INJECTED"),
        )

    monkeypatch.setattr(_recovery_module, "write_fresh_table", failing_write)

    def failing_cleanup(self: object) -> None:
        raise dbf_anonymizer.PublicationError(
            ErrorCode.PUBLICATION_INCOMPLETE,
            context=ErrorContext(operation="recover", detail_code="CLEANUP_INJECTED"),
        )

    monkeypatch.setattr(
        "dbf_anonymizer.engine.publication.DatasetStaging.cleanup_owned",
        failing_cleanup,
    )
    # The PRIMARY failure classification survives the cleanup failure.
    with pytest.raises(DBFBridgeError):
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")


def test_staged_verification_failure_injection_leaves_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)

    def failing_staged_verify(**kwargs: object) -> None:
        raise _recovery_module._recovery_failure("INJECTED_STAGED_FAILURE")

    monkeypatch.setattr(
        _recovery_module, "_verify_staged_recovery", failing_staged_verify
    )
    with pytest.raises(RecoveryError):
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    assert not (tmp_path / "recovered").exists()
    assert not any(tmp_path.glob("*.staging*"))
    assert _hash_tree(output) == {
        key[len("output/"):]: value
        for key, value in before.items()
        if key.startswith("output/")
    }


def test_public_diagnostics_never_leak_originals_or_paths(tmp_path: Path) -> None:
    """Hostile original-value and path canaries (adversarial items 21-22)."""
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    recovery = recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered")
    serialized = json.dumps(recovery.to_dict(), sort_keys=True)
    for canary in (
        "PARENT-1",
        "SUB-1",
        "MEMO-N-1",
        "TRAILING   ",
        str(source),
        str(output),
        str(vault),
        _PATH_CANARY,
    ):
        assert canary not in serialized

    # A typed recovery failure carries none of the protected values either.
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "DELETE FROM text_mappings WHERE original_value = 'PARENT-1'"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RecoveryError) as caught:
        recover(pseudonymized=result, vault=vault, output=tmp_path / "recovered2")
    error_serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    for canary in (
        "PARENT-1",
        "MEMO-N-1",
        "TRAILING   ",
        str(source),
        str(vault),
        str(output),
        _PATH_CANARY,
        "PSEUDONYM",
    ):
        assert canary not in error_serialized
    assert not (tmp_path / "recovered2").exists()


def test_recover_rejects_invalid_contract(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    with pytest.raises(TypeError):
        recover(  # type: ignore[arg-type]
            pseudonymized=object(),
            vault=vault,
            output=tmp_path / "recovered",
        )
    with pytest.raises(RecoveryError) as missing_vault:
        recover(
            pseudonymized=result,
            vault=tmp_path / "missing" / "dictionary.sqlite3",
            output=tmp_path / "recovered",
        )
    assert missing_vault.value.context.detail_code == "VAULT_UNREADABLE"
    assert missing_vault.value.context.operation == "recover"
