"""Real Direct Read -> engine -> Direct Write evidence for P4-006/P4-007."""

from __future__ import annotations

import dataclasses
import gc
import hashlib
import json
import tracemalloc
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import dbfbridge
import pytest

from dbf_anonymizer import CancellationError, PathError, build_plan
from dbf_anonymizer.engine import direct_io, run_two_pass
from dbf_anonymizer.engine import pass2 as pass2_module
from dbf_anonymizer.engine import run as run_module
from dbf_anonymizer.engine.state import spool_artifacts
from dbf_anonymizer.vault.store import VaultDatabase
from tests.support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table,
    write_numeric_table_with_deleted,
)


TEXT_CANARY = "P4007-MEMO-TEXT-CANARY-7A31"
BINARY_CANARY = b"P4007-BINARY-CANARY-9C52\x00\xff"


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _run(source_root: Path, tmp_path: Path):
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(source_root, output_root, vault_path)
    events: list[object] = []
    result = run_two_pass(plan, progress=events.append)
    return plan, result, events, output_root, vault_path


def _nullable_fields() -> tuple[Any, ...]:
    return (
        numeric_field("CVAL", "C", 40, flags=NULLABLE_FLAG),
        numeric_field("VVAL", "V", 20, flags=NULLABLE_FLAG),
        numeric_field("IVAL", "I", 4, flags=NULLABLE_FLAG),
        numeric_field("YVAL", "Y", 8, flags=NULLABLE_FLAG),
        numeric_field("MVAL", "M", 4, flags=NULLABLE_FLAG),
        numeric_field("GVAL", "G", 4, flags=NULLABLE_FLAG),
        numeric_field("PVAL", "P", 4, flags=NULLABLE_FLAG),
        numeric_field("DVAL", "D", 8, flags=NULLABLE_FLAG),
        numeric_field("TVAL", "T", 8, flags=NULLABLE_FLAG),
        numeric_field("LVAL", "L", 1, flags=NULLABLE_FLAG),
    )


def _nullable_entries() -> list[tuple[dict[str, object], bool]]:
    return [
        (
            {
                "CVAL": None,
                "VVAL": None,
                "IVAL": None,
                "YVAL": None,
                "MVAL": None,
                "GVAL": None,
                "PVAL": None,
                "DVAL": None,
                "TVAL": None,
                "LVAL": None,
            },
            False,
        ),
        (
            {
                "CVAL": "",
                "VVAL": "",
                "IVAL": 0,
                "YVAL": Decimal("0"),
                "MVAL": "",
                "GVAL": b"",
                "PVAL": b"",
                "DVAL": date(2020, 1, 2),
                "TVAL": datetime(2020, 1, 2, 3, 4, 5),
                "LVAL": False,
            },
            False,
        ),
        (
            {
                "CVAL": "P4006-CHARACTER-NONEMPTY",
                "VVAL": "TAIL  ",
                "IVAL": -7,
                "YVAL": Decimal("-12.3400"),
                "MVAL": TEXT_CANARY,
                "GVAL": BINARY_CANARY,
                "PVAL": b"P4007-PICTURE-CANARY",
                "DVAL": date(2021, 2, 3),
                "TVAL": datetime(2021, 2, 3, 4, 5, 6),
                "LVAL": True,
            },
            False,
        ),
        (
            {
                "CVAL": "P4006-CHARACTER-POSITIVE",
                "VVAL": "TAIL ",
                "IVAL": 11,
                "YVAL": Decimal("98.7654"),
                "MVAL": "P4007-DELETED-MEMO",
                "GVAL": b"P4007-DELETED-GENERAL",
                "PVAL": b"P4007-DELETED-PICTURE",
                "DVAL": date(2022, 3, 4),
                "TVAL": datetime(2022, 3, 4, 5, 6, 7),
                "LVAL": True,
            },
            True,
        ),
    ]


def test_full_nullable_matrix_and_memo_vault_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_root = tmp_path / "source"
    source = write_numeric_table_with_deleted(
        source_root, "nullable_memo.dbf", _nullable_fields(), _nullable_entries()
    )
    source_hashes = _hash_tree(source_root)

    public_write = direct_io.dbfbridge.write_table
    outgoing_records = 0

    def inspect_write(destination: object, **kwargs: object):
        records = kwargs["records"]

        def logical_records():
            nonlocal outgoing_records
            for record in records:  # type: ignore[union-attr]
                outgoing_records += 1
                assert "_NULLFLAGS" not in {
                    str(name).upper() for name in record.values
                }
                yield record

        kwargs["records"] = logical_records()
        return public_write(destination, **kwargs)

    monkeypatch.setattr(direct_io.dbfbridge, "write_table", inspect_write)
    plan, result, events, output_root, vault_path = _run(source_root, tmp_path)
    output_path = output_root / "nullable_memo.dbf"
    records = tuple(
        dbfbridge.iter_records(output_path, memo="inline", include_deleted=True)
    )

    assert outgoing_records == result.pass2_records_written == len(records) == 4
    assert [record.physical_index for record in records] == [0, 1, 2, 3]
    assert [record.deleted for record in records] == [False, False, False, True]

    assert records[0].values == {
        **{name: None for name in (
            "CVAL", "VVAL", "IVAL", "YVAL", "MVAL", "GVAL", "PVAL",
            "DVAL", "TVAL", "LVAL",
        )},
        "_NULLFLAGS": records[0].values["_NULLFLAGS"],
    }
    assert records[1].values["CVAL"] == ""
    assert records[1].values["VVAL"] == ""
    assert records[1].values["IVAL"] == 0
    assert records[1].values["YVAL"] == Decimal("0")
    assert records[1].values["LVAL"] is False
    assert records[2].values["IVAL"] == -7
    assert records[3].values["IVAL"] == 11
    assert records[2].values["YVAL"] == Decimal("-12.34")
    assert records[3].values["YVAL"] == Decimal("98.7654")
    assert records[2].values["LVAL"] is True

    assert records[0].values["MVAL"] is None
    assert records[0].values["GVAL"] is None
    assert records[0].values["PVAL"] is None
    for record_index in (1, 2, 3):
        source_values = _nullable_entries()[record_index][0]
        for field_name in ("MVAL", "GVAL", "PVAL"):
            masked = records[record_index].values[field_name]
            assert masked != source_values[field_name]
            if field_name == "MVAL":
                assert isinstance(masked, str)
            else:
                assert isinstance(masked, bytes)

    date_offset = (records[1].values["DVAL"] - date(2020, 1, 2)).days
    assert date_offset != 0
    assert records[0].values["DVAL"] is None
    assert records[0].values["TVAL"] is None
    for index in (1, 2, 3):
        originals = _nullable_entries()[index][0]
        assert (records[index].values["DVAL"] - originals["DVAL"]).days == date_offset
        shifted = records[index].values["TVAL"]
        original = originals["TVAL"]
        assert (shifted.date() - original.date()).days == date_offset
        assert shifted.time() == original.time()

    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
    ) as vault:
        rows = vault._internal_connection().execute(
            "SELECT m.physical_record_index, f.name, m.original_payload, "
            "m.payload_kind FROM memo_recovery AS m "
            "JOIN fields AS f ON f.field_id = m.field_id "
            "ORDER BY m.physical_record_index, f.name"
        ).fetchall()
        assert len(rows) == 9
        assert {int(row[0]) for row in rows} == {1, 2, 3}
        assert all(str(row[1]).upper() != "_NULLFLAGS" for row in rows)
        assert not any(int(row[0]) == 0 for row in rows)
        assert (1, "MVAL", b"", "TEXT") in rows
        assert (1, "GVAL", b"", "BINARY") in rows
        assert (2, "MVAL", TEXT_CANARY.encode("utf-8"), "TEXT") in rows
        assert (2, "GVAL", BINARY_CANARY, "BINARY") in rows

    assert _hash_tree(source_root) == source_hashes
    for produced in (output_path, output_path.with_suffix(".fpt")):
        data = produced.read_bytes()
        assert TEXT_CANARY.encode("ascii") not in data
        assert BINARY_CANARY not in data
        assert b"P4007-DELETED" not in data
    vault_bytes = vault_path.read_bytes()
    assert TEXT_CANARY.encode("utf-8") in vault_bytes
    assert BINARY_CANARY in vault_bytes

    public_surface = json.dumps(plan.to_dict(), sort_keys=True) + repr(result)
    public_surface += "".join(repr(event) for event in events)
    public_surface += caplog.text
    assert TEXT_CANARY not in public_surface
    assert BINARY_CANARY.decode("latin-1") not in public_surface
    assert str(tmp_path) not in public_surface

    assert spool_artifacts(vault_path.parent) == []
    assert sorted(path.name for path in output_root.iterdir()) == [
        "nullable_memo.dbf",
        "nullable_memo.fpt",
    ]
    assert not tuple(output_root.rglob("*-wal"))
    assert not tuple(output_root.rglob("*-shm"))
    assert not tuple(output_root.rglob("*-journal"))
    assert source.is_file()


def _write_two_memo_tables(source_root: Path) -> None:
    fields = (
        numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
        numeric_field("OBJECT", "G", 4, flags=NULLABLE_FLAG),
    )
    for name in ("first.dbf", "second.dbf"):
        write_numeric_table(
            source_root,
            name,
            fields,
            [
                {"NOTE": "PRIVATE-" + name, "OBJECT": b"PRIVATE-BINARY-" + name.encode()},
                {"NOTE": "", "OBJECT": b""},
            ],
        )


def test_memo_cancellation_removes_dbf_and_fpt_and_preserves_source(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    _write_two_memo_tables(source_root)
    before = _hash_tree(source_root)
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(source_root, output_root, vault_path)
    state = {"first_written": False}

    def progress(event: object) -> None:
        if (
            getattr(event, "phase_code", None) == "PASS2_WRITE"
            and getattr(event, "event_code", None) == "PROGRESS"
            and getattr(event, "table_path", None) == "first.dbf"
        ):
            state["first_written"] = True

    with pytest.raises(CancellationError):
        run_two_pass(
            plan,
            progress=progress,
            cancel_check=lambda: state["first_written"],
        )

    assert state["first_written"]
    assert _hash_tree(source_root) == before
    assert not output_root.exists() or not tuple(output_root.rglob("*.dbf"))
    assert not output_root.exists() or not tuple(output_root.rglob("*.fpt"))
    assert spool_artifacts(vault_path.parent) == []


def test_memo_failure_removes_all_completed_dbf_and_fpt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    _write_two_memo_tables(source_root)
    before = _hash_tree(source_root)
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(source_root, output_root, vault_path)
    real_write = pass2_module.write_fresh_table
    calls = 0

    def fail_after_write(*args: object, **kwargs: object):
        nonlocal calls
        result = real_write(*args, **kwargs)  # type: ignore[arg-type]
        calls += 1
        if calls == 2:
            raise RuntimeError("injected safe test failure")
        return result

    monkeypatch.setattr(pass2_module, "write_fresh_table", fail_after_write)
    with pytest.raises(RuntimeError, match="injected safe test failure") as excinfo:
        run_two_pass(plan)

    assert calls == 2
    assert TEXT_CANARY not in str(excinfo.value)
    assert str(tmp_path) not in str(excinfo.value)
    assert _hash_tree(source_root) == before
    assert not output_root.exists() or not tuple(output_root.rglob("*.dbf"))
    assert not output_root.exists() or not tuple(output_root.rglob("*.fpt"))
    assert spool_artifacts(vault_path.parent) == []


@pytest.mark.parametrize(
    ("dbf_type", "supported", "is_binary", "nocptrans"),
    [
        ("Q", False, True, True),
        ("W", False, True, True),
        ("M", True, True, False),
        ("V", True, True, True),
    ],
)
def test_unsupported_field_metadata_fails_before_vault_or_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dbf_type: str,
    supported: bool,
    is_binary: bool,
    nocptrans: bool,
) -> None:
    source_root = tmp_path / "source"
    write_numeric_table(
        source_root,
        "unsafe.dbf",
        (numeric_field("VALUE", "C", 12),),
        [{"VALUE": "SAFE-FIXTURE"}],
    )
    before = _hash_tree(source_root)
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(source_root, output_root, vault_path)
    real_read = run_module.direct_io.read_source_table

    def unsafe_schema(*args: object, **kwargs: object):
        table = real_read(*args, **kwargs)  # type: ignore[arg-type]
        original = table.schema.fields[0]
        field = dataclasses.replace(
            original,
            dbf_type=dbf_type,
            supported=supported,
            is_binary=is_binary,
            flags=(original.flags | 0x04) if nocptrans else original.flags,
        )
        return dataclasses.replace(
            table, schema=dataclasses.replace(table.schema, fields=(field,))
        )

    monkeypatch.setattr(run_module.direct_io, "read_source_table", unsafe_schema)
    with pytest.raises(PathError) as excinfo:
        run_two_pass(plan)

    boundary = str(excinfo.value) + repr(excinfo.value) + json.dumps(
        excinfo.value.to_dict(), sort_keys=True
    )
    assert "SAFE-FIXTURE" not in boundary
    assert str(tmp_path) not in boundary
    assert _hash_tree(source_root) == before
    assert not output_root.exists()
    assert not vault_path.exists()


def test_engine_large_memos_do_not_accumulate_total_dataset_in_memory(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    payload_size = 1024 * 1024
    record_count = 16
    payload = (bytes(range(256)) * (payload_size // 256))
    assert len(payload) == payload_size
    write_numeric_table(
        source_root,
        "large.dbf",
        (numeric_field("OBJECT", "G", 4),),
        ({"OBJECT": payload} for _ in range(record_count)),
    )
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(source_root, output_root, vault_path)

    gc.collect()
    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    result = run_two_pass(plan)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert result.pass2_records_written == record_count
    assert peak - baseline < 8 * payload_size
    assert current - baseline < 2 * payload_size
    assert (vault_path.stat().st_size) > record_count * payload_size
    output = tuple(
        dbfbridge.iter_records(output_root / "large.dbf", memo="inline")
    )
    assert len(output) == record_count
    assert all(record.values["OBJECT"] != payload for record in output)
