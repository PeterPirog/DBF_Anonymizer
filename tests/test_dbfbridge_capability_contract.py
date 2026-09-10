"""P0 public capability-contract evidence for REQ-P0-002.

Drives the five public dbfbridge 1.1 Direct Read / Direct Write operations
that form the sole approved DBF/FPT boundary of the future 1.0 engine:

    inspect_table, read_schema, iter_records, iter_raw_records, write_table

Only public ``dbfbridge`` symbols are used. The minimal synthetic table is
created through public ``write_table()`` and consumed with the Direct Read
calls. This proves the boundary contract only; it does NOT claim REQ-P0-003
(fixture corpus) or any later requirement.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from dbfbridge import (
    DirectRecord,
    FieldInfo,
    TableSchema,
    inspect_table,
    iter_raw_records,
    iter_records,
    read_schema,
    write_table,
)


def _field(name: str, dbf_type: str, length: int, *, decimals: int = 0) -> FieldInfo:
    return FieldInfo(
        ordinal=0,
        name=name,
        dbf_type=dbf_type,
        length=length,
        decimal_count=decimals,
        address=0,
        flags=0,
        index_field_flag=0,
        autoincrement_next_value=0,
        autoincrement_step=1,
        is_memo=dbf_type in {"M", "G", "P"},
        is_binary=False,
        supported=True,
        dbversion_byte=0x30,
    )


def _schema(fields: tuple[FieldInfo, ...]) -> TableSchema:
    return TableSchema(
        path=Path("memory:p0-fixture"),
        record_count=0,
        header_length=32 + 32 * len(fields) + 1,
        record_length=sum(field.length for field in fields) + 1,
        language_driver=0xC8,
        encoding="cp1250",
        has_memo=False,
        has_memo_flag=False,
        has_structural_cdx=False,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
        table_flags=0,
        fields=fields,
        warnings=(),
        dbversion_byte=0x30,
        dbversion_name="Visual FoxPro",
        last_update=None,
        incomplete_transaction=False,
        encryption_flag=False,
        memo_companion_format=None,
        memo_companion_present=False,
        memo_companion_path=None,
        memo_companion_size_bytes=None,
        memo_block_size=None,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def _fixture_fields() -> tuple[FieldInfo, ...]:
    return (
        _field("CODE", "C", 10),
        _field("AMOUNT", "N", 10, decimals=2),
        _field("WHEN", "D", 8),
        _field("FLAG", "L", 1),
    )


def _fixture_records() -> list[DirectRecord]:
    return [
        DirectRecord(
            physical_index=0,
            deleted=False,
            values={"CODE": "A1", "AMOUNT": 1.5, "WHEN": "20240101", "FLAG": True},
        ),
        DirectRecord(
            physical_index=1,
            deleted=True,
            values={"CODE": "B2", "AMOUNT": 2.5, "WHEN": "20240102", "FLAG": False},
        ),
        DirectRecord(
            physical_index=2,
            deleted=False,
            values={"CODE": "C3", "AMOUNT": 3.5, "WHEN": "20240103", "FLAG": True},
        ),
    ]


def test_public_direct_read_write_round_trip(tmp_path: Any) -> None:
    destination = tmp_path / "p0_boundary_fixture.dbf"

    result = write_table(
        destination,
        schema=_schema(_fixture_fields()),
        records=_fixture_records(),
        overwrite=False,
    )

    assert result.records_written == 3
    assert result.deleted_records == 1
    assert result.fpt_published is False  # plain table without memo fields
    assert result.to_dict()["records_written"] == 3

    info = inspect_table(destination)
    assert info.record_count == 3
    assert tuple(field.name for field in info.fields) == ("CODE", "AMOUNT", "WHEN", "FLAG")
    assert info.has_structural_cdx is False
    assert info.dbc_bound is False

    schema = read_schema(destination)
    assert schema.dbversion_name == "Visual FoxPro 6+"
    assert schema.encoding == "cp1250"
    assert schema.record_count == 3

    streamed = list(iter_records(destination, include_deleted=True))
    assert [record.physical_index for record in streamed] == [0, 1, 2]
    assert [record.deleted for record in streamed] == [False, True, False]
    assert [record.values["CODE"] for record in streamed] == ["A1", "B2", "C3"]
    assert [record.values["AMOUNT"] for record in streamed] == [1.5, 2.5, 3.5]
    assert [record.values["WHEN"] for record in streamed] == [
        date(2024, 1, 1),
        date(2024, 1, 2),
        date(2024, 1, 3),
    ]
    assert streamed[0].raw_record is None  # raw retention is opt-in, off by default

    projected = list(iter_records(destination, fields=["CODE"]))
    assert [record.values["CODE"] for record in projected] == ["A1", "C3"]

    raw_stream = list(iter_raw_records(destination))
    assert len(raw_stream) == 3
    assert [record.physical_index for record in raw_stream] == [0, 1, 2]
    assert all(record.values == {} for record in raw_stream)
    assert all(isinstance(record.raw_record, bytes) for record in raw_stream)
    assert raw_stream[1].deleted is True