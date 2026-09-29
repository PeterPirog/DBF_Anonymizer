"""Synthetic acceptance fixtures for the REQ-P8-002 release acceptance.

Self-contained, importable from the acceptance tooling WITHOUT the repository
root on ``sys.path`` (the installed-wheel canonical round trip must never
resolve anything from the source checkout).  Every table is deterministic,
obviously synthetic and redistributable; tables are built exclusively through
the PUBLIC ``dbfbridge.write_table`` boundary (no private imports, no manual
byte construction); the oracle reads back through the public ``iter_records``
stream.

The topology mirrors the accepted public consumer workflow acceptance
(REQ-P1-004): three DBF tables with memo/binary fields, NULLs, empty strings
and deleted records, plus one declared PK/FK text relation.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence

import dbfbridge
from dbfbridge import (
    TableSchema,
    iter_records,
)

MEMO_BLOCK_SIZE = 64

NULLFLAGS_TYPE = "0"
NULLFLAGS_NAME = "_NULLFLAGS"
NULLFLAGS_SYSTEM_FLAG = 0x01
NULLABLE_FLAG = 0x02

#: Synthetic seed values written into the fixture dataset.  They are
#: evidence-side controls only: they must be absent from the transferable
#: DATA_ONLY bundle and present again in the recovered dataset.
TEXT_CANARIES = ("PARENT-1", "PARENT-2", "MEMO-N-1", "MEMO-S-1", "TRAILING")
BINARY_CANARIES = (b"\x89SYNTHETIC-BINARY-\x00\x01", b"PICTURE-BYTES-\x02")


def field(name: str, dbf_type: str, length: int, *, flags: int = 0) -> dbfbridge.FieldInfo:
    """One public ``FieldInfo`` of a synthetic VFP table."""
    return dbfbridge.FieldInfo(
        ordinal=0,
        name=name,
        dbf_type=dbf_type,
        length=length,
        decimal_count=0,
        address=0,
        flags=flags,
        index_field_flag=0,
        autoincrement_next_value=0,
        autoincrement_step=1,
        is_memo=dbf_type in {"M", "G", "P"},
        is_binary=False,
        supported=True,
        dbversion_byte=0x30,
    )


def binary_memo(name: str, dbf_type: str) -> dbfbridge.FieldInfo:
    """One public binary-memo ``FieldInfo`` (general/picture payloads)."""
    return dbfbridge.FieldInfo(
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


def with_nullflags(fields: Sequence[dbfbridge.FieldInfo]) -> tuple[dbfbridge.FieldInfo, ...]:
    """Append the writer-managed ``_NullFlags`` system column when needed."""
    needs_bitmap = any((item.flags & NULLABLE_FLAG) or item.dbf_type == "V" for item in fields)
    if not needs_bitmap:
        return tuple(fields)
    null_bits = sum(1 for item in fields if (item.flags & NULLABLE_FLAG) or item.dbf_type == "V")
    byte_count = (null_bits + 7) // 8
    return (
        *fields,
        field(NULLFLAGS_NAME, NULLFLAGS_TYPE, byte_count, flags=NULLFLAGS_SYSTEM_FLAG),
    )


def schema(fields: Sequence[dbfbridge.FieldInfo], *, encoding: str = "cp1250") -> TableSchema:
    """A public ``TableSchema`` for one synthetic acceptance table."""
    ordered = tuple(with_nullflags(fields))
    return TableSchema(
        path=Path("memory:synthetic-acceptance"),
        record_count=0,
        header_length=32 + 32 * len(ordered) + 1,
        record_length=sum(item.length for item in ordered) + 1,
        language_driver=0xC8,
        encoding=encoding,
        has_memo=any(item.is_memo for item in ordered),
        has_memo_flag=any(item.is_memo for item in ordered),
        has_structural_cdx=False,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
        table_flags=0,
        fields=ordered,
        warnings=(),
        dbversion_byte=0x30,
        dbversion_name="Visual FoxPro",
        last_update="2026-01-01",
        incomplete_transaction=False,
        encryption_flag=False,
        memo_companion_format=None,
        memo_companion_present=False,
        memo_companion_path=None,
        memo_companion_size_bytes=None,
        memo_block_size=MEMO_BLOCK_SIZE,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def relationship_document() -> dict[str, object]:
    """The declared PK/FK relationship document used by the canonical run."""
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
            }
        ],
    }


def _write_table(
    source: Path,
    relative: str,
    fields: Sequence[dbfbridge.FieldInfo],
    entries: Sequence[tuple[Mapping[str, Any], bool]],
) -> None:
    path = source / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    dbfbridge.write_table(
        path,
        schema=schema(fields),
        records=[
            dbfbridge.DirectRecord(physical_index=index, deleted=deleted, values=values)
            for index, (values, deleted) in enumerate(entries)
        ],
    )


def write_dataset(source: Path) -> None:
    """Write the canonical synthetic multi-table dataset (public writer only)."""
    _write_table(
        source,
        "north/data.dbf",
        (
            field("CODE", "C", 12, flags=NULLABLE_FLAG),
            field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
            field("NOTE", "M", 4, flags=NULLABLE_FLAG),
            binary_memo("GEN", "G"),
            field("KEEP_N", "N", 6),
            field("KEEP_L", "L", 1),
        ),
        [
            (
                {
                    "CODE": "PARENT-1",
                    "WHEN_D": date(2026, 3, 1),
                    "NOTE": "MEMO-N-1",
                    "KEEP_N": 11,
                    "KEEP_L": True,
                    "GEN": BINARY_CANARIES[0],
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
    _write_table(
        source,
        "south/data.dbf",
        (
            field("CODE", "C", 12, flags=NULLABLE_FLAG),
            field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
            field("NOTE", "M", 4, flags=NULLABLE_FLAG),
            field("KEEP_N", "N", 6),
            field("KEEP_L", "L", 1),
        ),
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
                    "NOTE": "",
                    "KEEP_N": 55,
                    "KEEP_L": None,
                },
                False,
            ),
        ],
    )
    _write_table(
        source,
        "archive/data.dbf",
        (
            field("VCHAR", "V", 20, flags=NULLABLE_FLAG),
            field("PICTURE", "P", 4, flags=NULLABLE_FLAG),
            field("KEEP_I", "I", 4),
        ),
        [
            (
                {
                    "VCHAR": "TRAILING   ",
                    "PICTURE": BINARY_CANARIES[1],
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


def table_records(root: Path, relative: str) -> tuple[tuple[object, ...], ...]:
    """Canonical logical oracle rows through the public ``iter_records``."""
    return tuple(
        (record.physical_index, record.deleted, tuple(sorted(record.values.items())))
        for record in iter_records(root / relative, include_deleted=True, memo="inline")
    )
