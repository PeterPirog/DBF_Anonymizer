"""Synthetic numeric/logical table construction through the PUBLIC dbfbridge writer.

Every table used by the P3-004/P3-005 numeric evidence suites is deterministic,
obviously synthetic and redistributable.  Tables are built exclusively through
the public ``dbfbridge.write_table`` boundary (no private imports, no manual
byte construction); reading uses the public ``iter_records`` stream.  The
verified public dbfbridge 1.1 representation facts encoded here:

* ``I`` fields: fixed 4-byte signed integers; the writable range excludes both
  int32 extremes; NULL requires a ``_NullFlags`` type-0 system column;
* ``N(width, 0)`` fields: integral values whose canonical rendering fits the
  width; an empty field is NULL without a bitmap;
* autoincrement: the VFP field-flags mask ``0x0C`` on an Integer field;
* ``F``/``Y``/``B``/``L``: representative float/currency/double/logical
  identity values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from dbfbridge import (
    DirectRecord,
    FieldInfo,
    TableSchema,
    iter_records,
    write_table,
)

from tests.support.memo_tables import field as base_field

#: The verified writable Integer range through the public write boundary.
INTEGER_WRITABLE_LOW = -(2**31) + 1
INTEGER_WRITABLE_HIGH = 2**31 - 2

NULLFLAGS_TYPE = "0"
NULLFLAGS_NAME = "_NULLFLAGS"
NULLFLAGS_SYSTEM_FLAG = 0x01
NULLABLE_FLAG = 0x02
#: The verified VFP autoincrement field-flags mask on an Integer field.
AUTOINCREMENT_FLAG = 0x0C


def numeric_field(
    name: str,
    dbf_type: str,
    length: int,
    *,
    flags: int = 0,
    decimal_count: int = 0,
) -> FieldInfo:
    """One public ``FieldInfo`` of a synthetic numeric/logical table field."""
    replaced = base_field(name, dbf_type, length, flags=flags)
    return FieldInfo(
        ordinal=replaced.ordinal,
        name=replaced.name,
        dbf_type=replaced.dbf_type,
        length=replaced.length,
        decimal_count=decimal_count,
        address=replaced.address,
        flags=replaced.flags,
        index_field_flag=replaced.index_field_flag,
        autoincrement_next_value=0,
        autoincrement_step=1,
        is_memo=replaced.is_memo,
        is_binary=replaced.is_binary,
        supported=replaced.supported,
        dbversion_byte=replaced.dbversion_byte,
    )


def with_nullflags(fields: Sequence[FieldInfo]) -> tuple[FieldInfo, ...]:
    """Append the writer-managed ``_NullFlags`` system column when needed.

    A table with any NULLable field needs exactly one type-``0`` system
    column carrying the VFP system flag; its declared width must cover the
    allocated NULL bits (the writer derives the canonical bitmap itself).
    """
    needs_bitmap = any(
        (field.flags & NULLABLE_FLAG) or field.dbf_type == "V" for field in fields
    )
    if not needs_bitmap:
        return tuple(fields)
    null_bits = sum(
        1 for field in fields if (field.flags & NULLABLE_FLAG) or field.dbf_type == "V"
    )
    byte_count = (null_bits + 7) // 8
    return (
        *fields,
        base_field(NULLFLAGS_NAME, NULLFLAGS_TYPE, byte_count, flags=NULLFLAGS_SYSTEM_FLAG),
    )


def schema(fields: Sequence[FieldInfo], *, encoding: str = "cp1250") -> TableSchema:
    """A public ``TableSchema`` for a synthetic numeric/logical table."""
    ordered = tuple(with_nullflags(fields))
    return TableSchema(
        path=Path("memory:synthetic-numeric"),
        record_count=0,
        header_length=32 + 32 * len(ordered) + 1,
        record_length=sum(f.length for f in ordered) + 1,
        language_driver=0xC8,
        encoding=encoding,
        has_memo=any(f.is_memo for f in ordered),
        has_memo_flag=any(f.is_memo for f in ordered),
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
        memo_block_size=64,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def write_numeric_table(
    directory: Path,
    relative_path: str,
    fields: Sequence[FieldInfo],
    records: Iterable[Mapping[str, Any]],
) -> Path:
    """Write one synthetic numeric table through the public writer."""
    return _write_numeric_entries(
        directory, relative_path, fields, [(dict(record), False) for record in records]
    )


def write_numeric_table_with_deleted(
    directory: Path,
    relative_path: str,
    fields: Sequence[FieldInfo],
    entries: Iterable[tuple[Mapping[str, Any], bool]],
) -> Path:
    """Write one synthetic numeric table with active AND deleted records.

    The physical record order is the input order; the deleted marker is
    preserved by the public writer.
    """
    return _write_numeric_entries(
        directory, relative_path, fields, [(dict(values), deleted) for values, deleted in entries]
    )


def _write_numeric_entries(
    directory: Path,
    relative_path: str,
    fields: Sequence[FieldInfo],
    entries: Iterable[tuple[dict[str, Any], bool]],
) -> Path:
    destination = directory / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        destination,
        schema=schema(fields),
        records=[
            DirectRecord(physical_index=0, deleted=deleted, values=values)
            for values, deleted in entries
        ],
    )
    return destination


def read_numeric_records(dbf_path: Path, *, include_deleted: bool = True) -> tuple[Any, ...]:
    """Stream the public logical values of one numeric table (read-only)."""
    return tuple(iter_records(dbf_path, include_deleted=include_deleted))


def field_values(dbf_path: Path, field_name: str) -> list[Any]:
    """The ordered logical values of one field of a written table."""
    return [record.values[field_name] for record in read_numeric_records(dbf_path)]


__all__ = [
    "INTEGER_WRITABLE_LOW",
    "INTEGER_WRITABLE_HIGH",
    "NULLFLAGS_TYPE",
    "NULLFLAGS_NAME",
    "NULLFLAGS_SYSTEM_FLAG",
    "NULLABLE_FLAG",
    "AUTOINCREMENT_FLAG",
    "numeric_field",
    "with_nullflags",
    "write_numeric_table",
    "write_numeric_table_with_deleted",
    "schema",
    "read_numeric_records",
    "field_values",
]
