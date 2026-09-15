"""Synthetic M/G/P table construction through the PUBLIC dbfbridge writer.

Every payload used by the P2-007 evidence suite is deterministic, obviously
synthetic and redistributable.  Tables are built exclusively through the
public ``dbfbridge.write_table`` boundary (no private imports, no manual
byte construction); reading uses the public ``iter_records`` stream.
"""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import dbfbridge
from dbfbridge import (
    DirectRecord,
    FieldInfo,
    TableSchema,
    WriteResult,
    write_table,
)

MEMO_BLOCK_SIZE = 64


def field(name: str, dbf_type: str, length: int, *, flags: int = 0) -> FieldInfo:
    """One public ``FieldInfo`` of a synthetic VFP table."""
    return FieldInfo(
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


def schema(fields: Sequence[FieldInfo], *, encoding: str = "cp1250") -> TableSchema:
    """A public ``TableSchema`` for a synthetic memo-carrying table."""
    ordered = tuple(fields)
    return TableSchema(
        path=Path("memory:synthetic-memo"),
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
        memo_block_size=MEMO_BLOCK_SIZE,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def write_memo_table(
    directory: Path,
    relative_path: str,
    fields: Sequence[FieldInfo],
    records: Iterable[Mapping[str, Any]],
) -> Path:
    """Write one synthetic DBF/FPT memo table through the public writer."""
    destination = directory / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        destination,
        schema=schema(fields),
        records=[DirectRecord(physical_index=0, deleted=False, values=dict(r)) for r in records],
    )
    return destination


def read_memo_records(
    dbf_path: Path, *, include_deleted: bool = True
) -> tuple[DirectRecord, ...]:
    """Stream the public logical values of one memo table (read-only)."""
    return tuple(
        dbfbridge.iter_records(
            dbf_path, memo="inline", include_deleted=include_deleted
        )
    )


def file_sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(dbf_path: Path) -> dict[str, str]:
    """The SHA-256 inventory of one DBF table and its memo companion."""
    hashes = {"dbf": file_sha256(dbf_path)}
    companion = dbf_path.with_suffix(".fpt")
    if companion.is_file():
        hashes["fpt"] = file_sha256(companion)
    return hashes


def field_triplet(
    names: Sequence[str], types: Sequence[str], widths: Sequence[int]
) -> tuple[FieldInfo, ...]:
    return tuple(
        field(name, dbf_type, width)
        for name, dbf_type, width in zip(names, types, widths)
    )


__all__ = [
    "field",
    "field_triplet",
    "file_sha256",
    "read_memo_records",
    "schema",
    "source_hashes",
    "write_memo_table",
]