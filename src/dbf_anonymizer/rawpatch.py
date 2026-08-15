"""Odtwarzanie surowych bajtów pól identity bez cofania anonimizacji C/M."""
from __future__ import annotations

import base64
import json
import os
import struct
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .jsonstream import iter_jsonl
from .schema import RAW_RECORD_KEY, TableSchema, is_data_record


class RawIdentityPatchError(RuntimeError):
    """Niespójne metadane surowego rekordu albo układ DBF."""


def make_numeric_values_reconstructable(
    records: Iterable[dict[str, Any]],
    schema: TableSchema,
) -> tuple[list[dict[str, Any]], int]:
    """Zastępuje tylko wartości N/F, których normalizator nie zapisze w polu.

    Po utworzeniu DBF dokładne bajty tych pól (oraz pozostałych N/F/L) są
    przywracane przez :func:`restore_identity_field_bytes`.
    """

    output: list[dict[str, Any]] = []
    replacements = 0
    numeric_fields = tuple(field for field in schema.fields if field.is_numeric)
    for record in records:
        updated = dict(record)
        if is_data_record(record):
            for field in numeric_fields:
                value = record.get(field.name)
                if value not in (None, "") and not _numeric_fits(value, field.length, field.decimal):
                    updated[field.name] = 0
                    replacements += 1
        output.append(updated)
    return output, replacements


def restore_identity_field_bytes(
    target_dbf: str | Path,
    raw_records_jsonl: str | Path,
    schema_json: str | Path,
) -> int:
    """Przywraca N/F/L z raw recordów, pozostawiając C/M zanonimizowane."""

    target = Path(target_dbf)
    schema = json.loads(Path(schema_json).read_text(encoding="utf-8"))
    fields = [
        field
        for field in schema.get("fields", [])
        if str(field.get("dbf_type", "")).upper() in {"N", "F", "L"}
    ]
    if not fields:
        return 0
    with target.open("r+b") as dbf:
        header = dbf.read(32)
        if len(header) != 32:
            raise RawIdentityPatchError(f"[RAW_PATCH_HEADER_TRUNCATED] dbf={target}")
        record_count = struct.unpack_from("<I", header, 4)[0]
        header_length, record_length = struct.unpack_from("<HH", header, 8)
        patched_records = 0
        for record_index, record in enumerate(
            (item for item in iter_jsonl(raw_records_jsonl) if is_data_record(item))
        ):
            encoded = record.get(RAW_RECORD_KEY)
            if not isinstance(encoded, str):
                raise RawIdentityPatchError(
                    f"[RAW_PATCH_METADATA_MISSING] record={record_index + 1} "
                    f"jsonl={raw_records_jsonl}"
                )
            try:
                raw = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise RawIdentityPatchError(
                    f"[RAW_PATCH_METADATA_INVALID] record={record_index + 1}"
                ) from exc
            if len(raw) != record_length:
                raise RawIdentityPatchError(
                    f"[RAW_PATCH_LENGTH_MISMATCH] record={record_index + 1} "
                    f"expected={record_length} actual={len(raw)}"
                )
            record_offset = header_length + record_index * record_length
            for field in fields:
                address = int(field.get("address") or 0)
                length = int(field.get("length") or 0)
                if address <= 0 or length <= 0 or address + length > record_length:
                    raise RawIdentityPatchError(
                        f"[RAW_PATCH_FIELD_LAYOUT_INVALID] field={field.get('name')} "
                        f"address={address} length={length} record_length={record_length}"
                    )
                dbf.seek(record_offset + address)
                dbf.write(raw[address:address + length])
            patched_records += 1
        if patched_records != record_count:
            raise RawIdentityPatchError(
                f"[RAW_PATCH_RECORD_COUNT_MISMATCH] expected={record_count} "
                f"actual={patched_records} dbf={target}"
            )
        dbf.flush()
        os.fsync(dbf.fileno())
    return patched_records


def _numeric_fits(value: Any, length: int, decimals: int | None) -> bool:
    decimal_places = int(decimals or 0)
    try:
        number = Decimal(str(value))
        quantum = Decimal(1).scaleb(-decimal_places)
        rendered = format(number.quantize(quantum), f".{decimal_places}f")
    except (InvalidOperation, ValueError):
        return False
    if len(rendered) > length and rendered.startswith("0."):
        rendered = rendered[1:]
    elif len(rendered) > length and rendered.startswith("-0."):
        rendered = "-." + rendered[3:]
    if len(rendered) <= length:
        return True
    for precision in range(decimal_places, -1, -1):
        if len(format(number, f".{precision}E")) <= length:
            return True
    return False
