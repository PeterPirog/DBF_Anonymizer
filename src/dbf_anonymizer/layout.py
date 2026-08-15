"""Normalizacja opcjonalnego, 263-bajtowego obszaru backlink tabel VFP."""
from __future__ import annotations

import base64
import json
import os
import shutil
import struct
from pathlib import Path
from typing import Any


VFP_BACKLINK_BYTES = 263
DBF_HEADER_BYTES = 32
FIELD_DESCRIPTOR_BYTES = 32
HEADER_TERMINATOR_BYTES = 1


class HeaderLayoutError(RuntimeError):
    """Niespójny lub nieobsługiwany układ nagłówka DBF."""


def allow_generated_vfp_backlink(schema_path: str | Path) -> int:
    """Dopuszcza backlink writera wyłącznie dla źródła bez tego obszaru.

    Biblioteka ``dbf`` tworzy tabelę VFP z 263-bajtowym obszarem backlink.
    Niektóre poprawne tabele źródłowe go nie mają. Na czas rekonstrukcji
    podnosimy deklarowaną długość nagłówka, a po zapisie usuwamy nadmiar przez
    :func:`restore_source_header_layout`.
    """

    target = Path(schema_path)
    schema = _load_schema(target)
    dbf = schema.get("dbf")
    if not isinstance(dbf, dict):
        return 0
    expected = _integer(dbf.get("header_length_bytes"))
    if expected is None or expected != _compact_header_length(schema):
        return 0
    dbf["header_length_bytes"] = expected + VFP_BACKLINK_BYTES
    temporary = target.with_suffix(target.suffix + ".layout.tmp")
    temporary.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)
    return VFP_BACKLINK_BYTES


def restore_source_header_layout(
    target_dbf: str | Path,
    source_schema_path: str | Path,
) -> int:
    """Usuwa wyłącznie wygenerowany backlink i przywraca źródłowy nagłówek."""

    target = Path(target_dbf)
    schema = _load_schema(Path(source_schema_path))
    dbf = schema.get("dbf")
    if not isinstance(dbf, dict):
        return 0
    expected = _integer(dbf.get("header_length_bytes"))
    if expected is None:
        return 0
    with target.open("rb") as infile:
        generated_header = infile.read(DBF_HEADER_BYTES)
    if len(generated_header) != DBF_HEADER_BYTES:
        raise HeaderLayoutError(f"[HEADER_LAYOUT_TRUNCATED] dbf={target}")
    current, record_length = struct.unpack_from("<HH", generated_header, 8)
    if current == expected:
        return 0
    if (
        current - expected != VFP_BACKLINK_BYTES
        or expected != _compact_header_length(schema)
    ):
        raise HeaderLayoutError(
            f"[HEADER_LAYOUT_MISMATCH] dbf={target} current={current} "
            f"expected={expected}"
        )
    encoded = dbf.get("header_base64")
    if not isinstance(encoded, str):
        raise HeaderLayoutError(
            f"[SOURCE_HEADER_METADATA_MISSING] dbf={target} expected={expected}"
        )
    try:
        source_header = bytearray(base64.b64decode(encoded, validate=True))
    except ValueError as exc:
        raise HeaderLayoutError(
            f"[SOURCE_HEADER_METADATA_INVALID] dbf={target}"
        ) from exc
    if len(source_header) != expected:
        raise HeaderLayoutError(
            f"[SOURCE_HEADER_LENGTH_MISMATCH] dbf={target} "
            f"metadata={len(source_header)} expected={expected}"
        )
    expected_record = _integer(dbf.get("record_length_bytes"))
    if expected_record is not None and record_length != expected_record:
        raise HeaderLayoutError(
            f"[HEADER_RECORD_LENGTH_MISMATCH] dbf={target} "
            f"current={record_length} expected={expected_record}"
        )

    # Zachowaj liczbę rekordów wygenerowaną przez writer i przywróć źródłowy
    # układ, deskryptory pól, flagę CDX oraz długość nagłówka.
    source_header[4:8] = generated_header[4:8]
    struct.pack_into("<HH", source_header, 8, expected, record_length)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.header-layout.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with target.open("rb") as infile, temporary.open("wb") as outfile:
            outfile.write(source_header)
            infile.seek(current)
            shutil.copyfileobj(infile, outfile, length=1024 * 1024)
            outfile.flush()
            os.fsync(outfile.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return VFP_BACKLINK_BYTES


def _load_schema(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise HeaderLayoutError(f"[SCHEMA_ROOT_INVALID] schema={path}")
    return value


def _compact_header_length(schema: dict[str, Any]) -> int:
    fields = schema.get("fields")
    count = len(fields) if isinstance(fields, list) else 0
    return DBF_HEADER_BYTES + count * FIELD_DESCRIPTOR_BYTES + HEADER_TERMINATOR_BYTES


def _integer(value: Any) -> int | None:
    return int(value) if value is not None else None
