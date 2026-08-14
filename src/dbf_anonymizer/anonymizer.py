"""Orkiestracja per-tabela — łączy schema+transforms+uniqueness+dictionary.

Dwie główne operacje:
- anonymize_records(schema, records, options, salt) → (anonymized_records, TableDict)
- recover_records(schema, anon_records, table_dict) → recovered_records

Kluczowe: usuwa __dbfbridge_raw_record__ z rekordów, by reconstruct_dbf zbudował
DBF z zaanonimizowanych wartości pól (nie z surowych bajtów).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .dictionary import FieldDict, TableDict, column_mapping_to_field_dict, reverse_field_dict_values
from .schema import DELETED_KEY, FieldInfo, TableSchema
from .transforms import (
    identity,
    mask_memo,
    recover_date,
    recover_datetime,
    recover_identity,
    shift_date,
    shift_datetime,
)
from .uniqueness import build_column_mapping, detect_unique_columns


@dataclass
class AnonymizeOptions:
    """Opcje anonimizacji dla jednego przebiegu (katalogu)."""
    memo_mode: str = "mask"        # 'mask' lub 'keep'
    date_offset_days: int = 0      # 0 = bez zmian; >0 = przesunięcie w przód
    text_mode: str = "same_length"  # na razie tylko 'same_length'
    salt: str = ""                  # sól dla deterministycznego maskowania
    seed: int = 0                   # ziarno RNG dla offset_days (gdy random)


def _resolve_date_offset(options: AnonymizeOptions) -> int:
    """Zwraca offset dni (liczba całkowita)."""
    return int(options.date_offset_days)


def anonymize_records(
    schema: TableSchema,
    records: list[dict[str, Any]],
    options: AnonymizeOptions,
) -> tuple[list[dict[str, Any]], TableDict]:
    """Anonimizuje rekordy JSONL jednej tabeli wg schematu.

    Zwraca (anonymized_records, table_dict). Rekordy summary/table dbfbridge
    są pomijane (nie anonimizowane, ale zachowane w wyniku jako-takie jeśli
    zostały przekazane — pipeline je filtruje).
    """
    # 1. Rozdziel rekordy danych od raportów dbfbridge
    data_records: list[dict[str, Any]] = []
    for rec in records:
        if rec.get("type") in ("summary", "table"):
            continue
        data_records.append(rec)

    # 2. Detekcja unikatowych kolumn C
    c_field_names = [f.name for f in schema.fields if f.is_text]
    uniqueness = detect_unique_columns(data_records, c_field_names)

    # 3. Buduj mapowania dla kolumn C
    c_mappings: dict[str, Any] = {}  # field_name -> ColumnMapping
    for fname in c_field_names:
        finfo = schema.field_by_name(fname)
        if finfo is None:
            continue
        mapping = build_column_mapping(
            field_name=fname,
            records=data_records,
            length=finfo.length,
            unique=uniqueness.get(fname, False),
            salt=options.salt,
        )
        c_mappings[fname] = mapping

    # 4. Offset dni (stały dla katalogu — przekazany w options)
    offset_days = _resolve_date_offset(options)

    # 5. Transformuj rekordy
    #    Przy trybie mask dla M/G zbieraj oryginały pozycyjnie (w kolejności rekordów)
    #    do słownika — recovery przywróci je pozycyjnie.
    memo_originals: dict[str, list[Any]] = {
        f.name: [] for f in schema.fields if f.is_memo and options.memo_mode == "mask"
    }
    anonymized: list[dict[str, Any]] = []
    for rec in data_records:
        anon_rec: dict[str, Any] = {}
        for key, value in rec.items():
            if key == DELETED_KEY:
                anon_rec[key] = value
                continue
            if key.startswith("__dbfbridge_"):
                continue  # usuń raw_record, raw_text_fields, binary_memo_fields
            # Pole danych — transformuj wg typu
            finfo = schema.field_by_name(key)
            if finfo is None:
                # Nieznane pole — zachowaj bez zmian
                anon_rec[key] = value
                continue
            # Dla M/G w trybie mask zapisz oryginał pozycyjnie
            if finfo.is_memo and options.memo_mode == "mask":
                memo_originals[key].append(value)
            anon_rec[key] = _transform_field(finfo, value, c_mappings.get(key), offset_days, options)
        anonymized.append(anon_rec)

    # 6. Buduj słownik tabeli
    table_dict = TableDict(
        table=schema.table_name,
        relative_path=schema.relative_path,
        options={
            "memo_mode": options.memo_mode,
            "date_offset_days": offset_days,
            "text_mode": options.text_mode,
        },
    )
    for finfo in schema.fields:
        fd = _build_field_dict(finfo, c_mappings.get(finfo.name), offset_days, options)
        # Dla M/G w trybie mask zapisz oryginały pozycyjnie
        if finfo.is_memo and options.memo_mode == "mask":
            fd.memo_originals = list(memo_originals.get(finfo.name, []))
        table_dict.fields[finfo.name] = fd

    return anonymized, table_dict


def _transform_field(
    finfo: FieldInfo,
    value: Any,
    c_mapping: Any,
    offset_days: int,
    options: AnonymizeOptions,
) -> Any:
    """Transformuje pojedyncze pole wg typu DBF."""
    if finfo.is_text:
        # C — użyj mapowania (bijekcja dla unikatowych, 1:1 dla nieunikatowych)
        if c_mapping is None:
            return value
        if value is None or value == "":
            return value
        sval = str(value)
        return c_mapping.forward.get(sval, value)
    if finfo.is_memo:
        return mask_memo(value, mode=options.memo_mode)
    if finfo.is_date:
        return shift_date(value, offset_days=offset_days)
    if finfo.is_datetime:
        return shift_datetime(value, offset_days=offset_days)
    # N/F/L — identity
    return identity(value)


def _build_field_dict(
    finfo: FieldInfo,
    c_mapping: Any,
    offset_days: int,
    options: AnonymizeOptions,
) -> FieldDict:
    """Buduje FieldDict dla pola wg typu."""
    if finfo.is_text and c_mapping is not None:
        return column_mapping_to_field_dict(finfo.name, finfo.dbf_type, c_mapping)
    if finfo.is_memo:
        return FieldDict(
            name=finfo.name,
            dbf_type=finfo.dbf_type,
            memo_mode=options.memo_mode,
        )
    if finfo.is_date or finfo.is_datetime:
        return FieldDict(
            name=finfo.name,
            dbf_type=finfo.dbf_type,
            offset_days=offset_days,
        )
    # N/F/L — brak mapowania (identity)
    return FieldDict(name=finfo.name, dbf_type=finfo.dbf_type)


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

def recover_records(
    schema: TableSchema,
    anonymized_records: list[dict[str, Any]],
    table_dict: TableDict,
) -> list[dict[str, Any]]:
    """Odwraca anonimizację — przywraca pierwotne wartości z zaanonimizowanych.

    Używa słownika table_dict (mapowanie anonim→oryginał dla C/M,
    offset_days dla D/T). Zwraca listę rekordów z pierwotnymi wartościami.
    """
    # Przygotuj odwrócone mapowania dla C
    c_backward: dict[str, dict[str, str]] = {}
    for fname, fd in table_dict.fields.items():
        if fd.dbf_type == "C" and fd.values:
            c_backward[fname] = reverse_field_dict_values(fd)

    # Dla M/G w trybie mask: przygotuj listy oryginałów pozycyjnych
    memo_pos: dict[str, list[Any]] = {}
    memo_idx: dict[str, int] = {}
    for fname, fd in table_dict.fields.items():
        if fd.dbf_type in ("M", "G") and fd.memo_mode == "mask":
            memo_pos[fname] = list(fd.memo_originals)
            memo_idx[fname] = 0

    recovered: list[dict[str, Any]] = []
    for rec in anonymized_records:
        if rec.get("type") in ("summary", "table"):
            continue
        rec_out: dict[str, Any] = {}
        for key, value in rec.items():
            if key == DELETED_KEY:
                rec_out[key] = value
                continue
            if key.startswith("__dbfbridge_"):
                continue  # usuń raw_record, raw_text_fields, binary_memo_fields
            finfo = schema.field_by_name(key)
            if finfo is None:
                rec_out[key] = value
                continue
            # Dla M/G w trybie mask przywróć oryginał pozycyjnie
            if finfo.is_memo and finfo.name in memo_pos:
                idx = memo_idx[finfo.name]
                originals = memo_pos[finfo.name]
                if idx < len(originals):
                    rec_out[key] = originals[idx]
                    memo_idx[finfo.name] = idx + 1
                    continue
                rec_out[key] = value
                continue
            rec_out[key] = _recover_field(finfo, value, table_dict, c_backward)
        recovered.append(rec_out)
    return recovered


def _recover_field(
    finfo: FieldInfo,
    anon_value: Any,
    table_dict: TableDict,
    c_backward: dict[str, dict[str, str]],
) -> Any:
    """Odwraca transformację pojedynczego pola."""
    fd = table_dict.fields.get(finfo.name)
    if fd is None:
        return anon_value
    if finfo.is_text:
        if anon_value is None or anon_value == "":
            return anon_value
        backward = c_backward.get(finfo.name)
        if backward is None:
            return anon_value
        return backward.get(str(anon_value), anon_value)
    if finfo.is_memo:
        # keep = identity; mask = positional recovery (handled in recover_records)
        return anon_value
    if finfo.is_date:
        return recover_date(anon_value, offset_days=fd.offset_days)
    if finfo.is_datetime:
        return recover_datetime(anon_value, offset_days=fd.offset_days)
    # N/F/L
    return recover_identity(anon_value)
