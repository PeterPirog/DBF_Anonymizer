"""Transformacje rekordów ze słownikiem globalnym lub starszym per tabela.

Główne operacje:
- anonymize_records(...) → kodowanie rekordów mapą z globalnego SQLite,
- recover_records(...) → dekodowanie z uwzględnieniem ścieżki pliku.

``build_shared_dictionary`` pozostaje publiczne dla zgodności ze starszym
formatem JSON v2; nowy pipeline katalogowy zawsze używa mapowania globalnego.

Kluczowe: usuwa __dbfbridge_raw_record__ z rekordów, by reconstruct_dbf zbudował
DBF z zaanonimizowanych wartości pól (nie z surowych bajtów).
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .dictionary import (
    FieldDict,
    TableDict,
    column_mapping_to_field_dict,
    normalize_relative_path,
    reverse_field_dict_values,
)
from .schema import (
    BINARY_MEMO_FIELDS_KEY,
    DELETED_KEY,
    RAW_RECORD_KEY,
    RAW_TEXT_FIELDS_KEY,
    FieldInfo,
    TableSchema,
)
from .transforms import (
    identity,
    mask_memo,
    recover_date,
    recover_datetime,
    recover_identity,
    shift_date,
    shift_datetime,
)
from .uniqueness import ColumnMapping, build_column_mapping


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
    *,
    table_dict: TableDict | None = None,
    global_text_mapping: Mapping[str, str] | None = None,
) -> tuple[list[dict[str, Any]], TableDict]:
    """Anonimizuje rekordy JSONL jednej tabeli wg schematu.

    Zwraca (anonymized_records, table_dict). Rekordy summary/table dbfbridge
    są pomijane (nie anonimizowane, ale zachowane w wyniku jako-takie jeśli
    zostały przekazane — pipeline je filtruje).
    """
    data_records = _data_records(records)
    if table_dict is None and global_text_mapping is None:
        table_dict = build_shared_dictionary(
            schema.table_name,
            [(schema.relative_path, schema, records)],
            options,
        )
    elif table_dict is None:
        table_dict = _metadata_table_dictionary(schema, options)

    effective_options = AnonymizeOptions(
        memo_mode=str(table_dict.options.get("memo_mode", options.memo_mode)),
        date_offset_days=int(table_dict.options.get("date_offset_days", options.date_offset_days)),
        text_mode=str(table_dict.options.get("text_mode", options.text_mode)),
        salt=options.salt,
        seed=options.seed,
    )
    offset_days = _resolve_date_offset(effective_options)
    c_mappings: dict[str, ColumnMapping] = {}
    if global_text_mapping is not None:
        shared_mapping = ColumnMapping(
            field_name="__global__",
            unique=True,
            forward=dict(global_text_mapping),
        )
        c_mappings = {
            field.name: shared_mapping for field in schema.fields if field.is_text
        }
    else:
        for fname, field_dict in table_dict.fields.items():
            if field_dict.dbf_type == "C":
                c_mappings[fname] = ColumnMapping(
                    field_name=fname,
                    unique=field_dict.unique,
                    forward=dict(field_dict.values),
                )

    anonymized: list[dict[str, Any]] = []
    for rec in data_records:
        anon_rec: dict[str, Any] = {}
        for key, value in rec.items():
            if key == DELETED_KEY:
                anon_rec[key] = value
                continue
            if key.startswith("__dbfbridge_"):
                preserved = _preserved_dbfbridge_metadata(
                    key,
                    value,
                    schema,
                    memo_mode=effective_options.memo_mode,
                )
                if preserved is not None:
                    anon_rec[key] = preserved
                continue
            # Pole danych — transformuj wg typu
            finfo = schema.field_by_name(key)
            if finfo is None:
                # Nieznane pole — zachowaj bez zmian
                anon_rec[key] = value
                continue
            anon_rec[key] = _transform_field(
                finfo,
                value,
                c_mappings.get(finfo.name),
                offset_days,
                effective_options,
            )
        anonymized.append(anon_rec)
    return anonymized, table_dict


def _metadata_table_dictionary(
    schema: TableSchema,
    options: AnonymizeOptions,
) -> TableDict:
    """Tworzy lekkie metadane, gdy mapowanie C pochodzi z globalnego SQLite."""
    offset_days = _resolve_date_offset(options)
    table_dict = TableDict(
        table=schema.table_name,
        relative_path=schema.relative_path,
        relative_paths=[schema.relative_path],
        options={
            "memo_mode": options.memo_mode,
            "date_offset_days": offset_days,
            "text_mode": options.text_mode,
        },
    )
    for field in schema.fields:
        table_dict.fields[field.name] = _build_field_dict(
            field, None, offset_days, options
        )
    return table_dict


def _data_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Usuwa rekordy raportowe ``table``/``summary`` generowane przez dbfbridge."""
    return [rec for rec in records if rec.get("type") not in ("summary", "table")]


def build_shared_dictionary(
    table_name: str,
    tables: list[tuple[str, TableSchema, list[dict[str, Any]]]],
    options: AnonymizeOptions,
) -> TableDict:
    """Buduje wspólny słownik dla wszystkich plików o tej samej nazwie.

    Mapowania pól C powstają z sumy wartości ze wszystkich lokalizacji. Dzięki
    temu ta sama wartość w tym samym polu jest kodowana identycznie niezależnie
    od katalogu. Oryginały memo pozostają rozdzielone według ścieżki względnej,
    co umożliwia bezbłędne odtworzenie każdego pliku.
    """
    if not tables:
        raise ValueError(f"Brak tabel do zbudowania słownika: {table_name}")

    ordered = sorted(tables, key=lambda item: normalize_relative_path(item[0]).casefold())
    relative_paths = [normalize_relative_path(item[0]) for item in ordered]
    field_defs: dict[str, FieldInfo] = {}
    text_values: dict[str, list[str]] = {}
    text_seen: dict[str, set[str]] = {}
    text_unique: dict[str, bool] = {}
    memo_by_path: dict[str, dict[str, list[Any]]] = {}

    for relative_path, schema, records in ordered:
        rel_key = normalize_relative_path(relative_path)
        for finfo in schema.fields:
            existing = field_defs.get(finfo.name)
            if existing is not None and existing.dbf_type != finfo.dbf_type:
                raise ValueError(
                    f"Niezgodny typ pola {finfo.name} w grupie {table_name}: "
                    f"{existing.dbf_type} != {finfo.dbf_type} ({rel_key})"
                )
            if existing is None or finfo.length > existing.length:
                field_defs[finfo.name] = finfo
            if finfo.is_text:
                text_values.setdefault(finfo.name, [])
                text_seen.setdefault(finfo.name, set())
                text_unique.setdefault(finfo.name, True)
            if finfo.is_memo and options.memo_mode == "mask":
                memo_by_path.setdefault(finfo.name, {})[rel_key] = []

        for rec in _data_records(records):
            for finfo in schema.fields:
                value = rec.get(finfo.name)
                if finfo.is_text and value not in (None, ""):
                    sval = str(value)
                    if sval in text_seen[finfo.name]:
                        text_unique[finfo.name] = False
                    else:
                        text_seen[finfo.name].add(sval)
                        text_values[finfo.name].append(sval)
                elif finfo.is_memo and options.memo_mode == "mask":
                    memo_by_path[finfo.name][rel_key].append(value)

    offset_days = _resolve_date_offset(options)
    table_dict = TableDict(
        table=table_name,
        relative_path=relative_paths[0],
        relative_paths=relative_paths,
        options={
            "memo_mode": options.memo_mode,
            "date_offset_days": offset_days,
            "text_mode": options.text_mode,
        },
    )

    for finfo in field_defs.values():
        mapping: ColumnMapping | None = None
        if finfo.is_text:
            synthetic_records = [{finfo.name: value} for value in text_values[finfo.name]]
            mapping = build_column_mapping(
                field_name=finfo.name,
                records=synthetic_records,
                length=finfo.length,
                unique=text_unique[finfo.name] and bool(synthetic_records),
                salt=options.salt,
            )
        field_dict = _build_field_dict(finfo, mapping, offset_days, options)
        if finfo.is_memo and options.memo_mode == "mask":
            field_dict.memo_originals_by_path = {
                path: list(values) for path, values in memo_by_path[finfo.name].items()
            }
            # Pojedynczą listę zachowujemy tylko dla kompatybilności słownika
            # jednej tabeli. Przy wielu plikach nie duplikujemy potencjalnie
            # dużych memo — źródłem prawdy jest memo_originals_by_path.
            if len(relative_paths) == 1:
                field_dict.memo_originals = list(
                    field_dict.memo_originals_by_path.get(relative_paths[0], [])
                )
        table_dict.fields[finfo.name] = field_dict

    return table_dict


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
    *,
    relative_path: str | None = None,
    global_reverse_mapping: Mapping[str, str] | None = None,
    memo_originals: Mapping[str, list[Any]] | None = None,
) -> list[dict[str, Any]]:
    """Odwraca anonimizację — przywraca pierwotne wartości z zaanonimizowanych.

    Używa słownika table_dict (mapowanie anonim→oryginał dla C/M,
    offset_days dla D/T). Zwraca listę rekordów z pierwotnymi wartościami.
    """
    # Przygotuj odwrócone mapowania dla C
    c_backward: dict[str, dict[str, str]] = {}
    if global_reverse_mapping is not None:
        shared_backward = dict(global_reverse_mapping)
        c_backward = {
            field.name: shared_backward for field in schema.fields if field.is_text
        }
    else:
        for fname, fd in table_dict.fields.items():
            if fd.dbf_type == "C" and fd.values:
                c_backward[fname] = reverse_field_dict_values(fd)

    # Dla M/G w trybie mask: przygotuj listy oryginałów pozycyjnych wybranego
    # pliku. Starsze słowniki nie mają memo_originals_by_path, dlatego nadal
    # obsługujemy pojedynczą listę memo_originals.
    rel_key = normalize_relative_path(relative_path or schema.relative_path)
    memo_pos: dict[str, list[Any]] = {}
    memo_idx: dict[str, int] = {}
    for fname, fd in table_dict.fields.items():
        schema_field = schema.field_by_name(fname)
        if (
            schema_field is not None
            and schema_field.is_memo
            and fd.dbf_type in ("M", "G")
            and fd.memo_mode == "mask"
        ):
            if memo_originals is not None and fname in memo_originals:
                memo_pos[fname] = list(memo_originals[fname])
            elif fd.memo_originals_by_path:
                if rel_key not in fd.memo_originals_by_path:
                    raise ValueError(
                        f"Brak danych memo dla {rel_key} w słowniku {table_dict.table}"
                    )
                memo_pos[fname] = list(fd.memo_originals_by_path[rel_key])
            else:
                memo_pos[fname] = list(fd.memo_originals)
            memo_idx[fname] = 0

    data_records = _data_records(anonymized_records)
    for fname, originals in memo_pos.items():
        if len(originals) != len(data_records):
            raise ValueError(
                f"Niezgodna liczba wartości memo dla {rel_key}/{fname}: "
                f"{len(originals)} != {len(data_records)}"
            )

    recovered: list[dict[str, Any]] = []
    for rec in data_records:
        rec_out: dict[str, Any] = {}
        for key, value in rec.items():
            if key == DELETED_KEY:
                rec_out[key] = value
                continue
            if key.startswith("__dbfbridge_"):
                preserved = _preserved_dbfbridge_metadata(
                    key,
                    value,
                    schema,
                    memo_mode=str(table_dict.options.get("memo_mode", "mask")),
                )
                if preserved is not None:
                    rec_out[key] = preserved
                continue
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


def _preserved_dbfbridge_metadata(
    key: str,
    value: Any,
    schema: TableSchema,
    *,
    memo_mode: str,
) -> Any | None:
    """Zachowuje surową reprezentację wyłącznie pól nietransformowanych.

    Usunięcie całego ``raw_text_fields`` powodowało m.in. utratę nietypowej,
    lecz poprawnej w źródle reprezentacji ``-32`` w polu ``N(4,1)``. Pełny
    ``raw_record`` nadal musi zostać usunięty, bo nadpisałby anonimizowane pola.
    """

    if key == RAW_RECORD_KEY:
        return None
    if key == RAW_TEXT_FIELDS_KEY and isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for field_name, raw_value in value.items():
            field = schema.field_by_name(str(field_name))
            if field is None or field.is_numeric or field.is_logical:
                safe[str(field_name)] = raw_value
        return safe or None
    if key == BINARY_MEMO_FIELDS_KEY and memo_mode == "keep":
        return value
    return None


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
