"""Strumieniowe skanowanie i transformowanie eksportów JSONL tabel DBF."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .anonymizer import AnonymizeOptions, anonymize_records, recover_records
from .global_store import GlobalDictionaryStore
from .jsonstream import atomic_jsonl_writer, batched, iter_jsonl, write_records
from .rawpatch import make_numeric_values_reconstructable
from .schema import TableSchema, is_data_record


def count_data_records(path: str | Path) -> int:
    """Liczy rekordy danych bez utrzymywania tabeli w pamięci."""

    return sum(1 for record in iter_jsonl(path) if is_data_record(record))


def scan_table_into_store(
    store: GlobalDictionaryStore,
    *,
    jsonl_path: str | Path,
    schema: TableSchema,
    relative_path: str,
    memo_mode: str,
    batch_size: int = 5000,
) -> tuple[int, int]:
    """Dodaje wartości tabeli do SQLite partiami o ograniczonym rozmiarze.

    Zwraca ``(liczba_rekordów, liczba_wartości_pól_tekstowych_w_partiach)``.
    Druga liczba jest diagnostyczna; globalna deduplikacja odbywa się w SQLite.
    """

    text_fields = tuple(field for field in schema.fields if field.is_text)
    memo_fields = tuple(field for field in schema.fields if field.is_memo)
    record_count = 0
    text_values = 0
    for batch in batched(
        (record for record in iter_jsonl(jsonl_path) if is_data_record(record)),
        batch_size,
    ):
        batch_start = record_count
        for field in text_fields:
            text_values += store.add_text_values(
                (record.get(field.name) for record in batch),
                encoding=schema.encoding,
                relative_path=relative_path,
                field_name=field.name,
            )
        if memo_mode == "mask":
            for field in memo_fields:
                store.add_memo_values(
                    relative_path,
                    field.name,
                    (record.get(field.name) for record in batch),
                    start_index=batch_start,
                )
        record_count += len(batch)
    return record_count, text_values


def anonymize_jsonl(
    *,
    source_path: str | Path,
    target_path: str | Path,
    schema: TableSchema,
    store: GlobalDictionaryStore,
    options: AnonymizeOptions,
    batch_size: int = 5000,
) -> int:
    """Anonimizuje JSONL partiami, pobierając tylko mapowania danej partii."""

    count = 0
    with atomic_jsonl_writer(target_path) as outfile:
        for batch in batched(iter_jsonl(source_path), batch_size):
            text_values = _text_values(batch, schema)
            mapping = store.forward_many(text_values)
            transformed, _ = anonymize_records(
                schema,
                batch,
                options,
                global_text_mapping=mapping,
            )
            transformed, _ = make_numeric_values_reconstructable(transformed, schema)
            count += write_records(outfile, transformed)
    return count


def recover_jsonl(
    *,
    source_path: str | Path,
    target_path: str | Path,
    schema: TableSchema,
    relative_path: str,
    store: GlobalDictionaryStore,
    batch_size: int = 5000,
) -> int:
    """Odtwarza JSONL partiami, łącznie z pozycyjnymi wartościami memo."""

    count = 0
    data_offset = 0
    table_dict = store.table_dictionary(
        schema,
        relative_path,
        include_memo_values=False,
    )
    memo_fields = tuple(
        field for field in schema.fields
        if field.is_memo and table_dict.fields[field.name].memo_mode == "mask"
    )
    with atomic_jsonl_writer(target_path) as outfile:
        for batch in batched(iter_jsonl(source_path), batch_size):
            data_batch = [record for record in batch if is_data_record(record)]
            reverse = store.reverse_many(_text_values(data_batch, schema))
            memo_originals = {
                field.name: store.memo_values_range(
                    relative_path,
                    field.name,
                    start=data_offset,
                    count=len(data_batch),
                )
                for field in memo_fields
            }
            transformed = recover_records(
                schema,
                batch,
                table_dict,
                relative_path=relative_path,
                global_reverse_mapping=reverse,
                memo_originals=memo_originals,
            )
            transformed, _ = make_numeric_values_reconstructable(transformed, schema)
            count += write_records(outfile, transformed)
            data_offset += len(data_batch)
    return count


def _text_values(
    records: Iterable[dict[str, Any]],
    schema: TableSchema,
) -> set[str]:
    fields = tuple(field for field in schema.fields if field.is_text)
    return {
        str(value)
        for record in records
        if is_data_record(record)
        for field in fields
        if (value := record.get(field.name)) not in (None, "")
    }
