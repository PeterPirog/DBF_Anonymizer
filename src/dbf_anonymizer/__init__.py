"""DBF_Anonymizer — framework do anonimizacji plików DBF (Visual FoxPro).

Public API:
    from dbf_anonymizer import anonymize_directory, make_dbf_recovery, self_test

Anonimizacja zastępuje wartości tekstowe ciągami o identycznej długości bajtowej,
zachowuje unikalność kolumn unikatowych, pola N/F/L pozostawia bez zmian,
daty/czas przesuwa o stałą liczbę dni, a pola M/G maskuje ('MEMO') lub zachowuje.
Słownik (dictionary_*.json) pozwala odtworzyć oryginalne dane — jest SENSITIWNY
i musi być w .gitignore.
"""
from __future__ import annotations

from .anonymizer import AnonymizeOptions, anonymize_records, recover_records
from .dictionary import (
    FieldDict,
    TableDict,
    dictionary_filename,
    load_dictionary,
    save_dictionary,
)
from .pipeline import (
    AnonymizeResult,
    RecoveryResult,
    SelfTestReport,
    TableOutcome,
    anonymize_directory,
    make_dbf_recovery,
    self_test,
)
from .schema import FieldInfo, TableSchema, load_schema
from .transforms import mask_char, mask_memo, shift_date, shift_datetime

__all__ = [
    # Pipeline (główne API)
    "anonymize_directory",
    "make_dbf_recovery",
    "self_test",
    # Typy wyników
    "AnonymizeResult",
    "RecoveryResult",
    "SelfTestReport",
    "TableOutcome",
    # Opcje i per-tabela
    "AnonymizeOptions",
    "anonymize_records",
    "recover_records",
    # Słownik
    "FieldDict",
    "TableDict",
    "dictionary_filename",
    "save_dictionary",
    "load_dictionary",
    # Schema
    "FieldInfo",
    "TableSchema",
    "load_schema",
    # Transforms
    "mask_char",
    "mask_memo",
    "shift_date",
    "shift_datetime",
]

__version__ = "0.1.0"
