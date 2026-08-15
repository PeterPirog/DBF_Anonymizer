"""Ładowanie schematu DBF z pliku _schema.json generowanego przez dbfbridge.

Schemat zawiera metadane tabeli (kodowanie, memo) oraz listę pól z typami DBF
(C/N/D/L/M/T/G/F) i długościami. Używane do determinacji strategii anonimizacji
per pole.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .vfp import MEMO_FILE_FLAG, STRUCTURAL_CDX_FLAG

# Typy DBF: C=Character, N=Numeric, F=Float, D=Date, T=DateTime, L=Logical,
# M=Memo, G=General (Binary). Wszystkie inne traktujemy jako identity.
TEXT_TYPES = {"C"}
MEMO_TYPES = {"M", "G"}
DATE_TYPES = {"D"}
DATETIME_TYPES = {"T"}
NUMERIC_TYPES = {"N", "F"}
LOGICAL_TYPES = {"L"}


@dataclass(frozen=True)
class FieldInfo:
    """Opis jednego pola DBF."""
    name: str            # UPPER CASE, nazwa pola
    dbf_type: str        # C/N/D/L/M/T/G/F
    length: int          # długość w bajtach (dla C = max znaków cp1250)
    decimal: int | None  # ułamki (dla N/F)

    @property
    def is_text(self) -> bool:
        return self.dbf_type in TEXT_TYPES

    @property
    def is_memo(self) -> bool:
        return self.dbf_type in MEMO_TYPES

    @property
    def is_date(self) -> bool:
        return self.dbf_type in DATE_TYPES

    @property
    def is_datetime(self) -> bool:
        return self.dbf_type in DATETIME_TYPES

    @property
    def is_numeric(self) -> bool:
        return self.dbf_type in NUMERIC_TYPES

    @property
    def is_logical(self) -> bool:
        return self.dbf_type in LOGICAL_TYPES


@dataclass(frozen=True)
class TableSchema:
    """Opis tabeli DBF z _schema.json."""
    table_name: str          # np. "test.dbf"
    relative_path: str       # ścieżka względem źródła (np. "sub/test.dbf")
    encoding: str            # kodowanie (cp1250 / mazovia / auto)
    has_memo: bool           # czy tabela ma pola memo (.fpt)
    fields: tuple[FieldInfo, ...]
    # dbfbridge zachowuje pod tą historyczną nazwą cały bajt flag tabeli:
    # 0x01=CDX, 0x02=FPT, 0x04=DBC. Pole pozostaje dla zgodności schematu.
    structural_index_flag: int = 0

    def field_by_name(self, name: str) -> FieldInfo | None:
        """Zwraca FieldInfo po nazwie (case-insensitive)."""
        upper = name.upper()
        for f in self.fields:
            if f.name == upper:
                return f
        return None

    @property
    def data_field_names(self) -> tuple[str, ...]:
        """Nazwy pól danych (pomijaj __dbfbridge_*, __deleted__)."""
        return tuple(f.name for f in self.fields)

    @property
    def table_flags(self) -> int:
        """Pełna maska flag tabeli VFP z bajtu 28 nagłówka."""

        return self.structural_index_flag

    @property
    def has_structural_cdx(self) -> bool:
        return bool(self.table_flags & STRUCTURAL_CDX_FLAG)

    @property
    def has_memo_file_flag(self) -> bool:
        return bool(self.table_flags & MEMO_FILE_FLAG)


def load_schema(schema_path: Path) -> TableSchema:
    """Wczytuje _schema.json z dbfbridge → TableSchema."""
    data: dict[str, Any] = json.loads(schema_path.read_text(encoding="utf-8"))
    table_name = data.get("table") or schema_path.stem.replace("_schema", "")
    relative_path = data.get("relative_path") or table_name

    dbf_meta = data.get("dbf", {}) or {}
    encoding = data.get("text_encoding", "cp1250")
    if isinstance(encoding, dict):
        encoding = str(
            encoding.get("declared_or_detected_encoding")
            or encoding.get("codepage")
            or dbf_meta.get("encoding")
            or "cp1250"
        )

    memo_meta = data.get("memo", {}) or {}
    has_memo = bool(memo_meta.get("has_memo") or memo_meta.get("present") or
                    any(f.get("dbf_type") in MEMO_TYPES for f in data.get("fields", [])))

    fields_list: list[FieldInfo] = []
    for fld in data.get("fields", []) or []:
        name = str(fld.get("name", "")).upper()
        if not name:
            continue
        dbf_type = str(fld.get("dbf_type") or fld.get("type") or "").upper()
        length = int(fld.get("length") or 0)
        decimal_raw = fld.get("decimal_count")
        if decimal_raw is None:
            # Zgodność ze starszymi, ręcznie tworzonymi schematami.
            decimal_raw = fld.get("decimal")
        decimal = int(decimal_raw) if decimal_raw is not None else None
        fields_list.append(FieldInfo(name=name, dbf_type=dbf_type, length=length, decimal=decimal))

    return TableSchema(
        table_name=table_name,
        relative_path=relative_path,
        encoding=str(encoding),
        has_memo=has_memo,
        fields=tuple(fields_list),
        structural_index_flag=int(dbf_meta.get("structural_index_flag") or 0),
    )


def is_data_record(record: dict[str, Any]) -> bool:
    """Czy rekord JSONL to dane (nie summary/table report dbfbridge)?"""
    return record.get("type") not in ("summary", "table")


RAW_RECORD_KEY = "__dbfbridge_raw_record__"
RAW_TEXT_FIELDS_KEY = "__dbfbridge_raw_text_fields__"
BINARY_MEMO_FIELDS_KEY = "__dbfbridge_binary_memo_fields__"
DELETED_KEY = "__deleted__"


def is_structural_key(key: str) -> bool:
    """Czy klucz to metadane dbfbridge (nie pole danych)?"""
    return key.startswith("__dbfbridge_") or key == DELETED_KEY
