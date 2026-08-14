"""Słownik kodujący per-tabela — zapis/odczyt dictionary_[nazwa].json.

Słownik przechowuje:
- metadane tabeli (nazwa, opcje anonimizacji, offset dni),
- per-pole: typ, czy unikatowe, mapowanie oryginał↔anonim (dla C/M),
  offset dni (dla D/T), tryb (dla M/G).

Słownik jest SENSITIWNY (pozwala odtworzyć oryginalne dane) — musi być
w .gitignore i nie wysyłany na GitHub.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .uniqueness import ColumnMapping


@dataclass
class FieldDict:
    """Słownik dla jednego pola."""
    name: str
    dbf_type: str
    unique: bool = False        # dla C
    # oryginał → anonim (anonymize) / anonim → oryginał zależy od kierunku
    values: dict[str, str] = field(default_factory=dict)
    # dla D/T:
    offset_days: int = 0
    # dla M/G:
    memo_mode: str = "mask"     # 'mask' lub 'keep'
    # dla M/G w trybie mask: oryginalne wartości w kolejności rekordów
    # ( Recovery przywraca pozycyjnie, bo wszystkie stały się 'MEMO'. )
    memo_originals: list[str] = field(default_factory=list)


@dataclass
class TableDict:
    """Słownik dla jednej tabeli DBF."""
    table: str                  # nazwa pliku np. "bok.dbf"
    relative_path: str          # ścieżka względem źródła
    options: dict[str, Any] = field(default_factory=dict)
    fields: dict[str, FieldDict] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "relative_path": self.relative_path,
            "options": self.options,
            "fields": {
                name: {
                    "name": fd.name,
                    "dbf_type": fd.dbf_type,
                    "unique": fd.unique,
                    "values": fd.values,
                    "offset_days": fd.offset_days,
                    "memo_mode": fd.memo_mode,
                    "memo_originals": fd.memo_originals,
                }
                for name, fd in self.fields.items()
            },
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TableDict":
        fields: dict[str, FieldDict] = {}
        for fname, fd_data in (data.get("fields") or {}).items():
            fields[fname] = FieldDict(
                name=fd_data.get("name", fname),
                dbf_type=fd_data.get("dbf_type", ""),
                unique=fd_data.get("unique", False),
                values=dict(fd_data.get("values") or {}),
                offset_days=int(fd_data.get("offset_days") or 0),
                memo_mode=fd_data.get("memo_mode", "mask"),
                memo_originals=list(fd_data.get("memo_originals") or []),
            )
        return cls(
            table=data.get("table", ""),
            relative_path=data.get("relative_path", ""),
            options=dict(data.get("options") or {}),
            fields=fields,
        )


def dictionary_filename(table_name: str) -> str:
    """Zwraca nazwę pliku słownika dla tabeli: dictionary_[nazwa].json.

    nazwa bez rozszerzenia .dbf, lowercase dla spójności.
    """
    stem = table_name
    if stem.lower().endswith(".dbf"):
        stem = stem[:-4]
    return f"dictionary_{stem.lower()}.json"


def save_dictionary(table_dict: TableDict, dict_dir: Path) -> Path:
    """Zapisuje słownik tabeli do dict_dir/dictionary_[nazwa].json."""
    dict_dir.mkdir(parents=True, exist_ok=True)
    fname = dictionary_filename(table_dict.table)
    path = dict_dir / fname
    path.write_text(
        json.dumps(table_dict.to_json(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def load_dictionary(table_name: str, dict_dir: Path) -> TableDict | None:
    """Wczytuje słownik tabeli. Zwraca None jeśli plik nie istnieje."""
    fname = dictionary_filename(table_name)
    path = dict_dir / fname
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return TableDict.from_json(data)


def load_all_dictionaries(dict_dir: Path) -> dict[str, TableDict]:
    """Wczytuje wszystkie słowniki z dict_dir. Zwraca map table_name→TableDict."""
    result: dict[str, TableDict] = {}
    if not dict_dir.exists():
        return result
    for p in dict_dir.glob("dictionary_*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            td = TableDict.from_json(data)
            if td.table:
                result[td.table] = td
        except (json.JSONDecodeError, KeyError):
            continue
    return result


def column_mapping_to_field_dict(
    field_name: str,
    dbf_type: str,
    mapping: ColumnMapping,
) -> FieldDict:
    """Konwertuje ColumnMapping (uniqueness) na FieldDict (słownik)."""
    return FieldDict(
        name=field_name,
        dbf_type=dbf_type,
        unique=mapping.unique,
        values=dict(mapping.forward),
    )


def reverse_field_dict_values(fd: FieldDict) -> dict[str, str]:
    """Odwraca mapowanie values (anonim→oryginał) dla recovery."""
    return {v: k for k, v in fd.values.items()}
