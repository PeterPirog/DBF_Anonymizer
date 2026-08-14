"""Starszy słownik JSON per nazwa tabeli DBF (zgodność formatów v1/v2).

Słownik przechowuje:
- metadane tabel o tej samej nazwie (ścieżki względne i opcje anonimizacji),
- per-pole: typ, czy unikatowe, mapowanie oryginał↔anonim (dla C/M),
  offset dni (dla D/T), tryb (dla M/G).

Nowy pipeline zapisuje jeden globalny plik SQLite. Ten moduł pozostaje potrzebny
do recovery wcześniejszych wyników i dla zgodności publicznego API. Słownik jest
SENSITIWNY — musi być w .gitignore i nie może być wysyłany na GitHub.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
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
    memo_originals: list[Any] = field(default_factory=list)
    # W słowniku współdzielonym memo musi być odtwarzane osobno dla każdego
    # pliku, ponieważ po anonimizacji wszystkie niepuste wartości mają postać
    # ``MEMO``. Kluczem jest znormalizowana ścieżka względna (POSIX).
    memo_originals_by_path: dict[str, list[Any]] = field(default_factory=dict)


@dataclass
class TableDict:
    """Słownik współdzielony przez tabele DBF o tej samej nazwie."""
    table: str                  # nazwa pliku np. "bok.dbf"
    relative_path: str          # pierwsza ścieżka (zgodność ze starszym formatem)
    options: dict[str, Any] = field(default_factory=dict)
    fields: dict[str, FieldDict] = field(default_factory=dict)
    relative_paths: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "version": 2,
            "table": self.table,
            "relative_path": self.relative_path,
            "relative_paths": self.relative_paths or ([self.relative_path] if self.relative_path else []),
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
                    "memo_originals_by_path": fd.memo_originals_by_path,
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
                memo_originals_by_path={
                    normalize_relative_path(path): list(values or [])
                    for path, values in (fd_data.get("memo_originals_by_path") or {}).items()
                },
            )
        relative_path = normalize_relative_path(data.get("relative_path", ""))
        relative_paths = [
            normalize_relative_path(path)
            for path in (data.get("relative_paths") or ([relative_path] if relative_path else []))
        ]
        return cls(
            table=data.get("table", ""),
            relative_path=relative_path,
            options=dict(data.get("options") or {}),
            fields=fields,
            relative_paths=relative_paths,
        )


def normalize_relative_path(path: str | Path) -> str:
    """Normalizuje klucz pliku w słowniku niezależnie od systemu operacyjnego."""
    raw = str(path).replace("\\", "/")
    return PurePosixPath(raw).as_posix() if raw else ""


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
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(table_dict.to_json(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(path)
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
