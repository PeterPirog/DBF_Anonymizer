"""Globalny, odwracalny słownik SQLite dla całej bazy DBF.

Jeden plik SQLite przechowuje mapowanie tekstu niezależne od tabeli i pola,
oryginały memo indeksowane ścieżką oraz parametry transformacji. Podczas budowy
działa jeden writer; procesy kodujące i dekodujące otwierają bazę read-only.
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .dictionary import FieldDict, TableDict, normalize_relative_path
from .schema import TableSchema
from .transforms import _byte_len_cp1250

GLOBAL_DICTIONARY_FILENAME = "dictionary.sqlite3"
GLOBAL_DICTIONARY_VERSION = 3
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_QUERY_BATCH_SIZE = 800


class GlobalDictionaryError(RuntimeError):
    """Błąd spójności lub pojemności globalnego słownika."""


class GlobalDictionaryStore:
    """Cienka warstwa nad SQLite używana przez pipeline i procesy robocze."""

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = Path(path).resolve()
        if read_only:
            uri = f"{self.path.as_uri()}?mode=ro"
            self.connection = sqlite3.connect(uri, uri=True, timeout=60)
            self.connection.execute("PRAGMA query_only = ON")
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(self.path, timeout=60)
            self.connection.execute("PRAGMA journal_mode = DELETE")
            self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.row_factory = sqlite3.Row

    def __enter__(self) -> "GlobalDictionaryStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is None:
            self.connection.commit()
        elif self.connection.in_transaction:
            self.connection.rollback()
        self.connection.close()

    def initialize(self, *, options: dict[str, Any], salt: str) -> None:
        """Tworzy schemat nowego słownika i zapisuje parametry transformacji."""
        self.connection.executescript(
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE files (
                relative_path TEXT PRIMARY KEY,
                table_name TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE text_map (
                original TEXT PRIMARY KEY COLLATE BINARY,
                anonymized TEXT COLLATE BINARY,
                byte_length INTEGER NOT NULL CHECK (byte_length > 0)
            ) WITHOUT ROWID;

            CREATE UNIQUE INDEX text_map_anonymized_unique
                ON text_map(anonymized)
                WHERE anonymized IS NOT NULL;

            CREATE INDEX text_map_pending
                ON text_map(byte_length, original)
                WHERE anonymized IS NULL;

            CREATE TABLE memo_values (
                relative_path TEXT NOT NULL,
                field_name TEXT NOT NULL,
                record_index INTEGER NOT NULL,
                value_json TEXT NOT NULL,
                PRIMARY KEY (relative_path, field_name, record_index)
            ) WITHOUT ROWID;
            """
        )
        metadata = {
            "schema_version": GLOBAL_DICTIONARY_VERSION,
            "memo_mode": options.get("memo_mode", "mask"),
            "date_offset_days": int(options.get("date_offset_days", 0)),
            "text_mode": options.get("text_mode", "same_length"),
            "mapping_scope": "global_database",
            "salt_sha256": hashlib.sha256(salt.encode("utf-8")).hexdigest(),
        }
        self.connection.executemany(
            "INSERT INTO metadata(key, value_json) VALUES (?, ?)",
            [
                (key, json.dumps(value, ensure_ascii=False, separators=(",", ":")))
                for key, value in metadata.items()
            ],
        )
        self.connection.commit()

    def options(self) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT key, value_json FROM metadata"
        ).fetchall()
        values = {row["key"]: json.loads(row["value_json"]) for row in rows}
        version = int(values.get("schema_version", 0))
        if version != GLOBAL_DICTIONARY_VERSION:
            raise GlobalDictionaryError(
                f"Nieobsługiwana wersja słownika SQLite: {version}"
            )
        return values

    def commit(self) -> None:
        self.connection.commit()

    def register_file(self, relative_path: str, table_name: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO files(relative_path, table_name) VALUES (?, ?)",
            (normalize_relative_path(relative_path), table_name),
        )

    def registered_files(self) -> list[str]:
        rows = self.connection.execute(
            "SELECT relative_path FROM files ORDER BY relative_path COLLATE BINARY"
        ).fetchall()
        return [str(row["relative_path"]) for row in rows]

    def add_text_values(self, values: Iterable[Any]) -> None:
        """Dodaje unikalne niepuste wartości C bez ładowania całej mapy do RAM."""
        normalized = sorted(
            {str(value) for value in values if value is not None and value != ""}
        )
        self.connection.executemany(
            "INSERT OR IGNORE INTO text_map(original, byte_length) VALUES (?, ?)",
            [(value, _byte_len_cp1250(value)) for value in normalized],
        )

    def add_memo_values(
        self,
        relative_path: str,
        field_name: str,
        values: Iterable[Any],
    ) -> None:
        path = normalize_relative_path(relative_path)
        self.connection.executemany(
            """
            INSERT OR REPLACE INTO memo_values(
                relative_path, field_name, record_index, value_json
            ) VALUES (?, ?, ?, ?)
            """,
            (
                (
                    path,
                    field_name,
                    index,
                    json.dumps(value, ensure_ascii=False, separators=(",", ":")),
                )
                for index, value in enumerate(values)
            ),
        )

    def assign_anonymous_values(self, *, salt: str) -> None:
        """Nadaje odwracalne, globalnie unikalne pseudonimy wszystkim tekstom."""
        counts = self.connection.execute(
            "SELECT byte_length, COUNT(*) AS count FROM text_map GROUP BY byte_length"
        ).fetchall()
        for row in counts:
            length = int(row["byte_length"])
            capacity = len(_ALPHABET) ** length
            if int(row["count"]) > capacity:
                raise GlobalDictionaryError(
                    f"Za dużo różnych wartości o długości {length}: "
                    f"{row['count']} > {capacity}; odwracalne mapowanie jest niemożliwe"
                )

        while True:
            pending = self.connection.execute(
                """
                SELECT original, byte_length
                FROM text_map
                WHERE anonymized IS NULL
                ORDER BY byte_length, original COLLATE BINARY
                LIMIT 1000
                """
            ).fetchall()
            if not pending:
                break
            for row in pending:
                original = str(row["original"])
                length = int(row["byte_length"])
                capacity = len(_ALPHABET) ** length
                start, step = _probe_parameters(original, salt, capacity)
                max_attempts = capacity if capacity <= 1_000_000 else 1_000_000
                for attempt in range(max_attempts):
                    candidate = _encode_index(
                        (start + attempt * step) % capacity,
                        length,
                    )
                    try:
                        self.connection.execute(
                            "UPDATE text_map SET anonymized = ? WHERE original = ?",
                            (candidate, original),
                        )
                        break
                    except sqlite3.IntegrityError:
                        continue
                else:
                    raise GlobalDictionaryError(
                        f"Nie znaleziono wolnego pseudonimu dla wartości o długości {length}"
                    )
            self.connection.commit()
        self._remove_fixed_points(salt=salt)
        self.connection.commit()

    def _remove_fixed_points(self, *, salt: str) -> None:
        """Gwarantuje, że niepusty tekst nigdy nie mapuje się sam na siebie."""
        fixed_points = self.connection.execute(
            """
            SELECT original, byte_length
            FROM text_map
            WHERE original = anonymized
            ORDER BY byte_length, original COLLATE BINARY
            """
        ).fetchall()
        for row in fixed_points:
            original = str(row["original"])
            length = int(row["byte_length"])
            current = self.connection.execute(
                "SELECT anonymized FROM text_map WHERE original = ?",
                (original,),
            ).fetchone()
            if current is None or str(current["anonymized"]) != original:
                continue

            capacity = len(_ALPHABET) ** length
            start, step = _probe_parameters(original, f"{salt}\0derangement", capacity)
            max_attempts = capacity if capacity <= 1_000_000 else 1_000_000
            replacement: str | None = None
            for attempt in range(max_attempts):
                candidate = _encode_index(
                    (start + attempt * step) % capacity,
                    length,
                )
                if candidate == original:
                    continue
                used = self.connection.execute(
                    "SELECT 1 FROM text_map WHERE anonymized = ? LIMIT 1",
                    (candidate,),
                ).fetchone()
                if used is None:
                    replacement = candidate
                    break

            if replacement is not None:
                self.connection.execute(
                    "UPDATE text_map SET anonymized = ? WHERE original = ?",
                    (replacement, original),
                )
                continue

            # Przy całkowicie zajętej przestrzeni pseudonimów zamiana z dowolnym
            # innym rekordem usuwa punkt stały i zachowuje bijekcję.
            partner = self.connection.execute(
                """
                SELECT original, anonymized
                FROM text_map
                WHERE byte_length = ? AND original <> ?
                ORDER BY original COLLATE BINARY
                LIMIT 1
                """,
                (length, original),
            ).fetchone()
            if partner is None:
                raise GlobalDictionaryError(
                    f"Nie można zmienić pseudonimu identycznego z oryginałem "
                    f"dla długości {length}"
                )
            partner_original = str(partner["original"])
            partner_anonymized = str(partner["anonymized"])
            self.connection.execute(
                "UPDATE text_map SET anonymized = NULL WHERE original = ?",
                (original,),
            )
            self.connection.execute(
                "UPDATE text_map SET anonymized = ? WHERE original = ?",
                (original, partner_original),
            )
            self.connection.execute(
                "UPDATE text_map SET anonymized = ? WHERE original = ?",
                (partner_anonymized, original),
            )

    def forward_many(self, values: Iterable[Any]) -> dict[str, str]:
        originals = sorted(
            {str(value) for value in values if value is not None and value != ""}
        )
        return self._lookup_many(
            originals,
            source_column="original",
            target_column="anonymized",
        )

    def reverse_many(self, values: Iterable[Any]) -> dict[str, str]:
        anonymized = sorted(
            {str(value) for value in values if value is not None and value != ""}
        )
        return self._lookup_many(
            anonymized,
            source_column="anonymized",
            target_column="original",
        )

    def _lookup_many(
        self,
        values: list[str],
        *,
        source_column: str,
        target_column: str,
    ) -> dict[str, str]:
        if source_column not in {"original", "anonymized"}:
            raise ValueError(source_column)
        result: dict[str, str] = {}
        for offset in range(0, len(values), _QUERY_BATCH_SIZE):
            batch = values[offset:offset + _QUERY_BATCH_SIZE]
            placeholders = ",".join("?" for _ in batch)
            rows = self.connection.execute(
                f"SELECT {source_column}, {target_column} FROM text_map "
                f"WHERE {source_column} IN ({placeholders})",
                batch,
            ).fetchall()
            result.update(
                {str(row[source_column]): str(row[target_column]) for row in rows}
            )
        missing = set(values) - set(result)
        if missing:
            sample = ", ".join(repr(value) for value in sorted(missing)[:3])
            raise GlobalDictionaryError(
                f"Brak {len(missing)} wartości w globalnym słowniku, np. {sample}"
            )
        return result

    def memo_values(self, relative_path: str, field_name: str) -> list[Any]:
        rows = self.connection.execute(
            """
            SELECT value_json
            FROM memo_values
            WHERE relative_path = ? AND field_name = ?
            ORDER BY record_index
            """,
            (normalize_relative_path(relative_path), field_name),
        ).fetchall()
        return [json.loads(row["value_json"]) for row in rows]

    def table_dictionary(self, schema: TableSchema, relative_path: str) -> TableDict:
        """Buduje małe metadane recovery; globalna mapa C pozostaje w SQLite."""
        options = self.options()
        path = normalize_relative_path(relative_path)
        table_dict = TableDict(
            table=schema.table_name,
            relative_path=path,
            relative_paths=[path],
            options=options,
        )
        for field in schema.fields:
            field_dict = FieldDict(name=field.name, dbf_type=field.dbf_type)
            if field.is_memo:
                field_dict.memo_mode = str(options.get("memo_mode", "mask"))
                if field_dict.memo_mode == "mask":
                    field_dict.memo_originals_by_path[path] = self.memo_values(
                        path, field.name
                    )
            elif field.is_date or field.is_datetime:
                field_dict.offset_days = int(options.get("date_offset_days", 0))
            table_dict.fields[field.name] = field_dict
        return table_dict


def global_dictionary_path(dictionary_dir: str | Path) -> Path:
    return Path(dictionary_dir) / GLOBAL_DICTIONARY_FILENAME


def _probe_parameters(value: str, salt: str, capacity: int) -> tuple[int, int]:
    payload = f"{salt}\0{value}".encode("utf-8")
    start = int.from_bytes(hashlib.sha256(b"start\0" + payload).digest(), "big") % capacity
    step = int.from_bytes(hashlib.sha256(b"step\0" + payload).digest(), "big") % capacity
    step = step or 1
    while math.gcd(step, capacity) != 1:
        step = (step + 1) % capacity or 1
    return start, step


def _encode_index(index: int, length: int) -> str:
    chars = [_ALPHABET[0]] * length
    base = len(_ALPHABET)
    for position in range(length - 1, -1, -1):
        index, remainder = divmod(index, base)
        chars[position] = _ALPHABET[remainder]
    return "".join(chars)
