"""Globalny, odwracalny słownik SQLite dla całej bazy DBF.

Jeden plik SQLite przechowuje mapowanie tekstu niezależne od tabeli i pola,
oryginały memo indeksowane ścieżką oraz parametry transformacji. Podczas budowy
działa jeden writer; procesy kodujące i dekodujące otwierają bazę read-only.
"""
from __future__ import annotations

import codecs
import hashlib
import json
import logging
import math
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .dictionary import FieldDict, TableDict, normalize_relative_path
from .schema import TableSchema
from .transforms import _byte_len

GLOBAL_DICTIONARY_FILENAME = "dictionary.sqlite3"
GLOBAL_DICTIONARY_VERSION = 4
_SUPPORTED_DICTIONARY_VERSIONS = {3, GLOBAL_DICTIONARY_VERSION}
_LEGACY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_ALPHABET_PRIORITY = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    + "".join(chr(codepoint) for codepoint in range(33, 127))
)
_QUERY_BATCH_SIZE = 900
_WRITE_BATCH_SIZE = 10_000
logger = logging.getLogger(__name__)


class GlobalDictionaryError(RuntimeError):
    """Błąd spójności lub pojemności globalnego słownika."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "GLOBAL_DICTIONARY_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.details = details or {}
        detail_text = " ".join(
            f"{key}={_log_value(value)}"
            for key, value in sorted(self.details.items())
        )
        rendered = f"[{code}] {message}"
        if detail_text:
            rendered = f"{rendered} | {detail_text}"
        super().__init__(rendered)


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
            self.connection.execute("PRAGMA temp_store = MEMORY")
            self.connection.execute("PRAGMA cache_size = -131072")
            self.connection.execute("PRAGMA mmap_size = 268435456")
        self.connection.row_factory = sqlite3.Row

    def __enter__(self) -> "GlobalDictionaryStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is None:
            self.connection.commit()
        elif self.connection.in_transaction:
            self.connection.rollback()
        self.connection.close()

    def initialize(
        self,
        *,
        options: dict[str, Any],
        salt: str,
        text_encodings: Iterable[str] = ("cp1250",),
        text_alphabet: str | None = None,
    ) -> None:
        """Tworzy schemat nowego słownika i zapisuje parametry transformacji."""
        encodings = normalize_encodings(text_encodings)
        alphabet = text_alphabet or build_common_single_byte_alphabet(encodings)
        if not alphabet:
            raise GlobalDictionaryError(
                "Brak wspólnych drukowalnych znaków jednobajtowych dla kodowań",
                code="EMPTY_TEXT_ALPHABET",
                details={"encodings": ",".join(encodings)},
            )
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

            CREATE TABLE text_sources (
                original TEXT NOT NULL COLLATE BINARY,
                relative_path TEXT NOT NULL,
                field_name TEXT NOT NULL,
                encoding TEXT NOT NULL,
                byte_length INTEGER NOT NULL CHECK (byte_length > 0),
                PRIMARY KEY (original, relative_path, field_name)
            ) WITHOUT ROWID;

            CREATE INDEX text_sources_length
                ON text_sources(byte_length, relative_path, field_name);

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
            "text_encodings": encodings,
            "text_alphabet": alphabet,
            "text_alphabet_size": len(alphabet),
        }
        self.connection.executemany(
            "INSERT INTO metadata(key, value_json) VALUES (?, ?)",
            [
                (key, json.dumps(value, ensure_ascii=False, separators=(",", ":")))
                for key, value in metadata.items()
            ],
        )
        self.connection.commit()

    def prepare_incremental(
        self,
        *,
        options: dict[str, Any],
        salt: str,
        text_encodings: Iterable[str],
    ) -> None:
        """Zachowuje mapę C i rozpoczyna nową, zgodną generację konwersji.

        Informacje zależne od konkretnego zestawu plików i pozycyjne memo są
        czyszczone. Istniejące pary ``original↔anonymized`` pozostają, dzięki
        czemu kolejne konwersje z tą samą konfiguracją są stabilne.
        """

        current = self.options()
        expected = {
            "memo_mode": options.get("memo_mode", "mask"),
            "date_offset_days": int(options.get("date_offset_days", 0)),
            "text_mode": options.get("text_mode", "same_length"),
            "salt_sha256": hashlib.sha256(salt.encode("utf-8")).hexdigest(),
            "text_encodings": normalize_encodings(text_encodings),
        }
        mismatches = {
            key: {"stored": current.get(key), "requested": value}
            for key, value in expected.items()
            if current.get(key) != value
        }
        if mismatches:
            raise GlobalDictionaryError(
                "Nie można rozszerzyć słownika z inną konfiguracją",
                code="INCREMENTAL_DICTIONARY_CONFIG_MISMATCH",
                details={"keys": ",".join(sorted(mismatches))},
            )
        self.connection.execute("DELETE FROM files")
        self.connection.execute("DELETE FROM text_sources")
        self.connection.execute("DELETE FROM memo_values")
        self.connection.commit()

    def options(self) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT key, value_json FROM metadata"
        ).fetchall()
        values = {row["key"]: json.loads(row["value_json"]) for row in rows}
        version = int(values.get("schema_version", 0))
        if version not in _SUPPORTED_DICTIONARY_VERSIONS:
            raise GlobalDictionaryError(
                f"Nieobsługiwana wersja słownika SQLite: {version}",
                code="UNSUPPORTED_DICTIONARY_VERSION",
                details={"version": version},
            )
        return values

    def text_alphabet(self) -> str:
        """Zwraca alfabet pseudonimów zapisany razem ze słownikiem."""
        options = self.options()
        return str(options.get("text_alphabet") or _LEGACY_ALPHABET)

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

    def add_text_values(
        self,
        values: Iterable[Any],
        *,
        encoding: str = "cp1250",
        relative_path: str = "<unknown>",
        field_name: str = "<unknown>",
    ) -> int:
        """Dodaje wartości C wraz z bezpiecznym kontekstem diagnostycznym.

        Zwraca liczbę różnych niepustych wartości znalezionych w danym polu.
        Pełne wartości pozostają wyłącznie w sensytywnym SQLite; komunikaty błędów
        zawierają ścieżkę/pole/liczności, ale nie dane osobowe.
        """
        normalized_encoding = normalize_encoding(encoding)
        path = normalize_relative_path(relative_path)
        normalized = sorted(
            {str(value) for value in values if value is not None and value != ""}
        )
        rows: list[tuple[str, int]] = []
        for value in normalized:
            try:
                byte_length = _byte_len(value, normalized_encoding)
            except UnicodeEncodeError as exc:
                raise GlobalDictionaryError(
                    "Wartość tekstowa nie jest reprezentowalna w stronie kodowej DBF",
                    code="TEXT_ENCODING_ERROR",
                    details={
                        "encoding": normalized_encoding,
                        "field": field_name,
                        "path": path,
                        "value_sha256": hashlib.sha256(
                            value.encode("utf-8")
                        ).hexdigest()[:16],
                    },
                ) from exc
            if byte_length <= 0:
                continue
            rows.append((value, byte_length))

        existing_lengths = self._existing_text_lengths([value for value, _ in rows])
        for value, byte_length in rows:
            existing_length = existing_lengths.get(value)
            if existing_length is not None and existing_length != byte_length:
                raise GlobalDictionaryError(
                    "Ta sama wartość ma różną długość bajtową w używanych kodowaniach",
                    code="INCONSISTENT_TEXT_BYTE_LENGTH",
                    details={
                        "current_encoding": normalized_encoding,
                        "current_length": byte_length,
                        "existing_length": existing_length,
                        "field": field_name,
                        "path": path,
                        "value_sha256": hashlib.sha256(
                            value.encode("utf-8")
                        ).hexdigest()[:16],
                    },
                )
        self.connection.executemany(
            "INSERT OR IGNORE INTO text_map(original, byte_length) VALUES (?, ?)",
            rows,
        )
        self.connection.executemany(
            """
            INSERT OR IGNORE INTO text_sources(
                original, relative_path, field_name, encoding, byte_length
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (value, path, field_name, normalized_encoding, byte_length)
                for value, byte_length in rows
            ],
        )
        return len(rows)

    def _existing_text_lengths(self, values: list[str]) -> dict[str, int]:
        result: dict[str, int] = {}
        for offset in range(0, len(values), _QUERY_BATCH_SIZE):
            batch = values[offset:offset + _QUERY_BATCH_SIZE]
            if not batch:
                continue
            placeholders = ",".join("?" for _ in batch)
            rows = self.connection.execute(
                f"SELECT original, byte_length FROM text_map "
                f"WHERE original IN ({placeholders})",
                batch,
            ).fetchall()
            result.update(
                {str(row["original"]): int(row["byte_length"]) for row in rows}
            )
        return result

    def add_memo_values(
        self,
        relative_path: str,
        field_name: str,
        values: Iterable[Any],
        *,
        start_index: int = 0,
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
                for index, value in enumerate(values, start=start_index)
            ),
        )

    def assign_anonymous_values(self, *, salt: str) -> None:
        """Nadaje odwracalne, globalnie unikalne pseudonimy wszystkim tekstom."""
        alphabet = self.text_alphabet()
        counts = self.connection.execute(
            "SELECT byte_length, COUNT(*) AS count FROM text_map GROUP BY byte_length"
        ).fetchall()
        for row in counts:
            length = int(row["byte_length"])
            count = int(row["count"])
            capacity = len(alphabet) ** length
            logger.info(
                "phase=dictionary event=capacity_check byte_length=%d "
                "distinct_values=%d alphabet_size=%d capacity=%d",
                length,
                count,
                len(alphabet),
                capacity,
            )
            if count > capacity:
                sources = self._capacity_sources(length)
                raise GlobalDictionaryError(
                    "Za mała przestrzeń pseudonimów dla odwracalnego mapowania",
                    code="TEXT_DOMAIN_CAPACITY",
                    details={
                        "alphabet_size": len(alphabet),
                        "byte_length": length,
                        "capacity": capacity,
                        "distinct_values": count,
                        "encodings": ",".join(
                            str(item)
                            for item in self.options().get("text_encodings", [])
                        ),
                        "sources": sources,
                    },
                )

        while True:
            pending = self.connection.execute(
                """
                SELECT original, byte_length
                FROM text_map
                WHERE anonymized IS NULL
                ORDER BY byte_length, original COLLATE BINARY
                LIMIT ?
                """
                , (_WRITE_BATCH_SIZE,)
            ).fetchall()
            if not pending:
                break
            for row in pending:
                original = str(row["original"])
                length = int(row["byte_length"])
                capacity = len(alphabet) ** length
                start, step = _probe_parameters(original, salt, capacity)
                max_attempts = capacity if capacity <= 1_000_000 else 1_000_000
                for attempt in range(max_attempts):
                    candidate = _encode_index(
                        (start + attempt * step) % capacity,
                        length,
                        alphabet,
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
                        "Nie znaleziono wolnego pseudonimu mimo dostępnej pojemności",
                        code="TEXT_DOMAIN_EXHAUSTED",
                        details={
                            "alphabet_size": len(alphabet),
                            "byte_length": length,
                            "max_attempts": max_attempts,
                        },
                    )
            self.connection.commit()
        self._remove_fixed_points(salt=salt, alphabet=alphabet)
        self.connection.commit()

    def _capacity_sources(self, byte_length: int, limit: int = 12) -> str:
        rows = self.connection.execute(
            """
            SELECT relative_path, field_name, encoding, COUNT(*) AS value_count
            FROM text_sources
            WHERE byte_length = ?
            GROUP BY relative_path, field_name, encoding
            ORDER BY value_count DESC, relative_path, field_name
            LIMIT ?
            """,
            (byte_length, limit),
        ).fetchall()
        if not rows:
            return "unavailable"
        return ";".join(
            f"{row['relative_path']}:{row['field_name']}:{row['encoding']}:{row['value_count']}"
            for row in rows
        )

    def _remove_fixed_points(self, *, salt: str, alphabet: str) -> None:
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

            capacity = len(alphabet) ** length
            start, step = _probe_parameters(original, f"{salt}\0derangement", capacity)
            max_attempts = capacity if capacity <= 1_000_000 else 1_000_000
            replacement: str | None = None
            for attempt in range(max_attempts):
                candidate = _encode_index(
                    (start + attempt * step) % capacity,
                    length,
                    alphabet,
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
                    "Nie można usunąć pseudonimu identycznego z oryginałem",
                    code="TEXT_DERANGEMENT_FAILED",
                    details={"byte_length": length},
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
            fingerprints = ",".join(
                hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
                for value in sorted(missing)[:3]
            )
            raise GlobalDictionaryError(
                "Brak wartości w globalnym słowniku",
                code="GLOBAL_MAPPING_MISSING",
                details={"count": len(missing), "value_sha256": fingerprints},
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

    def memo_values_range(
        self,
        relative_path: str,
        field_name: str,
        *,
        start: int,
        count: int,
    ) -> list[Any]:
        """Czyta dokładnie jedną partię pozycyjnych wartości memo."""

        if start < 0 or count < 0:
            raise ValueError("start i count muszą być nieujemne")
        rows = self.connection.execute(
            """
            SELECT record_index, value_json
            FROM memo_values
            WHERE relative_path = ? AND field_name = ?
              AND record_index >= ? AND record_index < ?
            ORDER BY record_index
            """,
            (
                normalize_relative_path(relative_path),
                field_name,
                start,
                start + count,
            ),
        ).fetchall()
        expected_indexes = list(range(start, start + count))
        actual_indexes = [int(row["record_index"]) for row in rows]
        if actual_indexes != expected_indexes:
            raise GlobalDictionaryError(
                "Brak ciągłej partii wartości memo",
                code="MEMO_RANGE_MISSING",
                details={
                    "path": normalize_relative_path(relative_path),
                    "field": field_name,
                    "start": start,
                    "count": count,
                    "found": len(rows),
                },
            )
        return [json.loads(row["value_json"]) for row in rows]

    def table_dictionary(
        self,
        schema: TableSchema,
        relative_path: str,
        *,
        include_memo_values: bool = True,
    ) -> TableDict:
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
                if field_dict.memo_mode == "mask" and include_memo_values:
                    field_dict.memo_originals_by_path[path] = self.memo_values(
                        path, field.name
                    )
            elif field.is_date or field.is_datetime:
                field_dict.offset_days = int(options.get("date_offset_days", 0))
            table_dict.fields[field.name] = field_dict
        return table_dict


def global_dictionary_path(dictionary_dir: str | Path) -> Path:
    return Path(dictionary_dir) / GLOBAL_DICTIONARY_FILENAME


def normalize_encoding(encoding: str) -> str:
    """Normalizuje nazwę strony kodowej zgodnie z rejestrem kodeków Pythona."""
    raw = str(encoding or "").strip()
    if not raw or raw.casefold() in {"auto", "unknown", "none"}:
        raise GlobalDictionaryError(
            "Schemat DBF nie zawiera jednoznacznej strony kodowej",
            code="UNKNOWN_TEXT_ENCODING",
            details={"encoding": raw or "<empty>"},
        )
    try:
        return codecs.lookup(raw).name
    except LookupError as exc:
        raise GlobalDictionaryError(
            "Python nie obsługuje strony kodowej podanej przez schemat DBF",
            code="UNSUPPORTED_TEXT_ENCODING",
            details={"encoding": raw},
        ) from exc


def normalize_encodings(encodings: Iterable[str]) -> list[str]:
    normalized = sorted({normalize_encoding(encoding) for encoding in encodings})
    if not normalized:
        raise GlobalDictionaryError(
            "Nie znaleziono kodowania dla pól tekstowych DBF",
            code="NO_TEXT_ENCODINGS",
        )
    return normalized


def build_common_single_byte_alphabet(encodings: Iterable[str]) -> str:
    """Buduje drukowalny alfabet 1-bajtowy wspólny dla stron kodowych.

    Usuwamy białe i kontrolne znaki, ponieważ końcowa spacja pola C może zostać
    obcięta przez czytnik DBF. Usuwamy też duplikaty ``casefold``, aby nie
    wprowadzać oczywistych par A/a do indeksów używających porównań bez wielkości
    liter. Pozostałe znaki, w tym interpunkcja i znaki narodowe, są dozwolone.
    """
    normalized = normalize_encodings(encodings)
    per_encoding: list[set[str]] = []
    for encoding in normalized:
        characters: set[str] = set()
        for byte_value in range(1, 256):
            raw = bytes([byte_value])
            try:
                character = raw.decode(encoding, errors="strict")
                if (
                    len(character) == 1
                    and character.isprintable()
                    and not character.isspace()
                    and character.encode(encoding, errors="strict") == raw
                ):
                    characters.add(character)
            except UnicodeError:
                continue
        per_encoding.append(characters)

    common = set.intersection(*per_encoding)
    ordered_candidates = list(_ALPHABET_PRIORITY) + sorted(common, key=ord)
    alphabet: list[str] = []
    seen_casefold: set[str] = set()
    for character in ordered_candidates:
        folded = character.casefold()
        if character not in common or folded in seen_casefold:
            continue
        seen_casefold.add(folded)
        alphabet.append(character)
    return "".join(alphabet)


def _probe_parameters(value: str, salt: str, capacity: int) -> tuple[int, int]:
    payload = f"{salt}\0{value}".encode("utf-8")
    start = int.from_bytes(hashlib.sha256(b"start\0" + payload).digest(), "big") % capacity
    step = int.from_bytes(hashlib.sha256(b"step\0" + payload).digest(), "big") % capacity
    step = step or 1
    while math.gcd(step, capacity) != 1:
        step = (step + 1) % capacity or 1
    return start, step


def _encode_index(index: int, length: int, alphabet: str) -> str:
    chars = [alphabet[0]] * length
    base = len(alphabet)
    for position in range(length - 1, -1, -1):
        index, remainder = divmod(index, base)
        chars[position] = alphabet[remainder]
    return "".join(chars)


def _log_value(value: Any) -> str:
    text = str(value)
    return json.dumps(text, ensure_ascii=False, separators=(",", ":"))
