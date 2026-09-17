"""Protected ephemeral SQLite state of the Phase 4 two-pass engine (P4-002).

Zone B storage policy (truthful, per the Phase 4 contract):

* the spool is the EPHEMERAL, clearly NON-authoritative pass-1 state of ONE
  engine run: pass-1 observation state (text/numeric key observations) and
  the relationship evidence histograms.  The ONE authoritative RECOVERY
  vault (``dictionary.sqlite3``) stays the ONLY recovery dictionary — the
  spool has NO independent recovery semantics, NO reverse mappings and NO
  vault schema rows.
* the spool file lives ONLY in the protected vault directory (Zone B) —
  never under the source tree, the published output tree or a transfer
  bundle; it is reserved with owner-only modes (P2-009 policy, 0o600), is
  classified as SENSITIVE while it exists (it contains canonical original
  key identities needed for grouping during pass 1) and is EXPLICITLY
  cleaned after the run; cleanup failures are surfaced as typed errors.
* no secure-deletion claim is made; a crash leftover is classified as
  sensitive material: the engine refuses to start over an existing spool
  file instead of silently reusing it (typed, value-free refusal).
* the spool is never serialized publicly and never transferred; P5 transfer
  logic will exclude it by default later.

Bounded-memory design (REQ-P4-002): every dataset-sized or
distinct-value-sized state lives in SQLite tables that are read back through
streaming, index-ordered SQL queries (bounded ``MAX_SQL_BATCH`` writes,
streamed reads).  The Python-side state of every engine object is O(1):
bounded counters, small domain descriptors and bounded batch buffers only.
The multiplicity profile of one relation side is compared by STREAMING both
SQL histograms in the canonical count order — the O(distinct keys) profile
tuple is never materialized in production RAM (the P3 in-memory evidence
kernel remains the small-fixture oracle; equivalence is cross-checked).
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Iterator, Sequence

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VaultError

__all__ = [
    "MAX_RECORD_BATCH",
    "MAX_SQL_BATCH",
    "EVIDENCE_SPOOL_SCHEMA_VERSION",
    "PASS1_STATE_FILENAME",
    "PassOneSpool",
]

#: The bounded in-memory record batch of the engine (structural contract:
#: no internal buffer may grow beyond this with record count, table size or
#: distinct-key count).
MAX_RECORD_BATCH = 1024

#: The bounded SQLite parameter batch (``executemany`` chunk size).
MAX_SQL_BATCH = 512

#: The evidence/spool payload schema version (fail closed on unknown).
EVIDENCE_SPOOL_SCHEMA_VERSION = "1.0"

#: The spool filename inside the protected vault directory (Zone B).
PASS1_STATE_FILENAME = "pass1-state.sqlite3"

_SENSITIVE_SCHEMA = (
    "CREATE TABLE meta ("
    " key TEXT PRIMARY KEY,"
    " value TEXT NOT NULL)",
    "CREATE TABLE text_observation ("
    " canonical BLOB PRIMARY KEY,"
    " value_length INTEGER NOT NULL,"
    " min_width INTEGER NOT NULL)",
    "CREATE TABLE text_encoding (encoding TEXT PRIMARY KEY)",
    "CREATE TABLE numeric_observation ("
    " domain_id TEXT NOT NULL,"
    " canonical TEXT NOT NULL,"
    " PRIMARY KEY (domain_id, canonical))",
    "CREATE TABLE relation_keys ("
    " side TEXT NOT NULL,"
    " relation_id TEXT NOT NULL,"
    " role TEXT NOT NULL,"
    " canonical BLOB NOT NULL,"
    " occurrences INTEGER NOT NULL,"
    " PRIMARY KEY (side, relation_id, role, canonical))",
    "CREATE TABLE relation_side_facts ("
    " side TEXT NOT NULL,"
    " relation_id TEXT NOT NULL,"
    " role TEXT NOT NULL,"
    " rows_considered INTEGER NOT NULL,"
    " null_tuple_count INTEGER NOT NULL,"
    " PRIMARY KEY (side, relation_id, role))",
)


def _spool_failure(detail_code: str) -> VaultError:
    """A stable typed, privacy-safe spool failure (no values, no paths)."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(
            operation="engine", detail_code="ENGINE_SPOOL_" + detail_code
        ),
    )


def canonical_text_identity(value: str) -> bytes:
    """The canonical SQLite grouping identity of one decoded text value.

    Equality of decoded strings is exactly equality of their UTF-8
    encodings, so the canonical blob groups precisely the same values as
    the established Python-tuple semantics.  The identity is SENSITIVE Zone
    B material (it is the original key identity): it stays in the spool,
    never serialized publicly, never logged, never transferred.
    """
    return value.encode("utf-8")


def canonical_composite_identity(components: tuple[object, ...]) -> bytes:
    """The canonical grouping identity of one ordered composite key tuple.

    Deterministic length-prefixed component encoding: the ordinal order is
    preserved (``(A, B) != (B, A)``) and component equality matches the
    established Python-tuple semantics (text compared by decoded equality,
    numeric keys by their canonical integer text).  NULL tuples are never
    keyed (they are counted per side, not grouped).
    """
    parts: list[bytes] = [str(len(components)).encode("ascii")]
    for component in components:
        if isinstance(component, str):
            parts.append(b"T" + str(len(component.encode("utf-8"))).encode("ascii") + b":" + component.encode("utf-8"))
        elif isinstance(component, bool) or not isinstance(component, int):
            raise _spool_failure("KEY_COMPONENT_UNSUPPORTED")
        else:
            text = str(int(component))
            parts.append(b"N" + str(len(text)).encode("ascii") + b"|" + text.encode("ascii"))
    return b"\x00".join(parts)


class PassOneSpool:
    """The ephemeral protected SQLite state of one engine run (Zone B).

    Bounded by construction: every dataset-sized or distinct-value-sized
    fact lives in SQLite; the Python-side state of this object is O(1)
    (bounded SQL batch buffers of at most :data:`MAX_SQL_BATCH` rows).
    """

    __slots__ = ("_connection", "_path", "_pending_text", "_pending_numeric", "_pending_keys", "_pending_facts", "_closed")

    def __init__(self, vault_directory: Path) -> None:
        self._path = Path(vault_directory) / PASS1_STATE_FILENAME
        if self._path.exists():
            # A crash leftover is classified as sensitive state: refuse to
            # silently reuse or overwrite it (no secure-deletion claim).
            raise _spool_failure("LEFTOVER_REFUSED")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = self._connect(self._path)
        self._pending_text: list[tuple[bytes, int, int]] = []
        self._pending_numeric: list[tuple[str, str]] = []
        self._pending_keys: list[tuple[str, str, str, bytes, int]] = []
        self._pending_facts: list[tuple[str, str, str, int, int]] = []
        self._closed = False
        self._create_schema()

    @staticmethod
    def _connect(path: Path) -> "sqlite3.Connection":
        import os
        import sqlite3

        # Owner-only reservation (P2-009 policy) BEFORE the SQLite layer
        # opens the file: no intermediate world-readable state.
        descriptor = os.open(
            str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
        )
        os.close(descriptor)
        connection = sqlite3.connect(str(path))
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def _create_schema(self) -> None:
        for statement in _SENSITIVE_SCHEMA:
            self._connection.execute(statement)
        self._connection.execute(
            "INSERT INTO meta (key, value) VALUES ('evidence_schema_version', ?)",
            (EVIDENCE_SPOOL_SCHEMA_VERSION,),
        )
        self._connection.commit()

    # -- text observations ------------------------------------------------------
    def observe_text(self, value: str, *, byte_width: int) -> None:
        """Record one text occurrence constraint (strictest width = MIN)."""
        canonical = canonical_text_identity(value)
        self._pending_text.append(
            (canonical, len(value), int(byte_width))
        )
        if len(self._pending_text) >= MAX_SQL_BATCH:
            self._flush_text()

    def _flush_text(self) -> None:
        if not self._pending_text:
            return
        self._connection.executemany(
            "INSERT INTO text_observation (canonical, value_length, min_width) "
            "VALUES (?, ?, ?) ON CONFLICT(canonical) DO UPDATE SET "
            "min_width = MIN(min_width, excluded.min_width)",
            self._pending_text,
        )
        self._pending_text.clear()

    def observe_text_encoding(self, encoding: str) -> None:
        self._connection.execute(
            "INSERT OR IGNORE INTO text_encoding (encoding) VALUES (?)", (encoding,)
        )

    # -- numeric observations ---------------------------------------------------
    def observe_numeric(self, domain_id: str, canonical: str) -> None:
        self._pending_numeric.append((domain_id, canonical))
        if len(self._pending_numeric) >= MAX_SQL_BATCH:
            self._flush_numeric()

    def _flush_numeric(self) -> None:
        if not self._pending_numeric:
            return
        self._connection.executemany(
            "INSERT OR IGNORE INTO numeric_observation (domain_id, canonical) "
            "VALUES (?, ?)",
            self._pending_numeric,
        )
        self._pending_numeric.clear()

    # -- relationship evidence --------------------------------------------------
    def observe_relation_key(
        self, side: str, relation_id: str, role: str, canonical: bytes
    ) -> None:
        self._pending_keys.append((side, relation_id, role, canonical, 1))
        if len(self._pending_keys) >= MAX_SQL_BATCH:
            self._flush_keys()

    def observe_relation_side(
        self,
        side: str,
        relation_id: str,
        role: str,
        *,
        rows: int,
        nulls: int,
    ) -> None:
        self._pending_facts.append((side, relation_id, role, rows, nulls))
        if len(self._pending_facts) >= MAX_SQL_BATCH:
            self._flush_facts()

    def _flush_keys(self) -> None:
        if not self._pending_keys:
            return
        self._connection.executemany(
            "INSERT INTO relation_keys (side, relation_id, role, canonical, occurrences) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(side, relation_id, role, canonical) "
            "DO UPDATE SET occurrences = occurrences + 1",
            self._pending_keys,
        )
        self._pending_keys.clear()

    def _flush_facts(self) -> None:
        if not self._pending_facts:
            return
        self._connection.executemany(
            "INSERT INTO relation_side_facts (side, relation_id, role, "
            "rows_considered, null_tuple_count) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(side, relation_id, role) DO UPDATE SET "
            "rows_considered = rows_considered + excluded.rows_considered, "
            "null_tuple_count = null_tuple_count + excluded.null_tuple_count",
            self._pending_facts,
        )
        self._pending_facts.clear()

    def flush(self) -> None:
        """Flush every bounded pending batch and commit to SQLite."""
        self._flush_text()
        self._flush_numeric()
        self._flush_keys()
        self._flush_facts()
        self._connection.commit()

    # -- bounded SQL aggregation ------------------------------------------------
    def text_observations(self) -> Iterator[tuple[str, int]]:
        """Stream (canonical text, strictest width) in deterministic order.

        The canonical blob is decoded per streamed row; NO list of all
        distinct observations is ever materialized.
        """
        self.flush()
        cursor = self._connection.execute(
            "SELECT canonical, min_width FROM text_observation "
            "ORDER BY min_width ASC, canonical ASC"
        )
        while True:
            rows = cursor.fetchmany(MAX_SQL_BATCH)
            if not rows:
                return
            for canonical, width in rows:
                yield bytes(canonical).decode("utf-8"), int(width)

    def drop_text_observation(self, value: str) -> None:
        """Remove one persisted original's observation (it leaves the
        unpersisted set; its own value stops being a reserved token)."""
        self._connection.execute(
            "DELETE FROM text_observation WHERE canonical = ?",
            (canonical_text_identity(value),),
        )

    def text_encoding_union(self) -> frozenset[str]:
        rows = self._connection.execute(
            "SELECT encoding FROM text_encoding"
        ).fetchall()
        return frozenset(str(row[0]) for row in rows)

    def text_free_reserved_count(self, length: int) -> int:
        """Free reserved tokens of one length class (SQL aggregate)."""
        row = self._connection.execute(
            "SELECT COUNT(*) FROM text_observation "
            "WHERE value_length = ? AND min_width >= ?",
            (length, length),
        ).fetchone()
        return int(row[0])

    def text_is_observed(self, value: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM text_observation WHERE canonical = ?",
            (canonical_text_identity(value),),
        ).fetchone()
        return row is not None

    def text_unpersisted_count(self) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) FROM text_observation"
        ).fetchone()
        return int(row[0])

    def numeric_observation_stream(
        self, domain_id: str
    ) -> Iterator[str]:
        cursor = self._connection.execute(
            "SELECT canonical FROM numeric_observation WHERE domain_id = ? "
            "ORDER BY canonical ASC",
            (domain_id,),
        )
        while True:
            rows = cursor.fetchmany(MAX_SQL_BATCH)
            if not rows:
                return
            for (canonical,) in rows:
                yield str(canonical)

    def drop_numeric_observation(self, domain_id: str, canonical: str) -> None:
        self._connection.execute(
            "DELETE FROM numeric_observation WHERE domain_id = ? AND canonical = ?",
            (domain_id, canonical),
        )

    def numeric_unpersisted_count(self, domain_id: str) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) FROM numeric_observation WHERE domain_id = ?",
            (domain_id,),
        ).fetchone()
        return int(row[0])

    # -- bounded SQL aggregation ------------------------------------------------
    def internal_connection(self) -> "sqlite3.Connection":
        """The internal SQLite connection of the spool (engine-internal SQL).

        The same trust boundary as the vault's internal connection accessor:
        used ONLY by engine modules for the bounded SQL aggregation of the
        pass-1 state, never for anything public.
        """
        return self._connection

    def text_values_of_length(self, length: int) -> Iterator[str]:
        """Stream the remaining observed text values of one length class."""
        cursor = self._connection.execute(
            "SELECT canonical FROM text_observation WHERE value_length = ? "
            "ORDER BY canonical ASC",
            (length,),
        )
        while True:
            rows = cursor.fetchmany(MAX_SQL_BATCH)
            if not rows:
                return
            for (canonical,) in rows:
                yield bytes(canonical).decode("utf-8")

    def relation_side_facts(
        self, side: str, relation_id: str, role: str
    ) -> tuple[int, int]:
        row = self._connection.execute(
            "SELECT rows_considered, null_tuple_count FROM relation_side_facts "
            "WHERE side = ? AND relation_id = ? AND role = ?",
            (side, relation_id, role),
        ).fetchone()
        if row is None:
            return (0, 0)
        return (int(row[0]), int(row[1]))

    def relation_histogram_stream(
        self, side: str, relation_id: str, role: str
    ) -> Iterator[tuple[bytes, int]]:
        cursor = self._connection.execute(
            "SELECT canonical, occurrences FROM relation_keys "
            "WHERE side = ? AND relation_id = ? AND role = ? "
            "ORDER BY occurrences DESC, canonical ASC",
            (side, relation_id, role),
        )
        while True:
            rows = cursor.fetchmany(MAX_SQL_BATCH)
            if not rows:
                return
            for canonical, occurrences in rows:
                yield bytes(canonical), int(occurrences)

    def relation_unique_count(
        self, side: str, relation_id: str, role: str
    ) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) FROM relation_keys "
            "WHERE side = ? AND relation_id = ? AND role = ?",
            (side, relation_id, role),
        ).fetchone()
        return int(row[0])

    def relation_row_count(
        self, side: str, relation_id: str, role: str
    ) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(SUM(occurrences), 0) FROM relation_keys "
            "WHERE side = ? AND relation_id = ? AND role = ?",
            (side, relation_id, role),
        ).fetchone()
        return int(row[0])

    def relation_matched_count(
        self, side: str, relation_id: str, parent_role: str, foreign_role: str
    ) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(SUM(f.occurrences), 0) FROM relation_keys f "
            "WHERE f.side = ? AND f.relation_id = ? AND f.role = ? AND EXISTS ("
            " SELECT 1 FROM relation_keys p WHERE p.side = f.side"
            " AND p.role = ? AND p.relation_id = f.relation_id"
            " AND p.canonical = f.canonical)",
            (side, relation_id, foreign_role, parent_role),
        ).fetchone()
        return int(row[0])

    def relation_profile_equal(
        self, relation_id: str, left_side: str, right_side: str, role: str
    ) -> bool:
        """Streaming multiset-of-counts equality (O(1) RAM, no tuple)."""
        left = self.relation_histogram_stream(left_side, relation_id, role)
        right = self.relation_histogram_stream(right_side, relation_id, role)
        while True:
            left_row = next(left, None)
            right_row = next(right, None)
            if left_row is None and right_row is None:
                return True
            if left_row is None or right_row is None:
                return False
            if left_row[1] != right_row[1]:
                return False

    def relation_profile_digest(
        self, side: str, relation_id: str, role: str
    ) -> str:
        """A stable SHA-256 digest of the sorted multiplicity profile.

        The profile is streamed in canonical order and hashed incrementally:
        a bounded production comparison representation that never
        materializes the O(distinct keys) profile tuple in Python RAM.
        """
        digest = hashlib.sha256()
        digest.update(b"RELATION-PROFILE/v1")
        for _canonical, occurrences in self.relation_histogram_stream(
            side, relation_id, role
        ):
            digest.update(str(occurrences).encode("ascii") + b",")
        return digest.hexdigest()

    # -- lifecycle ---------------------------------------------------------------
    def cleanup(self) -> None:
        """Explicit spool cleanup: drop all sensitive rows, then the file.

        Cleanup failures are SURFACED (typed) — never silently ignored.  No
        secure-deletion claim is made; the unlink removes the artifact from
        the protected Zone B directory.
        """
        self.flush()
        try:
            self._connection.execute("DELETE FROM text_observation")
            self._connection.execute("DELETE FROM numeric_observation")
            self._connection.execute("DELETE FROM relation_keys")
            self._connection.execute("DELETE FROM relation_side_facts")
            self._connection.execute("DELETE FROM text_encoding")
            self._connection.execute("DELETE FROM meta")
            self._connection.commit()
            self._connection.execute("VACUUM")
            self._connection.close()
        except Exception as exc:  # noqa: BLE001 - surfaced storage failure
            raise _spool_failure("CLEANUP_FAILED") from None
        finally:
            self._closed = True
        if self._path.exists():
            try:
                self._path.unlink()
            except OSError as exc:
                raise _spool_failure("CLEANUP_FAILED") from None
