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
    "spool_artifacts",
    "canonical_text_identity",
    "canonical_composite_identity",
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

#: The COMPLETE sensitive artifact inventory of the ephemeral spool
#: (REQ-P4-002 / P2-009 policy): the main database plus every SQLite
#: sidecar SQLite could ever leave behind.  ``journal_mode=OFF`` keeps the
#: live set to the main file alone, but a crash under a different journal
#: mode (or a hostile leftover) can leave ANY of these — the lifecycle
#: refuses and cleans ALL of them.
_SPOOL_ARTIFACT_SUFFIXES: tuple[str, ...] = ("", "-wal", "-shm", "-journal")

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
    # -- exact bounded text residual solver state (REQ-P4-002) --------------
    # Every dataset-sized or distinct-value-sized traversal state of the
    # exact residual assignment lives HERE (disk-backed), never in Python.
    "CREATE TABLE res_original ("
    " idx INTEGER PRIMARY KEY,"
    " width INTEGER NOT NULL,"
    " canonical BLOB NOT NULL,"
    " own_token TEXT)",  # its own value when that is a free safe token
    "CREATE TABLE res_token ("
    " tid INTEGER PRIMARY KEY,"
    " value TEXT NOT NULL UNIQUE,"
    " length INTEGER NOT NULL,"
    " owner_idx INTEGER NOT NULL)",  # reserved self-value tokens
    "CREATE TABLE res_cap ("
    " length INTEGER PRIMARY KEY,"
    " fungible INTEGER NOT NULL)",  # free non-reserved tokens per class
    "CREATE TABLE res_assign ("
    " orig_idx INTEGER PRIMARY KEY,"
    " kind TEXT NOT NULL CHECK (kind IN ('class','token')),"
    " length INTEGER,"
    " token_idx INTEGER)",
    "CREATE INDEX res_assign_class ON res_assign(kind, length, orig_idx)",
    "CREATE INDEX res_assign_token ON res_assign(kind, token_idx)",
    # THE DATABASE-ENFORCED MATCHING INVARIANT: one reserved-token resource
    # may be assigned to AT MOST ONE original.  ``orig_idx`` uniqueness (the
    # primary key) already enforces one assignment per original; this
    # partial UNIQUE index enforces the other direction for kind='token'
    # rows, so a double occupancy of a reserved resource is a hard SQLite
    # refusal, never a silent algorithmic slip.
    "CREATE UNIQUE INDEX res_assign_token_once "
    "ON res_assign (token_idx) WHERE kind = 'token'",
    "CREATE TABLE res_visited (orig_idx INTEGER PRIMARY KEY)",
    "CREATE TABLE res_dfs ("
    " depth INTEGER PRIMARY KEY,"
    " orig_idx INTEGER NOT NULL,"
    " vacate_kind TEXT, vacate_length INTEGER, vacate_token_idx INTEGER,"
    " class_pos INTEGER NOT NULL, token_pos INTEGER NOT NULL,"
    " displace_from INTEGER NOT NULL)",
)


def spool_artifacts(vault_directory: Path) -> list[Path]:
    """The bounded artifact inventory of the ephemeral spool (P2-009).

    Returns every KNOWN spool artifact (main database plus every SQLite
    sidecar) that currently exists under *vault_directory*.  The inventory
    is value-free and internal: it never carries originals, pseudonyms or
    absolute paths into any public boundary.
    """
    base = Path(vault_directory) / PASS1_STATE_FILENAME
    found: list[Path] = []
    for suffix in _SPOOL_ARTIFACT_SUFFIXES:
        candidate = Path(str(base) + suffix)
        try:
            if candidate.exists():
                found.append(candidate)
        except OSError:
            found.append(candidate)  # an inspectable-but-inaccessible
            # artifact is treated as present (fail closed).
    return found


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
    (bounded SQL batch buffers of at most :data:`MAX_SQL_BATCH` rows, whose
    high-water marks are tracked for the structural boundedness evidence).

    Sensitive-artifact lifecycle (P2-009 policy): the spool is created with
    ``journal_mode=OFF`` (no SQLite sidecar is ever written for it), the
    main file is reserved owner-only where the platform permits, and the
    startup refuses ANY known leftover artifact (main, ``-wal``, ``-shm``,
    rollback journal) instead of silently reusing crash residue.  Cleanup
    removes and verifies the COMPLETE inventory; failures are surfaced as
    typed, value-free errors.  No secure-deletion claim is made.
    """

    __slots__ = (
        "_connection",
        "_path",
        "_pending_text",
        "_pending_numeric",
        "_pending_keys",
        "_pending_facts",
        "_closed",
        "pending_high_water",
    )

    def __init__(self, vault_directory: Path) -> None:
        leftovers = spool_artifacts(vault_directory)
        if leftovers:
            # ANY crash residue is classified as sensitive state: refuse to
            # silently reuse or overwrite it (no secure-deletion claim).
            raise _spool_failure("LEFTOVER_REFUSED")
        self._path = Path(vault_directory) / PASS1_STATE_FILENAME
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = self._connect(self._path)
        self._pending_text: list[tuple[bytes, int, int]] = []
        self._pending_numeric: list[tuple[str, str]] = []
        self._pending_keys: list[tuple[str, str, str, bytes, int]] = []
        self._pending_facts: list[tuple[str, str, str, int, int]] = []
        self._closed = False
        #: Structural boundedness instrumentation: the high-water mark of
        #: every bounded Python buffer (never exceeds MAX_SQL_BATCH).
        self.pending_high_water: dict[str, int] = {}
        self._create_schema()

    def _track_high_water(self) -> None:
        """One bounded-instrumentation update per flush (O(1) Python)."""
        for name, buffer in (
            ("text", self._pending_text),
            ("numeric", self._pending_numeric),
            ("keys", self._pending_keys),
            ("facts", self._pending_facts),
        ):
            previous = self.pending_high_water.get(name, 0)
            if len(buffer) > previous:
                self.pending_high_water[name] = len(buffer)

    @staticmethod
    def _connect(path: Path) -> "sqlite3.Connection":
        import os
        import sqlite3

        # Owner-only reservation (best-effort per platform) BEFORE the
        # SQLite layer opens the file.  On POSIX this is the 0o600 mode; on
        # Windows the platform ACL story is limited — no POSIX guarantee is
        # claimed, the reservation is best-effort and truthful.
        descriptor = os.open(
            str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
        )
        os.close(descriptor)
        connection = sqlite3.connect(str(path))
        # The spool is EPHEMERAL per-run state whose durability is worthless
        # (it is rebuilt from the source on every run and refused if left
        # behind): journal_mode=OFF writes NO sidecar artifact at all.
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
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
        self._track_high_water()
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
    def size_bytes(self) -> int:
        """The current main spool artifact size (a truthful evidence metric).

        Value-free: only the byte size of the ephemeral Zone B state file is
        reported — never any of its contents.
        """
        try:
            return self._path.stat().st_size
        except OSError:
            return 0

    def cleanup(self) -> None:
        """Explicit spool cleanup: drop all sensitive rows, then EVERY artifact.

        The COMPLETE inventory (main database plus every known SQLite
        sidecar) is removed and the removal is VERIFIED; any failure is
        SURFACED as a typed, value-free error — never silently ignored and
        never echoing absolute paths or originals.  No secure-deletion claim
        is made: the unlink removes the artifact from the protected Zone B
        directory, nothing more.
        """
        if self._closed:
            return
        self.flush()
        try:
            for table in (
                "text_observation",
                "numeric_observation",
                "relation_keys",
                "relation_side_facts",
                "text_encoding",
                "meta",
                "res_original",
                "res_token",
                "res_cap",
                "res_assign",
                "res_visited",
                "res_dfs",
            ):
                self._connection.execute(f"DELETE FROM {table}")
            self._connection.commit()
        except Exception:  # noqa: BLE001 - surfaced storage failure
            self._closed = True
            raise _spool_failure("CLEANUP_FAILED") from None
        try:
            self._connection.close()
        except Exception:  # noqa: BLE001 - surfaced storage failure
            self._closed = True
            raise _spool_failure("CLEANUP_FAILED") from None
        self._closed = True
        for artifact in spool_artifacts(self._path.parent):
            try:
                artifact.unlink()
            except OSError as exc:
                raise _spool_failure("CLEANUP_FAILED") from exc
        if spool_artifacts(self._path.parent):
            # The verified-removal contract: an artifact that survives the
            # unlink attempt is a surfaced cleanup failure.
            raise _spool_failure("CLEANUP_FAILED")
