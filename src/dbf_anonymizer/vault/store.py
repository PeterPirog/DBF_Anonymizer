"""Protected recovery-vault store: open/create, identity binding, integrity,
journal lifecycle, single logical writer authority, operation state.

One pseudonymization dataset owns exactly ONE authoritative dictionary
database (``dictionary.sqlite3``) for the whole source tree (REQ-P2-001).
This module owns the connection lifecycle and the fail-closed boundaries:

* **Creation** — ``VaultDatabase.open(path, create=True, ...)`` creates the
  schema 1.0 dictionary inside ONE transaction; creation over an existing
  file is refused (no dropping/recreating of unknown databases).
* **Reopen** — every open validates integrity (``PRAGMA quick_check``,
  ``PRAGMA foreign_key_check``), the exact schema version, the vault-id shape
  and — when expected values are supplied — the bound dataset identity
  (source/policy/relationship fingerprints). Any mismatch fails CLOSED with
  a typed ``VaultError`` and never exposes raw source values, private paths
  or raw SQLite error text (classification is by exception TYPE only).
* **Single logical writer authority** (REQ-P2-003) — a durable
  ``writer_authority`` lease row inside the same SQLite database: the first
  writer acquires it atomically (``BEGIN IMMEDIATE`` + conditional update);
  any competing writer fails deterministically with
  ``VAULT_WRITER_CONFLICT``; release returns authority cleanly; a crashed
  writer leaves an EXPLICIT stale lease that is readable and reclaimable
  only by naming its stored token. Readers never need the lease.
* **Journal lifecycle** — WAL journaling with a truncate checkpoint on every
  clean close (see :mod:`dbf_anonymizer.vault.schema`).
* **Operations/publication state** — persisted ``operations`` rows with
  bounded states and stable stored operation IDs.

The vault never touches DBF/FPT files, never imports the ``dbfbridge``
namespace, and is NOT reachable from ``build_plan``/``preflight`` (those
operations remain source-read-only; vault creation belongs to the future
execution engine).
"""

from __future__ import annotations

import hashlib

import importlib.metadata as _metadata
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError, VaultError
from dbf_anonymizer.vault.schema import (
    CREATE_META_SEED,
    DDL_STATEMENTS,
    VAULT_CLOSE_CHECKPOINT,
    VAULT_DATABASE_FILENAME,
    VAULT_ID_PREFIX,
    VAULT_JOURNAL_MODE,
    VAULT_OPERATION_ID_PREFIX,
    VAULT_OPERATION_STATE_COMPLETED,
    VAULT_OPERATION_STATE_STARTED,
    VAULT_PAYLOAD_KIND_BINARY,
    VAULT_PAYLOAD_KIND_TEXT,
    VAULT_SCHEMA_VERSION,
    VAULT_WRITER_TOKEN_PREFIX,
)
from dbf_anonymizer.vault.transactions import VaultTransaction

__all__ = [
    "VaultDatabase",
    "default_dictionary_path",
    "new_writer_token",
]


#: Bounded SQLite busy timeout: a competing writer WAITS (instead of failing
#: on a transient lock) and then deterministically observes the committed
#: lease — the concurrent-rejection evidence is a typed conflict, never a
#: flaky race.
VAULT_BUSY_TIMEOUT_MS = 10_000

_MAX_TOKEN_LENGTH = 128


def _validate_token(value: str, *, field_name: str) -> str:
    """Validate a bounded machine token without interpreting its meaning."""
    if not value or len(value) > _MAX_TOKEN_LENGTH or value.strip() != value:
        raise ValueError(
            f"{field_name} must be a non-empty token of at most {_MAX_TOKEN_LENGTH} characters"
        )
    if any(character.isspace() for character in value):
        raise ValueError(f"{field_name} must not contain whitespace")
    return value


def _utc_now() -> str:
    """Informational UTC timestamp (bounded ISO-8601 text)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_hex_id(prefix: str) -> str:
    """Privacy-safe, bounded, non-predictable identifier (never source-derived)."""
    return prefix + uuid.uuid4().hex


def new_writer_token() -> str:
    """A fresh single-writer lease token (bounded, privacy-safe)."""
    return _new_hex_id(VAULT_WRITER_TOKEN_PREFIX)


def default_dictionary_path(vault_directory: Path) -> Path:
    """The exact dictionary database file inside a vault directory.

    One dataset vault contains exactly one :data:`VAULT_DATABASE_FILENAME`.
    """
    return vault_directory / VAULT_DATABASE_FILENAME


def _package_version() -> str:
    try:
        return _metadata.version("dbf-anonymizer")
    except _metadata.PackageNotFoundError:  # pragma: no cover - defensive
        return "unknown"


def _vault_failure(
    code: ErrorCode,
    detail_code: str,
    *,
    operation: str = "vault",
) -> VaultError:
    """Build a privacy-safe, registry-controlled vault failure."""
    return VaultError(
        code,
        context=ErrorContext(operation=operation, detail_code=detail_code),
    )


def _sha16(value: str) -> str:
    """First 16 hex characters of the SHA-256 of *value* (stable identity)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _normalize_relative_path(value: str) -> str:
    """Normalize a relative posix path token (privacy-safe, traversal-free)."""
    if not value or "\x00" in value:
        raise ValueError("relative path must be a non-empty text path")
    normalized = value.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("relative path must be traversal-free")
    if any(":" in part for part in parts):
        raise ValueError("relative path must not contain drive separators")
    return "/".join(parts)


def vault_id_shape_valid(value: object, prefix: str) -> bool:
    """True when *value* is ``prefix`` followed by 32 lowercase hex digits."""
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    digits = value[len(prefix):]
    if len(digits) != 32:
        return False
    return all(character in "0123456789abcdef" for character in digits)


class VaultDatabase:
    """One open connection to the dataset's authoritative dictionary database.

    The instance owns exactly one SQLite connection. It is NOT thread-safe and
    must not be shared between threads; competing writers create their own
    instance on the same file (see the concurrency evidence tests).
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        path: Path,
        *,
        vault_id: str,
        schema_version: str,
        source_fingerprint: str,
        policy_fingerprint: str,
        relationship_fingerprint: str,
    ) -> None:
        self._connection = connection
        self._path = path
        self._vault_id = vault_id
        self._schema_version = schema_version
        self._source_fingerprint = source_fingerprint
        self._policy_fingerprint = policy_fingerprint
        self._relationship_fingerprint = relationship_fingerprint
        self._transaction: VaultTransaction | None = None
        self._closed = False

    # -- lifecycle -----------------------------------------------------------
    @classmethod
    def open(
        cls,
        path: Path | str,
        *,
        create: bool = False,
        expected_source_fingerprint: str | None = None,
        expected_policy_fingerprint: str | None = None,
        expected_relationship_fingerprint: str | None = None,
        dbfbridge_version: str | None = None,
    ) -> "VaultDatabase":
        """Open (or create) the dictionary database with full validation.

        ``create=True`` builds the schema 1.0 dictionary; the target file must
        not already exist (an unknown database is never dropped or recreated).
        ``dbfbridge_version`` (bounded token) is required for creation because
        the vault layer never imports the ``dbfbridge`` namespace itself.

        Without ``create`` the existing database must pass integrity, exact
        schema-version and metadata validation; expected dataset fingerprints
        fail closed as ``VAULT_IDENTITY_MISMATCH`` on any difference.
        """
        database_path = Path(path)
        if create:
            return cls._create(
                database_path,
                source_fingerprint=expected_source_fingerprint,
                policy_fingerprint=expected_policy_fingerprint,
                relationship_fingerprint=expected_relationship_fingerprint,
                dbfbridge_version=dbfbridge_version,
            )
        if not Path(path).is_file():
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "DICTIONARY_MISSING")
        connection = cls._connect(database_path)
        try:
            database = cls._validate_and_bind(
                connection,
                database_path,
                expected_source_fingerprint=expected_source_fingerprint,
                expected_policy_fingerprint=expected_policy_fingerprint,
                expected_relationship_fingerprint=expected_relationship_fingerprint,
            )
        except BaseException:
            connection.close()
            raise
        return database

    @classmethod
    def _connect(cls, path: Path) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                str(path),
                timeout=VAULT_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
            )
        except PermissionError:
            raise _vault_failure(ErrorCode.VAULT_ACCESS_DENIED, "OPEN_DENIED") from None
        except OSError:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "OPEN_FAILED") from None
        except sqlite3.Error:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "OPEN_FAILED") from None
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA journal_mode = {VAULT_JOURNAL_MODE}")
            connection.execute(f"PRAGMA busy_timeout = {VAULT_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error:
            connection.close()
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
        return connection

    @classmethod
    def _create(
        cls,
        path: Path,
        *,
        source_fingerprint: str | None,
        policy_fingerprint: str | None,
        relationship_fingerprint: str | None,
        dbfbridge_version: str | None,
    ) -> "VaultDatabase":
        if any(
            value is None
            for value in (
                source_fingerprint,
                policy_fingerprint,
                relationship_fingerprint,
                dbfbridge_version,
            )
        ):
            raise ValueError(
                "creation requires source_fingerprint, policy_fingerprint, "
                "relationship_fingerprint and dbfbridge_version"
            )
        assert source_fingerprint is not None
        assert policy_fingerprint is not None
        assert relationship_fingerprint is not None
        assert dbfbridge_version is not None
        _validate_token(source_fingerprint, field_name="source_fingerprint")
        _validate_token(policy_fingerprint, field_name="policy_fingerprint")
        _validate_token(relationship_fingerprint, field_name="relationship_fingerprint")
        _validate_token(dbfbridge_version, field_name="dbfbridge_version")

        if path.is_file():
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "ALREADY_EXISTS")
        if path.exists() and not path.is_file():
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "TARGET_NOT_A_FILE")
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True)

        connection = cls._connect(path)
        vault_id = _new_hex_id(VAULT_ID_PREFIX)
        try:
            transaction = VaultTransaction(connection)
            with transaction:
                for statement in DDL_STATEMENTS:
                    connection.execute(statement)
                for statement, parameters in CREATE_META_SEED:
                    connection.execute(statement, parameters)
                connection.execute(
                    "INSERT INTO meta (singleton, schema_version, vault_id, "
                    "created_at, package_version, dbfbridge_version) "
                    "VALUES (1, ?, ?, ?, ?, ?)",
                    (
                        VAULT_SCHEMA_VERSION,
                        vault_id,
                        _utc_now(),
                        _package_version(),
                        dbfbridge_version,
                    ),
                )
                connection.execute(
                    "INSERT INTO dataset (singleton, source_fingerprint, "
                    "policy_fingerprint, relationship_fingerprint) VALUES (1, ?, ?, ?)",
                    (source_fingerprint, policy_fingerprint, relationship_fingerprint),
                )
        except sqlite3.Error:
            connection.close()
            # The partially created file was never a valid vault; remove it so
            # a retry starts deterministically from a clean slate.
            try:
                path.unlink()
            except OSError:  # pragma: no cover - defensive
                pass
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "CREATION_FAILED") from None
        return cls(
            connection,
            path,
            vault_id=vault_id,
            schema_version=VAULT_SCHEMA_VERSION,
            source_fingerprint=source_fingerprint,
            policy_fingerprint=policy_fingerprint,
            relationship_fingerprint=relationship_fingerprint,
        )

    @classmethod
    def _validate_and_bind(
        cls,
        connection: sqlite3.Connection,
        path: Path,
        *,
        expected_source_fingerprint: str | None,
        expected_policy_fingerprint: str | None,
        expected_relationship_fingerprint: str | None,
    ) -> "VaultDatabase":
        try:
            vault_id, schema_version, fingerprints = cls._read_identity(connection)
        except sqlite3.DatabaseError:
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
        database = cls(
            connection,
            path,
            vault_id=vault_id,
            schema_version=schema_version,
            source_fingerprint=fingerprints["source"],
            policy_fingerprint=fingerprints["policy"],
            relationship_fingerprint=fingerprints["relationship"],
        )
        mismatches = (
            ("SOURCE_FINGERPRINT", expected_source_fingerprint, fingerprints["source"]),
            ("POLICY_FINGERPRINT", expected_policy_fingerprint, fingerprints["policy"]),
            (
                "RELATIONSHIP_FINGERPRINT",
                expected_relationship_fingerprint,
                fingerprints["relationship"],
            ),
        )
        for detail_code, expected, actual in mismatches:
            if expected is not None and expected != actual:
                database.close()
                raise _vault_failure(ErrorCode.VAULT_IDENTITY_MISMATCH, detail_code)
        return database

    @classmethod
    def _validate(cls, connection: sqlite3.Connection) -> None:
        """Deterministic integrity boundary (type-classified, never text-parsed)."""
        check_rows = connection.execute("PRAGMA quick_check").fetchall()
        if (
            len(check_rows) != 1
            or not isinstance(check_rows[0][0], str)
            or check_rows[0][0] != "ok"
        ):
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "QUICK_CHECK_FAILED")
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "FOREIGN_KEY_CHECK_FAILED")

    @classmethod
    def _read_identity(
        cls, connection: sqlite3.Connection
    ) -> tuple[str, str, dict[str, str]]:
        cls._validate(connection)
        meta = connection.execute(
            "SELECT schema_version, vault_id FROM meta WHERE singleton = 1"
        ).fetchone()
        if meta is None:
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "META_MISSING")
        vault_id = meta[1]
        if not vault_id_shape_valid(vault_id, VAULT_ID_PREFIX):
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "VAULT_ID_MALFORMED")
        if meta[0] != VAULT_SCHEMA_VERSION:
            raise _vault_failure(
                ErrorCode.VAULT_SCHEMA_UNSUPPORTED, "SCHEMA_VERSION_UNSUPPORTED"
            )
        dataset = connection.execute(
            "SELECT source_fingerprint, policy_fingerprint, relationship_fingerprint "
            "FROM dataset WHERE singleton = 1"
        ).fetchone()
        if dataset is None:
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATASET_MISSING")
        return (
            str(vault_id),
            str(meta[0]),
            {
                "source": str(dataset[0]),
                "policy": str(dataset[1]),
                "relationship": str(dataset[2]),
            },
        )

    # -- public state --------------------------------------------------------
    @property
    def path(self) -> Path:
        """The exact dictionary database file of this vault."""
        return self._path

    @property
    def vault_id(self) -> str:
        """Stable dataset-vault identity (persisted; stable across reopen)."""
        return self._vault_id

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def source_fingerprint(self) -> str:
        return self._source_fingerprint

    @property
    def policy_fingerprint(self) -> str:
        return self._policy_fingerprint

    @property
    def relationship_fingerprint(self) -> str:
        return self._relationship_fingerprint

    @property
    def connection(self) -> sqlite3.Connection:
        """The raw connection (internal seam; readers and the test suite)."""
        if self._closed:
            raise RuntimeError("vault database is closed")
        return self._connection

    @property
    def closed(self) -> bool:
        return self._closed

    def foreign_keys_enabled(self) -> bool:
        """True when the enforced per-connection FK pragma is active."""
        return int(self.connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 1

    def journal_mode(self) -> str:
        """The active SQLite journal mode (the explicit WAL policy)."""
        row = self.connection.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]) if row is not None else ""

    # -- transaction boundary --------------------------------------------------
    def transaction(self) -> VaultTransaction:
        """Start the deterministic ``BEGIN IMMEDIATE`` transaction unit.

        Exactly one transaction may be active per connection; nested or
        overlapping use is refused instead of silently merged.
        """
        if self._closed:
            raise RuntimeError("vault database is closed")
        if self._transaction is not None and self._transaction.active:
            raise ValueError("vault transaction already active")
        transaction = VaultTransaction(self._connection)
        self._transaction = transaction
        return transaction

    def _require_active_transaction(self, action: str) -> VaultTransaction:
        transaction = self._transaction
        if transaction is None or not transaction.active:
            raise ValueError(
                f"{action} requires an active VaultDatabase.transaction() unit"
            )
        return transaction

    # -- integrity -------------------------------------------------------------
    def verify(self, *, full: bool = False) -> None:
        """Run the deterministic integrity boundary on demand.

        ``quick_check`` (default) or the more thorough ``integrity_check``
        (``full=True``), plus ``foreign_key_check`` and the explicit
        metadata/schema validation. Any failure raises the typed
        ``VAULT_CORRUPT`` / ``VAULT_SCHEMA_UNSUPPORTED`` classification.
        """
        if self._closed:
            raise RuntimeError("vault database is closed")
        check_pragma = "PRAGMA integrity_check" if full else "PRAGMA quick_check"
        try:
            check_rows = self._connection.execute(check_pragma).fetchall()
            if (
                len(check_rows) != 1
                or not isinstance(check_rows[0][0], str)
                or check_rows[0][0] != "ok"
            ):
                raise _vault_failure(ErrorCode.VAULT_CORRUPT, "CHECK_FAILED")
            violations = self._connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            if violations:
                raise _vault_failure(
                    ErrorCode.VAULT_CORRUPT, "FOREIGN_KEY_CHECK_FAILED"
                )
            self._read_identity(self._connection)
        except sqlite3.DatabaseError:
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None

    # -- single logical writer authority (REQ-P2-003) ---------------------------
    def acquire_writer_lease(self, owner_token: str) -> int:
        """Atomically acquire the single logical writer authority.

        The lease lives in the durable ``writer_authority`` row of the same
        database: the conditional update succeeds for exactly one competing
        writer; any other writer (or an exhausted busy timeout) fails with
        the typed ``VAULT_WRITER_CONFLICT`` classification. The lease must be
        acquired outside any active transaction.
        """
        _validate_token(owner_token, field_name="owner_token")
        if self._closed:
            raise RuntimeError("vault database is closed")
        if self._transaction is not None and self._transaction.active:
            raise ValueError("writer lease acquisition requires no active transaction")
        try:
            with self.transaction() as unit:
                cursor = self._connection.execute(
                    "UPDATE writer_authority SET owner_token = ?, "
                    "acquire_tick = acquire_tick + 1 "
                    "WHERE singleton = 1 AND owner_token IS NULL",
                    (owner_token,),
                )
                if cursor.rowcount != 1:
                    raise _vault_failure(
                        ErrorCode.VAULT_WRITER_CONFLICT, "WRITER_LEASE_HELD"
                    )
                tick_row = self._connection.execute(
                    "SELECT acquire_tick FROM writer_authority WHERE singleton = 1"
                ).fetchone()
        except sqlite3.OperationalError:
            # Type-based classification (never SQLite text parsing): a busy
            # write lock on the lease row means another logical writer is
            # active — fail closed as a writer conflict.
            raise _vault_failure(ErrorCode.VAULT_WRITER_CONFLICT, "WRITER_LEASE_BUSY") from None
        tick = tick_row[0] if tick_row is not None else 0
        return int(tick)

    def release_writer_lease(self, owner_token: str) -> None:
        """Release the writer authority; only the current holder succeeds."""
        _validate_token(owner_token, field_name="owner_token")
        if self._closed:
            raise RuntimeError("vault database is closed")
        try:
            with self.transaction():
                cursor = self._connection.execute(
                    "UPDATE writer_authority SET owner_token = NULL "
                    "WHERE singleton = 1 AND owner_token = ?",
                    (owner_token,),
                )
                if cursor.rowcount != 1:
                    raise _vault_failure(
                        ErrorCode.VAULT_WRITER_CONFLICT, "NOT_LEASE_HOLDER"
                    )
        except sqlite3.OperationalError:
            raise _vault_failure(ErrorCode.VAULT_WRITER_CONFLICT, "WRITER_LEASE_BUSY") from None

    def stale_writer_lease(self) -> str | None:
        """The currently stored lease token (explicit crash-state evidence)."""
        row = self.connection.execute(
            "SELECT owner_token FROM writer_authority WHERE singleton = 1"
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return str(row[0])

    def writer_acquire_tick(self) -> int:
        row = self.connection.execute(
            "SELECT acquire_tick FROM writer_authority WHERE singleton = 1"
        ).fetchone()
        return int(row[0]) if row is not None and row[0] is not None else 0

    # -- operation/publication state (REQ-P2-002) ------------------------------
    def begin_operation(
        self,
        operation_id: str | None = None,
        *,
        source_fingerprint: str | None = None,
    ) -> str:
        """Persist one ``STARTED`` operation row; returns its stable ID."""
        self._require_active_transaction("begin_operation")
        if operation_id is None:
            operation_id = _new_hex_id(VAULT_OPERATION_ID_PREFIX)
        else:
            _validate_token(operation_id, field_name="operation_id")
            existing = self.connection.execute(
                "SELECT 1 FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if existing is not None:
                raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "OPERATION_EXISTS")
        try:
            self._connection.execute(
                "INSERT INTO operations (operation_id, state, source_fingerprint, "
                "started_at) VALUES (?, ?, ?, ?)",
                (operation_id, VAULT_OPERATION_STATE_STARTED, source_fingerprint, _utc_now()),
            )
        except sqlite3.IntegrityError:
            raise _vault_failure(
                ErrorCode.VAULT_STATE_INVALID, "OPERATION_REJECTED"
            ) from None
        return operation_id

    def complete_operation(
        self,
        operation_id: str,
        *,
        output_fingerprint: str | None = None,
    ) -> None:
        """Deterministically finish one started operation row."""
        self._require_active_transaction("complete_operation")
        cursor = self._connection.execute(
            "UPDATE operations SET state = ?, completed_at = ?, output_fingerprint = "
            "COALESCE(?, output_fingerprint) WHERE operation_id = ? AND state = ?",
            (
                VAULT_OPERATION_STATE_COMPLETED,
                _utc_now(),
                output_fingerprint,
                operation_id,
                VAULT_OPERATION_STATE_STARTED,
            ),
        )
        if cursor.rowcount != 1:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "OPERATION_NOT_STARTED")

    def operations(self) -> tuple[dict[str, str | None], ...]:
        """All persisted operations in stable operation-id order."""
        rows = self.connection.execute(
            "SELECT operation_id, state, source_fingerprint, output_fingerprint, "
            "started_at, completed_at FROM operations ORDER BY operation_id"
        ).fetchall()
        return tuple(
            {
                "operation_id": str(row[0]),
                "state": str(row[1]),
                "source_fingerprint": row[2],
                "output_fingerprint": row[3],
                "started_at": row[4],
                "completed_at": row[5],
            }
            for row in rows
        )

    def record_publication(
        self,
        operation_id: str,
        phase: str,
        *,
        output_fingerprint: str | None = None,
        vault_fingerprint: str | None = None,
    ) -> None:
        """Persist one bounded publication-phase row (future P4/P5 capacity)."""
        self._require_active_transaction("record_publication")
        _validate_token(phase, field_name="phase")
        try:
            self._connection.execute(
                "INSERT INTO publication (operation_id, phase, output_fingerprint, "
                "vault_fingerprint) VALUES (?, ?, ?, ?)",
                (operation_id, phase, output_fingerprint, vault_fingerprint),
            )
        except sqlite3.IntegrityError:
            raise _vault_failure(
                ErrorCode.VAULT_STATE_INVALID, "PUBLICATION_REJECTED"
            ) from None

    # -- dataset structure (stable table/field identities) ---------------------
    def register_table(
        self,
        relative_path: str,
        *,
        schema_fingerprint: str | None = None,
        source_fingerprint: str | None = None,
    ) -> str:
        """Register one dataset table; the table_id is stable across reopen.

        The identity is a bounded digest of the normalized relative path —
        never derived from source values.
        """
        self._require_active_transaction("register_table")
        normalized = _normalize_relative_path(relative_path)
        table_id = "tbl-" + _sha16(normalized)
        try:
            self._connection.execute(
                "INSERT INTO tables (table_id, relative_path, schema_fingerprint, "
                "source_fingerprint) VALUES (?, ?, ?, ?)",
                (table_id, normalized, schema_fingerprint, source_fingerprint),
            )
        except sqlite3.IntegrityError:
            raise _vault_failure(
                ErrorCode.VAULT_STATE_INVALID, "TABLE_REJECTED"
            ) from None
        return table_id

    def register_field(
        self,
        table_id: str,
        name: str,
        *,
        dbf_type: str,
        width: int,
        encoding: str | None = None,
        transform_action: str | None = None,
        mapping_domain_id: str | None = None,
    ) -> str:
        """Register one field row bound to its table (FK enforced by SQLite)."""
        self._require_active_transaction("register_field")
        _validate_token(table_id, field_name="table_id")
        _validate_token(name, field_name="field name")
        _validate_token(dbf_type, field_name="dbf_type")
        if width < 0:
            raise ValueError("field width must be non-negative")
        if transform_action is not None:
            _validate_token(transform_action, field_name="transform_action")
        field_id = "fld-" + _sha16(table_id + "\x00" + name)
        try:
            self._connection.execute(
                "INSERT INTO fields (field_id, table_id, name, dbf_type, encoding, "
                "width, transform_action, mapping_domain_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    field_id,
                    table_id,
                    name,
                    dbf_type,
                    encoding,
                    width,
                    transform_action,
                    mapping_domain_id,
                ),
            )
        except sqlite3.IntegrityError:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "FIELD_REJECTED") from None
        return field_id

    def tables(self) -> tuple[dict[str, str | None], ...]:
        rows = self.connection.execute(
            "SELECT table_id, relative_path, schema_fingerprint, source_fingerprint "
            "FROM tables ORDER BY relative_path"
        ).fetchall()
        return tuple(
            {
                "table_id": str(row[0]),
                "relative_path": str(row[1]),
                "schema_fingerprint": row[2],
                "source_fingerprint": row[3],
            }
            for row in rows
        )

    # -- close -----------------------------------------------------------------
    def close(self) -> None:
        """Clean close: truncate-checkpoint the WAL, then close the connection.

        A normal clean close leaves NO persistent ``-wal``/``-shm`` sidecars
        (SQLite removes them with the last connection). Checkpoint failures
        are absorbed at close time; surfacing cleanup failures is owned by
        REQ-P2-009 and is not part of this foundation.
        """
        if self._closed:
            return
        self._closed = True
        try:
            self._connection.execute(f"PRAGMA wal_checkpoint({VAULT_CLOSE_CHECKPOINT})")
        except sqlite3.Error:
            pass
        self._connection.close()

    def __enter__(self) -> "VaultDatabase":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()