"""Protected recovery-vault store: open/create, identity binding, integrity,
journal lifecycle, single logical writer authority, operation state.

One pseudonymization dataset owns exactly ONE authoritative dictionary
database (``dictionary.sqlite3``) for the whole source tree (REQ-P2-001).
This module owns the connection lifecycle and the fail-closed boundaries:

* **Creation** — ``VaultDatabase.open(path, create=True, ...)`` creates the
  schema 1.0 dictionary inside ONE system transaction; creation over an
  existing file is refused (an unknown database is never dropped, recreated
  or converted); the WAL journal mode is SET and its PRAGMA RESULT verified.
  Once the atomic ``O_CREAT | O_EXCL`` reservation succeeds, the whole
  creation runs inside ONE owner-scoped lifecycle boundary: EVERY
  initialization failure deterministically closes the opened connection and
  removes OUR reservation (only while the ownership identity still matches),
  cleanup failures SURFACE as typed privacy-safe failures, typed transaction
  control failures keep their root cause, and a replacement file is never
  unlinked.
* **Non-mutating reopen validation** — an EXISTING database is validated in a
  FIRST, strictly read-only stage (SQLite ``mode=ro`` URI connection): raw
  stat probe, integrity boundary, exact schema version, vault-id shape,
  dataset identity and expected fingerprints. The validation stage never
  writes: no journal-mode change, no metadata, no schema, no sidecars — a
  rejected vault stays byte-identical. Only AFTER acceptance does the
  operational read/write connection open (STAGE 2) and require the expected
  journal mode instead of silently converting it.
* **Single logical writer authority** (REQ-P2-003) — the durable
  ``writer_authority`` lease row is the ONLY mutation authority: a
  ``VaultDatabase`` acquires it atomically, the successful lease is bound to
  the instance, and every ordinary write transaction re-verifies the durable
  ownership INSIDE the ``BEGIN IMMEDIATE`` lock. A connection that does not
  hold the authority cannot execute any ordinary vault mutation. The private
  system transaction is reserved for creation, lease acquire/release and
  other narrowly scoped lifecycle work.
* **Integrity** — ``quick_check``/``integrity_check`` plus
  ``foreign_key_check`` and explicit metadata validation; classification is
  by exception TYPE only, never by parsing SQLite text.
* **Journal lifecycle** — WAL journaling with a truncate checkpoint on every
  clean close (see :mod:`dbf_anonymizer.vault.schema`); checkpoint/cleanup
  failures surface as typed, privacy-safe vault failures (recorded instead of
  raised only when an operation exception is already in flight).

The vault never touches DBF/FPT files, never imports the ``dbfbridge``
namespace, and is NOT reachable from ``build_plan``/``preflight`` (those
operations remain source-read-only; vault creation belongs to the future
execution engine).
"""

from __future__ import annotations

import hashlib
import os
import stat

import importlib.metadata as _metadata
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VaultError
from dbf_anonymizer.vault.protection import harden_vault_directory
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

_RAW_FILE_KIND_MISSING = "missing"
_RAW_FILE_KIND_FILE = "file"
_RAW_FILE_KIND_DIRECTORY = "directory"
_RAW_FILE_KIND_OTHER = "other"


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


def _raw_file_kind(path: Path) -> str:
    """Fail-closed raw stat probe (never pathlib predicates).

    Modern pathlib predicates can suppress ``OSError``/``PermissionError``;
    the vault therefore classifies filesystem reality with ``os.stat`` and
    ``stat.S_ISREG``/``stat.S_ISDIR`` only, mapping failures to typed,
    privacy-safe vault errors (no absolute paths escape).
    """
    try:
        status = os.stat(path)
    except FileNotFoundError:
        return _RAW_FILE_KIND_MISSING
    except NotADirectoryError:
        return _RAW_FILE_KIND_MISSING
    except PermissionError:
        raise _vault_failure(ErrorCode.VAULT_ACCESS_DENIED, "TARGET_STAT_DENIED") from None
    except OSError:
        raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "TARGET_STAT_FAILED") from None
    if stat.S_ISREG(status.st_mode):
        return _RAW_FILE_KIND_FILE
    if stat.S_ISDIR(status.st_mode):
        return _RAW_FILE_KIND_DIRECTORY
    return _RAW_FILE_KIND_OTHER


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

    Mutation authority: the instance must hold the durable writer lease
    (``acquire_writer_lease``) before any ordinary write transaction is
    accepted. Readers never need the lease.
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
        self._transaction_authorized = False
        self._writer_token: str | None = None
        self._cleanup_failure: VaultError | None = None
        self._poisoned: VaultError | None = None
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

        ``create=True`` builds the schema 1.0 dictionary (WAL mode set and its
        PRAGMA result verified); the target file must not already exist.

        Without ``create`` the open is TWO-STAGE and fail-closed: STAGE 1
        validates the existing file through a READ-ONLY connection (integrity,
        exact schema version, vault-id shape, dataset identity, expected
        fingerprints) WITHOUT mutating anything — a rejected vault stays
        byte-identical and journal-mode-identical. STAGE 2 then opens the
        operational read/write connection and REQUIRES the expected WAL
        journal mode (no silent conversion).
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
        kind = _raw_file_kind(database_path)
        if kind == _RAW_FILE_KIND_MISSING:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "DICTIONARY_MISSING")
        if kind != _RAW_FILE_KIND_FILE:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "TARGET_NOT_A_FILE")
        if cls._has_wal_sidecar(database_path):
            # Crash-dirty WAL: the immutable read-only snapshot cannot see the
            # recovered state, so the operational connection performs SQLite's
            # own committed-state recovery and the FULL validation then runs on
            # it (before any vault mutation is possible). A rejection here may
            # have checkpointed recovered state — that is recovery, never
            # tampering with a compatible vault.
            connection = cls._connect_operational(database_path)
            try:
                cls._require_wal_journal_mode(connection)
            except BaseException:
                connection.close()
                raise
            # The binding OWNS the connection from here: every failure path
            # inside ``_bind`` closes the raw operational connection itself.
            return cls._bind(
                connection,
                database_path,
                expected_source_fingerprint=expected_source_fingerprint,
                expected_policy_fingerprint=expected_policy_fingerprint,
                expected_relationship_fingerprint=expected_relationship_fingerprint,
            )
        # Cleanly-closed vault: STAGE 1 is strictly read-only, strictly
        # non-mutating validation (byte-identical rejection, zero sidecars).
        cls._validate_existing_readonly(
            database_path,
            expected_source_fingerprint=expected_source_fingerprint,
            expected_policy_fingerprint=expected_policy_fingerprint,
            expected_relationship_fingerprint=expected_relationship_fingerprint,
        )
        # STAGE 2 — accepted vault: open the operational connection.
        connection = cls._connect_operational(database_path)
        try:
            cls._require_wal_journal_mode(connection)
        except BaseException:
            connection.close()
            raise
        return cls._bind(
            connection,
            database_path,
            expected_source_fingerprint=expected_source_fingerprint,
            expected_policy_fingerprint=expected_policy_fingerprint,
            expected_relationship_fingerprint=expected_relationship_fingerprint,
        )

    @staticmethod
    def _has_wal_sidecar(path: Path) -> bool:
        """True when a crash-dirty ``-wal`` sidecar exists for the dictionary."""
        try:
            names = os.listdir(path.parent)
        except PermissionError:
            raise _vault_failure(ErrorCode.VAULT_ACCESS_DENIED, "TARGET_STAT_DENIED") from None
        except OSError:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "TARGET_STAT_FAILED") from None
        return f"{path.name}-wal" in names

    @classmethod
    def _require_wal_journal_mode(cls, connection: sqlite3.Connection) -> None:
        """Require the explicit WAL policy; never silently convert a vault."""
        current_mode = cls._read_journal_mode(connection)
        if current_mode.lower() != VAULT_JOURNAL_MODE.lower():
            raise _vault_failure(
                ErrorCode.VAULT_STATE_INVALID, "JOURNAL_MODE_UNEXPECTED"
            )

    @classmethod
    def _validate_existing_readonly(
        cls,
        path: Path,
        *,
        expected_source_fingerprint: str | None,
        expected_policy_fingerprint: str | None,
        expected_relationship_fingerprint: str | None,
    ) -> None:
        """STAGE 1: read-only validation — never writes, never converts.

        Uses an SQLite read-only URI connection so an incompatible, foreign or
        corrupt database is rejected without any possibility of journal-mode
        changes, metadata writes, sidecar creation or recovery writes. The
        expected dataset identity is compared HERE, before any read/write
        connection can exist.
        """
        connection = cls._connect_readonly(path)
        try:
            _vault_id, _schema_version, fingerprints = cls._read_identity(connection)
        except sqlite3.DatabaseError:
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
        finally:
            connection.close()
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
                raise _vault_failure(ErrorCode.VAULT_IDENTITY_MISMATCH, detail_code)

    @classmethod
    def _connect_readonly(cls, path: Path) -> sqlite3.Connection:
        try:
            # ``immutable=1`` reads the file without creating any -wal/-shm
            # wal-index artifacts (a plain ``mode=ro`` open of a WAL database
            # makes SQLite create persistent sidecars). The vault identity and
            # schema are immutable after creation, so the validation snapshot
            # is exact for every supported, cleanly-closed vault; a rejected
            # database stays byte-identical and artifact-free.
            uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=VAULT_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
            )
        except PermissionError:
            raise _vault_failure(ErrorCode.VAULT_ACCESS_DENIED, "OPEN_DENIED") from None
        except OSError:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "OPEN_FAILED") from None
        except sqlite3.Error:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "OPEN_FAILED") from None
        try:
            connection.execute(f"PRAGMA busy_timeout = {VAULT_BUSY_TIMEOUT_MS}")
        except sqlite3.Error:
            connection.close()
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
        return connection

    @staticmethod
    def _apply_journal_mode(connection: sqlite3.Connection) -> str:
        """Set the explicit WAL policy and RETURN the verified PRAGMA result."""
        row = connection.execute(
            f"PRAGMA journal_mode = {VAULT_JOURNAL_MODE}"
        ).fetchone()
        return str(row[0]) if row is not None and row[0] is not None else ""

    @staticmethod
    def _read_journal_mode(connection: sqlite3.Connection) -> str:
        row = connection.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]) if row is not None and row[0] is not None else ""

    @classmethod
    def _connect(cls, path: Path) -> sqlite3.Connection:
        """Open the operational read/write connection (no journal changes)."""
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
        try:
            connection.execute(f"PRAGMA busy_timeout = {VAULT_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error:
            connection.close()
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
        return connection

    #: Backwards-compatible internal alias for the operational connection.
    _connect_operational = _connect

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

        kind = _raw_file_kind(path)
        if kind == _RAW_FILE_KIND_FILE:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "ALREADY_EXISTS")
        if kind != _RAW_FILE_KIND_MISSING:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "TARGET_NOT_A_FILE")
        cls._ensure_parent_directory(path)

        # ATOMIC creator reservation: exactly one competing creator can create
        # the dictionary file (``O_CREAT | O_EXCL``). A losing creator never
        # opens, truncates, converts or unlinks the winner's dictionary.
        reserved_identity = cls._reserve_dictionary_file(path)

        # OWNER-SCOPED CREATION LIFECYCLE: from the successful reservation
        # until the VaultDatabase object exists, EVERY initialization failure
        # deterministically closes the opened connection (when present) and
        # removes OUR reservation (only while the ownership identity still
        # matches). Typed transaction-control failures (e.g.
        # TRANSACTION_BEGIN_FAILED / TRANSACTION_COMMIT_FAILED) preserve their
        # root cause; raw SQLite failures map to the truthful typed creation
        # classification AFTER safe cleanup; cleanup failures surface instead
        # of silently leaving protected residue; control exceptions are never
        # converted into vault errors.
        connection: sqlite3.Connection | None = None
        try:
            # EARLY best-effort hardening of the protected vault boundary:
            # the dictionary was reserved with owner-only modes (0o600); the
            # vault directory receives its protected modes here (POSIX;
            # Windows is truthfully classified as limited best-effort).  A
            # real hardening failure is typed and aborts the creation with
            # owner-scoped cleanup.
            harden_vault_directory(path.parent)
            connection = cls._connect(path)
            try:
                applied = cls._apply_journal_mode(connection)
            except sqlite3.Error:
                raise _vault_failure(
                    ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE"
                ) from None
            if applied.lower() != VAULT_JOURNAL_MODE.lower():
                raise _vault_failure(
                    ErrorCode.VAULT_CORRUPT, "JOURNAL_MODE_UNAVAILABLE"
                )
            vault_id = _new_hex_id(VAULT_ID_PREFIX)
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
            # An unexpected raw SQLite failure during creation: perform the
            # safe owner-scoped cleanup FIRST, then map to the truthful typed
            # creation classification (never raw SQLite text).
            cls._abort_failed_creation(connection, path, reserved_identity)
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "CREATION_FAILED") from None
        except VaultError:
            # A typed creation failure (journal policy, BEGIN/COMMIT control
            # failure, ...): cleanup, then preserve the original typed error.
            cls._abort_failed_creation(connection, path, reserved_identity)
            raise
        except BaseException:
            # Control exceptions (KeyboardInterrupt/SystemExit) are NEVER
            # converted: best-effort safe cleanup, then the original control
            # exception propagates.
            try:
                cls._abort_failed_creation(connection, path, reserved_identity)
            except VaultError:
                pass
            raise
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
    def _abort_failed_creation(
        cls,
        connection: sqlite3.Connection | None,
        path: Path,
        reserved_identity: tuple[int, int] | None,
    ) -> None:
        """Deterministic owner-scoped cleanup after a failed creation.

        Closes the opened connection when present and removes OUR reserved
        dictionary ONLY while the ownership identity still matches (a
        replacement file is never unlinked). Every cleanup failure surfaces as
        the typed, privacy-safe ``CREATION_CLEANUP_FAILED`` — protected residue
        is never silently absorbed and raw OS/SQLite text never escapes. A
        cleanup problem can never turn a failed creation into a success.
        """
        close_failed = False
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                close_failed = True
        try:
            cls._remove_partial_dictionary(path, reserved_identity)
        except VaultError:
            raise _vault_failure(
                ErrorCode.VAULT_CORRUPT, "CREATION_CLEANUP_FAILED"
            ) from None
        if close_failed:
            raise _vault_failure(
                ErrorCode.VAULT_CORRUPT, "CREATION_CLEANUP_FAILED"
            ) from None

    @staticmethod
    def _reserve_dictionary_file(path: Path) -> tuple[int, int]:
        """Atomically reserve the dictionary file for THIS creator.

        ``os.open(O_CREAT | O_EXCL)`` makes the create-vs-create race
        impossible: exactly one competing creator obtains the reservation; a
        loser receives the typed ``VAULT_STATE_INVALID`` (``ALREADY_EXISTS``)
        classification and never touches the winner's file. The fstat identity
        (device + inode) is returned so failed-creation cleanup can prove it
        is deleting its OWN reservation — never a file that replaced it.
        """
        try:
            descriptor = os.open(
                path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
        except FileExistsError:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "ALREADY_EXISTS") from None
        except PermissionError:
            raise _vault_failure(ErrorCode.VAULT_ACCESS_DENIED, "RESERVATION_DENIED") from None
        except OSError:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "RESERVATION_FAILED") from None
        try:
            status = os.fstat(descriptor)
            return (status.st_dev, status.st_ino)
        finally:
            os.close(descriptor)

    @staticmethod
    def _remove_partial_dictionary(
        path: Path, reserved_identity: tuple[int, int] | None
    ) -> None:
        """Remove OUR partially created dictionary; cleanup failures SURFACE.

        Ownership guard: when the file's current identity no longer matches
        the reservation captured at creation, the file was replaced and is
        NEVER unlinked — a different creator's (or operator's) file cannot be
        destroyed by this failed creation. No secure-deletion claim is made.
        """
        if reserved_identity is not None:
            try:
                status = os.stat(path)
                current_identity = (status.st_dev, status.st_ino)
            except FileNotFoundError:
                return  # the reservation is already gone: nothing of ours left
            except OSError:
                raise _vault_failure(
                    ErrorCode.VAULT_CORRUPT, "CREATION_CLEANUP_FAILED"
                ) from None
            if current_identity != reserved_identity:
                raise _vault_failure(
                    ErrorCode.VAULT_CORRUPT, "CREATION_CLEANUP_FAILED"
                ) from None
        try:
            path.unlink()
        except OSError:
            raise _vault_failure(
                ErrorCode.VAULT_CORRUPT, "CREATION_CLEANUP_FAILED"
            ) from None

    @classmethod
    def _ensure_parent_directory(cls, path: Path) -> None:
        parent = path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except FileExistsError:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "PARENT_NOT_A_DIRECTORY") from None
        except NotADirectoryError:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "PARENT_NOT_A_DIRECTORY") from None
        except PermissionError:
            raise _vault_failure(ErrorCode.VAULT_ACCESS_DENIED, "PARENT_CREATE_DENIED") from None
        except OSError:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "PARENT_CREATE_FAILED") from None
        if _raw_file_kind(parent) != _RAW_FILE_KIND_DIRECTORY:
            raise _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "PARENT_NOT_A_DIRECTORY")

    @classmethod
    def _bind(
        cls,
        connection: sqlite3.Connection,
        path: Path,
        *,
        expected_source_fingerprint: str | None,
        expected_policy_fingerprint: str | None,
        expected_relationship_fingerprint: str | None,
    ) -> "VaultDatabase":
        """Bind the accepted connection to the validated identity.

        The raw connection is OWNED by the binding until the VaultDatabase is
        successfully returned: EVERY failure path closes the raw operational
        connection exactly once and preserves the original typed failure. A
        rejected foreign vault is never checkpointed or rewritten merely to
        release its failed pre-bind connection.
        """
        try:
            vault_id, schema_version, fingerprints = cls._read_identity(connection)
        except sqlite3.DatabaseError:
            connection.close()
            raise _vault_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
        except BaseException:
            # Typed validation failures (e.g. VAULT_SCHEMA_UNSUPPORTED,
            # META_MISSING, VAULT_ID_MALFORMED) and control exceptions close
            # the connection, too — a failed binding can never leak it.
            connection.close()
            raise
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
                # Raw close of the REJECTED vault: no checkpoint, no rewrite.
                connection.close()
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
    def writer_token(self) -> str | None:
        """The lease token bound to this instance, or None when unauthorized."""
        return self._writer_token

    @property
    def cleanup_failure(self) -> VaultError | None:
        """A typed cleanup failure recorded during close (never raw OS text).

        Deterministic policy: an explicit ``close()`` re-raises cleanup
        failures immediately; a ``with``-block exit that already carries an
        operation exception records the cleanup failure here instead of
        replacing the more important original exception.
        """
        return self._cleanup_failure

    @property
    def poisoned(self) -> VaultError | None:
        """The typed poison reason, or None while the connection is trusted.

        A poisoned connection has uncertain transactional state (failed
        COMMIT/ROLLBACK). It refuses every further ordinary operation until it
        is closed and reopened — reopening revalidates the whole vault.
        """
        return self._poisoned

    def _internal_connection(self) -> sqlite3.Connection:
        """PRIVATE connection seam for the vault subsystem and its tests.

        The normal VaultDatabase interface intentionally exposes NO writable
        raw connection: every mutation funnels through the authorized
        transaction path guarded by the writer lease. A poisoned or closed
        vault refuses even this internal seam.
        """
        if self._closed:
            raise RuntimeError("vault database is closed")
        if self._poisoned is not None:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "CONNECTION_POISONED")
        return self._connection

    def _poison(self, reason: VaultError) -> None:
        """Fail closed: mark this connection's transaction state untrusted."""
        self._poisoned = reason

    @property
    def closed(self) -> bool:
        return self._closed

    def foreign_keys_enabled(self) -> bool:
        """True when the enforced per-connection FK pragma is active."""
        return int(
            self._internal_connection().execute("PRAGMA foreign_keys").fetchone()[0]
        ) == 1

    def journal_mode(self) -> str:
        """The active SQLite journal mode (the explicit WAL policy)."""
        row = self._internal_connection().execute("PRAGMA journal_mode").fetchone()
        return str(row[0]) if row is not None else ""

    # -- transaction boundary --------------------------------------------------
    def transaction(self) -> VaultTransaction:
        """Start one AUTHORIZED mutation transaction unit.

        The calling instance must hold the durable writer lease: entry is
        refused BEFORE any database access when no lease is bound to this
        instance, and the durable ownership is re-verified INSIDE the
        ``BEGIN IMMEDIATE`` lock (an authority handoff can never be raced).
        Exactly one transaction may be active per connection. Transaction
        control failures poison this instance (fail-closed) — a poisoned
        connection refuses further ordinary operations until reopened.
        """
        self._require_trusted_connection()
        if self._transaction is not None and self._transaction.active:
            raise ValueError("vault transaction already active")
        if self._writer_token is None:
            raise _vault_failure(ErrorCode.VAULT_WRITER_CONFLICT, "WRITER_LEASE_REQUIRED")
        transaction = VaultTransaction(
            self._connection,
            on_begin=self._verify_writer_ownership,
            on_poison=self._poison,
        )
        self._transaction = transaction
        self._transaction_authorized = True
        return transaction

    def _system_transaction(self) -> VaultTransaction:
        """PRIVATE system-level transaction (creation, lease acquire/release).

        This is the only transaction form that does not require the writer
        lease, because it IS the mechanism that establishes or transfers the
        authority. It must never be exposed for ordinary vault mutations.
        """
        self._require_trusted_connection()
        if self._transaction is not None and self._transaction.active:
            raise ValueError("vault transaction already active")
        transaction = VaultTransaction(self._connection, on_poison=self._poison)
        self._transaction = transaction
        self._transaction_authorized = False
        return transaction

    def _require_trusted_connection(self) -> None:
        if self._closed:
            raise RuntimeError("vault database is closed")
        if self._poisoned is not None:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "CONNECTION_POISONED")

    def _verify_writer_ownership(self) -> None:
        """Durable authority check, executed inside BEGIN IMMEDIATE."""
        row = self._connection.execute(
            "SELECT owner_token FROM writer_authority WHERE singleton = 1"
        ).fetchone()
        if row is None or row[0] is None or str(row[0]) != self._writer_token:
            raise _vault_failure(ErrorCode.VAULT_WRITER_CONFLICT, "WRITER_LEASE_REQUIRED")

    def _require_active_transaction(self, action: str) -> VaultTransaction:
        transaction = self._transaction
        if (
            transaction is None
            or not transaction.active
            or not self._transaction_authorized
        ):
            raise ValueError(
                f"{action} requires an active authorized VaultDatabase.transaction() unit"
            )
        return transaction

    # -- integrity -------------------------------------------------------------
    def verify(self, *, full: bool = False) -> None:
        """Run the deterministic integrity boundary on demand.

        ``quick_check`` (default) or the more thorough ``integrity_check``
        (``full=True``), plus ``foreign_key_check`` and the explicit
        metadata/schema validation. Any failure raises the typed
        ``VAULT_CORRUPT`` / ``VAULT_SCHEMA_UNSUPPORTED`` classification.

        Fail-closed: a poisoned connection refuses verification BEFORE any
        verification SQL runs — verification can never rehabilitate an
        untrusted connection state. Only :meth:`close` followed by
        :meth:`open` (which revalidates the whole vault) restores trust.
        """
        self._require_trusted_connection()
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
        writer; any other writer fails with the typed ``VAULT_WRITER_CONFLICT``
        classification. A physical SQLite operational failure is a storage
        failure (``VAULT_UNAVAILABLE``), never a writer conflict. On success
        the lease is bound to THIS instance, which from then on is the only
        connection allowed to run ordinary mutation transactions.
        """
        _validate_token(owner_token, field_name="owner_token")
        if self._closed:
            raise RuntimeError("vault database is closed")
        if self._poisoned is not None:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "CONNECTION_POISONED")
        if self._transaction is not None and self._transaction.active:
            raise ValueError("writer lease acquisition requires no active transaction")
        try:
            with self._system_transaction():
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
            # Type-based classification (never SQLite text parsing): a physical
            # operational failure is NOT proof of logical writer ownership.
            raise _vault_failure(
                ErrorCode.VAULT_UNAVAILABLE, "WRITER_LEASE_STORAGE_FAILURE"
            ) from None
        self._writer_token = owner_token
        tick = tick_row[0] if tick_row is not None else 0
        return int(tick)

    def release_writer_lease(self, owner_token: str) -> None:
        """Release the writer authority; only the current holder succeeds."""
        _validate_token(owner_token, field_name="owner_token")
        if self._closed:
            raise RuntimeError("vault database is closed")
        if self._poisoned is not None:
            raise _vault_failure(ErrorCode.VAULT_STATE_INVALID, "CONNECTION_POISONED")
        try:
            with self._system_transaction():
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
            raise _vault_failure(
                ErrorCode.VAULT_UNAVAILABLE, "WRITER_LEASE_STORAGE_FAILURE"
            ) from None
        if self._writer_token == owner_token:
            self._writer_token = None

    def stale_writer_lease(self) -> str | None:
        """The currently stored lease token (explicit crash-state evidence)."""
        row = self._internal_connection().execute(
            "SELECT owner_token FROM writer_authority WHERE singleton = 1"
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return str(row[0])

    def writer_acquire_tick(self) -> int:
        row = self._internal_connection().execute(
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
            existing = self._internal_connection().execute(
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
        rows = self._internal_connection().execute(
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
        rows = self._internal_connection().execute(
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
    def _checkpoint_wal(self) -> None:
        """Truncate-checkpoint the WAL and VERIFY the structured result.

        ``PRAGMA wal_checkpoint(TRUNCATE)`` returns a status row
        ``(busy, log_pages, checkpointed_pages)``; a BUSY/incomplete
        checkpoint does NOT raise. The full row is inspected and an
        incomplete checkpoint raises the typed lifecycle failure
        ``VAULT_UNAVAILABLE`` / ``CLOSE_CHECKPOINT_INCOMPLETE`` — no
        human-readable SQLite text is involved and success is never claimed
        for an incomplete checkpoint.
        """
        row = self._connection.execute(
            f"PRAGMA wal_checkpoint({VAULT_CLOSE_CHECKPOINT})"
        ).fetchone()
        if row is None or row[0] is None or len(row) < 1:
            raise _vault_failure(
                ErrorCode.VAULT_UNAVAILABLE, "CLOSE_CHECKPOINT_INCOMPLETE"
            )
        if int(row[0]) != 0:
            raise _vault_failure(
                ErrorCode.VAULT_UNAVAILABLE, "CLOSE_CHECKPOINT_INCOMPLETE"
            )

    def close(self) -> None:
        """Clean close: truncate-checkpoint the WAL, then close the connection.

        A normal clean close leaves NO persistent ``-wal``/``-shm`` sidecars
        (SQLite removes them with the last connection). A checkpoint status
        failure (BUSY/incomplete), a raising checkpoint or a failing close
        SURFACE as a typed, privacy-safe ``VaultError`` — never silently
        absorbed (the P2-009 protected-artifact policy builds on this).
        Deterministic policy for a ``with``-block exit that already carries an
        operation exception: the cleanup failure is RECORDED on
        :attr:`cleanup_failure` instead of replacing the original exception.
        """
        self._close(record_failure_only=False)

    def _close(self, *, record_failure_only: bool) -> None:
        if self._closed:
            return
        self._closed = True
        failure: VaultError | None = None
        try:
            self._checkpoint_wal()
        except VaultError as error:
            failure = error  # typed checkpoint status/execution failure
        except sqlite3.Error:
            failure = _vault_failure(
                ErrorCode.VAULT_UNAVAILABLE, "CLOSE_CHECKPOINT_FAILED"
            )
        try:
            self._connection.close()
        except sqlite3.Error:
            if failure is None:
                failure = _vault_failure(ErrorCode.VAULT_UNAVAILABLE, "CLOSE_FAILED")
        self._cleanup_failure = failure
        if failure is not None and not record_failure_only:
            raise failure

    def __enter__(self) -> "VaultDatabase":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._close(record_failure_only=exc_type is not None)
