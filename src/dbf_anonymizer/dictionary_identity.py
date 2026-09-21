"""Read-only identity validation of ONE protected dictionary database.

This INTERNAL kernel is shared by the vault store's strictly non-mutating
reopen validation (STAGE 1 of :meth:`VaultDatabase.open`) and by the
source-read-only, side-effect-free ``preflight`` (REQ-P1-006): both must be
able to decide whether an EXISTING dictionary file is a compatible reuse
candidate without ever writing, converting, recovering or checkpointing
anything (REQ-P2-010 identity checking without a mutation-capable open).

Guarantees:

* the database is read through an SQLite ``mode=ro&immutable=1`` URI
  connection: no ``-wal``/``-shm`` sidecar creation, no journal-mode change,
  no metadata/schema write, no recovery or checkpoint — a rejected database
  stays byte-identical and artifact-free;
* classification is by exception TYPE only, never by parsing SQLite text;
* every failure is a typed, privacy-safe ``VaultError`` boundary (no SQLite
  messages, no original values, no absolute private paths).

The module deliberately lives OUTSIDE the vault package and is the single
implementation of the SQLite schema/fingerprint parsing shared by the store
and preflight; it never creates a database and never imports the DBF/FPT
dependency namespace.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VaultError
from dbf_anonymizer.vault.schema import VAULT_ID_PREFIX, VAULT_SCHEMA_VERSION

__all__ = [
    "DICTIONARY_BUSY_TIMEOUT_MS",
    "DICTIONARY_SIDECAR_SUFFIXES",
    "connect_dictionary_readonly",
    "dictionary_id_shape_valid",
    "dictionary_sidecars",
    "incompatible_dictionary_identity",
    "read_dictionary_identity",
    "validate_dictionary_identity_readonly",
]

#: Bounded SQLite busy timeout (one shared connection policy).
DICTIONARY_BUSY_TIMEOUT_MS = 10_000

#: The ambiguous SQLite lifecycle artifacts that make a persisted dictionary
#: state unverifiable without recovery: a write-ahead log, its shared-memory
#: index and a rollback journal. A cleanly closed WAL dictionary leaves none
#: of them behind, so any of these beside an existing file — derived from the
#: dictionary's OWN filename — means the committed state cannot be validated
#: read-only and immutably.
DICTIONARY_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


def _dictionary_failure(code: ErrorCode, detail_code: str) -> VaultError:
    """Build a privacy-safe, registry-controlled dictionary failure."""
    return VaultError(
        code,
        context=ErrorContext(operation="vault", detail_code=detail_code),
    )


def dictionary_id_shape_valid(value: object, prefix: str) -> bool:
    """True when *value* is ``prefix`` followed by 32 lowercase hex digits."""
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    digits = value[len(prefix):]
    if len(digits) != 32:
        return False
    return all(character in "0123456789abcdef" for character in digits)


def dictionary_sidecars(path: Path) -> tuple[str, ...]:
    """The fail-closed sidecar inventory OWNED by exactly this dictionary file.

    Only companions derived from *path* itself (``<name>-wal``, ``<name>-shm``
    and ``<name>-journal``) belong to this dictionary's lifecycle state. An
    unrelated sibling's SQLite artifacts (e.g. ``other.sqlite3-wal``) are
    foreign state and must never influence THIS dictionary's compatibility
    (truthful REQ-P2-010 reuse). ``PermissionError``/``OSError`` become typed
    privacy-safe failures; an uninspectable directory is never treated as
    sidecar-free (fail-open is impossible).
    """
    try:
        names = os.listdir(path.parent)
    except PermissionError:
        raise _dictionary_failure(
            ErrorCode.VAULT_ACCESS_DENIED, "TARGET_STAT_DENIED"
        ) from None
    except OSError:
        raise _dictionary_failure(
            ErrorCode.VAULT_UNAVAILABLE, "TARGET_STAT_FAILED"
        ) from None
    owned = {f"{path.name}{suffix}" for suffix in DICTIONARY_SIDECAR_SUFFIXES}
    return tuple(name for name in sorted(names) if name in owned)


def connect_dictionary_readonly(path: Path) -> sqlite3.Connection:
    """Open the strictly read-only immutable validation snapshot connection.

    ``immutable=1`` reads the file without creating any ``-wal``/``-shm``
    wal-index artifacts (a plain ``mode=ro`` open of a WAL database makes
    SQLite create persistent sidecars). The dictionary identity and schema
    are immutable after creation, so the validation snapshot is exact for
    every supported, cleanly-closed database; a rejected database stays
    byte-identical and artifact-free.
    """
    try:
        uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
        connection = sqlite3.connect(
            uri,
            uri=True,
            timeout=DICTIONARY_BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
    except PermissionError:
        raise _dictionary_failure(ErrorCode.VAULT_ACCESS_DENIED, "OPEN_DENIED") from None
    except OSError:
        raise _dictionary_failure(ErrorCode.VAULT_UNAVAILABLE, "OPEN_FAILED") from None
    except sqlite3.Error:
        raise _dictionary_failure(ErrorCode.VAULT_UNAVAILABLE, "OPEN_FAILED") from None
    try:
        connection.execute(f"PRAGMA busy_timeout = {DICTIONARY_BUSY_TIMEOUT_MS}")
    except sqlite3.Error:
        connection.close()
        raise _dictionary_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
    return connection


def read_dictionary_identity(
    connection: sqlite3.Connection,
) -> tuple[str, str, dict[str, str]]:
    """Validate integrity + identity shape and read the dataset fingerprints.

    Type-classified integrity boundary, exact schema-version gate and
    bounded identifier shape check; the dataset identity row provides the
    source/policy/relationship fingerprints. Classification is by exception
    TYPE only; failures are typed and carry no database text.
    """
    check_rows = connection.execute("PRAGMA quick_check").fetchall()
    if (
        len(check_rows) != 1
        or not isinstance(check_rows[0][0], str)
        or check_rows[0][0] != "ok"
    ):
        raise _dictionary_failure(ErrorCode.VAULT_CORRUPT, "QUICK_CHECK_FAILED")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise _dictionary_failure(ErrorCode.VAULT_CORRUPT, "FOREIGN_KEY_CHECK_FAILED")
    meta = connection.execute(
        "SELECT schema_version, vault_id FROM meta WHERE singleton = 1"
    ).fetchone()
    if meta is None:
        raise _dictionary_failure(ErrorCode.VAULT_CORRUPT, "META_MISSING")
    vault_id = meta[1]
    if not dictionary_id_shape_valid(vault_id, VAULT_ID_PREFIX):
        raise _dictionary_failure(ErrorCode.VAULT_CORRUPT, "VAULT_ID_MALFORMED")
    if meta[0] != VAULT_SCHEMA_VERSION:
        raise _dictionary_failure(
            ErrorCode.VAULT_SCHEMA_UNSUPPORTED, "SCHEMA_VERSION_UNSUPPORTED"
        )
    dataset = connection.execute(
        "SELECT source_fingerprint, policy_fingerprint, relationship_fingerprint "
        "FROM dataset WHERE singleton = 1"
    ).fetchone()
    if dataset is None:
        raise _dictionary_failure(ErrorCode.VAULT_CORRUPT, "DATASET_MISSING")
    return (
        str(vault_id),
        str(meta[0]),
        {
            "source": str(dataset[0]),
            "policy": str(dataset[1]),
            "relationship": str(dataset[2]),
        },
    )


def incompatible_dictionary_identity(
    fingerprints: dict[str, str],
    *,
    expected_source_fingerprint: str | None,
    expected_policy_fingerprint: str | None,
    expected_relationship_fingerprint: str | None,
) -> str | None:
    """The stable detail code of the FIRST identity mismatch, or ``None``."""
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
            return detail_code
    return None


def validate_dictionary_identity_readonly(
    path: Path,
    *,
    expected_source_fingerprint: str | None,
    expected_policy_fingerprint: str | None,
    expected_relationship_fingerprint: str | None,
) -> None:
    """Read-only reuse validation of an existing dictionary file.

    Ambiguous sidecar state fails closed FIRST: validating a crash-dirty
    WAL/write-ahead state through an immutable snapshot would silently
    ignore uncheckpointed committed state, so it is refused without any
    recovery, checkpoint or connection attempt.

    Any rejection is a typed privacy-safe ``VaultError``; the file is never
    written, never converted and never left with new sidecars.
    """
    if dictionary_sidecars(path):
        raise _dictionary_failure(
            ErrorCode.VAULT_STATE_INVALID, "SIDECAR_STATE_AMBIGUOUS"
        )
    connection = connect_dictionary_readonly(path)
    try:
        _vault_id, _schema_version, fingerprints = read_dictionary_identity(connection)
    except sqlite3.DatabaseError:
        raise _dictionary_failure(ErrorCode.VAULT_CORRUPT, "DATABASE_UNREADABLE") from None
    finally:
        connection.close()
    detail = incompatible_dictionary_identity(
        fingerprints,
        expected_source_fingerprint=expected_source_fingerprint,
        expected_policy_fingerprint=expected_policy_fingerprint,
        expected_relationship_fingerprint=expected_relationship_fingerprint,
    )
    if detail is not None:
        raise _dictionary_failure(ErrorCode.VAULT_IDENTITY_MISMATCH, detail)