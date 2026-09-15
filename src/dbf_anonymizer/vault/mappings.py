"""Mapping domains and reversible-value rows in the vault (REQ-P2-002/003).

The mapping-consistency invariants live IN the database: the named UNIQUE
indexes on ``(domain_id, original_value)`` and ``(domain_id, pseudonym_value)``
make the bijection per domain a database property, not a Python promise. The
recorders here translate SQLite constraint failures (type-based, never by
parsing SQLite text) into the typed ``MAPPING_CONFLICT`` classification
without ever exposing the conflicting values or raw SQLite error text.

Original values and pseudonyms are stored INSIDE the protected vault by
design; they must never escape into public models, errors, logs or events
(proven by the privacy sentinel tests). Pseudonym ALLOCATION is REQ-P2-004
and is explicitly NOT implemented here — every insert takes caller-supplied
values.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError, VaultError
from dbf_anonymizer.vault.schema import (
    VAULT_PAYLOAD_KIND_BINARY,
    VAULT_PAYLOAD_KIND_TEXT,
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
)
from dbf_anonymizer.vault.store import VaultDatabase, _validate_token

__all__ = [
    "VAULT_TABLE_DOMAIN_KIND_TEXT",
    "VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY",
    "VAULT_PAYLOAD_KIND_TEXT",
    "VAULT_PAYLOAD_KIND_BINARY",
    "create_domain",
    "mapping_domains",
    "add_text_mapping",
    "get_text_pseudonym",
    "get_text_original",
    "text_mapping_rows",
    "add_numeric_key_mapping",
    "get_numeric_pseudonym",
    "numeric_mapping_rows",
    "add_memo_recovery",
    "get_memo_recovery",
    "memo_recovery_rows",
    "set_temporal_parameter",
    "temporal_parameter",
]


def _mapping_failure(detail_code: str) -> MappingError:
    """Privacy-safe, registry-controlled mapping failure (no values exposed)."""
    return MappingError(
        ErrorCode.MAPPING_CONFLICT,
        context=ErrorContext(operation="vault", detail_code=detail_code),
    )


def _vault_state_failure(detail_code: str) -> VaultError:
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code=detail_code),
    )


def create_domain(
    database: VaultDatabase,
    *,
    domain_kind: str,
    normalization: str | None = None,
    relational_role: str | None = None,
    domain_id: str | None = None,
) -> str:
    """Register one mapping domain; returns its stable domain_id.

    ``domain_kind`` must be one of the bounded kind constants. When
    ``domain_id`` is omitted a privacy-safe random identifier is generated.
    """
    database._require_active_transaction("create_domain")
    if domain_kind not in (
        VAULT_TABLE_DOMAIN_KIND_TEXT,
        VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
        VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
    ):
        raise ValueError(f"unsupported domain_kind: {domain_kind!r}")
    if domain_id is None:
        domain_id = "dom-" + uuid.uuid4().hex
    else:
        _validate_token(domain_id, field_name="domain_id")
    for optional in (normalization, relational_role):
        if optional is not None:
            _validate_token(optional, field_name="domain descriptor")
    try:
        database._internal_connection().execute(
            "INSERT INTO mapping_domains (domain_id, domain_kind, normalization, "
            "relational_role) VALUES (?, ?, ?, ?)",
            (domain_id, domain_kind, normalization, relational_role),
        )
    except sqlite3.IntegrityError:
        raise _vault_state_failure("DOMAIN_REJECTED") from None
    return domain_id


def mapping_domains(database: VaultDatabase) -> tuple[dict[str, str | None], ...]:
    rows = database._internal_connection().execute(
        "SELECT domain_id, domain_kind, normalization, relational_role "
        "FROM mapping_domains ORDER BY domain_id"
    ).fetchall()
    return tuple(
        {
            "domain_id": str(row[0]),
            "domain_kind": str(row[1]),
            "normalization": row[2],
            "relational_role": row[3],
        }
        for row in rows
    )


def add_text_mapping(
    database: VaultDatabase,
    domain_id: str,
    original_value: str,
    pseudonym_value: str,
    *,
    logical_byte_length: int,
) -> None:
    """Insert one reversible text mapping (caller-supplied pseudonym).

    SQLite enforces both bijection directions; a collision raises the typed
    ``MAPPING_CONFLICT`` classification and the transaction context decides
    the rollback boundary. Values are never part of the error.
    """
    database._require_active_transaction("add_text_mapping")
    _validate_token(domain_id, field_name="domain_id")
    if logical_byte_length < 0:
        raise ValueError("logical_byte_length must be non-negative")
    try:
        database._internal_connection().execute(
            "INSERT INTO text_mappings (domain_id, original_value, pseudonym_value, "
            "logical_byte_length) VALUES (?, ?, ?, ?)",
            (domain_id, original_value, pseudonym_value, logical_byte_length),
        )
    except sqlite3.IntegrityError:
        raise _mapping_failure("MAPPING_BIJECTION_REJECTED") from None


def _corrupt_recovery_state(detail_code: str) -> VaultError:
    """Typed, privacy-safe refusal for hostile/corrupt recovery storage."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code=detail_code),
    )


def get_text_pseudonym(database: VaultDatabase, domain_id: str, original_value: str) -> str | None:
    row = database._internal_connection().execute(
        "SELECT pseudonym_value, typeof(pseudonym_value) FROM text_mappings "
        "WHERE domain_id = ? AND original_value = ?",
        (domain_id, original_value),
    ).fetchone()
    if row is None:
        return None
    # Adversarial corruption hardening: SQLite dynamic typing means a hostile
    # or corrupt row may hold an unexpected storage class; refuse it instead
    # of coercively accepting it.
    if row[1] != "text":
        raise _corrupt_recovery_state("TEXT_MAPPING_CORRUPT")
    return str(row[0])


def get_text_original(database: VaultDatabase, domain_id: str, pseudonym_value: str) -> str | None:
    row = database._internal_connection().execute(
        "SELECT original_value, typeof(original_value) FROM text_mappings "
        "WHERE domain_id = ? AND pseudonym_value = ?",
        (domain_id, pseudonym_value),
    ).fetchone()
    if row is None:
        return None
    if row[1] != "text":
        raise _corrupt_recovery_state("TEXT_MAPPING_CORRUPT")
    return str(row[0])


def text_mapping_rows(database: VaultDatabase, domain_id: str) -> tuple[tuple[str, str, int], ...]:
    rows = database._internal_connection().execute(
        "SELECT original_value, pseudonym_value, logical_byte_length, "
        "typeof(original_value), typeof(pseudonym_value), "
        "typeof(logical_byte_length) FROM text_mappings "
        "WHERE domain_id = ? ORDER BY original_value",
        (domain_id,),
    ).fetchall()
    for row in rows:
        if row[3] != "text" or row[4] != "text" or row[5] != "integer":
            raise _corrupt_recovery_state("TEXT_MAPPING_CORRUPT")
    return tuple((str(row[0]), str(row[1]), int(row[2])) for row in rows)


def add_numeric_key_mapping(
    database: VaultDatabase,
    domain_id: str,
    original_value: str,
    pseudonym_value: str,
) -> None:
    """Insert one numeric-key mapping (bounded TEXT-encoded numbers).

    Both directions of the bijection are enforced by the named UNIQUE indexes
    of the ``numeric_key_mappings`` table.
    """
    database._require_active_transaction("add_numeric_key_mapping")
    _validate_token(domain_id, field_name="domain_id")
    try:
        database._internal_connection().execute(
            "INSERT INTO numeric_key_mappings (domain_id, original_value, "
            "pseudonym_value) VALUES (?, ?, ?)",
            (domain_id, original_value, pseudonym_value),
        )
    except sqlite3.IntegrityError:
        raise _mapping_failure("MAPPING_BIJECTION_REJECTED") from None


def get_numeric_pseudonym(database: VaultDatabase, domain_id: str, original_value: str) -> str | None:
    row = database._internal_connection().execute(
        "SELECT pseudonym_value FROM numeric_key_mappings WHERE domain_id = ? AND original_value = ?",
        (domain_id, original_value),
    ).fetchone()
    return None if row is None else str(row[0])


def numeric_mapping_rows(database: VaultDatabase, domain_id: str) -> tuple[tuple[str, str], ...]:
    rows = database._internal_connection().execute(
        "SELECT original_value, pseudonym_value FROM numeric_key_mappings "
        "WHERE domain_id = ? ORDER BY original_value",
        (domain_id,),
    ).fetchall()
    return tuple((str(row[0]), str(row[1])) for row in rows)


def add_memo_recovery(
    database: VaultDatabase,
    table_id: str,
    physical_record_index: int,
    field_id: str,
    payload: bytes | bytearray | str,
    *,
    payload_kind: str,
) -> None:
    """Store one reversible memo recovery row (REQ-P2-007).

    The row is keyed by the stable ``table_id + physical_record_index +
    field_id`` identity (the primary key makes a duplicate identity a typed
    fail-closed rejection) and the enforced foreign key proves that the
    field belongs to the table.  The payload kind is exactly bounded:

    * ``TEXT``  — the payload must be a ``str``; it is stored as its exact
      UTF-8 image (encoding-independent and lossless);
    * ``BINARY`` — the payload must be ``bytes``/``bytearray`` and is stored
      byte-for-byte (normalized to immutable ``bytes``).

    A type/kind mismatch is refused (fail closed) before any database
    access.  Conflicting values never appear in the typed failure.
    """
    database._require_active_transaction("add_memo_recovery")
    _validate_token(table_id, field_name="table_id")
    _validate_token(field_id, field_name="field_id")
    if payload_kind not in (VAULT_PAYLOAD_KIND_TEXT, VAULT_PAYLOAD_KIND_BINARY):
        raise ValueError(
            "payload_kind must be exactly VAULT_PAYLOAD_KIND_TEXT or "
            "VAULT_PAYLOAD_KIND_BINARY"
        )
    if isinstance(physical_record_index, bool) or not isinstance(
        physical_record_index, int
    ):
        raise TypeError("physical_record_index must be an int")
    if physical_record_index < 0:
        raise ValueError("physical_record_index must be non-negative")
    if payload_kind == VAULT_PAYLOAD_KIND_TEXT:
        if not isinstance(payload, str):
            raise ValueError("a TEXT memo recovery payload must be a str")
        blob: bytes = payload.encode("utf-8")
    else:
        if isinstance(payload, (bytes, bytearray)):
            blob = bytes(payload)
        else:
            raise ValueError("a BINARY memo recovery payload must be bytes")
    try:
        database._internal_connection().execute(
            "INSERT INTO memo_recovery (table_id, physical_record_index, field_id, "
            "original_payload, payload_kind) VALUES (?, ?, ?, ?, ?)",
            (table_id, physical_record_index, field_id, blob, payload_kind),
        )
    except sqlite3.IntegrityError:
        raise _vault_state_failure("MEMO_ROW_REJECTED") from None


def get_memo_recovery(
    database: VaultDatabase,
    table_id: str,
    physical_record_index: int,
    field_id: str,
) -> tuple[bytes, str] | None:
    """The exact recovery row of one stable memo identity, or ``None``.

    Returns ``(original_payload, payload_kind)`` for the unique row of the
    stable ``table_id + physical_record_index + field_id`` identity — the
    narrow, unambiguous retrieval the later recovery pipeline consumes.  A
    missing identity is ``None``; no row payload ever reaches an error.
    Hostile/corrupt storage classes (SQLite dynamic typing) fail closed.
    """
    _validate_token(table_id, field_name="table_id")
    _validate_token(field_id, field_name="field_id")
    if isinstance(physical_record_index, bool) or not isinstance(
        physical_record_index, int
    ):
        raise TypeError("physical_record_index must be an int")
    if physical_record_index < 0:
        raise ValueError("physical_record_index must be non-negative")
    row = database._internal_connection().execute(
        "SELECT original_payload, payload_kind, typeof(original_payload), "
        "typeof(payload_kind) FROM memo_recovery "
        "WHERE table_id = ? AND physical_record_index = ? AND field_id = ?",
        (table_id, physical_record_index, field_id),
    ).fetchone()
    if row is None:
        return None
    if row[2] != "blob" or row[3] != "text":
        raise _corrupt_recovery_state("MEMO_ROW_CORRUPT")
    return (bytes(row[0]), str(row[1]))


def memo_recovery_rows(database: VaultDatabase, table_id: str) -> tuple[dict[str, Any], ...]:
    rows = database._internal_connection().execute(
        "SELECT physical_record_index, field_id, original_payload, payload_kind "
        "FROM memo_recovery WHERE table_id = ? ORDER BY physical_record_index",
        (table_id,),
    ).fetchall()
    return tuple(
        {
            "physical_record_index": int(row[0]),
            "field_id": str(row[1]),
            "original_payload": row[2],
            "payload_kind": str(row[3]),
        }
        for row in rows
    )


def set_temporal_parameter(
    database: VaultDatabase, domain_id: str, *, offset_days: int
) -> None:
    """Persist the Date/DateTime recovery parameter of one temporal domain.

    The internal write boundary refuses logically invalid temporal state:
    the offset must be a genuine ``int`` (never ``bool``) and a NON-ZERO
    reversible shift — offset 0 is never a valid temporal parameter.
    """
    database._require_active_transaction("set_temporal_parameter")
    _validate_token(domain_id, field_name="domain_id")
    if isinstance(offset_days, bool) or not isinstance(offset_days, int):
        raise TypeError("offset_days must be an int")
    if offset_days == 0:
        raise ValueError("offset_days must be a non-zero reversible shift")
    try:
        database._internal_connection().execute(
            "INSERT INTO temporal_parameters (domain_id, offset_days) VALUES (?, ?)",
            (domain_id, offset_days),
        )
    except sqlite3.IntegrityError:
        raise _vault_state_failure("TEMPORAL_REJECTED") from None


def temporal_parameter(database: VaultDatabase, domain_id: str) -> int | None:
    row = database._internal_connection().execute(
        "SELECT offset_days, typeof(offset_days) FROM temporal_parameters "
        "WHERE domain_id = ?",
        (domain_id,),
    ).fetchone()
    if row is None:
        return None
    # Adversarial corruption hardening: only an INTEGER storage class is a
    # valid persisted temporal offset (never a coercible TEXT/REAL/BLOB).
    if row[1] != "integer":
        raise _corrupt_recovery_state("TEMPORAL_STATE_INVALID")
    return int(row[0])
