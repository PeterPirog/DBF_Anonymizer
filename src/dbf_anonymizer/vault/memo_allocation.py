"""Reversible Memo/General/Picture allocation on the vault foundation.

This module is the REQ-P2-007 boundary that binds the PURE transformation
kernels of :mod:`dbf_anonymizer.transforms.memo` to the protected SQLite
vault storage.  It introduces NO second recovery store, NO payload sidecar
file and NO public recovery pipeline; the ``memo_recovery`` rows of the one
authoritative vault remain the only place where an original memo payload
exists outside the source dataset.

The core ordering invariant of the requirement is structural here:

NO transformed non-NULL memo value may be considered successfully persisted
unless its recovery payload has been durably committed to the authoritative
vault.

:func:`persist_memo_recovery` therefore inserts the recovery row INSIDE one
authorized ``BEGIN IMMEDIATE`` transaction and returns the safe mask only
after that unit has COMMITTED — any storage or authority failure propagates
before a mask could ever be produced, and the transaction rolls back the
failed row together with everything else in the unit.  The future P4 engine
batches many records inside one of ITS transactions by using the pure
kernels plus :func:`dbf_anonymizer.vault.mappings.add_memo_recovery`
directly; this per-value unit is the independently testable P2 boundary.

Bounded memory: the service is stateless — no payload from a previous
record is ever retained (no in-memory collection exists).  Ownership of the
current logical value returned by the public reader is reused when it is
already immutable ``bytes``; the SQLite binding holds one transient
reference to the CURRENT payload only (truthfully documented, not claimed
zero-copy).
"""

from __future__ import annotations

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError, VaultError
from dbf_anonymizer.transforms import memo as memo_kernels
from dbf_anonymizer.vault.mappings import (
    VAULT_PAYLOAD_KIND_BINARY,
    VAULT_PAYLOAD_KIND_TEXT,
    add_memo_recovery,
    get_memo_recovery,
)
from dbf_anonymizer.vault.store import VaultDatabase

__all__ = [
    "persist_memo_recovery",
    "recover_memo_value",
]


def _unsupported(dbf_type: str | None = None) -> MappingError:
    """Stable typed refusal for an unsupported memo representation."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(
            operation="transform", detail_code="MEMO_UNSUPPORTED_REPRESENTATION"
        ),
    )


def _recovery_invalid() -> VaultError:
    """Stable typed failure for incompatible/corrupt recovery state."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code="MEMO_RECOVERY_INVALID"),
    )


def _mask_for(dbf_type: str, value: object) -> str | bytes | None:
    """The safe mask of *value* under its field kind (fail closed).

    ``M`` fields carry TEXT or BINARY payloads (the value type decides,
    exactly like the public writer's binary-memo discriminator).  ``G`` and
    ``P`` fields are binary-only: a text value there is an unsupported
    representation.  Every other field kind — including the opaque/raw-only
    ``W``/``Q`` classes — has NO proven safe memo transformation and must
    never pass: the typed refusal is raised before anything is stored.
    """
    if dbf_type not in memo_kernels.MEMO_FIELD_TYPES:
        raise _unsupported()
    if value is None:
        return None
    if isinstance(value, str):
        if dbf_type in {"G", "P"}:
            raise _unsupported()  # a binary-only class never carries text
        return memo_kernels.MEMO_TEXT_MASK
    if isinstance(value, (bytes, bytearray)):
        return memo_kernels.MEMO_BINARY_MASK
    raise _unsupported()


def persist_memo_recovery(
    database: VaultDatabase,
    *,
    table_id: str,
    physical_record_index: int,
    field_id: str,
    dbf_type: str,
    value: object,
) -> str | bytes | None:
    """Store-then-mask one logical memo value (the P2-007 allocation unit).

    ``None`` preserves NULL: nothing is stored and ``None`` is returned —
    the pseudonymized output keeps the original NULL pointer semantics.  A
    non-NULL payload is stored EXACTLY (UTF-8 image for text, byte-for-byte
    for binary) as one recovery row keyed by the stable ``table_id +
    physical_record_index + field_id`` identity, inside one authorized
    transaction; only after that unit commits does the method return the
    constant safe mask the pseudonymized output must carry instead of the
    original payload.

    The calling instance must hold the durable writer lease (the
    transaction unit refuses otherwise).  Any storage failure propagates
    before a mask exists; a failed unit rolls back and commits nothing.
    """
    mask = _mask_for(dbf_type, value)
    if mask is None:
        return None
    if not isinstance(value, (str, bytes, bytearray)):
        # _mask_for already refused non-vocabulary values; this branch keeps
        # the row API's declared payload type honest for the type checker.
        raise _unsupported()
    kind = (
        VAULT_PAYLOAD_KIND_TEXT
        if isinstance(value, str)
        else VAULT_PAYLOAD_KIND_BINARY
    )
    with database.transaction():
        # The vault row API owns the exact storage image (UTF-8 for TEXT,
        # byte-for-byte for BINARY); the service passes the logical value.
        add_memo_recovery(
            database,
            table_id,
            physical_record_index,
            field_id,
            value,
            payload_kind=kind,
        )
    return mask


def recover_memo_value(
    database: VaultDatabase,
    *,
    table_id: str,
    physical_record_index: int,
    field_id: str,
) -> str | bytes | None:
    """The original logical memo value of one stable identity (INTERNAL).

    ``None`` means the identity has no recovery row (a NULL memo needs
    none).  A ``TEXT`` row is decoded from its exact UTF-8 image; a
    ``BINARY`` row is returned byte-for-byte.  Incompatible or corrupt
    stored state (an unknown payload kind, an undecodable TEXT image)
    fails closed with a stable typed error — values never reach errors.
    This internal retrieval seam exists for the later recovery pipeline;
    it is deliberately NOT public API surface yet.
    """
    row = get_memo_recovery(database, table_id, physical_record_index, field_id)
    if row is None:
        return None
    payload, kind = row
    if kind == VAULT_PAYLOAD_KIND_TEXT:
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            raise _recovery_invalid() from None
    if kind == VAULT_PAYLOAD_KIND_BINARY:
        return payload
    raise _recovery_invalid()