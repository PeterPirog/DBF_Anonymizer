"""Pure shared Memo/General/Picture transformation semantics (REQ-P2-007).

This module is the ONE authoritative model of the reversible memo
transformation for the three memo-carrying DBF logical classes:

* ``M`` Memo — TEXT or BINARY payload (the public reader decodes a text
  block to ``str`` and returns a binary block as a ``bytes`` subclass);
* ``G`` General — BINARY payload;
* ``P`` Picture — BINARY payload.

The logical value vocabulary is EXACTLY the public ``dbfbridge`` Direct Read
contract for these fields: ``None`` (NULL memo — pointer absent or empty
block), ``str`` (decoded text payload) and ``bytes`` (binary payload,
including the public ``bytes`` subclasses).  Anything else — unloaded lazy
references, ``memoryview``, numbers, opaque W/Q payloads — is an UNSAFE
representation for which no safe logical transformation is proven: every
consumer MUST fail closed with a stable typed error instead of guessing,
decoding arbitrary bytes as text or copying opaque source blocks.

Semantics (immutable architecture baseline, field transformation table):

* NULL stays NULL: no vault row, no mask, no error;
* every non-NULL payload is stored ONLY in the protected SQLite vault (the
  caller persists the recovery payload through the vault foundation, which
  owns the exact storage image: a UTF-8 encoding for text payloads and a
  byte-for-byte image for binary payloads) and the emitted output value is
  a CONSTANT, source-independent safe mask — the mask can never contain
  original source bytes because it is a fixed literal;
* the mask type is type-appropriate: a text payload is masked with a text
  (``str``) mask, a binary payload with a binary (``bytes``) mask, so the
  public writer's per-record binary-memo discriminator keeps the original
  block-kind semantics of the field;
* ``""`` and ``b""`` are legitimate non-NULL payloads: they are stored and
  masked exactly like any other payload and are never collapsed into NULL
  (the public writer/reader round-trips empty blocks distinctly from NULL
  pointers);
* the module is value-typed only: it never encodes, hashes or derives
  anything from a payload; the vault storage image is decided by the vault
  foundation in one place.

The module is PURE: standard library only, no I/O, no vault access, no
``dbfbridge`` import and no randomness.  It must therefore never grow DBF/FPT
parsing, vault access or payload-bearing public structures.
"""

from __future__ import annotations

from typing import Literal

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError

__all__ = [
    "MEMO_MASK_POLICY_VERSION",
    "MEMO_TEXT_MASK",
    "MEMO_BINARY_MASK",
    "MEMO_PAYLOAD_KIND_TEXT",
    "MEMO_PAYLOAD_KIND_BINARY",
    "is_memo_logical_value",
    "memo_payload_kind",
    "memo_safe_mask",
    "memo_requires_binary",
]

#: Versioned identity of the safe-mask policy (single authoritative
#: definition; the vault allocation service and the evidence tests bind it).
MEMO_MASK_POLICY_VERSION = "1.0"

#: The constant TEXT safe mask.  A fixed, obviously synthetic ASCII token:
#: source-independent by construction, so no original memo text (and no byte
#: of any original payload) can ever leak through the masked output.
MEMO_TEXT_MASK: str = "[MASKED-MEMO]"

#: The constant BINARY safe mask for General/Picture (and binary Memo)
#: payloads: a fixed ASCII byte token that cannot contain original bytes.
MEMO_BINARY_MASK: bytes = b"[MASKED-MEMO]"

#: The bounded payload-kind vocabulary of the vault recovery rows.
MEMO_PAYLOAD_KIND_TEXT = "TEXT"
MEMO_PAYLOAD_KIND_BINARY = "BINARY"

#: Memo-carrying DBF field types supported by this transformation.
MEMO_FIELD_TYPES = frozenset({"M", "G", "P"})


def _unsupported() -> MappingError:
    """Stable typed failure for an unsafe memo representation (no values)."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(
            operation="transform", detail_code="MEMO_UNSUPPORTED_REPRESENTATION"
        ),
    )


def is_memo_logical_value(value: object) -> bool:
    """True exactly for the public logical vocabulary: ``None|str|bytes``."""
    return value is None or isinstance(value, (str, bytes, bytearray))


def memo_payload_kind(value: object) -> Literal["TEXT", "BINARY"]:
    """The bounded vault payload kind of one non-NULL logical memo value."""
    if isinstance(value, str):
        return "TEXT"
    if isinstance(value, (bytes, bytearray)):
        return "BINARY"
    raise _unsupported()


def memo_safe_mask(value: object) -> str | bytes | None:
    """The type-appropriate constant safe mask, or ``None`` for NULL.

    ``None`` preserves NULL identity (no mask, no recovery row).  A text
    payload is masked with :data:`MEMO_TEXT_MASK`, a binary payload with
    :data:`MEMO_BINARY_MASK`; both masks are fixed literals, so they cannot
    contain any original source bytes by construction.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return MEMO_TEXT_MASK
    if isinstance(value, (bytes, bytearray)):
        return MEMO_BINARY_MASK
    raise _unsupported()


def memo_requires_binary(dbf_type: str) -> bool:
    """Whether a memo-carrying field kind admits only BINARY payloads.

    ``G``/``P`` payloads are always binary; an ``M`` field may carry a text
    OR a binary payload (the value type decides, exactly like the public
    writer's binary-memo discriminator).  Any other field kind has no proven
    safe memo transformation and must fail closed.
    """
    if dbf_type in {"G", "P"}:
        return True
    if dbf_type == "M":
        return False
    raise _unsupported()