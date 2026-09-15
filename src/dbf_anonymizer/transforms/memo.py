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
  a mask selected from a fixed bounded synthetic vocabulary;
* the mask vocabulary has TWO members per payload type and deterministic
  SELF-EXCLUSION: the mask is the primary member unless the complete
  original payload equals the primary, in which case the alternate member
  is emitted (a source equal to the alternate naturally receives the
  primary).  The mandatory invariant therefore holds for EVERY supported
  non-NULL logical payload:

      emitted_mask != original_payload

  No impossible substring guarantee is claimed — the invariant is about the
  COMPLETE logical value, and it is proven exhaustively by the adversarial
  regressions;
* the mask type is type-appropriate: a text payload is masked with a text
  (``str``) mask, a binary payload with a binary (``bytes``) mask, so the
  public writer's per-record binary-memo discriminator keeps the original
  block-kind semantics of the field;
* ``""`` and ``b""`` are legitimate non-NULL payloads: they are stored and
  masked exactly like any other payload and are never collapsed into NULL
  (the public writer/reader round-trips empty blocks distinctly from NULL
  pointers);
* the module is value-typed only: it never encodes, hashes, seeds or derives
  anything from a payload (no source-derived pseudonymization); the vault
  storage image is decided by the vault foundation in one place; ordinary
  output never INTENTIONALLY reproduces the original logical memo value,
  and original payload recovery remains exclusively in the protected vault.

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
    "MEMO_TEXT_MASK_ALT",
    "MEMO_BINARY_MASK_ALT",
    "MEMO_PAYLOAD_KIND_TEXT",
    "MEMO_PAYLOAD_KIND_BINARY",
    "is_memo_logical_value",
    "memo_payload_kind",
    "memo_safe_mask",
    "memo_requires_binary",
]

#: Versioned identity of the safe-mask policy (single authoritative
#: definition; the vault allocation service and the evidence tests bind it).
#: v1.1 adds deterministic self-exclusion: a source payload equal to one
#: vocabulary member is masked with the OTHER member, so the complete
#: supported non-NULL logical payload is never emitted unchanged.
MEMO_MASK_POLICY_VERSION = "1.1"

#: The primary TEXT safe mask (fixed, obviously synthetic ASCII token).
MEMO_TEXT_MASK: str = "[MASKED-MEMO]"

#: The alternate TEXT safe mask: emitted exactly when the complete original
#: text payload equals the primary mask, so the mask never equals its source.
MEMO_TEXT_MASK_ALT: str = "[MASKED-MEMO-ALT]"

#: The primary BINARY safe mask for General/Picture (and binary Memo)
#: payloads.
MEMO_BINARY_MASK: bytes = b"[MASKED-MEMO]"

#: The alternate BINARY safe mask: emitted exactly when the complete binary
#: payload equals the primary binary mask.
MEMO_BINARY_MASK_ALT: bytes = b"[MASKED-MEMO-ALT]"

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
    """The type-appropriate safe mask with self-exclusion, or ``None``.

    ``None`` preserves NULL identity (no mask, no recovery row).  A non-NULL
    payload receives the primary mask of its type, EXCEPT when the complete
    original payload equals that primary — then the alternate member is
    emitted, so ``emitted_mask != original_payload`` holds for every
    supported non-NULL logical payload (a source equal to the alternate
    naturally receives the primary).  ONE authoritative selection kernel;
    the vault allocation service delegates here.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return MEMO_TEXT_MASK_ALT if value == MEMO_TEXT_MASK else MEMO_TEXT_MASK
    if isinstance(value, (bytes, bytearray)):
        return (
            MEMO_BINARY_MASK_ALT
            if bytes(value) == MEMO_BINARY_MASK
            else MEMO_BINARY_MASK
        )
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