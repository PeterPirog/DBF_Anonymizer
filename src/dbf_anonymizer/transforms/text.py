"""Pure shared text-domain pseudonym semantics (REQ-P2-004/005/006).

This module is the ONE authoritative mathematical model of the global text
mapping domain.  Both the source-read-only preflight capacity proof
(REQ-P1-006) and the allocating vault service (REQ-P2-004/005/006) derive
their decisions from the SAME kernels defined here:

* the conservative safe candidate alphabet — one single case, ASCII upper
  case letters and digits — filtered by ACTUAL single-byte encodability
  under every participating source encoding (``ch.encode(encoding)`` must
  yield exactly one byte; an encoding that cannot be proven this way yields
  an empty alphabet and every consumer MUST fail closed);
* the finite token space of the domain: ``base^1 + ... + base^w`` — every
  alphabet string with logical encoded length ``1..w``;
* the strictest-width reduction: the minimum logical byte-width constraint
  encountered across every occurrence of an original in any participating
  table/field (occurrence order never changes the result);
* exact index/token bijections used by the collision-safe CSPRNG allocation
  in :mod:`dbf_anonymizer.vault.text_allocation`.

Source identity is EXACT decoded Python string equality.  No strip/case/
Unicode/locale normalization exists anywhere in this model, so Varchar
significant trailing spaces remain identity-significant (``"ABC"``,
``"ABC "``, ``"ABC  "`` and ``"abc"`` are four distinct originals).

The module is PURE: standard library only, no I/O, no vault access, no
``dbfbridge`` import and no randomness of its own.  It must therefore never
grow DBF parsing/writing or weak-randomness behavior.
"""

from __future__ import annotations

from typing import Iterable

__all__ = [
    "TEXT_ALPHABET_POLICY_VERSION",
    "SAFE_TEXT_ALPHABET",
    "candidate_alphabet",
    "encoded_byte_length",
    "max_encoded_byte_length",
    "reduced_strictest",
    "token_space",
    "token_space_at_least",
    "token_index",
    "token_at",
    "is_safe_token",
]

#: Versioned identity of the safe-alphabet policy (single authoritative
#: definition; both the preflight proof and the allocation service carry it).
TEXT_ALPHABET_POLICY_VERSION = "1.0"

#: The conservative safe candidate alphabet: one single case, ASCII upper
#: case letters and digits, so case-insensitive collation ambiguity is not
#: introduced and every character is a plain single-byte ASCII codepoint in
#: every single-byte code page that can be PROVEN so.
SAFE_TEXT_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def candidate_alphabet(participating_encodings: Iterable[str]) -> str:
    """Intersect the conservative alphabet with single-byte codepoints.

    Keeps only characters that encode to exactly one byte under every
    participating source encoding.  A single case form is used so that
    case-insensitive collision ambiguity is not introduced.

    Provability is judged against the LIVE Python codec registry at call
    time — never against invented aliases.  The public ``dbfbridge`` boundary
    registers its custom code pages (Mazovia/PIAST) at operation time when a
    table schema or record stream is read, so the encoding names taken from
    the public ``dbfbridge`` schema are provable in the very process that
    read them.  An encoding that cannot be proven single-byte for a
    character — an unknown codec name, or a code page never established by
    the dependency — removes that character; if ANY participating encoding
    cannot be proven at all, the result is the empty string and every
    consumer of this model MUST fail closed instead of guessing.
    """
    keep: list[str] = []
    for character in SAFE_TEXT_ALPHABET:
        accepted = True
        for encoding in participating_encodings:
            try:
                if len(character.encode(encoding, "strict")) != 1:
                    accepted = False
                    break
            except (LookupError, UnicodeEncodeError, ValueError):
                accepted = False
                break
        if accepted:
            keep.append(character)
    return "".join(keep)


def encoded_byte_length(value: str, encoding: str) -> int | None:
    """The exact encoded byte length of *value* under *encoding*.

    Returns ``None`` when the encoding cannot be proven in the live codec
    registry (unknown codec name, unencodable character); consumers fail
    closed on ``None``.  The logical DBF field fit is judged by ACTUAL
    encoded bytes — never by the Python character count.
    """
    try:
        return len(value.encode(encoding, "strict"))
    except (LookupError, UnicodeEncodeError, ValueError):
        return None


def max_encoded_byte_length(value: str, encodings: Iterable[str]) -> int | None:
    """The largest encoded byte length of *value* across *encodings*.

    A candidate fits a field only when this conservative maximum is within
    the field's logical byte width for EVERY participating encoding.
    Returns ``None`` when any encoding cannot be proven.
    """
    largest: int | None = None
    for encoding in encodings:
        length = encoded_byte_length(value, encoding)
        if length is None:
            return None
        if largest is None or length > largest:
            largest = length
    return largest


def reduced_strictest(previous: int | None, width: int) -> int:
    """The strictest (minimum) logical byte width across occurrences.

    ``previous=None`` marks a first occurrence.  The result is independent
    of encounter order by construction.
    """
    if width < 0:
        raise ValueError("logical byte width must be non-negative")
    return width if previous is None else min(previous, width)


def token_space(max_width: int, base: int) -> int:
    """The EXACT number of alphabet tokens with encoded length ``1..max_width``.

    This is the same geometric token space the preflight proof streams with
    :func:`token_space_at_least`; allocation knows it exactly so truthful
    domain exhaustion can be distinguished from a random collision.
    """
    if max_width < 0:
        raise ValueError("max_width must be non-negative")
    if base < 1:
        raise ValueError("base must be positive")
    total = 0
    term = 1
    for _ in range(max_width):
        term *= base
        total += term
    return total


def token_space_at_least(max_width: int, base: int, needed: int) -> bool:
    """True when ``base^1 + ... + base^max_width >= needed``.

    Streams the geometric terms and stops as soon as *needed* is reached, so
    wide field lengths never build astronomically large integers.  The
    streamed predicate and the exact :func:`token_space` count are the same
    formula (cross-proven by the shared-semantics regression tests).
    """
    if max_width < 1 or base < 1:
        return needed <= 0
    total = 0
    term = 1
    for _ in range(max_width):
        term *= base
        total += term
        if total >= needed:
            return True
    return False


def is_safe_token(candidate: str, alphabet: str) -> bool:
    """True when *candidate* is a non-empty string over *alphabet* only."""
    if not candidate:
        return False
    return all(character in alphabet for character in candidate)


def token_index(token: str, alphabet: str) -> int:
    """The 0-based index of *token* inside the open-ended token space.

    Tokens of length ``l`` occupy the index block after all shorter tokens;
    the inverse of :func:`token_at` for ``len(token) <= max_width``.
    """
    base = len(alphabet)
    if not is_safe_token(token, alphabet):
        raise ValueError("token must be a non-empty string over the alphabet")
    cumulative = 0
    term = 1
    for _ in range(1, len(token)):
        term *= base
        cumulative += term
    offset = 0
    for character in token:
        offset = offset * base + alphabet.index(character)
    return cumulative + offset


def token_at(index: int, max_width: int, alphabet: str) -> str:
    """The token at *index* of the finite token space ``1..max_width``.

    Exact bijection (the inverse of :func:`token_index` for indices below
    :func:`token_space`): shorter lengths come first, then fixed-length
    blocks in conservative alphabet order.
    """
    base = len(alphabet)
    if base < 1:
        raise ValueError("alphabet must not be empty")
    if not 0 <= index < token_space(max_width, base):
        raise ValueError("token index is outside the admissible token space")
    cumulative = 0
    term = 1
    for length in range(1, max_width + 1):
        term *= base
        if index < cumulative + term:
            offset = index - cumulative
            digits: list[str] = []
            for _ in range(length):
                digits.append(alphabet[offset % base])
                offset //= base
            return "".join(reversed(digits))
        cumulative += term
    raise ValueError("token index is outside the admissible token space")