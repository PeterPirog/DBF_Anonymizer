"""Pure numeric key-domain kernels (REQ-P3-004/005).

The ONE authoritative PURE model of declared numeric key domains: canonical
reversible value representation, representable ranges, and the exact
feasibility/selection arithmetic of a bounded bijection.  This module performs
no I/O, opens no file, imports no ``dbfbridge`` namespace, touches no vault
state and draws no randomness — the CSPRNG-backed allocation service is
:mod:`dbf_anonymizer.vault.numeric_allocation`, a consumer of these kernels.

Verified public dbfbridge 1.1.0 facts this model encodes (never guessed):

* an Integer (``I``) value is a signed 32-bit little-endian integer read as a
  Python ``int`` in ``[-2**31, 2**31 - 1]`` (NULL only through the VFP
  ``_NullFlags`` bitmap);
* the public Direct Write boundary REFUSES both ``-2**31`` and ``2**31 - 1``
  for an ``I`` field (typed overflow failure), so the WRITABLE pseudonym
  range of an Integer member is ``[-2**31 + 1, 2**31 - 2]``;
* an integral Numeric (``N(width, 0)``) field stores values whose canonical
  fixed-point rendering fits *width* characters: positive values up to
  ``10**width - 1`` and negative values down to ``-(10**(width-1) - 1)``
  (a one-character Numeric cannot hold any negative value);
* VFP autoincrement is derived from the field-flags mask on Integer fields by
  the public schema and is NEVER a supported numeric-key domain here.

Canonical value representation inside the vault (bounded TEXT, one form):

* canonical signed decimal integer: ``0`` is the canonical zero, no ``+``
  sign, no leading zeros, no locale dependence, no scientific notation,
  no float involvement and no NaN/Infinity; booleans are rejected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

__all__ = [
    "INTEGER_KEY_ORIGINAL_LOW",
    "INTEGER_KEY_ORIGINAL_HIGH",
    "INTEGER_KEY_WRITABLE_LOW",
    "INTEGER_KEY_WRITABLE_HIGH",
    "NUMERIC_KEY_MAX_WIDTH",
    "canonical_integer_text",
    "parse_canonical_integer_text",
    "integer_original_range",
    "integer_readable_original_range",
    "integer_writable_pseudonym_range",
    "integral_numeric_range",
    "intersect_ranges",
    "range_contains",
    "NumericKeyMemberRange",
    "NumericKeyDomain",
    "integer_member",
    "integral_numeric_member",
    "numeric_key_domain_for",
    "free_token_count",
    "selectable_token_count",
    "jth_free_token",
    "plan_numeric_bijection",
]

#: The verified readable original domain of a signed VFP Integer field.
INTEGER_KEY_ORIGINAL_LOW = -(2**31)
INTEGER_KEY_ORIGINAL_HIGH = 2**31 - 1

#: The verified WRITABLE pseudonym range of an Integer member through the
#: public Direct Write boundary (both int32 extremes are refused there).
INTEGER_KEY_WRITABLE_LOW = INTEGER_KEY_ORIGINAL_LOW + 1
INTEGER_KEY_WRITABLE_HIGH = INTEGER_KEY_ORIGINAL_HIGH - 1

#: The maximum Numeric field width the public Direct Write contract accepts.
NUMERIC_KEY_MAX_WIDTH = 20

_CANONICAL_INTEGER = re.compile(r"\A(?:0|-?[1-9][0-9]*)\Z")


def canonical_integer_text(value: object) -> str:
    """The canonical reversible text of one exact integer key value.

    Accepts only a genuine ``int`` (never ``bool``, never float, never
    ``Decimal``): ``0`` is the canonical zero, negative values carry exactly
    one leading ``-``, no leading zeros and no ``+`` sign exist, and the
    representation is locale-independent.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("an exact integer key value must be an int (never bool/float)")
    return str(value)


def parse_canonical_integer_text(text: object) -> int:
    """Parse one canonical integer text into its exact ``int`` value.

    Strictly bounded: only ``0``, ``-0``-free negatives and positive integers
    without leading zeros are canonical; ``+5``, ``007``, ``-0``, `` 5``,
    ``1.0``, ``1e3``, ``NaN`` and ``Infinity`` are refused (typed
    ``ValueError``), and booleans are refused as integers.
    """
    if isinstance(text, bool) or not isinstance(text, str):
        raise TypeError("a canonical integer key value must be text")
    if not _CANONICAL_INTEGER.match(text):
        raise ValueError("value is not a canonical integer representation")
    return int(text)


def integer_original_range() -> tuple[int, int]:
    """The verified readable original range of a signed VFP Integer key."""
    return (INTEGER_KEY_ORIGINAL_LOW, INTEGER_KEY_ORIGINAL_HIGH)


def integer_writable_pseudonym_range() -> tuple[int, int]:
    """The verified writable pseudonym range of an Integer member.

    Both int32 extremes are refused by the public Direct Write boundary, so
    no pseudonym may ever be one of them.
    """
    return (INTEGER_KEY_WRITABLE_LOW, INTEGER_KEY_WRITABLE_HIGH)


def integral_numeric_range(width: int) -> tuple[int, int]:
    """The verified writable range of an integral ``N(width, 0)`` key field.

    A value fits exactly when its canonical decimal rendering (with the
    leading ``-`` for negatives) fits *width* characters; a one-character
    Numeric therefore cannot hold any negative value.  The width must be a
    genuine ``int`` in ``1..20`` (the public writer limit) — never ``bool``.
    """
    if isinstance(width, bool) or not isinstance(width, int):
        raise TypeError("integral numeric width must be an int")
    if not 1 <= width <= NUMERIC_KEY_MAX_WIDTH:
        raise ValueError("integral numeric key width must be between 1 and 20")
    return (-(10 ** (width - 1) - 1), 10**width - 1)


def intersect_ranges(
    ranges: Sequence[tuple[int, int]],
) -> tuple[int, int] | None:
    """The intersection of closed integer ranges, or ``None`` when empty."""
    if not ranges:
        return None
    low = max(low for low, _high in ranges)
    high = min(high for _low, high in ranges)
    if low > high:
        return None
    return (low, high)


@dataclass(frozen=True)
class NumericKeyMemberRange:
    """The verified representation facts of ONE participating member field.

    ``original_low``/``original_high`` is the member's verified READABLE
    original range (what the public direct read can decode for its field
    type); ``pseudonym_low``/``pseudonym_high`` is the member's verified
    WRITABLE range (what the public Direct Write boundary accepts, the
    strictest representation a pseudonym of this member can take).
    """

    original_low: int
    original_high: int
    pseudonym_low: int
    pseudonym_high: int

    @property
    def original_range(self) -> tuple[int, int]:
        return (self.original_low, self.original_high)

    @property
    def pseudonym_range(self) -> tuple[int, int]:
        return (self.pseudonym_low, self.pseudonym_high)

    def contains_original(self, value: int) -> bool:
        return self.original_low <= value <= self.original_high


@dataclass(frozen=True)
class NumericKeyDomain:
    """The bounded representable domain of ONE numeric key domain.

    ``pseudonym_low``/``pseudonym_high`` is the intersection of the WRITABLE
    ranges of every member — the strictest participating representation every
    pseudonym must fit (range/width/sign preservation, never truncation);
    ``members`` carries the verified per-member original/pseudonym ranges.
    """

    pseudonym_low: int
    pseudonym_high: int
    members: tuple[NumericKeyMemberRange, ...]

    @property
    def size(self) -> int:
        """The number of representable pseudonym tokens (Python ints; no overflow)."""
        return self.pseudonym_high - self.pseudonym_low + 1

    def contains_pseudonym(self, value: int) -> bool:
        return self.pseudonym_low <= value <= self.pseudonym_high

    @property
    def pseudonym_range(self) -> tuple[int, int]:
        """The strictest participating WRITABLE pseudonym range."""
        return (self.pseudonym_low, self.pseudonym_high)

    @property
    def member_ranges(self) -> tuple[tuple[int, int], ...]:
        """The members' WRITABLE pseudonym ranges (strictest-representation view)."""
        return tuple(member.pseudonym_range for member in self.members)

    @property
    def member_original_ranges(self) -> tuple[tuple[int, int], ...]:
        """The members' readable ORIGINAL ranges."""
        return tuple(member.original_range for member in self.members)


def integer_member() -> NumericKeyMemberRange:
    """The verified member representation facts of a reversible VFP Integer key.

    Recovery truthfulness (REQ-P3-005): a REVERSIBLE mapping must be able to
    write the pseudonymized value back through the public Direct Write
    boundary, and the SAME public writer must later be able to reconstruct
    the ORIGINAL during recovery.  The pinned ``dbfbridge[write]==1.1.0``
    boundary refuses both int32 extremes (typed write failure), so a
    reversible Integer member's ORIGINAL range is the verified WRITABLE
    sub-range: an original Integer value outside it (readable, but not
    reconstructable by the only architecture-permitted writer) must fail
    closed BEFORE publication
    (``NUMERIC_KEY_RECOVERY_UNWRITABLE``).  The full readable int32 facts
    remain :data:`INTEGER_KEY_ORIGINAL_LOW`/:data:`INTEGER_KEY_ORIGINAL_HIGH`
    and :func:`integer_original_range` for the identity path and diagnostics.
    """
    return NumericKeyMemberRange(
        original_low=INTEGER_KEY_WRITABLE_LOW,
        original_high=INTEGER_KEY_WRITABLE_HIGH,
        pseudonym_low=INTEGER_KEY_WRITABLE_LOW,
        pseudonym_high=INTEGER_KEY_WRITABLE_HIGH,
    )


def integer_readable_original_range() -> tuple[int, int]:
    """The verified READABLE original range of a signed VFP Integer field.

    This is the full signed 32-bit decoding range of the public direct read.
    It is NOT the reversible-mapping member range: the two int32 extremes are
    readable but not reconstructable through the pinned public Direct Write
    boundary (see :func:`integer_member`).
    """
    return (INTEGER_KEY_ORIGINAL_LOW, INTEGER_KEY_ORIGINAL_HIGH)


def integral_numeric_member(width: int) -> NumericKeyMemberRange:
    """The verified member representation facts of an integral ``N(w, 0)`` key.

    For an integral Numeric field the readable and writable ranges coincide:
    a value fits exactly when its canonical decimal rendering fits the
    declared width (never truncated, never silently rounded).
    """
    low, high = integral_numeric_range(width)
    return NumericKeyMemberRange(
        original_low=low,
        original_high=high,
        pseudonym_low=low,
        pseudonym_high=high,
    )


def numeric_key_domain_for(
    members: Sequence[NumericKeyMemberRange],
) -> NumericKeyDomain:
    """Resolve the ONE shared candidate domain of a numeric key relation.

    The shared candidate domain is the exact intersection of the members'
    WRITABLE pseudonym ranges.  An empty intersection is an impossible
    capacity/range constraint and fails closed with the typed ``ValueError``
    contract of this pure kernel.
    """
    if not members:
        raise ValueError("a numeric key domain requires at least one member range")
    intersection = intersect_ranges([member.pseudonym_range for member in members])
    if intersection is None:
        raise ValueError("the participating member ranges have no common representable value")
    return NumericKeyDomain(
        pseudonym_low=intersection[0],
        pseudonym_high=intersection[1],
        members=tuple(members),
    )


def free_token_count(domain: NumericKeyDomain, occupied: Sequence[int]) -> int:
    """The exact number of free tokens of *domain* (bounded arithmetic only).

    Consistency contract with :func:`jth_free_token`: only UNIQUE occupied
    token values INSIDE the domain consume capacity; blocked values below or
    above ``pseudonym_low..pseudonym_high`` never consume capacity and
    duplicates never double-count.
    """
    in_domain = {
        value for value in occupied if domain.contains_pseudonym(value)
    }
    return domain.size - len(in_domain)


def selectable_token_count(domain: NumericKeyDomain, blocked: Sequence[int]) -> int:
    """The exact number of selectable free tokens of *domain*.

    Identical to :func:`free_token_count` — the two kernels agree on the
    number of selectable tokens by construction.
    """
    return free_token_count(domain, blocked)


def jth_free_token(domain: NumericKeyDomain, blocked: Sequence[int], j: int) -> int:
    """The ``j``-th free token of *domain* (0-based, ascending order).

    ``blocked`` holds UNIQUE occupied token values. The selection walks the
    sorted blocked values and their gaps — it never materializes the token
    universe (which is 2**32 for a full Integer domain), so the computation
    is bounded by the number of blocked tokens, not by the domain size.
    """
    if j < 0:
        raise ValueError("the requested free-token index must be non-negative")
    previous = domain.pseudonym_low - 1
    remaining = j
    for value in sorted(set(blocked)):
        if value < domain.pseudonym_low or value > domain.pseudonym_high:
            continue  # outside this domain: never blocks it
        gap = value - previous - 1
        if remaining < gap:
            return previous + 1 + remaining
        remaining -= gap
        previous = value
    result = previous + 1 + remaining
    if result > domain.pseudonym_high:
        raise ValueError("the requested free-token index exceeds the domain capacity")
    return result


def plan_numeric_bijection(
    domain: NumericKeyDomain,
    unpersisted_originals: Sequence[int],
    occupied_pseudonyms: Sequence[int],
) -> bool:
    """The exact feasibility proof of the residual allocation problem.

    Every unpersisted original receives a distinct free pseudonym token of
    the shared domain and may never receive its own value (self-exclusion —
    which applies exactly when the original's own value is itself a
    representable token of the pseudonym domain).  For this flat, fully
    fungible domain (each original forbids at most one token — its own
    value) Hall's condition reduces to the two EXACT deterministic
    requirements:

    * the free token count covers every unpersisted original; and
    * every original keeps at least one allowed token: when its own value is
      itself still free inside the domain, the domain must retain a second
      free token for it.

    A single available self-token with self-exclusion therefore fails closed
    (no derangement exists), while a two-token domain with two originals is
    feasible through the swap.  The result is deterministic, needs no
    materialization of the token universe and reports capacity truthfully.
    """
    blocked = {
        value for value in occupied_pseudonyms if domain.contains_pseudonym(value)
    }
    originals = list(unpersisted_originals)
    distinct = set(originals)
    if len(distinct) != len(originals):
        raise ValueError("unpersisted originals must be distinct")
    for value in distinct:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("numeric key originals must be exact ints")
    free = domain.size - len(blocked)
    if free < len(distinct):
        return False
    for value in distinct:
        allowed = free
        if domain.contains_pseudonym(value) and value not in blocked:
            # The original's own value is a free token of the domain and is
            # forbidden for this original (self-exclusion).
            allowed -= 1
        if allowed < 1:
            return False
    return True