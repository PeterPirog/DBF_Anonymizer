"""Pure shared Date/DateTime transformation semantics (REQ-P2-008).

This module is the ONE authoritative model of the reversible temporal shift
for the two temporal DBF logical classes:

* ``D`` Date     — a ``datetime.date`` logical value;
* ``T`` DateTime — a ``datetime.datetime`` logical value.

The logical value vocabulary is EXACTLY the proven public ``dbfbridge``
Direct Read/Direct Write contract for these fields (probed empirically):
``None`` (NULL date), ``datetime.date`` and ``datetime.datetime``.  The
whole Python logical calendar range ``date(1, 1, 1) .. date(9999, 12, 31)``
round-trips through the public dependency; anything else — strings,
timestamps, epoch numbers, ``time`` objects, ``memoryview`` — is an UNSAFE
representation for which no safe logical transformation is proven: every
consumer MUST fail closed with a stable typed error instead of parsing
strings, converting epochs, inventing timezones or reading raw DBF bytes.

Semantics (immutable architecture baseline):

* NULL stays NULL: identity, no shift, no error;
* a ``date`` is shifted by the domain ``offset_days`` through its calendar
  ordinal (leap days, end-of-month and year crossings are handled by the
  exact ordinal arithmetic — never by string parsing);
* a ``datetime`` has ONLY its calendar-date component shifted; the
  hour/minute/second/microsecond (time-of-day) stays EXACTLY the same
  object value — no time-of-day offset, no DST/timezone invention;
* the domain-wide feasible integer offset interval keeps every shifted
  calendar date inside the proven logical range:

      lower_bound = LOGICAL_MIN_ORDINAL - min_observed_ordinal
      upper_bound = LOGICAL_MAX_ORDINAL - max_observed_ordinal

  so ``shift(B) - shift(A) == B - A`` for every two non-NULL values of one
  domain (the same constant offset preserves intervals by construction);
* recovery is the exact inverse shift: ``recovered = shifted - offset``;
  for a DateTime the unchanged time-of-day of the shifted object is kept.

The module is PURE: standard library only, no I/O, no vault access, no
``dbfbridge`` import and no randomness of its own.  It must therefore never
grow DBF parsing/writing, vault access or payload-bearing structures.
"""

from __future__ import annotations

from datetime import date, datetime

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError

__all__ = [
    "TEMPORAL_SHIFT_POLICY_VERSION",
    "TEMPORAL_FIELD_TYPES",
    "LOGICAL_MIN_ORDINAL",
    "LOGICAL_MAX_ORDINAL",
    "is_temporal_logical_value",
    "temporal_ordinal",
    "temporal_shift",
    "temporal_recover",
    "temporal_feasible_interval",
]

#: Versioned identity of the reversible temporal-shift policy (single
#: authoritative definition; the vault allocation service binds it).
TEMPORAL_SHIFT_POLICY_VERSION = "1.0"

#: Temporal-carrying DBF field types supported by this transformation.
TEMPORAL_FIELD_TYPES = frozenset({"D", "T"})

#: The proven logical calendar bounds of the public dbfbridge D/T contract
#: (verified empirically: ``date(1,1,1)`` .. ``date(9999,12,31)`` both
#: round-trip exactly through the public writer and reader).
LOGICAL_MIN_ORDINAL: int = date.min.toordinal()  # 1  (0001-01-01)
LOGICAL_MAX_ORDINAL: int = date.max.toordinal()  # 3652059 (9999-12-31)


def _unsupported() -> MappingError:
    """Stable typed failure for an unsafe temporal representation."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(
            operation="transform", detail_code="TEMPORAL_UNSUPPORTED_REPRESENTATION"
        ),
    )


def _zero_only_infeasible() -> MappingError:
    """Stable typed failure when only offset 0 would fit the whole domain."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(
            operation="transform", detail_code="TEMPORAL_ONLY_ZERO_FEASIBLE"
        ),
    )


def _out_of_range() -> MappingError:
    """Stable typed failure for a shift outside the proven logical range."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(
            operation="transform", detail_code="TEMPORAL_SHIFT_OUT_OF_RANGE"
        ),
    )


def is_temporal_logical_value(value: object) -> bool:
    """True exactly for the proven public vocabulary: ``None|date|datetime``."""
    return value is None or isinstance(value, (date, datetime))


def temporal_ordinal(value: object) -> int:
    """The calendar-date ordinal of one non-NULL temporal logical value.

    The bounded collection information of one temporal domain: Date and
    DateTime share the calendar-date level, so interval preservation is
    provable at ordinal granularity for both classes.
    """
    if isinstance(value, datetime):
        return value.toordinal()
    if isinstance(value, date):
        return value.toordinal()
    raise _unsupported()


def temporal_shift(value: object, offset_days: int) -> date | datetime | None:
    """Shift one logical temporal value by *offset_days* calendar days.

    ``None`` stays ``None``.  A ``datetime`` keeps its exact time-of-day
    (hour/minute/second/microsecond are untouched); only the calendar-date
    component moves.  An out-of-range shifted ordinal is an internal
    contract violation (the domain interval keeps every shift inside the
    logical range) and raises the typed refusal, never a bare
    ``OverflowError``/``ValueError``.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        ordinal = value.toordinal() + offset_days
        if not LOGICAL_MIN_ORDINAL <= ordinal <= LOGICAL_MAX_ORDINAL:
            raise _out_of_range()
        shifted_date = date.fromordinal(ordinal)
        return value.replace(year=shifted_date.year, month=shifted_date.month, day=shifted_date.day)
    if isinstance(value, date):
        ordinal = value.toordinal() + offset_days
        if not LOGICAL_MIN_ORDINAL <= ordinal <= LOGICAL_MAX_ORDINAL:
            raise _out_of_range()
        return date.fromordinal(ordinal)
    raise _unsupported()


def temporal_recover(value: object, offset_days: int) -> date | datetime | None:
    """The exact inverse shift (recovery): ``shifted - offset_days``.

    For a DateTime the unchanged time-of-day of the shifted object is
    preserved by the kernel; the calendar date returns to the original.
    """
    return temporal_shift(value, -offset_days)


def temporal_feasible_interval(
    min_observed_ordinal: int, max_observed_ordinal: int
) -> tuple[int, int]:
    """The domain-wide feasible integer offset interval ``[lower, upper]``.

    Every non-NULL calendar ordinal ``o`` of the domain must satisfy
    ``LOGICAL_MIN_ORDINAL <= o + offset <= LOGICAL_MAX_ORDINAL``; the
    feasible set for the WHOLE domain is the intersection over the observed
    extrema (interval mathematics, never a greedy per-value choice):

        lower = LOGICAL_MIN_ORDINAL - min_observed_ordinal
        upper = LOGICAL_MAX_ORDINAL - max_observed_ordinal
    """
    if min_observed_ordinal > max_observed_ordinal:
        raise ValueError("min observed ordinal must not exceed the max")
    return (
        LOGICAL_MIN_ORDINAL - min_observed_ordinal,
        LOGICAL_MAX_ORDINAL - max_observed_ordinal,
    )


def temporal_nonzero_count(lower: int, upper: int) -> int:
    """The number of feasible NON-ZERO integer offsets in ``[lower, upper]``."""
    total = upper - lower + 1
    if total <= 0:
        return 0
    return total - 1 if lower <= 0 <= upper else total


def temporal_offset_at(
    lower: int, upper: int, index: int
) -> int:
    """The *index*-th feasible NON-ZERO offset of ``[lower, upper]``.

    Uniform index semantics for the CSPRNG selection: the candidate order is
    the natural integer order with 0 skipped exactly when it lies inside the
    interval.  ``temporal_nonzero_count`` candidates exist; a request outside
    that range is an internal contract violation (never an offset).
    """
    count = temporal_nonzero_count(lower, upper)
    if not 0 <= index < count:
        raise _zero_only_infeasible()
    if lower <= 0 <= upper:
        # 0 lies inside: candidates are [lower..-1] then [1..upper].
        return lower + index if index < -lower else lower + index + 1
    return lower + index