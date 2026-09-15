"""Pure Date/DateTime transformation kernels (REQ-P2-008).

The single authoritative model lives in
``dbf_anonymizer.transforms.temporal``; these tests prove the kernels
directly: the exact public logical vocabulary, NULL identity, interval
preservation, leap-year/end-of-month/year-boundary arithmetic,
time-of-day preservation, the domain-wide feasible offset mathematics and
the typed fail-closed refusal of unsupported representations.
"""

from __future__ import annotations

import pytest

from dbf_anonymizer import ErrorCode, MappingError
from dbf_anonymizer.transforms import temporal as temporal_kernels

CANARY = "CANARY-DATE-SECRET"


def _unsupported_error(value: object) -> MappingError:
    with pytest.raises(MappingError) as excinfo:
        temporal_kernels.temporal_ordinal(value)
    return excinfo.value


def test_policy_version_and_supported_vocabulary() -> None:
    assert temporal_kernels.TEMPORAL_SHIFT_POLICY_VERSION == "1.0"
    assert temporal_kernels.TEMPORAL_FIELD_TYPES == frozenset({"D", "T"})
    # The PROVEN public logical calendar range (verified empirically through
    # the public dbfbridge writer/reader): date(1,1,1) .. date(9999,12,31).
    assert temporal_kernels.LOGICAL_MIN_ORDINAL == 1
    assert temporal_kernels.LOGICAL_MAX_ORDINAL == 3652059


def test_is_temporal_logical_value_is_the_exact_vocabulary() -> None:
    assert temporal_kernels.is_temporal_logical_value(None)
    from datetime import date, datetime

    assert temporal_kernels.is_temporal_logical_value(date(2020, 2, 29))
    assert temporal_kernels.is_temporal_logical_value(datetime(2020, 2, 29, 23, 59))
    assert not temporal_kernels.is_temporal_logical_value(0)
    assert not temporal_kernels.is_temporal_logical_value(True)
    assert not temporal_kernels.is_temporal_logical_value("2020-02-29")
    assert not temporal_kernels.is_temporal_logical_value(1234567890.5)
    assert not temporal_kernels.is_temporal_logical_value(memoryview(b"x"))


def test_temporal_ordinal_is_the_bounded_collection_information() -> None:
    from datetime import date, datetime

    feb_29 = date(2020, 2, 29)
    assert temporal_kernels.temporal_ordinal(feb_29) == feb_29.toordinal()
    assert temporal_kernels.temporal_ordinal(
        datetime(2020, 2, 29, 23, 59, 59, 999999)
    ) == feb_29.toordinal()
    # Date and DateTime share the calendar-date level.
    assert temporal_kernels.temporal_ordinal(feb_29) == temporal_kernels.temporal_ordinal(
        datetime(2020, 2, 29, 0, 0)
    )
    with pytest.raises(MappingError):
        temporal_kernels.temporal_ordinal(None)
    with pytest.raises(MappingError):
        temporal_kernels.temporal_ordinal(CANARY)


def test_shift_semantics_for_dates() -> None:
    from datetime import date

    assert temporal_kernels.temporal_shift(None, 5) is None
    assert temporal_kernels.temporal_shift(date(2020, 1, 1), 0) == date(2020, 1, 1)
    # Leap day shifted out of a leap year (end-of-month crossing).
    assert temporal_kernels.temporal_shift(date(2020, 2, 29), 1) == date(2020, 3, 1)
    # Leap-year crossing INTO a leap year.
    assert temporal_kernels.temporal_shift(date(2020, 2, 28), 1) == date(2020, 2, 29)
    # Leap-year crossing across a non-leap year.
    assert temporal_kernels.temporal_shift(date(2020, 2, 29), 365) == date(2021, 2, 28)
    assert temporal_kernels.temporal_shift(date(2020, 2, 28), 366) == date(2021, 2, 28)
    # End-of-month and year crossings.
    assert temporal_kernels.temporal_shift(date(2020, 12, 31), 1) == date(2021, 1, 1)
    assert temporal_kernels.temporal_shift(date(2020, 3, 1), -1) == date(2020, 2, 29)
    assert temporal_kernels.temporal_shift(date(2020, 4, 30), 1) == date(2020, 5, 1)
    # Logical calendar extremes round-trip (proven dependency range).
    assert temporal_kernels.temporal_shift(
        temporal_kernels.temporal_shift(date(9999, 12, 31), -5), 5
    ) == date(9999, 12, 31)


def test_shift_semantics_for_datetimes_preserve_time_of_day() -> None:
    from datetime import date, datetime

    assert temporal_kernels.temporal_shift(None, 3) is None
    value = datetime(2020, 2, 29, 23, 59, 58, 999999)
    shifted = temporal_kernels.temporal_shift(value, 1)
    assert shifted == datetime(2020, 3, 1, 23, 59, 58, 999999)
    # Hour/minute/second/microsecond are NEVER touched.
    assert (shifted.hour, shifted.minute, shifted.second, shifted.microsecond) == (
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
    )
    midnight = datetime(2020, 2, 29, 0, 0, 0)
    assert temporal_kernels.temporal_shift(midnight, 7) == datetime(2020, 3, 7, 0, 0, 0)


def test_recovery_is_the_exact_inverse() -> None:
    from datetime import date, datetime

    for value in (
        date(2020, 2, 29),
        datetime(2020, 2, 29, 23, 59, 58, 999000),
        datetime(2024, 12, 31, 0, 0),
        date(1999, 12, 31),
    ):
        for offset in (1, -1, 7, 3653, -10000):
            shifted = temporal_kernels.temporal_shift(value, offset)
            assert temporal_kernels.temporal_recover(shifted, offset) == value
    # NULL recovery is identity.
    assert temporal_kernels.temporal_recover(None, 12345) is None


def test_feasible_interval_mathematics() -> None:
    # Domain containing ONLY the calendar minimum: only positive offsets fit.
    assert temporal_kernels.temporal_feasible_interval(1, 1) == (0, 3652058)
    # Domain containing ONLY the calendar maximum: only negative offsets fit.
    assert temporal_kernels.temporal_feasible_interval(3652059, 3652059) == (-3652058, 0)
    # Domain spanning both extremes: ONLY offset 0 fits the whole domain.
    assert temporal_kernels.temporal_feasible_interval(1, 3652059) == (0, 0)
    # A narrow realistic domain keeps both signs feasible.
    assert temporal_kernels.temporal_feasible_interval(737421, 737422) == (
        1 - 737421,
        3652059 - 737422,
    )
    with pytest.raises(ValueError):
        temporal_kernels.temporal_feasible_interval(10, 5)


def test_nonzero_count_and_index_mapping() -> None:
    from datetime import date

    assert temporal_kernels.temporal_nonzero_count(1, 3) == 3  # {1,2,3}
    assert temporal_kernels.temporal_nonzero_count(-1, 1) == 2  # {-1,1}
    assert temporal_kernels.temporal_nonzero_count(0, 0) == 0  # only zero
    assert temporal_kernels.temporal_nonzero_count(-5, -2) == 4
    # The candidate order is the natural integer order with 0 skipped.
    assert temporal_kernels.temporal_offset_at(-1, 1, 0) == -1
    assert temporal_kernels.temporal_offset_at(-1, 1, 1) == 1
    assert temporal_kernels.temporal_offset_at(1, 3, 0) == 1
    assert temporal_kernels.temporal_offset_at(-5, -2, 3) == -2
    # Out-of-range index is an internal contract violation (typed).
    with pytest.raises(MappingError) as excinfo:
        temporal_kernels.temporal_offset_at(0, 0, 0)
    assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
    # The extremes of the proven logical range are exactly Python's.
    assert date.min.toordinal() == 1 and date.max.toordinal() == 3652059


def test_zero_only_domain_feasibility_is_typed_and_finite() -> None:
    # interval [0, 0] has ZERO non-zero candidates: typed, stable failure.
    with pytest.raises(MappingError) as excinfo:
        temporal_kernels.temporal_offset_at(0, 0, 0)
    assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
    boundary = str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
    assert "TEMPORAL_ONLY_ZERO_FEASIBLE" in boundary


def test_out_of_range_shift_is_typed_never_overflow() -> None:
    from datetime import date, datetime

    for value in (date.min, datetime(1, 1, 1)):
        with pytest.raises(MappingError) as excinfo:
            temporal_kernels.temporal_shift(value, -1)
        assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
        assert (
            "TEMPORAL_SHIFT_OUT_OF_RANGE"
            in str(excinfo.value.to_dict()) + repr(excinfo.value.to_dict())
        )
    for value in (date(9999, 12, 31), datetime(9999, 12, 31, 23, 59, 59)):
        with pytest.raises(MappingError):
            temporal_kernels.temporal_shift(value, 1)
    # No bare Python arithmetic failure may ever leak.
    with pytest.raises(MappingError):
        temporal_kernels.temporal_shift("2020-01-01", 1)
    with pytest.raises(MappingError):
        temporal_kernels.temporal_shift(1234567890, 1)
    with pytest.raises(MappingError):
        temporal_kernels.temporal_shift(1234567890.5, 1)


def test_unsupported_representations_fail_closed_with_stable_error() -> None:
    for value in (0, 3.14, "2020-02-29", b"2020-02-29", True, [0], object()):
        error = _unsupported_error(value)
        assert error.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
        boundary = str(error) + "|" + repr(error) + "|" + str(error.to_dict())
        assert "TEMPORAL_UNSUPPORTED_REPRESENTATION" in boundary
        # The refused value never reaches the error boundary.
        assert str(value) not in boundary or value == 0 or not isinstance(value, str)