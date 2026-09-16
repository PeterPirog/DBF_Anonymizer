"""Numeric key-domain kernels: canonical representation, ranges, feasibility.

REQ-P3-005 evidence for the PURE transformation kernel
(:mod:`dbf_anonymizer.transforms.numeric_keys`): the ONE canonical reversible
representation, the verified representable ranges (including the public
writer boundary facts), the exact feasibility proof and the bounded-memory
free-token selection over the full Integer universe.
"""

from __future__ import annotations

import pytest

from dbf_anonymizer.transforms.numeric_keys import (
    INTEGER_KEY_ORIGINAL_HIGH,
    INTEGER_KEY_ORIGINAL_LOW,
    INTEGER_KEY_WRITABLE_HIGH,
    INTEGER_KEY_WRITABLE_LOW,
    NUMERIC_KEY_MAX_WIDTH,
    NumericKeyDomain,
    canonical_integer_text,
    free_token_count,
    integer_member,
    integer_original_range,
    integer_writable_pseudonym_range,
    integral_numeric_member,
    integral_numeric_range,
    intersect_ranges,
    jth_free_token,
    numeric_key_domain_for,
    parse_canonical_integer_text,
    plan_numeric_bijection,
)


# ---------------------------------------------------------------------------
# canonical reversible representation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0"),
        (7, "7"),
        (-7, "-7"),
        (10, "10"),
        (-10, "-10"),
        (2147483647, "2147483647"),
        (-2147483648, "-2147483648"),
        (99999999999, "99999999999"),
    ],
)
def test_canonical_integer_text_form(value: int, expected: str) -> None:
    assert canonical_integer_text(value) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0", 0),
        ("7", 7),
        ("-7", -7),
        ("10", 10),
        ("-2147483648", -2147483648),
        ("2147483647", 2147483647),
    ],
)
def test_parse_canonical_integer_text_round_trip(text: str, expected: int) -> None:
    assert parse_canonical_integer_text(text) == expected
    assert canonical_integer_text(parse_canonical_integer_text(text)) == text


@pytest.mark.parametrize(
    "invalid",
    ["+5", "007", "-0", " 5", "5 ", "", "-00", "1.0", "1e3", "NaN", "Infinity", "-Infinity", "0x10"],
)
def test_parse_canonical_integer_text_rejects_malformed_text(invalid: str) -> None:
    with pytest.raises(ValueError):
        parse_canonical_integer_text(invalid)


def test_canonical_representation_rejects_bools_and_floats() -> None:
    with pytest.raises(TypeError):
        canonical_integer_text(True)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        canonical_integer_text(False)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        canonical_integer_text(1.0)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        parse_canonical_integer_text(True)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        parse_canonical_integer_text(7)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# verified representable ranges (public dbfbridge 1.1.0 facts)
# ---------------------------------------------------------------------------
def test_integer_member_ranges_match_the_verified_public_boundary() -> None:
    assert integer_original_range() == (-(2**31), 2**31 - 1)
    assert integer_writable_pseudonym_range() == (-(2**31) + 1, 2**31 - 2)
    member = integer_member()
    assert member.original_range == integer_original_range()
    assert member.pseudonym_range == integer_writable_pseudonym_range()


@pytest.mark.parametrize(
    ("width", "expected"),
    [
        (1, (0, 9)),
        (2, (-9, 99)),
        (5, (-9999, 99999)),
        (8, (-9999999, 99999999)),
    ],
)
def test_integral_numeric_range_formula(width: int, expected: tuple[int, int]) -> None:
    assert integral_numeric_range(width) == expected


def test_integral_numeric_width_bounds_are_verified_contract() -> None:
    with pytest.raises(ValueError):
        integral_numeric_range(0)
    with pytest.raises(ValueError):
        integral_numeric_range(NUMERIC_KEY_MAX_WIDTH + 1)
    with pytest.raises(TypeError):
        integral_numeric_range(True)  # type: ignore[arg-type]


def test_numeric_domain_is_the_intersection_of_member_writable_ranges() -> None:
    domain = numeric_key_domain_for(
        [integer_member(), integral_numeric_member(5)]
    )
    assert domain.member_ranges == ((-(2**31) + 1, 2**31 - 2), (-9999, 99999))
    assert domain.pseudonym_range == (-9999, 99999)
    assert domain.member_original_ranges == ((-(2**31), 2**31 - 1), (-9999, 99999))
    # Differing compatible widths across tables: N(8) and N(5) intersect.
    narrowed = numeric_key_domain_for(
        [integral_numeric_member(8), integral_numeric_member(5)]
    )
    assert narrowed.pseudonym_range == (-9999, 99999)


def test_impossible_range_intersection_fails_closed() -> None:
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyMemberRange

    negative_only = NumericKeyMemberRange(
        original_low=-1, original_high=-1, pseudonym_low=-1, pseudonym_high=-1
    )
    positive_only = integral_numeric_member(1)
    with pytest.raises(ValueError):
        numeric_key_domain_for([negative_only, positive_only])
    with pytest.raises(ValueError):
        numeric_key_domain_for([])


def test_integer_domain_size_is_exact_and_never_materialized() -> None:
    domain = numeric_key_domain_for([integer_member()])
    assert domain.size == 2**32 - 2
    # Bounded arithmetic only: the selection kernel never enumerates the
    # token universe (the walk below touches a single blocked token).
    assert jth_free_token(domain, [0, 1], 0) == -2147483647
    assert jth_free_token(domain, [], 0) == INTEGER_KEY_WRITABLE_LOW


# ---------------------------------------------------------------------------
# exact feasibility proof
# ---------------------------------------------------------------------------
def test_feasible_domain_allocates_the_full_mapping() -> None:
    domain = numeric_key_domain_for([integral_numeric_member(2)])
    assert plan_numeric_bijection(domain, [-9, 0, 99, 5], []) is True


def test_exhausted_domain_fails_closed() -> None:
    # N(2,0) holds exactly 109 representable tokens (-9..99); 110 distinct
    # originals can never receive distinct pseudonyms.
    domain = numeric_key_domain_for([integral_numeric_member(2)])
    originals = list(range(-9, 101))  # 110 values (one beyond the capacity)
    assert len(originals) == 110 > domain.size
    assert plan_numeric_bijection(domain, originals, []) is False


def test_boundary_negative_and_positive_values_are_safe() -> None:
    domain = numeric_key_domain_for([integral_numeric_member(5)])
    assert plan_numeric_bijection(domain, [-9999, 99999, 0], []) is True


def test_single_self_token_with_self_exclusion_fails_closed() -> None:
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyMemberRange

    # A domain with exactly one token [5, 5] whose only original is 5: the
    # single available token is the original's own value and self-exclusion
    # leaves no alternative -> fail closed.
    domain = NumericKeyDomain(pseudonym_low=5, pseudonym_high=5, members=(
        NumericKeyMemberRange(5, 5, 5, 5),
    ))
    assert plan_numeric_bijection(domain, [5], []) is False


def test_two_token_domain_with_two_originals_is_feasible_through_the_swap() -> None:
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyMemberRange

    domain = NumericKeyDomain(pseudonym_low=1, pseudonym_high=2, members=(
        NumericKeyMemberRange(1, 2, 1, 2),
    ))
    assert plan_numeric_bijection(domain, [1, 2], []) is True


def test_single_original_outside_the_pseudonym_domain_needs_one_free_token() -> None:
    # An Integer extreme original is readable but outside the WRITABLE
    # pseudonym domain; it still requires one free token (self-exclusion is
    # automatically satisfied because its own value is not a token).
    domain = numeric_key_domain_for([integer_member()])
    assert domain.contains_pseudonym(2**31 - 1) is False
    assert plan_numeric_bijection(domain, [2**31 - 1], []) is True
    assert plan_numeric_bijection(domain, [-(2**31)], []) is True


def test_feasibility_accounts_for_persisted_occupied_tokens() -> None:
    domain = numeric_key_domain_for([integral_numeric_member(2)])  # -9..99
    # 108 occupied tokens leave exactly one free token; a single remaining
    # original whose own value is that last free token fails closed.
    occupied = [value for value in range(-9, 100) if value not in {50}]
    assert plan_numeric_bijection(domain, [50], occupied) is False
    # The same occupied set leaves room for an original outside the domain's
    # self-exclusion conflict (its own value is occupied).
    assert plan_numeric_bijection(domain, [-9], occupied) is True


# ---------------------------------------------------------------------------
# bounded-memory free-token selection
# ---------------------------------------------------------------------------
def test_jth_free_token_walks_blocked_tokens_only() -> None:
    # A small exact domain: N(2,0) spans -9..99; blocked = [-9, 0, 3] leaves
    # the free sequence -8, -7, -6, -5, -4, -3, -2, -1, 1, 2, ...
    domain = numeric_key_domain_for([integral_numeric_member(2)])
    blocked = [-9, 0, 3]
    assert jth_free_token(domain, blocked, 0) == -8
    assert jth_free_token(domain, blocked, 4) == -4
    assert jth_free_token(domain, blocked, 5) == -3
    assert jth_free_token(domain, blocked, 7) == -1
    assert jth_free_token(domain, blocked, 8) == 1
    with pytest.raises(ValueError):
        jth_free_token(domain, blocked, domain.size - len(set(blocked)))
    with pytest.raises(ValueError):
        jth_free_token(domain, blocked, -1)


def test_jth_free_token_ignores_blocked_tokens_outside_the_domain() -> None:
    domain = numeric_key_domain_for([integral_numeric_member(5)])
    # Blocked values beyond the domain never block it.
    assert jth_free_token(domain, [10**30, domain.pseudonym_high + 1], 0) == -9999


def test_free_token_count_is_exact() -> None:
    domain = numeric_key_domain_for([integral_numeric_member(2)])  # 109 tokens
    assert free_token_count(domain, []) == 109
    assert free_token_count(domain, [-9, 0, 0, 99]) == 106


def test_full_integer_domain_selection_never_overflows() -> None:
    domain = numeric_key_domain_for([integer_member()])
    # The exact completion over the full 2**32-2 token universe with a few
    # blocked tokens stays inside the domain bounds (no wraparound).
    first = jth_free_token(domain, [], 0)
    last = jth_free_token(domain, [], domain.size - 1)
    assert first == INTEGER_KEY_WRITABLE_LOW
    assert last == INTEGER_KEY_WRITABLE_HIGH
    assert INTEGER_KEY_ORIGINAL_LOW <= last <= INTEGER_KEY_ORIGINAL_HIGH


def test_domain_rejects_bool_and_float_originals() -> None:
    domain = numeric_key_domain_for([integral_numeric_member(5)])
    with pytest.raises(TypeError):
        plan_numeric_bijection(domain, [True], [])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        plan_numeric_bijection(domain, [1.0], [])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        plan_numeric_bijection(domain, [5, 5], [])