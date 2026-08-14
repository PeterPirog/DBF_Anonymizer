"""Testy modułu transforms — per-type transformacje i odwrotności."""
from __future__ import annotations

import datetime as dt

from dbf_anonymizer.transforms import (
    _byte_len_cp1250,
    identity,
    mask_char,
    mask_memo,
    recover_date,
    recover_datetime,
    recover_identity,
    shift_date,
    shift_datetime,
)


class TestMaskChar:
    def test_same_byte_length_ascii(self):
        original = "Jan Kowalski"
        masked = mask_char(original, length=20, salt="s1")
        assert _byte_len_cp1250(masked) == _byte_len_cp1250(original)

    def test_same_byte_length_polish(self):
        original = "Zażółć gęślą jaźń"
        masked = mask_char(original, length=20, salt="s2")
        # długość bajtowa cp1250 dla polskich znaków > długość znakowa
        assert _byte_len_cp1250(masked) == _byte_len_cp1250(original)

    def test_deterministic_same_salt(self):
        v = "TestValue"
        m1 = mask_char(v, length=20, salt="abc")
        m2 = mask_char(v, length=20, salt="abc")
        assert m1 == m2

    def test_different_salt_different_mask(self):
        v = "TestValue"
        m1 = mask_char(v, length=20, salt="abc")
        m2 = mask_char(v, length=20, salt="xyz")
        assert m1 != m2

    def test_empty_and_none(self):
        assert mask_char("", length=10, salt="x") == ""
        assert mask_char(None, length=10, salt="x") is None

    def test_different_values_different_mask(self):
        m1 = mask_char("AAA", length=10, salt="s")
        m2 = mask_char("BBB", length=10, salt="s")
        assert m1 != m2


class TestMaskMemo:
    def test_mask_mode(self):
        assert mask_memo("secret content", mode="mask") == "MEMO"
        assert mask_memo("anything", mode="mask") == "MEMO"

    def test_keep_mode(self):
        assert mask_memo("secret content", mode="keep") == "secret content"

    def test_none(self):
        assert mask_memo(None, mode="mask") is None
        assert mask_memo(None, mode="keep") is None


class TestDateShift:
    def test_zero_offset_no_change(self):
        d = "1980-05-12"
        assert shift_date(d, offset_days=0) == d

    def test_positive_offset(self):
        assert shift_date("1980-05-12", offset_days=10) == "1980-05-22"

    def test_negative_offset(self):
        assert shift_date("1980-05-12", offset_days=-10) == "1980-05-02"

    def test_none(self):
        assert shift_date(None, offset_days=10) is None
        assert shift_date("", offset_days=10) is None

    def test_recover_date(self):
        original = "1980-05-12"
        shifted = shift_date(original, offset_days=30)
        recovered = recover_date(shifted, offset_days=30)
        assert recovered == original

    def test_datetime_shift_preserves_time(self):
        original = "2024-01-15T10:30:00"
        shifted = shift_datetime(original, offset_days=5)
        assert shifted == "2024-01-20T10:30:00"

    def test_recover_datetime(self):
        original = "2024-01-15T10:30:00"
        shifted = shift_datetime(original, offset_days=5)
        recovered = recover_datetime(shifted, offset_days=5)
        assert recovered == original


class TestIdentity:
    def test_identity(self):
        assert identity(42) == 42
        assert identity(3.14) == 3.14
        assert identity(True) is True

    def test_recover_identity(self):
        assert recover_identity(42) == 42
