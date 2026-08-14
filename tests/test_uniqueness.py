"""Testy modułu uniqueness — detekcja unikalnych kolumn i bijekcja."""
from __future__ import annotations

from dbf_anonymizer.transforms import _byte_len_cp1250
from dbf_anonymizer.uniqueness import (
    build_column_mapping,
    detect_unique_columns,
)


def _records(name_col: list[str]) -> list[dict]:
    return [{"NAME": v} for v in name_col]


class TestDetectUnique:
    def test_all_unique(self):
        recs = _records(["AAA", "BBB", "CCC"])
        result = detect_unique_columns(recs, ["NAME"])
        assert result["NAME"] is True

    def test_duplicates(self):
        recs = _records(["AAA", "BBB", "AAA"])
        result = detect_unique_columns(recs, ["NAME"])
        assert result["NAME"] is False

    def test_empty_values_ignored(self):
        recs = [{"NAME": "AAA"}, {"NAME": ""}, {"NAME": "CCC"}]
        result = detect_unique_columns(recs, ["NAME"])
        assert result["NAME"] is True

    def test_all_empty(self):
        recs = _records(["", "", ""])
        result = detect_unique_columns(recs, ["NAME"])
        assert result["NAME"] is False

    def test_none_values(self):
        recs = [{"NAME": "AAA"}, {"NAME": None}, {"NAME": "CCC"}]
        result = detect_unique_columns(recs, ["NAME"])
        assert result["NAME"] is True


class TestBuildMapping:
    def test_unique_column_bijection(self):
        recs = _records(["AAA", "BBB", "CCC"])
        mapping = build_column_mapping("NAME", recs, length=10, unique=True, salt="s")
        assert len(mapping.forward) == 3
        # anonimy są unikalne
        anons = list(mapping.forward.values())
        assert len(set(anons)) == 3

    def test_same_byte_length(self):
        recs = _records(["Jan", "Anna", "Piotr"])
        mapping = build_column_mapping("NAME", recs, length=10, unique=True, salt="s")
        for orig, anon in mapping.forward.items():
            assert _byte_len_cp1250(anon) == _byte_len_cp1250(orig)

    def test_non_unique_1to1(self):
        recs = _records(["AAA", "BBB", "AAA", "CCC", "AAA"])
        mapping = build_column_mapping("NAME", recs, length=10, unique=False, salt="s")
        # 3 unikalne wartości → 3 anonimy
        assert len(mapping.forward) == 3
        # ten sam oryginał → ten sam anonim
        assert mapping.forward["AAA"] == mapping.forward["AAA"]

    def test_polish_chars_byte_length(self):
        recs = _records(["Żółw", "Gęś", "Jaźń"])
        mapping = build_column_mapping("NAME", recs, length=10, unique=True, salt="s")
        for orig, anon in mapping.forward.items():
            assert _byte_len_cp1250(anon) == _byte_len_cp1250(orig)

    def test_empty_values_skipped(self):
        recs = [{"NAME": "AAA"}, {"NAME": ""}, {"NAME": "BBB"}]
        mapping = build_column_mapping("NAME", recs, length=10, unique=True, salt="s")
        # tylko 2 niepuste wartości w mapowaniu
        assert len(mapping.forward) == 2
        assert "AAA" in mapping.forward
        assert "BBB" in mapping.forward
