"""Testy pipeline — round-trip anonimizacja + recovery na fixture DBF.

Kluczowy test: self_test weryfikuje, że po pełnym round-trip
(source → anonymized → recovered) DBF zrekonstruowany jest kanonicznie
identyczny ze źródłowym.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from dbf_anonymizer import (
    anonymize_directory,
    make_dbf_recovery,
    self_test,
)
from dbf_anonymizer.dictionary import dictionary_filename


class TestSelfTestSingleTable:
    """Self-test na pojedynczej tabeli z memo, polskimi znakami, deleted."""

    def test_roundtrip_mask_mode(self, sample_dbf_dir: Path):
        """Round-trip z memo_mode=mask — zrekonstruowany == źródłowy."""
        report = self_test(sample_dbf_dir, memo_mode="mask", date_offset_days=0)
        assert report.canonical_mismatches == 0, (
            f"Nie dopasowano {report.canonical_mismatches} tabel; "
            f"błędy: {[t.errors for t in report.tables if t.errors]}"
        )
        assert report.canonical_matches == 1
        assert report.successful

    def test_roundtrip_keep_mode(self, sample_dbf_dir: Path):
        """Round-trip z memo_mode=keep (memo bez zmian)."""
        report = self_test(sample_dbf_dir, memo_mode="keep", date_offset_days=0)
        assert report.canonical_mismatches == 0, (
            f"błędy: {[t.errors for t in report.tables if t.errors]}"
        )
        assert report.successful

    def test_roundtrip_date_offset(self, sample_dbf_dir: Path):
        """Round-trip z date_offset_days=30 (daty przesunięte)."""
        report = self_test(sample_dbf_dir, memo_mode="keep", date_offset_days=30)
        assert report.canonical_mismatches == 0, (
            f"błędy: {[t.errors for t in report.tables if t.errors]}"
        )
        assert report.successful

    def test_roundtrip_salt(self, sample_dbf_dir: Path):
        """Round-trim z solą — deterministyczne maskowanie."""
        report = self_test(sample_dbf_dir, memo_mode="mask", salt="my-secret-salt")
        assert report.canonical_mismatches == 0, (
            f"błędy: {[t.errors for t in report.tables if t.errors]}"
        )
        assert report.successful


class TestSelfTestMultiTable:
    """Self-test na katalogu z wieloma tabelami i zagnieżdżoną strukturą."""

    def test_roundtrip_multi(self, multi_dbf_dir: Path):
        report = self_test(multi_dbf_dir, memo_mode="mask")
        assert report.canonical_mismatches == 0, (
            f"błędy: {[t.errors for t in report.tables if t.errors]}"
        )
        # 2 tabele: klienci.dbf + produkty.dbf
        assert report.canonical_matches == 2
        assert report.successful


class TestAnonymizeDirectory:
    """Testy anonymize_directory — struktura wyjścia i słowniki."""

    def test_creates_anonymized_dir(self, sample_dbf_dir: Path):
        result = anonymize_directory(sample_dbf_dir, memo_mode="mask")
        # exit_code 0 (OK) lub 2 (WARNING — raw SHA różni się, oczekiwane przy anonimizacji)
        assert result.exit_code in (0, 2)
        assert result.failed == 0
        assert result.output.is_dir()
        # plik DBF istnieje w wyjściu
        assert (result.output / "klienci.dbf").is_file()

    def test_creates_dictionary(self, sample_dbf_dir: Path):
        result = anonymize_directory(sample_dbf_dir, memo_mode="mask")
        assert result.exit_code in (0, 2)
        assert result.failed == 0
        dict_file = result.dictionary_dir / dictionary_filename("klienci.dbf")
        assert dict_file.is_file(), f"Słownik nie istnieje: {dict_file}"

    def test_anonymized_data_differs(self, sample_dbf_dir: Path):
        """Po anonimizacji pola tekstowe różnią się od oryginału."""
        result = anonymize_directory(sample_dbf_dir, memo_mode="mask", salt="test")
        assert result.exit_code in (0, 2)
        assert result.failed == 0
        # Słownik zawiera mapowanie oryginał→anonim
        import json
        dict_file = result.dictionary_dir / dictionary_filename("klienci.dbf")
        data = json.loads(dict_file.read_text(encoding="utf-8"))
        # ID jest unikalną kolumną C — powinno mieć mapowanie
        id_field = data["fields"]["ID"]
        assert id_field["unique"] is True
        assert len(id_field["values"]) > 0
        # oryginały i anonimy różne
        for orig, anon in id_field["values"].items():
            assert orig != anon

    def test_exit_code_on_failure(self, tmp_path: Path):
        """Nieistniejący katalog → FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            anonymize_directory(tmp_path / "nonexistent")


class TestMakeRecovery:
    """Testy make_dbf_recovery — odtwarzanie z zaanonimizowanego + słownika."""

    def test_recovery_creates_dir(self, sample_dbf_dir: Path):
        anon = anonymize_directory(sample_dbf_dir, memo_mode="mask")
        assert anon.failed == 0
        rec = make_dbf_recovery(anon.output, anon.dictionary_dir)
        assert rec.exit_code in (0, 2)
        assert rec.failed == 0
        assert rec.output.is_dir()
        assert (rec.output / "klienci.dbf").is_file()

    def test_recovery_missing_dict_dir(self, sample_dbf_dir: Path, tmp_path: Path):
        anon = anonymize_directory(sample_dbf_dir, memo_mode="mask")
        with pytest.raises(FileNotFoundError):
            make_dbf_recovery(anon.output, tmp_path / "no_dicts")


class TestAnonymizedProperties:
    """Weryfikacja właściwości zaanonimizowanych danych."""

    def test_unique_columns_stay_unique(self, sample_dbf_dir: Path):
        """Kolumny unikalne przed anonimizacją pozostają unikalne po."""
        from dbfbridge import export_dbf
        result = anonymize_directory(sample_dbf_dir, memo_mode="mask", salt="u1")
        assert result.exit_code in (0, 2)
        assert result.failed == 0
        # Eksport zaanonimizowanego DBF do JSONL i sprawdź unikalność ID
        import json
        from pathlib import Path as P
        tmp = P(result.output.parent) / "check_anon"
        export_dbf(result.output / "klienci.dbf", tmp, formats=("jsonl",),
                   memo="inline", deleted="include", overwrite=True, validate=False)
        jsonl = tmp / "klienci.jsonl"
        ids = []
        with jsonl.open("r", encoding="utf-8-sig") as f:
            for line in f:
                rec = json.loads(line)
                if rec.get("type") in ("summary", "table"):
                    continue
                ids.append(rec.get("ID"))
        non_empty = [i for i in ids if i]
        assert len(non_empty) == len(set(non_empty)), "ID nie są unikalne po anonimizacji"
