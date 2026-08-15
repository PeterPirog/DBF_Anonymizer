"""Testy pipeline — round-trip anonimizacja + recovery na fixture DBF.

Kluczowy test: self_test weryfikuje, że po pełnym round-trip
(source → anonymized → recovered) DBF zrekonstruowany jest kanonicznie
identyczny ze źródłowym.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from dbf_anonymizer import (
    AnonymizeOptions,
    anonymize_directory,
    make_dbf_recovery,
    self_test,
)
from dbf_anonymizer.global_store import GlobalDictionaryStore, global_dictionary_path
from dbf_anonymizer.pipeline import (
    TableOutcome,
    _numeric_width_context,
    _parallel_prepared,
    _publish_reconstructed_table,
)
from dbf_anonymizer.schema import FieldInfo, TableSchema
from dbf_anonymizer.worker_tasks import PreparedTable


class TestSelfTestSingleTable:
    """Self-test na pojedynczej tabeli z memo, polskimi znakami, deleted."""

    def test_roundtrip_mask_mode(self, sample_dbf_dir: Path):
        """Round-trip z memo_mode=mask — zrekonstruowany == źródłowy."""
        report = self_test(
            sample_dbf_dir,
            memo_mode="mask",
            date_offset_days=0,
            batch_size=2,
        )
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


class TestDuplicateTableNames:
    """Wspólny słownik dla tej samej nazwy pliku w różnych katalogach."""

    def test_shared_dictionary_and_parallel_encoding(
        self,
        duplicate_name_dbf_dir: Path,
        tmp_path: Path,
    ):
        from dbfbridge import export_dbf

        result = anonymize_directory(
            duplicate_name_dbf_dir,
            memo_mode="mask",
            salt="shared-test",
            workers=2,
        )
        assert result.failed == 0, [table.errors for table in result.tables]
        assert len(result.tables) == 2

        dictionary_path = global_dictionary_path(result.dictionary_dir)
        with GlobalDictionaryStore(dictionary_path, read_only=True) as store:
            assert set(store.registered_files()) == {
                "oddzial_a/klienci.dbf",
                "oddzial_b/klienci.dbf",
            }
            assert store.memo_values("oddzial_a/klienci.dbf", "NOTE") == [
                "memo oddział A", "tylko A"
            ]
            assert store.memo_values("oddzial_b/klienci.dbf", "NOTE") == [
                "tylko B", "memo oddział B"
            ]
            shared_anonymous_id = store.forward_many(["SHARED"])["SHARED"]
        for branch in ("oddzial_a", "oddzial_b"):
            export_dir = tmp_path / f"export_{branch}"
            export_dbf(
                result.output / branch / "klienci.dbf",
                export_dir,
                formats=("jsonl",),
                memo="inline",
                deleted="include",
                overwrite=True,
                validate=False,
            )
            records = [
                json.loads(line)
                for line in (export_dir / "klienci.jsonl").read_text(
                    encoding="utf-8-sig"
                ).splitlines()
                if line.strip()
            ]
            assert shared_anonymous_id in {
                record.get("ID")
                for record in records
                if record.get("type") not in ("summary", "table")
            }

    def test_parallel_roundtrip_uses_relative_paths(
        self,
        duplicate_name_dbf_dir: Path,
    ):
        report = self_test(
            duplicate_name_dbf_dir,
            memo_mode="mask",
            workers=2,
        )
        assert report.canonical_mismatches == 0, [
            table.errors for table in report.tables if table.errors
        ]
        assert report.canonical_matches == 2
        assert {table.relative_path for table in report.tables} == {
            "oddzial_a/klienci.dbf",
            "oddzial_b/klienci.dbf",
        }
        assert report.successful


class TestGlobalRelationalMapping:
    """Ten sam klucz tekstowy musi być identyczny w różnych tabelach i polach."""

    def test_foreign_key_uses_same_global_mapping(
        self,
        relational_dbf_dir: Path,
        tmp_path: Path,
    ):
        from dbfbridge import export_dbf

        result = anonymize_directory(
            relational_dbf_dir,
            salt="relational-test",
            workers=2,
        )
        assert result.failed == 0, [table.errors for table in result.tables]

        with GlobalDictionaryStore(
            global_dictionary_path(result.dictionary_dir), read_only=True
        ) as store:
            anonymous_k001 = store.forward_many(["K001"])["K001"]

        exported: dict[str, list[dict]] = {}
        for table_name in ("klienci", "zamowienia"):
            export_dir = tmp_path / f"export_{table_name}"
            export_dbf(
                result.output / f"{table_name}.dbf",
                export_dir,
                formats=("jsonl",),
                memo="inline",
                deleted="include",
                overwrite=True,
                validate=False,
            )
            exported[table_name] = [
                json.loads(line)
                for line in (export_dir / f"{table_name}.jsonl").read_text(
                    encoding="utf-8-sig"
                ).splitlines()
                if line.strip()
            ]

        client_ids = {
            record.get("ID") for record in exported["klienci"] if "ID" in record
        }
        foreign_keys = {
            record.get("CLIENT_ID")
            for record in exported["zamowienia"]
            if "CLIENT_ID" in record
        }
        assert anonymous_k001 in client_ids
        assert anonymous_k001 in foreign_keys

        report = self_test(relational_dbf_dir, workers=2)
        assert report.successful
        assert report.canonical_matches == 2


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
        dict_file = global_dictionary_path(result.dictionary_dir)
        assert dict_file.is_file(), f"Słownik nie istnieje: {dict_file}"

    def test_default_dictionary_is_sibling_of_custom_output(
        self,
        sample_dbf_dir: Path,
        tmp_path: Path,
    ):
        output = tmp_path / "publikacja" / "baza-anonimowa"

        result = anonymize_directory(sample_dbf_dir, output_dir=output)

        assert result.exit_code in (0, 2)
        assert result.output == output.resolve()
        assert result.dictionary_dir == (
            output.parent / f"{sample_dbf_dir.name}_dict"
        ).resolve()
        assert global_dictionary_path(result.dictionary_dir).is_file()

    def test_anonymized_data_differs(self, sample_dbf_dir: Path):
        """Po anonimizacji pola tekstowe różnią się od oryginału."""
        result = anonymize_directory(sample_dbf_dir, memo_mode="mask", salt="test")
        assert result.exit_code in (0, 2)
        assert result.failed == 0
        with GlobalDictionaryStore(
            global_dictionary_path(result.dictionary_dir), read_only=True
        ) as store:
            mapping = store.forward_many(["K001", "K002", "K003", "K004", "K005"])
        assert len(mapping) == 5
        for original, anonymous in mapping.items():
            assert original != anonymous

    def test_exit_code_on_failure(self, tmp_path: Path):
        """Nieistniejący katalog → FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            anonymize_directory(tmp_path / "nonexistent")

    def test_emits_diagnostic_phase_logs(self, sample_dbf_dir: Path, caplog):
        caplog.set_level(logging.INFO, logger="dbf_anonymizer")

        result = anonymize_directory(sample_dbf_dir, workers=1, salt="logs")

        assert result.failed == 0
        messages = [record.getMessage() for record in caplog.records]
        assert any("phase=export event=start" in message for message in messages)
        assert any(
            "phase=dictionary event=text_domain_ready" in message
            for message in messages
        )
        assert any("alphabet_size=" in message for message in messages)
        assert any("phase=anonymize event=done" in message for message in messages)

    def test_logs_failure_returned_by_worker_with_table_and_error_code(
        self,
        tmp_path: Path,
        caplog,
        monkeypatch,
    ):
        prepared = PreparedTable(
            source=str(tmp_path / "problem.dbf"),
            relative_path="DANE/problem.dbf",
            job_root=str(tmp_path / "job"),
            jsonl_path=str(tmp_path / "problem.jsonl"),
            schema_path=str(tmp_path / "problem_schema.json"),
            records=12,
        )

        def returned_failure(*args, **kwargs):
            return TableOutcome(
                table="problem.dbf",
                relative_path="DANE/problem.dbf",
                status="FAILED",
                records=12,
                errors=[
                    "[DBFBRIDGE_RECONSTRUCTION_FAILED] source=problem "
                    "error=synthetic"
                ],
            )

        monkeypatch.setattr(
            "dbf_anonymizer.pipeline._anonymize_prepared_worker",
            returned_failure,
        )
        caplog.set_level(logging.ERROR, logger="dbf_anonymizer.pipeline")

        outcomes = _parallel_prepared(
            [prepared],
            output=tmp_path / "output",
            dictionary_dir=tmp_path / "dictionary",
            options=AnonymizeOptions(),
            batch_size=5000,
            workers=1,
        )

        assert outcomes[0].status == "FAILED"
        messages = [record.getMessage() for record in caplog.records]
        assert any(
            "phase=anonymize event=file_failed path=DANE/problem.dbf" in message
            and "error_code=DBFBRIDGE_RECONSTRUCTION_FAILED" in message
            and "error=synthetic" in message
            for message in messages
        )

    def test_cdx_failure_does_not_publish_partial_generation(
        self,
        sample_dbf_dir: Path,
        tmp_path: Path,
        caplog,
        monkeypatch,
    ):
        caplog.set_level(logging.ERROR, logger="dbf_anonymizer.pipeline")
        output = tmp_path / "published-output"
        dictionary = tmp_path / "published-dictionary"
        output.mkdir()
        dictionary.mkdir()
        (output / "generation.txt").write_text("old-output", encoding="utf-8")
        (dictionary / "generation.txt").write_text("old-dictionary", encoding="utf-8")
        (sample_dbf_dir / "klienci.cdx").write_bytes(b"definitions")

        def fail_reindex(*args, **kwargs):
            raise RuntimeError("synthetic VFP failure")

        monkeypatch.setattr(
            "dbf_anonymizer.pipeline.rebuild_companion_cdx",
            fail_reindex,
        )

        result = anonymize_directory(
            sample_dbf_dir,
            output_dir=output,
            dictionary_dir=dictionary,
            workers=1,
        )

        assert result.failed == 1
        assert result.exit_code == 1
        assert (output / "generation.txt").read_text(encoding="utf-8") == "old-output"
        assert (
            dictionary / "generation.txt"
        ).read_text(encoding="utf-8") == "old-dictionary"
        assert not (output / "klienci.dbf").exists()
        assert any(
            "phase=pipeline event=publication_blocked operation=anonymize" in
            record.getMessage()
            and "failed_paths=klienci.dbf" in record.getMessage()
            for record in caplog.records
        )


class TestParallelReconstructionIsolation:
    """Regresje wykryte podczas konwersji 94 tabel na Windows."""

    def test_publishes_only_table_artifacts_not_shared_report(
        self,
        tmp_path: Path,
    ):
        staging = tmp_path / "job" / "reconstructed"
        output = tmp_path / "output" / "DANE"
        staging.mkdir(parents=True)
        (staging / "sample.dbf").write_bytes(b"dbf")
        (staging / "sample.fpt").write_bytes(b"fpt")
        (staging / "reconstruction_report.jsonl").write_text(
            "report\n", encoding="utf-8"
        )

        _publish_reconstructed_table(
            staging,
            output,
            "sample",
            overwrite=True,
        )

        assert (output / "sample.dbf").read_bytes() == b"dbf"
        assert (output / "sample.fpt").read_bytes() == b"fpt"
        assert not (output / "reconstruction_report.jsonl").exists()
        assert not list(output.glob("*.partial"))

    def test_numeric_width_error_identifies_record_and_field(self):
        schema = TableSchema(
            table_name="pers_nob_arch.DBF",
            relative_path="DANE/pers_nob_arch.DBF",
            encoding="cp1250",
            has_memo=False,
            fields=(FieldInfo("VALUE", "N", 4, 1),),
        )

        context = _numeric_width_context(schema, [{"VALUE": -32}])

        assert context is not None
        assert "record=1" in context
        assert "field=VALUE" in context
        assert "dbf_type=N(4,1)" in context
        assert "rendered='-32.0'" in context


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
