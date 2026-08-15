from pathlib import Path
from types import SimpleNamespace

from dbf_anonymizer.worker_tasks import (
    _canonical_jsonl_matches_dbf,
    _reconstruct_isolated,
)


def test_canonical_jsonl_matches_exported_dbf(sample_dbf_dir: Path, tmp_path: Path):
    from dbfbridge import export_dbf

    source = sample_dbf_dir / "klienci.dbf"
    exported = tmp_path / "exported"
    export_dbf(
        source=source,
        output=exported,
        formats=("jsonl",),
        memo="inline",
        deleted="include",
        overwrite=True,
        validate=False,
    )

    matches, expected, actual = _canonical_jsonl_matches_dbf(
        source,
        exported / "klienci.jsonl",
        exported / "klienci_schema.json",
    )

    assert matches
    assert expected == actual


def test_reconstruct_repairs_returned_canonical_failure_after_raw_patch(
    tmp_path: Path,
    monkeypatch,
):
    source_dir = tmp_path / "source"
    staging = tmp_path / "staging"
    output = tmp_path / "output"
    source_dir.mkdir()
    records = source_dir / "indexed_table.jsonl"
    records.write_text("{}\n", encoding="utf-8")
    raw_records = source_dir / "raw.jsonl"
    raw_records.write_text("{}\n", encoding="utf-8")
    schema = source_dir / "indexed_table_schema.json"
    schema.write_text("{}", encoding="utf-8")
    item = SimpleNamespace(
        status="FAILED",
        errors=["Canonical checksum mismatch after reading the reconstructed DBF/FPT."],
        differences=[{"scope": "field"}],
        warnings=[],
        canonical_match=False,
        input_canonical_sha256="before",
        reconstructed_canonical_sha256="different",
    )
    reconstruction = SimpleNamespace(results=[item])

    def fake_reconstruct(**kwargs):
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "indexed_table.dbf").write_bytes(b"dbf")
        return reconstruction

    published: list[str] = []
    monkeypatch.setattr(
        "dbf_anonymizer.worker_tasks.reconstruct_dbf",
        fake_reconstruct,
    )
    monkeypatch.setattr(
        "dbf_anonymizer.worker_tasks.restore_source_header_layout",
        lambda *args: 0,
    )
    monkeypatch.setattr(
        "dbf_anonymizer.worker_tasks.restore_identity_field_bytes",
        lambda *args: 1,
    )
    monkeypatch.setattr(
        "dbf_anonymizer.worker_tasks._canonical_jsonl_matches_dbf",
        lambda *args: (True, "repaired", "repaired"),
    )
    monkeypatch.setattr(
        "dbf_anonymizer.worker_tasks.publish_reconstructed_table",
        lambda *args, **kwargs: published.append("indexed_table.dbf"),
    )

    result = _reconstruct_isolated(
        source_dir=source_dir,
        staging_output=staging,
        output_parent=output,
        table_stem="indexed_table",
        relative_path="DATA/indexed_table.DBF",
        schema=SimpleNamespace(fields=()),
        records_path=records,
        raw_records_path=raw_records,
        schema_path=schema,
    )

    assert result is reconstruction
    assert item.status == "WARNING"
    assert item.errors == []
    assert item.differences == []
    assert item.canonical_match is True
    assert item.input_canonical_sha256 == "repaired"
    assert item.reconstructed_canonical_sha256 == "repaired"
    assert "CANONICAL_MISMATCH_REPAIRED_BY_RAW_IDENTITY_PATCH" in item.warnings[0]
    assert published == ["indexed_table.dbf"]
