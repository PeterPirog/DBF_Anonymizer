import json
from pathlib import Path

from dbf_anonymizer.pipeline import _safe_difference
from dbf_anonymizer.verification import compare_dbf_canonical


def test_canonical_difference_never_contains_field_values(
    tmp_path: Path,
    monkeypatch,
):
    secret = "PRIVATE-PERSONAL-DATA-123"
    source = tmp_path / "source.dbf"
    recovered = tmp_path / "recovered.dbf"
    source.write_bytes(b"source")
    recovered.write_bytes(b"recovered")

    def fake_export(dbf: Path, output: Path, **kwargs):
        output.mkdir(parents=True, exist_ok=True)
        value = secret if Path(dbf) == source else "different"
        (output / f"{Path(dbf).stem}.jsonl").write_text(
            json.dumps({"NAME": value}) + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr("dbf_anonymizer.verification.export_dbf", fake_export)

    matches, report = compare_dbf_canonical(
        source,
        recovered,
        tmp_path / "work",
        "job",
    )

    assert not matches
    rendered_report = json.dumps(report, ensure_ascii=False)
    rendered_error = _safe_difference(report["differences"][0])
    assert secret not in rendered_report
    assert secret not in rendered_error
    assert "expected_sha256=" in rendered_error
    assert "actual_sha256=" in rendered_error

