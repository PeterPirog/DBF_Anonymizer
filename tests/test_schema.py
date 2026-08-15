import json
from pathlib import Path

from dbf_anonymizer.schema import load_schema


def test_loads_dbfbridge_decimal_count_and_declared_encoding(tmp_path: Path):
    schema_path = tmp_path / "table_schema.json"
    schema_path.write_text(
        json.dumps({
            "table": "legacy_numeric",
            "relative_path": "DATA/legacy_numeric.DBF",
            "text_encoding": {
                "declared_or_detected_encoding": "cp852",
            },
            "fields": [
                {
                    "name": "VALUE",
                    "dbf_type": "N",
                    "length": 4,
                    "decimal_count": 1,
                }
            ],
        }),
        encoding="utf-8",
    )

    schema = load_schema(schema_path)

    assert schema.encoding == "cp852"
    assert schema.fields[0].decimal == 1


def test_dbfbridge_structural_index_field_is_treated_as_combined_table_flags(
    tmp_path: Path,
):
    schema_path = tmp_path / "memo_schema.json"
    schema_path.write_text(
        json.dumps({
            "table": "memo_table",
            "dbf": {"structural_index_flag": 0x02},
            "memo": {"has_memo": True},
            "fields": [{"name": "TRESC", "dbf_type": "M", "length": 4}],
        }),
        encoding="utf-8",
    )

    memo_only = load_schema(schema_path)

    assert memo_only.table_flags == 0x02
    assert memo_only.has_memo_file_flag
    assert not memo_only.has_structural_cdx

    combined = schema_path.read_text(encoding="utf-8").replace(": 2", ": 3")
    schema_path.write_text(combined, encoding="utf-8")
    assert load_schema(schema_path).has_structural_cdx
