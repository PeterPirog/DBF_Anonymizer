import json
from pathlib import Path

from dbf_anonymizer.schema import load_schema


def test_loads_dbfbridge_decimal_count_and_declared_encoding(tmp_path: Path):
    schema_path = tmp_path / "table_schema.json"
    schema_path.write_text(
        json.dumps({
            "table": "pers_nob_arch",
            "relative_path": "DANE/pers_nob_arch.DBF",
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
