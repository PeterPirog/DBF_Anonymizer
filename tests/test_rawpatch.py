import base64
import json
import struct
from pathlib import Path

from dbf_anonymizer.rawpatch import (
    make_numeric_values_reconstructable,
    restore_identity_field_bytes,
)
from dbf_anonymizer.schema import FieldInfo, TableSchema


def test_n_4_1_uses_placeholder_then_restores_raw_bytes(tmp_path: Path):
    schema = TableSchema(
        table_name="pers_nob_arch.DBF",
        relative_path="DANE/pers_nob_arch.DBF",
        encoding="cp1250",
        has_memo=False,
        fields=(FieldInfo("VALUE", "N", 4, 1),),
    )
    records, replacements = make_numeric_values_reconstructable(
        [{"VALUE": "-32"}], schema
    )
    assert records == [{"VALUE": 0}]
    assert replacements == 1

    header_length = 65
    record_length = 5
    header = bytearray(header_length)
    struct.pack_into("<I", header, 4, 1)
    struct.pack_into("<HH", header, 8, header_length, record_length)
    target = tmp_path / "table.dbf"
    target.write_bytes(header + b"    0")
    raw_record = b" -32 "
    jsonl = tmp_path / "table.jsonl"
    jsonl.write_text(
        json.dumps({
            "VALUE": "-32",
            "__dbfbridge_raw_record__": base64.b64encode(raw_record).decode("ascii"),
        }) + "\n",
        encoding="utf-8",
    )
    schema_path = tmp_path / "table_schema.json"
    schema_path.write_text(
        json.dumps({
            "fields": [
                {"name": "VALUE", "dbf_type": "N", "length": 4, "address": 1}
            ]
        }),
        encoding="utf-8",
    )

    assert restore_identity_field_bytes(target, jsonl, schema_path) == 1
    assert target.read_bytes()[header_length:] == raw_record
