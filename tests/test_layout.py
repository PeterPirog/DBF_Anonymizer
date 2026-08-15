import base64
import json
import struct
from pathlib import Path

from dbf_anonymizer.layout import (
    VFP_BACKLINK_BYTES,
    allow_generated_vfp_backlink,
    restore_source_header_layout,
)


def _schema(path: Path, *, header_length: int, record_length: int) -> Path:
    header = bytearray(header_length)
    struct.pack_into("<I", header, 4, 2)
    struct.pack_into("<HH", header, 8, header_length, record_length)
    schema_path = path / "table_schema.json"
    schema_path.write_text(
        json.dumps({
            "dbf": {
                "header_length_bytes": header_length,
                "record_length_bytes": record_length,
                "header_base64": base64.b64encode(header).decode("ascii"),
            },
            # 16 deskryptorów: 32 + 16*32 + terminator = 545.
            "fields": [
                {"name": f"F{index}", "dbf_type": "C", "length": 1}
                for index in range(16)
            ],
        }),
        encoding="utf-8",
    )
    return schema_path


def test_allows_writer_backlink_then_restores_compact_source_header(tmp_path: Path):
    source_header_length = 545
    generated_header_length = source_header_length + VFP_BACKLINK_BYTES
    record_length = 17
    schema_path = _schema(
        tmp_path,
        header_length=source_header_length,
        record_length=record_length,
    )
    reconstruction_schema = tmp_path / "reconstruction_schema.json"
    reconstruction_schema.write_bytes(schema_path.read_bytes())

    assert allow_generated_vfp_backlink(reconstruction_schema) == VFP_BACKLINK_BYTES
    adjusted = json.loads(reconstruction_schema.read_text(encoding="utf-8"))
    assert adjusted["dbf"]["header_length_bytes"] == generated_header_length

    generated = bytearray(generated_header_length)
    struct.pack_into("<I", generated, 4, 2)
    struct.pack_into(
        "<HH", generated, 8, generated_header_length, record_length
    )
    records = b" " + b"A" * 16 + b" " + b"B" * 16
    target = tmp_path / "table.dbf"
    target.write_bytes(generated + records + b"\x1a")

    assert restore_source_header_layout(target, schema_path) == VFP_BACKLINK_BYTES
    restored = target.read_bytes()
    assert struct.unpack_from("<H", restored, 8)[0] == source_header_length
    assert restored[source_header_length:] == records + b"\x1a"
