"""End-to-end reversible Memo/General/Picture round-trip evidence (REQ-P2-007).

Proves the complete internal transformation/vault boundary against REAL
DBF/FPT artifacts built through the PUBLIC ``dbfbridge`` Direct Write
contract:

    original -> safe mask + protected vault row -> recovered original

with adversarial canaries proving that the original payload never appears in
the masked output bytes, public summaries, progress events, produced file
names or helper artifacts — and a bounded-memory large-payload sweep proving
the boundary retains nothing dataset-sized.
"""

from __future__ import annotations

import gc
import json
import tracemalloc
from pathlib import Path
from typing import Any, Mapping

import dbfbridge
from dbfbridge import DirectRecord, WriteResult, write_table

from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    persist_memo_recovery,
    recover_memo_value,
)
from support.memo_tables import (
    field,
    read_memo_records,
    schema as schema_of,
    source_hashes,
)
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60

CANARY_TEXT = "CANARY-MEMO-ORIGINAL-SECRET-ZAZOLC"
CANARY_BYTES = b"CANARY-BINARY-ORIGINAL-SECRET\x00\x01\xff"

_MEMO_FIELDS = ("TXT", "BIN", "GEN", "PIC")
_MEMO_TYPES = {"TXT": "M", "BIN": "M", "GEN": "G", "PIC": "P"}
_TEXT_MASK = "[MASKED-MEMO]"
_BINARY_MASK = b"[MASKED-MEMO]"

ROUNDTRIP_FIELDS = (
    field("CODE", "C", 8),
    field("TXT", "M", 4),
    field("BIN", "M", 4),
    field("GEN", "G", 4),
    field("PIC", "P", 4),
)

ROUNDTRIP_RECORDS: tuple[dict[str, object], ...] = (
    {
        "CODE": "R-A",
        "TXT": "Zażółć gęślą jaźń SYNTH-MEMO",
        "BIN": b"SYNTH-BINARY-\x00\x01\x02",
        "GEN": b"SYNTH-GENERAL-\x00\x01\x02",
        "PIC": b"SYNTH-PICTURE-\x01\x02",
    },
    {
        "CODE": "R-B",
        "TXT": "",
        "BIN": b"",
        "GEN": b"",
        "PIC": b"",
    },
    {
        "CODE": "R-C",
        "TXT": None,
        "BIN": None,
        "GEN": None,
        "PIC": None,
    },
    {
        "CODE": "R-D",
        "TXT": "DELETED-RECORD-SYNTH",
        "BIN": b"\xff\x00\x01",
        "GEN": CANARY_BYTES,
        "PIC": None,
    },
)
DELETED_INDEX = 2


def _vault(tmp_path: Path, *, create: bool) -> VaultDatabase:
    kwargs: dict[str, Any] = {
        "expected_source_fingerprint": SOURCE_FP,
        "expected_policy_fingerprint": POLICY_FP,
        "expected_relationship_fingerprint": RELATIONSHIP_FP,
    }
    if create:
        return VaultDatabase.open(
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            create=True,
            dbfbridge_version="1.1.0",
            **kwargs,
        )
    return VaultDatabase.open(tmp_path / "vault" / VAULT_DATABASE_FILENAME, **kwargs)


def _write_source(
    tmp_path: Path, stem: str
) -> tuple[Path, list[DirectRecord]]:
    """Build the synthetic source table; returns (dbf_path, original values)."""
    dbf_path = tmp_path / "src" / "memo" / f"{stem}.dbf"
    dbf_path.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        dbf_path,
        schema=schema_of(ROUNDTRIP_FIELDS),
        records=[
            DirectRecord(
                physical_index=index,
                deleted=index == DELETED_INDEX,
                values=dict(record),
            )
            for index, record in enumerate(ROUNDTRIP_RECORDS)
        ],
    )
    return dbf_path, list(read_memo_records(dbf_path))


def _register(
    vault: VaultDatabase, relative_path: str, names: tuple[str, ...] = _MEMO_FIELDS
) -> tuple[str, dict[str, str]]:
    with writer_session(vault), vault.transaction():
        table_id = vault.register_table(relative_path)
        field_ids = {
            name: vault.register_field(
                table_id, name, dbf_type=_MEMO_TYPES[name], width=4
            )
            for name in names
        }
    return table_id, field_ids


def _persist_all(
    vault: VaultDatabase,
    table_id: str,
    field_ids: dict[str, str],
    records: list[DirectRecord],
    names: tuple[str, ...] = _MEMO_FIELDS,
) -> list[dict[str, object]]:
    masks: list[dict[str, object]] = []
    with writer_session(vault):
        for record in records:
            record_masks: dict[str, object] = {}
            for name in names:
                record_masks[name] = persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=record.physical_index,
                    field_id=field_ids[name],
                    dbf_type=_MEMO_TYPES[name],
                    value=record.values[name],
                )
            masks.append(record_masks)
    return masks


def _masked_record(record: DirectRecord, masks: Mapping[str, object]) -> DirectRecord:
    values = dict(record.values)
    for name, mask in masks.items():
        values[name] = mask
    return DirectRecord(
        physical_index=record.physical_index, deleted=record.deleted, values=values
    )


def _masked_records(
    records: list[DirectRecord], masks: list[dict[str, object]]
) -> list[DirectRecord]:
    return [_masked_record(record, mask) for record, mask in zip(records, masks)]


def _public_surface(result: WriteResult, events: list[object]) -> str:
    pieces = [
        str(result),
        repr(result),
        json.dumps(result.to_dict(), sort_keys=True, default=str),
    ]
    for event in events:
        pieces.append(json.dumps(event, sort_keys=True, default=str))
    return "|".join(pieces)


def _assert_public_surface_clean(result: WriteResult, events: list[object]) -> None:
    surface = _public_surface(result, events)
    assert "CANARY" not in surface
    assert CANARY_TEXT not in surface
    assert "SYNTH-BINARY" not in surface
    assert "SYNTH-GENERAL" not in surface
    assert "SYNTH-PICTURE" not in surface


def _assert_canary_absent_from_outputs(masked_path: Path) -> None:
    for path in (masked_path, masked_path.with_suffix(".fpt")):
        data = path.read_bytes()
        assert CANARY_TEXT.encode("utf-8") not in data
        assert CANARY_BYTES not in data
        assert b"SYNTH-BINARY" not in data
        assert b"SYNTH-GENERAL" not in data
        assert b"SYNTH-PICTURE" not in data
        assert "Zażółć".encode("cp1250") not in data


def test_full_memo_roundtrip_through_public_dbf_boundary(tmp_path: Path) -> None:
    """original -> mask + protected vault -> recovered original (M/G/P)."""
    dbf_path, records = _write_source(tmp_path, "roundtrip")
    hashes_before = source_hashes(dbf_path)

    with _vault(tmp_path, create=True) as vault:
        table_id, field_ids = _register(vault, "memo/roundtrip.dbf")
        masks = _persist_all(vault, table_id, field_ids, records)
        # NULL record: no mask and no recovery row at all.
        assert all(masks[2][name] is None for name in _MEMO_FIELDS)
        # Empty payloads ARE masked (never collapsed into NULL).
        assert masks[1]["TXT"] == _TEXT_MASK
        assert masks[1]["GEN"] == _BINARY_MASK

        masked_path = tmp_path / "masked" / "memo" / "roundtrip.dbf"
        events: list[object] = []
        result = write_table(
            masked_path,
            schema=dbfbridge.read_schema(dbf_path),
            records=_masked_records(records, masks),
            progress=lambda event: events.append(event),
        )
        _assert_public_surface_clean(result, events)
        _assert_canary_absent_from_outputs(masked_path)
        # The output tree contains exactly the DBF and its FPT companion.
        produced = sorted(p.name for p in masked_path.parent.iterdir())
        assert produced == ["roundtrip.dbf", "roundtrip.fpt"]
        for name in produced:
            assert "CANARY" not in name and "SYNTH-GENERAL" not in name

        masked_records = list(read_memo_records(masked_path))
        assert len(masked_records) == len(records)
        for record, masked, record_masks in zip(records, masked_records, masks):
            assert masked.deleted == record.deleted
            assert masked.values["CODE"] == record.values["CODE"]
            for name in _MEMO_FIELDS:
                assert masked.values[name] == record_masks[name]

        # Recovery from vault state restores every original logical value.
        recovered: list[DirectRecord] = []
        for masked in masked_records:
            values: dict[str, object] = dict(masked.values)
            for name in _MEMO_FIELDS:
                values[name] = recover_memo_value(
                    vault,
                    table_id=table_id,
                    physical_record_index=masked.physical_index,
                    field_id=field_ids[name],
                )
            recovered.append(
                DirectRecord(
                    physical_index=masked.physical_index,
                    deleted=masked.deleted,
                    values=values,
                )
            )

    recovered_path = tmp_path / "recovered" / "memo" / "roundtrip.dbf"
    recovered_path.parent.mkdir(parents=True, exist_ok=True)
    write_table(recovered_path, schema=dbfbridge.read_schema(dbf_path), records=recovered)
    reread = list(read_memo_records(recovered_path))
    assert len(reread) == len(records)
    for record, back in zip(records, reread):
        assert back.deleted == record.deleted
        assert dict(back.values) == dict(record.values)

    # The source stayed byte-identical through the whole cycle.
    assert source_hashes(dbf_path) == hashes_before


def test_repeated_equal_payloads_round_trip_independently(tmp_path: Path) -> None:
    shared = b"IDENTICAL-SHARED-PAYLOAD-\x00\x01"
    fields = (field("CODE", "C", 8), field("GEN", "G", 4))
    records_values = (
        {"CODE": "X-1", "GEN": shared},
        {"CODE": "X-2", "GEN": shared},
    )
    source = tmp_path / "src" / "memo" / "equal.dbf"
    source.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        source,
        schema=schema_of(fields),
        records=[
            DirectRecord(physical_index=i, deleted=False, values=dict(record))
            for i, record in enumerate(records_values)
        ],
    )
    with _vault(tmp_path, create=True) as vault:
        table_id, field_ids = _register(vault, "memo/equal.dbf", names=("GEN",))
        records = list(read_memo_records(source))
        masks = _persist_all(vault, table_id, field_ids, records, names=("GEN",))
        assert masks[0]["GEN"] == masks[1]["GEN"] == _BINARY_MASK
        # Two independent rows for the SAME payload value.
        row_a = recover_memo_value(
            vault, table_id=table_id, physical_record_index=0, field_id=field_ids["GEN"]
        )
        row_b = recover_memo_value(
            vault, table_id=table_id, physical_record_index=1, field_id=field_ids["GEN"]
        )
        assert row_a == row_b == shared


def test_large_payload_bounded_memory_no_dataset_retention(tmp_path: Path) -> None:
    """Large-payload bounded-memory acceptance evidence (deterministic)."""
    # A deterministic >8 MiB binary payload spanning the full byte spectrum.
    pattern = bytes(range(256))
    payload = (pattern + b"SYNTH-LARGE-MEMO-BOUNDARY-") * (
        8 * 1024 * 1024 // len(pattern) + 1
    )
    assert len(payload) > 8 * 1024 * 1024

    fields = (field("CODE", "C", 8), field("GEN", "G", 4))
    source = tmp_path / "src" / "memo" / "large.dbf"
    source.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        source,
        schema=schema_of(fields),
        records=[
            DirectRecord(
                physical_index=0, deleted=False, values={"CODE": "L0", "GEN": b""}
            ),
        ],
    )

    with _vault(tmp_path, create=True) as vault:
        table_id, field_ids = _register(vault, "memo/large.dbf", names=("GEN",))
        with writer_session(vault):
            gc.collect()
            tracemalloc.start()
            baseline = tracemalloc.get_traced_memory()[0]
            for record_index in range(4):
                gc.collect()
                mask = persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=record_index,
                    field_id=field_ids["GEN"],
                    dbf_type="G",
                    value=payload,
                )
                assert mask == _BINARY_MASK
                current, peak = tracemalloc.get_traced_memory()
                # No dataset-sized retention: after every call the traced
                # heap returns to the baseline — no payload from a previous
                # record is kept in memory (the boundary owns nothing
                # between records).
                assert abs(current - baseline) < 2 * 1024 * 1024, record_index
                # The per-call transient cost stays bounded and does NOT
                # grow with the record count (no N-fold copies).
                assert peak - baseline < 3 * len(payload), record_index
            after = tracemalloc.get_traced_memory()[0]
            assert abs(after - baseline) < 2 * 1024 * 1024
            tracemalloc.stop()
        # Every large payload remains independently recoverable.
        for record_index in range(4):
            assert (
                recover_memo_value(
                    vault,
                    table_id=table_id,
                    physical_record_index=record_index,
                    field_id=field_ids["GEN"],
                )
                == payload
            )