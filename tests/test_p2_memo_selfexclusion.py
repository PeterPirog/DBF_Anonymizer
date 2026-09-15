"""Mask self-exclusion regressions for the PR #26 review defect.

The chief-architect review found a material defect in the original PR #26
mask design: the safe masks were plain constants, so an original sensitive
payload that HAPPENED to equal the mask survived the pseudonymized output
completely unchanged:

    original == "[MASKED-MEMO]"  ->  masked == "[MASKED-MEMO]"  (identical)
    original == b"[MASKED-MEMO]" ->  b"[MASKED-MEMO]"           (identical)

These deterministic regressions FAIL on the reviewed HEAD ``19d6a93`` and pin
the repaired semantics: a fixed bounded mask vocabulary with deterministic
self-exclusion, so for EVERY supported non-NULL logical payload the emitted
mask is never equal to the complete original payload.
"""

from __future__ import annotations

from pathlib import Path

import dbfbridge
from dbfbridge import DirectRecord, FieldInfo, TableSchema, write_table

from dbf_anonymizer.transforms import memo as memo_kernels
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    persist_memo_recovery,
    recover_memo_value,
)
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60

TEXT_PRIMARY = memo_kernels.MEMO_TEXT_MASK
BINARY_PRIMARY = memo_kernels.MEMO_BINARY_MASK
TEXT_ALTERNATE = "[MASKED-MEMO-ALT]"
BINARY_ALTERNATE = b"[MASKED-MEMO-ALT]"


# ---------------------------------------------------------------------------
# TEXT Memo self-exclusion
# ---------------------------------------------------------------------------
def test_text_source_equal_primary_mask_receives_alternate_mask() -> None:
    """A source payload equal to the primary mask MUST NOT survive unchanged."""
    mask = memo_kernels.memo_safe_mask(TEXT_PRIMARY)
    assert mask != TEXT_PRIMARY
    assert mask == TEXT_ALTERNATE


def test_text_source_equal_alternate_mask_receives_primary_mask() -> None:
    # A source equal to the ALTERNATE naturally receives the PRIMARY mask.
    assert memo_kernels.memo_safe_mask(TEXT_ALTERNATE) == TEXT_PRIMARY


def test_ordinary_text_source_receives_primary_mask() -> None:
    for value in ("sensitive memo text", "", "Zażółć", "x" * 1000):
        mask = memo_kernels.memo_safe_mask(value)
        assert mask == TEXT_PRIMARY
        assert mask != value


def test_every_text_mask_differs_from_its_complete_source() -> None:
    # THE mandatory invariant, over adversarial boundary values AND both
    # vocabulary members as sources.
    sources = (
        TEXT_PRIMARY,
        TEXT_ALTERNATE,
        "",
        "sensitive text",
        "Zażółć gęślą jaźń",
        "[MASKED-MEMO " + "x" * 8,
        "[MASKED-MEMO-ALT" + "!",
    )
    for value in sources:
        mask = memo_kernels.memo_safe_mask(value)
        assert mask is not None  # non-NULL sources get a non-NULL mask
        assert mask != value, f"mask collided with the complete source: {value!r}"


# ---------------------------------------------------------------------------
# BINARY Memo / General / Picture self-exclusion
# ---------------------------------------------------------------------------
def test_binary_source_equal_primary_mask_receives_alternate_mask() -> None:
    mask = memo_kernels.memo_safe_mask(BINARY_PRIMARY)
    assert mask != BINARY_PRIMARY
    assert mask == BINARY_ALTERNATE


def test_binary_source_equal_alternate_mask_receives_primary_mask() -> None:
    assert memo_kernels.memo_safe_mask(BINARY_ALTERNATE) == BINARY_PRIMARY


def test_ordinary_binary_source_receives_primary_mask() -> None:
    for value in (b"ordinary binary payload\x00\x01", b"", b"\xff" * 512):
        mask = memo_kernels.memo_safe_mask(value)
        assert mask == BINARY_PRIMARY
        assert mask != value


def test_every_binary_mask_differs_from_its_complete_source() -> None:
    sources = (
        BINARY_PRIMARY,
        BINARY_ALTERNATE,
        b"",
        b"binary payload\x00\x01\x02",
        b"\xff\x00",
    )
    for value in sources:
        mask = memo_kernels.memo_safe_mask(value)
        assert mask is not None
        assert mask != value, f"mask collided with the complete source: {value!r}"


# ---------------------------------------------------------------------------
# real DBF/FPT collision round-trip through the PUBLIC dbfbridge boundary
# ---------------------------------------------------------------------------
def _write_source_table(
    tmp_path: Path, stem: str
) -> tuple[Path, list[DirectRecord]]:
    fields = (
        FieldInfo(
            ordinal=0,
            name="CODE",
            dbf_type="C",
            length=16,
            decimal_count=0,
            address=0,
            flags=0,
            index_field_flag=0,
            autoincrement_next_value=0,
            autoincrement_step=1,
            is_memo=False,
            is_binary=False,
            supported=True,
            dbversion_byte=0x30,
        ),
        FieldInfo(
            ordinal=0,
            name="TXT",
            dbf_type="M",
            length=4,
            decimal_count=0,
            address=0,
            flags=0,
            index_field_flag=0,
            autoincrement_next_value=0,
            autoincrement_step=1,
            is_memo=True,
            is_binary=False,
            supported=True,
            dbversion_byte=0x30,
        ),
        FieldInfo(
            ordinal=0,
            name="BIN",
            dbf_type="M",
            length=4,
            decimal_count=0,
            address=0,
            flags=0,
            index_field_flag=0,
            autoincrement_next_value=0,
            autoincrement_step=1,
            is_memo=True,
            is_binary=False,
            supported=True,
            dbversion_byte=0x30,
        ),
        FieldInfo(
            ordinal=0,
            name="GEN",
            dbf_type="G",
            length=4,
            decimal_count=0,
            address=0,
            flags=0,
            index_field_flag=0,
            autoincrement_next_value=0,
            autoincrement_step=1,
            is_memo=True,
            is_binary=True,
            supported=True,
            dbversion_byte=0x30,
        ),
    )
    schema = TableSchema(
        path=Path("memory:collision"),
        record_count=0,
        header_length=32 + 32 * len(fields) + 1,
        record_length=sum(f.length for f in fields) + 1,
        language_driver=0xC8,
        encoding="cp1250",
        has_memo=True,
        has_memo_flag=True,
        has_structural_cdx=False,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
        table_flags=0,
        fields=fields,
        warnings=(),
        dbversion_byte=0x30,
        dbversion_name="Visual FoxPro",
        last_update="2026-01-01",
        incomplete_transaction=False,
        encryption_flag=False,
        memo_companion_format=None,
        memo_companion_present=False,
        memo_companion_path=None,
        memo_companion_size_bytes=None,
        memo_block_size=64,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )
    # The SOURCE payloads are EXACTLY the current mask vocabulary values:
    # the pre-repair code emits them unchanged into the pseudonymized DBF.
    records = [
        {
            "CODE": "COLLIDE-TEXT",
            "TXT": TEXT_PRIMARY,
            "BIN": BINARY_PRIMARY,
            "GEN": BINARY_PRIMARY,
        },
        {
            "CODE": "COLLIDE-ALT",
            "TXT": TEXT_ALTERNATE,
            "BIN": BINARY_ALTERNATE,
            "GEN": BINARY_ALTERNATE,
        },
        {
            "CODE": "COLLIDE-GEN",
            "TXT": "ordinary text",
            "BIN": b"ordinary\x00binary",
            "GEN": BINARY_PRIMARY,
        },
    ]
    dbf_path = tmp_path / "src" / "collision.dbf"
    dbf_path.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        dbf_path,
        schema=schema,
        records=[
            DirectRecord(physical_index=index, deleted=False, values=dict(record))
            for index, record in enumerate(records)
        ],
    )
    originals = list(
        dbfbridge.iter_records(dbf_path, memo="inline", include_deleted=True)
    )
    assert len(originals) == 3
    return dbf_path, originals


def _open_vault(tmp_path: Path, *, create: bool = True) -> VaultDatabase:
    if create:
        return VaultDatabase.open(
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            create=True,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
            dbfbridge_version="1.1.0",
        )
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


def test_dbf_collision_source_equal_masks_never_survive_unchanged(
    tmp_path: Path,
) -> None:
    """Real DBF/FPT round-trip where the source payload IS the mask value.

    Deterministic regression of the review defect: before the repair, the
    pseudonymized logical value of the masked output was IDENTICAL to the
    sensitive source value (``masked == original``) for the primary-mask
    collision rows.
    """
    import hashlib

    dbf_path, originals = _write_source_table(tmp_path, "collision")
    hashes_before = {
        "dbf": hashlib.sha256(dbf_path.read_bytes()).hexdigest(),
        "fpt": hashlib.sha256(dbf_path.with_suffix(".fpt").read_bytes()).hexdigest(),
    }
    memo_names = {"TXT": "M", "BIN": "M", "GEN": "G"}
    with _open_vault(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            table_id = vault.register_table("collision/collision.dbf")
            field_ids = {
                name: vault.register_field(table_id, name, dbf_type=kind, width=4)
                for name, kind in memo_names.items()
            }
        masks: list[dict[str, object]] = []
        with writer_session(vault):
            for record in originals:
                record_masks: dict[str, object] = {}
                for name, kind in memo_names.items():
                    record_masks[name] = persist_memo_recovery(
                        vault,
                        table_id=table_id,
                        physical_record_index=record.physical_index,
                        field_id=field_ids[name],
                        dbf_type=kind,
                        value=record.values[name],
                    )
                masks.append(record_masks)
        # THE invariant: every emitted mask differs from the complete source.
        for record, record_masks in zip(originals, masks):
            for name in memo_names:
                assert record_masks[name] != record.values[name]
        # Primary-mask sources receive the ALTERNATE mask; alternate-mask
        # sources receive the PRIMARY mask.
        assert masks[0]["TXT"] == TEXT_ALTERNATE
        assert masks[0]["BIN"] == BINARY_ALTERNATE
        assert masks[0]["GEN"] == BINARY_ALTERNATE
        assert masks[1]["TXT"] == TEXT_PRIMARY
        assert masks[1]["BIN"] == BINARY_PRIMARY
        assert masks[1]["GEN"] == BINARY_PRIMARY
        # Ordinary sources keep the primary mask.
        assert masks[2]["TXT"] == TEXT_PRIMARY
        assert masks[2]["BIN"] == BINARY_PRIMARY
        assert masks[2]["GEN"] == BINARY_ALTERNATE  # GEN source == primary

        masked_records = [
            DirectRecord(
                physical_index=record.physical_index,
                deleted=record.deleted,
                values={**dict(record.values), **dict(record_masks)},
            )
            for record, record_masks in zip(originals, masks)
        ]

    masked_path = tmp_path / "masked" / "collision.dbf"
    masked_path.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        masked_path,
        schema=dbfbridge.read_schema(dbf_path),
        records=masked_records,
    )
    masked_values = list(
        dbfbridge.iter_records(masked_path, memo="inline", include_deleted=True)
    )
    for record, masked, record_masks in zip(originals, masked_values, masks):
        for name in memo_names:
            # The output logical payload is never identical to the source.
            assert masked.values[name] != record.values[name]
            assert masked.values[name] == record_masks[name]
    # The complete originals remain recoverable from the (reopened) vault.
    with _open_vault(tmp_path, create=False) as vault:
        for record in originals:
            for name in memo_names:
                assert (
                    recover_memo_value(
                        vault,
                        table_id=table_id,
                        physical_record_index=record.physical_index,
                        field_id=field_ids[name],
                    )
                    == record.values[name]
                )
    # The source stayed byte-identical through the whole cycle.
    assert {
        "dbf": hashlib.sha256(dbf_path.read_bytes()).hexdigest(),
        "fpt": hashlib.sha256(dbf_path.with_suffix(".fpt").read_bytes()).hexdigest(),
    } == hashes_before