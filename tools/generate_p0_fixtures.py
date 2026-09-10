"""Deterministic generator for the REQ-P0-003 synthetic fixture corpus.

Every valid artifact is created EXCLUSIVELY through the public dbfbridge 1.1
Direct Write contract (``write_table`` with a public ``TableSchema``) and
verified through the public Direct Read contract.  The generator implements
no DBF parser or writer of its own.

The ONLY byte-level operations are the three narrowly scoped, fully
documented malformed-fixture mutations (``_corrupt_*`` functions below),
applied exclusively to wholly synthetic artifacts built by this tool in a
temporary staging directory.  They exist to create deterministic malformed
input evidence only; they are not a DBF parser or writer.

Regeneration is deterministic: all schemas pin ``last_update`` and all
records are fixed literals; re-running this tool with the same pinned
dbfbridge artifact reproduces byte-identical artifacts.

Usage:
    python tools/generate_p0_fixtures.py [--out <dir>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import tempfile
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import cast

from dbfbridge import (
    DirectRecord,
    FieldInfo,
    TableSchema,
    inspect_table,
    iter_records,
    read_schema,
    write_table,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "tests" / "fixtures" / "p0"

DBFBRIDGE_VERSION = "1.1.0"
PINNED_LAST_UPDATE = "2026-01-01"
MEMO_BLOCK_SIZE = 64

#: Deterministic, obviously synthetic Polish pangram-based strings.  They
#: contain no personal data, addresses or production identifiers.
PANGRAM = "Zażółć gęślą jaźń ĄĆĘŁŃÓŚŹŻ ąćęłńóśźż"
TEXT_SYNTH_SUFFIX = {"cp1250": "SYNTH-P1250", "cp852": "SYNTH-P852", "mazovia": "SYNTH-MAZOVIA"}

SHARED_KEYS = ("KEY0001", "KEY0002", "KEY0003", "KEY0004")

MEMO_TEXT = "Zażółć gęślą jaźń SYNTH-MEMO"
MEMO_BINARY = b"SYNTH-BINARY-MEMO-\x00\x01\x02"
GENERAL_PAYLOAD = b"SYNTHETIC-GENERAL-PAYLOAD-\x00\x01\x02"
PICTURE_PAYLOAD = b"SYNTHETIC-PICTURE-PAYLOAD-\x01\x02"

GAPS = [
    {
        "dimension": "structural_cdx_metadata",
        "blocker": (
            "No public dbfbridge 1.1.0 mechanism persists the structural-CDX "
            "header flag in a freshly written DBF: write_table() accepts "
            "schema.has_structural_cdx=True, returns structural_cdx=true / "
            "index_rebuild_required=true and emits the authoritative "
            "STRUCTURAL_CDX warning, but the published header keeps the "
            "structural-CDX table flag unset and no CDX file is created.  "
            "Authoritative CDX artifacts require the VFP index backend "
            "(REQ-P6-003).  No CDX/IDX fixture artifact is committed."
        ),
        "capability_evidence": [
            "tests.test_p0_fixture_corpus::test_structural_cdx_capability_fact"
        ],
    },
    {
        "dimension": "dbc_bound_metadata",
        "blocker": (
            "No public dbfbridge 1.1.0 mechanism writes a VFP 263-byte DBC "
            "backlink: Direct Write publishes standalone tables "
            "(read_schema().dbc_bound is always False).  DBC-bound metadata "
            "evidence requires the authoritative VFP/DBC toolchain "
            "(REQ-P6-005).  No DBC artifact is fabricated."
        ),
        "capability_evidence": [
            "tests.test_p0_fixture_corpus::test_written_fixtures_are_standalone"
        ],
    },
    {
        "dimension": "standalone_idx_inventory",
        "blocker": (
            "No public dbfbridge 1.1.0 mechanism writes standalone .idx "
            "artifacts and no index writer may be implemented in this "
            "repository.  An IDX inventory fixture would therefore have to "
            "be fabricated, which the architecture forbids.  IDX inventory "
            "evidence is deferred to REQ-P6-004 with the VFP toolchain."
        ),
        "capability_evidence": [
            "tests.test_p0_fixture_corpus::test_declared_gaps_are_not_claimed"
        ],
    },
]

COVERAGE_BY_CAPABILITY_ONLY = {
    "negative_opaque_field_cases": [
        "tests.test_p0_fixture_corpus::test_opaque_field_write_refusal",
        "tests.test_p0_fixture_corpus::test_unknown_projection_negative",
        "tests.test_p0_fixture_corpus::test_malformed_fixtures_fail_with_typed_dependency_errors",
        "tests.test_p0_fixture_corpus::test_missing_memo_companion_behavior",
    ],
}


# ---------------------------------------------------------------------------
# public-schema construction helpers
# ---------------------------------------------------------------------------


def _field(name: str, dbf_type: str, length: int, *, decimals: int = 0, flags: int = 0) -> FieldInfo:
    return FieldInfo(
        ordinal=0,
        name=name,
        dbf_type=dbf_type,
        length=length,
        decimal_count=decimals,
        address=0,
        flags=flags,
        index_field_flag=0,
        autoincrement_next_value=0,
        autoincrement_step=1,
        is_memo=dbf_type in {"M", "G", "P"},
        is_binary=False,
        supported=True,
        dbversion_byte=0x30,
    )


def _schema(
    fields: tuple[FieldInfo, ...],
    *,
    dbversion: int = 0x30,
    driver: int = 0xC8,
    encoding: str = "cp1250",
) -> TableSchema:
    """Build a public ``TableSchema`` for a synthetic fixture table.

    The ``_NullFlags`` system column is sized from the canonical VFP
    allocation (one varlength bit per Varchar field plus one NULL bit per
    nullable application field, rounded up to whole bytes).  The public
    Direct Write contract re-validates the allocation and fails closed if it
    is wrong, so this helper makes no private assumptions.
    """
    field_list = list(fields)
    bits = sum(
        1 for f in field_list if f.dbf_type != "0" and (f.dbf_type == "V" or (f.flags & 0x02))
    )
    if bits:
        field_list.append(_field("_NULLFLAGS", "0", (bits + 7) // 8, flags=0x01))
    ordered = tuple(field_list)
    return TableSchema(
        path=Path("memory:fixture"),
        record_count=0,
        header_length=32 + 32 * len(ordered) + 1,
        record_length=sum(f.length for f in ordered) + 1,
        language_driver=driver,
        encoding=encoding,
        has_memo=any(f.is_memo for f in ordered),
        has_memo_flag=any(f.is_memo for f in ordered),
        has_structural_cdx=False,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
        table_flags=0,
        fields=ordered,
        warnings=(),
        dbversion_byte=dbversion,
        dbversion_name="Visual FoxPro",
        last_update=PINNED_LAST_UPDATE,
        incomplete_transaction=False,
        encryption_flag=False,
        memo_companion_format=None,
        memo_companion_present=False,
        memo_companion_path=None,
        memo_companion_size_bytes=None,
        memo_block_size=MEMO_BLOCK_SIZE,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def _rec(index: int, values: Mapping[str, object], *, deleted: bool = False) -> DirectRecord:
    return DirectRecord(physical_index=index, deleted=deleted, values=dict(values))


# ---------------------------------------------------------------------------
# table definitions (all values are deterministic and obviously synthetic)
# ---------------------------------------------------------------------------

_PLAIN_FIELDS = (
    _field("CODE", "C", 10),
    _field("CNT", "I", 4),
    _field("AMOUNT", "N", 10, decimals=2),
    _field("RATIO", "F", 12, decimals=4),
    _field("PRICE", "Y", 8),
    _field("MEASURE", "B", 8),
    _field("FLAG", "L", 1),
    _field("WHEN", "D", 8),
    _field("MOMENT", "T", 8),
)

_PLAIN_RECORDS = [
    {"CODE": "SYNTH-01", "CNT": -42, "AMOUNT": 123.45, "RATIO": 2.5,
     "PRICE": Decimal("1234.5678"), "MEASURE": 3.14159, "FLAG": True,
     "WHEN": date(2028, 2, 29), "MOMENT": datetime(2028, 2, 29, 23, 59, 58)},
    {"CODE": "SYNTH-02", "CNT": 0, "AMOUNT": 0.0, "RATIO": 0.5,
     "PRICE": Decimal("0.0001"), "MEASURE": -2.5, "FLAG": False,
     "WHEN": date(2024, 2, 29), "MOMENT": datetime(2024, 2, 29, 0, 0, 1)},
    {"CODE": "SYNTH-03", "CNT": 77, "AMOUNT": 999.99, "RATIO": -1.25,
     "PRICE": Decimal("0.05"), "MEASURE": 12345.6789, "FLAG": False,
     "WHEN": date(2026, 1, 1), "MOMENT": datetime(2026, 1, 1, 12, 0, 0)},
    {"CODE": "SYNTH-04", "CNT": -1, "AMOUNT": 1.01, "RATIO": 100.0,
     "PRICE": Decimal("999999.9999"), "MEASURE": 0.0, "FLAG": True,
     "WHEN": date(2020, 12, 31), "MOMENT": datetime(2020, 12, 31, 0, 0, 0)},
    {"CODE": "SYNTH-05", "CNT": 123, "AMOUNT": 12.34, "RATIO": 0.0001,
     "PRICE": Decimal("1.99"), "MEASURE": 2.5, "FLAG": False,
     "WHEN": date(1999, 12, 31), "MOMENT": datetime(1999, 12, 31, 6, 30, 0)},
    {"CODE": "SYNTH-06", "CNT": 5, "AMOUNT": 5.55, "RATIO": 5.0,
     "PRICE": Decimal("5.55"), "MEASURE": 5.5, "FLAG": None,
     "WHEN": date(2001, 1, 1), "MOMENT": datetime(2001, 1, 1, 1, 1, 1)},
]
_PLAIN_DELETED = (3, 5)

_TEXT_TEXTS = {
    "cp1250": f"{PANGRAM} SYNTH-P1250",
    "cp852": f"{PANGRAM} SYNTH-P852",
    "mazovia": f"{PANGRAM} SYNTH-MAZOVIA",
}

_NULLABLE_FIELDS = (
    _field("VC", "V", 20),
    _field("QTY", "N", 10, decimals=2, flags=0x02),
    _field("CNT", "I", 4, flags=0x02),
    _field("NOTE", "C", 10),
    _field("WHEN", "D", 8, flags=0x02),
)
_NULLABLE_RECORDS = [
    {"VC": "padded   ", "QTY": 1.5, "CNT": 10, "NOTE": "x", "WHEN": date(2026, 1, 2)},
    {"VC": "  lead", "QTY": None, "CNT": None, "NOTE": "", "WHEN": None},
    {"VC": None, "QTY": 0.0, "CNT": 0, "NOTE": "", "WHEN": None},
    {"VC": "", "QTY": 2.25, "CNT": -7, "NOTE": "      ", "WHEN": None},
]

_NORTH_FIELDS = (_field("KEY", "C", 8), _field("NAME", "C", 20), _field("SEQ", "I", 4))
_NORTH_RECORDS = [
    {"KEY": "KEY0001", "NAME": "SYNTH-NORTH-1", "SEQ": 1},
    {"KEY": "KEY0002", "NAME": "SYNTH-NORTH-2", "SEQ": 2},
    {"KEY": "KEY0003", "NAME": "SYNTH-NORTH-3", "SEQ": 3},
    {"KEY": "KEY0004", "NAME": "SYNTH-NORTH-4", "SEQ": 4},
    {"KEY": "KEY0009", "NAME": "SYNTH-NORTH-9", "SEQ": 9},
]
_NORTH_DELETED = (4,)

_SOUTH_FIELDS = (_field("KEY", "C", 8), _field("AMOUNT", "N", 8, decimals=2))
_SOUTH_RECORDS = [
    {"KEY": "KEY0001", "AMOUNT": 10.0},
    {"KEY": "KEY0002", "AMOUNT": 20.0},
    {"KEY": "KEY0002", "AMOUNT": 22.0},
    {"KEY": "", "AMOUNT": 0.0},
    {"KEY": "KEY0004", "AMOUNT": 40.0},
    {"KEY": "KEY0003", "AMOUNT": 30.0},
]
_SOUTH_DELETED = (5,)

_MEMO_FIELDS = (
    _field("CODE", "C", 8),
    _field("TXT", "M", 4),
    _field("BIN", "M", 4),
    _field("GEN", "G", 4),
    _field("PIC", "P", 4),
)
_MEMO_RECORDS = [
    {"CODE": "SYNTH-A", "TXT": "Zażółć gęślą jaźń SYNTH-MEMO",
     "BIN": MEMO_BINARY, "GEN": GENERAL_PAYLOAD, "PIC": PICTURE_PAYLOAD},
    {"CODE": "SYNTH-B", "TXT": None, "BIN": None, "GEN": None, "PIC": None},
    {"CODE": "SYNTH-C", "TXT": "DELETED-MEMO-SYNTH", "BIN": b"\x01\x02\x03",
     "GEN": None, "PIC": None},
]
_MEMO_DELETED = (2,)

_NEGATIVE_BASE_FIELDS = (_field("KEY", "C", 8), _field("AMOUNT", "N", 8, decimals=2))
_NEGATIVE_BASE_RECORDS = [
    {"KEY": "KEY0001", "AMOUNT": 1.0},
    {"KEY": "KEY0002", "AMOUNT": 2.0},
    {"KEY": "KEY0003", "AMOUNT": 3.0},
]

_ORPHAN_FIELDS = (_field("TXT", "M", 4),)
_ORPHAN_RECORDS = [{"TXT": "orphan memo payload"}]


# ---------------------------------------------------------------------------
# documented malformed-fixture mutations (test tooling only)
# ---------------------------------------------------------------------------


def _corrupt_truncate_records(source: Path, target: Path, *, record_length: int) -> None:
    """Malformed mutation 1/3: remove exactly one trailing record image.

    Provenance: *source* is a wholly synthetic 3-record table built by this
    tool; the single mutation drops the byte image of the last record so the
    declared record count exceeds the physical record area.  Purpose:
    deterministic ``DBF_TRUNCATED`` delegation evidence.
    """
    data = bytearray(source.read_bytes())
    assert len(data) > record_length
    target.write_bytes(bytes(data[:-record_length]))


def _corrupt_version_byte(source: Path, target: Path) -> None:
    """Malformed mutation 2/3: overwrite the DBF version byte with 0x99.

    Provenance: single-byte mutation of a wholly synthetic table header.
    Purpose: deterministic ``DBF_FORMAT_UNSUPPORTED`` delegation evidence.
    """
    data = bytearray(source.read_bytes())
    data[0] = 0x99
    target.write_bytes(bytes(data))


def _corrupt_header_length(source: Path, target: Path) -> None:
    """Malformed mutation 3/3: declare a header length far beyond EOF.

    Provenance: 2-byte little-endian patch of header bytes 8-9 to 65000 on a
    wholly synthetic table.  Purpose: deterministic header-truncation
    delegation evidence.
    """
    data = bytearray(source.read_bytes())
    struct.pack_into("<H", data, 8, 65000)
    target.write_bytes(bytes(data))


# ---------------------------------------------------------------------------
# corpus generation
# ---------------------------------------------------------------------------


def _build_table(
    out_root: Path,
    relative: str,
    fields: tuple[FieldInfo, ...],
    records: Sequence[Mapping[str, object]],
    deleted: tuple[int, ...],
    *,
    dbversion: int = 0x30,
    driver: int = 0xC8,
    encoding: str = "cp1250",
) -> TableSchema:
    destination = out_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_table(
        destination,
        schema=_schema(fields, dbversion=dbversion, driver=driver, encoding=encoding),
        records=[
            _rec(index, values, deleted=index in deleted)
            for index, values in enumerate(records)
        ],
        overwrite=True,
    )
    return read_schema(destination)


def _dbf_facts(schema: TableSchema, path: Path, *, include_deleted: bool = True) -> dict[str, object]:
    records = list(iter_records(schema.path, include_deleted=include_deleted))
    deleted = sum(1 for record in records if record.deleted)
    info = inspect_table(schema.path)
    return {
        "dbversion_byte": schema.dbversion_byte,
        "language_driver": schema.language_driver,
        "encoding": schema.encoding,
        "record_count": len(records),
        "deleted_records": deleted,
        "field_classes": [f.dbf_type for f in schema.fields if f.dbf_type != "0"],
        "has_memo": schema.has_memo,
        "has_nullflags": any(f.dbf_type == "0" for f in schema.fields),
        "memo_companion_present": schema.memo_companion_present,
        "dbc_bound": schema.dbc_bound,
        "has_structural_cdx": schema.has_structural_cdx,
        "inspection_warnings": list(info.warnings),
    }


def generate(out_root: Path) -> None:
    out_root.mkdir(parents=True, exist_ok=True)
    fixtures: list[dict[str, object]] = []

    def declare(
        fixture_id: str,
        path: Path,
        *,
        artifact_class: str,
        coverage: list[str],
        dbf_facts: dict[str, object] | None = None,
        malformed: dict[str, object] | None = None,
        relationships: dict[str, object] | None = None,
        expectations: dict[str, object] | None = None,
    ) -> None:
        fixtures.append(
            {
                "id": fixture_id,
                "path": path.relative_to(out_root).as_posix(),
                "artifact_class": artifact_class,
                "synthetic": True,
                "generated_by": "tools/generate_p0_fixtures.py",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                **({"dbf": dbf_facts} if dbf_facts else {}),
                **({"malformed": malformed} if malformed else {}),
                **({"relationships": relationships} if relationships else {}),
                **({"expectations": expectations} if expectations else {}),
                "coverage": coverage,
            }
        )

    # A. plain scalar table with deleted records
    plain_schema = _build_table(
        out_root, "plain/plain_customers.dbf", _PLAIN_FIELDS, _PLAIN_RECORDS,
        deleted=_PLAIN_DELETED,
    )
    declare(
        "plain.plain_customers",
        plain_schema.path,
        artifact_class="dbf",
        dbf_facts=_dbf_facts(plain_schema, plain_schema.path),
        coverage=[
            "plain_dbf", "deleted_records", "character", "integer", "numeric",
            "float", "currency", "double", "logical", "date", "datetime", "cp1250",
        ],
        expectations={
            "values": {
                "row0": {
                    "CODE": "SYNTH-01", "CNT": -42, "AMOUNT": 123.45, "RATIO": 2.5,
                    "PRICE": "1234.5678", "MEASURE": 3.14159, "FLAG": True,
                    "WHEN": "2028-02-29", "MOMENT": "2028-02-29T23:59:58",
                }
            },
            "deleted_physical_indexes": [3, 5],
        },
    )

    # B. codepage text cases
    text_schemas: dict[str, TableSchema] = {}
    for encoding, driver in (("cp1250", 0xC8), ("cp852", 0x64), ("mazovia", 0x69)):
        text_fields = (_field("CODE", "C", 4), _field("TEXT", "C", 64))
        text_records = [
            {"CODE": "SYN1", "TEXT": _TEXT_TEXTS[encoding]},
            {"CODE": "SYN2", "TEXT": "ASCII-ONLY-SYNTH-ROW"},
        ]
        text_schemas[encoding] = _build_table(
            out_root, f"text/text_{encoding}.dbf", text_fields, text_records,
            deleted=(), driver=driver, encoding=encoding,
        )
        declare(
            f"text.{encoding}",
            text_schemas[encoding].path,
            artifact_class="dbf",
            dbf_facts=_dbf_facts(text_schemas[encoding], text_schemas[encoding].path),
            coverage=[
                "character", "cp1250" if encoding == "cp1250" else (
                    "cp852" if encoding == "cp852" else "mazovia_piast_text"
                ),
            ],
            expectations={"row0_text": _TEXT_TEXTS[encoding]},
        )

    # C. NULL values + _NullFlags + significant Varchar trailing spaces
    nullable_schema = _build_table(
        out_root, "nullable/nullable_varchar.dbf", _NULLABLE_FIELDS,
        _NULLABLE_RECORDS, deleted=(), dbversion=0x32,
    )
    declare(
        "nullable.nullable_varchar",
        nullable_schema.path,
        artifact_class="dbf",
        dbf_facts=_dbf_facts(nullable_schema, nullable_schema.path),
        coverage=[
            "null_values_and_nullflags", "varchar_significant_trailing_spaces",
            "character", "integer", "numeric", "logical", "date",
        ],
        expectations={
            "row0_varchar": "padded   ",
            "null_row": {"QTY": None, "CNT": None, "WHEN": None},
            "zero_row": {"QTY": 0.0, "CNT": 0},
            "system_column": "_NULLFLAGS",
        },
    )

    # D. cross-table topology: duplicate basenames + shared keys
    north_schema = _build_table(
        out_root, "topology/north/registry.dbf", _NORTH_FIELDS, _NORTH_RECORDS,
        deleted=_NORTH_DELETED,
    )
    declare(
        "topology.north_registry",
        north_schema.path,
        artifact_class="dbf",
        dbf_facts=_dbf_facts(north_schema, north_schema.path),
        coverage=["duplicate_basenames", "shared_cross_table_keys", "character",
                  "integer", "deleted_records"],
        relationships={
            "role": "primary-key-side",
            "shared_key_field": "KEY",
            "shared_key_values": list(SHARED_KEYS),
            "key_uniqueness": "unique-active-rows",
            "duplicate_basename": "registry.dbf",
        },
    )
    south_schema = _build_table(
        out_root, "topology/south/registry.dbf", _SOUTH_FIELDS, _SOUTH_RECORDS,
        deleted=_SOUTH_DELETED,
    )
    declare(
        "topology.south_registry",
        south_schema.path,
        artifact_class="dbf",
        dbf_facts=_dbf_facts(south_schema, south_schema.path),
        coverage=["duplicate_basenames", "shared_cross_table_keys", "character", "numeric"],
        relationships={
            "role": "foreign-key-side",
            "shared_key_field": "KEY",
            "shared_key_values": list(SHARED_KEYS),
            "key_uniqueness": "duplicates-and-empty-key-rows-present",
            "duplicate_basename": "registry.dbf",
        },
    )

    # F. DBF + FPT memo payloads (text memo, binary memo, General, Picture)
    memo_schema = _build_table(
        out_root, "memos/memo_payloads.dbf", _MEMO_FIELDS, _MEMO_RECORDS,
        deleted=_MEMO_DELETED,
    )
    declare(
        "memos.memo_payloads",
        memo_schema.path,
        artifact_class="dbf",
        dbf_facts=_dbf_facts(memo_schema, memo_schema.path),
        coverage=["dbf_fpt", "memo", "general_picture_payloads", "deleted_records", "cp1250"],
        expectations={
            "row0": {
                "TXT": "Zażółć gęślą jaźń SYNTH-MEMO",
                "BIN_hex": MEMO_BINARY.hex(),
                "GEN_hex": GENERAL_PAYLOAD.hex(),
                "PIC_hex": PICTURE_PAYLOAD.hex(),
            },
            "null_memo_row_index": 1,
            "deleted_memo_row_index": 2,
        },
    )
    fpt_path = memo_schema.path.with_suffix(".fpt")
    declare(
        "memos.memo_payloads.fpt",
        fpt_path,
        artifact_class="fpt",
        coverage=["dbf_fpt", "memo", "general_picture_payloads"],
        expectations={"companion_of": "memos.memo_payloads"},
    )

    # H. malformed / negative fixtures (documented deterministic mutations of
    # wholly synthetic tables built into a temporary staging directory)
    with tempfile.TemporaryDirectory(prefix="p0-fixture-staging-") as staging:
        staging_dir = Path(staging)
        malformed_dir = out_root / "malformed"
        malformed_dir.mkdir(parents=True, exist_ok=True)
        negative_base = staging_dir / "negative_base.dbf"
        negative_schema = _build_table(
            staging_dir, "negative_base.dbf", _NEGATIVE_BASE_FIELDS,
            _NEGATIVE_BASE_RECORDS, deleted=(),
        )
        negative_facts = _dbf_facts(negative_schema, negative_schema.path)

        truncated = out_root / "malformed" / "truncated_records.dbf"
        _corrupt_truncate_records(
            negative_schema.path, truncated, record_length=negative_schema.record_length
        )
        declare(
            "malformed.truncated_records",
            truncated,
            artifact_class="dbf-malformed",
            dbf_facts=negative_facts,
            coverage=["malformed_inputs"],
            malformed={
                "mutation": "remove exactly one trailing record image "
                            "(len(data) - record_length bytes kept)",
                "mutation_bytes": negative_schema.record_length,
                "expected": {"operation": "iter_records", "error_code": "DBF_TRUNCATED"},
            },
        )

        unknown_version = out_root / "malformed" / "unknown_version.dbf"
        _corrupt_version_byte(negative_schema.path, unknown_version)
        declare(
            "malformed.unknown_version",
            unknown_version_path := unknown_version,
            artifact_class="dbf-malformed",
            dbf_facts=negative_facts,
            coverage=["malformed_inputs"],
            malformed={
                "mutation": "header byte 0 set to 0x99",
                "mutation_bytes": 1,
                "expected": {"operation": "read_schema", "error_code": "DBF_FORMAT_UNSUPPORTED"},
            },
        )

        bad_layout = out_root / "malformed" / "corrupt_header_length.dbf"
        _corrupt_header_length(negative_schema.path, bad_layout)
        declare(
            "malformed.corrupt_header_length",
            bad_layout,
            artifact_class="dbf-malformed",
            dbf_facts=negative_facts,
            coverage=["malformed_inputs"],
            malformed={
                "mutation": "little-endian header bytes 8-9 set to 65000 "
                            "(declared header length far beyond EOF)",
                "mutation_bytes": 2,
                "expected": {"operation": "read_schema", "error_code": "DBF_TRUNCATED"},
            },
        )

        orphan = staging_dir / "orphan_memo.dbf"
        orphan_schema = _build_table(staging_dir, "orphan_memo.dbf", _ORPHAN_FIELDS,
                                     _ORPHAN_RECORDS, deleted=())
        missing = out_root / "malformed" / "missing_memo_companion.dbf"
        shutil.copyfile(orphan_schema.path, missing)
        assert not missing.with_suffix(".fpt").exists()
        declare(
            "malformed.missing_memo_companion",
            missing,
            artifact_class="dbf-missing-companion",
            dbf_facts={
                "dbversion_byte": orphan_schema.dbversion_byte,
                "language_driver": orphan_schema.language_driver,
                "encoding": orphan_schema.encoding,
                "record_count": 1,
                "deleted_records": 0,
                "field_classes": ["M"],
                "has_memo": True,
                "has_nullflags": False,
                "memo_companion_present": False,
                "dbc_bound": False,
                "has_structural_cdx": False,
                "inspection_warnings": [
                    "Memo fields 'TXT' require a FPT companion file (.fpt) that "
                    "was not found; memo values cannot be read."
                ],
            },
            coverage=["malformed_inputs", "dbf_fpt", "memo"],
            malformed={
                "mutation": "companion produced by construction: the synthetic "
                            "DBF was built through public write_table() in a "
                            "staging directory and only the DBF was published; "
                            "the FPT companion was intentionally not shipped",
                "mutation_bytes": 0,
                "expected": {
                    "operations": [
                        {"operation": "inspect_table", "result": "companion-warning"},
                        {"operation": "iter_records", "memo": "inline",
                         "error_code": "FPT_REQUIRED_MISSING"},
                        {"operation": "iter_records", "result": "lazy-memo-values"},
                    ]
                },
            },
        )

    # G. explicitly declared gaps (no fabricated artifacts)
    coverage: dict[str, list[str]] = {}
    for fixture in fixtures:
        for dimension in cast("list[str]", fixture["coverage"]):
            coverage.setdefault(dimension, []).append(str(fixture["id"]))
    coverage.update(COVERAGE_BY_CAPABILITY_ONLY)

    manifest = {
        "manifest_schema": "req-p0-003/1",
        "generator": {
            "tool": "tools/generate_p0_fixtures.py",
            "dbfbridge": DBFBRIDGE_VERSION,
            "dbfbridge_extra": "write",
            "dbfbridge_import_namespace": "dbfbridge",
            "public_apis_used": [
                "write_table", "read_schema", "iter_records", "inspect_table",
                "DirectRecord", "FieldInfo", "TableSchema",
            ],
            "deterministic": True,
            "pinned_last_update": PINNED_LAST_UPDATE,
            "memo_block_size": MEMO_BLOCK_SIZE,
        },
        "coverage": coverage,
        "gaps": GAPS,
        "fixtures": fixtures,
    }
    manifest_path = out_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    generate(args.out)
    print(f"generated corpus + manifest under {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())