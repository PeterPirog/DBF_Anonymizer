"""Synthetic DBF/FPT dataset helper for the DBF_Anonymizer examples.

EXAMPLE SUPPORT ONLY — this module is not part of the public DBF_Anonymizer
API and is not exported from ``dbf_anonymizer``.  Its only purpose is to keep
the pedagogic examples focused on the DBF_Anonymizer workflow instead of
``dbfbridge`` schema boilerplate.

Facts kept true by construction:

- only PUBLIC ``dbfbridge`` Direct Write / Direct Read APIs are used; this
  module implements no DBF/FPT parsing or writing of its own;
- every value is a fixed, deterministic synthetic constant (no production,
  customer or organizational content, no private machine paths);
- no network access, no VFP/COM, no subprocesses;
- the same dataset is rebuilt byte-identically on every run.

Run ``python examples/synthetic_dataset.py [SOURCE_ROOT]`` to create the
two-table demo dataset (``people.dbf`` + ``orders.dbf``) without any other
step.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

import dbfbridge

_LANGUAGE_DRIVER = 0x03
_ENCODING = "cp1252"


def _field(name: str, dbf_type: str, length: int) -> dbfbridge.FieldInfo:
    """One public ``FieldInfo`` of a synthetic table."""
    return dbfbridge.FieldInfo(
        ordinal=0,
        name=name,
        dbf_type=dbf_type,
        length=length,
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
    )


def _schema(path: Path, fields: tuple[dbfbridge.FieldInfo, ...]) -> dbfbridge.TableSchema:
    """A public ``TableSchema`` for one synthetic table."""
    return dbfbridge.TableSchema(
        path=path,
        record_count=0,
        header_length=32 + 32 * len(fields) + 1,
        record_length=sum(field.length for field in fields) + 1,
        language_driver=_LANGUAGE_DRIVER,
        encoding=_ENCODING,
        has_memo=False,
        has_memo_flag=False,
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
        memo_block_size=None,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def _write_table(
    path: Path,
    fields: tuple[dbfbridge.FieldInfo, ...],
    rows: tuple[dict[str, Any], ...],
) -> None:
    """Write one deterministic synthetic table through the public writer."""
    dbfbridge.write_table(
        path,
        schema=_schema(path, fields),
        records=[
            dbfbridge.DirectRecord(physical_index=index, deleted=False, values=row)
            for index, row in enumerate(rows)
        ],
    )


def create_single_table_dataset(root: Path) -> Path:
    """Create the minimal one-table demo dataset: ``people.dbf``."""
    root.mkdir(parents=True, exist_ok=True)
    _write_table(
        root / "people.dbf",
        (_field("ID", "I", 4), _field("NAME", "C", 24)),
        (
            {"ID": 1, "NAME": "SYNTH-ANNA"},
            {"ID": 2, "NAME": "SYNTH-BRUNO"},
            {"ID": 3, "NAME": "SYNTH-CAROL"},
        ),
    )
    return root


def create_related_dataset(root: Path) -> Path:
    """Create the two-table demo dataset with a real PK/FK-compatible domain.

    ``people.dbf`` carries the PRIMARY ``ID`` domain; ``orders.dbf`` carries
    the FOREIGN ``PERSON_ID`` domain whose values are drawn from it.
    """
    root.mkdir(parents=True, exist_ok=True)
    _write_table(
        root / "people.dbf",
        (_field("ID", "I", 4), _field("NAME", "C", 24)),
        (
            {"ID": 1, "NAME": "SYNTH-ANNA"},
            {"ID": 2, "NAME": "SYNTH-BRUNO"},
            {"ID": 3, "NAME": "SYNTH-CAROL"},
        ),
    )
    _write_table(
        root / "orders.dbf",
        (_field("ORDER_NO", "I", 4), _field("PERSON_ID", "I", 4)),
        (
            {"ORDER_NO": 100, "PERSON_ID": 1},
            {"ORDER_NO": 101, "PERSON_ID": 2},
            {"ORDER_NO": 102, "PERSON_ID": 2},
        ),
    )
    return root


def policy_relationship_document() -> dict[str, Any]:
    """The declared PK/FK relationship document for the demo dataset."""
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "orders-person-id-people-id",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": "people.dbf",
                        "field": "ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                    {
                        "table": "orders.dbf",
                        "field": "PERSON_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                ],
            }
        ],
    }


def _main() -> None:
    """CLI helper: create the synthetic two-table demo dataset."""
    if len(sys.argv) > 1:
        source = Path(sys.argv[1])
    else:
        source = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-example-dataset-")) / "source"
    create_related_dataset(source)
    print(f"synthetic demo dataset created: {source}")
    print(f"tables: people.dbf, orders.dbf (in {source})")


if __name__ == "__main__":
    _main()
