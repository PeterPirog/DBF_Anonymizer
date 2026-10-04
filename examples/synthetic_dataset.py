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
- the same dataset is rebuilt byte-identically on every run;
- an EXPLICITLY supplied workspace must NOT exist yet: the helper refuses an
  existing target BEFORE creating or writing anything (fail-closed, no
  overwrite, no silent reuse, no ``--force``); automatically allocated
  ``tempfile`` workspaces are always fresh by construction;
- stdout stays privacy-safe: bounded summaries only, never resolved paths.

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
_NULLABLE_FLAG = 0x02
_NULLFLAGS_NAME = "_NULLFLAGS"
_NULLFLAGS_TYPE = "0"
_NULLFLAGS_SYSTEM_FLAG = 0x01


def require_fresh_workspace(work_root: Path) -> Path:
    """Fail-closed EXAMPLE workspace guard (examples-only safety policy).

    An explicitly supplied workspace must not exist yet: the examples never
    write into, reuse or overwrite an existing tree, and refuse BEFORE
    creating or writing any DBF/FPT file.  Production path policy is not
    involved; this guard only protects the demo helper's callers.
    """
    if work_root.exists():
        print("refused: the supplied workspace already exists (examples never overwrite)")
        print("use a NEW directory for the demo workspace")
        raise SystemExit(2)
    return work_root


def _field(name: str, dbf_type: str, length: int, *, flags: int = 0) -> dbfbridge.FieldInfo:
    """One public ``FieldInfo`` of a synthetic table."""
    return dbfbridge.FieldInfo(
        ordinal=0,
        name=name,
        dbf_type=dbf_type,
        length=length,
        decimal_count=0,
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


def _with_nullflags(fields: tuple[dbfbridge.FieldInfo, ...]) -> tuple[dbfbridge.FieldInfo, ...]:
    """Append the writer-managed ``_NULLFLAGS`` system column when needed."""
    needs_bitmap = any((field.flags & _NULLABLE_FLAG) or field.dbf_type == "V" for field in fields)
    if not needs_bitmap:
        return fields
    null_bits = sum(
        1 for field in fields if (field.flags & _NULLABLE_FLAG) or field.dbf_type == "V"
    )
    return (
        *fields,
        _field(
            _NULLFLAGS_NAME, _NULLFLAGS_TYPE, (null_bits + 7) // 8, flags=_NULLFLAGS_SYSTEM_FLAG
        ),
    )


def _schema(path: Path, fields: tuple[dbfbridge.FieldInfo, ...]) -> dbfbridge.TableSchema:
    """A public ``TableSchema`` for one synthetic table."""
    ordered = _with_nullflags(fields)
    return dbfbridge.TableSchema(
        path=path,
        record_count=0,
        header_length=32 + 32 * len(ordered) + 1,
        record_length=sum(field.length for field in ordered) + 1,
        language_driver=_LANGUAGE_DRIVER,
        encoding=_ENCODING,
        has_memo=any(field.is_memo for field in ordered),
        has_memo_flag=any(field.is_memo for field in ordered),
        has_structural_cdx=False,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
        table_flags=0,
        fields=ordered,
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
        memo_block_size=64 if any(field.is_memo for field in ordered) else None,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def _write_table(
    path: Path,
    fields: tuple[dbfbridge.FieldInfo, ...],
    entries: tuple[tuple[dict[str, Any], bool], ...],
) -> None:
    """Write one deterministic synthetic table through the public writer.

    The physical record order is the input order; the deleted marker is
    preserved by the public writer.
    """
    dbfbridge.write_table(
        path,
        schema=_schema(path, fields),
        records=[
            dbfbridge.DirectRecord(physical_index=index, deleted=deleted, values=row)
            for index, (row, deleted) in enumerate(entries)
        ],
    )


def create_single_table_dataset(root: Path) -> Path:
    """Create the minimal one-table demo dataset: ``people.dbf``.

    ``root`` must not exist (fail-closed: the demo helper never overwrites).
    """
    root.mkdir(parents=True)
    _write_table(
        root / "people.dbf",
        (_field("ID", "I", 4), _field("NAME", "C", 24)),
        (
            ({"ID": 1, "NAME": "SYNTH-ANNA"}, False),
            ({"ID": 2, "NAME": "SYNTH-BRUNO"}, False),
            ({"ID": 3, "NAME": "SYNTH-CAROL"}, False),
        ),
    )
    return root


def create_related_dataset(root: Path) -> Path:
    """Create the two-table demo dataset with a real PK/FK-compatible domain.

    ``people.dbf`` carries the PRIMARY ``ID`` domain; ``orders.dbf`` carries
    the FOREIGN ``PERSON_ID`` domain whose values are drawn from it.  ``root``
    must not exist (fail-closed).
    """
    root.mkdir(parents=True)
    _write_table(
        root / "people.dbf",
        (_field("ID", "I", 4), _field("NAME", "C", 24)),
        (
            ({"ID": 1, "NAME": "SYNTH-ANNA"}, False),
            ({"ID": 2, "NAME": "SYNTH-BRUNO"}, False),
            ({"ID": 3, "NAME": "SYNTH-CAROL"}, False),
        ),
    )
    _write_table(
        root / "orders.dbf",
        (_field("ORDER_NO", "I", 4), _field("PERSON_ID", "I", 4)),
        (
            ({"ORDER_NO": 100, "PERSON_ID": 1}, False),
            ({"ORDER_NO": 101, "PERSON_ID": 2}, False),
            ({"ORDER_NO": 102, "PERSON_ID": 2}, False),
        ),
    )
    return root


def create_field_semantics_dataset(root: Path) -> Path:
    """Create the advanced demo dataset for DBF/VFP field semantics.

    ``registry.dbf`` demonstrates the privacy-critical field facts on one
    deterministic synthetic table (built through the public writer only):

    - ``ID`` (Integer, kept as a key under the default policy);
    - ``NAME`` (nullable Character) — NULL stays NULL, "" stays "";
    - ``VARVAL`` (nullable Varchar) — same pseudonym domain as Character;
    - ``NOTE`` (text memo, FPT companion) — freshly written and masked;
    - one DELETED record whose sensitive content is still transformed.
    """
    root.mkdir(parents=True)
    _write_table(
        root / "registry.dbf",
        (
            _field("ID", "I", 4),
            _field("NAME", "C", 16, flags=_NULLABLE_FLAG),
            _field("VARVAL", "V", 16, flags=_NULLABLE_FLAG),
            _field("NOTE", "M", 4),
        ),
        (
            ({"ID": 1, "NAME": "SYNTH-A", "VARVAL": "V-SYNTH-A", "NOTE": "MEMO-CANARY-A"}, False),
            ({"ID": 2, "NAME": None, "VARVAL": None, "NOTE": "MEMO-CANARY-B"}, False),
            ({"ID": 3, "NAME": "SYNTH-A", "VARVAL": "V-SYNTH-A", "NOTE": "MEMO-CANARY-A"}, True),
            ({"ID": 4, "NAME": "SYNTH-B", "VARVAL": "", "NOTE": "MEMO-CANARY-C"}, False),
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


def workspace_from_arguments(
    example_name: str,
) -> Path:
    """Resolve the example workspace: explicit argument (must be NEW) or TEMP.

    Automatically allocated ``tempfile`` workspaces are always fresh; an
    explicitly supplied workspace is fail-closed refused when it exists.
    """
    if len(sys.argv) > 1:
        return require_fresh_workspace(Path(sys.argv[1]))
    return Path(tempfile.mkdtemp(prefix=f"dbf-anonymizer-example-{example_name}-"))


def _main() -> None:
    """CLI helper: create the synthetic two-table demo dataset (bounded output)."""
    if len(sys.argv) > 1:
        source = require_fresh_workspace(Path(sys.argv[1]))
    else:
        source = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-example-dataset-")) / "source"
    create_related_dataset(source)
    print("synthetic demo dataset created (tables: people.dbf, orders.dbf)")
    print("workspace: the location you supplied (not echoed for privacy)")


if __name__ == "__main__":
    _main()
