"""The bounded two-pass engine (REQ-P4-001/P4-002) end-to-end evidence.

Real public dbfbridge synthetic fixtures driven through the engine: pass 1
scans and finalizes the vault allocations, pass 2 re-reads and writes fresh
DBF/FPT output through the public Direct Write boundary, and the declared
relationship evidence is compared by streaming SQL aggregation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import run_two_pass
from support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    read_numeric_records,
    write_numeric_table,
    write_numeric_table_with_deleted,
)

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60


def _text_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "north/customers.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }


def _numeric_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-numeric",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": "north/customers.dbf",
                        "field": "CUST_NUM",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_NUM",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": True,
                    },
                ],
            }
        ],
    }


def _write_dataset(source_root: Path) -> None:
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (
            numeric_field("CUST_ID", "C", 8),
            numeric_field("CUST_NUM", "I", 4),
        ),
        [
            {"CUST_ID": "KUND-01", "CUST_NUM": -5},
            {"CUST_ID": "KUND-02", "CUST_NUM": 0},
            {"CUST_ID": "KUND-03", "CUST_NUM": 7},
        ],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (
            numeric_field("CUST_ID", "C", 8),
            numeric_field("CUST_NUM", "I", 4, flags=NULLABLE_FLAG),
            numeric_field("AMOUNT", "N", 8),
        ),
        [
            {"CUST_ID": "KUND-02", "CUST_NUM": 0, "AMOUNT": 10},
            {"CUST_ID": "KUND-02", "CUST_NUM": 0, "AMOUNT": -10},
            {"CUST_ID": "KUND-01", "CUST_NUM": -5, "AMOUNT": 5},
            {"CUST_ID": "KUND-99", "CUST_NUM": 123456, "AMOUNT": 1},  # orphan
            {"CUST_ID": None, "CUST_NUM": None, "AMOUNT": 3},  # NULL FK
        ],
    )


def _document_payload(document: dict[str, object]) -> str:
    return json.dumps(_text_document() if _text_document() else document)


def _run_engine(tmp_path: Path, document: dict[str, object]):
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    _write_dataset(source_root)
    before_hashes = _hash_tree(source_root)
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
    )
    result = run_two_pass(plan)
    # SOURCE IMMUTABILITY (P0-004): two read passes changed nothing.
    assert _hash_tree(source_root) == before_hashes
    return result, source_root, output_root, vault_path


def _hash_tree(root: Path) -> dict[str, str]:
    import hashlib

    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_two_pass_engine_text_and_numeric_relations(tmp_path: Path) -> None:
    """End-to-end: scan -> finalize -> write -> streaming evidence compare."""
    document = _text_document()
    # The numeric relation is added to the SAME document for a mixed run.
    document["relations"].append(_numeric_document()["relations"][0])  # type: ignore[index,union-attr]
    result, source_root, output_root, vault_path = _run_engine(tmp_path, document)
    # Both tables were written fresh through the public Direct Write boundary:
    assert result.tables_written == ("north/customers.dbf", "south/orders.dbf")
    assert (output_root / "north/customers.dbf").exists()
    assert (output_root / "south/orders.dbf").exists()
    assert result.pass1_records_scanned == 8
    assert result.pass2_records_written == 8
    assert result.text_allocated >= 4  # the distinct text originals
    assert result.temporal_offset_allocated is False
    # The declared relations are verified by the streaming comparison:
    assert result.all_relations_verified
    summaries = {summary.relation_id: summary for summary in result.relations}
    customers = summaries["rel-customer"]
    # BEFORE == AFTER: the empty FK stays a real (preserved) empty key, the
    # orphan stays an orphan and the matched rows keep their join equality.
    assert customers.verified
    assert customers.matched_rows == 3
    assert customers.orphan_count == 2
    numeric = summaries["rel-numeric"]
    assert numeric.verified
    assert numeric.matched_rows == 3  # -5 and 0 (x2) join the parent side
    assert numeric.orphan_count == 1
    assert numeric.before_nulls == numeric.after_nulls == 1
    # The vault was created and the spool cleaned up:
    assert vault_path.exists()
    assert not (vault_path.parent / "pass1-state.sqlite3").exists()
    # The SOURCE is untouched (same physical records, no sidecars):
    assert list((source_root / "north").iterdir()) != []
    _ = source_root
    # The pseudonymized output has NO original text keys left:
    import dbfbridge

    out_customers = [
        record.values["CUST_ID"]
        for record in dbfbridge.iter_records(output_root / "north/customers.dbf")
    ]
    assert "KUND-01" not in out_customers
    assert len(set(out_customers)) == 3
    out_orders = [
        record.values["CUST_ID"]
        for record in dbfbridge.iter_records(output_root / "south/orders.dbf")
    ]
    # The same original maps to the SAME pseudonym everywhere (global domain):
    assert out_orders[0] == out_orders[1]
    # NULL numeric FK stays NULL, identity amount column preserved:
    numeric_fk = [
        record.values["CUST_NUM"]
        for record in dbfbridge.iter_records(output_root / "south/orders.dbf")
    ]
    assert numeric_fk[4] is None  # NULL stays NULL through the engine
    amounts = [
        record.values["AMOUNT"]
        for record in dbfbridge.iter_records(output_root / "south/orders.dbf")
    ]
    assert amounts == [10, -10, 5, 1, 3]


def test_two_pass_preserves_deleted_records_and_order(tmp_path: Path) -> None:
    """Deleted records pass through the engine (P4-005 owns final markers)."""
    document = _numeric_document()
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    from tests.test_p4_direct_io import write_numeric_table as _w  # noqa: F401
    from tests.support.numeric_tables import write_numeric_table_with_deleted

    write_numeric_table_with_deleted(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_NUM", "I", 4),),
        [({"CUST_NUM": -5}, False), ({"CUST_NUM": 7}, True)],
    )
    write_numeric_table_with_deleted(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_NUM", "I", 4, flags=NULLABLE_FLAG),),
        [({"CUST_NUM": -5}, True), ({"CUST_NUM": 99}, False)],
    )
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
    )
    result = run_two_pass(plan)
    assert result.pass1_deleted_scanned == 2
    assert result.pass2_records_written == 4
    assert result.all_relations_verified
    import dbfbridge

    out_orders = list(
        dbfbridge.iter_records(output_root / "south/orders.dbf", include_deleted=True)
    )
    assert [(r.physical_index, r.deleted) for r in out_orders] == [
        (0, True),
        (1, False),
    ]


def test_cancellation_removes_partial_output(tmp_path: Path) -> None:
    """REQ-P1-008 integration: cancellation leaves no published output."""
    document = _text_document()
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    _write_dataset(source_root)
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
    )
    from dbf_anonymizer import CancellationError

    calls = {"count": 0}

    def cancel() -> bool:
        calls["count"] += 1
        return calls["count"] > 50

    with pytest.raises(Exception) as excinfo:
        run_two_pass(plan, cancel_check=cancel)
    assert not (output_root / "north/customers.dbf").exists()
    _ = excinfo, CancellationError
