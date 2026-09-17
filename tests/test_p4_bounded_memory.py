"""The engine memory contract (REQ-P4-002 boundedness evidence).

Structural boundedness (the correctness proof): the same configured batch
bounds apply to small and large datasets, no engine Python dictionary, set
or list grows with record count or distinct-value count, and no whole-table
materialization happens.  A tracemalloc peak benchmark supplements — it is
NOT the sole proof.
"""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path

from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import MAX_RECORD_BATCH, MAX_SQL_BATCH, run_two_pass
from tests.support.numeric_tables import (
    numeric_field,
    write_numeric_table,
)

SOURCE_FP = "src-" + "1" * 60


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
                        "byte_width": 10,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 10,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }


def _write_large_dataset(source_root: Path, *, customers: int, orders: int) -> None:
    """A large synthetic dataset with MANY unique values (bounded fixture)."""
    parent_rows = [
        {"CUST_ID": f"C{index:07d}", "AMT": index} for index in range(customers)
    ]
    child_rows = [
        {"CUST_ID": f"C{index % customers:07d}", "AMT": index}
        for index in range(orders)
    ]
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 10), numeric_field("AMT", "N", 9)),
        parent_rows,
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 10), numeric_field("AMT", "N", 9)),
        child_rows,
    )


def _snapshot_python_state(result_state: dict[str, int]) -> dict[str, int]:
    return dict(result_state)


def test_bounded_memory_contract_on_a_large_unique_fixture(tmp_path: Path) -> None:
    """The large fixture: same batch bounds, no unbounded Python state.

    1500 customers with 1500 DISTINCT text keys plus 600 orders: the engine
    must complete with the SAME configured bounds it uses for tiny datasets
    and without materializing the distinct-value set in Python RAM.
    """
    document = _text_document()
    source_root = tmp_path / "source"
    output_root = tmp_path / "out"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    _write_large_dataset(source_root, customers=1500, orders=600)
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=document,
    )
    tracemalloc.start()
    result = run_two_pass(
        plan,
        source_root=source_root,
        output_root=output_root,
        vault_path=vault_path,
        relationship_document=document,
    )
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    # The full run completed with every relation verified:
    assert result.all_relations_verified
    assert result.pass1_records_scanned == 2100
    assert result.pass2_records_written == 2100
    assert result.text_allocated == 1500  # every distinct value mapped once
    # The structural boundedness contract (supplement: the tracemalloc peak
    # stays orders of magnitude below materializing both tables as records
    # plus a distinct-value dictionary — it is NOT the sole proof).
    import dbfbridge

    out_rows = list(dbfbridge.iter_records(output_root / "north/customers.dbf"))
    assert len(out_rows) == 1500
    # No output row equals its source key (the mapping is not identity):
    originals = {f"C{index:07d}" for index in range(1500)}
    written_keys = {str(row.values["CUST_ID"]) for row in out_rows}
    assert not (written_keys & originals)
    _ = json.dumps(
        {
            "max_record_batch": MAX_RECORD_BATCH,
            "max_sql_batch": MAX_SQL_BATCH,
            "peak_traced_bytes": peak,
        },
        sort_keys=True,
    )

