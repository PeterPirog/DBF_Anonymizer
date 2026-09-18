"""The reproducible Phase 4 two-pass benchmark harness (REQ-P0-005/P4-002).

Machine-readable JSON plus a human summary over SYNTHETIC fixtures only.
It records the optional Phase 4 metrics (pass1 read/sqlite/finalize time,
pass2 read/write time, peak memory, evidence-spool bytes) WITHOUT deleting
or renaming any established metric and WITHOUT fabricating a release
baseline (the field pipeline is not complete; the final baseline profile is
owned by the P0-005 release acceptance).

Usage:
    python tools/bench_two_pass.py --customers 1500 --orders 600 \
        --output bench_two_pass.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import tracemalloc
from datetime import date, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.support.numeric_tables import (  # noqa: E402
    numeric_field,
    write_numeric_table,
)
from dbf_anonymizer import build_plan  # noqa: E402
from dbf_anonymizer.engine import run_two_pass  # noqa: E402

BENCH_SCHEMA_VERSION = "1.0"

DOCUMENT = {
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
                    "byte_width": 14,
                    "encoding": "cp1250",
                    "nullable": False,
                },
                {
                    "table": "south/orders.dbf",
                    "field": "CUST_ID",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "C",
                    "byte_width": 14,
                    "encoding": "cp1250",
                    "nullable": False,
                },
            ],
        }
    ],
}


def _write_dataset(source_root: Path, customers: int, orders: int) -> None:
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 14), numeric_field("AMT", "N", 9)),
        [
            {"CUST_ID": f"CUST{index:09d}", "AMT": index}
            for index in range(customers)
        ],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 14), numeric_field("AMT", "N", 9)),
        [
            {"CUST_ID": f"CUST{index % customers:09d}", "AMT": index}
            for index in range(orders)
        ],
    )


def run_benchmark(customers: int, orders: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as workdir:
        root = Path(workdir)
        source_root = root / "source"
        output_root = root / "out"
        vault_path = root / "vault" / "dictionary.sqlite3"
        fixture_start = time.perf_counter()
        _write_dataset(source_root, customers, orders)
        fixture_seconds = time.perf_counter() - fixture_start
        plan = build_plan(
            str(source_root),
            str(output_root),
            str(vault_path),
            relationship_document=DOCUMENT,
        )
        tracemalloc.start()
        started = time.perf_counter()
        result = run_two_pass(plan)
        run_seconds = time.perf_counter() - started
        _current, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return {
        "schema_version": BENCH_SCHEMA_VERSION,
        "generated_at": date.today().isoformat(),
        "fixture": {
            "customers": customers,
            "orders": orders,
            "build_seconds": round(fixture_seconds, 4),
        },
        "metrics": {
            "pass1_records_scanned": result.pass1_records_scanned,
            "pass1_deleted_scanned": result.pass1_deleted_scanned,
            "pass2_records_written": result.pass2_records_written,
            "text_allocated": result.text_allocated,
            "text_reused": result.text_reused,
            "run_total_seconds": round(run_seconds, 4),
            "peak_traced_bytes": peak_bytes,
            "evidence_spool_bytes": result.evidence_spool_bytes,
            "relations_verified": result.all_relations_verified,
        },
        "notes": (
            "Synthetic reproducible fixture; no release baseline is "
            "fabricated. The pass-level timing split (pass1 read/sqlite/"
            "finalize, pass2 read/write) becomes authoritative when the "
            "final P4 field pipeline lands (P4-003/004)."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--customers", type=int, default=1500)
    parser.add_argument("--orders", type=int, default=600)
    parser.add_argument("--output", type=str, default=None)
    arguments = parser.parse_args()
    report = run_benchmark(arguments.customers, arguments.orders)
    machine = json.dumps(report, sort_keys=True, indent=2)
    if arguments.output:
        Path(arguments.output).write_text(machine, encoding="utf-8")
    print(machine)
    print("## human summary")
    metrics = report["metrics"]
    print(
        f"tables scanned/written: {metrics['pass1_records_scanned']}/"
        f"{metrics['pass2_records_written']} records; "
        f"text mappings: {metrics['text_allocated']} allocated "
        f"({metrics['text_reused']} reused); "
        f"run: {metrics['run_total_seconds']}s; "
        f"peak traced: {metrics['peak_traced_bytes']} bytes; "
        f"relations verified: {metrics['relations_verified']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
