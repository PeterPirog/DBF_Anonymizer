"""BLOCKER 5 regressions: EXACTLY one source stream per table per pass.

REQ-P4-002 requires one-shot per-pass evidence at the REAL production Direct
Read boundary: pass 1 opens exactly ONE ``iter_records`` stream per table,
pass 2 opens exactly ONE per table, and no allocation/finalization phase
re-opens any DBF (SQLite spool state may be scanned freely — DBF streams may
not).  Two independent proofs are combined:

* the PRODUCTION instrumentation (:attr:`TwoPassResult.read_streams`) counts
  the streams the engine itself opened, in order;
* a TEST-side wrapper around the public ``dbfbridge.iter_records`` symbol
  counts every REAL reader invocation at the true boundary — a hidden third
  read the production counter missed could not hide from it.  Test-side
  post-run verification reads are intentionally NOT performed in these
  fixtures, so no verification read can ever enter any counter.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

import dbfbridge
from dbf_anonymizer import CancellationError, build_plan
from dbf_anonymizer.engine import run_two_pass
from support.numeric_tables import numeric_field, write_numeric_table

_DOCUMENT = {
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

_TABLES = ("north/customers.dbf", "south/orders.dbf")


def _write_dataset(source_root: Path) -> None:
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 8), numeric_field("NAME", "C", 8)),
        [
            {"CUST_ID": "KEY-01", "NAME": "ALFA"},
            {"CUST_ID": "KEY-02", "NAME": "BETA"},
        ],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 8), numeric_field("NAME", "C", 8)),
        [{"CUST_ID": "KEY-01", "NAME": "O1"}],
    )


def _plan(tmp_path: Path):
    source_root = tmp_path / "source"
    _write_dataset(source_root)
    return build_plan(
        str(source_root),
        str(tmp_path / "output"),
        str(tmp_path / "vault" / "dictionary.sqlite3"),
        relationship_document=_DOCUMENT,
    )


class _BoundaryCounter:
    """A test-side invocation counter over the REAL public reader symbol."""

    def __init__(self) -> None:
        self.by_table: Counter[str] = Counter()
        self.total = 0

    def __enter__(self) -> "_BoundaryCounter":
        real = dbfbridge.iter_records

        def counting_iter_records(path: object, *args: object, **kwargs: object):
            name = Path(str(path)).as_posix()
            for table in _TABLES:
                if name.endswith(table):
                    self.by_table[table] += 1
                    break
            self.total += 1
            return real(path, *args, **kwargs)

        self._patch = pytest.MonkeyPatch()
        self._patch.setattr(dbfbridge, "iter_records", counting_iter_records)
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._patch.undo()


def test_two_table_success_exactly_one_stream_per_table_per_pass(
    tmp_path: Path,
) -> None:
    expected: tuple[tuple[str, str], ...] = ()
    for table in _TABLES:
        expected += (("pass1", table),)
    for table in _TABLES:
        expected += (("pass2", table),)
    with _BoundaryCounter() as counter:
        result = run_two_pass(_plan(tmp_path))
    # Production instrumentation: deterministic phase order, one per pair.
    assert result.read_streams == expected
    # True-boundary proof: the public reader was invoked EXACTLY once per
    # table per pass — a hidden third DBF read could not hide.
    assert dict(counter.by_table) == {
        "north/customers.dbf": 2,
        "south/orders.dbf": 2,
    }
    assert counter.total == 4
    assert result.all_relations_verified


def test_cancellation_mid_pass_one_opens_no_pass_two_stream(
    tmp_path: Path,
) -> None:
    """Cancel right after the first pass-1 table completes: the second
    table's pass-1 stream never opens and pass 2 opens nothing at all."""
    state = {"pass1_first_done": False}

    def progress(event: object) -> None:
        if (
            getattr(event, "phase_code", "") == "PASS1_SCAN"
            and getattr(event, "event_code", "") == "PROGRESS"
            and getattr(event, "table_path", None) == _TABLES[0]
        ):
            state["pass1_first_done"] = True

    def cancel() -> bool:
        return state["pass1_first_done"]

    with _BoundaryCounter() as counter:
        with pytest.raises(CancellationError):
            run_two_pass(_plan(tmp_path), progress=progress, cancel_check=cancel)
    assert counter.by_table["north/customers.dbf"] == 1
    assert counter.by_table["south/orders.dbf"] == 0
    assert counter.total == 1
    assert not (tmp_path / "output" / "north" / "customers.dbf").exists()
    assert not (tmp_path / "output" / "south" / "orders.dbf").exists()


def test_cancellation_mid_pass_two_closes_after_first_table(
    tmp_path: Path,
) -> None:
    """Cancel right after the first pass-2 table is written: pass 1 read
    both tables once, pass 2 read only the first table, nothing else."""
    state = {"pass2_first_done": False}

    def progress(event: object) -> None:
        if (
            getattr(event, "phase_code", "") == "PASS2_WRITE"
            and getattr(event, "event_code", "") == "PROGRESS"
            and getattr(event, "table_path", None) == _TABLES[0]
        ):
            state["pass2_first_done"] = True

    def cancel() -> bool:
        return state["pass2_first_done"]

    with _BoundaryCounter() as counter:
        with pytest.raises(CancellationError):
            run_two_pass(_plan(tmp_path), progress=progress, cancel_check=cancel)
    assert counter.by_table["north/customers.dbf"] == 2
    assert counter.by_table["south/orders.dbf"] == 1
    assert counter.total == 3
    assert not (tmp_path / "output" / "north" / "customers.dbf").exists()
    assert not (tmp_path / "output" / "south" / "orders.dbf").exists()


def test_finalization_never_reopens_any_dbf(tmp_path: Path) -> None:
    """PASS1_FINALIZE allocates from the SQLite spool only: between the last
    pass-1 stream and the first pass-2 stream no reader invocation occurs."""
    events: list[tuple[str, str]] = []
    state = {"phase": "pass1"}

    def progress(event: object) -> None:
        phase = getattr(event, "phase_code", "")
        code = getattr(event, "event_code", "")
        if code == "STARTED" and phase in ("PASS1_FINALIZE", "PASS2_WRITE"):
            state["phase"] = str(phase).lower()
            events.append((str(code), str(phase)))

    real = dbfbridge.iter_records

    def counting_iter_records(path: object, *args: object, **kwargs: object):
        events.append((state["phase"], Path(str(path)).name))
        return real(path, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(dbfbridge, "iter_records", counting_iter_records)
        result = run_two_pass(_plan(tmp_path), progress=progress)
    finalize_reads = [event for event in events if event[0] == "pass1_finalize"]
    assert finalize_reads == []
    assert result.pass1_records_scanned == 3
    assert result.pass2_records_written == 3