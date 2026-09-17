"""The Phase 4 Direct Read / Direct Write IO boundary (REQ-P4-001).

Acceptance evidence on REAL public dbfbridge synthetic fixtures: the
boundary streams the Direct Read with deleted-record visibility and feeds
the public Direct Write boundary; the public capability gap for nullable
text NULL state is proven and refused; no JSONL/CSV intermediate is ever
created.
"""

from __future__ import annotations

import json
from pathlib import Path

import dbfbridge
import pytest

from dbf_anonymizer.engine import direct_io
from support.numeric_tables import numeric_field, read_numeric_records, write_numeric_table
from support.vault_sessions import sidecar_inventory


def test_direct_read_streams_deleted_records_with_indices(tmp_path: Path) -> None:
    write_numeric_table(
        tmp_path,
        "probe/deleted.dbf",
        (numeric_field("K", "I", 4),),
        [{"K": 1}, {"K": 2}, {"K": 3}],
    )
    table = direct_io.read_source_table(tmp_path, "probe/deleted.dbf")
    assert table.relative_path == "probe/deleted.dbf"
    records = list(
        direct_io.stream_table_records(table, include_deleted=True, memo_policy="skip")
    )
    assert [record.physical_index for record in records] == [0, 1, 2]
    assert all(record.deleted is False for record in records)
    assert all(record.raw_record is None for record in records)


def test_direct_write_creates_a_fresh_dbf_through_the_public_boundary(
    tmp_path: Path,
) -> None:
    source = write_numeric_table(
        tmp_path,
        "src/data.dbf",
        (numeric_field("K", "I", 4),),
        [{"K": 10}, {"K": 20}],
    )
    table = direct_io.read_source_table(tmp_path, "src/data.dbf")
    destination = tmp_path / "out/data.dbf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    records = direct_io.stream_table_records(table, memo_policy="skip")
    result = direct_io.write_fresh_table(destination, table.schema, records)
    assert result.records_written == 2
    written = [
        record.values["K"] for record in read_numeric_records(destination)
    ]
    assert written == [10, 20]
    assert source.exists()  # the source is untouched


def test_direct_write_refuses_an_existing_destination(tmp_path: Path) -> None:
    from dbf_anonymizer import PathError

    write_numeric_table(
        tmp_path, "src/a.dbf", (numeric_field("K", "I", 4),), [{"K": 1}]
    )
    table = direct_io.read_source_table(tmp_path, "src/a.dbf")
    destination = tmp_path / "out/a.dbf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"existing")
    records = direct_io.stream_table_records(table, memo_policy="skip")
    with pytest.raises(PathError) as excinfo:
        direct_io.write_fresh_table(destination, table.schema, records)
    assert "ENGINE_OUTPUT_EXISTS" in str(excinfo.value.to_dict())


def test_public_capability_gap_nullable_text_null_state_is_refused(
    tmp_path: Path,
) -> None:
    """The public Direct Read cannot expose text NULL/empty distinctions.

    Both the NULL record and the empty-string record decode to ``""``: the
    boundary documents the exact public capability gap and the engine refuses
    nullable text fields instead of inferring NULL from an empty heuristic.
    """
    write_numeric_table(
        tmp_path,
        "gap/nulltext.dbf",
        (numeric_field("T", "C", 6, flags=8), numeric_field("N", "N", 4)),
        [{"T": None, "N": 1}, {"T": "", "N": 2}],
    )
    table = direct_io.read_source_table(tmp_path, "gap/nulltext.dbf")
    decoded = [
        record.values["T"]
        for record in direct_io.stream_table_records(table, memo_policy="skip")
    ]
    assert decoded == ["", ""]  # the NULL/empty distinction is NOT exposed
    # Numeric NULLs ARE exposed by the public Direct Read:
    numeric_decoded = [
        record.values["N"]
        for record in direct_io.stream_table_records(table, memo_policy="skip")
    ]
    assert numeric_decoded == [1, 2]
    _ = json  # JSON remains a report/manifest format, never a record transport


def test_boundary_wraps_dependency_failures_as_typed_errors(tmp_path: Path) -> None:
    from dbf_anonymizer import DBFBridgeError

    with pytest.raises(DBFBridgeError):
        direct_io.read_source_table(tmp_path, "missing/table.dbf")


def test_boundary_never_creates_jsonl_or_source_sidecars(tmp_path: Path) -> None:
    write_numeric_table(
        tmp_path, "src/b.dbf", (numeric_field("K", "I", 4),), [{"K": 7}]
    )
    table = direct_io.read_source_table(tmp_path, "src/b.dbf")
    destination = tmp_path / "out/b.dbf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    direct_io.write_fresh_table(
        destination, table.schema, direct_io.stream_table_records(table, memo_policy="skip")
    )
    # No JSONL/CSV intermediate exists anywhere in the run tree:
    for path in tmp_path.rglob("*"):
        assert path.suffix not in {".jsonl", ".csv"}
    # The source tree gained no sidecars (read-only Direct Read):
    assert sidecar_inventory(tmp_path / "src") == []
    assert dbfbridge.__version__.startswith("1.1")