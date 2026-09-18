"""BLOCKER 6 regressions: failure output cleanup never swallows errors.

``_discard_written`` must attempt removal of every artifact the run created,
collect removal failures boundedly and SURFACE a typed cleanup/publication
safety failure — while the original operation failure stays identifiable
(chained ``__cause__``) and no path or value ever enters the error boundary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dbf_anonymizer import CancellationError, build_plan
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.errors import PublicationError
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


def _plan(tmp_path: Path):
    source_root = tmp_path / "source"
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 8), numeric_field("NAME", "C", 8)),
        [{"CUST_ID": "KEY-01", "NAME": "ALFA"}],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 8), numeric_field("NAME", "C", 8)),
        [{"CUST_ID": "KEY-01", "NAME": "O1"}],
    )
    return build_plan(
        str(source_root),
        str(tmp_path / "output"),
        str(tmp_path / "vault" / "dictionary.sqlite3"),
        relationship_document=_DOCUMENT,
    )


def _cancel_after_first_pass2_table() -> tuple[object, object]:
    """A cancellation that fires after the first pass-2 table is written."""
    state = {"written": False}

    def progress(event: object) -> None:
        if (
            getattr(event, "phase_code", "") == "PASS2_WRITE"
            and getattr(event, "event_code", "") == "PROGRESS"
            and getattr(event, "table_path", None) == _TABLES[0]
        ):
            state["written"] = True

    def cancel() -> bool:
        return state["written"]

    return progress, cancel


def test_injected_unlink_failure_surfaces_typed_cleanup_error(
    tmp_path: Path,
) -> None:
    """One artifact cannot be removed: the run must NOT silently claim a
    clean failure — a typed publication-safety refusal is raised and the
    original cancellation stays its chained cause."""
    progress, cancel = _cancel_after_first_pass2_table()
    real_unlink = Path.unlink
    failed: list[str] = []

    def failing_unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name == _TABLES[0].rsplit("/", 1)[-1]:
            failed.append(self.name)
            raise OSError("injected unlink failure")
        real_unlink(self, missing_ok=missing_ok)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "unlink", failing_unlink)
        with pytest.raises(PublicationError) as excinfo:
            run_two_pass(_plan(tmp_path), progress=progress, cancel_check=cancel)
    # The original operation failure (the cancellation) is preserved as the
    # chained cause of the typed cleanup-safety refusal.
    assert isinstance(excinfo.value.__cause__, CancellationError)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_OUTPUT_CLEANUP_FAILED"
    )
    # The unlink attempt really failed (truthful: the artifact stays).
    assert failed
    assert (tmp_path / "output" / _TABLES[0]).exists()
    # No path or value leakage in the typed boundary.
    boundary = (
        str(excinfo.value)
        + repr(excinfo.value)
        + str(excinfo.value.to_dict())
    )
    assert str(tmp_path) not in boundary
    assert _TABLES[0] not in boundary
    assert "KEY-01" not in boundary
    assert "ALFA" not in boundary


def test_successful_cleanup_keeps_the_plain_operation_failure(
    tmp_path: Path,
) -> None:
    """With NO injected unlink failure the same cancellation still removes
    every written artifact and surfaces the ORIGINAL typed failure."""
    progress, cancel = _cancel_after_first_pass2_table()
    with pytest.raises(CancellationError):
        run_two_pass(_plan(tmp_path), progress=progress, cancel_check=cancel)
    assert not (tmp_path / "output" / _TABLES[0]).exists()
    assert not (tmp_path / "output" / _TABLES[1]).exists()
    assert not list((tmp_path / "output").rglob("*.fpt"))