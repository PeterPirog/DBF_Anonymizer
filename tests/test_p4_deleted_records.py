"""Deleted-record transformation and physical fidelity for REQ-P4-005."""

from __future__ import annotations

import hashlib
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping

import dbfbridge
import pytest

from dbf_anonymizer import CancellationError, build_plan
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.engine.state import spool_artifacts
from dbf_anonymizer.vault.store import VaultDatabase
from support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table_with_deleted,
)


def _run(
    source_root: Path,
    tmp_path: Path,
    *,
    relationship_document: Mapping[str, Any] | None = None,
):
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    plan = build_plan(
        source_root,
        output_root,
        vault_path,
        relationship_document=relationship_document,
    )
    result = run_two_pass(plan)
    return plan, result, output_root, vault_path


def _sequence(path: Path) -> list[tuple[int, bool]]:
    return [
        (record.physical_index, record.deleted)
        for record in dbfbridge.iter_records(path, include_deleted=True)
    ]


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_deleted_nullable_character_and_varchar_use_same_text_domain(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source = write_numeric_table_with_deleted(
        source_root,
        "text.dbf",
        (
            numeric_field("CHARVAL", "C", 16, flags=NULLABLE_FLAG),
            numeric_field("VARVAL", "V", 16, flags=NULLABLE_FLAG),
        ),
        [
            ({"CHARVAL": "ALPHA", "VARVAL": "V-ALPHA"}, False),
            ({"CHARVAL": "ALPHA", "VARVAL": "V-ALPHA"}, True),
            ({"CHARVAL": "BETA", "VARVAL": "V-BETA"}, False),
            ({"CHARVAL": "BETA", "VARVAL": "V-BETA"}, True),
            ({"CHARVAL": None, "VARVAL": None}, False),
            ({"CHARVAL": None, "VARVAL": None}, True),
            ({"CHARVAL": "", "VARVAL": ""}, False),
            ({"CHARVAL": "", "VARVAL": ""}, True),
        ],
    )
    source_sequence = _sequence(source)

    _plan, result, output_root, _vault_path = _run(source_root, tmp_path)
    output_path = output_root / "text.dbf"
    records = tuple(dbfbridge.iter_records(output_path, include_deleted=True))
    chars = [record.values["CHARVAL"] for record in records]
    varchars = [record.values["VARVAL"] for record in records]

    assert source_sequence == _sequence(output_path) == [
        (0, False),
        (1, True),
        (2, False),
        (3, True),
        (4, False),
        (5, True),
        (6, False),
        (7, True),
    ]
    assert chars[0] == chars[1] and chars[0] not in {"", "ALPHA"}
    assert chars[2] == chars[3] and chars[2] not in {"", "BETA", chars[0]}
    assert varchars[0] == varchars[1] and varchars[0] not in {"", "V-ALPHA"}
    assert varchars[2] == varchars[3] and varchars[2] not in {
        "",
        "V-BETA",
        varchars[0],
    }
    assert chars[4:6] == [None, None]
    assert varchars[4:6] == [None, None]
    assert chars[6:8] == ["", ""]
    assert varchars[6:8] == ["", ""]
    assert result.pass1_deleted_scanned == 4


def _numeric_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "deleted-numeric",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": "parent.dbf",
                        "field": "KEY",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                    {
                        "table": "child.dbf",
                        "field": "KEY",
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


def test_deleted_numeric_keys_share_mapping_and_relation_evidence(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    write_numeric_table_with_deleted(
        source_root,
        "parent.dbf",
        (numeric_field("KEY", "I", 4),),
        [({"KEY": -5}, False), ({"KEY": 7}, True)],
    )
    child_source = write_numeric_table_with_deleted(
        source_root,
        "child.dbf",
        (numeric_field("KEY", "I", 4, flags=NULLABLE_FLAG),),
        [
            ({"KEY": -5}, False),
            ({"KEY": -5}, True),
            ({"KEY": 7}, False),
            ({"KEY": 7}, True),
            ({"KEY": 99}, False),
            ({"KEY": None}, True),
        ],
    )

    _plan, result, output_root, _vault_path = _run(
        source_root, tmp_path, relationship_document=_numeric_document()
    )
    parents = tuple(
        dbfbridge.iter_records(output_root / "parent.dbf", include_deleted=True)
    )
    children = tuple(
        dbfbridge.iter_records(output_root / "child.dbf", include_deleted=True)
    )
    parent_values = [record.values["KEY"] for record in parents]
    child_values = [record.values["KEY"] for record in children]

    assert _sequence(child_source) == _sequence(output_root / "child.dbf")
    assert parent_values[0] != -5 and parent_values[1] != 7
    assert child_values[:4] == [
        parent_values[0],
        parent_values[0],
        parent_values[1],
        parent_values[1],
    ]
    assert child_values[4] not in {99, parent_values[0], parent_values[1]}
    assert child_values[5] is None
    summary = result.relations[0]
    assert summary.verified
    assert summary.before_rows == summary.after_rows == 8
    assert summary.before_unique == summary.after_unique == 2
    assert summary.before_nulls == summary.after_nulls == 1
    assert summary.matched_rows == 4
    assert summary.orphan_count == 1
    assert summary.parent_profile_equal and summary.foreign_profile_equal


def test_deleted_temporal_values_share_persisted_offset_and_keep_time(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    first_date = date(2020, 2, 29)
    second_date = date(2024, 1, 15)
    first_time = datetime(2020, 2, 29, 6, 7, 8)
    second_time = datetime(2024, 1, 15, 21, 22, 23)
    source = write_numeric_table_with_deleted(
        source_root,
        "temporal.dbf",
        (
            numeric_field("DAY", "D", 8, flags=NULLABLE_FLAG),
            numeric_field("STAMP", "T", 8, flags=NULLABLE_FLAG),
        ),
        [
            ({"DAY": first_date, "STAMP": first_time}, False),
            ({"DAY": first_date, "STAMP": first_time}, True),
            ({"DAY": second_date, "STAMP": second_time}, False),
            ({"DAY": None, "STAMP": None}, True),
        ],
    )

    _plan, result, output_root, _vault_path = _run(source_root, tmp_path)
    output_path = output_root / "temporal.dbf"
    output = tuple(dbfbridge.iter_records(output_path, include_deleted=True))
    days = [record.values["DAY"] for record in output]
    stamps = [record.values["STAMP"] for record in output]
    offset = (days[0] - first_date).days

    assert _sequence(source) == _sequence(output_path)
    assert result.temporal_offset_allocated
    assert offset != 0
    assert days[0] == days[1]
    assert (days[2] - second_date).days == offset
    assert stamps[0] == stamps[1]
    assert (stamps[0].date() - first_time.date()).days == offset
    assert (stamps[2].date() - second_time.date()).days == offset
    assert stamps[0].time() == first_time.time()
    assert stamps[2].time() == second_time.time()
    assert days[3] is None and stamps[3] is None


def _composite_document() -> dict[str, object]:
    members: list[dict[str, object]] = []
    for table, role, nullable in (
        ("parent.dbf", "PRIMARY", False),
        ("child.dbf", "FOREIGN", True),
    ):
        for ordinal, name in enumerate(("PART_A", "PART_B"), start=1):
            members.append(
                {
                    "table": table,
                    "field": name,
                    "role": role,
                    "ordinal": ordinal,
                    "dbf_type": "C",
                    "byte_width": 8,
                    "encoding": "cp1250",
                    "nullable": nullable,
                }
            )
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "deleted-composite",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": members,
            }
        ],
    }


def test_deleted_composite_relations_preserve_tuple_multiplicity(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    write_numeric_table_with_deleted(
        source_root,
        "parent.dbf",
        (numeric_field("PART_A", "C", 8), numeric_field("PART_B", "C", 8)),
        [
            ({"PART_A": "A", "PART_B": "ONE"}, False),
            ({"PART_A": "B", "PART_B": "TWO"}, True),
        ],
    )
    write_numeric_table_with_deleted(
        source_root,
        "child.dbf",
        (
            numeric_field("PART_A", "C", 8, flags=NULLABLE_FLAG),
            numeric_field("PART_B", "C", 8, flags=NULLABLE_FLAG),
        ),
        [
            ({"PART_A": "A", "PART_B": "ONE"}, False),
            ({"PART_A": "A", "PART_B": "ONE"}, True),
            ({"PART_A": "B", "PART_B": "TWO"}, False),
            ({"PART_A": "B", "PART_B": "TWO"}, True),
            ({"PART_A": "X", "PART_B": "NINE"}, False),
            ({"PART_A": None, "PART_B": "TWO"}, True),
        ],
    )

    _plan, result, output_root, _vault_path = _run(
        source_root, tmp_path, relationship_document=_composite_document()
    )
    parents = tuple(
        dbfbridge.iter_records(output_root / "parent.dbf", include_deleted=True)
    )
    children = tuple(
        dbfbridge.iter_records(output_root / "child.dbf", include_deleted=True)
    )
    parent_tuples = [
        (record.values["PART_A"], record.values["PART_B"]) for record in parents
    ]
    child_tuples = [
        (record.values["PART_A"], record.values["PART_B"]) for record in children
    ]

    assert child_tuples[:4] == [
        parent_tuples[0],
        parent_tuples[0],
        parent_tuples[1],
        parent_tuples[1],
    ]
    summary = result.relations[0]
    assert summary.verified
    assert summary.before_rows == summary.after_rows == 8
    assert summary.before_nulls == summary.after_nulls == 1
    assert summary.before_unique == summary.after_unique == 2
    assert summary.matched_rows == 4
    assert summary.orphan_count == 1
    assert summary.parent_profile_equal and summary.foreign_profile_equal


def test_cancellation_with_deleted_records_preserves_source_and_cleans_output(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    source_paths = []
    for name in ("first.dbf", "second.dbf"):
        source_paths.append(
            write_numeric_table_with_deleted(
                source_root,
                name,
                (numeric_field("SECRET", "C", 24),),
                [
                    ({"SECRET": "ACTIVE-PRIVATE"}, False),
                    ({"SECRET": "DELETED-PRIVATE"}, True),
                    ({"SECRET": "ACTIVE-OTHER"}, False),
                    ({"SECRET": "DELETED-OTHER"}, True),
                ],
            )
        )
    before_hashes = _hash_tree(source_root)
    before_records = {
        path.name: [
            (record.physical_index, record.deleted, record.values["SECRET"])
            for record in dbfbridge.iter_records(path, include_deleted=True)
        ]
        for path in source_paths
    }
    plan = build_plan(source_root, output_root, vault_path)
    state = {"first_written": False}

    def progress(event: object) -> None:
        if (
            getattr(event, "phase_code", None) == "PASS2_WRITE"
            and getattr(event, "event_code", None) == "PROGRESS"
            and getattr(event, "table_path", None) == "first.dbf"
        ):
            state["first_written"] = True

    def cancel() -> bool:
        return state["first_written"]

    with pytest.raises(CancellationError):
        run_two_pass(plan, progress=progress, cancel_check=cancel)

    assert state["first_written"]
    assert _hash_tree(source_root) == before_hashes
    after_records = {
        path.name: [
            (record.physical_index, record.deleted, record.values["SECRET"])
            for record in dbfbridge.iter_records(path, include_deleted=True)
        ]
        for path in source_paths
    }
    assert after_records == before_records
    assert not output_root.exists() or not tuple(output_root.rglob("*.dbf"))
    assert not output_root.exists() or not tuple(output_root.rglob("*.fpt"))
    assert spool_artifacts(vault_path.parent) == []
    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
    ) as vault:
        vault.verify()
