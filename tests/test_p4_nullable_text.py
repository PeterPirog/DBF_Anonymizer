"""Nullable logical-value regressions for the P4 two-pass engine.

Fixtures and verification use only the public dbfbridge Direct Read/Write
boundary.  Application records carry logical values; dbfbridge exclusively
owns the VFP _NullFlags bitmap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import dbfbridge
import pytest

from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import direct_io, run_two_pass
from dbf_anonymizer.vault.mappings import memo_recovery_rows, text_mapping_rows
from dbf_anonymizer.vault.store import VaultDatabase
from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID
from support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table,
    write_numeric_table_with_deleted,
)


def _text_mappings(plan: Any, vault_path: Path) -> dict[str, str]:
    vault = VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version=str(dbfbridge.__version__),
    )
    try:
        return {
            original: pseudonym
            for original, pseudonym, _length in text_mapping_rows(
                vault, GLOBAL_TEXT_DOMAIN_ID
            )
        }
    finally:
        vault.close()


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


def test_nullable_character_end_to_end_preserves_null_empty_deleted_and_mappings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    write_numeric_table_with_deleted(
        source_root,
        "character.dbf",
        (numeric_field("TXT", "C", 8, flags=NULLABLE_FLAG),),
        [
            ({"TXT": None}, False),
            ({"TXT": ""}, False),
            ({"TXT": "ALPHA"}, False),
            ({"TXT": "ALPHA"}, True),
            ({"TXT": "BETA"}, False),
        ],
    )

    public_write = direct_io.dbfbridge.write_table
    supplied_records = {"count": 0}

    def inspect_write(destination: object, **kwargs: object):
        records = kwargs["records"]

        def logical_records():
            for record in records:  # type: ignore[union-attr]
                supplied_records["count"] += 1
                assert all(
                    str(name).upper() != "_NULLFLAGS" for name in record.values
                )
                yield record

        kwargs["records"] = logical_records()
        return public_write(destination, **kwargs)

    monkeypatch.setattr(direct_io.dbfbridge, "write_table", inspect_write)
    plan, result, output_root, vault_path = _run(source_root, tmp_path)

    output = tuple(
        dbfbridge.iter_records(
            output_root / "character.dbf", include_deleted=True
        )
    )
    values = [record.values["TXT"] for record in output]
    assert values[0] is None
    assert values[1] == ""
    assert values[2] == values[3]
    assert values[2] not in {"", "ALPHA"}
    assert values[4] not in {"", "BETA", values[2]}
    assert [record.deleted for record in output] == [False, False, False, True, False]
    assert result.pass1_deleted_scanned == 1
    assert result.text_allocated == 2
    assert supplied_records["count"] == 5
    mappings = _text_mappings(plan, vault_path)
    assert set(mappings) == {"ALPHA", "BETA"}
    assert len(mappings) == 2


def test_nullable_varchar_preserves_significant_values_and_mapping_partition(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    originals = [None, "", " ", "A", "A ", "A  ", "B"]
    write_numeric_table_with_deleted(
        source_root,
        "varchar.dbf",
        (numeric_field("TXT", "V", 8, flags=NULLABLE_FLAG),),
        [({"TXT": value}, index == 5) for index, value in enumerate(originals)],
    )
    plan, result, output_root, vault_path = _run(source_root, tmp_path)

    output = tuple(
        dbfbridge.iter_records(output_root / "varchar.dbf", include_deleted=True)
    )
    values = [record.values["TXT"] for record in output]
    assert values[0] is None
    assert values[1] == ""
    assert all(isinstance(value, str) and value for value in values[2:])
    assert all(values[index] != originals[index] for index in range(2, len(values)))
    assert len(set(values[2:])) == 5
    assert output[5].deleted is True
    assert result.text_allocated == 5
    mappings = _text_mappings(plan, vault_path)
    assert set(mappings) == {" ", "A", "A ", "A  ", "B"}
    assert len(mappings) == 5


def test_nullable_text_relation_projection_preserves_null_empty_and_counts(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    write_numeric_table(
        source_root,
        "parent.dbf",
        (numeric_field("KEY", "C", 8, flags=NULLABLE_FLAG),),
        [{"KEY": None}, {"KEY": ""}, {"KEY": "A"}, {"KEY": "B"}],
    )
    write_numeric_table(
        source_root,
        "child.dbf",
        (numeric_field("KEY", "V", 8, flags=NULLABLE_FLAG),),
        [
            {"KEY": None},
            {"KEY": ""},
            {"KEY": "A"},
            {"KEY": "A"},
            {"KEY": "ORPHAN"},
        ],
    )
    document = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-nullable-text",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "parent.dbf",
                        "field": "KEY",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                    {
                        "table": "child.dbf",
                        "field": "KEY",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "V",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                ],
            }
        ],
    }
    _plan, result, output_root, _vault_path = _run(
        source_root, tmp_path, relationship_document=document
    )

    summary = result.relations[0]
    assert summary.relation_id == "rel-nullable-text"
    assert summary.verified
    assert summary.before_nulls == summary.after_nulls == 1
    assert summary.before_unique == summary.after_unique == 3
    assert summary.matched_rows == 3
    assert summary.orphan_count == 1
    assert summary.parent_profile_equal
    assert summary.foreign_profile_equal
    parent = tuple(dbfbridge.iter_records(output_root / "parent.dbf"))
    child = tuple(dbfbridge.iter_records(output_root / "child.dbf"))
    assert parent[0].values["KEY"] is None
    assert parent[1].values["KEY"] == ""
    assert child[0].values["KEY"] is None
    assert child[1].values["KEY"] == ""
    assert child[2].values["KEY"] == child[3].values["KEY"]


def test_nullable_identity_numeric_preserves_none_zero_and_nonzero(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    write_numeric_table(
        source_root,
        "numeric.dbf",
        (numeric_field("VALUE", "I", 4, flags=NULLABLE_FLAG),),
        [{"VALUE": None}, {"VALUE": 0}, {"VALUE": 7}, {"VALUE": -5}],
    )
    _plan, result, output_root, _vault_path = _run(source_root, tmp_path)
    output = tuple(dbfbridge.iter_records(output_root / "numeric.dbf"))
    assert [record.values["VALUE"] for record in output] == [None, 0, 7, -5]
    assert result.text_allocated == 0


def test_nullable_memo_preserves_null_and_masks_empty_and_nonempty(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_table(
        source_root,
        "memo.dbf",
        (numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),),
        [{"NOTE": None}, {"NOTE": ""}, {"NOTE": "ABC"}],
    )
    plan = build_plan(source_root, output_root, vault_path)
    run_two_pass(plan)

    output = tuple(
        dbfbridge.iter_records(output_root / "memo.dbf", memo="inline")
    )
    values = [record.values["NOTE"] for record in output]
    assert values[0] is None
    assert values[1] == values[2] == "[MASKED-MEMO]"
    assert values[1] != "" and values[2] != "ABC"

    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
    ) as vault:
        table_id = str(vault.tables()[0]["table_id"])
        rows = memo_recovery_rows(vault, table_id)
        assert [row["physical_record_index"] for row in rows] == [1, 2]
        assert [bytes(row["original_payload"]) for row in rows] == [b"", b"ABC"]
        registered_names = {
            str(row[0])
            for row in vault._internal_connection().execute(
                "SELECT name FROM fields ORDER BY name"
            )
        }
        assert registered_names == {"NOTE"}
