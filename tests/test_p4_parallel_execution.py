"""REQ-P4-008 bounded table-parallel execution acceptance evidence."""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import dbfbridge
import pytest

from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import pass2 as pass2_module
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.vault.store import VaultDatabase
from tests.support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table_with_deleted,
)


def _relationships() -> dict[str, object]:
    members = (
        ("north/data.dbf", "PRIMARY", True),
        ("south/data.dbf", "FOREIGN", True),
    )
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-text",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": table,
                        "field": "TEXT_KEY",
                        "role": role,
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": nullable,
                    }
                    for table, role, nullable in members
                ],
            },
            {
                "relation_id": "rel-number",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": table,
                        "field": "NUMBER_KEY",
                        "role": role,
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": nullable,
                    }
                    for table, role, nullable in members
                ],
            },
        ],
    }


def _write_dataset(source: Path) -> None:
    fields = (
        numeric_field("TEXT_KEY", "C", 12, flags=NULLABLE_FLAG),
        numeric_field("NUMBER_KEY", "I", 4, flags=NULLABLE_FLAG),
        numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
    )
    write_numeric_table_with_deleted(
        source,
        "north/data.dbf",
        fields,
        [
            ({"TEXT_KEY": "PARENT-1", "NUMBER_KEY": -7, "NOTE": "MEMO-N-1"}, False),
            ({"TEXT_KEY": "PARENT-2", "NUMBER_KEY": 5, "NOTE": None}, True),
            ({"TEXT_KEY": "PARENT-3", "NUMBER_KEY": 99, "NOTE": ""}, False),
        ],
    )
    write_numeric_table_with_deleted(
        source,
        "south/data.dbf",
        fields,
        [
            ({"TEXT_KEY": "PARENT-1", "NUMBER_KEY": -7, "NOTE": "MEMO-S-1"}, True),
            ({"TEXT_KEY": "PARENT-1", "NUMBER_KEY": -7, "NOTE": ""}, False),
            ({"TEXT_KEY": "ORPHAN", "NUMBER_KEY": 1234, "NOTE": None}, False),
            ({"TEXT_KEY": None, "NUMBER_KEY": None, "NOTE": "MEMO-S-NULL"}, False),
        ],
    )
    write_numeric_table_with_deleted(
        source,
        "archive/memo.dbf",
        fields,
        [
            ({"TEXT_KEY": "ARCHIVE", "NUMBER_KEY": 42, "NOTE": "MEMO-ARCHIVE"}, False),
            ({"TEXT_KEY": None, "NUMBER_KEY": None, "NOTE": None}, True),
        ],
    )


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _logical_tree(root: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    result: dict[str, tuple[tuple[object, ...], ...]] = {}
    for path in sorted(root.rglob("*.dbf")):
        rows = tuple(
            (
                record.physical_index,
                record.deleted,
                tuple(sorted(record.values.items())),
            )
            for record in dbfbridge.iter_records(
                path, include_deleted=True, memo="inline"
            )
        )
        result[path.relative_to(root).as_posix()] = rows
    return result


def _vault_mapping_snapshot(plan: object, vault_path: Path) -> tuple[object, ...]:
    dataset = plan.dataset  # type: ignore[attr-defined]
    policy = plan.policy  # type: ignore[attr-defined]
    relationships = plan.relationships  # type: ignore[attr-defined]
    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=dataset.source_fingerprint,
        expected_policy_fingerprint=policy.policy_fingerprint,
        expected_relationship_fingerprint=relationships.relationship_fingerprint,
    ) as vault:
        connection = vault._internal_connection()
        return (
            tuple(
                connection.execute(
                    "SELECT domain_id, original_value, pseudonym_value "
                    "FROM text_mappings ORDER BY domain_id, original_value"
                )
            ),
            tuple(
                connection.execute(
                    "SELECT domain_id, original_value, pseudonym_value "
                    "FROM numeric_key_mappings ORDER BY domain_id, original_value"
                )
            ),
            tuple(
                connection.execute(
                    "SELECT table_id, physical_record_index, field_id, "
                    "hex(original_payload), payload_kind FROM memo_recovery "
                    "ORDER BY table_id, physical_record_index, field_id"
                )
            ),
        )


def test_workers_one_and_many_are_same_vault_equivalent_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    _write_dataset(source)
    source_before = _hash_tree(source)
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    output_one = tmp_path / "output-one"
    plan_one = build_plan(
        source, output_one, vault_path, relationship_document=_relationships()
    )
    result_one = run_two_pass(plan_one, workers=1)
    mapping_snapshot = _vault_mapping_snapshot(plan_one, vault_path)

    barrier = threading.Barrier(3)
    guard = threading.Lock()
    active = 0
    peak = 0
    worker_threads: set[int] = set()
    destinations: list[Path] = []
    real_write = pass2_module.write_fresh_table

    def coordinated_write(*args: object, **kwargs: object):
        nonlocal active, peak
        assert isinstance(args[0], (str, Path))
        destination = Path(args[0])
        with guard:
            active += 1
            peak = max(peak, active)
            worker_threads.add(threading.get_ident())
            destinations.append(destination)
        barrier.wait(timeout=30)
        try:
            return real_write(*args, **kwargs)  # type: ignore[arg-type]
        finally:
            with guard:
                active -= 1

    monkeypatch.setattr(pass2_module, "write_fresh_table", coordinated_write)
    callback_threads: list[int] = []
    output_many = tmp_path / "output-many"
    plan_many = build_plan(
        source, output_many, vault_path, relationship_document=_relationships()
    )
    result_many = run_two_pass(
        plan_many,
        workers=3,
        progress=lambda _event: callback_threads.append(threading.get_ident()),
        cancel_check=lambda: False,
    )

    assert peak == 3
    assert len(worker_threads) == 3
    assert callback_threads and set(callback_threads) == {threading.get_ident()}
    assert len({destination.parent for destination in destinations}) == 3
    assert all(output_many not in destination.parents for destination in destinations)
    assert result_one.tables_written == result_many.tables_written
    assert result_one.relations == result_many.relations
    assert result_one.all_relations_verified and result_many.all_relations_verified
    assert result_one.pass1_deleted_scanned == result_many.pass1_deleted_scanned == 3
    assert _logical_tree(output_one) == _logical_tree(output_many)
    assert _hash_tree(output_one) == _hash_tree(output_many)
    assert _vault_mapping_snapshot(plan_many, vault_path) == mapping_snapshot
    assert _hash_tree(source) == source_before


def test_parallel_same_vault_stress_is_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_dataset(source)
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    reference_output = tmp_path / "reference"
    reference_plan = build_plan(
        source,
        reference_output,
        vault_path,
        relationship_document=_relationships(),
    )
    run_two_pass(reference_plan, workers=1)
    reference_logical = _logical_tree(reference_output)
    reference_hashes = _hash_tree(reference_output)
    mapping_snapshot = _vault_mapping_snapshot(reference_plan, vault_path)

    for iteration in range(3):
        output = tmp_path / f"parallel-{iteration}"
        plan = build_plan(
            source, output, vault_path, relationship_document=_relationships()
        )
        result = run_two_pass(plan, workers=3)
        assert result.all_relations_verified
        assert _logical_tree(output) == reference_logical
        assert _hash_tree(output) == reference_hashes
        assert _vault_mapping_snapshot(plan, vault_path) == mapping_snapshot
