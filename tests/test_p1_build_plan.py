"""REQ-P1-005 — read-only deterministic build planning evidence.

Proves: filesystem side-effect-free, deterministic plan, privacy-safe
serialization, correct source/policy/relationship fingerprints, and
correct strategy identification.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

import dbfbridge
from dbf_anonymizer import (
    build_plan,
    Plan,
    PlanExecutionContext,
    PolicySummary,
    RelationshipMetadata,
    RelationalAssuranceLevel,
    TransferProfile,
)
from dbf_anonymizer.errors import AnonymizerError, PathError, PolicyError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_source(dest: Path) -> None:
    """Create a small valid synthetic source dataset using public dbfbridge."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    def _field(name: str, dbf_type: str, length: int, decimals: int = 0):
        return dbfbridge.FieldInfo(
            ordinal=0, name=name, dbf_type=dbf_type, length=length,
            decimal_count=decimals, address=0, flags=0, index_field_flag=0,
            autoincrement_next_value=0, autoincrement_step=1,
            is_memo=dbf_type in {"M", "G", "P"}, is_binary=False,
            supported=True, dbversion_byte=0x30,
        )

    def _schema(fields: tuple) -> dbfbridge.TableSchema:
        return dbfbridge.TableSchema(
            path=Path("memory:test"), record_count=0,
            header_length=32 + 32 * len(fields) + 1,
            record_length=sum(f.length for f in fields) + 1,
            language_driver=0xC8, encoding="cp1250",
            has_memo=False, has_memo_flag=False, has_structural_cdx=False,
            is_database_container=False, dbc_bound=False, dbc_backlink_path=None,
            table_flags=0, fields=fields, warnings=(),
            dbversion_byte=0x30, dbversion_name="Visual FoxPro",
            last_update=None, incomplete_transaction=False, encryption_flag=False,
            memo_companion_format=None, memo_companion_present=False,
            memo_companion_path=None, memo_companion_size_bytes=None,
            memo_block_size=None, memo_next_free_block=None,
            companion_cdx_present=False, companion_cdx_path=None,
        )

    # Plain table: text + numeric fields
    (dest / "customers").mkdir()
    dbfbridge.write_table(
        dest / "customers" / "customers.dbf",
        schema=_schema((_field("ID", "N", 10, 0), _field("NAME", "C", 50), _field("CITY", "C", 30), _field("AMT", "N", 12, 2))),
        records=[
            {"ID": 1, "NAME": "Alice", "CITY": "Paris", "AMT": 100.50},
            {"ID": 2, "NAME": "Bob", "CITY": "Rome", "AMT": 200.75},
            {"ID": 3, "NAME": "Carol", "CITY": "Berlin", "AMT": 300.00},
        ],
    )

    # Memo table
    (dest / "notes").mkdir()
    dbfbridge.write_table(
        dest / "notes" / "notes.dbf",
        schema=_schema((_field("TITLE", "C", 40), _field("BODY", "M", 4))),
        records=[
            {"TITLE": "Meeting", "BODY": "Discussed project timeline."},
            {"TITLE": "Follow-up", "BODY": "Action items assigned."},
        ],
    )

    # Duplicate basenames in nested dirs
    (dest / "north").mkdir()
    (dest / "south").mkdir()
    dbfbridge.write_table(
        dest / "north" / "registry.dbf",
        schema=_schema((_field("KEY", "C", 10), _field("VALUE", "C", 20))),
        records=[{"KEY": "K1", "VALUE": "North-1"}, {"KEY": "K2", "VALUE": "North-2"}],
    )
    dbfbridge.write_table(
        dest / "south" / "registry.dbf",
        schema=_schema((_field("KEY", "C", 10), _field("VALUE", "C", 20))),
        records=[{"KEY": "K1", "VALUE": "South-1"}, {"KEY": "K2", "VALUE": "South-2"}],
    )


def _sha256_files(root: Path) -> dict[str, str]:
    """Return {relative_posix_path: sha256} for all files under root."""
    result: dict[str, str] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for fname in filenames:
            p = Path(dirpath) / fname
            rel = p.relative_to(root).as_posix()
            h = hashlib.sha256()
            with p.open("rb") as fh:
                while chunk := fh.read(65536):
                    h.update(chunk)
            result[rel] = h.hexdigest()
    return result


def _assert_no_absolute_paths(obj: Any) -> None:
    """Recursively assert no value in the serialized dict is an absolute path."""
    if isinstance(obj, dict):
        for v in obj.values():
            _assert_no_absolute_paths(v)
    elif isinstance(obj, list):
        for item in obj:
            _assert_no_absolute_paths(item)
    elif isinstance(obj, str):
        assert not obj.startswith("/"), f"absolute POSIX path found: {obj}"
        assert not (len(obj) >= 3 and obj[1] == ":"), f"absolute Windows path found: {obj}"
        assert not obj.startswith("\\"), f"UNC path found: {obj}"


def _collect_strings(obj: Any) -> list[str]:
    if isinstance(obj, dict):
        out: list[str] = []
        for v in obj.values():
            out.extend(_collect_strings(v))
        return out
    elif isinstance(obj, (list, tuple)):
        out = []
        for item in obj:
            out.extend(_collect_strings(item))
        return out
    elif isinstance(obj, str):
        return [obj]
    return []


# ---------------------------------------------------------------------------
# Basic functional tests
# ---------------------------------------------------------------------------

def test_build_plan_returns_plan_instance(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(
        source=src,
        output=tmp_path / "output",
        vault=tmp_path / "vault" / "dictionary.sqlite3",
        policy=None,
        relationships=None,
    )
    assert isinstance(plan, Plan)
    assert plan.plan_id.startswith("plan-")
    assert len(plan.tables) > 0
    assert plan.dataset.source_fingerprint
    assert isinstance(plan.execution_context, PlanExecutionContext)


def test_build_plan_root_import_works() -> None:
    import dbf_anonymizer

    assert callable(dbf_anonymizer.build_plan)


# ---------------------------------------------------------------------------
# Filesystem side-effect tests (Phase 16)
# ---------------------------------------------------------------------------

def test_source_tree_byte_identical_after_success(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    before = _sha256_files(src)

    build_plan(
        source=src,
        output=tmp_path / "output",
        vault=tmp_path / "vault" / "dict.sqlite3",
    )

    after = _sha256_files(src)
    assert before == after, "source tree was modified by build_plan"


def test_non_existing_output_remains_non_existing(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    out = tmp_path / "does_not_exist_output"

    build_plan(source=src, output=out, vault=tmp_path / "vault")

    assert not out.exists()


def test_non_existing_vault_remains_non_existing(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    vault = tmp_path / "vault_dir" / "dictionary.sqlite3"

    build_plan(source=src, output=tmp_path / "out", vault=vault)

    assert not vault.parent.exists()
    assert not vault.exists()


def test_no_staging_lock_log_files_created(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    before_snapshot = set(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))

    build_plan(
        source=src,
        output=tmp_path / "output",
        vault=tmp_path / "vault" / "dict.sqlite3",
    )

    after_snapshot = set(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    new_files = after_snapshot - before_snapshot
    assert not new_files, f"build_plan created files: {new_files}"


def test_existing_empty_output_dir_not_modified(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    out = tmp_path / "output"
    out.mkdir()
    out_before = sorted(p.name for p in out.iterdir())

    build_plan(source=src, output=out, vault=tmp_path / "vault")

    out_after = sorted(p.name for p in out.iterdir())
    assert out_before == out_after == []


def test_build_plan_failure_is_side_effect_free(tmp_path: Path) -> None:
    empty_src = tmp_path / "empty_source"
    empty_src.mkdir()

    with pytest.raises(AnonymizerError):
        build_plan(
            source=empty_src,
            output=tmp_path / "output",
            vault=tmp_path / "vault",
        )

    created = [p for p in tmp_path.rglob("*") if p.name not in ("empty_source",)]
    assert not created, f"files created despite failure: {created}"


# ---------------------------------------------------------------------------
# Deterministic plan tests (Phase 17)
# ---------------------------------------------------------------------------

def test_identical_inputs_produce_equal_plan_dicts(tmp_path: Path) -> None:
    src1 = tmp_path / "src1"
    src2 = tmp_path / "src2"
    _make_valid_source(src1)
    _make_valid_source(src2)

    policy = {"schema_version": 1, "profile": "SAFE_TRANSFER", "indexes": {"profile": "DATA_ONLY"}}

    plan1 = build_plan(
        source=src1,
        output=tmp_path / "out1",
        vault=tmp_path / "v1",
        policy=policy,
    )
    plan2 = build_plan(
        source=src2,
        output=tmp_path / "out2",
        vault=tmp_path / "v2",
        policy=policy,
    )

    assert plan1.to_dict() == plan2.to_dict()


def test_policy_key_order_does_not_change_plan(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)

    policy_a = {"schema_version": 1, "profile": "SAFE_TRANSFER", "indexes": {"profile": "DATA_ONLY"}}
    policy_b = {"indexes": {"profile": "DATA_ONLY"}, "profile": "SAFE_TRANSFER", "schema_version": 1}

    plan_a = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy_a)
    plan_b = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy_b)

    assert plan_a.to_dict() == plan_b.to_dict()


def test_policy_change_changes_fingerprint(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)

    policy1 = {"schema_version": 1, "profile": "SAFE_TRANSFER"}
    policy2 = {"schema_version": 1, "profile": "DATA_ONLY"}

    plan1 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy1)
    plan2 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy2)

    assert plan1.policy.policy_fingerprint != plan2.policy.policy_fingerprint
    assert plan1.plan_id != plan2.plan_id


def test_source_byte_change_changes_fingerprint(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)

    plan1 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")

    target = src / "customers" / "customers.dbf"
    original_bytes = target.read_bytes()
    modified_bytes = original_bytes + b"X"
    target.write_bytes(modified_bytes)
    try:
        plan2 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
        assert plan1.dataset.source_fingerprint != plan2.dataset.source_fingerprint
        assert plan1.plan_id != plan2.plan_id
    finally:
        target.write_bytes(original_bytes)


def test_relationship_fingerprint_change_changes_plan(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)

    rel1 = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance="declared",
        relationship_fingerprint="a" * 64,
        relation_count=1,
        authoritative=True,
    )
    rel2 = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance="declared",
        relationship_fingerprint="b" * 64,
        relation_count=2,
        authoritative=True,
    )

    plan1 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", relationships=rel1)
    plan2 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", relationships=rel2)

    assert plan1.plan_id != plan2.plan_id


def test_serialized_plan_contains_no_absolute_paths(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(
        source=src,
        output=tmp_path / "output",
        vault=tmp_path / "vault" / "dict.sqlite3",
    )
    d = plan.to_dict()
    _assert_no_absolute_paths(d)


def test_serialized_plan_contains_no_original_values(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)

    canary_value = "CANARY_XYZZY_12345_SECRET"
    target = src / "customers" / "customers.dbf"
    original = target.read_bytes()
    target.write_bytes(original + canary_value.encode())
    try:
        plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
        d = json.dumps(plan.to_dict(), ensure_ascii=False)
        assert canary_value not in d
    finally:
        target.write_bytes(original)


def test_table_ordering_is_deterministic(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    paths = [t.table_path for t in plan.tables]
    assert paths == sorted(paths)


def test_duplicate_basenames_remain_distinct(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    paths = [t.table_path for t in plan.tables]
    assert len(paths) == len(set(paths))
    topology_tables = [p for p in paths if "registry" in p]
    assert len(topology_tables) >= 2
    assert "north/registry.dbf" in topology_tables
    assert "south/registry.dbf" in topology_tables


# ---------------------------------------------------------------------------
# Error contract tests
# ---------------------------------------------------------------------------

def test_invalid_policy_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(
            source=src,
            output=tmp_path / "out",
            vault=tmp_path / "v",
            policy={"schema_version": 1, "profile": "UNKNOWN_PROFILE"},
        )


def test_unknown_policy_key_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(
            source=src,
            output=tmp_path / "out",
            vault=tmp_path / "v",
            policy={"schema_version": 1, "bogus_key": "value"},
        )


def test_nonexistent_source_raises_path_error() -> None:
    with pytest.raises(PathError):
        build_plan(
            source="/nonexistent/path/xyz",
            output="/tmp/out",
            vault="/tmp/vault",
        )


# ---------------------------------------------------------------------------
# Strategy identification tests
# ---------------------------------------------------------------------------

def test_output_profile_data_only_by_default(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert plan.output_profile is TransferProfile.DATA_ONLY


def test_output_profile_vfp_indexed(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    policy = {"schema_version": 1, "indexes": {"profile": "VFP_INDEXED"}}
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy)
    assert plan.output_profile is TransferProfile.VFP_INDEXED


def test_recovery_enabled_when_transformations_present(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert plan.policy.recovery_enabled is True
    assert len(plan.policy.transformation_classes) > 0


def test_empty_relationships_gives_incomplete_assurance(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert plan.relationships.relation_count == 0
    assert plan.relationship_assurance_target is RelationalAssuranceLevel.INCOMPLETE


def test_authoritative_relationships_give_verified_assurance(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    rel = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance="declared",
        relationship_fingerprint="f" * 64,
        relation_count=3,
        authoritative=True,
    )
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", relationships=rel)
    assert plan.relationship_assurance_target is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED


# ---------------------------------------------------------------------------
# Execution context privacy tests
# ---------------------------------------------------------------------------

def test_execution_context_not_in_serialization(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    secret_path = "/C:/Users/secret/source/data"
    plan = build_plan(
        source=src,
        output=Path("/C:/Users/secret/output"),
        vault=Path("/C:/Users/secret/vault/dict.sqlite3"),
    )
    d = plan.to_dict()
    serialized = json.dumps(d)
    assert "Users" not in serialized
    assert "secret" not in serialized
    assert "execution_context" not in d


def test_execution_context_excluded_from_repr(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(
        source=src,
        output=Path("/C:/Users/secret/output"),
        vault=Path("/C:/Users/secret/vault/dict.sqlite3"),
    )
    r = repr(plan)
    assert "secret" not in r
    assert "C:/Users" not in r


def test_execution_context_does_not_affect_equality(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan1 = build_plan(source=src, output=tmp_path / "out1", vault=tmp_path / "v1")
    plan2 = build_plan(source=src, output=tmp_path / "out2", vault=tmp_path / "v2")
    assert plan1 == plan2, "execution_context should not affect Plan equality"


# ---------------------------------------------------------------------------
# Policy fingerprint determinism
# ---------------------------------------------------------------------------

def test_policy_fingerprint_deterministic(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    policy = {"schema_version": 1, "profile": "SAFE_TRANSFER", "text": {"default_action": "PSEUDONYMIZE_REVERSIBLE"}}
    plan1 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy)
    plan2 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy)
    assert plan1.policy.policy_fingerprint == plan2.policy.policy_fingerprint


def test_policy_whitespace_independent(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    policy1 = {"schema_version": 1, "profile": "SAFE_TRANSFER"}
    policy2 = json.loads('  { "schema_version" : 1 ,  "profile" : "SAFE_TRANSFER"  }')
    plan1 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy1)
    plan2 = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy2)
    assert plan1.policy.policy_fingerprint == plan2.policy.policy_fingerprint
