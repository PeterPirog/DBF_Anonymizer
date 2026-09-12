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
    PolicySummary,
    RelationshipMetadata,
    RelationalAssuranceLevel,
    TransferProfile,
    VaultStrategy,
)
import dataclasses
from dbf_anonymizer.errors import AnonymizerError, DBFBridgeError, PathError, PolicyError

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "p0"


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
    assert plan.execution_context is not None


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

    policy1 = {"schema_version": 1, "profile": "SAFE_TRANSFER", "text": {"default_action": "PSEUDONYMIZE_REVERSIBLE"}}
    policy2 = {"schema_version": 1, "profile": "SAFE_TRANSFER", "text": {"default_action": "KEEP"}}

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


# ---------------------------------------------------------------------------
# REPAIR: A. Public boundary
# ---------------------------------------------------------------------------

def test_private_execution_context_not_root_exported() -> None:
    import dbf_anonymizer
    assert not hasattr(dbf_anonymizer, "PlanExecutionContext")
    assert "PlanExecutionContext" not in dbf_anonymizer.__all__


def test_execution_context_repr_does_not_leak_paths(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(
        source=src,
        output=Path("/C:/Users/secret/output"),
        vault=Path("/C:/Users/secret/vault/dict.sqlite3"),
    )
    assert "secret" not in repr(plan)
    assert "C:/Users" not in repr(plan)
    if plan.execution_context is not None:
        assert "secret" not in repr(plan.execution_context)
        assert "C:/Users" not in repr(plan.execution_context)


# ---------------------------------------------------------------------------
# REPAIR: B. Policy fail-closed validation
# ---------------------------------------------------------------------------

def test_unknown_nested_text_key_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "text": {"bogus_key": "x"}})


def test_unknown_nested_memo_key_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "memo": {"bogus_key": "x"}})


def test_unknown_nested_temporal_key_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "temporal": {"bogus_key": "x"}})


def test_unknown_nested_numeric_key_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "numeric": {"bogus_key": "x"}})


def test_unknown_nested_relationships_key_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "relationships": {"bogus_key": "x"}})


def test_unknown_nested_indexes_key_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "indexes": {"bogus_key": "x"}})


def test_indexes_profile_unknown_value_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "indexes": {"profile": "UNKNOWN_PROFILE"}})


@pytest.mark.parametrize("bad_sv", [2, 999, True, "1"])
def test_schema_version_must_be_exactly_1(tmp_path: Path, bad_sv: object) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": bad_sv})


def test_non_json_policy_value_rejected(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    class NotSerializable:
        pass
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "text": {"default_action": NotSerializable()}})


def test_non_null_metadata_file_fails_closed(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    with pytest.raises(PolicyError):
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v",
                   policy={"schema_version": 1, "relationships": {"metadata_file": "some_file.json"}})


@pytest.mark.parametrize("policy", [
    {"profile": "SAFE_TRANSFER"},
    {"text": {"domain": "GLOBAL_TEXT"}},
    {"numeric": {"default_action": "KEEP"}},
])
def test_supported_policy_values_accepted(tmp_path: Path, policy: dict[str, Any]) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    default = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    explicit = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy)
    assert explicit.to_dict() == default.to_dict()


@pytest.mark.parametrize("policy,detail_code", [
    ({"profile": "DATA_ONLY"}, "unsupported_top_level_profile"),
    ({"text": {"domain": "UNKNOWN_DOMAIN"}}, "unsupported_text_domain"),
    ({"numeric": {"default_action": "PSEUDONYMIZE_REVERSIBLE"}}, "unsupported_numeric_action"),
])
def test_unsupported_policy_values_rejected(
    tmp_path: Path, policy: dict[str, Any], detail_code: str,
) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    before = _sha256_files(tmp_path)
    with pytest.raises(PolicyError) as exc_info:
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", policy=policy)
    assert exc_info.value.code.value == "POLICY_UNSUPPORTED"
    assert exc_info.value.context.detail_code == detail_code
    assert _sha256_files(tmp_path) == before
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "v").exists()


# ---------------------------------------------------------------------------
# REPAIR: C. Field classification V/M/G/P
# ---------------------------------------------------------------------------

def test_V_field_planned_as_text_transformation(tmp_path: Path) -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = {"text": {"default_action": "PSEUDONYMIZE_REVERSIBLE"}, "memo": {"text": "MASK_REVERSIBLE", "binary": "MASK_REVERSIBLE"}, "temporal": {"date": "SHIFT_REVERSIBLE", "datetime": "SHIFT_REVERSIBLE"}, "numeric": {"default_action": "KEEP"}}
    result, unsafe, system = classify_field_capability("V", "TEXT", True, False, False, False, policy)
    assert result == "PSEUDONYMIZE_REVERSIBLE"
    assert not unsafe and not system


def test_G_P_fields_planned_as_memo_binary(tmp_path: Path) -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = {"text": {"default_action": "PSEUDONYMIZE_REVERSIBLE"}, "memo": {"text": "MASK_REVERSIBLE", "binary": "MASK_REVERSIBLE"}, "temporal": {"date": "SHIFT_REVERSIBLE", "datetime": "SHIFT_REVERSIBLE"}, "numeric": {"default_action": "KEEP"}}
    g_result, g_unsafe, _ = classify_field_capability("G", "GENERAL", True, True, False, False, policy)
    p_result, p_unsafe, _ = classify_field_capability("P", "PICTURE", True, True, False, False, policy)
    m_result, m_unsafe, _ = classify_field_capability("M", "MEMO", True, False, False, False, policy)
    assert g_result == "MASK_REVERSIBLE" and not g_unsafe
    assert p_result == "MASK_REVERSIBLE" and not p_unsafe
    assert m_result == "MASK_REVERSIBLE" and not m_unsafe


# ---------------------------------------------------------------------------
# REPAIR: D. DBFbridge error wrapping
# ---------------------------------------------------------------------------

def test_malformed_dbf_becomes_dbfbridge_error(tmp_path: Path) -> None:
    src = tmp_path / "source"
    src.mkdir(parents=True)
    (src / "bad.dbf").write_bytes(b"\x00" * 10)
    with pytest.raises(DBFBridgeError) as exc_info:
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    err = exc_info.value
    assert err.code.value == "DBFBRIDGE_FAILURE"
    assert err.context.table_path == "bad.dbf"
    assert "C:\\" not in repr(err)
    assert "D:\\" not in repr(err)


def test_dbfbridge_error_preserves_dependency_code(tmp_path: Path) -> None:
    src = tmp_path / "source"
    src.mkdir(parents=True)
    (src / "bad.dbf").write_bytes(b"\x00" * 10)
    with pytest.raises(DBFBridgeError) as exc_info:
        build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    err = exc_info.value
    d = err.to_dict()
    assert d["code"] == "DBFBRIDGE_FAILURE"
    assert d["category"] == "dbfbridge"
    assert "bad.dbf" not in d.get("message", "")
    assert "C:\\" not in json.dumps(d)


# ---------------------------------------------------------------------------
# REPAIR: E. Companion discovery from dbfbridge facts
# ---------------------------------------------------------------------------

def test_memo_companion_from_dbfbridge_facts(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    notes_table = next(t for t in plan.tables if t.table_path == "notes/notes.dbf")
    assert notes_table.memo_path is not None
    assert "notes.dbf" not in notes_table.memo_path
    assert notes_table.memo_path.endswith(".fpt") or notes_table.memo_path.endswith(".FPT")


def test_no_cdx_inferred_without_structural_cdx(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    for table in plan.tables:
        if not table.structural_cdx:
            assert table.index_strategy == "DATA_ONLY"


# ---------------------------------------------------------------------------
# REPAIR: F. IDX truthfulness
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("idx_relative_path", ["north/registry.idx", "south/registry.idx"])
def test_same_stem_idx_not_associated_with_dbf(tmp_path: Path, idx_relative_path: str) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    baseline = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    idx = src / idx_relative_path
    idx.write_bytes(b"synthetic disposable index A")
    before = _sha256_files(src)
    first = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert _sha256_files(src) == before

    idx.write_bytes(b"synthetic disposable index B")
    changed = _sha256_files(src)
    assert {p for p in before if before[p] != changed[p]} == {idx_relative_path}
    second = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert _sha256_files(src) == changed

    assert baseline.dataset.source_fingerprint != first.dataset.source_fingerprint
    assert first.dataset.source_fingerprint != second.dataset.source_fingerprint
    assert first.plan_id != second.plan_id
    # Adding/changing IDX cannot invent an ownership relation on any TablePlan.
    assert baseline.tables == first.tables == second.tables
    assert baseline.to_dict()["tables"] == first.to_dict()["tables"] == second.to_dict()["tables"]
    assert all(".idx" not in json.dumps(t.to_dict()).lower() for t in second.tables)
    assert baseline.policy == first.policy == second.policy
    assert baseline.relationships == first.relationships == second.relationships
    assert baseline.output_profile == first.output_profile == second.output_profile


# ---------------------------------------------------------------------------
# REPAIR: G. Vault strategy
# ---------------------------------------------------------------------------

def test_vault_strategy_in_public_serialization(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    d = plan.to_dict()
    assert d["policy"]["vault_strategy"] in ("NONE", "SINGLE_DATASET_SQLITE")
    assert plan.policy.vault_strategy is not None


def test_vault_strategy_singlesqlite_when_recovery(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    if plan.policy.recovery_enabled:
        assert plan.policy.vault_strategy is VaultStrategy.SINGLE_DATASET_SQLITE
    else:
        assert plan.policy.vault_strategy is VaultStrategy.NONE


def test_vault_strategy_no_absolute_path(tmp_path: Path) -> None:
    src = tmp_path / "source"
    _make_valid_source(src)
    plan = build_plan(
        source=src,
        output=Path("/C:/Users/secret/output"),
        vault=Path("/C:/Users/secret/vault/dict.sqlite3"),
    )
    d = json.dumps(plan.to_dict())
    assert "secret" not in d
    assert "C:/Users" not in d


# ---------------------------------------------------------------------------
# REPAIR: H. NOCPTRANS
# ---------------------------------------------------------------------------

def _full_policy() -> dict[str, object]:
    return {
        "text": {"default_action": "PSEUDONYMIZE_REVERSIBLE"},
        "memo": {"text": "MASK_REVERSIBLE", "binary": "MASK_REVERSIBLE"},
        "temporal": {"date": "SHIFT_REVERSIBLE", "datetime": "SHIFT_REVERSIBLE"},
        "numeric": {"default_action": "KEEP"},
    }


@pytest.mark.parametrize("dbf_type", ["C", "V"])
def test_nocptrans_text_field_classified_unsafe(dbf_type: str) -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = _full_policy()
    action, unsafe, system = classify_field_capability(dbf_type, "TEXT", True, False, False, True, policy)
    assert action is None and unsafe is True and system is False


def test_nocptrans_memo_field_classified_unsafe() -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = _full_policy()
    action, unsafe, system = classify_field_capability("M", "MEMO", True, False, False, True, policy)
    assert action is None and unsafe is True and system is False


def test_nocptrans_numeric_field_stays_identity() -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = _full_policy()
    action, unsafe, system = classify_field_capability("N", "NUMBER", True, False, False, True, policy)
    assert action is None and unsafe is False and system is False


def test_nocptrans_with_unsupported_is_unsafe() -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = _full_policy()
    action, unsafe, system = classify_field_capability("C", "TEXT", False, False, False, True, policy)
    assert action is None and unsafe is True and system is False


def test_nocptrans_does_not_affect_system_field() -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = _full_policy()
    action, unsafe, system = classify_field_capability("0", "_NULLFLAGS", True, True, True, True, policy)
    assert action is None and unsafe is False and system is True


# ---------------------------------------------------------------------------
# REPAIR: I. _NullFlags / system fields
# ---------------------------------------------------------------------------

def test_nullflags_field_is_system_not_unsafe(tmp_path: Path) -> None:
    src = tmp_path / "source"
    shutil.copytree(FIXTURES / "nullable", src)
    before = _sha256_files(src)
    schema = dbfbridge.read_schema(src / "nullable_varchar.dbf")
    nullflags = next(f for f in schema.fields if f.name == "_NULLFLAGS")
    assert nullflags.dbf_type == "0" and nullflags.system is True
    varchar = next(f for f in schema.fields if f.dbf_type == "V")
    assert varchar.supported is True and varchar.system is False
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    table = plan.tables[0]
    assert table.table_path == "nullable_varchar.dbf"
    assert table.system_field_count == 1
    assert table.unsafe_field_count == 0
    assert table.unsupported_field_count == 0
    assert table.transform_field_count == 3  # Varchar, Character, Date only
    assert "PSEUDONYMIZE_REVERSIBLE" in plan.policy.transformation_classes
    assert _sha256_files(src) == before


def test_nullflags_field_not_counted_as_transform(tmp_path: Path) -> None:
    src = tmp_path / "source"
    shutil.copytree(FIXTURES / "nullable", src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    table = plan.tables[0]
    # 5 user fields + 1 system = 6 total; none should be unsafe
    assert table.field_count == 6
    assert table.unsafe_field_count == 0
    assert table.transform_field_count == 3


@pytest.mark.parametrize("field_name", ["_NullFlags", "_NULLFLAGS", "_nullflags"])
def test_system_field_classification_unit(field_name: str) -> None:
    from dbf_anonymizer.policy import classify_field_capability
    policy = _full_policy()
    action, unsafe, system = classify_field_capability("0", field_name, True, True, True, False, policy)
    assert action is None and unsafe is False and system is True


@pytest.mark.parametrize("dbf_type", ["C", "V", "M", "N", "X", "Q", "W"])
@pytest.mark.parametrize("supported", [False, True])
def test_untrusted_system_field_is_unsafe(dbf_type: str, supported: bool) -> None:
    from dbf_anonymizer.policy import classify_field_capability
    assert classify_field_capability(
        dbf_type, "USER_DATA", supported, False, True, False, _full_policy(),
    ) == (None, True, False)


@pytest.mark.parametrize("field_name,is_system", [
    ("OTHER", True), ("_NULLFLAGS_EXTRA", True), ("_NULLFLAGS", False),
])
def test_type_zero_requires_known_name_and_system_flag(field_name: str, is_system: bool) -> None:
    from dbf_anonymizer.policy import classify_field_capability
    assert classify_field_capability(
        "0", field_name, True, True, is_system, False, _full_policy(),
    ) == (None, True, False)


@pytest.mark.parametrize("dbf_type", ["C", "V", "M", "X", "Q", "W"])
def test_unsupported_user_field_without_system_flag_is_unsafe(dbf_type: str) -> None:
    from dbf_anonymizer.policy import classify_field_capability
    assert classify_field_capability(
        dbf_type, "USER_DATA", False, False, False, False, _full_policy(),
    ) == (None, True, False)


@pytest.mark.parametrize("dbf_type,field_name,supported,system,expected_system", [
    ("0", "_NULLFLAGS", True, True, 1),
    ("0", "_NullFlags", False, True, 1),
    ("C", "USER_DATA", True, True, 0),
    ("C", "_NULLFLAGS", True, True, 0),
    ("V", "USER_DATA", True, True, 0),
    ("M", "USER_DATA", True, True, 0),
    ("X", "USER_DATA", False, True, 0),
    ("Q", "USER_DATA", False, True, 0),
    ("W", "USER_DATA", False, True, 0),
    ("0", "OTHER", True, True, 0),
    ("0", "_NULLFLAGS", True, False, 0),
])
def test_build_plan_classifies_public_field_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    dbf_type: str, field_name: str, supported: bool, system: bool, expected_system: int,
) -> None:
    src = tmp_path / "source"
    shutil.copytree(FIXTURES / "nullable", src)
    source_table = src / "nullable_varchar.dbf"
    schema = dbfbridge.read_schema(source_table)
    field = dataclasses.replace(
        schema.fields[0], name=field_name, dbf_type=dbf_type,
        supported=supported, flags=0x01 if system else 0,
    )
    assert isinstance(field, dbfbridge.FieldInfo)
    assert field.system is system
    schema = dataclasses.replace(schema, fields=(field,))

    def read_schema(path: Path) -> dbfbridge.TableSchema:
        assert Path(path) == source_table
        return schema

    monkeypatch.setattr(dbfbridge, "read_schema", read_schema)
    before = _sha256_files(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    table = plan.tables[0]
    assert table.field_count == 1
    assert table.system_field_count == expected_system
    assert table.unsafe_field_count == 1 - expected_system
    assert table.transform_field_count == 0
    assert table.unsupported_field_count == int(not supported and not expected_system)
    assert _sha256_files(src) == before


# ---------------------------------------------------------------------------
# REPAIR: J. Memo requirement completeness
# ---------------------------------------------------------------------------

def test_memo_required_when_has_memo_true(tmp_path: Path) -> None:
    src = tmp_path / "source"
    shutil.copytree(FIXTURES / "memos", src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    table = plan.tables[0]
    assert table.memo_required is True
    assert table.memo_companion_present is True


@pytest.mark.parametrize("has_memo,has_memo_flag,expected", [
    (False, False, False),
    (True, False, True),
    (False, True, True),
    (True, True, True),
])
def test_memo_required_public_schema_truth_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    has_memo: bool, has_memo_flag: bool, expected: bool,
) -> None:
    src = tmp_path / "source"
    shutil.copytree(FIXTURES / "plain", src)
    source_table = next(src.glob("*.dbf"))
    schema = dataclasses.replace(
        dbfbridge.read_schema(source_table),
        has_memo=has_memo, has_memo_flag=has_memo_flag,
    )
    assert isinstance(schema, dbfbridge.TableSchema)
    assert schema.has_memo is has_memo
    assert schema.has_memo_flag is has_memo_flag

    def read_schema(path: Path) -> dbfbridge.TableSchema:
        assert Path(path) == source_table
        return schema

    monkeypatch.setattr(dbfbridge, "read_schema", read_schema)
    before = _sha256_files(src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert len(plan.tables) == 1
    assert plan.tables[0].memo_required is expected
    assert _sha256_files(src) == before


def test_memo_required_false_when_no_memo_fields(tmp_path: Path) -> None:
    src = tmp_path / "source"
    shutil.copytree(FIXTURES / "plain", src)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    table = plan.tables[0]
    assert table.memo_required is False
    assert table.memo_companion_present is False


# ---------------------------------------------------------------------------
# REPAIR: K. TablePlan invariants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("unsupported,unsafe,expected_message", [
    (2, 1, "unsupported_field_count cannot exceed unsafe_field_count"),
    (4, 0, "unsupported_field_count cannot exceed field_count"),
])
def test_tableplan_unsupported_count_invariants(
    unsupported: int, unsafe: int, expected_message: str,
) -> None:
    from dbf_anonymizer.models import TablePlan
    with pytest.raises(ValueError, match=expected_message):
        TablePlan(
            table_path="a.dbf", memo_path=None, record_count=0, field_count=3,
            transform_field_count=0, structural_cdx=False, dbc_bound=False,
            index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
            structural_cdx_companion_present=False, unsupported_field_count=unsupported,
            unsafe_field_count=unsafe, system_field_count=0,
        )


def test_tableplan_all_fields_unsupported_and_unsafe_is_valid() -> None:
    from dbf_anonymizer.models import TablePlan
    table = TablePlan(
        table_path="a.dbf", memo_path=None, record_count=0, field_count=3,
        transform_field_count=0, structural_cdx=False, dbc_bound=False,
        index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
        structural_cdx_companion_present=False, unsupported_field_count=3,
        unsafe_field_count=3, system_field_count=0,
    )
    assert table.unsupported_field_count == table.unsafe_field_count == table.field_count


def test_tableplan_transform_plus_unsafe_plus_system_leq_field_count() -> None:
    from dbf_anonymizer.models import TablePlan
    with pytest.raises(ValueError, match="transformed \\+ unsafe \\+ system"):
        TablePlan(
            table_path="a.dbf", memo_path=None, record_count=0, field_count=3,
            transform_field_count=2, structural_cdx=False, dbc_bound=False,
            index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
            structural_cdx_companion_present=False, unsupported_field_count=0,
            unsafe_field_count=2, system_field_count=1,
        )


def test_tableplan_transform_leq_field_count() -> None:
    from dbf_anonymizer.models import TablePlan
    with pytest.raises(ValueError, match="transform_field_count"):
        TablePlan(
            table_path="a.dbf", memo_path=None, record_count=0, field_count=2,
            transform_field_count=3, structural_cdx=False, dbc_bound=False,
            index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
            structural_cdx_companion_present=False, unsupported_field_count=0,
            unsafe_field_count=0, system_field_count=0,
        )


def test_tableplan_unsafe_leq_field_count() -> None:
    from dbf_anonymizer.models import TablePlan
    with pytest.raises(ValueError, match="unsafe_field_count"):
        TablePlan(
            table_path="a.dbf", memo_path=None, record_count=0, field_count=1,
            transform_field_count=0, structural_cdx=False, dbc_bound=False,
            index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
            structural_cdx_companion_present=False, unsupported_field_count=0,
            unsafe_field_count=2, system_field_count=0,
        )


def test_tableplan_system_leq_field_count() -> None:
    from dbf_anonymizer.models import TablePlan
    with pytest.raises(ValueError, match="system_field_count"):
        TablePlan(
            table_path="a.dbf", memo_path=None, record_count=0, field_count=1,
            transform_field_count=0, structural_cdx=False, dbc_bound=False,
            index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
            structural_cdx_companion_present=False, unsupported_field_count=0,
            unsafe_field_count=0, system_field_count=2,
        )


def test_tableplan_frozen_rejects_all_mutation() -> None:
    from dbf_anonymizer.models import TablePlan
    t = TablePlan(
        table_path="a.dbf", memo_path=None, record_count=0, field_count=1,
        transform_field_count=0, structural_cdx=False, dbc_bound=False,
        index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
        structural_cdx_companion_present=False, unsupported_field_count=0,
        unsafe_field_count=0, system_field_count=0,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        t.table_path = "b.dbf"
    with pytest.raises(dataclasses.FrozenInstanceError):
        t.system_field_count = 5


def test_tableplan_serialization_roundtrip_includes_system() -> None:
    from dbf_anonymizer.models import TablePlan
    t = TablePlan(
        table_path="a.dbf", memo_path=None, record_count=10, field_count=5,
        transform_field_count=2, structural_cdx=False, dbc_bound=False,
        index_strategy="DATA_ONLY", memo_required=False, memo_companion_present=False,
        structural_cdx_companion_present=False, unsupported_field_count=0,
        unsafe_field_count=1, system_field_count=1,
    )
    d = t.to_dict()
    assert d["system_field_count"] == 1
    assert d["unsafe_field_count"] == 1
    assert d["transform_field_count"] == 2
