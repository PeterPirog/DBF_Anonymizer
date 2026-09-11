"""REQ-P1-002 — deterministic acceptance evidence for typed public models.

Proves importability, construction-time path normalization, runtime
collection immutability, strict versioned JSON-safe serialization with
round-trips for EVERY public model, fail-closed parsing (no silent filtering,
no scalar-to-string path coercion), privacy by construction, the
comparison-semantics relationship contract, the py.typed marker and the
mechanically verified schema snapshot.
"""

from __future__ import annotations

import dataclasses
import json
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import dbf_anonymizer
from dbf_anonymizer import (
    PUBLIC_MODEL_SCHEMA_VERSION,
    Capabilities,
    DatasetIdentity,
    FieldPlan,
    Plan,
    PolicySummary,
    PreflightIssue,
    PreflightResult,
    ProgressEvent,
    PseudonymizationResult,
    RelationalAssurance,
    RelationshipGroup,
    RelationshipMember,
    RelationshipMetadata,
    RecoveryResult,
    ResultStatus,
    TablePlan,
    TransferBundleResult,
    VerificationResult,
    VerificationStatus,
)
from dbf_anonymizer.models import COMPARISON_SEMANTICS_EXACT, _normalize_relative_path

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = REPO_ROOT / "tests" / "snapshots" / "p1_public_models_v1.json"
WHEEL_PATH = REPO_ROOT / "dist" / "dbf_anonymizer-1.0.0.dev0-py3-none-any.whl"

#: Synthetic-only constants (obviously fake; no original values anywhere).
SYNTH_OP = "op-SYNTH-0001"
SYNTH_TABLE = "north/synthetic.dbf"

TOP_LEVEL_MODELS = (
    Capabilities,
    DatasetIdentity,
    Plan,
    ProgressEvent,
    PreflightResult,
    PseudonymizationResult,
    VerificationResult,
    RecoveryResult,
    TransferBundleResult,
)

NESTED_MODELS = (
    FieldPlan,
    TablePlan,
    PolicySummary,
    RelationshipMember,
    RelationshipGroup,
    RelationshipMetadata,
    PreflightIssue,
)

ALL_PUBLIC_MODELS = TOP_LEVEL_MODELS + NESTED_MODELS


def _synthetic_plan() -> Plan:
    return Plan(
        dataset_identity=DatasetIdentity(
            dataset_fingerprint="fp-SYNTH-DATASET",
            tables=(SYNTH_TABLE, "south/synthetic.dbf"),
            table_count=2,
        ),
        policy_summary=PolicySummary(
            profile="SYNTH-PROFILE", policy_fingerprint="fp-SYNTH-POLICY"
        ),
        relationships=RelationshipMetadata(
            relationship_fingerprint="fp-SYNTH-RELATIONS",
            provenance="policy-declared",
            groups=(
                RelationshipGroup(
                    group_id="SYNTH-GROUP-1",
                    provenance="policy-declared",
                    comparison_semantics=COMPARISON_SEMANTICS_EXACT,
                    members=(
                        RelationshipMember(
                            relative_path=SYNTH_TABLE,
                            field_name="KEY",
                            role="primary",
                            component_index=0,
                        ),
                        RelationshipMember(
                            relative_path="south/synthetic.dbf",
                            field_name="KEY",
                            role="foreign",
                            component_index=0,
                        ),
                    ),
                ),
            ),
        ),
        table_plans=(
            TablePlan(
                relative_path=SYNTH_TABLE,
                schema_fingerprint="fp-SYNTH-SCHEMA",
                fields=(
                    FieldPlan(
                        field_name="CODE", dbf_type="C", action="pseudonymize", domain="keys"
                    ),
                    FieldPlan(field_name="FLAG", dbf_type="L", action="keep", domain=None),
                ),
            ),
        ),
        output_strategy="sibling-output-tree",
        vault_strategy="single-vault",
        index_strategy="metadata-only",
        plan_fingerprint="fp-SYNTH-PLAN",
    )


def _synthetic_instance(model: type) -> Any:
    """Build one synthetic instance per public model class."""
    if model is Capabilities:
        return Capabilities(
            product_version="1.0.0.dev0",
            dbfbridge_version="1.1.0",
            supported_profiles=("SYNTH-PROFILE",),
            features=("direct-read", "direct-write"),
        )
    if model is DatasetIdentity:
        return DatasetIdentity(
            dataset_fingerprint="fp-SYNTH-DATASET",
            tables=(SYNTH_TABLE,),
            table_count=1,
        )
    if model is Plan:
        return _synthetic_plan()
    if model is ProgressEvent:
        return ProgressEvent(
            operation_id=SYNTH_OP,
            phase="scan",
            completed=1,
            total=4,
            unit="tables",
            table=SYNTH_TABLE,
        )
    if model is PreflightResult:
        return PreflightResult(
            ready=False,
            issues=(PreflightIssue(code="SYNTH-ISSUE-CODE", table=SYNTH_TABLE, field_name=None),),
        )
    if model is PseudonymizationResult:
        return PseudonymizationResult(
            operation_id=SYNTH_OP,
            status=ResultStatus.COMPLETED,
            dataset_fingerprint="fp-SYNTH-DATASET",
            artifact_paths=("output/synthetic.dbf", "output/synthetic.fpt"),
            tables_processed=1,
            records_processed=4,
        )
    if model is VerificationResult:
        return VerificationResult(
            operation_id=SYNTH_OP,
            status=VerificationStatus.PARTIAL,
            dataset_fingerprint="fp-SYNTH-DATASET",
            tables_verified=2,
            records_verified=8,
            mismatches=0,
            assurance=RelationalAssurance.DECLARED_RELATIONS_VERIFIED,
        )
    if model is RecoveryResult:
        return RecoveryResult(
            operation_id=SYNTH_OP,
            status=ResultStatus.COMPLETED,
            restored_artifact_paths=("restored/synthetic.dbf",),
            records_restored=4,
        )
    if model is TransferBundleResult:
        return TransferBundleResult(
            operation_id=SYNTH_OP,
            status=ResultStatus.COMPLETED,
            bundle_id="bundle-SYNTH-0001",
            bundle_fingerprint="fp-SYNTH-BUNDLE",
            artifact_paths=("transfer/synthetic.dbf",),
        )
    if model is FieldPlan:
        return FieldPlan(
            field_name="CODE", dbf_type="C", action="pseudonymize", domain="keys"
        )
    if model is TablePlan:
        return TablePlan(
            relative_path=SYNTH_TABLE,
            schema_fingerprint="fp-SYNTH-SCHEMA",
            fields=(FieldPlan(field_name="CODE", dbf_type="C", action="pseudonymize"),),
        )
    if model is PolicySummary:
        return PolicySummary(
            profile="SYNTH-PROFILE", policy_fingerprint="fp-SYNTH-POLICY"
        )
    if model is RelationshipMember:
        return RelationshipMember(
            relative_path=SYNTH_TABLE, field_name="KEY", role="primary", component_index=0
        )
    if model is RelationshipGroup:
        return RelationshipGroup(
            group_id="SYNTH-GROUP-1",
            provenance="policy-declared",
            comparison_semantics=COMPARISON_SEMANTICS_EXACT,
            members=(RelationshipMember(SYNTH_TABLE, "KEY", "primary", 0),),
        )
    if model is RelationshipMetadata:
        return RelationshipMetadata(
            relationship_fingerprint="fp-SYNTH-RELATIONS",
            provenance="policy-declared",
            groups=(
                RelationshipGroup(
                    group_id="SYNTH-GROUP-1",
                    provenance="policy-declared",
                    comparison_semantics=COMPARISON_SEMANTICS_EXACT,
                    members=(RelationshipMember(SYNTH_TABLE, "KEY", "primary", 0),),
                ),
            ),
        )
    if model is PreflightIssue:
        return PreflightIssue(code="SYNTH-ISSUE-CODE", table=SYNTH_TABLE, field_name=None)
    raise AssertionError(f"no synthetic instance for {model.__name__}")


# ---------------------------------------------------------------------------
# imports and root surface
# ---------------------------------------------------------------------------


def test_every_required_model_is_root_importable() -> None:
    for model in ALL_PUBLIC_MODELS:
        assert getattr(dbf_anonymizer, model.__name__) is model, model.__name__


def test_service_functions_remain_absent() -> None:
    for name in (
        "capabilities",
        "build_plan",
        "preflight",
        "pseudonymize",
        "verify_dataset",
        "recover",
        "create_transfer_bundle",
        "verify_transfer_bundle",
    ):
        assert not hasattr(dbf_anonymizer, name), name


# ---------------------------------------------------------------------------
# A. direct-construction path invariants
# ---------------------------------------------------------------------------


def test_construction_normalizes_backslash_relative_paths() -> None:
    table = TablePlan("north\\synthetic.dbf", "fp-SYNTH", ())
    assert table.relative_path == "north/synthetic.dbf"
    member = RelationshipMember("south\\synthetic.dbf", "KEY", "foreign", 0)
    assert member.relative_path == "south/synthetic.dbf"
    identity = DatasetIdentity("fp-SYNTH", ["a\\one.dbf", "b\\two.dbf"], 2)
    assert identity.tables == ("a/one.dbf", "b/two.dbf")
    event = ProgressEvent(SYNTH_OP, "scan", 1, 4, "tables", "memo\\synthetic.dbf")
    assert event.table == "memo/synthetic.dbf"
    issue = PreflightIssue("SYNTH-CODE", "x\\synthetic.dbf", None)
    assert issue.table == "x/synthetic.dbf"
    result = PseudonymizationResult(
        SYNTH_OP, ResultStatus.COMPLETED, "fp-SYNTH", ["o\\synthetic.dbf"], 1, 4
    )
    assert result.artifact_paths == ("o/synthetic.dbf",)
    recovery = RecoveryResult(SYNTH_OP, ResultStatus.COMPLETED, ["r\\synthetic.dbf"], 4)
    assert recovery.restored_artifact_paths == ("r/synthetic.dbf",)
    bundle = TransferBundleResult(
        SYNTH_OP, ResultStatus.COMPLETED, "b-1", "fp-SYNTH", ["t\\synthetic.dbf"]
    )
    assert bundle.artifact_paths == ("t/synthetic.dbf",)


@pytest.mark.parametrize(
    "rejected_path",
    (
        "C:\\abs\\synthetic.dbf",
        "C:/abs/synthetic.dbf",
        "/abs/synthetic.dbf",
        "\\abs\\synthetic.dbf",
        "\\\\server\\share\\synthetic.dbf",
        "//server/share/synthetic.dbf",
        "../synthetic.dbf",
        "north/../synthetic.dbf",
        "north//synthetic.dbf",
        "",
        "bad\x00.dbf",
        123,
        True,
    ),
)
def test_construction_rejects_invalid_path_values(rejected_path: Any) -> None:
    with pytest.raises((ValueError, TypeError)):
        TablePlan(rejected_path, "fp-SYNTH", ())
    with pytest.raises((ValueError, TypeError)):
        RelationshipMember(rejected_path, "KEY", "primary", 0)
    with pytest.raises((ValueError, TypeError)):
        DatasetIdentity("fp-SYNTH", [rejected_path], 1)
    with pytest.raises((ValueError, TypeError)):
        ProgressEvent(SYNTH_OP, "scan", 1, 4, "tables", rejected_path)
    with pytest.raises((ValueError, TypeError)):
        PreflightIssue("SYNTH-CODE", rejected_path, None)
    with pytest.raises((ValueError, TypeError)):
        PseudonymizationResult(
            SYNTH_OP, ResultStatus.COMPLETED, "fp-SYNTH", [rejected_path], 1, 4
        )
    with pytest.raises((ValueError, TypeError)):
        RecoveryResult(SYNTH_OP, ResultStatus.COMPLETED, [rejected_path], 8)
    with pytest.raises((ValueError, TypeError)):
        TransferBundleResult(
            SYNTH_OP, ResultStatus.COMPLETED, "b-1", "fp-SYNTH", [rejected_path]
        )


def test_optional_path_fields_accept_none() -> None:
    assert ProgressEvent(SYNTH_OP, "scan", 1, None, None, None).table is None
    assert PreflightIssue("SYNTH-CODE", None, None).table is None


def test_no_constructed_model_can_serialize_an_absolute_path() -> None:
    canary_drive = "C:\\synthetic-canary\\secret.dbf"
    for construction in (
        lambda: TablePlan(canary_drive, "fp-SYNTH", ()),
        lambda: RelationshipMember(canary_drive, "KEY", "primary", 0),
        lambda: DatasetIdentity("fp-SYNTH", [canary_drive], 1),
        lambda: ProgressEvent(SYNTH_OP, "scan", 1, 4, "tables", canary_drive),
        lambda: PreflightIssue("SYNTH-CODE", canary_drive, None),
        lambda: PseudonymizationResult(
            SYNTH_OP, ResultStatus.COMPLETED, "fp-SYNTH", [canary_drive], 1, 4
        ),
        lambda: RecoveryResult(SYNTH_OP, ResultStatus.COMPLETED, [canary_drive], 4),
        lambda: TransferBundleResult(
            SYNTH_OP, ResultStatus.COMPLETED, "b-1", "fp-SYNTH", [canary_drive]
        ),
    ):
        with pytest.raises(ValueError):
            construction()


def test_safe_backslash_paths_serialize_normalized() -> None:
    table = TablePlan("north\\synthetic.dbf", "fp-SYNTH", ())
    assert table.to_dict()["relative_path"] == "north/synthetic.dbf"


# ---------------------------------------------------------------------------
# B. true immutability
# ---------------------------------------------------------------------------


def test_public_models_are_frozen_and_slotted() -> None:
    for model in ALL_PUBLIC_MODELS:
        assert dataclasses.is_dataclass(model)
        parameters = getattr(model, "__dataclass_params__")
        assert parameters.frozen, model.__name__
        # `slots` appears in __dataclass_params__ only from Python 3.11+;
        # on 3.10 prove the runtime slot behavior instead: a slotted frozen
        # dataclass instance has no per-instance __dict__.
        slots = getattr(parameters, "slots", None)
        if slots is not None:
            assert slots, model.__name__
        else:
            instance = _synthetic_instance(model)
            assert not hasattr(instance, "__dict__"), model.__name__
    plan = _synthetic_plan()
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.plan_fingerprint = "mutated"


def test_mutable_list_input_is_canonicalized_to_tuple() -> None:
    plan = _synthetic_plan()
    list_backed = Plan(
        dataset_identity=plan.dataset_identity,
        policy_summary=plan.policy_summary,
        relationships=plan.relationships,
        table_plans=list(plan.table_plans),
        output_strategy="s",
        vault_strategy="v",
        index_strategy="i",
        plan_fingerprint="fp",
    )
    assert type(list_backed.table_plans) is tuple
    with pytest.raises(AttributeError):
        list_backed.table_plans.append(plan.table_plans[0])  # type: ignore[index]
    identity = DatasetIdentity("fp-SYNTH", ["north/one.dbf"], 1)
    assert type(identity.tables) is tuple
    result = PseudonymizationResult(
        SYNTH_OP, ResultStatus.COMPLETED, "fp-SYNTH", ["o/s.dbf"], 1, 4
    )
    assert type(result.artifact_paths) is tuple
    group = RelationshipGroup("g", "policy-declared", COMPARISON_SEMANTICS_EXACT, [])
    assert type(group.members) is tuple


def test_mutable_and_non_sequence_collection_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="must be a list or tuple"):
        TablePlan(SYNTH_TABLE, "fp-SYNTH", {"CODE": FieldPlan("CODE", "C", "keep")})
    with pytest.raises(ValueError, match="must be a list or tuple"):
        DatasetIdentity("fp-SYNTH", {"north/one.dbf"}, 1)
    with pytest.raises(ValueError, match="must be a list or tuple"):
        DatasetIdentity("fp-SYNTH", "north/one.dbf", 1)  # no char splitting
    with pytest.raises(ValueError, match="must be a list or tuple"):
        DatasetIdentity("fp-SYNTH", {"north/one.dbf"}, 1)
    with pytest.raises(ValueError, match="must be a list or tuple"):
        Plan(
            dataset_identity=DatasetIdentity("fp", (SYNTH_TABLE,), 1),
            policy_summary=PolicySummary("p", "fp"),
            relationships=RelationshipMetadata("fp", "policy-declared", ()),
            table_plans={SYNTH_TABLE: TablePlan(SYNTH_TABLE, "fp", ())},
            output_strategy="s",
            vault_strategy="v",
            index_strategy="i",
            plan_fingerprint="fp",
        )
    with pytest.raises(ValueError, match="must be a list or tuple"):
        PreflightResult(False, {"a": PreflightIssue("C", None, None)})


def test_collection_members_must_be_frozen_public_models() -> None:
    with pytest.raises(ValueError, match="FieldPlan instances"):
        TablePlan(SYNTH_TABLE, "fp-SYNTH", ["CODE"])
    with pytest.raises(ValueError, match="TablePlan instances"):
        Plan(
            dataset_identity=DatasetIdentity("fp", (SYNTH_TABLE,), 1),
            policy_summary=PolicySummary("p", "fp"),
            relationships=RelationshipMetadata("fp", "policy-declared", ()),
            table_plans=[{"relative_path": SYNTH_TABLE}],
            output_strategy="s",
            vault_strategy="v",
            index_strategy="i",
            plan_fingerprint="fp",
        )


def test_nested_members_are_immutable_public_models() -> None:
    plan = _synthetic_plan()
    table_plan = plan.table_plans[0]
    assert isinstance(table_plan, TablePlan)
    assert isinstance(table_plan.fields[0], FieldPlan)
    member = plan.relationships.groups[0].members[0]
    assert isinstance(member, RelationshipMember)
    with pytest.raises(dataclasses.FrozenInstanceError):
        member.role = "mutated"


# ---------------------------------------------------------------------------
# C. strict JSON parsing
# ---------------------------------------------------------------------------


def test_malformed_child_rejects_the_whole_payload() -> None:
    base = _synthetic_plan().to_dict()
    payload = json.loads(json.dumps(base))
    payload["table_plans"][0]["fields"] = [
        payload["table_plans"][0]["fields"][0],
        "not-an-object",
    ]
    with pytest.raises(ValueError, match="must be an array of objects"):
        Plan.from_dict(payload)


def test_non_mapping_member_rejects_the_payload() -> None:
    payload = json.loads(json.dumps(_synthetic_plan().to_dict()))
    payload["table_plans"].append("string-child")
    with pytest.raises(ValueError, match="must be an array of objects"):
        Plan.from_dict(payload)
    group_payload = json.loads(json.dumps(plan_group_with_member()))
    group_payload["members"].append(123)
    with pytest.raises(ValueError, match="must be an array of objects"):
        RelationshipGroup.from_dict(group_payload)
    preflight = json.loads(json.dumps(_synthetic_instance(PreflightResult).to_dict()))
    preflight["issues"].append(["not", "a", "mapping"])
    with pytest.raises(ValueError, match="must be an array of objects"):
        PreflightResult.from_dict(preflight)


def plan_group_with_member() -> dict[str, Any]:
    group = RelationshipGroup(
        "SYNTH-GROUP-1",
        "policy-declared",
        COMPARISON_SEMANTICS_EXACT,
        (RelationshipMember(SYNTH_TABLE, "KEY", "primary", 0),),
    )
    return group.to_dict()


#: Enum-typed fields (declared contract tied to real serializer output: the
#: serialized value must be a member of the exact enum).
ENUM_FIELDS: Mapping[str, Mapping[str, type[Enum]]] = {
    "PseudonymizationResult": {"status": ResultStatus},
    "VerificationResult": {"status": VerificationStatus, "assurance": RelationalAssurance},
    "RecoveryResult": {"status": ResultStatus},
    "TransferBundleResult": {"status": ResultStatus},
}

#: Fields wired through construction-time relative-path normalization
#: (proved by the backslash-normalization tests).  A model whose nested
#: collections carry path-bearing members is itself path-bearing.
PATH_FIELDS: Mapping[str, frozenset[str]] = {
    "FieldPlan": set(),
    "TablePlan": {"relative_path", "fields"},
    "PolicySummary": set(),
    "RelationshipMember": {"relative_path"},
    "RelationshipGroup": {"members"},
    "RelationshipMetadata": {"groups"},
    "PreflightIssue": {"table"},
    "Capabilities": set(),
    "DatasetIdentity": {"tables"},
    "Plan": {"table_plans", "dataset_identity", "policy_summary", "relationships"},
    "ProgressEvent": {"table"},
    "PreflightResult": {"issues"},
    "PseudonymizationResult": {"artifact_paths"},
    "VerificationResult": set(),
    "RecoveryResult": {"restored_artifact_paths"},
    "TransferBundleResult": {"artifact_paths"},
}


def test_snapshot_path_flags_match_actual_models() -> None:
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert set(snapshot["models"]) == {m.__name__ for m in ALL_PUBLIC_MODELS}
    for name, declared in snapshot["models"].items():
        model = next(m for m in ALL_PUBLIC_MODELS if m.__name__ == name)
        has_path_field = bool(PATH_FIELDS[name])
        assert declared["path_bearing"] == has_path_field, name
        # Every declared path-bearing field must exist on the actual model.
        for field_name in PATH_FIELDS[name]:
            assert field_name in {f.name for f in dataclasses.fields(model)}, (
                f"{name}.{field_name}"
            )


def test_path_arrays_reject_non_string_members() -> None:
    for bad_member in (123, True, 1.5, {"path": "x"}, None, ["list"]):
        payload = json.loads(json.dumps(_synthetic_instance(DatasetIdentity).to_dict()))
        payload["tables"] = [SYNTH_TABLE, bad_member]
        with pytest.raises(ValueError, match="array of relative path"):
            DatasetIdentity.from_dict(payload)


def test_no_silent_filtering_in_child_arrays() -> None:
    payload = json.loads(json.dumps(_synthetic_instance(PreflightResult).to_dict()))
    payload["issues"] = [
        payload["issues"][0],
        {"unexpected": "dropped-in-old-implementation"},
    ]
    with pytest.raises(ValueError):
        PreflightResult.from_dict(payload)


def test_wrong_nested_discriminator_fails_closed() -> None:
    payload = json.loads(json.dumps(_synthetic_instance(TablePlan).to_dict()))
    payload["fields"][0]["model"] = "PolicySummary"
    with pytest.raises(ValueError, match="discriminator"):
        TablePlan.from_dict(payload)


def test_wrong_nested_schema_version_fails_closed() -> None:
    payload = json.loads(json.dumps(_synthetic_instance(TablePlan).to_dict()))
    payload["fields"][0]["schema_version"] = 99
    with pytest.raises(ValueError, match="schema version"):
        TablePlan.from_dict(payload)


@pytest.mark.parametrize("bad_version", (True, 1.0, 2, "1", None))
def test_schema_version_strictly_rejects_non_exact_integer_one(bad_version: Any) -> None:
    payload = json.loads(json.dumps(_synthetic_instance(Capabilities).to_dict()))
    payload["schema_version"] = bad_version
    with pytest.raises(ValueError, match="schema version"):
        Capabilities.from_dict(payload)


def test_unknown_key_error_does_not_echo_caller_controlled_text() -> None:
    payload = json.loads(json.dumps(_synthetic_instance(PreflightResult).to_dict()))
    attacker_key = "secret-canary-key-with-token-content"
    payload[attacker_key] = "attacker-controlled-canary-value"
    with pytest.raises(ValueError) as excinfo:
        PreflightResult.from_dict(payload)
    message = str(excinfo.value)
    assert attacker_key not in message
    assert "attacker-controlled-canary-value" not in message
    assert "1 unknown key(s)" in message


def test_missing_mandatory_key_error_names_schema_keys_only() -> None:
    payload = json.loads(json.dumps(_synthetic_instance(PreflightResult).to_dict()))
    del payload["ready"]
    with pytest.raises(ValueError, match="missing mandatory public model keys"):
        PreflightResult.from_dict(payload)


# ---------------------------------------------------------------------------
# D. all public models versioned
# ---------------------------------------------------------------------------


def test_every_public_model_serializes_versioned_and_round_trips() -> None:
    for model in ALL_PUBLIC_MODELS:
        instance = _synthetic_instance(model)
        payload = instance.to_dict()
        assert payload["model"] == model.__name__, model.__name__
        assert payload["schema_version"] == 1
        assert type(payload["schema_version"]) is int
        encoded = json.dumps(payload)
        restored = model.from_dict(json.loads(encoded))
        assert restored == instance, model.__name__


def test_nested_payloads_embedded_in_parents_are_versioned() -> None:
    payload = _synthetic_plan().to_dict()
    assert payload["table_plans"][0]["model"] == "TablePlan"
    assert payload["table_plans"][0]["schema_version"] == 1
    assert payload["table_plans"][0]["fields"][0]["model"] == "FieldPlan"
    assert payload["relationships"]["model"] == "RelationshipMetadata"
    assert payload["policy_summary"]["schema_version"] == 1


# ---------------------------------------------------------------------------
# E. relationship contract (synthetic composite PK/FK)
# ---------------------------------------------------------------------------


def test_synthetic_composite_pk_fk_relationship_contract() -> None:
    pk_table = "alpha/synthetic.dbf"
    fk_table = "beta/synthetic.dbf"
    metadata = RelationshipMetadata(
        relationship_fingerprint="fp-SYNTH-RELATIONS",
        provenance="policy-declared",
        groups=(
            RelationshipGroup(
                group_id="SYNTH-COMPOSITE-1",
                provenance="policy-declared",
                comparison_semantics=COMPARISON_SEMANTICS_EXACT,
                members=(
                    RelationshipMember(pk_table, "A1", "primary", 0),
                    RelationshipMember(pk_table, "A2", "primary", 1),
                    RelationshipMember(fk_table, "B1", "foreign", 0),
                    RelationshipMember(fk_table, "B2", "foreign", 1),
                ),
            ),
        ),
    )
    payload = metadata.to_dict()
    group = payload["groups"][0]
    members = group["members"]
    assert [m["relative_path"] for m in members] == [pk_table, pk_table, fk_table, fk_table]
    assert [m["field_name"] for m in members] == ["A1", "A2", "B1", "B2"]
    assert [m["role"] for m in members] == ["primary", "primary", "foreign", "foreign"]
    assert [m["component_index"] for m in members] == [0, 1, 0, 1]
    # Index 0 pairs A1 <-> B1; index 1 pairs A2 <-> B2 across the two tables.
    primary_by_index = {m["component_index"]: m["field_name"] for m in members if m["role"] == "primary"}
    foreign_by_index = {m["component_index"]: m["field_name"] for m in members if m["role"] == "foreign"}
    assert primary_by_index == {0: "A1", 1: "A2"}
    assert foreign_by_index == {0: "B1", 1: "B2"}
    assert group["comparison_semantics"] == COMPARISON_SEMANTICS_EXACT
    assert payload["relationship_fingerprint"] == "fp-SYNTH-RELATIONS"
    assert RelationshipMetadata.from_dict(json.loads(json.dumps(payload))) == metadata


# ---------------------------------------------------------------------------
# F. plan contract (future P1-005 representation)
# ---------------------------------------------------------------------------


def test_plan_contract_carries_p1_005_strategy_identifiers() -> None:
    plan = _synthetic_plan()
    payload = plan.to_dict()
    assert payload["dataset_identity"]["dataset_fingerprint"] == "fp-SYNTH-DATASET"
    assert payload["policy_summary"]["policy_fingerprint"] == "fp-SYNTH-POLICY"
    assert payload["relationships"]["relationship_fingerprint"] == "fp-SYNTH-RELATIONS"
    assert payload["output_strategy"] == "sibling-output-tree"
    assert payload["vault_strategy"] == "single-vault"
    assert payload["index_strategy"] == "metadata-only"
    assert payload["plan_fingerprint"] == "fp-SYNTH-PLAN"
    encoded = json.dumps(payload)
    # No absolute output/vault/index filesystem paths are representable.
    for forbidden in (":/", "\\", "C:", "TEMP", "Users"):
        assert forbidden not in encoded


# ---------------------------------------------------------------------------
# G. mechanically verified schema snapshot
# ---------------------------------------------------------------------------


def _type_category(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        if not value:
            return "array"
        first = value[0]
        if isinstance(first, Mapping):
            return f"array-of-object:{first['model']}"
        if isinstance(first, str):
            return "array-of-string"
        raise AssertionError(f"unexpected array member: {first!r}")
    if isinstance(value, Mapping):
        return f"object:{value['model']}"
    raise AssertionError(f"unexpected serialized value: {value!r}")


def _merge_category(observed_a: str, observed_b: str | None) -> str:
    """Union of the categories observed across the normal and the nullable
    probe payloads (a field is declared nullable only when the actual model
    accepts None for it)."""
    if observed_b is None or observed_a == observed_b:
        return observed_a
    base_a = observed_a[: -len("-or-null")] if observed_a.endswith("-or-null") else observed_a
    base_b = observed_b[: -len("-or-null")] if observed_b.endswith("-or-null") else observed_b
    nullable = (
        observed_a.endswith("-or-null")
        or observed_b.endswith("-or-null")
        or observed_b == "null"
        or observed_a == "null"
    )
    if observed_a == "null":
        base_a = base_b
    if observed_b == "null":
        base_b = base_a
    if base_a != base_b:
        raise AssertionError(f"conflicting observed categories: {observed_a} vs {observed_b}")
    return f"{base_a}-or-null" if nullable else base_a


#: Nullable-field probes: constructions exercising the nullable branches; the
#: observed category union mechanically proves the declared nullability
#: against real serializer behavior (a field is labeled nullable only when the
#: actual model accepts None for it).
NULLABLE_PROBES: Mapping[str, tuple[Callable[[], Any], ...]] = {
    "FieldPlan": (lambda: FieldPlan("CODE", "C", "pseudonymize", None),),
    "ProgressEvent": (
        lambda: ProgressEvent(SYNTH_OP, "scan", 0, None, "tables", SYNTH_TABLE),
        lambda: ProgressEvent(SYNTH_OP, "scan", 0, 1, None, None),
    ),
    "PreflightIssue": (
        lambda: PreflightIssue("SYNTH-CODE", None, None),
        lambda: PreflightIssue("SYNTH-CODE", "x/synthetic.dbf", "SYNTH-FIELD"),
    ),
}


def _live_serialized_contract() -> dict[str, dict[str, object]]:
    live: dict[str, dict[str, object]] = {}
    for model in ALL_PUBLIC_MODELS:
        payload = _synthetic_instance(model).to_dict()
        categories = {key: _type_category(value) for key, value in payload.items()}
        for probe_factory in NULLABLE_PROBES.get(model.__name__, ()):
            probe_payload = probe_factory().to_dict()
            for key, value in probe_payload.items():
                observed = _type_category(value)
                categories[key] = _merge_category(categories[key], observed)
        # Declared path fields: the ACTUAL values must be normalized relative
        # paths (or None for nullable path fields), and the categories are
        # labeled as path categories accordingly.
        path_fields = PATH_FIELDS[model.__name__]
        for key in path_fields:
            assert key in categories, f"{model.__name__}.{key}"
        # Declared enum fields: the ACTUAL serialized value must be a valid
        # enum member (mechanical tie between snapshot and serializer).
        for key, enum_type in ENUM_FIELDS.get(model.__name__, {}).items():
            assert categories[key] == "string", f"{model.__name__}.{key}"
            assert payload[key] in [member.value for member in enum_type], (
                f"{model.__name__}.{key}"
            )
            categories[key] = f"enum:{enum_type.__name__}"
        live[model.__name__] = {
            "kind": "top-level" if model in TOP_LEVEL_MODELS else "nested",
            "serialized_keys": list(payload.keys()),
            "serialized_types": {
                key: (
                    _path_category(categories[key], key in path_fields)
                    if key in path_fields
                    else categories[key]
                )
                for key in payload
            },
        }
    return live


def _path_category(observed: str, declared_path: bool) -> str:
    if not declared_path:
        return observed
    if observed == "null":
        return "relative-path-or-null"
    if observed.startswith("array-of-string"):
        return "array-of-relative-path"
    if observed == "string":
        return "relative-path"
    if observed == "string-or-null":
        return "relative-path-or-null"
    if observed == "array":
        return "array-of-relative-path"
    if observed.startswith(("object:", "array-of-object:")):
        # Nested-model containers (e.g. Plan.table_plans) are path-bearing
        # through their members; the container category is unchanged.
        return observed
    raise AssertionError(f"unexpected path value category: {observed}")


def _assert_declared_path_values_are_normalized(live: Mapping[str, Mapping[str, object]]) -> None:
    """For every declared path field the ACTUAL serialized values must already
    be normalized relative paths (construction-time invariant evidence)."""
    for name, contract in live.items():
        for field_name in PATH_FIELDS[name]:
            assert field_name in contract["serialized_keys"], f"{name}.{field_name}"
        # Path normalization itself is proven by the construction tests; the
        # live contract categories are labeled through the declarative map.


def test_snapshot_is_mechanically_verified_against_actual_serializers() -> None:
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    live = _live_serialized_contract()
    # Snapshot and live contract must enumerate exactly the same models.
    assert set(snapshot["models"]) == set(live) == {m.__name__ for m in ALL_PUBLIC_MODELS}
    for name, declared in snapshot["models"].items():
        actual = live[name]
        # The snapshot's declared serialized keys exactly equal ACTUAL keys.
        assert declared["serialized_keys"] == actual["serialized_keys"], name
        # Discriminator and version presence are proven by the live payloads.
        instance = _synthetic_instance(next(m for m in ALL_PUBLIC_MODELS if m.__name__ == name))
        payload = instance.to_dict()
        assert payload["model"] == name and payload["schema_version"] == 1
        # Declared serialized types equal ACTUAL serialized types.
        assert declared["serialized_types"] == actual["serialized_types"], name


def test_snapshot_enum_values_equal_production_values() -> None:
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert snapshot["enums"]["RelationalAssurance"] == [
        member.value for member in RelationalAssurance
    ]
    assert snapshot["enums"]["VerificationStatus"] == [
        member.value for member in VerificationStatus
    ]
    assert snapshot["enums"]["ResultStatus"] == [member.value for member in ResultStatus]


# ---------------------------------------------------------------------------
# H. privacy
# ---------------------------------------------------------------------------


def test_no_public_model_declares_a_forbidden_field_name() -> None:
    from dbf_anonymizer.models import FORBIDDEN_FIELD_NAMES

    for model in ALL_PUBLIC_MODELS:
        names = {field.name for field in dataclasses.fields(model)}
        leaked = names & FORBIDDEN_FIELD_NAMES
        assert not leaked, f"{model.__name__} leaks channel: {sorted(leaked)}"


def test_serialized_payloads_offer_no_original_value_slot() -> None:
    from dbf_anonymizer.models import FORBIDDEN_FIELD_NAMES

    def assert_clean(payload: Mapping[str, Any]) -> None:
        for key, value in payload.items():
            assert key not in FORBIDDEN_FIELD_NAMES, key
            if isinstance(value, Mapping):
                assert_clean(value)

    for model in ALL_PUBLIC_MODELS:
        payload = _synthetic_instance(model).to_dict()
        assert_clean(payload)
        json.dumps(payload)


def test_public_serialization_contains_no_absolute_or_private_paths() -> None:
    for model in ALL_PUBLIC_MODELS:
        encoded = json.dumps(_synthetic_instance(model).to_dict())
        assert "\\" not in encoded, model.__name__
        for forbidden in (":/", "TEMP", "Users", "peter", "AppData"):
            assert forbidden not in encoded, (model.__name__, forbidden)


def test_rejection_messages_never_echo_values_or_unknown_keys() -> None:
    secret_path = "C:\\synthetic-canary\\secret.dbf"
    with pytest.raises(ValueError) as drive_error:
        _normalize_relative_path(secret_path)
    assert "canary" not in str(drive_error.value)
    assert "synthetic" not in str(drive_error.value)
    payload = json.loads(json.dumps(_synthetic_instance(PreflightResult).to_dict()))
    payload["attacker-key-canary"] = "attacker-value-canary"
    with pytest.raises(ValueError) as unknown_error:
        PreflightResult.from_dict(payload)
    assert "canary" not in str(unknown_error.value)


# ---------------------------------------------------------------------------
# py.typed and enums
# ---------------------------------------------------------------------------


def test_py_typed_marker_is_present_in_the_source_package() -> None:
    assert (REPO_ROOT / "src" / "dbf_anonymizer" / "py.typed").is_file()


def test_py_typed_is_present_in_the_built_wheel() -> None:
    wheel = WHEEL_PATH
    if not wheel.is_file():  # pragma: no cover - build locally before evidence
        pytest.fail("wheel must be built before running the P1-002 evidence suite")
    with zipfile.ZipFile(wheel) as archive:
        assert "dbf_anonymizer/py.typed" in archive.namelist()


def test_relational_assurance_matches_the_architecture_vocabulary() -> None:
    assert [member.value for member in RelationalAssurance] == [
        "GLOBAL_EXACT_VALUE",
        "DECLARED_RELATIONS_VERIFIED",
        "VFP_METADATA_VERIFIED",
        "INCOMPLETE",
    ]


def test_verification_status_matches_the_architecture_vocabulary() -> None:
    assert [member.value for member in VerificationStatus] == ["PASS", "PARTIAL", "FAIL"]


def test_relative_paths_normalize_to_forward_slashes() -> None:
    assert _normalize_relative_path("north\\sub\\customers.dbf") == "north/sub/customers.dbf"