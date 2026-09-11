"""REQ-P1-002 — deterministic acceptance evidence for typed public models.

Proves importability, immutability, JSON-safe versioned serialization,
round-trips, fail-closed parsing, normalized relative paths, privacy by
construction, the py.typed marker and the committed schema snapshot.
"""

from __future__ import annotations

import dataclasses
import json
import re
import zipfile
from collections.abc import Mapping
from pathlib import Path

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
from dbf_anonymizer.models import FORBIDDEN_FIELD_NAMES, _normalize_relative_path

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = REPO_ROOT / "tests" / "snapshots" / "p1_public_models_v1.json"

#: Synthetic-only constants (obviously fake; no original values anywhere).
SYNTH_OP = "op-SYNTH-0001"
SYNTH_FINGERPRINT = "sha256:SYNTH-FINGERPRINT"
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

FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "raw_value",
        "original_value",
        "source_value",
        "sample",
        "record",
        "memo_payload",
        "binary_payload",
        "arbitrary_data",
        "metadata",
        "context",
        "details",
    }
)


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
            provenance="policy-declared",
            groups=(
                RelationshipGroup(
                    group_id="SYNTH-GROUP-1",
                    provenance="policy-declared",
                    members=(
                        RelationshipMember(
                            relative_path=SYNTH_TABLE, field_name="KEY", role="primary"
                        ),
                        RelationshipMember(
                            relative_path="south/synthetic.dbf",
                            field_name="KEY",
                            role="foreign",
                        ),
                    ),
                    composite_ordering=("KEY",),
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
        strategy="direct-read-write",
        plan_fingerprint="fp-SYNTH-PLAN",
    )


def _synthetic_instance(model: type) -> object:
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
            issues=(
                PreflightIssue(code="SYNTH-ISSUE-CODE", table=SYNTH_TABLE, field_name=None),
            ),
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
            relative_path=SYNTH_TABLE, field_name="KEY", role="primary"
        )
    if model is RelationshipGroup:
        return RelationshipGroup(
            group_id="SYNTH-GROUP-1",
            provenance="policy-declared",
            members=(RelationshipMember(SYNTH_TABLE, "KEY", "primary"),),
            composite_ordering=("KEY",),
        )
    if model is RelationshipMetadata:
        return RelationshipMetadata(
            provenance="policy-declared",
            groups=(RelationshipGroup("SYNTH-GROUP-1", "policy-declared", (), ()),),
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


def test_enums_are_root_importable() -> None:
    assert dbf_anonymizer.RelationalAssurance is RelationalAssurance
    assert dbf_anonymizer.VerificationStatus is VerificationStatus
    assert dbf_anonymizer.ResultStatus is ResultStatus
    assert dbf_anonymizer.PUBLIC_MODEL_SCHEMA_VERSION == 1


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
# immutability
# ---------------------------------------------------------------------------


def test_public_models_are_frozen_with_slots() -> None:
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
        plan.strategy = "mutated"


def test_public_model_collections_are_immutable_tuples() -> None:
    plan = _synthetic_plan()
    assert isinstance(plan.dataset_identity.tables, tuple)
    assert isinstance(plan.table_plans, tuple)
    assert isinstance(plan.relationships.groups, tuple)
    assert isinstance(plan.relationships.groups[0].members, tuple)
    for model in ALL_PUBLIC_MODELS:
        for field in dataclasses.fields(model):
            assert field.type.startswith("tuple[") or field.type not in {
                "list",
                "dict",
                "set",
            }, (model.__name__, field.name)


# ---------------------------------------------------------------------------
# relative path normalization and rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized"),
    (
        ("customers.dbf", "customers.dbf"),
        ("north/customers.dbf", "north/customers.dbf"),
        ("north\\customers.dbf", "north/customers.dbf"),
        ("north\\sub\\customers.dbf", "north/sub/customers.dbf"),
    ),
)
def test_relative_paths_normalize_to_forward_slashes(raw: str, normalized: str) -> None:
    assert _normalize_relative_path(raw) == normalized


@pytest.mark.parametrize(
    "rejected",
    (
        "/abs/customers.dbf",
        "\\abs\\customers.dbf",
        "C:\\data\\customers.dbf",
        "C:/data/customers.dbf",
        "\\\\server\\share\\customers.dbf",
        "//server/share/customers.dbf",
        "../customers.dbf",
        "north/../customers.dbf",
        "north/..\\customers.dbf",
        "north//customers.dbf",
        "north/./customers.dbf",
        "",
        "bad\x00.dbf",
    ),
)
def test_invalid_paths_are_rejected(rejected: str) -> None:
    with pytest.raises(ValueError):
        _normalize_relative_path(rejected)


def test_rejection_messages_never_echo_the_value() -> None:
    secret_like = "C:\\synthetic-secret\\canary.dbf"
    with pytest.raises(ValueError) as excinfo:
        _normalize_relative_path(secret_like)
    assert "canary" not in str(excinfo.value)
    assert "synthetic-secret" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# serialization: JSON safety, discriminator, version, round-trips
# ---------------------------------------------------------------------------


def test_every_top_level_to_dict_is_json_safe_and_carries_discriminator() -> None:
    for model in TOP_LEVEL_MODELS:
        payload = _synthetic_instance(model).to_dict()
        encoded = json.dumps(payload := json.loads(json.dumps(payload)))  # type: ignore[name-defined]
        assert json.loads(encoded) == payload
        assert payload["model"] == model.__name__
        assert payload["schema_version"] == 1
        assert "canary" not in encoded


def test_every_required_model_survives_the_json_round_trip() -> None:
    for model in ALL_PUBLIC_MODELS:
        instance = _synthetic_instance(model)
        decoded = json.loads(json.dumps(instance.to_dict()))
        restored = model.from_dict(decoded)
        assert restored == instance, model.__name__


def test_nested_models_serialize_as_plain_objects() -> None:
    table = TablePlan(
        relative_path=SYNTH_TABLE,
        schema_fingerprint="fp-SYNTH",
        fields=(FieldPlan(field_name="CODE", dbf_type="C", action="pseudonymize"),),
    )
    payload = table.to_dict()
    assert "model" not in payload and "schema_version" not in payload
    assert TablePlan.from_dict(payload) == table


def test_unsupported_schema_version_fails_closed() -> None:
    payload = _synthetic_instance(Capabilities).to_dict()
    payload["schema_version"] = PUBLIC_MODEL_SCHEMA_VERSION + 1
    with pytest.raises(ValueError, match="schema version"):
        Capabilities.from_dict(payload)


def test_wrong_discriminator_fails_closed() -> None:
    payload = _synthetic_instance(DatasetIdentity).to_dict()
    payload["model"] = "Plan"
    with pytest.raises(ValueError, match="discriminator"):
        DatasetIdentity.from_dict(payload)


@pytest.mark.parametrize(
    ("model", "payload_key"),
    (
        (Capabilities, "dbfbridge_version"),
        (DatasetIdentity, "tables"),
        (Plan, "strategy"),
        (PreflightResult, "ready"),
        (PseudonymizationResult, "records_processed"),
        (VerificationResult, "assurance"),
    ),
)
def test_missing_mandatory_key_fails_closed(model: type, payload_key: str) -> None:
    payload = _synthetic_instance(model).to_dict()
    del payload[payload_key]
    with pytest.raises(ValueError, match="missing mandatory"):
        model.from_dict(payload)


def test_unknown_key_fails_closed() -> None:
    payload = _synthetic_instance(PreflightResult).to_dict()
    payload["details"] = {"anything": "original canary value"}
    with pytest.raises(ValueError, match="unknown public model keys"):
        PreflightResult.from_dict(payload)


def test_invalid_enum_value_fails_closed() -> None:
    payload = _synthetic_instance(VerificationResult).to_dict()
    payload["status"] = "NOT-A-STATUS"
    with pytest.raises(ValueError, match="must be one of"):
        VerificationResult.from_dict(payload)


def test_invalid_path_fails_closed_in_from_dict() -> None:
    payload = _synthetic_instance(DatasetIdentity).to_dict()
    payload["tables"] = ["C:\\absolute\\canary.dbf"]
    with pytest.raises(ValueError, match="path fields"):
        DatasetIdentity.from_dict(payload)


# ---------------------------------------------------------------------------
# schema snapshot (three-way consistency, not snapshot vs itself)
# ---------------------------------------------------------------------------


CONTRACT_SPEC: Mapping[str, object] = {
    "top_level_models": {
        "Capabilities": {"discriminator": "Capabilities", "kind": "top-level", "fields": {
            "product_version": {"type": "string", "path": False},
            "dbfbridge_version": {"type": "string", "path": False},
            "supported_profiles": {"type": "array-of-string", "path": False},
            "features": {"type": "array-of-string", "path": False}}},
        "DatasetIdentity": {"discriminator": "DatasetIdentity", "kind": "top-level", "fields": {
            "dataset_fingerprint": {"type": "string", "path": False},
            "tables": {"type": "array-of-relative-path", "path": True},
            "table_count": {"type": "integer", "path": False}}},
        "Plan": {"discriminator": "Plan", "kind": "top-level", "fields": {
            "dataset_identity": {"type": "object:DatasetIdentity", "path": False},
            "policy_summary": {"type": "object:PolicySummary", "path": False},
            "relationships": {"type": "object:RelationshipMetadata", "path": False},
            "table_plans": {"type": "array-of-object:TablePlan", "path": False},
            "strategy": {"type": "string", "path": False},
            "plan_fingerprint": {"type": "string", "path": False}}},
        "ProgressEvent": {"discriminator": "ProgressEvent", "kind": "top-level", "fields": {
            "operation_id": {"type": "string", "path": False},
            "phase": {"type": "string", "path": False},
            "completed": {"type": "integer", "path": False},
            "total": {"type": "integer-or-null", "path": False},
            "unit": {"type": "string-or-null", "path": False},
            "table": {"type": "relative-path-or-null", "path": True}}},
        "PreflightResult": {"discriminator": "PreflightResult", "kind": "top-level", "fields": {
            "ready": {"type": "boolean", "path": False},
            "issues": {"type": "array-of-object:PreflightIssue", "path": False}}},
        "PseudonymizationResult": {"discriminator": "PseudonymizationResult", "kind": "top-level", "fields": {
            "operation_id": {"type": "string", "path": False},
            "status": {"type": "enum:ResultStatus", "path": False},
            "dataset_fingerprint": {"type": "string", "path": False},
            "artifact_paths": {"type": "array-of-relative-path", "path": True},
            "tables_processed": {"type": "integer", "path": False},
            "records_processed": {"type": "integer", "path": False}}},
        "VerificationResult": {"discriminator": "VerificationResult", "kind": "top-level", "fields": {
            "operation_id": {"type": "string", "path": False},
            "status": {"type": "enum:VerificationStatus", "path": False},
            "dataset_fingerprint": {"type": "string", "path": False},
            "tables_verified": {"type": "integer", "path": False},
            "records_verified": {"type": "integer", "path": False},
            "mismatches": {"type": "integer", "path": False},
            "assurance": {"type": "enum:RelationalAssurance", "path": False}}},
        "RecoveryResult": {"discriminator": "RecoveryResult", "kind": "top-level", "fields": {
            "operation_id": {"type": "string", "path": False},
            "status": {"type": "enum:ResultStatus", "path": False},
            "restored_artifact_paths": {"type": "array-of-relative-path", "path": True},
            "records_restored": {"type": "integer", "path": False}}},
        "TransferBundleResult": {"discriminator": "TransferBundleResult", "kind": "top-level", "fields": {
            "operation_id": {"type": "string", "path": False},
            "status": {"type": "enum:ResultStatus", "path": False},
            "bundle_id": {"type": "string", "path": False},
            "bundle_fingerprint": {"type": "string", "path": False},
            "artifact_paths": {"type": "array-of-relative-path", "path": True}}},
    },
    "nested_models": {
        "FieldPlan": {"kind": "nested", "fields": {
            "field_name": {"type": "string", "path": False},
            "dbf_type": {"type": "string", "path": False},
            "action": {"type": "string", "path": False},
            "domain": {"type": "string-or-null", "path": False}}},
        "TablePlan": {"kind": "nested", "fields": {
            "relative_path": {"type": "relative-path", "path": True},
            "schema_fingerprint": {"type": "string", "path": False},
            "fields": {"type": "array-of-object:FieldPlan", "path": False}}},
        "PolicySummary": {"kind": "nested", "fields": {
            "profile": {"type": "string", "path": False},
            "policy_fingerprint": {"type": "string", "path": False}}},
        "RelationshipMember": {"kind": "nested", "fields": {
            "relative_path": {"type": "relative-path", "path": True},
            "field_name": {"type": "string", "path": False},
            "role": {"type": "string", "path": False}}},
        "RelationshipGroup": {"kind": "nested", "fields": {
            "group_id": {"type": "string", "path": False},
            "provenance": {"type": "string", "path": False},
            "members": {"type": "array-of-object:RelationshipMember", "path": False},
            "composite_ordering": {"type": "array-of-string", "path": False}}},
        "RelationshipMetadata": {"kind": "nested", "fields": {
            "provenance": {"type": "string", "path": False},
            "groups": {"type": "array-of-object:RelationshipGroup", "path": False}}},
        "PreflightIssue": {"kind": "nested", "fields": {
            "code": {"type": "string", "path": False},
            "table": {"type": "relative-path-or-null", "path": True},
            "field_name": {"type": "string-or-null", "path": False}}},
    },
    "enums": {
        "RelationalAssurance": [member.value for member in RelationalAssurance],
        "VerificationStatus": [member.value for member in VerificationStatus],
        "ResultStatus": [member.value for member in ResultStatus],
    },
}


def _normalized_snapshot_specs(snapshot: Mapping[str, object]) -> dict[str, dict[str, object]]:
    """Snapshot field specs carry required=true; the live contract encodes
    optionality in the serialized type itself, so compare with ``required``
    normalized out (it is separately asserted present and true everywhere)."""
    normalized: dict[str, dict[str, object]] = {}
    for section in ("top_level_models", "nested_models"):
        section_snapshot = snapshot[section]
        assert isinstance(section_snapshot, Mapping)
        section_data: dict[str, object] = {}
        for name, entry in section_snapshot.items():
            assert isinstance(entry, Mapping)
            fields: Mapping[str, Mapping[str, object]] = entry["fields"]  # type: ignore[assignment]
            entry_copy: dict[str, object] = {
                key: value for key, value in entry.items() if key != "fields"
            }
            entry_copy["fields"] = {
                field: {k: v for k, v in spec.items() if k != "required"}
                for field, spec in fields.items()
            }
            section_data[name] = entry_copy
        normalized[section] = section_data
    return normalized


def test_schema_snapshot_matches_the_current_public_contract() -> None:
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert snapshot["schema_version"] == PUBLIC_MODEL_SCHEMA_VERSION
    # Every snapshot field spec must declare required=true (P1-002 fields are
    # all mandatory; optional values are represented as nullable types).
    for section in ("top_level_models", "nested_models"):
        for fields in snapshot[section].values():  # type: ignore[union-attr]
            for spec in fields["fields"].values():  # type: ignore[index]
                assert spec["required"] is True
    # The live contract must equal the committed snapshot exactly.
    live_spec = {"top_level_models": CONTRACT_SPEC["top_level_models"], "nested_models": CONTRACT_SPEC["nested_models"]}
    assert _normalized_snapshot_specs(snapshot) == _normalized_snapshot_specs(live_spec)
    assert snapshot["enums"] == CONTRACT_SPEC["enums"]
    # ...and the contract must match the ACTUAL dataclass field names/counts.
    for section, kind in (("top_level_models", TOP_LEVEL_MODELS), ("nested_models", NESTED_MODELS)):
        declared = set(CONTRACT_SPEC[section])  # type: ignore[union-attr]
        actual = {model.__name__ for model in kind}
        assert declared == actual, (declared, actual)
        for model in kind:
            contract_fields = CONTRACT_SPEC[section][model.__name__]["fields"]  # type: ignore[index]
            assert set(contract_fields) == {f.name for f in dataclasses.fields(model)}


def test_snapshot_contains_only_generic_metadata() -> None:
    text = SNAPSHOT_PATH.read_text(encoding="utf-8")
    for forbidden in ("C:\\", "C:/", "/home/", "Users", "peter", "AppData"):
        assert forbidden not in text


# ---------------------------------------------------------------------------
# privacy by construction
# ---------------------------------------------------------------------------


def test_no_public_model_declares_a_forbidden_field_name() -> None:
    for model in ALL_PUBLIC_MODELS:
        names = {field.name for field in dataclasses.fields(model)}
        leaked = names & FORBIDDEN_FIELD_NAMES
        assert not leaked, f"{model.__name__} leaks channel: {sorted(leaked)}"


def test_serialized_payloads_offer_no_original_value_slot() -> None:
    for model in ALL_PUBLIC_MODELS:
        payload = _synthetic_instance(model).to_dict()
        _assert_no_forbidden_keys(payload)
        assert json.dumps(payload)


def _assert_no_forbidden_keys(payload: Mapping[str, object]) -> None:
    for key, value in payload.items():
        assert key not in FORBIDDEN_FIELD_NAMES, key
        if isinstance(value, Mapping):
            _assert_no_forbidden_keys(value)


def test_public_serialization_contains_no_absolute_or_private_paths() -> None:
    for model in ALL_PUBLIC_MODELS:
        encoded = json.dumps(_synthetic_instance(model).to_dict())
        assert "\\" not in encoded, model.__name__
        for forbidden in (":/", "TEMP", "Users", "peter", "AppData"):
            assert forbidden not in encoded, (model.__name__, forbidden)


# ---------------------------------------------------------------------------
# enums and py.typed
# ---------------------------------------------------------------------------


def test_relational_assurance_matches_the_architecture_vocabulary() -> None:
    assert [member.value for member in RelationalAssurance] == [
        "GLOBAL_EXACT_VALUE",
        "DECLARED_RELATIONS_VERIFIED",
        "VFP_METADATA_VERIFIED",
        "INCOMPLETE",
    ]


def test_verification_status_matches_the_architecture_vocabulary() -> None:
    assert [member.value for member in VerificationStatus] == ["PASS", "PARTIAL", "FAIL"]


def test_py_typed_marker_is_present_in_the_source_package() -> None:
    assert (REPO_ROOT / "src" / "dbf_anonymizer" / "py.typed").is_file()


def test_py_typed_is_declared_as_package_data() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dbf_anonymizer = ["py.typed"]' in pyproject