"""REQ-P1-002 — immutable typed public-model contract evidence."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, fields
from typing import Any

import pytest

from dbf_anonymizer import (
    MODEL_SCHEMA_VERSION,
    Capabilities,
    DatasetIdentity,
    Plan,
    PolicySummary,
    PreflightResult,
    ProgressEvent,
    PseudonymizationResult,
    RecoveryResult,
    RelationalAssurance,
    RelationalAssuranceLevel,
    RelationshipMetadata,
    TablePlan,
    TransferBundleResult,
    TransferProfile,
    VerificationResult,
)
from dbf_anonymizer.models import PUBLIC_MODEL_TYPES


def _samples() -> tuple[object, ...]:
    capabilities = Capabilities(
        direct_read=True,
        direct_write=True,
        recovery=True,
        transfer_bundle=True,
        vfp_index_backend=False,
        dbfbridge_version="1.1.0",
    )
    dataset = DatasetIdentity(
        dataset_id="dataset-001",
        source_fingerprint="sha256:source",
        table_paths=("north\\registry.dbf", "south/orders.dbf"),
    )
    tables = (
        TablePlan(
            table_path="north\\registry.dbf",
            memo_path=None,
            record_count=5,
            field_count=3,
            transform_field_count=1,
            structural_cdx=False,
            dbc_bound=False,
            index_strategy="DATA_ONLY",
        ),
        TablePlan(
            table_path="south/orders.dbf",
            memo_path="south/orders.fpt",
            record_count=10,
            field_count=5,
            transform_field_count=2,
            structural_cdx=True,
            dbc_bound=True,
            index_strategy="OMIT_STALE",
        ),
    )
    policy = PolicySummary(
        policy_schema_version="1.0",
        policy_fingerprint="sha256:policy",
        transformed_field_count=3,
        relationship_count=1,
        recovery_enabled=True,
        transformation_classes=("BIJECTIVE_TEXT", "DATE_SHIFT"),
    )
    relationships = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance="declared",
        relationship_fingerprint="sha256:relationships",
        relation_count=1,
        authoritative=False,
        metadata_path="metadata\\relationships.json",
    )
    assurance = RelationalAssurance(
        level=RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED,
        declared_relations=1,
        verified_relations=1,
        failed_relations=0,
        evidence_fingerprint="sha256:relationship-evidence",
    )
    plan = Plan(
        plan_id="plan-001",
        dataset=dataset,
        tables=tables,
        policy=policy,
        relationships=relationships,
        output_profile=TransferProfile.DATA_ONLY,
        relationship_assurance_target=RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED,
    )
    return (
        capabilities,
        dataset,
        tables[0],
        policy,
        relationships,
        assurance,
        plan,
        ProgressEvent(
            operation_id="operation-001",
            phase_code="WRITE",
            event_code="TABLE_DONE",
            completed_units=1,
            total_units=2,
            table_path="north\\registry.dbf",
        ),
        PreflightResult(
            ready=True,
            plan_id="plan-001",
            capabilities=capabilities,
            check_codes=("SOURCE_READABLE",),
            warning_codes=("STRUCTURAL_CDX_OMITTED",),
            error_codes=(),
        ),
        PseudonymizationResult(
            operation_id="operation-001",
            dataset=dataset,
            output_path="output\\pseudonymized",
            table_count=2,
            record_count=15,
            vault_created=True,
            output_fingerprint="sha256:output",
            assurance=assurance,
        ),
        VerificationResult(
            verified=True,
            dataset=dataset,
            table_count=2,
            record_count=15,
            check_codes=("HASH_OK", "RELATIONS_OK"),
            assurance=assurance,
        ),
        RecoveryResult(
            operation_id="operation-002",
            dataset=dataset,
            output_path="output\\recovered",
            table_count=2,
            record_count=15,
            verified=True,
        ),
        TransferBundleResult(
            bundle_path="transfer\\bundle",
            profile=TransferProfile.DATA_ONLY,
            file_count=4,
            manifest_fingerprint="sha256:manifest",
            verified=True,
            assurance=assurance,
        ),
    )


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        result = {str(key) for key in value}
        for nested in value.values():
            result.update(_walk_keys(nested))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for nested in value:
            result.update(_walk_keys(nested))
        return result
    return set()


def test_all_required_models_are_public_root_imports() -> None:
    expected = {
        "Capabilities",
        "DatasetIdentity",
        "Plan",
        "TablePlan",
        "PolicySummary",
        "RelationshipMetadata",
        "RelationalAssurance",
        "ProgressEvent",
        "PreflightResult",
        "PseudonymizationResult",
        "VerificationResult",
        "RecoveryResult",
        "TransferBundleResult",
    }
    assert {model.__name__ for model in PUBLIC_MODEL_TYPES} == expected


def test_models_are_frozen_and_deeply_use_immutable_public_containers() -> None:
    dataset = _samples()[1]
    assert isinstance(dataset, DatasetIdentity)
    with pytest.raises(FrozenInstanceError):
        dataset.dataset_id = "changed"  # type: ignore[misc]
    assert isinstance(dataset.table_paths, tuple)


def test_every_public_model_is_json_safe_and_versioned() -> None:
    for model in _samples():
        payload = model.to_dict()  # type: ignore[union-attr]
        assert payload["schema_version"] == MODEL_SCHEMA_VERSION == "1.0"
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        assert json.loads(encoded) == payload


def test_relative_paths_are_normalized_before_serialization() -> None:
    samples = _samples()
    dataset = samples[1]
    progress = samples[7]
    pseudonymized = samples[9]
    bundle = samples[12]
    assert isinstance(dataset, DatasetIdentity)
    assert isinstance(progress, ProgressEvent)
    assert isinstance(pseudonymized, PseudonymizationResult)
    assert isinstance(bundle, TransferBundleResult)
    assert dataset.table_paths == ("north/registry.dbf", "south/orders.dbf")
    assert progress.table_path == "north/registry.dbf"
    assert pseudonymized.output_path == "output/pseudonymized"
    assert bundle.bundle_path == "transfer/bundle"


@pytest.mark.parametrize(
    "unsafe_path",
    ["C:\\private\\source.dbf", "/private/source.dbf", "../source.dbf", "x/../../source.dbf"],
)
def test_public_models_reject_absolute_or_traversing_paths(unsafe_path: str) -> None:
    with pytest.raises(ValueError):
        DatasetIdentity(
            dataset_id="dataset-001",
            source_fingerprint="sha256:source",
            table_paths=(unsafe_path,),
        )


def test_public_schema_has_no_fields_for_original_values_or_privileged_payloads() -> None:
    forbidden_field_names = {
        "original_value",
        "original_values",
        "value",
        "values",
        "memo_payload",
        "reverse_mapping",
        "vault_contents",
        "secret",
        "secrets",
        "source_absolute_path",
        "vault_path",
    }
    for model_type in PUBLIC_MODEL_TYPES:
        assert forbidden_field_names.isdisjoint(field.name for field in fields(model_type))
    for model in _samples():
        assert forbidden_field_names.isdisjoint(_walk_keys(model.to_dict()))  # type: ignore[union-attr]


def test_progress_event_has_codes_and_counts_but_no_free_form_message() -> None:
    assert {field.name for field in fields(ProgressEvent)} == {
        "operation_id",
        "phase_code",
        "event_code",
        "completed_units",
        "total_units",
        "table_path",
    }


def test_relational_assurance_levels_are_exact_architecture_values() -> None:
    assert {level.value for level in RelationalAssuranceLevel} == {
        "GLOBAL_EXACT_VALUE",
        "DECLARED_RELATIONS_VERIFIED",
        "VFP_METADATA_VERIFIED",
        "INCOMPLETE",
    }


def test_invalid_counts_and_inconsistent_states_fail_fast() -> None:
    capabilities = _samples()[0]
    assert isinstance(capabilities, Capabilities)
    with pytest.raises(ValueError):
        TablePlan("a.dbf", None, -1, 1, 0, False, False, "DATA_ONLY")
    with pytest.raises(ValueError):
        RelationalAssurance(
            RelationalAssuranceLevel.INCOMPLETE,
            declared_relations=1,
            verified_relations=1,
            failed_relations=1,
            evidence_fingerprint="sha256:evidence",
        )
    with pytest.raises(ValueError):
        PreflightResult(
            True,
            "plan-001",
            capabilities,
            check_codes=(),
            warning_codes=(),
            error_codes=("POLICY_INVALID",),
        )


def test_schema_key_snapshot_is_stable_for_req_p1_002() -> None:
    snapshots: dict[str, tuple[str, ...]] = {}
    for model in _samples():
        payload = model.to_dict()  # type: ignore[union-attr]
        snapshots[str(payload["model_type"])] = tuple(payload.keys())

    assert snapshots == {
        "Capabilities": (
            "schema_version", "model_type", "direct_read", "direct_write", "recovery",
            "transfer_bundle", "vfp_index_backend", "dbfbridge_version",
        ),
        "DatasetIdentity": (
            "schema_version", "model_type", "dataset_id", "source_fingerprint", "table_paths",
        ),
        "TablePlan": (
            "schema_version", "model_type", "table_path", "memo_path", "record_count",
            "field_count", "transform_field_count", "structural_cdx", "dbc_bound", "index_strategy",
        ),
        "PolicySummary": (
            "schema_version", "model_type", "policy_schema_version", "policy_fingerprint",
            "transformed_field_count", "relationship_count", "recovery_enabled", "transformation_classes",
        ),
        "RelationshipMetadata": (
            "schema_version", "model_type", "metadata_schema_version", "provenance",
            "relationship_fingerprint", "relation_count", "authoritative", "metadata_path",
        ),
        "RelationalAssurance": (
            "schema_version", "model_type", "level", "declared_relations", "verified_relations",
            "failed_relations", "evidence_fingerprint",
        ),
        "Plan": (
            "schema_version", "model_type", "plan_id", "dataset", "tables", "policy",
            "relationships", "output_profile", "relationship_assurance_target",
        ),
        "ProgressEvent": (
            "schema_version", "model_type", "operation_id", "phase_code", "event_code",
            "completed_units", "total_units", "table_path",
        ),
        "PreflightResult": (
            "schema_version", "model_type", "ready", "plan_id", "capabilities", "check_codes",
            "warning_codes", "error_codes",
        ),
        "PseudonymizationResult": (
            "schema_version", "model_type", "operation_id", "dataset", "output_path", "table_count",
            "record_count", "vault_created", "output_fingerprint", "assurance",
        ),
        "VerificationResult": (
            "schema_version", "model_type", "verified", "dataset", "table_count", "record_count",
            "check_codes", "assurance",
        ),
        "RecoveryResult": (
            "schema_version", "model_type", "operation_id", "dataset", "output_path", "table_count",
            "record_count", "verified",
        ),
        "TransferBundleResult": (
            "schema_version", "model_type", "bundle_path", "profile", "file_count",
            "manifest_fingerprint", "verified", "assurance",
        ),
    }
