"""REQ-P1-002 — immutable typed public-model contract evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, fields
from typing import Any

import pytest

from dbf_anonymizer import (
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    MODEL_SCHEMA_VERSION,
    Capabilities,
    DatasetIdentity,
    IndexBackendCapability,
    IndexBackendResult,
    IndexVerificationResult,
    NumericIdentityReview,
    Plan,
    PolicySummary,
    PreflightResult,
    ProgressEvent,
    PseudonymizationResult,
    RawByteEquivalence,
    RecoveryResult,
    RelationalAssurance,
    RelationalAssuranceLevel,
    RelationshipMetadata,
    StandaloneIdxAssociationResult,
    StandaloneIdxEvidence,
    TablePlan,
    TransferBundleResult,
    TransferProfile,
    VerificationResult,
    VerificationStatus,
    VaultStrategy,
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
        standalone_idx_paths=("north\\registry.idx",),
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
            memo_required=False,
            memo_companion_present=False,
            structural_cdx_companion_present=False,
            unsupported_field_count=0,
            unsafe_field_count=0,
            system_field_count=0,
        ),
        TablePlan(
            table_path="south/orders.dbf",
            memo_path="south/orders.fpt",
            record_count=10,
            field_count=5,
            transform_field_count=2,
            structural_cdx=True,
            dbc_bound=True,
            index_strategy="DATA_ONLY",
            memo_required=True,
            memo_companion_present=True,
            structural_cdx_companion_present=True,
            unsupported_field_count=0,
            unsafe_field_count=0,
            system_field_count=0,
        ),
    )
    policy = PolicySummary(
        policy_schema_version="1.0",
        policy_fingerprint="sha256:policy",
        transformed_field_count=3,
        relationship_count=1,
        recovery_enabled=True,
        transformation_classes=("BIJECTIVE_TEXT", "DATE_SHIFT"),
        vault_strategy=VaultStrategy.SINGLE_DATASET_SQLITE,
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
        incomplete_relations=0,
        evidence_fingerprint="sha256:relationship-evidence",
        relationship_fingerprint="sha256:relationships",
        evidence_schema_version="1.0",
        scope_note="DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY",
    )
    idx_path = "north/registry.idx"
    idx_evidence = StandaloneIdxEvidence(
        artifact_id="idx-" + hashlib.sha256(idx_path.encode("utf-8")).hexdigest(),
        artifact_path=idx_path,
        status="OMITTED_DATA_ONLY",
        source_sha256="a" * 64,
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
    index_capability = IndexBackendCapability(
        backend_id="synthetic-index-backend",
        backend_schema_version="1.0",
        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        supports_structural_cdx_rebuild=True,
        supports_standalone_idx_rebuild=False,
        supports_verification=True,
        vfp_runtime_available=True,
    )
    index_result = IndexBackendResult(
        backend_id="synthetic-index-backend",
        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        artifact_class="STRUCTURAL_CDX",
        table_path="north/registry.dbf",
        status="REBUILT",
        detail_code="REBUILT_OK",
    )
    index_verification = IndexVerificationResult(
        backend_id="synthetic-index-backend",
        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        artifact_class="STRUCTURAL_CDX",
        table_path="north/registry.dbf",
        status="VERIFIED",
        detail_code="VERIFIED_OK",
    )
    idx_association = StandaloneIdxAssociationResult(
        backend_id="synthetic-index-backend",
        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        artifact_path=idx_path,
        status="ASSOCIATED",
        detail_code="ASSOCIATED_OK",
        table_path="north/registry.dbf",
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
            index_artifacts=(idx_evidence,),
        ),
        VerificationResult(
            status=VerificationStatus.PASS,
            dataset=dataset,
            operation_id="operation-001",
            table_count=2,
            record_count=15,
            check_codes=(),
            assurance=assurance,
            index_artifacts=(idx_evidence,),
        ),
        RecoveryResult(
            operation_id="operation-002",
            dataset=dataset,
            output_path="output\\recovered",
            table_count=2,
            record_count=15,
            canonical_verified=True,
            raw_byte_equivalence=RawByteEquivalence.NOT_EVALUATED,
        ),
        TransferBundleResult(
            bundle_path="transfer\\bundle",
            profile=TransferProfile.DATA_ONLY,
            file_count=4,
            manifest_fingerprint="sha256:manifest",
            verified=True,
            assurance=assurance,
        ),
        NumericIdentityReview(
            table_path="north\\registry.dbf",
            field_name="REGISTRY_ID",
            dbf_type="I",
            status="IDENTITY_PRIVACY_REVIEW_REQUIRED",
        ),
        index_capability,
        index_result,
        index_verification,
        idx_evidence,
        idx_association,
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
        "NumericIdentityReview",
        "ProgressEvent",
        "PreflightResult",
        "PseudonymizationResult",
        "VerificationResult",
        "RecoveryResult",
        "TransferBundleResult",
        # REQ-P6-001: the injected index-backend protocol models.
        "IndexBackendCapability",
        "IndexBackendResult",
        "IndexVerificationResult",
        "StandaloneIdxEvidence",
        "StandaloneIdxAssociationResult",
    }
    assert {model.__name__ for model in PUBLIC_MODEL_TYPES} == expected


def test_models_are_frozen_and_deeply_use_immutable_public_containers() -> None:
    dataset = _samples()[1]
    assert isinstance(dataset, DatasetIdentity)
    with pytest.raises(FrozenInstanceError):
        dataset.dataset_id = "changed"  # type: ignore[misc]
    assert isinstance(dataset.table_paths, tuple)


def test_every_public_model_is_json_safe_and_versioned() -> None:
    samples = _samples()
    assert {type(sample) for sample in samples} == set(PUBLIC_MODEL_TYPES)
    for model in samples:
        payload = model.to_dict()  # type: ignore[union-attr]
        # REQ-P6-003 advances the public shape for verification evidence.
        # REQ-P6-004 adds standalone IDX fields and bumps schema to 1.6.
        assert payload["schema_version"] == MODEL_SCHEMA_VERSION == "1.6"
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        assert json.loads(encoded) == payload


def test_p6_public_models_use_current_model_and_protocol_contracts() -> None:
    assert MODEL_SCHEMA_VERSION == "1.6"
    assert INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION == "1.2"
    p6_types = {
        IndexBackendCapability,
        IndexBackendResult,
        IndexVerificationResult,
        StandaloneIdxAssociationResult,
        StandaloneIdxEvidence,
    }
    p6_samples = tuple(
        sample for sample in _samples() if type(sample) in p6_types
    )
    assert {type(sample) for sample in p6_samples} == p6_types
    for sample in p6_samples:
        payload = sample.to_dict()  # type: ignore[union-attr]
        assert payload["schema_version"] == "1.6"
        if type(sample) is not StandaloneIdxEvidence:
            assert payload["protocol_schema_version"] == "1.2"
        assert json.loads(json.dumps(payload, sort_keys=True)) == payload


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
        assert forbidden_field_names.isdisjoint(
            field.name for field in fields(model_type)  # type: ignore[arg-type]
        )
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


@pytest.mark.parametrize("hostile", ["true", 1, None, object()])
def test_relationship_metadata_authoritative_is_a_genuine_bool(hostile: object) -> None:
    """Authority is a boolean FACT: no truthy string/number/object shortcut."""
    with pytest.raises(ValueError):
        RelationshipMetadata(
            metadata_schema_version="1.0",
            provenance="declared",
            relationship_fingerprint="sha256:relationships",
            relation_count=1,
            authoritative=hostile,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "malformed", ["", " 1.0", "1.0 ", "1 .0", "schema version", "\t1.0"]
)
def test_relationship_metadata_schema_version_is_a_validated_code(
    malformed: str,
) -> None:
    """REQ-P1-002 regression: the declared metadata schema version is a
    validated bounded code — empty, leading/trailing whitespace and embedded
    whitespace are refused, never silently accepted malformed input."""
    with pytest.raises(ValueError):
        RelationshipMetadata(
            metadata_schema_version=malformed,
            provenance="declared",
            relationship_fingerprint="sha256:relationships",
            relation_count=1,
            authoritative=False,
        )


@pytest.mark.parametrize("hostile", [1, 1.0, None, b"1.0", ["1.0"], True])
def test_relationship_metadata_schema_version_rejects_non_string_input(
    hostile: object,
) -> None:
    """The established runtime type convention: hostile non-string input is
    a typed refusal, never an accidental AttributeError or silent truthiness."""
    with pytest.raises(TypeError):
        RelationshipMetadata(
            metadata_schema_version=hostile,  # type: ignore[arg-type]
            provenance="declared",
            relationship_fingerprint="sha256:relationships",
            relation_count=1,
            authoritative=False,
        )


def test_relationship_metadata_schema_version_accepts_the_supported_version() -> None:
    metadata = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance="declared",
        relationship_fingerprint="sha256:relationships",
        relation_count=1,
        authoritative=False,
    )
    assert metadata.metadata_schema_version == "1.0"
    assert metadata.to_dict()["metadata_schema_version"] == "1.0"


def test_invalid_counts_and_inconsistent_states_fail_fast() -> None:
    capabilities = _samples()[0]
    assert isinstance(capabilities, Capabilities)
    dataset = _samples()[1]
    assurance = _samples()[5]
    assert isinstance(dataset, DatasetIdentity)
    assert isinstance(assurance, RelationalAssurance)
    with pytest.raises(ValueError):
        TablePlan("a.dbf", None, -1, 1, 0, False, False, "DATA_ONLY", False, False, False, 0, 0, 0)
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
    with pytest.raises(ValueError):
        VerificationResult(
            status=VerificationStatus.PASS,
            dataset=dataset,
            operation_id="operation-001",
            table_count=-1,
            record_count=1,
            check_codes=(),
            assurance=assurance,
        )


def test_verification_status_is_the_one_authoritative_pass_partial_fail_vocabulary() -> None:
    """REQ-P5-001: the authoritative status vocabulary is exactly
    PASS/PARTIAL/FAIL; ``verified`` is a DERIVED convenience (PASS only),
    never a second independent truth field."""
    assert {status.value for status in VerificationStatus} == {
        "PASS",
        "PARTIAL",
        "FAIL",
    }
    samples = _samples()
    dataset = samples[1]
    assurance = samples[5]
    idx_evidence = samples[17]
    assert isinstance(dataset, DatasetIdentity)
    assert isinstance(assurance, RelationalAssurance)
    assert isinstance(idx_evidence, StandaloneIdxEvidence)
    passed = VerificationResult(
        status=VerificationStatus.PASS,
        dataset=dataset,
        operation_id="operation-001",
        table_count=1,
        record_count=3,
        check_codes=(),
        assurance=assurance,
        index_artifacts=(idx_evidence,),
    )
    partial = VerificationResult(
        status=VerificationStatus.PARTIAL,
        dataset=dataset,
        operation_id="operation-001",
        table_count=1,
        record_count=3,
        check_codes=("INDEX_ARTIFACT_UNVERIFIED",),
        assurance=assurance,
        index_artifacts=(idx_evidence,),
    )
    failed = VerificationResult(
        status=VerificationStatus.FAIL,
        dataset=dataset,
        operation_id="operation-001",
        table_count=1,
        record_count=3,
        check_codes=("OUTPUT_FINGERPRINT_MISMATCH",),
        assurance=assurance,
        index_artifacts=(idx_evidence,),
    )
    assert passed.verified is True
    assert partial.verified is False
    assert failed.verified is False
    assert passed.to_dict()["status"] == "PASS"
    assert partial.to_dict()["status"] == "PARTIAL"
    assert failed.to_dict()["status"] == "FAIL"


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
            "standalone_idx_paths",
        ),
        "TablePlan": (
            "schema_version", "model_type", "table_path", "memo_path", "record_count",
            "field_count", "transform_field_count", "structural_cdx", "dbc_bound", "index_strategy",
            "memo_required", "memo_companion_present", "structural_cdx_companion_present",
            "unsupported_field_count", "unsafe_field_count", "system_field_count",
        ),
        "PolicySummary": (
            "schema_version", "model_type", "policy_schema_version", "policy_fingerprint",
            "transformed_field_count", "relationship_count", "recovery_enabled", "transformation_classes", "vault_strategy",
        ),
        "RelationshipMetadata": (
            "schema_version", "model_type", "metadata_schema_version", "provenance",
            "relationship_fingerprint", "relation_count", "authoritative", "metadata_path",
        ),
        "RelationalAssurance": (
            # REQ-P3-007 extended the ONE canonical assurance model with the
            # truthful evidence binding (incomplete count, relationship
            # fingerprint, evidence schema version, machine scope note).
            "schema_version", "model_type", "level", "declared_relations", "verified_relations",
            "failed_relations", "incomplete_relations", "evidence_fingerprint",
            "relationship_fingerprint", "evidence_schema_version", "scope_note",
        ),
        "Plan": (
            "schema_version", "model_type", "plan_id", "dataset", "tables", "policy",
            "relationships", "output_profile", "relationship_assurance_target",
            "numeric_identity_review",
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
            "record_count", "vault_created", "output_fingerprint", "assurance", "index_artifacts",
        ),
        "VerificationResult": (
            "schema_version", "model_type", "status", "dataset", "operation_id", "table_count",
            "record_count", "check_codes", "assurance", "index_artifacts",
        ),
        "RecoveryResult": (
            "schema_version", "model_type", "operation_id", "dataset", "output_path", "table_count",
            "record_count", "canonical_verified", "raw_byte_equivalence",
        ),
        "TransferBundleResult": (
            "schema_version", "model_type", "bundle_path", "profile", "file_count",
            "manifest_fingerprint", "verified", "assurance",
        ),
        "NumericIdentityReview": (
            "schema_version", "model_type", "table_path", "field_name", "dbf_type", "status",
        ),
        "IndexBackendCapability": (
            "schema_version", "model_type", "backend_id", "backend_schema_version",
            "protocol_schema_version", "supports_structural_cdx_rebuild",
            "supports_standalone_idx_rebuild", "supports_verification",
            "vfp_runtime_available",
        ),
        "IndexBackendResult": (
            "schema_version", "model_type", "backend_id", "protocol_schema_version",
            "artifact_class", "table_path", "status", "detail_code", "artifact_path",
        ),
        "IndexVerificationResult": (
            "schema_version", "model_type", "backend_id", "protocol_schema_version",
            "artifact_class", "table_path", "status", "detail_code", "artifact_path",
        ),
        "StandaloneIdxEvidence": (
            "schema_version", "model_type", "artifact_id", "artifact_path", "status",
            "source_sha256", "backend_id", "table_path", "output_sha256",
        ),
        "StandaloneIdxAssociationResult": (
            "schema_version", "model_type", "backend_id", "protocol_schema_version",
            "artifact_path", "status", "detail_code", "table_path",
        ),
    }


# ---------------------------------------------------------------------------
# Canonical relationship-fingerprint contract (round-6 coherence)
# ---------------------------------------------------------------------------
def test_relationship_fingerprint_rejects_hostile_tokens_at_public_boundary() -> None:
    """The ONE canonical contract is enforced at the PUBLIC typed input
    boundary: hostile unbounded/path-bearing relationship fingerprints are
    refused by RelationshipMetadata itself (never surviving to a later
    transfer stage), with the rejected value absent from the message."""
    hostile_tokens = (
        "",
        " leading-space",
        "trailing-space ",
        "internal space",
        "with-nul\x00",
        "with-control\x07char",
        "C:\\private\\vault",
        "/absolute/path",
        "../relative/path",
        "x" * 129,
        "C:\\private\\canary\\vault\\token",
    )
    for hostile in hostile_tokens:
        with pytest.raises((ValueError, TypeError)) as caught:
            RelationshipMetadata(
                metadata_schema_version="1.1",
                provenance="none",
                relationship_fingerprint=hostile,
                relation_count=0,
                authoritative=False,
            )
        # The rejected value never appears in the public exception
        # message (empty/short tokens are vacuously substrings of any
        # message, so only substantive hostiles are asserted).
        if len(hostile) >= 8:
            assert hostile not in str(caught.value)
        assert "C:" not in str(caught.value)


def test_relationship_fingerprint_accepts_legitimate_tokens() -> None:
    """Ordinary stable non-hex tokens AND canonical 64-lowercase-hex
    document digests are both accepted by the public boundary."""
    metadata = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint="relationship-token-v1",
        relation_count=0,
        authoritative=False,
    )
    assert metadata.relationship_fingerprint == "relationship-token-v1"
    hex_digest = "a" * 64
    metadata_hex = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint=hex_digest,
        relation_count=0,
        authoritative=False,
    )
    assert metadata_hex.relationship_fingerprint == hex_digest
