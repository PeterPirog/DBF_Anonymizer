"""REQ-P7-002 bounded, versioned public JSON contract evidence."""

from __future__ import annotations

import ast
import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

import dbf_anonymizer as public
from dbf_anonymizer.errors import ERROR_REGISTRY
from dbf_anonymizer.models import (
    INDEX_ARTIFACT_CLASSES,
    INDEX_BACKEND_RESULT_DETAIL_CODES,
    INDEX_BACKEND_RESULT_STATUSES,
    INDEX_VERIFICATION_DETAIL_CODES,
    INDEX_VERIFICATION_STATUSES,
    PROGRESS_EVENT_CODES,
    PROGRESS_PHASE_CODES,
    PUBLIC_JSON_MAX_COUNT,
    PUBLIC_JSON_MAX_DATASET_TABLES,
    PUBLIC_JSON_MAX_FINDING_CODES,
    PUBLIC_JSON_MAX_INDEX_ARTIFACTS,
    PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS,
    PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
    PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH,
    PUBLIC_JSON_MAX_TOKEN_LENGTH,
    PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES,
    PUBLIC_MODEL_TYPES,
    STANDALONE_IDX_ASSOCIATION_DETAIL_CODES,
    STANDALONE_IDX_ASSOCIATION_STATUSES,
    STANDALONE_IDX_EVIDENCE_STATUSES,
    _PlanExecutionContext,
    _PseudonymizationExecutionContext,
    _json_value,
    standalone_idx_artifact_id,
)
from dbf_anonymizer.progress import ProgressController


SNAPSHOT_PATH = Path(__file__).parent / "snapshots" / "public_json" / "schema-1.8.json"
SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer"
PYPROJECT_PATH = Path(__file__).resolve().parents[1] / "pyproject.toml"

FORBIDDEN_TRANSPORT_ROOTS = frozenset(
    {
        "mcp",
        "fastmcp",
        "mcp_vfp9sp2_toolchain",
        "vfp_toolchain",
        "fastapi",
        "flask",
        "starlette",
        "aiohttp",
        "uvicorn",
    }
)

CANARIES = (
    "CHAR_ORIGINAL_Z7Q4Y2P9",
    "VARCHAR_ORIGINAL_R8M3K6W1",
    "MEMO_TEXT_H5N9C2L7",
    "BINARY_MEMO_7f4a9c31d8e2",
    "VAULT_SECRET_B6T1J8Q5",
    "REVERSE_MAPPING_F3P7X2V9",
    "TEMPORAL_OFFSET_MINUS_1739",
    r"C:\Users\private-canary\dataset.dbf",
    "/home/private-canary/dataset.dbf",
    "BACKEND_EXCEPTION_SECRET_K9D4S7A2",
    "credential_sk_live_8H2Q5M9X",
)


def _canonical_json(value: object) -> str:
    if isinstance(value, public.AnonymizerError):
        payload = value.to_dict()
    else:
        payload = value.to_dict()  # type: ignore[union-attr]
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _max_path(prefix: str, suffix: str) -> str:
    fill = PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH - len(prefix) - len(suffix)
    assert fill > 0
    return prefix + ("x" * fill) + suffix


def _token(prefix: str, ordinal: int) -> str:
    head = f"{prefix}{ordinal:04d}_"
    return head + ("X" * (PUBLIC_JSON_MAX_TOKEN_LENGTH - len(head)))


def _assurance() -> public.RelationalAssurance:
    return public.RelationalAssurance(
        level=public.RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED,
        declared_relations=1,
        verified_relations=1,
        failed_relations=0,
        evidence_fingerprint="e" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
        relationship_fingerprint="r" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
        evidence_schema_version="1.0",
        scope_note="DECLARED_RELATIONS_ONLY",
    )


def _dataset(
    *,
    table_paths: tuple[str, ...] = ("tables/people.dbf",),
    idx_paths: tuple[str, ...] = (),
) -> public.DatasetIdentity:
    return public.DatasetIdentity(
        dataset_id="dataset-public-json",
        source_fingerprint="s" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
        table_paths=table_paths,
        standalone_idx_paths=idx_paths,
    )


def _capabilities() -> public.Capabilities:
    return public.Capabilities(
        direct_read=True,
        direct_write=True,
        recovery=True,
        transfer_bundle=True,
        vfp_index_backend=False,
        dbfbridge_version="1.1.1",
    )


def _schema_snapshot() -> dict[str, Any]:
    excluded = {"execution_context"}
    model_fields = {
        model.__name__: [
            "schema_version",
            "model_type",
            *[
                item.name
                for item in fields(model)  # type: ignore[arg-type]
                if item.name not in excluded
            ],
        ]
        for model in sorted(PUBLIC_MODEL_TYPES, key=lambda item: item.__name__)
    }
    return {
        "error_contract": {
            "context_fields": [
                "operation",
                "operation_id",
                "artifact_path",
                "table_path",
                "policy_rule",
                "relationship_id",
                "detail_code",
            ],
            "error_codes": [
                {
                    "category": definition.category.value,
                    "code": definition.code.value,
                }
                for definition in ERROR_REGISTRY
            ],
            "payload_fields": [
                "schema_version",
                "registry_version",
                "code",
                "category",
                "message",
                "dependency_code",
                "context",
            ],
            "registry_version": public.ERROR_REGISTRY_VERSION,
            "schema_version": public.ERROR_SCHEMA_VERSION,
        },
        "families": {
            "capability": ["Capabilities", "IndexBackendCapability"],
            "progress": ["ProgressEvent"],
            "result": [
                "Plan",
                "PreflightResult",
                "PseudonymizationResult",
                "VerificationResult",
                "RecoveryResult",
                "TransferBundleResult",
            ],
        },
        "limits": {
            "count_max": PUBLIC_JSON_MAX_COUNT,
            "dataset_tables_max_items": PUBLIC_JSON_MAX_DATASET_TABLES,
            "finding_codes_max_items": PUBLIC_JSON_MAX_FINDING_CODES,
            "index_artifacts_max_items": PUBLIC_JSON_MAX_INDEX_ARTIFACTS,
            "numeric_identity_reviews_max_items": PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS,
            "operation_id_max_length": PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
            "relative_path_max_length": PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH,
            "token_max_length": PUBLIC_JSON_MAX_TOKEN_LENGTH,
            "transformation_classes_max_items": PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES,
        },
        "model_fields": model_fields,
        "model_schema_version": public.MODEL_SCHEMA_VERSION,
        "vocabularies": {
            "index_artifact_class": list(INDEX_ARTIFACT_CLASSES),
            "index_backend_detail": list(INDEX_BACKEND_RESULT_DETAIL_CODES),
            "index_backend_status": list(INDEX_BACKEND_RESULT_STATUSES),
            "index_verification_detail": list(INDEX_VERIFICATION_DETAIL_CODES),
            "index_verification_status": list(INDEX_VERIFICATION_STATUSES),
            "output_data_state": [item.value for item in public.OutputDataState],
            "progress_event": list(PROGRESS_EVENT_CODES),
            "progress_phase": list(PROGRESS_PHASE_CODES),
            "raw_byte_equivalence": [item.value for item in public.RawByteEquivalence],
            "relational_assurance": [
                item.value for item in public.RelationalAssuranceLevel
            ],
            "standalone_idx_association_detail": list(
                STANDALONE_IDX_ASSOCIATION_DETAIL_CODES
            ),
            "standalone_idx_association_status": list(
                STANDALONE_IDX_ASSOCIATION_STATUSES
            ),
            "standalone_idx_evidence_status": list(
                STANDALONE_IDX_EVIDENCE_STATUSES
            ),
            "transfer_profile": [item.value for item in public.TransferProfile],
            "vault_strategy": [item.value for item in public.VaultStrategy],
            "verification_status": [item.value for item in public.VerificationStatus],
        },
    }


def test_committed_schema_snapshot_is_exact_and_deterministic() -> None:
    expected = _schema_snapshot()
    assert public.MODEL_SCHEMA_VERSION == "1.8"
    assert public.ERROR_SCHEMA_VERSION == "1.1"
    assert public.INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION == "1.2"
    assert SNAPSHOT_PATH.name == "schema-1.8.json"
    assert expected["model_schema_version"] == "1.8"
    committed_text = SNAPSHOT_PATH.read_text(encoding="ascii")
    assert json.loads(committed_text) == expected
    assert committed_text == json.dumps(
        expected, ensure_ascii=True, indent=2, sort_keys=True
    ) + "\n"


def test_result_capability_progress_and_error_json_are_versioned_deterministic() -> None:
    dataset = _dataset()
    assurance = _assurance()
    capability = public.capabilities()
    progress = public.ProgressEvent(
        operation_id="op-" + ("a" * 32),
        phase_code="VERIFICATION",
        event_code="PROGRESS",
        completed_units=1,
        total_units=2,
        table_path="tables\\people.dbf",
    )
    results: tuple[object, ...] = (
        public.PreflightResult(True, "plan-1", capability, ("READY",), (), ()),
        public.PseudonymizationResult(
            "vop-" + ("b" * 32),
            dataset,
            "output",
            1,
            2,
            True,
            "f" * 64,
            assurance,
            public.OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        ),
        public.VerificationResult(
            public.VerificationStatus.PASS,
            dataset,
            "vop-" + ("b" * 32),
            1,
            2,
            (),
            assurance,
            public.OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        ),
        public.RecoveryResult(
            "op-" + ("c" * 32),
            dataset,
            "recovered",
            1,
            2,
            True,
            public.RawByteEquivalence.NOT_EVALUATED,
        ),
        public.TransferBundleResult(
            "bundle",
            public.TransferProfile.DATA_ONLY,
            2,
            "m" * 64,
            True,
            assurance,
        ),
    )
    error = public.VerificationError(
        public.ErrorCode.VERIFICATION_FAILED,
        context=public.ErrorContext(
            operation="verify_dataset",
            operation_id="op-" + ("d" * 32),
            detail_code="OUTPUT_FINGERPRINT_MISMATCH",
        ),
    )

    for value in (capability, progress, *results, error):
        first = _canonical_json(value)
        second = _canonical_json(value)
        assert first == second
        payload = json.loads(first)
        assert isinstance(payload["schema_version"], str)
        if not isinstance(value, public.AnonymizerError):
            assert payload["model_type"] == type(value).__name__


def test_objective_payload_bounds_are_exercised_at_collection_limits() -> None:
    table_paths = tuple(
        _max_path(f"t{i:03d}/", ".dbf")
        for i in range(PUBLIC_JSON_MAX_DATASET_TABLES)
    )
    tables = tuple(
        public.TablePlan(
            path,
            None,
            PUBLIC_JSON_MAX_COUNT,
            1,
            0,
            False,
            False,
            "DATA_ONLY",
            False,
            False,
            False,
            0,
            0,
            0,
        )
        for path in table_paths
    )
    reviews = tuple(
        public.NumericIdentityReview(
            table_paths[index % len(table_paths)],
            _token("FIELD", index),
            "I",
            "IDENTITY_PRIVACY_REVIEW_REQUIRED",
        )
        for index in range(PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS)
    )
    plan = public.Plan(
        plan_id="p" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
        dataset=_dataset(table_paths=table_paths),
        tables=tables,
        policy=public.PolicySummary(
            "1.0",
            "f" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
            PUBLIC_JSON_MAX_COUNT,
            PUBLIC_JSON_MAX_COUNT,
            True,
            tuple(
                _token("CLASS", index)
                for index in range(PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES)
            ),
            public.VaultStrategy.SINGLE_DATASET_SQLITE,
        ),
        relationships=public.RelationshipMetadata(
            "1.0",
            "DECLARED",
            "r" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
            PUBLIC_JSON_MAX_COUNT,
            False,
        ),
        output_profile=public.TransferProfile.DATA_ONLY,
        relationship_assurance_target=public.RelationalAssuranceLevel.INCOMPLETE,
        output_data_state=public.OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        numeric_identity_review=reviews,
    )
    finding_codes = tuple(
        _token("CHECK", index) for index in range(PUBLIC_JSON_MAX_FINDING_CODES)
    )
    preflight = public.PreflightResult(
        False,
        "p" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
        _capabilities(),
        finding_codes,
        finding_codes,
        finding_codes,
    )

    idx_paths = tuple(
        _max_path(f"i{i:03d}/", ".idx")
        for i in range(PUBLIC_JSON_MAX_INDEX_ARTIFACTS)
    )
    indexed_dataset = _dataset(table_paths=table_paths, idx_paths=idx_paths)
    evidence = tuple(
        public.StandaloneIdxEvidence(
            artifact_id=standalone_idx_artifact_id(path),
            artifact_path=path,
            status="OMITTED_DATA_ONLY",
            source_sha256="a" * 64,
        )
        for path in idx_paths
    )
    result = public.PseudonymizationResult(
        "v" * PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
        indexed_dataset,
        _max_path("o/", ""),
        PUBLIC_JSON_MAX_COUNT,
        PUBLIC_JSON_MAX_COUNT,
        True,
        "f" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
        _assurance(),
        public.OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        evidence,
    )
    progress = public.ProgressEvent(
        "o" * PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
        "TABLE_EVALUATION",
        "PROGRESS",
        PUBLIC_JSON_MAX_COUNT,
        PUBLIC_JSON_MAX_COUNT,
        _max_path("p/", ""),
    )
    error = public.PathError(
        public.ErrorCode.PATH_INVALID,
        context=public.ErrorContext(
            operation="o" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
            operation_id="i" * PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
            artifact_path=_max_path("a/", ""),
            table_path=_max_path("t/", ""),
            policy_rule="p" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
            relationship_id="r" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
            detail_code="d" * PUBLIC_JSON_MAX_TOKEN_LENGTH,
        ),
    )

    observed = {
        "capability": len(_canonical_json(_capabilities()).encode("ascii")),
        "error": len(_canonical_json(error).encode("ascii")),
        "findings": len(_canonical_json(preflight).encode("ascii")),
        "plan": len(_canonical_json(plan).encode("ascii")),
        "progress": len(_canonical_json(progress).encode("ascii")),
        "result": len(_canonical_json(result).encode("ascii")),
    }
    assert observed["capability"] <= 1024
    assert observed["progress"] <= 2048
    assert observed["error"] <= 4096
    assert observed["findings"] <= 32768
    assert observed["result"] <= 2 * 1024 * 1024
    assert observed["plan"] <= 4 * 1024 * 1024


def test_limits_reject_one_past_the_public_boundaries() -> None:
    with pytest.raises(ValueError, match="operation_id"):
        public.ProgressEvent(
            "o" * (PUBLIC_JSON_MAX_OPERATION_ID_LENGTH + 1),
            "OPERATION",
            "STARTED",
            0,
        )
    with pytest.raises(ValueError, match="relative path"):
        public.ProgressEvent(
            "op-" + ("a" * 32),
            "OPERATION",
            "STARTED",
            0,
            table_path="x" * (PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH + 1),
        )
    with pytest.raises(ValueError, match="table_paths"):
        _dataset(
            table_paths=tuple(
                f"t/{index}.dbf"
                for index in range(PUBLIC_JSON_MAX_DATASET_TABLES + 1)
            )
        )
    with pytest.raises(ValueError, match="check_codes"):
        public.PreflightResult(
            False,
            "plan",
            _capabilities(),
            tuple(f"C{index}" for index in range(PUBLIC_JSON_MAX_FINDING_CODES + 1)),
            (),
            (),
        )


def test_build_plan_table_limit_refusal_is_early_deterministic_and_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import dbf_anonymizer.planning as planning
    from dbf_anonymizer.discovery import DiscoveredTable

    source = tmp_path / CANARIES[0]
    output = tmp_path / CANARIES[1]
    vault = tmp_path / CANARIES[4]
    source.mkdir()
    discovered = tuple(
        DiscoveredTable(
            relative_path=f"tables/table-{index:03d}.dbf",
            memo_relative_path=None,
            record_count=0,
            field_count=0,
            structural_cdx=False,
            dbc_bound=False,
            companion_cdx_relative_path=None,
        )
        for index in range(PUBLIC_JSON_MAX_DATASET_TABLES + 1)
    )
    monkeypatch.setattr(
        planning, "enumerate_in_scope_paths", lambda *args, **kwargs: {}
    )
    monkeypatch.setattr(
        planning, "discover_tables", lambda *args, **kwargs: discovered
    )

    def fingerprint_must_not_run(*args: object, **kwargs: object) -> object:
        pytest.fail("fingerprinting ran after the public table limit was exceeded")

    monkeypatch.setattr(
        planning, "collect_fingerprint_entries", fingerprint_must_not_run
    )

    payloads = []
    for _ in range(2):
        with pytest.raises(public.PathError) as caught:
            public.build_plan(source=source, output=output, vault=vault)
        payloads.append(caught.value.to_dict())

    assert payloads[0] == payloads[1]
    assert payloads[0]["code"] == "PATH_INVALID"
    assert (
        payloads[0]["context"]["detail_code"]
        == "PUBLIC_DATASET_TABLE_LIMIT_EXCEEDED"
    )
    serialized = json.dumps(payloads[0], sort_keys=True)
    assert all(canary not in serialized for canary in CANARIES)
    assert not output.exists()
    assert not vault.exists()


@pytest.mark.parametrize(
    "path",
    (r"C:\private\source.dbf", "/private/source.dbf", "../source.dbf"),
)
def test_path_representation_is_portable_bounded_and_private(path: str) -> None:
    with pytest.raises(ValueError):
        public.ProgressEvent(
            "op-" + ("a" * 32), "SCAN", "PROGRESS", 0, table_path=path
        )


def test_status_assurance_and_progress_vocabularies_are_closed() -> None:
    assert {item.value for item in public.VerificationStatus} == {
        "PASS",
        "PARTIAL",
        "FAIL",
    }
    assert {item.value for item in public.RelationalAssuranceLevel} == {
        "GLOBAL_EXACT_VALUE",
        "DECLARED_RELATIONS_VERIFIED",
        "VFP_METADATA_VERIFIED",
        "INCOMPLETE",
    }
    with pytest.raises(TypeError, match="VerificationStatus"):
        public.VerificationResult(
            "UNKNOWN",  # type: ignore[arg-type]
            _dataset(),
            "op-" + ("a" * 32),
            1,
            1,
            (),
            _assurance(),
            public.OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        )
    with pytest.raises(ValueError, match="progress vocabulary"):
        public.ProgressEvent("op-" + ("a" * 32), "SCAN", "RAW_MESSAGE", 0)


def test_incompatible_index_protocol_version_is_rejected() -> None:
    with pytest.raises(ValueError, match=public.INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION):
        public.IndexBackendCapability(
            backend_id="backend",
            backend_schema_version="1.0",
            protocol_schema_version="999.0",
            supports_structural_cdx_rebuild=False,
            supports_standalone_idx_rebuild=False,
            supports_verification=False,
            vfp_runtime_available=False,
        )


def test_success_payload_redacts_all_private_sentinels_and_dictionary_rows() -> None:
    private_rows = [{"original": item, "pseudonym": f"masked-{index}"} for index, item in enumerate(CANARIES)]
    table = public.TablePlan(
        "tables/people.dbf",
        None,
        1,
        1,
        0,
        False,
        False,
        "DATA_ONLY",
        False,
        False,
        False,
        0,
        0,
        0,
    )
    dataset = _dataset()
    plan = public.Plan(
        "plan-redaction",
        dataset,
        (table,),
        public.PolicySummary(
            "1.0", "policy", 0, 0, False, (), public.VaultStrategy.NONE
        ),
        public.RelationshipMetadata("1.0", "none", "relationships", 0, False),
        public.TransferProfile.DATA_ONLY,
        public.RelationalAssuranceLevel.INCOMPLETE,
        public.OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        execution_context=_PlanExecutionContext(
            source_root=CANARIES[7],
            output_root=CANARIES[8],
            vault_path=CANARIES[4],
            relationship_document=private_rows,
            relationship_bindings={"reverse": CANARIES[5]},
            resolved_policy={
                "dictionary_rows": private_rows,
                "temporal_offset": CANARIES[6],
                "credential": CANARIES[10],
            },
        ),
    )
    result = public.PseudonymizationResult(
        "vop-" + ("a" * 32),
        dataset,
        "output",
        1,
        1,
        True,
        "output-fingerprint",
        _assurance(),
        public.OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        execution_context=_PseudonymizationExecutionContext(
            output_root=CANARIES[8],
            source_root="|".join(CANARIES[:4]),
            vault_path="|".join(CANARIES[4:]),
        ),
    )
    serialized = _canonical_json(plan) + _canonical_json(result)
    assert "dictionary_rows" not in serialized
    for canary in CANARIES:
        assert canary not in serialized

    with pytest.raises(TypeError, match="Capabilities"):
        public.PreflightResult(
            False,
            "plan",
            {"dictionary_rows": private_rows},  # type: ignore[arg-type]
            (),
            (),
            (),
        )


def test_failure_payloads_redact_backend_and_callback_sentinels() -> None:
    class HostileBackendFailure(RuntimeError):
        code = "X" * (PUBLIC_JSON_MAX_TOKEN_LENGTH + 1)

    backend_error = public.DBFBridgeError.from_exception(
        HostileBackendFailure("|".join(CANARIES))
    )
    assert backend_error.dependency_code is None

    def fail_progress(_event: public.ProgressEvent) -> None:
        raise RuntimeError("|".join(CANARIES))

    control = ProgressController(operation="build_plan", progress=fail_progress)
    with pytest.raises(public.CallbackError) as caught:
        control.start_phase("OPERATION")

    serialized = _canonical_json(backend_error) + _canonical_json(caught.value)
    for canary in CANARIES:
        assert canary not in serialized
    assert caught.value.context.operation_id is not None
    assert len(caught.value.context.operation_id) <= PUBLIC_JSON_MAX_OPERATION_ID_LENGTH


@pytest.mark.parametrize("malformed", (float("nan"), float("inf"), float("-inf")))
def test_strict_json_rejects_non_finite_values(malformed: float) -> None:
    with pytest.raises(TypeError, match="finite"):
        _json_value(malformed)
    with pytest.raises(TypeError, match="integer"):
        public.ProgressEvent(
            "op-" + ("a" * 32),
            "SCAN",
            "PROGRESS",
            malformed,  # type: ignore[arg-type]
        )


def test_p7_001_transport_and_dependency_boundary_remains_intact() -> None:
    offending: dict[str, list[str]] = {}
    for path in sorted(SRC_ROOT.rglob("*.py")):
        roots: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                roots.add(node.module.split(".")[0])
        forbidden = sorted(roots & FORBIDDEN_TRANSPORT_ROOTS)
        if forbidden:
            offending[path.relative_to(SRC_ROOT).as_posix()] = forbidden
    assert offending == {}

    pyproject = PYPROJECT_PATH.read_text(encoding="utf-8")
    assert '"dbfbridge[write]>=1.1.0,<2"' in pyproject
    assert all(root not in pyproject for root in FORBIDDEN_TRANSPORT_ROOTS)
