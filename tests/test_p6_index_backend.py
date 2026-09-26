"""REQ-P6-001 — the injected Windows/VFP index-backend protocol evidence.

Proves the synchronous, transport-neutral, typed backend boundary: no
import-time COM/subprocess/network dependency, standalone DATA_ONLY
operation with ``index_backend=None``, deterministic test-double injection
with consumed typed capability/result models, fail-closed unknown/malformed
backend contracts, stable privacy-safe backend-failure conversion, JSON-safe
bounded serialization and the established public API/boundary purity.
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import dbf_anonymizer  # noqa: E402
import tools.final_pipeline_benchmark  # noqa: E402,F401  (pipeline seam check)
from dbf_anonymizer import (  # noqa: E402
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    INDEX_ARTIFACT_CLASSES,
    INDEX_BACKEND_RESULT_STATUSES,
    INDEX_VERIFICATION_STATUSES,
    IndexBackend,
    IndexBackendCapability,
    IndexBackendError,
    IndexBackendResult,
    IndexVerificationResult,
    VerificationStatus,
    build_plan,
    preflight,
    pseudonymize,
    verify_dataset,
)
from dbf_anonymizer.index_backend import (  # noqa: E402
    IndexRebuildOutcome,
    IndexRebuildRequest,
    IndexVerificationOutcome,
    IndexVerificationRequest,
    index_backend_failure,
    require_backend_runtime,
    run_backend_rebuild,
    validate_backend_capabilities,
)
from tests.support.deterministic_index_backend import (  # noqa: E402
    DeterministicIndexBackend,
)
from tests.support.numeric_tables import (  # noqa: E402
    numeric_field,
    write_numeric_table,
)

_PRIVATE_CANARIES = (
    "ORIGINAL-CANARY-987654",
    "C:\\synthetic-private\\secret.dbc",
    "synthetic-secret-token",
)
_PRIVATE_DIAGNOSTIC = " | ".join(_PRIVATE_CANARIES)


def _tiny_plan(tmp_path: Path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_tables(source)
    return build_plan(str(source), str(output), str(vault))


def write_numeric_tables(source: Path) -> None:
    from tests.support.numeric_tables import write_numeric_table

    write_numeric_table(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 14), numeric_field("AMT", "N", 9)),
        [
            {"CUST_ID": f"CUST{index:09d}", "AMT": index}
            for index in range(30)
        ],
    )


def _protected_request(tmp_path: Path) -> IndexRebuildRequest:
    source = tmp_path / "source"
    staging = tmp_path / "protected-staging"
    write_numeric_tables(source)
    write_numeric_tables(staging)
    return IndexRebuildRequest(
        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        artifact_class="STRUCTURAL_CDX",
        table_path="north/customers.dbf",
        source_table_path=(source / "north/customers.dbf").resolve(),
        staged_table_path=(staging / "north/customers.dbf").resolve(),
    )


# ---------------------------------------------------------------------------
# Deterministic test-double backend: typed capabilities/results consumed
# ---------------------------------------------------------------------------
def test_deterministic_test_double_is_a_valid_public_backend(tmp_path: Path) -> None:
    backend = DeterministicIndexBackend()
    # The runtime-checkable public protocol accepts the double.
    assert isinstance(backend, IndexBackend)
    capability = validate_backend_capabilities(backend)
    assert backend.capabilities_calls == 1
    assert capability.backend_id == "deterministic-test-double"
    assert capability.protocol_schema_version == INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION
    assert capability.vfp_runtime_available is True
    payload = capability.to_dict()
    reparsed = json.loads(json.dumps(payload, sort_keys=True))
    assert reparsed == payload

    request = _protected_request(tmp_path)
    outcome = run_backend_rebuild(backend, request)
    assert isinstance(outcome, IndexRebuildOutcome)
    assert outcome.result.status == "REBUILT"
    assert outcome.expected_tag_inventory == ("SYNTHCODE", "SYNTHNOTE")
    assert backend.rebuild_requests == (request,)
    assert outcome.result.to_dict() == json.loads(
        json.dumps(outcome.result.to_dict())
    )


def test_injected_backend_is_consumed_by_the_public_service(
    tmp_path: Path,
) -> None:
    """The REAL standalone pipeline runs unchanged with a backend injected
    and its typed capabilities are consumed exactly once, fail-closed."""
    plan = _tiny_plan(tmp_path)
    backend = DeterministicIndexBackend()
    result = pseudonymize(plan, index_backend=backend)
    assert result.record_count == 30
    assert backend.capabilities_calls == 1
    verification = verify_dataset(result, source=tmp_path / "source",
                                  vault=tmp_path / "vault" / "dictionary.sqlite3")
    assert verification.status is VerificationStatus.PASS


def test_public_service_rejects_non_protocol_objects(tmp_path: Path) -> None:
    plan = _tiny_plan(tmp_path)
    with pytest.raises(TypeError):
        pseudonymize(plan, index_backend=object())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Fail-closed malformed / unknown backend contracts
# ---------------------------------------------------------------------------
class _ForeignCapabilityBackend(DeterministicIndexBackend):
    def capabilities(self) -> object:
        return {"backend_id": "foreign", "protocol_schema_version": "9.9"}

    def verify_index(self, request) -> object:
        return {"status": "MAGIC", "table_opened": True, "actual_record_count": 0, "actual_tag_inventory": ()}


class _UnknownProtocolBackend(DeterministicIndexBackend):
    def capabilities(self) -> object:  # type: ignore[override]
        raise ValueError(_PRIVATE_DIAGNOSTIC)

    def verify_index(self, request) -> object:
        raise ValueError(_PRIVATE_DIAGNOSTIC)


class _LegacyProtocolBackend(DeterministicIndexBackend):
    def capabilities(self) -> IndexBackendCapability:
        return IndexBackendCapability(
            backend_id="legacy-backend",
            backend_schema_version="1.0",
            protocol_schema_version="1.0",
            supports_structural_cdx_rebuild=True,
            supports_standalone_idx_rebuild=False,
            supports_verification=False,
            vfp_runtime_available=True,
        )


class _ForeignResultBackend(DeterministicIndexBackend):
    def rebuild_index(self, request: IndexRebuildRequest) -> object:
        return {"status": "MAGIC"}

    def verify_index(self, request) -> object:
        return {"status": "MAGIC", "table_opened": True, "actual_record_count": 0, "actual_tag_inventory": ()}


class _HostileTypedCapabilityBackend(DeterministicIndexBackend):
    def capabilities(self) -> IndexBackendCapability:
        raise IndexBackendError(
            dbf_anonymizer.ErrorCode.INDEX_BACKEND_FAILED,
            context=dbf_anonymizer.ErrorContext(
                operation="index_backend",
                table_path="ORIGINAL-CANARY-987654.dbf",
                detail_code="synthetic-secret-token",
            ),
        )

    def verify_index(self, request) -> IndexVerificationResult:
        raise IndexBackendError(
            dbf_anonymizer.ErrorCode.INDEX_BACKEND_FAILED,
            context=dbf_anonymizer.ErrorContext(
                operation="index_backend",
                table_path="ORIGINAL-CANARY-987654.dbf",
                detail_code="synthetic-secret-token",
            ),
        )


def test_malformed_capability_schema_fails_closed() -> None:
    with pytest.raises(IndexBackendError) as caught:
        validate_backend_capabilities(_ForeignCapabilityBackend())
    assert caught.value.context.detail_code == "INDEX_BACKEND_CAPABILITY_MALFORMED"
    # The raw foreign payload never reaches the typed failure context.
    assert "9.9" not in str(caught.value)


def test_unknown_protocol_schema_version_fails_closed() -> None:
    with pytest.raises(IndexBackendError) as caught:
        validate_backend_capabilities(_LegacyProtocolBackend())
    assert caught.value.code is dbf_anonymizer.ErrorCode.INDEX_BACKEND_FAILED
    assert caught.value.context.detail_code == "INDEX_BACKEND_CAPABILITIES_FAILED"
    rendered = json.dumps(caught.value.to_dict()) + "".join(
        traceback.format_exception(caught.value)
    )
    assert "legacy-backend" not in rendered
    assert "protocol_schema_version must be" not in rendered


def test_backend_exception_becomes_a_stable_privacy_safe_error() -> None:
    backend = _UnknownProtocolBackend()
    with pytest.raises(IndexBackendError) as caught:
        validate_backend_capabilities(backend)
    error = caught.value
    # The typed error carries the registry-controlled message only, and the
    # untrusted exception is suppressed from the normal traceback chain.
    assert error.code.value == "INDEX_BACKEND_FAILED"
    assert error.context.detail_code == "INDEX_BACKEND_CAPABILITIES_FAILED"
    rendered = (
        str(error),
        repr(error),
        json.dumps(error.to_dict(), sort_keys=True),
        "".join(traceback.format_exception(error)),
        json.dumps(error.context.to_dict(), sort_keys=True),
    )
    assert error.__cause__ is None
    for canary in _PRIVATE_CANARIES:
        assert all(canary not in surface for surface in rendered)


def test_unrecognized_failure_detail_is_reduced_to_closed_vocabulary() -> None:
    error = index_backend_failure(_PRIVATE_DIAGNOSTIC)
    assert error.context.detail_code == "INDEX_BACKEND_FAILURE_UNCLASSIFIED"
    rendered = json.dumps(error.to_dict(), sort_keys=True) + str(error)
    for canary in _PRIVATE_CANARIES:
        assert canary not in rendered


def test_backend_cannot_smuggle_a_typed_error_context() -> None:
    with pytest.raises(IndexBackendError) as caught:
        validate_backend_capabilities(_HostileTypedCapabilityBackend())
    error = caught.value
    assert error.context.to_dict() == {
        "operation": "index_backend",
        "artifact_path": None,
        "table_path": None,
        "policy_rule": None,
        "relationship_id": None,
        "detail_code": "INDEX_BACKEND_CAPABILITIES_FAILED",
    }
    assert error.__cause__ is None
    rendered = json.dumps(error.to_dict(), sort_keys=True) + "".join(
        traceback.format_exception(error)
    )
    assert "ORIGINAL-CANARY-987654" not in rendered
    assert "synthetic-secret-token" not in rendered


def test_run_backend_rebuild_wraps_failures_and_foreign_results(
    tmp_path: Path,
) -> None:
    backend = DeterministicIndexBackend()
    backend.fail_rebuild_with = RuntimeError(_PRIVATE_DIAGNOSTIC)
    request = _protected_request(tmp_path)
    with pytest.raises(IndexBackendError) as caught:
        run_backend_rebuild(backend, request)
    error = caught.value
    assert error.code.value == "INDEX_BACKEND_FAILED"
    assert error.context.detail_code == "INDEX_BACKEND_REBUILD_FAILED"
    rendered = (
        str(error),
        repr(error),
        json.dumps(error.to_dict(), sort_keys=True),
        "".join(traceback.format_exception(error)),
        json.dumps(error.context.to_dict(), sort_keys=True),
    )
    assert error.__cause__ is None
    for canary in _PRIVATE_CANARIES:
        assert all(canary not in surface for surface in rendered)

    foreign = _ForeignResultBackend()
    with pytest.raises(IndexBackendError) as caught:
        run_backend_rebuild(foreign, request)
    assert caught.value.context.detail_code == "INDEX_BACKEND_RESULT_MALFORMED"


def test_require_backend_support_fails_closed() -> None:
    from dbf_anonymizer.index_backend import (
        require_backend_support,
        require_backend_verification,
    )

    capability = DeterministicIndexBackend(
        supports_standalone_idx_rebuild=False
    ).capabilities()
    with pytest.raises(IndexBackendError) as caught:
        require_backend_support(capability, "STANDALONE_IDX")
    assert caught.value.context.detail_code == "INDEX_BACKEND_SUPPORT_MISSING"
    require_backend_support(capability, "STRUCTURAL_CDX")  # declared: passes
    unavailable = DeterministicIndexBackend(
        supports_verification=False, vfp_runtime_available=False
    ).capabilities()
    with pytest.raises(IndexBackendError):
        require_backend_verification(unavailable, "STRUCTURAL_CDX")
    with pytest.raises(IndexBackendError):
        require_backend_runtime(unavailable)


def test_request_and_result_contracts_are_bounded_and_closed(
    tmp_path: Path,
) -> None:
    valid = _protected_request(tmp_path)
    with pytest.raises(ValueError):
        IndexRebuildRequest(
            protocol_schema_version="9.9",
            artifact_class="STRUCTURAL_CDX",
            table_path="north/customers.dbf",
            source_table_path=valid.source_table_path,
            staged_table_path=valid.staged_table_path,
        )
    with pytest.raises(ValueError):
        IndexRebuildRequest(
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class="FOREIGN_CLASS",
            table_path="north/customers.dbf",
            source_table_path=valid.source_table_path,
            staged_table_path=valid.staged_table_path,
        )
    with pytest.raises(ValueError):
        IndexRebuildRequest(
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class="STRUCTURAL_CDX",
            table_path="C:\\absolute\\path.dbf",
            source_table_path=valid.source_table_path,
            staged_table_path=valid.staged_table_path,
        )
    with pytest.raises(ValueError):
        IndexRebuildRequest(
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class="STRUCTURAL_CDX",
            table_path="north/customers.dbf",
            source_table_path=valid.source_table_path,
            staged_table_path=valid.source_table_path,
        )
    with pytest.raises(ValueError):
        IndexBackendResult(
            backend_id="x",
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class="STRUCTURAL_CDX",
            table_path="north/customers.dbf",
            status="INVENTED",
            detail_code="OK",
        )
    with pytest.raises(ValueError):
        IndexBackendResult(
            backend_id="x",
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class="STRUCTURAL_CDX",
            table_path="north/customers.dbf",
            status="REBUILT",
            detail_code="INTERNAL_ERROR",
        )
    with pytest.raises(ValueError):
        IndexVerificationResult(
            backend_id="x",
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class="STRUCTURAL_CDX",
            table_path="north/customers.dbf",
            status="VERIFIED",
            detail_code="TAG_INVENTORY_MISMATCH",
        )
    assert INDEX_ARTIFACT_CLASSES == ("STRUCTURAL_CDX", "STANDALONE_IDX")
    assert INDEX_BACKEND_RESULT_STATUSES == ("REBUILT", "REFUSED", "FAILED")


def test_protected_backend_requests_and_evidence_have_no_public_json_route(
    tmp_path: Path,
) -> None:
    from dbf_anonymizer.models import PUBLIC_MODEL_TYPES, PublicModel

    request = _protected_request(tmp_path)
    verification_request = IndexVerificationRequest(
        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        artifact_class="STRUCTURAL_CDX",
        table_path="north/customers.dbf",
        staged_table_path=request.staged_table_path,
    )
    assert not isinstance(request, PublicModel)
    assert not isinstance(verification_request, PublicModel)
    assert IndexRebuildRequest not in PUBLIC_MODEL_TYPES
    assert IndexVerificationRequest not in PUBLIC_MODEL_TYPES
    assert not hasattr(request, "to_dict")
    assert not hasattr(verification_request, "to_dict")
    assert "IndexRebuildRequest" not in dbf_anonymizer.__all__
    assert not hasattr(dbf_anonymizer, "IndexRebuildRequest")

    backend = DeterministicIndexBackend()
    capability = validate_backend_capabilities(backend)
    outcome = run_backend_rebuild(backend, request)
    assert not isinstance(outcome, PublicModel)
    assert not hasattr(outcome, "to_dict")
    error = dbf_anonymizer.IndexBackendError(
        dbf_anonymizer.ErrorCode.INDEX_BACKEND_FAILED,
        context=dbf_anonymizer.ErrorContext(
            operation="index_backend", detail_code="INDEX_BACKEND_REBUILD_FAILED"
        ),
    )
    public_json = json.dumps(
        [capability.to_dict(), outcome.result.to_dict(), error.to_dict()], sort_keys=True
    )
    assert backend.rebuild_requests == (request,)
    for canary in _PRIVATE_CANARIES:
        assert canary not in public_json


def test_backend_none_keeps_data_only_fully_standalone(tmp_path: Path) -> None:
    """The default DATA_ONLY pipeline requires NO backend at all."""
    plan = _tiny_plan(tmp_path)
    check = preflight(plan)
    assert check.ready
    assert "DATA_ONLY_STANDALONE" in check.check_codes
    result = pseudonymize(plan)  # index_backend defaults to None
    assert result.record_count == 30
    assert plan.output_profile is dbf_anonymizer.TransferProfile.DATA_ONLY
    verification = verify_dataset(result, source=tmp_path / "source",
                                  vault=tmp_path / "vault" / "dictionary.sqlite3")
    assert verification.status is VerificationStatus.PASS


def test_root_exports_are_import_time_pure() -> None:
    """Root export surface exposes the protocol; the boundary module imports
    no transport, subprocess, network or toolchain machinery (AST proof)."""
    import ast

    assert dbf_anonymizer.INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION == "1.2"
    assert "IndexBackend" in dbf_anonymizer.__all__
    import dbf_anonymizer.index_backend as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    allowed_roots = {
        "__future__",
        "dbf_anonymizer",
        "dataclasses",
        "pathlib",
        "typing",
    }
    assert imported_roots <= allowed_roots, sorted(imported_roots)
