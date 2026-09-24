"""A deterministic injected index-backend test double (REQ-P6-001/P6-003).

The double implements the public ``dbf_anonymizer.IndexBackend`` protocol
without ANY VFP, COM, subprocess or network dependency: its behaviour is
fully scripted, deterministic and observable.  It is test-support only and
is never imported by production code.
"""

from __future__ import annotations

from dbf_anonymizer.models import (
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    INDEX_VERIFICATION_STATUSES,
    INDEX_VERIFICATION_DETAIL_CODES,
    IndexBackendCapability,
    IndexBackendResult,
    IndexVerificationRequest,
    IndexVerificationResult,
)
from dbf_anonymizer.index_backend import IndexRebuildRequest


class DeterministicIndexBackend:
    """Scripted, deterministic ``IndexBackend`` implementation.

    ``rebuilds`` records every request it receives (bounded tokens only) and
    returns the scripted result, so tests can prove the pipeline consumes
    the typed capability/result models of an injected backend.
    """

    def __init__(
        self,
        *,
        backend_id: str = "deterministic-test-double",
        supports_structural_cdx_rebuild: bool = True,
        supports_standalone_idx_rebuild: bool = True,
        supports_verification: bool = True,
        status: str = "REBUILT",
        detail_code: str = "DETERMINISTIC_REBUILD_OK",
        verification_status: str = "VERIFIED",
        verification_detail_code: str = "DETERMINISTIC_VERIFY_OK",
    ) -> None:
        self.backend_id = backend_id
        self.supports_structural_cdx_rebuild = supports_structural_cdx_rebuild
        self.supports_standalone_idx_rebuild = supports_standalone_idx_rebuild
        self.supports_verification = supports_verification
        self.status = status
        self.detail_code = detail_code
        self.verification_status = verification_status
        self.verification_detail_code = verification_detail_code
        self.rebuild_requests: tuple[IndexRebuildRequest, ...] = ()
        self.verification_requests: tuple[IndexVerificationRequest, ...] = ()
        self.capabilities_calls = 0
        self.fail_rebuild_with: Exception | None = None
        self.fail_verification_with: Exception | None = None

    def capabilities(self) -> IndexBackendCapability:
        self.capabilities_calls += 1
        return IndexBackendCapability(
            backend_id=self.backend_id,
            backend_schema_version="1.0",
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            supports_structural_cdx_rebuild=self.supports_structural_cdx_rebuild,
            supports_standalone_idx_rebuild=self.supports_standalone_idx_rebuild,
            supports_verification=self.supports_verification,
            vfp_runtime_available=False,
        )

    def rebuild_index(self, request: IndexRebuildRequest) -> IndexBackendResult:
        if self.fail_rebuild_with is not None:
            raise self.fail_rebuild_with
        self.rebuild_requests = self.rebuild_requests + (request,)
        return IndexBackendResult(
            backend_id=self.backend_id,
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class=request.artifact_class,
            table_path=request.table_path,
            status=self.status,
            detail_code=self.detail_code,
        )

    def verify_index(self, request: IndexVerificationRequest) -> IndexVerificationResult:
        if self.fail_verification_with is not None:
            raise self.fail_verification_with
        self.verification_requests = self.verification_requests + (request,)
        return IndexVerificationResult(
            backend_id=self.backend_id,
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class=request.artifact_class,
            table_path=request.table_path,
            status=self.verification_status,
            detail_code=self.verification_detail_code,
        )
