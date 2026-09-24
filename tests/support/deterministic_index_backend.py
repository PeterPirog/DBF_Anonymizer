"""A deterministic injected index-backend test double (REQ-P6-001).

The double implements the public ``dbf_anonymizer.IndexBackend`` protocol
without ANY VFP, COM, subprocess or network dependency: its behaviour is
fully scripted, deterministic and observable.  It is test-support only and
is never imported by production code.
"""

from __future__ import annotations

from dbf_anonymizer.models import (
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    IndexBackendCapability,
    IndexBackendResult,
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
        status: str = "REBUILT",
        detail_code: str = "DETERMINISTIC_REBUILD_OK",
    ) -> None:
        self.backend_id = backend_id
        self.supports_structural_cdx_rebuild = supports_structural_cdx_rebuild
        self.supports_standalone_idx_rebuild = supports_standalone_idx_rebuild
        self.status = status
        self.detail_code = detail_code
        self.rebuild_requests: tuple[IndexRebuildRequest, ...] = ()
        self.capabilities_calls = 0
        self.fail_rebuild_with: Exception | None = None

    def capabilities(self) -> IndexBackendCapability:
        self.capabilities_calls += 1
        return IndexBackendCapability(
            backend_id=self.backend_id,
            backend_schema_version="1.0",
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            supports_structural_cdx_rebuild=self.supports_structural_cdx_rebuild,
            supports_standalone_idx_rebuild=self.supports_standalone_idx_rebuild,
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
