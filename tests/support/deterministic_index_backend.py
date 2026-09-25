"""A deterministic injected index-backend test double (REQ-P6-001/P6-003).

The double implements the public ``dbf_anonymizer.IndexBackend`` protocol
without ANY VFP, COM, subprocess or network dependency: its behaviour is
fully scripted, deterministic and observable.  It is test-support only and
is never imported by production code.
"""

from __future__ import annotations

import dbfbridge

from dbf_anonymizer.models import (
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    IndexBackendCapability,
    IndexBackendResult,
    IndexVerificationResult,
)
from dbf_anonymizer.index_backend import (
    IndexRebuildOutcome,
    IndexRebuildRequest,
    IndexVerificationOutcome,
    IndexVerificationRequest,
)


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
        vfp_runtime_available: bool = True,
        status: str = "REBUILT",
        detail_code: str = "REBUILT_OK",
        verification_status: str = "VERIFIED",
        verification_detail_code: str = "VERIFIED_OK",
        table_opened: bool = True,
        actual_record_count: int | None = None,
        expected_tag_inventory: tuple[str, ...] = ("SYNTHCODE", "SYNTHNOTE"),
        actual_tag_inventory: tuple[str, ...] | None = None,
    ) -> None:
        self.backend_id = backend_id
        self.supports_structural_cdx_rebuild = supports_structural_cdx_rebuild
        self.supports_standalone_idx_rebuild = supports_standalone_idx_rebuild
        self.supports_verification = supports_verification
        self.vfp_runtime_available = vfp_runtime_available
        self.status = status
        self.detail_code = detail_code
        self.verification_status = verification_status
        self.verification_detail_code = verification_detail_code
        self.table_opened = table_opened
        self.actual_record_count = actual_record_count
        self.expected_tag_inventory = expected_tag_inventory
        self.actual_tag_inventory = actual_tag_inventory
        self.rebuild_requests: tuple[IndexRebuildRequest, ...] = ()
        self.verification_requests: tuple[IndexVerificationRequest, ...] = ()
        self.capabilities_calls = 0
        self.fail_rebuild_with: Exception | None = None
        self.fail_verification_with: Exception | None = None
        self.staged_table_existed_at_rebuild = False
        self.staged_rows_at_rebuild: tuple[dict[str, object], ...] = ()
        self.rebuilt_cdx_existed_before_return = False

    def capabilities(self) -> IndexBackendCapability:
        self.capabilities_calls += 1
        return IndexBackendCapability(
            backend_id=self.backend_id,
            backend_schema_version="1.0",
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            supports_structural_cdx_rebuild=self.supports_structural_cdx_rebuild,
            supports_standalone_idx_rebuild=self.supports_standalone_idx_rebuild,
            supports_verification=self.supports_verification,
            vfp_runtime_available=self.vfp_runtime_available,
        )

    def rebuild_index(self, request: IndexRebuildRequest) -> IndexRebuildOutcome:
        if self.fail_rebuild_with is not None:
            raise self.fail_rebuild_with
        self.rebuild_requests = self.rebuild_requests + (request,)
        self.staged_table_existed_at_rebuild = request.staged_table_path.is_file()
        if self.staged_table_existed_at_rebuild:
            self.staged_rows_at_rebuild = tuple(
                dict(record.values)
                for record in dbfbridge.iter_records(
                    request.staged_table_path, include_deleted=True, memo="inline"
                )
            )
        if request.artifact_class == "STRUCTURAL_CDX":
            cdx_path = request.staged_table_path.with_suffix(".cdx")
            cdx_path.write_bytes(b"DETERMINISTIC_FRESH_CDX_CONTENT")
            self.rebuilt_cdx_existed_before_return = cdx_path.is_file()
        return IndexRebuildOutcome(
            result=IndexBackendResult(
                backend_id=self.backend_id,
                protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                artifact_class=request.artifact_class,
                table_path=request.table_path,
                status=self.status,
                detail_code=self.detail_code,
            ),
            expected_tag_inventory=(
                self.expected_tag_inventory if self.status == "REBUILT" else ()
            ),
        )

    def verify_index(self, request: IndexVerificationRequest) -> IndexVerificationOutcome:
        if self.fail_verification_with is not None:
            raise self.fail_verification_with
        self.verification_requests = self.verification_requests + (request,)
        actual_record_count = self.actual_record_count
        if actual_record_count is None and self.table_opened:
            actual_record_count = int(
                dbfbridge.read_schema(request.staged_table_path).record_count
            )
        return IndexVerificationOutcome(
            result=IndexVerificationResult(
                backend_id=self.backend_id,
                protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                artifact_class=request.artifact_class,
                table_path=request.table_path,
                status=self.verification_status,
                detail_code=self.verification_detail_code,
            ),
            table_opened=self.table_opened,
            actual_record_count=actual_record_count or 0,
            actual_tag_inventory=(
                self.actual_tag_inventory
                if self.actual_tag_inventory is not None
                else self.expected_tag_inventory
            ),
        )
