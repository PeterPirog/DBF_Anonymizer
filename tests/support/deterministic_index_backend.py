"""A deterministic injected index-backend test double (REQ-P6-001/P6-003).

The double implements the public ``dbf_anonymizer.IndexBackend`` protocol
without ANY VFP, COM, subprocess or network dependency: its behaviour is
fully scripted, deterministic and observable.  It is test-support only and
is never imported by production code.
"""

from __future__ import annotations

from collections.abc import Mapping

import dbfbridge

from dbf_anonymizer.models import (
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    IndexBackendCapability,
    IndexBackendResult,
    IndexVerificationResult,
    StandaloneIdxAssociationResult,
)
from dbf_anonymizer.index_backend import (
    IndexRebuildOutcome,
    IndexRebuildRequest,
    IndexVerificationOutcome,
    IndexVerificationRequest,
    StandaloneIdxAssociationOutcome,
    StandaloneIdxAssociationRequest,
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
        standalone_idx_associations: Mapping[str, str] | None = None,
        create_standalone_idx_artifact: bool = True,
        standalone_idx_bytes: bytes = b"DETERMINISTIC_FRESH_IDX_CONTENT",
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
        self.standalone_idx_associations = dict(standalone_idx_associations or {})
        self.create_standalone_idx_artifact = create_standalone_idx_artifact
        self.standalone_idx_bytes = standalone_idx_bytes
        self.association_requests: tuple[StandaloneIdxAssociationRequest, ...] = ()
        self.rebuild_requests: tuple[IndexRebuildRequest, ...] = ()
        self.verification_requests: tuple[IndexVerificationRequest, ...] = ()
        self.capabilities_calls = 0
        self.fail_rebuild_with: Exception | None = None
        self.fail_verification_with: Exception | None = None
        self.staged_table_existed_at_rebuild = False
        self.staged_rows_at_rebuild: tuple[dict[str, object], ...] = ()
        self.rebuilt_cdx_existed_before_return = False
        self.rebuilt_idx_existed_before_return = False

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

    def associate_standalone_idx(
        self, request: StandaloneIdxAssociationRequest
    ) -> StandaloneIdxAssociationOutcome:
        self.association_requests = self.association_requests + (request,)
        table_path = self.standalone_idx_associations.get(request.artifact_path)
        return StandaloneIdxAssociationOutcome(
            result=StandaloneIdxAssociationResult(
                backend_id=self.backend_id,
                protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                artifact_path=request.artifact_path,
                status="ASSOCIATED" if table_path is not None else "UNAVAILABLE",
                detail_code=(
                    "ASSOCIATED_OK"
                    if table_path is not None
                    else "DEFINITION_UNAVAILABLE"
                ),
                table_path=table_path,
            )
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
        if request.artifact_class == "STRUCTURAL_CDX" and self.status == "REBUILT":
            cdx_path = request.staged_table_path.with_suffix(".cdx")
            cdx_path.write_bytes(b"DETERMINISTIC_FRESH_CDX_CONTENT")
            self.rebuilt_cdx_existed_before_return = cdx_path.is_file()
        elif (
            request.artifact_class == "STANDALONE_IDX"
            and self.status == "REBUILT"
            and self.create_standalone_idx_artifact
        ):
            if request.staged_idx_path is None:
                raise ValueError("STANDALONE_IDX requires staged_idx_path")
            request.staged_idx_path.write_bytes(self.standalone_idx_bytes)
            self.rebuilt_idx_existed_before_return = request.staged_idx_path.is_file()
        return IndexRebuildOutcome(
            result=IndexBackendResult(
                backend_id=self.backend_id,
                protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                artifact_class=request.artifact_class,
                table_path=request.table_path,
                status=self.status,
                detail_code=self.detail_code,
                artifact_path=request.artifact_path,
            ),
            expected_tag_inventory=(
                self.expected_tag_inventory
                if self.status == "REBUILT"
                and request.artifact_class == "STRUCTURAL_CDX"
                else ()
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
        # For STANDALONE_IDX, verify the rebuilt IDX artifact exists
        if request.artifact_class == "STANDALONE_IDX":
            if request.staged_idx_path is None:
                raise ValueError("STANDALONE_IDX requires staged_idx_path")
            if not request.staged_idx_path.is_file():
                # IDX artifact missing - verification should fail
                return IndexVerificationOutcome(
                    result=IndexVerificationResult(
                        backend_id=self.backend_id,
                        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                        artifact_class=request.artifact_class,
                        table_path=request.table_path,
                        status="FAILED",
                        detail_code="OPEN_FAILED",
                        artifact_path=request.artifact_path,
                    ),
                    table_opened=False,
                    actual_record_count=0,
                    actual_tag_inventory=(),
                )
        return IndexVerificationOutcome(
            result=IndexVerificationResult(
                backend_id=self.backend_id,
                protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                artifact_class=request.artifact_class,
                table_path=request.table_path,
                status=self.verification_status,
                detail_code=self.verification_detail_code,
                artifact_path=request.artifact_path,
            ),
            table_opened=self.table_opened,
            actual_record_count=actual_record_count or 0,
            actual_tag_inventory=(() if request.artifact_class == "STANDALONE_IDX" else (
                self.actual_tag_inventory
                if self.actual_tag_inventory is not None
                else self.expected_tag_inventory
            )),
        )
