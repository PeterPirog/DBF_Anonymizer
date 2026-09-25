"""The injected Windows/VFP index-backend protocol (REQ-P6-001).

DBF_Anonymizer remains FULLY functional without VFP: standalone DATA_ONLY
operation needs no backend at all (``index_backend=None`` everywhere).
When authoritative Windows/VFP index work is required (the future
``VFP_INDEXED`` profile, REQ-P6-003), the caller supplies an
:class:`IndexBackend` explicitly at the public service boundary.

Design invariants of this boundary:

* TYPED, synchronous, transport-neutral Python contracts only.  MCP
  transport, authorization, async jobs, timeouts and server policy stay
  OUTSIDE DBF_Anonymizer (REQ-P7-001).
* JSON-safe, versioned, bounded capability/result models with a closed
  vocabulary: a backend whose capability declares any other protocol
  schema version or an unbounded/mis-typed field FAILS CLOSED with a
  stable typed error, never with a best-effort downgrade.
* NO import-time work: importing this module initializes no COM, starts no
  subprocess, touches no network endpoint and imports no
  ``mcp-vfp9sp2-toolchain`` (the real backend stays behind the injected
  interface, supplied by the caller's own environment).
* Backend exceptions are converted to the stable, privacy-safe
  :class:`~dbf_anonymizer.errors.IndexBackendError` WITHOUT parsing
  human-readable exception text (REQ-P1-003 discipline).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from dbf_anonymizer.errors import (
    ErrorCode,
    ErrorContext,
    IndexBackendError,
)
from dbf_anonymizer.models import (
    INDEX_ARTIFACT_CLASSES,
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    INDEX_BACKEND_RESULT_STATUSES,
    INDEX_VERIFICATION_DETAIL_CODES,
    INDEX_VERIFICATION_STATUSES,
    IndexBackendCapability,
    IndexBackendResult,
    IndexVerificationResult,
    _normalized_relative_path,
)

__all__ = [
    "INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION",
    "INDEX_ARTIFACT_CLASSES",
    "INDEX_BACKEND_RESULT_STATUSES",
    "INDEX_VERIFICATION_STATUSES",
    "INDEX_VERIFICATION_DETAIL_CODES",
    "IndexBackend",
    "IndexBackendCapability",
    "IndexRebuildRequest",
    "IndexRebuildOutcome",
    "IndexBackendResult",
    "IndexBackendError",
    "IndexBackendContract",
    "validate_backend_capabilities",
    "require_backend_support",
    "run_backend_rebuild",
    "index_backend_failure",
    "require_backend_verification",
    "run_backend_verification",
    "IndexVerificationRequest",
    "IndexVerificationOutcome",
    "IndexVerificationResult",
    "require_backend_runtime",
]

_BACKEND_OPERATION = "index_backend"
_MAX_TAG_COUNT = 256
_MAX_TAG_NAME_LENGTH = 128

_INDEX_BACKEND_FAILURE_DETAIL_CODES = frozenset(
    {
        "INDEX_BACKEND_ARTIFACT_CLASS_UNKNOWN",
        "INDEX_BACKEND_ID_MISMATCH",
        "INDEX_BACKEND_CAPABILITIES_FAILED",
        "INDEX_BACKEND_CAPABILITY_MALFORMED",
        "INDEX_BACKEND_FAILURE_UNCLASSIFIED",
        "INDEX_BACKEND_MISSING",
        "INDEX_BACKEND_REBUILD_FAILED",
        "INDEX_BACKEND_REBUILD_REFUSED",
        "INDEX_BACKEND_REBUILT_ARTIFACT_MISSING",
        "INDEX_BACKEND_RESULT_MALFORMED",
        "INDEX_BACKEND_RESULT_MISMATCH",
        "INDEX_BACKEND_RUNTIME_UNAVAILABLE",
        "INDEX_BACKEND_SUPPORT_MISSING",
        "INDEX_BACKEND_TABLE_DIRECTIVE_MISSING",
        "INDEX_BACKEND_TABLE_NOT_OPENED",
        "INDEX_BACKEND_RECORD_COUNT_MISMATCH",
        "INDEX_BACKEND_TAG_INVENTORY_MISMATCH",
        "INDEX_BACKEND_VERIFICATION_FAILED",
        "INDEX_BACKEND_VERIFICATION_RESULT_MALFORMED",
        "INDEX_BACKEND_VERIFICATION_RESULT_MISMATCH",
        "INDEX_BACKEND_VERIFICATION_SUPPORT_MISSING",
        "INDEX_BACKEND_VERIFY_FAILED",
    }
)


def _validated_tag_inventory(
    tags: object, *, field_name: str, allow_empty: bool = False
) -> tuple[str, ...]:
    if not isinstance(tags, tuple):
        raise TypeError(f"{field_name} must be a tuple of strings")
    minimum = 0 if allow_empty else 1
    if len(tags) < minimum or len(tags) > _MAX_TAG_COUNT:
        raise ValueError(
            f"{field_name} must contain from {minimum} to {_MAX_TAG_COUNT} tags"
        )
    normalized: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            raise TypeError(f"each {field_name} item must be a string")
        if not tag or len(tag) > _MAX_TAG_NAME_LENGTH:
            raise ValueError(
                f"each {field_name} item must contain from 1 to "
                f"{_MAX_TAG_NAME_LENGTH} characters"
            )
        normalized.append(tag.upper())
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicate tags")
    return tuple(normalized)


def _validated_absolute_path(path: object, *, field_name: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{field_name} must be a pathlib.Path")
    if not path.is_absolute():
        raise ValueError(f"{field_name} must be absolute")
    return path


@dataclass(frozen=True, slots=True)
class IndexRebuildRequest:
    """Protected process-local input for one authoritative index operation.

    This is deliberately NOT a ``PublicModel`` and has no ``to_dict`` method.
    The authoritative backend reads definitions from ``source_table_path``
    and applies them to ``staged_table_path``. DBF_Anonymizer neither parses
    CDX nor receives raw definitions. Both absolute paths stay process-local
    and must never enter public JSON, manifests, results, progress or errors.
    """

    protocol_schema_version: str
    artifact_class: str
    table_path: str
    source_table_path: Path
    staged_table_path: Path

    def __post_init__(self) -> None:
        if self.protocol_schema_version != INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION:
            raise ValueError(
                "protocol_schema_version must be "
                f"{INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION}"
            )
        if self.artifact_class not in INDEX_ARTIFACT_CLASSES:
            raise ValueError(
                "artifact_class must be one of " + ", ".join(INDEX_ARTIFACT_CLASSES)
            )
        object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))
        object.__setattr__(
            self,
            "source_table_path",
            _validated_absolute_path(
                self.source_table_path, field_name="source_table_path"
            ),
        )
        object.__setattr__(
            self,
            "staged_table_path",
            _validated_absolute_path(
                self.staged_table_path, field_name="staged_table_path"
            ),
        )
        if self.source_table_path == self.staged_table_path:
            raise ValueError("source_table_path and staged_table_path must differ")


@dataclass(frozen=True, slots=True)
class IndexRebuildOutcome:
    """Process-local rebuild verdict plus source-derived tag expectations."""

    result: IndexBackendResult
    expected_tag_inventory: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.result, IndexBackendResult):
            raise TypeError("result must be an IndexBackendResult")
        object.__setattr__(
            self,
            "expected_tag_inventory",
            _validated_tag_inventory(
                self.expected_tag_inventory,
                field_name="expected_tag_inventory",
                allow_empty=self.result.status != "REBUILT",
            ),
        )
        if self.result.status == "REBUILT" and not self.expected_tag_inventory:
            raise ValueError("REBUILT requires expected tag inventory")
        if self.result.status != "REBUILT" and self.expected_tag_inventory:
            raise ValueError("non-REBUILT outcomes must not claim expected tags")


@dataclass(frozen=True, slots=True)
class IndexVerificationRequest:
    """Process-local request to inspect the rebuilt staged table and index."""

    protocol_schema_version: str
    artifact_class: str
    table_path: str
    staged_table_path: Path

    def __post_init__(self) -> None:
        if self.protocol_schema_version != INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION:
            raise ValueError(
                "protocol_schema_version must be "
                f"{INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION}"
            )
        if self.artifact_class not in INDEX_ARTIFACT_CLASSES:
            raise ValueError(
                "artifact_class must be one of " + ", ".join(INDEX_ARTIFACT_CLASSES)
            )
        object.__setattr__(self, "table_path", _normalized_relative_path(self.table_path))
        object.__setattr__(
            self,
            "staged_table_path",
            _validated_absolute_path(
                self.staged_table_path, field_name="staged_table_path"
            ),
        )


@dataclass(frozen=True, slots=True)
class IndexVerificationOutcome:
    """Process-local objective evidence from opening the rebuilt staged table."""

    result: IndexVerificationResult
    table_opened: bool
    actual_record_count: int
    actual_tag_inventory: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.result, IndexVerificationResult):
            raise TypeError("result must be an IndexVerificationResult")
        if not isinstance(self.table_opened, bool):
            raise TypeError("table_opened must be a genuine bool")
        if (
            isinstance(self.actual_record_count, bool)
            or not isinstance(self.actual_record_count, int)
            or self.actual_record_count < 0
        ):
            raise TypeError("actual_record_count must be a non-negative int")
        object.__setattr__(
            self,
            "actual_tag_inventory",
            _validated_tag_inventory(
                self.actual_tag_inventory,
                field_name="actual_tag_inventory",
                allow_empty=self.result.status != "VERIFIED",
            ),
        )
        if self.result.status in {"VERIFIED", "MISMATCH"} and not self.table_opened:
            raise ValueError(
                f"{self.result.status} requires table_opened evidence"
            )
        if self.result.detail_code == "OPEN_FAILED" and self.table_opened:
            raise ValueError("OPEN_FAILED requires table_opened=False")


def index_backend_failure(
    detail_code: str, *, table_path: str | None = None
) -> IndexBackendError:
    """A stable typed, privacy-safe index-backend refusal (no values).

    Only the closed internal machine vocabulary can cross the public error
    boundary. Unknown backend or caller text is reduced to one generic code.
    """
    safe_detail_code = (
        detail_code
        if detail_code in _INDEX_BACKEND_FAILURE_DETAIL_CODES
        else "INDEX_BACKEND_FAILURE_UNCLASSIFIED"
    )
    return IndexBackendError(
        ErrorCode.INDEX_BACKEND_FAILED,
        context=ErrorContext(
            operation="index_backend",
            table_path=table_path,
            detail_code=safe_detail_code,
        ),
    )


@runtime_checkable
class IndexBackend(Protocol):
    """The ONE injected authoritative index-work boundary (REQ-P6-001/REQ-P6-003).

    A backend is a plain synchronous Python object supplied EXPLICITLY by
    the caller at the public service boundary.  DBF_Anonymizer never
    discovers, imports, installs or launches a backend itself; a real
    Windows/VFP implementation (e.g. an adapter for an external toolchain)
    belongs entirely behind this protocol.
    """

    def capabilities(self) -> IndexBackendCapability:
        """Return the backend's validated capability statement."""
        ...

    def rebuild_index(self, request: IndexRebuildRequest) -> IndexRebuildOutcome:
        """Perform one authoritative index artifact operation."""
        ...

    def verify_index(self, request: IndexVerificationRequest) -> IndexVerificationOutcome:
        """Perform one authoritative index verification operation.

        Verifies that the rebuilt index matches the expected state:
        - table opens successfully in the authoritative VFP context
        - record count equals the expected pseudonymized record count
        - structural tag inventory matches the authoritative expected inventory
        """
        ...


def validate_backend_capabilities(
    backend: IndexBackend,
) -> IndexBackendCapability:
    """Consume and VALIDATE one backend's capability statement (fail closed).

    Any unknown protocol schema version, unbounded/mis-typed field or
    malformed contract becomes the stable typed
    :class:`~dbf_anonymizer.errors.IndexBackendError` — the pipeline never
    proceeds with an untrusted backend contract.
    """
    try:
        capability = backend.capabilities()
    except Exception:
        raise index_backend_failure("INDEX_BACKEND_CAPABILITIES_FAILED") from None
    if not isinstance(capability, IndexBackendCapability):
        # The closed model constructor already rejects unknown protocol
        # schema versions and mis-typed fields; a foreign object is not
        # contract-compliant even if it happens to quack similarly.
        raise index_backend_failure("INDEX_BACKEND_CAPABILITY_MALFORMED")
    return capability


def require_backend_support(
    capability: IndexBackendCapability,
    artifact_class: str,
) -> None:
    """Fail closed when the backend does not declare the required support."""
    if artifact_class not in INDEX_ARTIFACT_CLASSES:
        raise index_backend_failure("INDEX_BACKEND_ARTIFACT_CLASS_UNKNOWN")
    required = (
        capability.supports_structural_cdx_rebuild
        if artifact_class == "STRUCTURAL_CDX"
        else capability.supports_standalone_idx_rebuild
    )
    if not required:
        raise index_backend_failure("INDEX_BACKEND_SUPPORT_MISSING")


def run_backend_rebuild(
    backend: IndexBackend,
    request: IndexRebuildRequest,
) -> IndexRebuildOutcome:
    """Run one backend rebuild call behind the typed, privacy-safe boundary.

    The result is validated through the closed public model constructor
    (unknown status/artifact_class/schema version fail closed); a backend
    exception becomes the stable typed privacy-safe error.
    """
    try:
        result = backend.rebuild_index(request)
    except Exception:
        raise index_backend_failure("INDEX_BACKEND_REBUILD_FAILED") from None
    if not isinstance(result, IndexRebuildOutcome):
        raise index_backend_failure("INDEX_BACKEND_RESULT_MALFORMED")
    verdict = result.result
    if (
        verdict.protocol_schema_version != request.protocol_schema_version
        or verdict.artifact_class != request.artifact_class
        or verdict.table_path != request.table_path
    ):
        raise index_backend_failure("INDEX_BACKEND_RESULT_MISMATCH")
    return result


def require_backend_verification(
    capability: IndexBackendCapability,
    artifact_class: str,
) -> None:
    """Fail closed when the backend does not declare verification support."""
    if artifact_class not in INDEX_ARTIFACT_CLASSES:
        raise index_backend_failure("INDEX_BACKEND_ARTIFACT_CLASS_UNKNOWN")
    if not capability.supports_verification:
        raise index_backend_failure("INDEX_BACKEND_VERIFICATION_SUPPORT_MISSING")


def require_backend_runtime(capability: IndexBackendCapability) -> None:
    """Fail closed when no authoritative VFP-compatible runtime is available."""
    if not capability.vfp_runtime_available:
        raise index_backend_failure("INDEX_BACKEND_RUNTIME_UNAVAILABLE")


def run_backend_verification(
    backend: IndexBackend,
    request: IndexVerificationRequest,
) -> IndexVerificationOutcome:
    """Run one backend verification call behind the typed, privacy-safe boundary.

    The result is validated through the closed public model constructor
    (unknown status/artifact_class/schema version fail closed); a backend
    exception becomes the stable typed privacy-safe error.
    """
    try:
        result = backend.verify_index(request)
    except Exception:
        raise index_backend_failure("INDEX_BACKEND_VERIFICATION_FAILED") from None
    if not isinstance(result, IndexVerificationOutcome):
        raise index_backend_failure("INDEX_BACKEND_VERIFICATION_RESULT_MALFORMED")
    verdict = result.result
    if (
        verdict.protocol_schema_version != request.protocol_schema_version
        or verdict.artifact_class != request.artifact_class
        or verdict.table_path != request.table_path
    ):
        raise index_backend_failure("INDEX_BACKEND_VERIFICATION_RESULT_MISMATCH")
    return result


@dataclass(frozen=True, slots=True)
class IndexBackendContract:
    """The consumed, validated view of one injected backend (internal).

    This is the ONLY form the pipeline retains after the capability
    handshake: the validated typed capability plus the injected object.
    It is never serialized and never contains source values.
    """

    backend: IndexBackend
    capability: IndexBackendCapability

    @property
    def backend_id(self) -> str:
        return self.capability.backend_id
