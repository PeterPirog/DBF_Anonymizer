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
from typing import Protocol, runtime_checkable

from dbf_anonymizer.errors import (
    ErrorCode,
    ErrorContext,
    IndexBackendError,
)
from dbf_anonymizer.models import (
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    INDEX_ARTIFACT_CLASSES,
    IndexBackendCapability,
    IndexBackendResult,
    _normalized_relative_path,
)

__all__ = [
    "INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION",
    "INDEX_ARTIFACT_CLASSES",
    "INDEX_BACKEND_RESULT_STATUSES",
    "IndexBackend",
    "IndexBackendCapability",
    "IndexRebuildRequest",
    "IndexBackendResult",
    "IndexBackendError",
    "IndexBackendContract",
    "validate_backend_capabilities",
    "require_backend_support",
    "run_backend_rebuild",
    "index_backend_failure",
]

_BACKEND_OPERATION = "index_backend"
_MAX_INDEX_DEFINITION_LENGTH = 65536


@dataclass(frozen=True, slots=True)
class IndexRebuildRequest:
    """Protected process-local input for one authoritative index operation.

    This is deliberately NOT a ``PublicModel`` and has no ``to_dict`` method.
    Its raw ``definition`` belongs only to the future P6-003 protected-staging
    lifecycle and may be passed in process to an injected backend. It must
    never enter public JSON, manifests, results, progress, errors or logs.
    """

    protocol_schema_version: str
    artifact_class: str
    table_path: str
    definition: str

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
        if not isinstance(self.definition, str):
            raise TypeError("definition must be text")
        if not self.definition or len(self.definition) > _MAX_INDEX_DEFINITION_LENGTH:
            raise ValueError(
                "definition must be non-empty text of at most "
                f"{_MAX_INDEX_DEFINITION_LENGTH} characters"
            )


def index_backend_failure(
    detail_code: str, *, table_path: str | None = None
) -> IndexBackendError:
    """A stable typed, privacy-safe index-backend refusal (no values)."""
    return IndexBackendError(
        ErrorCode.INDEX_BACKEND_FAILED,
        context=ErrorContext(
            operation="index_backend",
            table_path=table_path,
            detail_code=detail_code,
        ),
    )


@runtime_checkable
class IndexBackend(Protocol):
    """The ONE injected authoritative index-work boundary (REQ-P6-001).

    A backend is a plain synchronous Python object supplied EXPLICITLY by
    the caller at the public service boundary.  DBF_Anonymizer never
    discovers, imports, installs or launches a backend itself; a real
    Windows/VFP implementation (e.g. an adapter for an external toolchain)
    belongs entirely behind this protocol.
    """

    def capabilities(self) -> IndexBackendCapability:
        """Return the backend's validated capability statement."""
        ...

    def rebuild_index(self, request: IndexRebuildRequest) -> IndexBackendResult:
        """Perform one authoritative index artifact operation."""
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
) -> IndexBackendResult:
    """Run one backend rebuild call behind the typed, privacy-safe boundary.

    The result is validated through the closed public model constructor
    (unknown status/artifact_class/schema version fail closed); a backend
    exception becomes the stable typed privacy-safe error.
    """
    try:
        result = backend.rebuild_index(request)
    except Exception:
        raise index_backend_failure("INDEX_BACKEND_REBUILD_FAILED") from None
    if not isinstance(result, IndexBackendResult):
        raise index_backend_failure("INDEX_BACKEND_RESULT_MALFORMED")
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
