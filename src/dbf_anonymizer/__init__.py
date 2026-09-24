"""DBF_Anonymizer clean-slate 1.0 public package boundary.

The historical 0.3 API is intentionally not preserved.  Public 1.0 contracts
currently include the immutable typed models from REQ-P1-002, the stable,
privacy-safe error hierarchy from REQ-P1-003, the read-only deterministic
build planning function ``build_plan`` from REQ-P1-005, the source-read-only,
side-effect-free ``preflight`` operation from REQ-P1-006, and the
side-effect-free public capability discovery ``capabilities`` from
REQ-P1-007.  The long-running read/scan operations support the REQ-P1-008
bounded structured progress and cooperative cancellation callbacks
(keyword-only ``progress`` / ``cancel_check`` arguments).  The public
independent dataset verification ``verify_dataset`` (REQ-P5-001), the
protected canonical dataset recovery ``recover`` (REQ-P5-002/REQ-P5-003)
and the safe standalone DATA_ONLY transfer bundle
``create_transfer_bundle`` / ``verify_transfer_bundle``
(REQ-P5-004..REQ-P5-007) are the implemented public service slices; no
placeholder success functions are exported.

The sole DBF/FPT parser and writer boundary for 1.0 remains the published
public ``dbfbridge[write]>=1.1.0,<2`` distribution.
"""

from __future__ import annotations

from .errors import (
    ERROR_REGISTRY,
    ERROR_REGISTRY_VERSION,
    ERROR_SCHEMA_VERSION,
    AnonymizerError,
    CallbackError,
    CancellationError,
    DBFBridgeError,
    ErrorCategory,
    ErrorCode,
    ErrorContext,
    ErrorDefinition,
    IndexBackendError,
    MappingError,
    PathError,
    PolicyError,
    PublicationError,
    RecoveryError,
    TransferError,
    RelationshipError,
    VaultError,
    VerificationError,
)
from .models import (
    MODEL_SCHEMA_VERSION,
    IDENTITY_PRIVACY_REVIEW_REQUIRED,
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    INDEX_ARTIFACT_CLASSES,
    INDEX_BACKEND_RESULT_STATUSES,
    Capabilities,
    DatasetIdentity,
    IndexBackendCapability,
    IndexBackendResult,
    IndexRebuildRequest,
    NumericIdentityReview,
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
    VaultStrategy,
    VerificationResult,
    VerificationStatus,
    RawByteEquivalence,
)
from .index_backend import IndexBackend
from .api import (
    build_plan,
    capabilities,
    create_transfer_bundle,
    preflight,
    pseudonymize,
    recover,
    verify_dataset,
    verify_transfer_bundle,
)

__version__ = "1.0.0.dev0"

__all__ = [
    "MODEL_SCHEMA_VERSION",
    "IDENTITY_PRIVACY_REVIEW_REQUIRED",
    "INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION",
    "INDEX_ARTIFACT_CLASSES",
    "INDEX_BACKEND_RESULT_STATUSES",
    "IndexBackend",
    "IndexBackendCapability",
    "IndexRebuildRequest",
    "IndexBackendResult",
    "IndexBackendError",
    "Capabilities",
    "DatasetIdentity",
    "NumericIdentityReview",
    "Plan",
    "TablePlan",
    "PolicySummary",
    "RelationshipMetadata",
    "RelationalAssurance",
    "RelationalAssuranceLevel",
    "ProgressEvent",
    "PreflightResult",
    "PseudonymizationResult",
    "VerificationStatus",
    "VerificationResult",
    "RawByteEquivalence",
    "RecoveryResult",
    "TransferBundleResult",
    "TransferProfile",
    "VaultStrategy",
    "build_plan",
    "preflight",
    "pseudonymize",
    "verify_dataset",
    "recover",
    "create_transfer_bundle",
    "verify_transfer_bundle",
    "capabilities",
    "ERROR_SCHEMA_VERSION",
    "ERROR_REGISTRY_VERSION",
    "ERROR_REGISTRY",
    "ErrorCategory",
    "ErrorCode",
    "ErrorDefinition",
    "ErrorContext",
    "AnonymizerError",
    "PathError",
    "PolicyError",
    "DBFBridgeError",
    "VaultError",
    "MappingError",
    "RelationshipError",
    "PublicationError",
    "VerificationError",
    "RecoveryError",
    "TransferError",
    "IndexBackendError",
    "CancellationError",
    "CallbackError",
]
