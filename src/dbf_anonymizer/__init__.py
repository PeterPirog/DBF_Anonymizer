"""DBF_Anonymizer 1.0 development baseline.

Public typed model surface (REQ-P1-002): immutable value models with a
stable, versioned, JSON-safe serialization contract (see
``dbf_anonymizer.models``).  This package does not yet expose public
operation functions (``capabilities``, ``build_plan``, ``preflight``,
``pseudonymize``, ``verify_dataset``, ``recover``,
``create_transfer_bundle``, ``verify_transfer_bundle``) — those belong to
REQ-P1-004 and are intentionally absent.

No compatibility obligation exists toward the historical 0.3 API; see
``docs/migration-1.0-clean-slate.md``.
"""

from __future__ import annotations

from dbf_anonymizer.models import (
    PUBLIC_MODEL_SCHEMA_VERSION,
    Capabilities,
    DatasetIdentity,
    FieldPlan,
    Plan,
    PolicySummary,
    PreflightIssue,
    PreflightResult,
    ProgressEvent,
    PseudonymizationResult,
    RelationalAssurance,
    RelationshipGroup,
    RelationshipMember,
    RelationshipMetadata,
    RecoveryResult,
    ResultStatus,
    TablePlan,
    TransferBundleResult,
    VerificationResult,
    VerificationStatus,
)

__version__ = "1.0.0.dev0"

__all__ = [
    "PUBLIC_MODEL_SCHEMA_VERSION",
    "Capabilities",
    "DatasetIdentity",
    "FieldPlan",
    "Plan",
    "PolicySummary",
    "PreflightIssue",
    "PreflightResult",
    "ProgressEvent",
    "PseudonymizationResult",
    "RelationalAssurance",
    "RecoveryResult",
    "RelationshipGroup",
    "RelationshipMember",
    "RelationshipMetadata",
    "ResultStatus",
    "TablePlan",
    "TransferBundleResult",
    "VerificationResult",
    "VerificationStatus",
]