"""DBF_Anonymizer clean-slate 1.0 public package boundary.

The historical 0.3 API is intentionally not preserved.  The first public 1.0
contracts are the immutable typed models from REQ-P1-002.  Product operations
(``capabilities``, ``build_plan``, ``preflight``, ``pseudonymize``,
``verify_dataset``, ``recover``, ``create_transfer_bundle`` and
``verify_transfer_bundle``) are introduced only when their owning requirements
are implemented; no placeholder success functions are exported.

The sole DBF/FPT parser and writer boundary for 1.0 remains the published
public ``dbfbridge[write]>=1.1.0,<2`` distribution.
"""

from __future__ import annotations

from .models import (
    MODEL_SCHEMA_VERSION,
    Capabilities,
    DatasetIdentity,
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
    VerificationResult,
)

__version__ = "1.0.0.dev0"

__all__ = [
    "MODEL_SCHEMA_VERSION",
    "Capabilities",
    "DatasetIdentity",
    "Plan",
    "TablePlan",
    "PolicySummary",
    "RelationshipMetadata",
    "RelationalAssurance",
    "RelationalAssuranceLevel",
    "ProgressEvent",
    "PreflightResult",
    "PseudonymizationResult",
    "VerificationResult",
    "RecoveryResult",
    "TransferBundleResult",
    "TransferProfile",
]
