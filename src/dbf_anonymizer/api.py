"""Public API entry point for DBF_Anonymizer 1.0 operational functions.

Exposes capability discovery, deterministic planning/preflight and the
synchronous transport-neutral ``pseudonymize`` service operation.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from dbf_anonymizer.capabilities import capabilities
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.errors import ErrorCode, ErrorContext, PublicationError
from dbf_anonymizer.models import (
    Plan,
    PseudonymizationResult,
    _PseudonymizationExecutionContext,
)
from dbf_anonymizer.planning import build_plan
from dbf_anonymizer.preflight import PreflightCode, preflight
from dbf_anonymizer.progress import CancelCheck, ProgressCallback
from dbf_anonymizer.relationships.assurance import (
    _derive_relational_assurance_from_bounded_evidence,
)

__all__ = ["capabilities", "build_plan", "preflight", "pseudonymize"]

_MAX_PUBLIC_WORKERS = 32


def _preflight_refusal() -> PublicationError:
    return PublicationError(
        ErrorCode.PUBLICATION_FAILED,
        context=ErrorContext(
            operation="pseudonymize", detail_code="PREFLIGHT_REJECTED"
        ),
    )


def _completed_retry_candidate(plan: Plan) -> bool:
    """Whether execution identity can safely classify an existing target.

    Vault COMPATIBILITY is owned by preflight's read-only dictionary-identity
    validation: an opaque, corrupt, schema-unsupported, sidecar-ambiguous or
    fingerprint-mismatched dictionary emits ``VAULT_REUSE_INCOMPATIBLE`` and
    can never appear in a destination-conflict-only error set, so it can
    never reach the engine through this retry exception. This structural
    probe only confirms the completed-dataset FORM (an existing output
    directory plus a regular dictionary file): with both durable targets
    present the engine can only return an exact completed receipt or fail
    before acquiring its writer lease — it cannot enter a new transformation
    pass over an existing output directory, and the durable operation
    binding still verifies the exact receipt and output fingerprint.
    """
    context = plan.execution_context
    if context is None:
        return False
    try:
        output_mode = os.stat(context.output_root).st_mode
        vault_mode = os.stat(context.vault_path).st_mode
    except OSError:
        return False
    return stat.S_ISDIR(output_mode) and stat.S_ISREG(vault_mode)


def pseudonymize(
    plan: Plan,
    *,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
    workers: int = 1,
) -> PseudonymizationResult:
    """Synchronously pseudonymize one immutable plan (REQ-P4-008/P4-009).

    Fresh execution is gated by the existing side-effect-free preflight. Exact
    completed retries are classified by the engine's durable execution
    identity and return the persisted receipt without entering either pass.
    All transformation, locking, cleanup and atomic publication remain owned
    by :func:`dbf_anonymizer.engine.run_two_pass`.
    """
    if not isinstance(plan, Plan):
        raise TypeError("pseudonymize requires a Plan")
    if (
        isinstance(workers, bool)
        or not isinstance(workers, int)
        or not 1 <= workers <= _MAX_PUBLIC_WORKERS
    ):
        raise ValueError(f"workers must be an integer from 1 to {_MAX_PUBLIC_WORKERS}")

    check = preflight(plan, cancel_check=cancel_check)
    if not check.ready:
        retry_only = (
            set(check.error_codes) == {PreflightCode.DESTINATION_CONFLICT}
            and _completed_retry_candidate(plan)
        )
        if not retry_only:
            raise _preflight_refusal()

    result = run_two_pass(
        plan,
        progress=progress,
        cancel_check=cancel_check,
        workers=workers,
    )
    if result.operation_id is None or result.output_fingerprint is None:
        raise PublicationError(
            ErrorCode.PUBLICATION_INCOMPLETE,
            context=ErrorContext(
                operation="pseudonymize",
                detail_code="ENGINE_RESULT_IDENTITY_MISSING",
            ),
        )
    context = plan.execution_context
    if context is None:
        raise _preflight_refusal()
    output_name = Path(context.output_root).name
    assurance = _derive_relational_assurance_from_bounded_evidence(
        plan.relationships, result.relations
    )
    return PseudonymizationResult(
        operation_id=result.operation_id,
        dataset=plan.dataset,
        output_path=output_name,
        table_count=len(result.tables_written),
        record_count=result.pass2_records_written,
        vault_created=result.protected_state_created,
        output_fingerprint=result.output_fingerprint,
        assurance=assurance,
        execution_context=_PseudonymizationExecutionContext(
            output_root=context.output_root
        ),
    )
