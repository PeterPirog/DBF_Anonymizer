"""Public API entry point for DBF_Anonymizer 1.0 operational functions.

Exposes capability discovery, deterministic planning/preflight, the
synchronous transport-neutral ``pseudonymize`` service operation and the
public independent dataset verification ``verify_dataset`` service.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from dbf_anonymizer.capabilities import capabilities
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.engine.publication import (
    derive_destination_identity,
    derive_operation_id,
)
from dbf_anonymizer.errors import ErrorCode, ErrorContext, PublicationError
from dbf_anonymizer.index_backend import (
    IndexBackend,
    IndexBackendContract,
    validate_backend_capabilities,
)
from dbf_anonymizer.models import (
    Plan,
    PseudonymizationResult,
    _PseudonymizationExecutionContext,
    TransferProfile,
)
from dbf_anonymizer.planning import build_plan
from dbf_anonymizer.preflight import PreflightCode, _evaluate_plan_readonly, preflight
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)
from dbf_anonymizer.relationships.assurance import (
    _derive_relational_assurance_from_bounded_evidence,
)
from dbf_anonymizer.recovery import recover
from dbf_anonymizer.transfer_bundle import (
    create_transfer_bundle,
    verify_transfer_bundle,
)
from dbf_anonymizer.verification import verify_dataset

__all__ = [
    "capabilities",
    "build_plan",
    "preflight",
    "pseudonymize",
    "verify_dataset",
    "recover",
    "create_transfer_bundle",
    "verify_transfer_bundle",
]

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
    index_backend: IndexBackend | None = None,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
    workers: int = 1,
) -> PseudonymizationResult:
    """Synchronously pseudonymize one immutable plan (REQ-P4-008/P4-009).

    ``index_backend`` (REQ-P6-001) is the explicit injected Windows/VFP
    index-backend boundary: ``None`` (the default) keeps the pipeline fully
    standalone — no VFP, no COM, no subprocess, no network.  When supplied,
    the backend's capability statement is consumed and VALIDATED fail-closed
    BEFORE any transformation work: an unknown protocol schema version, a
    malformed contract or a backend failure becomes the stable typed
    privacy-safe :class:`~dbf_anonymizer.errors.IndexBackendError`.  The
    default DATA_ONLY profile never requires a backend. VFP_INDEXED uses the
    validated backend operation-scoped for protected-staging rebuild and
    objective open/count/tag verification (REQ-P6-003).

    ONE invocation is ONE logical operation with ONE canonical operation id
    (REQ-P1-008): the durable publication identity, the vault operation row,
    the publication receipt, the engine result, every
    :class:`~dbf_anonymizer.models.ProgressEvent` and the returned
    :class:`~dbf_anonymizer.models.PseudonymizationResult` all carry the
    SAME stable ``vop-`` id, deterministically derived before any event is
    emitted from identity digests only (source/policy/relationship
    fingerprints plus the canonical destination identity) — stable for an
    exact compatible retry, independent of source values, and still protected
    by the engine's full operation binding including the actual vault
    fingerprint.

    A single ``ProgressController`` seeded with that canonical id drives the
    shared side-effect-free preflight evaluation (source verification, table
    evaluation and capacity scanning WITHOUT an intermediate preflight
    completion), the engine's pre-execution source revalidation and every
    pass1/pass2/publication phase. The terminal ``COMPLETED`` event is owned
    by the PUBLIC operation: it is emitted exactly once, only after the
    relational assurance has been derived and the public result constructed
    — never after a cancellation, rejection or callback failure, and never
    with a late cancellation poll after an already committed publication.

    Fresh execution is gated by that shared read-only preflight evaluation.
    Exact completed retries are classified by the engine's durable execution
    identity and return the persisted receipt without entering either pass.
    All transformation, locking, cleanup and atomic publication remain owned
    by :func:`dbf_anonymizer.engine.run_two_pass` under the SAME controller.
    """
    if not isinstance(plan, Plan):
        raise TypeError("pseudonymize requires a Plan")
    if index_backend is not None and not isinstance(index_backend, IndexBackend):
        raise TypeError("index_backend must implement the IndexBackend protocol")
    if (
        isinstance(workers, bool)
        or not isinstance(workers, int)
        or not 1 <= workers <= _MAX_PUBLIC_WORKERS
    ):
        raise ValueError(f"workers must be an integer from 1 to {_MAX_PUBLIC_WORKERS}")
    # REQ-P6-001: the injected backend handshake happens FIRST and fails
    # closed.  A malformed/unknown backend capability schema is the stable
    # typed index-backend failure, never a silent best-effort downgrade and
    # never a raw dependency exception.
    backend_contract: IndexBackendContract | None = None
    if index_backend is not None:
        backend_contract = IndexBackendContract(
            backend=index_backend,
            capability=validate_backend_capabilities(index_backend),
        )
    context = plan.execution_context
    if context is None:
        # Impossible for a real build_plan result; fail closed rather than guess.
        raise _preflight_refusal()

    # The canonical durable operation id exists BEFORE the first public
    # progress event and is stable for exact compatible retries.
    canonical_operation_id = derive_operation_id(
        source_fingerprint=plan.dataset.source_fingerprint,
        policy_fingerprint=plan.policy.policy_fingerprint,
        relationship_fingerprint=plan.relationships.relationship_fingerprint,
        destination_identity=derive_destination_identity(Path(context.output_root)),
    )
    control = ProgressController(
        operation="pseudonymize",
        progress=progress,
        cancel_check=cancel_check,
        operation_id=canonical_operation_id,
    )
    control.start_phase(ProgressPhase.OPERATION)
    # The shared internal preflight evaluation core runs through THIS
    # controller: bounded progress for the potentially long read-only scan
    # stages, and NO preflight terminal completion (the public service owns
    # the invocation's single COMPLETED event).
    check = _evaluate_plan_readonly(
        plan,
        control,
        injected_backend_capability=(
            backend_contract.capability
            if backend_contract is not None
            and plan.output_profile is TransferProfile.VFP_INDEXED
            else None
        ),
    )
    if not check.ready:
        retry_only = (
            set(check.error_codes) == {PreflightCode.DESTINATION_CONFLICT}
            and _completed_retry_candidate(plan)
        )
        if not retry_only:
            raise _preflight_refusal()

    result = run_two_pass(
        plan,
        workers=workers,
        control=control,
        operation_id=canonical_operation_id,
        backend_contract=backend_contract if plan.output_profile is TransferProfile.VFP_INDEXED else None,
    )
    if result.operation_id is None or result.output_fingerprint is None:
        raise PublicationError(
            ErrorCode.PUBLICATION_INCOMPLETE,
            context=ErrorContext(
                operation="pseudonymize",
                detail_code="ENGINE_RESULT_IDENTITY_MISSING",
            ),
        )
    output_name = Path(context.output_root).name
    assurance = _derive_relational_assurance_from_bounded_evidence(
        plan.relationships, result.relations
    )
    public_result = PseudonymizationResult(
        operation_id=result.operation_id,
        dataset=plan.dataset,
        output_path=output_name,
        table_count=len(result.tables_written),
        record_count=result.pass2_records_written,
        vault_created=result.protected_state_created,
        output_fingerprint=result.output_fingerprint,
        assurance=assurance,
        execution_context=_PseudonymizationExecutionContext(
            output_root=context.output_root,
            source_root=context.source_root,
            vault_path=context.vault_path,
        ),
    )
    # The PUBLIC operation owns its single terminal completion: emitted only
    # now — after the assurance was derived and the public result constructed
    # — and never with a late cancellation poll after the committed
    # publication (the post-promotion cancellation rule is preserved).
    control.complete(completed=len(result.tables_written), check_cancel=False)
    return public_result
