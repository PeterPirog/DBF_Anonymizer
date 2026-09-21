"""Shared structured-progress / cooperative-cancellation layer (REQ-P1-008).

This module is the SINGLE callback control layer for the long-running public
operations.  ``planning.build_plan`` and ``preflight`` both drive it; the
private discovery/fingerprint helpers only receive narrow probes supplied by
the controller, so callback handling is never duplicated.

Contracts implemented here:

* **Bounded structured progress** — every callback invocation receives an
  immutable public :class:`~dbf_anonymizer.models.ProgressEvent` carrying only
  privacy-safe metadata (operation ID, phase code, event code, unit counts and
  a normalized relative table path).  Progress frequency is bounded by the
  documented quanta below; source values are never part of any event or of the
  throttling state.
* **Cooperative cancellation** — ``cancel_check`` is polled at the declared
  scan safe points.  When it returns a truthy value the typed public
  :class:`~dbf_anonymizer.errors.CancellationError` (``OPERATION_CANCELLED``)
  is raised and no result / completion event is produced.
* **Contained, classified callback failures** — a progress callback or
  cancel-check callback may contain private paths, source values, secrets or
  arbitrary exception text.  Raw exceptions therefore never escape: EVERY
  ``Exception`` raised by a user callback — ``CancellationError`` and
  ``CallbackError`` included — is reclassified at the callback boundary into
  :class:`~dbf_anonymizer.errors.CallbackError` carrying only the
  registry-controlled message and a stable machine code
  (``PROGRESS_CALLBACK_FAILED`` / ``CANCEL_CALLBACK_FAILED``).  A user
  callback can never manufacture ``OPERATION_CANCELLED`` by raising;
  cancellation is produced only by a ``cancel_check`` that RETURNS a truthy
  value.  Exception text is never parsed and never propagated.

The layer is synchronous and transport-neutral: no asyncio, jobs, threads,
MCP or server logic.  ``progress=None`` / ``cancel_check=None`` (the defaults)
keep the existing deterministic behavior and results byte-identical.
"""

from __future__ import annotations

import uuid
from typing import Callable

from dbf_anonymizer.errors import (
    CallbackError,
    CancellationError,
    ErrorCode,
    ErrorContext,
)
from dbf_anonymizer.models import ProgressEvent

__all__ = [
    "PROGRESS_QUANTUM_VERSION",
    "ProgressCallback",
    "CancelCheck",
    "ProgressPhase",
    "ProgressEventCode",
    "ProgressController",
    "FINGERPRINT_HASH_CHUNK_SIZE",
    "FINGERPRINT_CANCEL_CHUNK_QUANTUM",
    "CAPACITY_PROGRESS_RECORD_QUANTUM",
]

#: Versioned identity of the bounded-progress / cancellation-quanta vocabulary.
PROGRESS_QUANTUM_VERSION = "1.1"

#: Type of the synchronous progress callback (REQ-P1-002 ProgressEvent).
ProgressCallback = Callable[[ProgressEvent], None]

#: Type of the synchronous cooperative cancellation check.
CancelCheck = Callable[[], bool]


class ProgressPhase:
    """Stable phase-code vocabulary for the current long-running operations.

    ``SCAN`` is the phase family realized today (discovery, fingerprinting,
    table evaluation, source revalidation, capacity scanning).  ``WRITE``,
    ``VERIFICATION`` and ``PUBLICATION`` phases are documented as the
    internal safe-point concepts for the future P4/P5 operations; the
    Phase 4 two-pass engine (REQ-P4-002) realizes its own bounded phases
    ``PASS1_SCAN``/``PASS1_FINALIZE``/``PASS2_WRITE`` on the same bounded
    progress contract, plus ``SOURCE_REVALIDATION`` for the pre-execution
    trust re-scan.  No operation outside the engine emits them.

    Vocabulary note (version 1.1): ``SOURCE_REVALIDATION`` was added so the
    engine's pre-execution source re-scan reports bounded progress under its
    OWN phase — a public ``pseudonymize`` invocation shares ONE controller
    between the shared preflight evaluation and the engine, and reusing
    ``SOURCE_VERIFICATION`` there would reset that phase's unit counts
    within the same operation stream.
    """

    OPERATION = "OPERATION"
    DISCOVERY = "DISCOVERY"
    FINGERPRINT = "FINGERPRINT"
    TABLE_EVALUATION = "TABLE_EVALUATION"
    SOURCE_VERIFICATION = "SOURCE_VERIFICATION"
    SOURCE_REVALIDATION = "SOURCE_REVALIDATION"
    CAPACITY_SCAN = "CAPACITY_SCAN"
    SCAN = "SCAN"
    WRITE = "WRITE"
    VERIFICATION = "VERIFICATION"
    PUBLICATION = "PUBLICATION"
    PASS1_SCAN = "PASS1_SCAN"
    PASS1_FINALIZE = "PASS1_FINALIZE"
    PASS2_WRITE = "PASS2_WRITE"


class ProgressEventCode:
    """Stable event-code vocabulary (read-only string constants)."""

    STARTED = "STARTED"
    PROGRESS = "PROGRESS"
    COMPLETED = "COMPLETED"


# ---------------------------------------------------------------------------
# Bounded progress / cancellation quanta (documented rationale)
# ---------------------------------------------------------------------------
#: Fingerprint hashing chunk size (the pre-existing 64 KiB read quantum).
FINGERPRINT_HASH_CHUNK_SIZE = 65536

#: Cooperative cancellation is polled at least every
#: ``FINGERPRINT_CANCEL_CHUNK_QUANTUM`` chunks during artifact hashing —
#: 16 chunks * 64 KiB = 1 MiB — and once before every artifact.  This bounds
#: cancellation latency for whole-artifact fingerprint hashing without adding
#: per-chunk callback overhead to every small file.
FINGERPRINT_CANCEL_CHUNK_QUANTUM = 16

#: During the capacity record scan, cancellation is polled at EVERY streamed
#: record boundary (quantum 1 record: minimal deterministic latency) and at
#: every table boundary.  The progress EVENT frequency is bounded separately:
#: at most one progress event per ``CAPACITY_PROGRESS_RECORD_QUANTUM`` streamed
#: records per table, which avoids callback floods on large datasets while
#: still providing useful progress.
CAPACITY_PROGRESS_RECORD_QUANTUM = 4096

#: Bounded operation-id shape: "op-" + 32 lowercase hex characters.
_OPERATION_ID_PREFIX = "op-"

#: Stable detail codes for the contained callback-failure classification.
_PROGRESS_CALLBACK_DETAIL = "PROGRESS_CALLBACK"
_CANCEL_CHECK_DETAIL = "CANCEL_CHECK"
_CANCELLED_DETAIL = "CANCELLED_BY_CHECK"


def _uuid_operation_id() -> str:
    """Privacy-safe in-memory invocation ID (no files, no network, no globals)."""
    return _OPERATION_ID_PREFIX + uuid.uuid4().hex


#: Private test seam: deterministic tests may replace this module-level
#: callable (same pattern as the preflight filesystem seams).  It is not part
#: of the public API and the generated ID never depends on source values.
_next_operation_id: Callable[[], str] = _uuid_operation_id


class ProgressController:
    """One invocation's progress/cancellation control state.

    All events of one invocation share one lazily generated, privacy-safe,
    whitespace-free ``operation_id``.  Event ordering is deterministic for a
    deterministic source: ``STARTED`` precedes every progress event of its
    phase, ``completed_units`` never decreases within a phase, and exactly one
    terminal ``COMPLETED`` event is emitted — only immediately before a
    genuine successful return, never after cancellation or a callback failure.
    """

    def __init__(
        self,
        *,
        operation: str,
        progress: ProgressCallback | None = None,
        cancel_check: CancelCheck | None = None,
    ) -> None:
        self._operation = operation
        self._progress = progress
        self._cancel_check = cancel_check
        self._operation_id: str | None = None
        self._phase_totals: dict[str, int | None] = {}
        self._phase_counts: dict[str, int] = {}

    @property
    def operation_id(self) -> str:
        """Privacy-safe invocation ID, generated lazily on first use."""
        if self._operation_id is None:
            self._operation_id = _next_operation_id()
        return self._operation_id

    @property
    def has_progress(self) -> bool:
        """True when a progress callback was supplied for this invocation."""
        return self._progress is not None

    # -- cancellation -------------------------------------------------------
    def check_cancelled(self) -> None:
        """Poll cooperative cancellation at a scan safe point.

        Raises the typed :class:`CancellationError` (``OPERATION_CANCELLED``,
        privacy-safe bounded context) when the caller's check returns a truthy
        value — this is the ONLY way an ``OPERATION_CANCELLED`` outcome is
        produced.  A raising cancel-check is contained and classified as
        ``CANCEL_CALLBACK_FAILED`` no matter what the callback throws
        (``CancellationError`` and ``CallbackError`` included): a user
        callback can never manufacture a genuine cancellation by raising, and
        the raw exception never escapes.
        """
        if self._cancel_check is None:
            return
        try:
            requested = self._cancel_check()
        except Exception:
            raise CallbackError(
                ErrorCode.CANCEL_CALLBACK_FAILED,
                context=ErrorContext(
                    operation=self._operation,
                    detail_code=_CANCEL_CHECK_DETAIL,
                ),
            ) from None
        if requested:
            raise CancellationError(
                ErrorCode.OPERATION_CANCELLED,
                context=ErrorContext(
                    operation=self._operation,
                    detail_code=_CANCELLED_DETAIL,
                ),
            )

    # -- progress -----------------------------------------------------------
    def start_phase(self, phase: str, *, total: int | None = None) -> None:
        """Enter a phase: poll cancellation, then emit its ``STARTED`` event."""
        self.check_cancelled()
        self._phase_totals[phase] = total
        self._phase_counts[phase] = 0
        self.emit(ProgressEventCode.STARTED, phase, completed=0, total=total)

    def bump(self, phase: str, *, table_path: str | None = None) -> None:
        """Count one completed unit of *phase* and emit its progress event."""
        self._phase_counts[phase] = self._phase_counts.get(phase, 0) + 1
        self.emit(
            ProgressEventCode.PROGRESS,
            phase,
            completed=self._phase_counts[phase],
            total=self._phase_totals.get(phase),
            table_path=table_path,
        )

    def progress(
        self,
        phase: str,
        *,
        completed: int,
        total: int | None = None,
        table_path: str | None = None,
    ) -> None:
        """Emit a progress event with an explicit unit count."""
        self.emit(
            ProgressEventCode.PROGRESS,
            phase,
            completed=completed,
            total=total,
            table_path=table_path,
        )

    def complete(self, *, completed: int, check_cancel: bool = True) -> None:
        """Emit the single terminal ``COMPLETED`` event before a real return.

        Cancellation is polled first, so a cancellation observed at the very
        end still produces no completion event and no result.
        """
        if check_cancel:
            self.check_cancelled()
        self.emit(
            ProgressEventCode.COMPLETED,
            ProgressPhase.OPERATION,
            completed=completed,
            total=completed,
        )

    def emit(
        self,
        event_code: str,
        phase: str,
        *,
        completed: int,
        total: int | None = None,
        table_path: str | None = None,
    ) -> None:
        """Build one immutable ProgressEvent and invoke the callback safely.

        Callback exceptions are contained: ANY exception raised by the
        callback — ``CancellationError`` and ``CallbackError`` included —
        becomes the stable ``PROGRESS_CALLBACK_FAILED`` classification without
        any of the raw exception content.  A user callback therefore can never
        manufacture an ``OPERATION_CANCELLED`` outcome or any other machine
        code by throwing; the raw exception never escapes.
        """
        if self._progress is None:
            return
        event = ProgressEvent(
            operation_id=self.operation_id,
            phase_code=phase,
            event_code=event_code,
            completed_units=completed,
            total_units=total,
            table_path=table_path,
        )
        try:
            self._progress(event)
        except Exception:
            raise CallbackError(
                ErrorCode.PROGRESS_CALLBACK_FAILED,
                context=ErrorContext(
                    operation=self._operation,
                    detail_code=_PROGRESS_CALLBACK_DETAIL,
                ),
            ) from None
