"""Progress and cooperative-cancellation workflow (public API only).

Run:

    python examples/progress_cancellation.py [WORK_ROOT]

Two deterministic demonstrations on synthetic data:

1. PROGRESS — a synchronous ``progress`` callback receives bounded
   structured ``ProgressEvent`` objects (stable phase/event vocabulary and
   counters, never free-form text).  ``cancel_check=lambda: False`` keeps
   the operation running; the operation completes and verifies PASS.
2. CANCELLATION — a ``cancel_check`` that returns ``True`` at a safe early
   point stops the operation deterministically (event-driven, no sleeps, no
   timing assumptions): the public API raises the typed ``CancellationError``
   with the stable ``OPERATION_CANCELLED`` code, emits NO terminal
   ``COMPLETED`` event, produces NO published pseudonymized output, and the
   source dataset stays byte-identical (bounded hash-tree comparison).

No async API is involved.  No private module imports; no network; no VFP.
The optional ``WORK_ROOT`` argument must NOT exist yet (fail-closed).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import dbf_anonymizer as public

try:
    from examples import synthetic_dataset  # package-style execution
except ImportError:  # pragma: no cover - plain script execution
    import synthetic_dataset  # script execution


def _require(condition: bool, message: str) -> None:
    """An explicit safety check that cannot disappear under ``python -O``."""
    if not condition:
        raise RuntimeError(message)


def _hash_tree(root: Path) -> dict[str, str]:
    """Bounded source-immutability evidence (same pattern as the
    architecture acceptance tests)."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def main() -> None:
    work_root = synthetic_dataset.workspace_from_arguments("progress")

    # Part 1 — bounded progress callbacks (non-cancelling).
    progress_source = synthetic_dataset.create_single_table_dataset(work_root / "source")
    progress_plan = public.build_plan(
        progress_source, work_root / "output", work_root / "protected" / "recovery.sqlite3"
    )
    events: list[public.ProgressEvent] = []
    result = public.pseudonymize(progress_plan, progress=events.append, cancel_check=lambda: False)
    verification = public.verify_dataset(
        result, source=progress_source, vault=work_root / "protected" / "recovery.sqlite3"
    )
    _require(
        verification.status is public.VerificationStatus.PASS,
        "dataset verification did not reach PASS",
    )
    _require(bool(events), "no progress events were emitted")
    operation_ids = {event.operation_id for event in events}
    _require(len(operation_ids) == 1, "one invocation must carry one stable operation id")
    ordered_phases: list[str] = []
    for event in events:
        if event.phase_code not in ordered_phases:
            ordered_phases.append(event.phase_code)

    print("DBF_Anonymizer progress workflow (synthetic data)")
    print(f"progress events observed: {len(events)}")
    print("phases in order: " + " -> ".join(ordered_phases))
    print(f"verification status: {verification.status.value}")

    # Part 2 — deterministic cooperative cancellation (event-driven).
    cancel_source = synthetic_dataset.create_single_table_dataset(work_root / "cancel-source")
    cancel_source_before = _hash_tree(cancel_source)
    cancel_plan = public.build_plan(
        cancel_source,
        work_root / "cancel-output",
        work_root / "cancel-protected" / "recovery.sqlite3",
    )
    cancel_state = {"requested": False}
    cancel_events: list[public.ProgressEvent] = []

    def progress(event: public.ProgressEvent) -> None:
        cancel_events.append(event)
        if event.phase_code == "PASS2_WRITE" and event.event_code == "STARTED":
            cancel_state["requested"] = True

    try:
        public.pseudonymize(
            cancel_plan,
            progress=progress,
            cancel_check=lambda: cancel_state["requested"],
        )
    except public.CancellationError as error:
        _require(
            error.code is public.ErrorCode.OPERATION_CANCELLED,
            "cancellation must report the stable OPERATION_CANCELLED code",
        )
        refusal = error.code.value
    else:  # pragma: no cover - a requested cancellation must raise
        raise RuntimeError("the requested cancellation was not honoured")
    _require(
        not (work_root / "cancel-output").exists(),
        "a cancelled operation must not publish a completed dataset",
    )
    _require(
        not any(event.event_code == "COMPLETED" for event in cancel_events),
        "a cancelled operation must not emit the terminal COMPLETED event",
    )
    _require(
        _hash_tree(cancel_source) == cancel_source_before,
        "the cancelled operation must leave the source byte-identical",
    )

    print("DBF_Anonymizer cancellation workflow (synthetic data)")
    print(
        f"cancellation code: {refusal} "
        "(no COMPLETED event, no published output, source byte-identical)"
    )


if __name__ == "__main__":
    main()
