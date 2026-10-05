"""Recovery workflow with both authorization paths (public API only).

Run:

    python examples/recovery_workflow.py [WORK_ROOT]

Recovery authorization is a HOST decision expressed through the public
``RecoveryPolicy``:

- ``RecoveryPolicy.ENABLED``  — an authorized operator reconstructs a
  canonical copy of the original logical dataset from the pseudonymized
  output plus the protected vault;
- ``RecoveryPolicy.DISABLED`` — recovery is refused with the stable typed
  error ``RecoveryError`` / ``ErrorCode.RECOVERY_NOT_PERMITTED`` BEFORE any
  vault access (no vault file is opened, nothing is created).

All material stays inside the trusted workspace: the recovered copy belongs
to the internal environment and must never be transferred.  Synthetic data
only; no network, no VFP, no private module imports, no vault-row reading.
The optional ``WORK_ROOT`` argument must NOT exist yet (fail-closed).
Output stays privacy-safe: bounded summaries only, never resolved paths.
"""

from __future__ import annotations

import dbf_anonymizer as public

try:
    from examples import synthetic_dataset  # package-style execution
except ImportError:  # pragma: no cover - plain script execution
    import synthetic_dataset  # script execution


def _require(condition: bool, message: str) -> None:
    """An explicit safety check that cannot disappear under ``python -O``."""
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    work_root = synthetic_dataset.workspace_from_arguments("recovery")

    source = synthetic_dataset.create_single_table_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(source, output, vault)
    preflight_result = public.preflight(plan)
    _require(preflight_result.ready, "preflight refused the plan; nothing was executed")
    result = public.pseudonymize(plan)

    # Path A — authorized recovery inside the trusted environment.
    recovered = synthetic_dataset.call_with_transient_retry(
        public.recover,
        output,
        vault=vault,
        output=work_root / "recovered",
        recovery_policy=public.RecoveryPolicy.ENABLED,
    )
    _require(recovered.canonical_verified, "recovery did not verify the canonical dataset")
    _require(
        recovered.table_count == result.table_count
        and recovered.record_count == result.record_count,
        "recovered dataset shape is inconsistent with the pseudonymized dataset",
    )

    # Path B — a host that must NOT be able to recover data sets DISABLED.
    # The refusal happens BEFORE any vault access and creates no output.
    refused_output = work_root / "refused"
    try:
        public.recover(
            output,
            vault=vault,
            output=refused_output,
            recovery_policy=public.RecoveryPolicy.DISABLED,
        )
    except public.RecoveryError as error:
        _require(
            error.code is public.ErrorCode.RECOVERY_NOT_PERMITTED,
            "DISABLED recovery must refuse with RECOVERY_NOT_PERMITTED",
        )
        refusal = error.code.value
    else:  # pragma: no cover - DISABLED must always refuse
        raise RuntimeError("DISABLED recovery did not refuse")
    _require(not refused_output.exists(), "a refused recovery must not create output")

    print("DBF_Anonymizer recovery workflow (synthetic data)")
    print("ENABLED:  canonical_verified=True (recovered copy stays in the trusted workspace)")
    print(f"DISABLED: typed refusal {refusal} (before any vault access; no output created)")
    print("recovered material is internal-environment data; it is never transferable")


if __name__ == "__main__":
    main()
