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
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import dbf_anonymizer as public

try:
    from examples import synthetic_dataset  # package-style execution
except ImportError:  # pragma: no cover - plain script execution
    import synthetic_dataset  # script execution


def main() -> None:
    if len(sys.argv) > 1:
        work_root = Path(sys.argv[1])
    else:
        work_root = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-example-recovery-"))

    source = synthetic_dataset.create_single_table_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(source, output, vault)
    preflight_result = public.preflight(plan)
    assert preflight_result.ready
    result = public.pseudonymize(plan)

    # Path A — authorized recovery inside the trusted environment.
    recovered = public.recover(
        output,
        vault=vault,
        output=work_root / "recovered",
        recovery_policy=public.RecoveryPolicy.ENABLED,
    )
    assert recovered.canonical_verified
    assert recovered.table_count == result.table_count
    assert recovered.record_count == result.record_count

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
        assert error.code is public.ErrorCode.RECOVERY_NOT_PERMITTED
        refusal = error.code.value
    else:  # pragma: no cover - DISABLED must always refuse
        raise AssertionError("DISABLED recovery did not refuse")
    assert not refused_output.exists()

    print("DBF_Anonymizer recovery workflow (synthetic data)")
    print(f"ENABLED:  canonical_verified=True, records={recovered.record_count}")
    print(f"DISABLED: typed refusal {refusal} (before any vault access)")
    print("recovered material stays in the trusted environment; it is never transferable")


if __name__ == "__main__":
    main()
