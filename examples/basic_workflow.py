"""The canonical DBF_Anonymizer quick-start workflow (public API only).

Run:

    python examples/basic_workflow.py [WORK_ROOT]

Everything is SYNTHETIC: the demo dataset is created through the public
``dbfbridge`` writer into a disposable workspace (the optional ``WORK_ROOT``
argument, or a fresh system-TEMP directory).  No production data, no network,
no VFP, no private module imports — the example is downstream-consumer code.

Roles shown explicitly:

- SOURCE  — the synthetic dataset (read-only, stays where it is);
- OUTPUT  — the pseudonymized dataset DBF_Anonymizer writes;
- VAULT   — the ONE protected recovery vault for the whole dataset; it must
  stay inside the trusted internal environment and is NEVER transferable.
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
        work_root = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-example-basic-"))

    source = synthetic_dataset.create_single_table_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    capabilities = public.capabilities()
    assert capabilities.direct_read and capabilities.direct_write and capabilities.recovery

    plan = public.build_plan(source, output, vault)
    preflight_result = public.preflight(plan)
    assert preflight_result.ready

    result = public.pseudonymize(plan)
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS

    print("DBF_Anonymizer basic workflow (synthetic data)")
    print(f"SOURCE (synthetic, read-only): {source}")
    print(f"OUTPUT (pseudonymized):        {output}")
    print(f"VAULT (protected, trusted):    {vault}")
    print(f"tables: {result.table_count}, records: {result.record_count}")
    print(f"verification status: {verification.status.value}")
    print(f"assurance level: {verification.assurance.level.value}")


if __name__ == "__main__":
    main()
