"""The canonical DBF_Anonymizer quick-start workflow (public API only).

Run:

    python examples/basic_workflow.py [WORK_ROOT]

Everything is SYNTHETIC: the demo dataset is created through the public
``dbfbridge`` writer into a disposable workspace (the optional ``WORK_ROOT``
argument, which must NOT exist yet, or a fresh system-TEMP directory).  No
production data, no network, no VFP, no private module imports — the example
is downstream-consumer code.

Roles shown explicitly (bounded, privacy-safe output — no resolved paths):

- SOURCE  — the synthetic dataset (read-only, stays where it is);
- OUTPUT  — the pseudonymized dataset DBF_Anonymizer writes;
- VAULT   — the ONE protected recovery vault for the whole dataset; it must
  stay inside the trusted internal environment and is NEVER transferable.
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
    work_root = synthetic_dataset.workspace_from_arguments("basic")

    source = synthetic_dataset.create_single_table_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    capabilities = public.capabilities()
    _require(
        capabilities.direct_read and capabilities.direct_write and capabilities.recovery,
        "the installed runtime must support direct read/write and recovery",
    )

    plan = public.build_plan(source, output, vault)
    preflight_result = public.preflight(plan)
    _require(preflight_result.ready, "preflight refused the plan; nothing was executed")

    result = public.pseudonymize(plan)
    verification = public.verify_dataset(result, source=source, vault=vault)
    _require(
        verification.status is public.VerificationStatus.PASS,
        "dataset verification did not reach PASS",
    )

    print("DBF_Anonymizer basic workflow (synthetic data)")
    print("SOURCE role:  source/ (synthetic, read-only, trusted environment)")
    print("OUTPUT role:  output/ (pseudonymized)")
    print("VAULT role:   protected/recovery.sqlite3 (ONE protected vault, never transferred)")
    print(f"tables: {result.table_count}, records: {result.record_count}")
    print(f"verification status: {verification.status.value}")
    print(f"assurance level: {verification.assurance.level.value}")


if __name__ == "__main__":
    main()
