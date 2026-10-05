"""DATA_ONLY transfer-bundle workflow (public API only).

Run:

    python examples/data_only_bundle.py [WORK_ROOT]

The verified DATA_ONLY bundle is the ONLY transferable artifact:

- it contains the pseudonymized DBF tables, their fresh FPT companions and
  the sanitized public manifest — nothing else;
- it EXCLUDES the vault, every SQLite sidecar, recovery material, secrets,
  original values and stale/unverified index artifacts BY CONSTRUCTION (the
  authoritative exclusion rules are owned by ``create_transfer_bundle`` /
  ``verify_transfer_bundle`` — this example only re-states the observable
  public outcome);
- it can be re-verified ANYWHERE by ``verify_transfer_bundle`` without the
  source and without the vault.

DATA_ONLY is pseudonymized data whose recovery material is absent — it is
NOT anonymous data.  Synthetic data only; no network, no VFP.
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
    work_root = synthetic_dataset.workspace_from_arguments("bundle")

    source = synthetic_dataset.create_single_table_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(source, output, vault)
    preflight_result = public.preflight(plan)
    _require(preflight_result.ready, "preflight refused the plan; nothing was executed")
    result = public.pseudonymize(plan)

    bundle_path = work_root / "bundle"
    bundle = public.create_transfer_bundle(result, destination=bundle_path, profile="DATA_ONLY")
    _require(bundle.verified, "the bundle was not verified at creation")
    standalone = public.verify_transfer_bundle(bundle_path)
    _require(standalone.verified, "the bundle was not verified standalone")
    _require(
        standalone.manifest_fingerprint == bundle.manifest_fingerprint,
        "standalone verification saw a different manifest",
    )

    # Observable public outcome only: no vault database or SQLite sidecar is
    # part of the bundle tree. The authoritative security claim is owned by
    # the bundle creation/verification API itself.
    bundle_files = tuple(path for path in bundle_path.rglob("*") if path.is_file())
    _require(bool(bundle_files), "the bundle tree is empty")
    _require(
        not tuple(bundle_path.rglob("*.sqlite3*")),
        "no SQLite database may appear inside a DATA_ONLY bundle",
    )

    print("DBF_Anonymizer DATA_ONLY workflow (synthetic data)")
    print(f"bundle verified at creation:  {bundle.verified}")
    print(f"bundle verified standalone:   {standalone.verified}")
    print(f"bundle files: {len(bundle_files)}")
    print(f"manifest fingerprint: {bundle.manifest_fingerprint}")
    print("DATA_ONLY is pseudonymized, NOT anonymous; the vault is never part of it")


if __name__ == "__main__":
    main()
