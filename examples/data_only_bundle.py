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
        work_root = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-example-bundle-"))

    source = synthetic_dataset.create_single_table_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(source, output, vault)
    preflight_result = public.preflight(plan)
    assert preflight_result.ready
    result = public.pseudonymize(plan)

    bundle_path = work_root / "bundle"
    bundle = public.create_transfer_bundle(result, destination=bundle_path, profile="DATA_ONLY")
    assert bundle.verified
    standalone = public.verify_transfer_bundle(bundle_path)
    assert standalone.verified
    assert standalone.manifest_fingerprint == bundle.manifest_fingerprint

    # Observable public outcome only: no vault database or SQLite sidecar is
    # part of the bundle tree. The authoritative security claim is owned by
    # the bundle creation/verification API itself.
    bundle_files = tuple(path for path in bundle_path.rglob("*") if path.is_file())
    assert bundle_files
    assert not tuple(bundle_path.rglob("*.sqlite3*"))

    print("DBF_Anonymizer DATA_ONLY workflow (synthetic data)")
    print(f"bundle verified at creation:  {bundle.verified}")
    print(f"bundle verified standalone:   {standalone.verified}")
    print(f"bundle files: {len(bundle_files)}")
    print(f"manifest fingerprint: {bundle.manifest_fingerprint}")
    print("DATA_ONLY is pseudonymized, NOT anonymous; the vault is never part of it")


if __name__ == "__main__":
    main()
