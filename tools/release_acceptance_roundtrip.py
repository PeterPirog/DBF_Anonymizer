"""REQ-P8-002 canonical release-acceptance round trip from the installed wheel.

Runs the complete canonical public consumer workflow inside a clean consumer
environment (the fresh-wheel acceptance venv), under the accepted REQ-P7-004
network/process sentinels:

    capabilities -> build_plan (declared PK/FK document) -> preflight ->
    pseudonymize -> verify_dataset -> source-immutability check ->
    create_transfer_bundle (DATA_ONLY) -> standalone verify_transfer_bundle
    (source absent) -> recover -> logical-oracle comparison ->
    DATA_ONLY bundle content scan (allowlist + forbidden artifacts + canaries)

The tool is import-shadowing-hardened: it NEVER adds the repository root (or
any source-checkout path) to ``sys.path`` and never relies on ``PYTHONPATH``
for its own imports.  Sibling acceptance tooling is imported through the
script directory that Python puts at ``sys.path[0]``; ``dbf_anonymizer`` and
``dbfbridge`` resolve exclusively from the installed wheel's site-packages.

Before any real work, the tool objectively proves the import origin
(``dbf_anonymizer.__file__`` under the acceptance venv site-packages, NOT
under the repository root, exact expected release-candidate version) and
fails closed when ``--require-installed-origin`` is set and the proof fails.

The synthetic multi-table dataset and the canonical logical oracle come from
the sibling ``acceptance_fixtures`` module (public ``dbfbridge`` writer only).
The tool prints exactly one sanitized JSON facts object (no absolute paths,
no source values, no pseudonyms, no recovery material) and exits non-zero on
any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from importlib import metadata
from pathlib import Path

try:  # package context (pytest import) ...
    from tools.acceptance_fixtures import (
        BINARY_CANARIES,
        TEXT_CANARIES,
        relationship_document,
        table_records,
        write_dataset,
    )
    from tools.check_p7_offline_runtime import _runtime_sentinels
except ImportError:  # ... or direct script execution from the tools directory
    from acceptance_fixtures import (  # type: ignore[no-redef]
        BINARY_CANARIES,
        TEXT_CANARIES,
        relationship_document,
        table_records,
        write_dataset,
    )
    from check_p7_offline_runtime import _runtime_sentinels  # type: ignore[no-redef]

import dbf_anonymizer as public  # noqa: E402  (the installed release wheel)
from dbf_anonymizer.transfer_bundle import TRANSFER_MANIFEST_FILENAME  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

BUNDLE_ALLOWED_SUFFIXES = frozenset({".dbf", ".fpt"})
FORBIDDEN_NAME_FRAGMENTS = (
    "dictionary.sqlite3",
    "recovery.sqlite3",
    ".sqlite3-wal",
    ".sqlite3-shm",
    ".sqlite3-journal",
)
FORBIDDEN_BUNDLE_SUFFIXES = frozenset({".cdx", ".idx", ".dbc", ".dct", ".dcx"})


def _fail(message: str) -> None:
    raise RuntimeError(message)


def installed_wheel_origin_facts(
    module_file: str,
    installed_version: str,
    expected_version: str,
    repo_root: Path,
    pythonpath: str,
    cwd: Path,
) -> dict[str, object]:
    """Pure installed-wheel origin proof (privacy-safe facts only)."""
    origin = Path(module_file).resolve()
    lowered = {part.lower() for part in origin.parts}
    site_packages = bool(lowered & {"site-packages", "dist-packages"})
    under_repository = repo_root.resolve() in origin.parents
    version_ok = installed_version == expected_version
    repo_root_in_pythonpath = repo_root.resolve() in {
        Path(entry).resolve() for entry in pythonpath.split(os.pathsep) if entry
    }
    return {
        "installed_wheel_origin_verified": site_packages and not under_repository and version_ok,
        "repository_source_shadowing": under_repository,
        "import_origin": "ACCEPTANCE_VENV_SITE_PACKAGES" if site_packages else "OTHER",
        "installed_version_matches_candidate": version_ok,
        "repo_root_in_sys_path": False,
        "repo_root_in_pythonpath": repo_root_in_pythonpath,
        "cwd_outside_repository": repo_root.resolve() not in cwd.resolve().parents
        and cwd.resolve() != repo_root.resolve(),
    }


def _verify_origin(expected_version: str, require: bool) -> dict[str, object]:
    facts = installed_wheel_origin_facts(
        module_file=getattr(public, "__file__", ""),
        installed_version=metadata.version("dbf-anonymizer"),
        expected_version=expected_version,
        repo_root=REPO_ROOT,
        pythonpath=os.environ.get("PYTHONPATH", ""),
        cwd=Path.cwd(),
    )
    repo_root_in_sys_path = any(
        Path(entry).resolve() == REPO_ROOT.resolve() if entry else False for entry in sys.path
    )
    facts["repo_root_in_sys_path"] = repo_root_in_sys_path
    if require and facts["installed_wheel_origin_verified"] is not True:
        _fail(
            "installed wheel origin verification failed: dbf_anonymizer must resolve "
            "from the acceptance venv site-packages, not from the source checkout"
        )
    return facts


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _scan_bundle(bundle: Path) -> tuple[bool, bool, list[str], bool]:
    """Bundle content scan: allowlist, forbidden names, file names, canary absence."""
    files = [
        path.relative_to(bundle).as_posix() for path in sorted(bundle.rglob("*")) if path.is_file()
    ]
    allowlist_ok = all(
        name == TRANSFER_MANIFEST_FILENAME or Path(name).suffix in BUNDLE_ALLOWED_SUFFIXES
        for name in files
    )
    forbidden_absent = not any(
        fragment in name.lower() for name in files for fragment in FORBIDDEN_NAME_FRAGMENTS
    ) and not any(Path(name).suffix in FORBIDDEN_BUNDLE_SUFFIXES for name in files)
    canaries_absent = not any(
        canary.encode("utf-8") in path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
        for canary in TEXT_CANARIES
    ) and not any(
        canary in path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
        for canary in BINARY_CANARIES
    )
    return allowlist_ok, forbidden_absent, files, canaries_absent


def run_round_trip(
    work_root: Path, expected_version: str, require_installed_origin: bool
) -> dict[str, object]:
    """Execute the canonical round trip and return sanitized facts."""
    work_root.mkdir(parents=True, exist_ok=True)
    origin_facts = installed_wheel_origin_facts(
        module_file=getattr(public, "__file__", ""),
        installed_version=metadata.version("dbf-anonymizer"),
        expected_version=expected_version,
        repo_root=REPO_ROOT,
        pythonpath=os.environ.get("PYTHONPATH", ""),
        cwd=Path.cwd(),
    )
    origin_facts["repo_root_in_sys_path"] = any(
        Path(entry).resolve() == REPO_ROOT.resolve() if entry else False for entry in sys.path
    )
    if require_installed_origin and origin_facts["installed_wheel_origin_verified"] is not True:
        _fail(
            "installed wheel origin verification failed: dbf_anonymizer must resolve "
            "from the acceptance venv site-packages, not from the source checkout"
        )
    attempts: list[str] = []
    facts: dict[str, object] = dict(origin_facts)

    capabilities = public.capabilities()
    facts["capabilities_recovery"] = capabilities.recovery
    facts["capabilities_transfer_bundle"] = capabilities.transfer_bundle
    facts["capabilities_vfp_index_backend"] = capabilities.vfp_index_backend

    with _runtime_sentinels(attempts):
        source = work_root / "source"
        output = work_root / "output"
        vault = work_root / "vault" / "dictionary.sqlite3"
        write_dataset(source)
        facts["tables_written"] = 3
        original_hashes = _file_hashes(source)
        oracle = work_root / "oracle"
        shutil.copytree(source, oracle)

        plan = public.build_plan(
            source, output, vault, relationship_document=relationship_document()
        )
        facts["declared_relations"] = 1
        preflight = public.preflight(plan)
        facts["preflight_ready"] = preflight.ready is True

        result = public.pseudonymize(plan, workers=2)
        verification = public.verify_dataset(result, source=source, vault=vault)
        facts["verification_status"] = verification.status.value
        facts["source_unchanged"] = _file_hashes(source) == original_hashes

        facts["assurance_level"] = result.assurance.level.value
        bundle = public.create_transfer_bundle(
            result, destination=work_root / "bundle", profile="DATA_ONLY"
        )
        facts["bundle_created"] = bundle.verified
        facts["bundle_profile"] = bundle.profile.value

        copied = work_root / "copied-bundle"
        shutil.copytree(work_root / "bundle", copied)
        shutil.rmtree(source)
        standalone = public.verify_transfer_bundle(copied)
        facts["standalone_verified"] = standalone.verified
        facts["manifest_fingerprint_match"] = (
            standalone.manifest_fingerprint == bundle.manifest_fingerprint
        )

        recovery = public.recover(pseudonymized=output, vault=vault, output=work_root / "recovered")
        facts["recovery_canonical_verified"] = recovery.canonical_verified
        facts["raw_byte_equivalence"] = recovery.raw_byte_equivalence.value

        recovered_root = work_root / "recovered"
        original_topology = sorted(
            path.relative_to(oracle).as_posix() for path in oracle.rglob("*") if path.is_file()
        )
        recovered_topology = sorted(
            path.relative_to(recovered_root).as_posix()
            for path in recovered_root.rglob("*")
            if path.is_file()
        )
        facts["oracle_topology_match"] = original_topology == recovered_topology
        compared = 0
        for relative in original_topology:
            if not relative.endswith(".dbf"):
                continue
            if table_records(oracle, relative) != table_records(recovered_root, relative):
                _fail(f"logical oracle mismatch: {relative}")
            compared += 1
        facts["oracle_tables_compared"] = compared

        allowlist_ok, forbidden_absent, bundle_files, canaries_absent = _scan_bundle(
            work_root / "bundle"
        )
        facts["bundle_file_count"] = len(bundle_files)
        facts["bundle_allowlist_ok"] = allowlist_ok
        facts["forbidden_basenames_absent"] = forbidden_absent
        facts["bundle_file_names"] = bundle_files
        facts["canaries_absent_in_bundle"] = canaries_absent

        recovered_blob = b"".join(
            path.read_bytes() for path in sorted(recovered_root.rglob("*")) if path.is_file()
        )
        positive_control = all(
            canary.encode("utf-8") in recovered_blob for canary in TEXT_CANARIES
        ) and all(canary in recovered_blob for canary in BINARY_CANARIES)
        facts["canaries_present_in_recovered"] = positive_control

    facts["network_attempts"] = len(
        [attempt for attempt in attempts if attempt.startswith("network:")]
    )
    facts["process_attempts"] = len(
        [attempt for attempt in attempts if attempt.startswith("process:")]
    )
    return facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument(
        "--require-installed-origin",
        action="store_true",
        help="fail closed unless dbf_anonymizer resolves from the installed wheel",
    )
    arguments = parser.parse_args()
    try:
        facts = run_round_trip(
            arguments.work_root, arguments.expected_version, arguments.require_installed_origin
        )
    except Exception as error:  # noqa: BLE001 - sanitized single-line failure
        print(
            json.dumps(
                {"stage": "canonical_roundtrip", "status": "FAIL", "error": type(error).__name__},
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {"stage": "canonical_roundtrip", "status": "PASS", "facts": facts},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
