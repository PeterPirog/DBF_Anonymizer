"""REQ-P8-002 canonical release-acceptance round trip from the installed wheel.

Runs the complete canonical public consumer workflow inside a clean consumer
environment (the fresh-wheel virtual environment prepared by the release
acceptance orchestrator), under the accepted REQ-P7-004 network/process
sentinels:

    capabilities -> build_plan (declared PK/FK document) -> preflight ->
    pseudonymize -> verify_dataset -> source-immutability check ->
    create_transfer_bundle (DATA_ONLY) -> standalone verify_transfer_bundle
    (source absent) -> recover -> logical-oracle comparison ->
    DATA_ONLY bundle content scan (allowlist + forbidden artifacts + canaries)

The synthetic multi-table dataset and the canonical logical oracle are REUSED
from the accepted public consumer workflow acceptance (REQ-P1-004):
``tests.test_public_workflow_acceptance``.  Data is synthetic only; canary
values never leave this work root and never enter the printed facts.

The tool prints exactly one sanitized JSON facts object (no absolute paths,
no source values, no pseudonyms, no recovery material) and exits non-zero on
any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import dbf_anonymizer as public  # noqa: E402  (the installed release wheel)
from dbf_anonymizer.transfer_bundle import TRANSFER_MANIFEST_FILENAME  # noqa: E402
from tools.check_p7_offline_runtime import _runtime_sentinels  # noqa: E402
from tests.test_public_workflow_acceptance import (  # noqa: E402
    _relationship_document,
    _table_records,
    _write_dataset,
)

#: Synthetic seed values written by the accepted fixture.  They are
#: evidence-side controls only: they must be absent from the transferable
#: bundle and present again in the recovered dataset.
TEXT_CANARIES = ("PARENT-1", "PARENT-2", "MEMO-N-1", "MEMO-S-1", "TRAILING")
BINARY_CANARIES = (b"\x89SYNTHETIC-BINARY-\x00\x01", b"PICTURE-BYTES-\x02")

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


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _scan_bytes(bundle: Path) -> tuple[bool, bool, list[str], bool]:
    """Bundle content scan: allowlist, forbidden names, file names, canary absence."""
    files = [
        path.relative_to(bundle).as_posix() for path in sorted(bundle.rglob("*")) if path.is_file()
    ]
    allowlist_ok = all(
        name == TRANSFER_MANIFEST_FILENAME or PurePosixPath(name).suffix in BUNDLE_ALLOWED_SUFFIXES
        for name in files
    )
    forbidden_absent = not any(
        fragment in name.lower() for name in files for fragment in FORBIDDEN_NAME_FRAGMENTS
    ) and not any(PurePosixPath(name).suffix in FORBIDDEN_BUNDLE_SUFFIXES for name in files)
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


def run_round_trip(work_root: Path) -> dict[str, object]:
    """Execute the canonical round trip and return sanitized facts."""
    work_root.mkdir(parents=True, exist_ok=True)
    attempts: list[str] = []
    facts: dict[str, object] = {}

    capabilities = public.capabilities()
    facts["capabilities_recovery"] = capabilities.recovery
    facts["capabilities_transfer_bundle"] = capabilities.transfer_bundle
    facts["capabilities_vfp_index_backend"] = capabilities.vfp_index_backend

    with _runtime_sentinels(attempts):
        source = work_root / "source"
        output = work_root / "output"
        vault = work_root / "vault" / "dictionary.sqlite3"
        _write_dataset(source)
        facts["tables_written"] = 3
        original_hashes = _file_hashes(source)
        oracle = work_root / "oracle"
        shutil.copytree(source, oracle)

        plan = public.build_plan(
            source, output, vault, relationship_document=_relationship_document()
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
            if _table_records(oracle, relative) != _table_records(recovered_root, relative):
                _fail(f"logical oracle mismatch: {relative}")
            compared += 1
        facts["oracle_tables_compared"] = compared

        allowlist_ok, forbidden_absent, bundle_files, canaries_absent = _scan_bytes(
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
    args = parser.parse_args()
    try:
        facts = run_round_trip(args.work_root)
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
