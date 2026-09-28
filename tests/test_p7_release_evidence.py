"""REQ-P7-008 objective release-evidence tests.

Two complementary evidence layers:

1. The COMMITTED evidence bundle (tests/fixtures/p7_release_evidence/) is the
   version-controlled record of a real release-evidence run.  The fail-closed
   verifier must accept it, its SBOM must be a valid CycloneDX 1.5 inventory
   of the exact pinned runtime closure, regenerating the SBOM from the
   recorded inputs must be byte-identical, and every tampering scenario must
   make the verifier fail closed.

2. LIVE execution on the current revision: two independent, clean,
   task-owned builds of sdist and wheel MUST produce identical final SHA-256
   values; the release metadata must validate; and the EXACT release wheel
   must work from site-packages in a fresh environment outside the repository
   working tree (fresh-wheel smoke reusing the established helpers, with
   network/process sentinels).

No runtime behavior of dbf-anonymizer is exercised here beyond the published
release machinery; P7-004 offline runtime and P7-006 CI isolation tests remain
untouched and authoritative.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tools.build_release_evidence import (
    REPO_ROOT,
    _download_wheelhouse,
    _fresh_wheel_smoke,
    _read_acceptance_version,
    build_once,
)
from tools.check_p7_offline_wheelhouse import _wheel_identity
from tools.generate_release_sbom import build_sbom, render_sbom
from tools.verify_release_evidence import (
    ARCHITECTURE_SHA256,
    VerificationFailure,
    verify_evidence,
)

FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "p7_release_evidence"
MANIFEST_NAME = "release-evidence.manifest.json"
SBOM_NAME = "release-sbom.cdx.json"
VERIFIER = REPO_ROOT / "tools" / "verify_release_evidence.py"
# Fixed deterministic epoch for the live two-build comparison (independent of
# wall-clock); the committed fixture records its own epoch derived from its
# source revision commit time.
LIVE_EPOCH = 1759000000


@pytest.fixture(scope="module")
def fixture_manifest() -> dict[str, object]:
    document = json.loads((FIXTURE_ROOT / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


@pytest.fixture(scope="module")
def live_pipeline(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """Two independent builds + the pinned wheelhouse + the fresh-wheel smoke."""
    task_root = tmp_path_factory.mktemp("p7-008-live-release")
    sdist_1, wheel_1 = build_once(REPO_ROOT, task_root, LIVE_EPOCH, 1)
    sdist_2, wheel_2 = build_once(REPO_ROOT, task_root, LIVE_EPOCH, 2)
    evidence_root = task_root / "evidence"
    (evidence_root / "dist").mkdir(parents=True)
    shutil.copyfile(sdist_1, evidence_root / "dist" / sdist_1.name)
    shutil.copyfile(wheel_1, evidence_root / "dist" / wheel_1.name)
    acceptance_version = _read_acceptance_version(
        REPO_ROOT / "requirements" / "p0-dbfbridge-tested.txt"
    )
    _download_wheelhouse(REPO_ROOT, task_root, evidence_root, wheel_1)
    smoke = _fresh_wheel_smoke(
        REPO_ROOT,
        task_root,
        evidence_root,
        wheel_1,
        acceptance_version,
    )
    return {
        "task_root": task_root,
        "sdist_1": sdist_1,
        "wheel_1": wheel_1,
        "sdist_2": sdist_2,
        "wheel_2": wheel_2,
        "evidence_root": evidence_root,
        "smoke": smoke,
        "acceptance_version": acceptance_version,
    }


def _run_verifier(manifest: Path, evidence_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
            "--manifest",
            str(manifest),
            "--evidence-root",
            str(evidence_root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# Layer 1: the committed evidence bundle
# ---------------------------------------------------------------------------


def test_committed_evidence_bundle_verifies() -> None:
    completed = _run_verifier(FIXTURE_ROOT / MANIFEST_NAME, FIXTURE_ROOT)
    assert completed.returncode == 0, completed.stderr
    verdict = json.loads(completed.stdout.strip().splitlines()[-1])
    assert verdict["result"] == "PASS"


def test_committed_manifest_verifies_in_process() -> None:
    verdict = verify_evidence(FIXTURE_ROOT / MANIFEST_NAME, FIXTURE_ROOT)
    assert verdict["result"] == "PASS"


def test_manifest_schema_and_identity_are_complete(
    fixture_manifest: dict[str, object],
) -> None:
    assert fixture_manifest["schema_version"] == "1.0"
    assert fixture_manifest["kind"] == "dbf-anonymizer-release-evidence-manifest"
    package = fixture_manifest["package"]
    assert isinstance(package, dict)
    assert package["name"] == "dbf-anonymizer"
    assert package["version"] == "1.0.0.dev0"
    source = fixture_manifest["source"]
    assert isinstance(source, dict)
    assert source["architecture_sha256"] == ARCHITECTURE_SHA256
    commit = source["git_commit_sha"]
    assert isinstance(commit, str) and len(commit) == 40
    build_environment = fixture_manifest["build_environment"]
    assert isinstance(build_environment, dict)
    assert isinstance(build_environment["source_date_epoch"], int)
    tool_versions = build_environment["tool_versions"]
    assert isinstance(tool_versions, dict)
    assert {"build", "setuptools", "wheel"} <= set(tool_versions)


def test_manifest_records_reproducible_two_build_result(
    fixture_manifest: dict[str, object],
) -> None:
    repro = fixture_manifest["reproducibility"]
    assert isinstance(repro, dict)
    assert repro["result"] == "PASS"
    assert repro["independent_builds"] == 2
    for artifact in ("sdist", "wheel"):
        first = repro[f"{artifact}_sha256_build_1"]
        second = repro[f"{artifact}_sha256_build_2"]
        assert first == second
    assert isinstance(repro["sdist_canonicalization"], str)
    assert "mtime" in repro["sdist_canonicalization"]


def test_manifest_hashes_match_the_committed_artifacts(
    fixture_manifest: dict[str, object],
) -> None:
    artifacts = fixture_manifest["artifacts"]
    assert isinstance(artifacts, dict)
    for key in ("sdist", "wheel"):
        entry = artifacts[key]
        assert isinstance(entry, dict)
        path = FIXTURE_ROOT / str(entry["filename"])
        assert path.is_file()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == entry["sha256"]
    sbom_entry = fixture_manifest["sbom"]
    assert isinstance(sbom_entry, dict)
    sbom_path = FIXTURE_ROOT / str(sbom_entry["filename"])
    digest = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
    assert digest == sbom_entry["sha256"]


def test_sbom_is_a_valid_cyclonedx_inventory(
    fixture_manifest: dict[str, object],
) -> None:
    document = json.loads((FIXTURE_ROOT / SBOM_NAME).read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["serialNumber"].startswith("urn:uuid:")
    metadata = document["metadata"]
    assert metadata["component"]["name"] == "dbf-anonymizer"
    assert metadata["component"]["version"] == "1.0.0.dev0"
    provenance = fixture_manifest["dependency_provenance"]
    assert isinstance(provenance, dict)
    closure = {entry["name"]: entry["version"] for entry in provenance["wheelhouse_artifacts"]}
    components = document["components"]
    inventory = {component["name"]: component["version"] for component in components}
    assert inventory == closure
    for component in components:
        hashes = component["hashes"]
        assert any(item["alg"] == "SHA-256" for item in hashes)
        assert component["scope"] == "required"
    dependencies = document["dependencies"]
    application_ref = metadata["component"]["bom-ref"]
    app_entry = [item for item in dependencies if item["ref"] == application_ref]
    assert app_entry, dependencies
    assert sorted(app_entry[0]["dependsOn"]) == sorted(
        component["bom-ref"] for component in components
    )


def test_sbom_regeneration_is_byte_identical(
    fixture_manifest: dict[str, object],
) -> None:
    source = fixture_manifest["source"]
    assert isinstance(source, dict)
    build_environment = fixture_manifest["build_environment"]
    assert isinstance(build_environment, dict)
    sbom_entry = fixture_manifest["sbom"]
    assert isinstance(sbom_entry, dict)
    wheelhouse_dir = FIXTURE_ROOT / "wheelhouse"
    application_wheel = [
        path.name
        for path in wheelhouse_dir.glob("*.whl")
        if path.name.startswith("dbf_anonymizer-")
    ]
    assert len(application_wheel) == 1
    document = build_sbom(
        application_name="dbf-anonymizer",
        application_version="1.0.0.dev0",
        git_commit_sha=str(source["git_commit_sha"]),
        source_date_epoch=int(build_environment["source_date_epoch"]),
        wheelhouse_manifest=REPO_ROOT / "requirements" / "p7-offline-wheelhouse.txt",
        wheelhouse_dir=wheelhouse_dir,
        architecture_sha256=ARCHITECTURE_SHA256,
        exclude_filenames=frozenset(application_wheel),
    )
    regenerated = render_sbom(document)
    committed = (FIXTURE_ROOT / SBOM_NAME).read_bytes()
    assert regenerated == committed


def test_dependency_provenance_is_complete(
    fixture_manifest: dict[str, object],
) -> None:
    provenance = fixture_manifest["dependency_provenance"]
    assert isinstance(provenance, dict)
    assert str(provenance["runtime_requirement"]).replace(" ", "") in {
        "dbfbridge[write]>=1.1.0,<2",
        "dbfbridge[write]<2,>=1.1.0",
    }
    pin_lines = [
        line.strip()
        for line in (REPO_ROOT / "requirements" / "p0-dbfbridge-tested.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    pinned_version = pin_lines[0].split("==", 1)[1]
    acceptance = provenance["acceptance_artifact"]
    assert isinstance(acceptance, dict)
    assert acceptance == {"name": "dbfbridge[write]", "version": pinned_version}
    entries = provenance["wheelhouse_artifacts"]
    closure_names = {entry["name"] for entry in entries}
    assert closure_names == {"dbfbridge", "dbfread", "dbf", "aenum"}
    for entry in entries:
        assert entry["filename"].startswith("wheelhouse/")
        path = FIXTURE_ROOT / str(entry["filename"])
        assert path.is_file()
        name, version = _wheel_identity(path)
        assert name == entry["name"] and version == entry["version"]
    assert provenance["resolved_runtime_closure"] == [
        {"name": entry["name"], "version": entry["version"]} for entry in entries
    ]


def test_no_private_paths_or_sensitive_material_in_evidence() -> None:
    from tools.verify_release_evidence import _scan_forbidden_content

    _scan_forbidden_content(FIXTURE_ROOT)  # must not raise


# ---------------------------------------------------------------------------
# Tamper detection (fail-closed verifier)
# ---------------------------------------------------------------------------


def _tampered_copy(
    tmp_path: Path,
    manifest_patch: dict[str, object] | None,
    tamper_file: str | None,
) -> tuple[Path, Path]:
    case_dir = tmp_path / "evidence-copy"
    shutil.copytree(FIXTURE_ROOT, case_dir)
    manifest_path = case_dir / MANIFEST_NAME
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    # Make the copy a fully valid manifest so the tampering itself is what
    # the verifier must detect.
    document["tamper_detection_selftest"] = {
        "result": "PASS",
        "cases": ["artifact", "sbom", "manifest_hash", "private_path"],
    }
    if manifest_patch is not None:
        for pointer, value in manifest_patch.items():
            section, key = pointer.split(".", 1)
            target = document[section]
            assert isinstance(target, dict)
            target[key] = value
    manifest_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if tamper_file is not None:
        path = case_dir / tamper_file
        payload = bytearray(path.read_bytes())
        payload[-1] ^= 0x01
        path.write_bytes(bytes(payload))
    return manifest_path, case_dir


def _expect_verification_failure(manifest: Path, evidence_root: Path) -> str:
    with pytest.raises(VerificationFailure):
        verify_evidence(manifest, evidence_root)
    completed = _run_verifier(manifest, evidence_root)
    assert completed.returncode != 0
    return completed.stderr


def test_tampered_artifact_fails_verification(tmp_path: Path) -> None:
    manifest, evidence_root = _tampered_copy(
        tmp_path, None, "dist/dbf_anonymizer-1.0.0.dev0-py3-none-any.whl"
    )
    stderr = _expect_verification_failure(manifest, evidence_root)
    assert "mismatch" in stderr


def test_tampered_sbom_fails_verification(tmp_path: Path) -> None:
    manifest, case_dir = _tampered_copy(tmp_path, None, SBOM_NAME)
    stderr = _expect_verification_failure(manifest, case_dir)
    assert "mismatch" in stderr or "SHA-256" in stderr


def test_tampered_manifest_hash_fails_verification(tmp_path: Path) -> None:
    manifest, case_dir = _tampered_copy(tmp_path, {"artifacts.sdist.sha256": "0" * 64}, None)
    stderr = _expect_verification_failure(manifest, case_dir)
    assert "mismatch" in stderr


def test_injected_private_path_fails_verification(tmp_path: Path) -> None:
    manifest, case_dir = _tampered_copy(
        tmp_path,
        {"workflow_identity.run_id": r"C:\Users\attacker\private\run-12345"},
        None,
    )
    stderr = _expect_verification_failure(manifest, case_dir)
    assert "forbidden content" in stderr


def test_missing_artifact_fails_verification(tmp_path: Path) -> None:
    manifest, case_dir = _tampered_copy(tmp_path, None, None)
    (case_dir / "dist" / "dbf_anonymizer-1.0.0.dev0.tar.gz").unlink()
    with pytest.raises(VerificationFailure):
        verify_evidence(manifest, case_dir)
    shutil.rmtree(case_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Layer 2: live execution on the current revision
# ---------------------------------------------------------------------------


def test_two_independent_builds_produce_identical_hashes(
    live_pipeline: dict[str, object],
) -> None:
    sdist_1 = live_pipeline["sdist_1"]
    sdist_2 = live_pipeline["sdist_2"]
    wheel_1 = live_pipeline["wheel_1"]
    wheel_2 = live_pipeline["wheel_2"]
    assert isinstance(sdist_1, Path) and isinstance(sdist_2, Path)
    assert isinstance(wheel_1, Path) and isinstance(wheel_2, Path)
    sdist_hash_1 = hashlib.sha256(sdist_1.read_bytes()).hexdigest()
    sdist_hash_2 = hashlib.sha256(sdist_2.read_bytes()).hexdigest()
    wheel_hash_1 = hashlib.sha256(wheel_1.read_bytes()).hexdigest()
    wheel_hash_2 = hashlib.sha256(wheel_2.read_bytes()).hexdigest()
    assert sdist_hash_1 == sdist_hash_2
    assert wheel_hash_1 == wheel_hash_2


def test_live_release_artifacts_metadata_is_valid(
    live_pipeline: dict[str, object],
) -> None:
    from tools.check_wheel_metadata import check_wheel
    from tools.generate_release_sbom import _sdist_identity

    wheel_1 = live_pipeline["wheel_1"]
    sdist_1 = live_pipeline["sdist_1"]
    assert isinstance(wheel_1, Path) and isinstance(sdist_1, Path)
    check_wheel(wheel_1)  # must not raise
    name, version = _sdist_identity(sdist_1)
    assert (name, version) == ("dbf-anonymizer", "1.0.0.dev0")
    wheel_name, wheel_version = _wheel_identity(wheel_1)
    assert (wheel_name, wheel_version) == ("dbf-anonymizer", "1.0.0.dev0")


def test_live_release_wheel_works_from_site_packages(
    live_pipeline: dict[str, object],
) -> None:
    smoke = live_pipeline["smoke"]
    assert isinstance(smoke, dict)
    assert smoke["result"] == "PASS"
    assert smoke["import_origin"] == "site-packages"
    assert smoke["source_tree_import"] == "BLOCKED"
    assert smoke["network_attempts"] == 0
    assert smoke["process_attempts"] == 0
    assert smoke["pip_check"] == "PASS"
    assert smoke["cli_complete_workflow"] == "PASS"
    assert smoke["installed_dbfbridge_version"] == live_pipeline["acceptance_version"]


def test_live_release_wheel_dependency_metadata_matches_the_installed_environment(
    live_pipeline: dict[str, object],
) -> None:
    """The exact release wheel declares the unchanged runtime requirement and
    the smoke environment resolved exactly the pinned acceptance artifact."""
    wheel_1 = live_pipeline["wheel_1"]
    assert isinstance(wheel_1, Path)
    with zipfile.ZipFile(wheel_1) as archive:
        metadata_name = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        assert len(metadata_name) == 1
        metadata = archive.read(metadata_name[0]).decode("utf-8")
    requirements = [
        line.split(": ", 1)[1].strip()
        for line in metadata.splitlines()
        if line.startswith("Requires-Dist: ")
    ]
    dbfbridge = [
        item.split(";")[0].strip().replace(" ", "")
        for item in requirements
        if item.split(";")[0].strip().replace(" ", "").startswith("dbfbridge")
    ]
    assert dbfbridge in (
        ["dbfbridge[write]>=1.1.0,<2"],
        ["dbfbridge[write]<2,>=1.1.0"],
    )
    assert not [item for item in requirements if "@" in item]
