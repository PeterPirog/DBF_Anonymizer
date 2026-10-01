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
    MANIFEST_DIGEST_SIDECAR,
    _assert_clean_source_tree,
    _download_wheelhouse,
    _export_commit_source,
    _fresh_wheel_smoke,
    _read_acceptance_version,
    build_once,
)
from tools.check_p7_offline_wheelhouse import _wheel_identity
from tools.generate_release_sbom import build_sbom, render_sbom
from tools.verify_release_evidence import (
    CURRENT_ARCHITECTURE_SHA256,
    HISTORICAL_ARCHITECTURE_SHA256,
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
    """Two independent builds + the pinned wheelhouse + the fresh-wheel smoke.

    The builds run from the EXACT commit export (clean tree guard + git
    archive), never from the mutable working tree.
    """
    task_root = tmp_path_factory.mktemp("p7-008-live-release")
    assert _assert_clean_source_tree(REPO_ROOT) == "PASS"
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    source_root = _export_commit_source(REPO_ROOT, commit, task_root / "source-export")
    sdist_1, wheel_1 = build_once(source_root, task_root, LIVE_EPOCH, 1)
    sdist_2, wheel_2 = build_once(source_root, task_root, LIVE_EPOCH, 2)
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


def _run_verifier(
    manifest: Path, evidence_root: Path, *, historical: bool = False
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(VERIFIER),
        "--manifest",
        str(manifest),
        "--evidence-root",
        str(evidence_root),
    ]
    if historical:
        command.append("--historical")
    return subprocess.run(command, capture_output=True, text=True, check=False)


# ---------------------------------------------------------------------------
# Layer 1: the committed evidence bundle (an explicitly HISTORICAL record)
# ---------------------------------------------------------------------------


def test_committed_evidence_bundle_verifies() -> None:
    """The committed bundle is a REAL historical run: it verifies ONLY through
    the explicit non-default historical mode."""
    completed = _run_verifier(FIXTURE_ROOT / MANIFEST_NAME, FIXTURE_ROOT, historical=True)
    assert completed.returncode == 0, completed.stderr
    verdict = json.loads(completed.stdout.strip().splitlines()[-1])
    assert verdict["result"] == "PASS"
    assert verdict["architecture_mode"] == "HISTORICAL"


def test_committed_manifest_verifies_in_process() -> None:
    verdict = verify_evidence(FIXTURE_ROOT / MANIFEST_NAME, FIXTURE_ROOT, historical=True)
    assert verdict["result"] == "PASS"
    assert verdict["architecture_mode"] == "HISTORICAL"


def test_committed_historical_bundle_rejected_by_current_verification(
    tmp_path: Path,
) -> None:
    """The CURRENT verification mode must fail closed on the stale digest.

    The committed historical bundle records the obsolete 2026-09-10
    architecture identity; the default CURRENT mode exists for fresh bundles
    only and must never accept that stale identity (no historical bytes are
    modified for this proof).
    """
    historical_copy = tmp_path / "historical-copy"
    shutil.copytree(FIXTURE_ROOT, historical_copy)
    with pytest.raises(VerificationFailure) as expected:
        verify_evidence(historical_copy / MANIFEST_NAME, historical_copy)
    assert "architecture" in str(expected.value)
    completed = _run_verifier(historical_copy / MANIFEST_NAME, historical_copy)
    assert completed.returncode != 0
    shutil.rmtree(historical_copy, ignore_errors=True)


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
    # The committed bundle is an explicitly HISTORICAL evidence record: it was
    # produced by a real run under the former 2026-09-10 architecture and its
    # recorded digest is the HISTORICAL one (never the current identity).
    assert source["architecture_sha256"] == HISTORICAL_ARCHITECTURE_SHA256
    commit = source["git_commit_sha"]
    assert isinstance(commit, str) and len(commit) == 40
    # Exact-source provenance: cleanliness + commit-object export protocol.
    assert source["cleanliness_check"] == "PASS"
    export_mode = source["source_export_mode"]
    assert isinstance(export_mode, str) and "git archive" in export_mode
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
        architecture_sha256=HISTORICAL_ARCHITECTURE_SHA256,
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
    """Copy the fixture and apply the given tampering.

    The copy's sidecar is re-signed to the copy's own (tampered) manifest
    digest: a mutable sidecar is exactly what a real attacker can rewrite, so
    internal-consistency tampering must be detected by the verifier's internal
    checks, while ONLY the trusted external digest detects coherent
    substitution (see the coherent-substitution test).
    """
    case_dir = tmp_path / "evidence-copy"
    shutil.copytree(FIXTURE_ROOT, case_dir)
    manifest_path = case_dir / MANIFEST_NAME
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    # Make the copy a fully valid manifest so the tampering itself is what
    # the verifier must detect.
    document["tamper_detection_selftest"] = {
        "result": "PASS",
        "cases": ["artifact", "sbom", "manifest_hash", "private_path", "coherent_substitution"],
    }
    if manifest_patch is not None:
        for pointer, value in manifest_patch.items():
            parts = pointer.split(".")
            target: object = document
            for part in parts[:-1]:
                assert isinstance(target, dict), pointer
                target = target[part]
            assert isinstance(target, dict), pointer
            target[parts[-1]] = value
    manifest_path.write_bytes(
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    if tamper_file is not None:
        path = case_dir / tamper_file
        payload = bytearray(path.read_bytes())
        payload[-1] ^= 0x01
        path.write_bytes(bytes(payload))
    # Re-sign the mutable sidecar to the copy's own (tampered) manifest digest:
    # a sidecar is not trusted by itself, so internal tampering must still be
    # caught by the verifier's internal checks (the trusted external digest is
    # what catches coherent substitution).
    copy_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (case_dir / MANIFEST_DIGEST_SIDECAR).write_text(
        f"{copy_digest}  {MANIFEST_NAME}\n", encoding="utf-8"
    )
    return manifest_path, case_dir


def _fixture_trusted_digest() -> str:
    sidecar = (FIXTURE_ROOT / MANIFEST_DIGEST_SIDECAR).read_text(encoding="utf-8")
    digest = sidecar.strip().split()[0]
    assert len(digest) == 64
    return digest


def _expect_verification_failure(manifest: Path, evidence_root: Path) -> str:
    with pytest.raises(VerificationFailure):
        verify_evidence(manifest, evidence_root, historical=True)
    completed = _run_verifier(manifest, evidence_root, historical=True)
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
        verify_evidence(manifest, case_dir, historical=True)
    shutil.rmtree(case_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Manifest integrity binding (trusted digest layer)
# ---------------------------------------------------------------------------


def test_manifest_digest_sidecar_binds_the_exact_manifest_bytes() -> None:
    sidecar = (FIXTURE_ROOT / MANIFEST_DIGEST_SIDECAR).read_text(encoding="utf-8")
    parts = sidecar.strip().split()
    assert len(parts) == 2
    digest, filename = parts
    assert filename == MANIFEST_NAME
    manifest_bytes = (FIXTURE_ROOT / MANIFEST_NAME).read_bytes()
    assert hashlib.sha256(manifest_bytes).hexdigest() == digest


def test_correct_manifest_with_correct_expected_digest_passes() -> None:
    verdict = verify_evidence(
        FIXTURE_ROOT / MANIFEST_NAME,
        FIXTURE_ROOT,
        expected_manifest_sha256=_fixture_trusted_digest(),
        historical=True,
    )
    assert verdict["result"] == "PASS"


def test_wrong_expected_manifest_digest_fails(tmp_path: Path) -> None:
    manifest, case_dir = _tampered_copy(tmp_path, None, None)
    wrong = "0" * 64  # valid 64-hex, but not this manifest's digest
    with pytest.raises(VerificationFailure) as expected:
        verify_evidence(manifest, case_dir, expected_manifest_sha256=wrong, historical=True)
    assert "trusted expected" in str(expected.value)
    completed = _run_verifier_with_expected(manifest, case_dir, wrong)
    assert completed.returncode != 0
    shutil.rmtree(tmp_path / "evidence-copy", ignore_errors=True)


def test_malformed_expected_manifest_digest_fails(tmp_path: Path) -> None:
    manifest, case_dir = _tampered_copy(tmp_path, None, None)
    with pytest.raises(VerificationFailure) as expected:
        verify_evidence(
            manifest, case_dir, expected_manifest_sha256="not-a-digest", historical=True
        )
    assert "malformed" in str(expected.value)
    shutil.rmtree(tmp_path / "evidence-copy", ignore_errors=True)


def test_missing_manifest_digest_source_fails(tmp_path: Path) -> None:
    case_dir = tmp_path / "no-sidecar"
    shutil.copytree(FIXTURE_ROOT, case_dir)
    (case_dir / MANIFEST_DIGEST_SIDECAR).unlink()
    with pytest.raises(VerificationFailure) as expected:
        verify_evidence(case_dir / MANIFEST_NAME, case_dir, historical=True)
    assert "missing manifest integrity binding" in str(expected.value)
    shutil.rmtree(case_dir, ignore_errors=True)


def test_tampered_manifest_digest_sidecar_fails(tmp_path: Path) -> None:
    case_dir = tmp_path / "sidecar-tamper"
    shutil.copytree(FIXTURE_ROOT, case_dir)
    sidecar = case_dir / MANIFEST_DIGEST_SIDECAR
    original = sidecar.read_text(encoding="utf-8")
    digest, filename = original.strip().split()
    flipped = ("0" if digest[0] != "0" else "1") + digest[1:]
    sidecar.write_text(f"{flipped}  {filename}\n", encoding="utf-8")
    with pytest.raises(VerificationFailure) as expected:
        verify_evidence(case_dir / MANIFEST_NAME, case_dir, historical=True)
    assert "sidecar" in str(expected.value)
    shutil.rmtree(case_dir, ignore_errors=True)


def test_coherent_artifact_manifest_substitution_rejected_against_trusted_digest(
    tmp_path: Path,
) -> None:
    """A coherent malicious modification (artifact + manifest + re-signed
    sidecar) is internally self-consistent, so the plain verifier accepts it —
    proving that internal checks alone cannot authenticate evidence.  Against
    the TRUSTED original manifest digest (the value the privileged CI
    attestation would cover) the same bundle is rejected."""
    manifest, case_dir = _tampered_copy(
        tmp_path,
        None,
        "dist/dbf_anonymizer-1.0.0.dev0-py3-none-any.whl",
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    # The attacker recomputes every manifest reference to the substituted wheel
    # and re-signs the sidecar (already re-signed by the helper).
    wheel_path = case_dir / str(document["artifacts"]["wheel"]["filename"])
    substituted = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    document["artifacts"]["wheel"]["sha256"] = substituted
    repro = document["reproducibility"]
    assert isinstance(repro, dict)
    repro["wheel_sha256_build_1"] = substituted
    repro["wheel_sha256_build_2"] = substituted
    manifest.write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    copy_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    (case_dir / MANIFEST_DIGEST_SIDECAR).write_text(
        f"{copy_digest}  {MANIFEST_NAME}\n", encoding="utf-8"
    )

    # Internally self-consistent: the plain (sidecar-mode) HISTORICAL verifier
    # accepts.
    assert verify_evidence(manifest, case_dir, historical=True)["result"] == "PASS"

    # Against the TRUSTED original digest: rejected fail-closed.
    trusted = _fixture_trusted_digest()
    with pytest.raises(VerificationFailure) as expected:
        verify_evidence(manifest, case_dir, expected_manifest_sha256=trusted, historical=True)
    assert "trusted expected" in str(expected.value)
    completed = _run_verifier_with_expected(manifest, case_dir, trusted)
    assert completed.returncode != 0
    shutil.rmtree(case_dir, ignore_errors=True)


def _run_verifier_with_expected(
    manifest: Path, evidence_root: Path, expected: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
            "--manifest",
            str(manifest),
            "--evidence-root",
            str(evidence_root),
            "--expected-manifest-sha256",
            expected,
            "--historical",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_verifier_accepts_bundle_without_expected_digest_via_sidecar() -> None:
    completed = _run_verifier(FIXTURE_ROOT / MANIFEST_NAME, FIXTURE_ROOT, historical=True)
    assert completed.returncode == 0, completed.stderr
    verdict = json.loads(completed.stdout.strip().splitlines()[-1])
    assert verdict["result"] == "PASS"
    assert verdict["manifest_digest_source"] == MANIFEST_DIGEST_SIDECAR


def test_verifier_rejects_bundle_when_sidecar_and_expected_disagree(tmp_path: Path) -> None:
    case_dir = tmp_path / "disagree"
    shutil.copytree(FIXTURE_ROOT, case_dir)
    # The sidecar stays consistent with the manifest, but the caller supplies a
    # DIFFERENT trusted digest: the trusted expectation wins and must reject.
    manifest_digest = hashlib.sha256((case_dir / MANIFEST_NAME).read_bytes()).hexdigest()
    assert manifest_digest == _fixture_trusted_digest()
    first_char = manifest_digest[0]
    different = ("f" if first_char != "f" else "0") + manifest_digest[1:]
    with pytest.raises(VerificationFailure) as expected:
        verify_evidence(
            case_dir / MANIFEST_NAME,
            case_dir,
            expected_manifest_sha256=different,
            historical=True,
        )
    assert "trusted expected" in str(expected.value)
    shutil.rmtree(case_dir, ignore_errors=True)


def test_current_architecture_digest_is_the_operational_identity() -> None:
    """The verifier's CURRENT mode is bound to the live architecture identity
    and the historical digest is an explicitly separate constant."""
    assert CURRENT_ARCHITECTURE_SHA256 == (
        "126af414b2ba6497760a866475b2517b5470ce3b9681da3863401156bf235587"
    )
    assert HISTORICAL_ARCHITECTURE_SHA256 == (
        "483932970d44770b05fcfad7430b85820d771458110f004b0397bd5d56398615"
    )
    assert CURRENT_ARCHITECTURE_SHA256 != HISTORICAL_ARCHITECTURE_SHA256


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
    assert (name, version) == ("dbf-anonymizer", "1.0.0")
    wheel_name, wheel_version = _wheel_identity(wheel_1)
    assert (wheel_name, wheel_version) == ("dbf-anonymizer", "1.0.0")


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
