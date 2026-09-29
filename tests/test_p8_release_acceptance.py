"""REQ-P8-002: objective tests for the one-command release acceptance."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

from tools.run_release_acceptance import (
    ENTRY_POINT,
    MANIFEST_FILENAME,
    REPO_ROOT,
    StageResult,
    _git_clean,
    _git_commit,
    build_manifest,
)

WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "p8-release-acceptance.yml"
ROUNDTRIP_TOOL = REPO_ROOT / "tools" / "release_acceptance_roundtrip.py"
CANARY_TEXTS = ("PARENT-1", "PARENT-2", "MEMO-N-1", "MEMO-S-1", "SYNTHETIC-BINARY")
REQUIRED_MANIFEST_KEYS = (
    "schema_version",
    "source_commit",
    "package_version",
    "public_contract",
    "release_candidate",
    "dbfbridge_provenance",
    "stages",
    "quality_gate_status",
    "wheel_install_status",
    "canonical_roundtrip_status",
    "relationship_status",
    "transfer_bundle_status",
    "forbidden_material_status",
    "offline_status",
    "vfp_evidence_status",
    "final_status",
)
STAGE_NAMES = (
    "source_binding",
    "quality_gates",
    "public_contract_freeze",
    "dependency_audit",
    "release_build",
    "offline_fresh_wheel",
    "installed_wheel_contract",
    "canonical_roundtrip",
    "no_vfp_standalone",
)


def _run_roundtrip(work_root: Path) -> dict[str, object]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    completed = subprocess.run(  # noqa: S603 - fixed tool invocation
        [sys.executable, str(ROUNDTRIP_TOOL), "--work-root", str(work_root)],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    payload: dict[str, object] = json.loads(completed.stdout.strip())
    return payload


def test_canonical_roundtrip_runner_proves_the_full_public_workflow(
    tmp_path: Path,
) -> None:
    payload = _run_roundtrip(tmp_path / "work")
    assert payload["stage"] == "canonical_roundtrip"
    assert payload["status"] == "PASS"
    facts: dict[str, object] = payload["facts"]  # type: ignore[index]
    assert facts["verification_status"] == "PASS"
    assert facts["source_unchanged"] is True
    assert facts["assurance_level"] == "DECLARED_RELATIONS_VERIFIED"
    assert facts["declared_relations"] == 1
    assert facts["preflight_ready"] is True
    assert facts["standalone_verified"] is True
    assert facts["manifest_fingerprint_match"] is True
    assert facts["recovery_canonical_verified"] is True
    assert facts["raw_byte_equivalence"] == "NOT_EVALUATED"
    assert facts["oracle_topology_match"] is True
    assert facts["oracle_tables_compared"] == 3
    assert facts["bundle_allowlist_ok"] is True
    assert facts["forbidden_basenames_absent"] is True
    assert facts["canaries_absent_in_bundle"] is True
    assert facts["canaries_present_in_recovered"] is True
    assert facts["network_attempts"] == 0
    assert facts["process_attempts"] == 0
    assert facts["bundle_profile"] == "DATA_ONLY"
    assert facts["capabilities_vfp_index_backend"] is False


def test_roundtrip_facts_never_leak_sensitive_material(tmp_path: Path) -> None:
    payload = _run_roundtrip(tmp_path / "roundtrip")
    serialized = json.dumps(payload)
    for canary in CANARY_TEXTS:
        assert canary not in serialized
    assert "SYNTHETIC-BINARY" not in serialized
    assert str(tmp_path) not in serialized
    assert not re.search(r"[A-Za-z]:[\\/]", serialized)
    facts = payload["facts"]
    assert isinstance(facts, dict)


def _passing_bind() -> dict[str, object]:
    return {
        "source_commit": "0" * 40,
        "package_version": "1.0.0.dev0",
        "python_version": "3.12.0",
        "platform": "Linux-x86_64",
        "public_contract_sha256": "a" * 64,
        "installed_dbfbridge_main": "1.1.1",
        "acceptance_pin": "dbfbridge[write]==1.1.1",
        "trusted_vfp_runtime_declared": False,
    }


def _passing_stages() -> dict[str, StageResult]:
    stages: dict[str, StageResult] = dict.fromkeys(
        STAGE_NAMES, StageResult("placeholder", "PASS", {})
    )
    stages["canonical_roundtrip"] = StageResult(
        "canonical_roundtrip",
        "PASS",
        {
            "assurance_level": "DECLARED_RELATIONS_VERIFIED",
            "standalone_verified": True,
            "forbidden_basenames_absent": True,
            "bundle_allowlist_ok": True,
            "canaries_absent_in_bundle": True,
            "network_attempts": 0,
            "process_attempts": 0,
            "capabilities_vfp_index_backend": False,
        },
    )
    stages["release_build"] = StageResult(
        "release_build",
        "PASS",
        {
            "wheel_filename": "dist/dbf_anonymizer-1.0.0.dev0-py3-none-any.whl",
            "wheel_sha256": "b" * 64,
            "sdist_filename": "dist/dbf_anonymizer-1.0.0.dev0.tar.gz",
            "sdist_sha256": "c" * 64,
            "release_evidence_manifest_sha256": "d" * 64,
            "wheelhouse_dbfbridge": {
                "filename": "wheelhouse/dbfbridge-1.1.1-py3-none-any.whl",
                "sha256": "e" * 64,
            },
        },
    )
    stages["offline_fresh_wheel"] = StageResult(
        "offline_fresh_wheel", "PASS", {"fresh_dbfbridge_version": "1.1.1"}
    )
    return stages


def test_build_manifest_is_fail_closed() -> None:
    bind = _passing_bind()
    passing = _passing_stages()
    manifest = build_manifest(passing, bind)
    assert manifest["final_status"] == "PASS"
    assert manifest["relationship_status"] == "PASS"
    assert manifest["forbidden_material_status"] == "PASS"
    assert manifest["offline_status"] == "PASS"
    assert manifest["vfp_evidence_status"] == "NOT_RUN"

    failing = dict(passing)
    failing["installed_wheel_contract"] = StageResult(
        "installed_wheel_contract", "FAIL", {"error": "RuntimeError"}
    )
    assert build_manifest(failing, bind)["final_status"] == "FAIL"

    incomplete = {name: result for name, result in passing.items() if name != "no_vfp_standalone"}
    assert build_manifest(incomplete, bind)["final_status"] == "FAIL"

    weak_bundle = dict(passing)
    weak_bundle["canonical_roundtrip"] = StageResult(
        "canonical_roundtrip",
        "PASS",
        {
            "assurance_level": "DECLARED_RELATIONS_VERIFIED",
            "standalone_verified": True,
            "forbidden_basenames_absent": True,
            "bundle_allowlist_ok": True,
            "canaries_absent_in_bundle": False,
            "network_attempts": 0,
            "process_attempts": 0,
            "capabilities_vfp_index_backend": False,
        },
    )
    assert build_manifest(weak_bundle, bind)["forbidden_material_status"] == "FAIL"
    assert build_manifest(weak_bundle, bind)["final_status"] == "FAIL"


def test_manifest_serialization_is_deterministic_and_privacy_safe() -> None:
    bind = _passing_bind()
    stages = _passing_stages()
    first = build_manifest(stages, bind)
    second = build_manifest(stages, bind)
    assert json.dumps(first, indent=2, sort_keys=True) == json.dumps(
        second, indent=2, sort_keys=True
    )
    serialized = json.dumps(first)
    for canary in CANARY_TEXTS:
        assert canary not in serialized
    assert "SYNTHETIC-BINARY" not in serialized
    assert not re.search(r"[A-Za-z]:[\\/]", serialized)
    assert all(key in first for key in REQUIRED_MANIFEST_KEYS)
    assert first["entry_point"] == ENTRY_POINT


def test_release_acceptance_workflow_contract() -> None:
    document = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert document["permissions"] == {"contents": "read"}
    triggers = document.get(True) or document.get("on")
    assert set(triggers) <= {"push", "pull_request", "workflow_dispatch"}
    assert not set(triggers) & {"pull_request_target", "workflow_run", "repository_dispatch"}
    jobs = document["jobs"]
    assert set(jobs) == {"release-acceptance"}
    job = jobs["release-acceptance"]
    assert job["runs-on"] == "ubuntu-latest"
    sha_pinned = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
    for step in job["steps"]:
        uses = step.get("uses")
        if isinstance(uses, str):
            assert sha_pinned.match(uses), uses
    runs = "\n".join(step.get("run", "") for step in job["steps"] if isinstance(step, dict))
    assert "tools/run_release_acceptance.py" in runs
    assert "--output-dir" in runs
    serialized = json.dumps(document)
    for forbidden in ("id-token", "attestations", "gh-action-pypi-publish"):
        assert forbidden not in serialized
    for step in jobs["release-acceptance"]["steps"]:
        if str(step.get("uses", "")).startswith("actions/upload-artifact"):
            path = str(step["with"]["path"])
            assert "${{ runner.temp }}" in path


def test_source_cleanliness_is_fail_closed(tmp_path: Path) -> None:
    def git(*arguments: str) -> None:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=str(tmp_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert completed.returncode == 0, completed.stderr

    git("init", "-q")
    git(
        "-c",
        "user.email=acceptance@example.com",
        "-c",
        "user.name=acceptance",
        "commit",
        "--allow-empty",
        "-q",
        "-m",
        "seed",
    )
    clean, _ = _git_clean(tmp_path)
    assert clean is True
    assert len(_git_commit(tmp_path)) == 40
    (tmp_path / "tracked.txt").write_text("modified", encoding="utf-8")
    git("add", "tracked.txt")
    clean_with_dirty, status = _git_clean(tmp_path)
    assert clean_with_dirty is False
    assert "tracked.txt" in status


def test_entry_point_constants_are_bound() -> None:
    assert ENTRY_POINT == "tools/run_release_acceptance.py"
    assert MANIFEST_FILENAME == "release-acceptance-evidence.json"
    manifest_keys = (
        "schema_version",
        "kind",
        "requirement",
        "entry_point",
        "source_commit",
        "package_version",
        "python_version",
        "platform",
        "release_candidate",
        "public_contract",
        "dbfbridge_provenance",
        "stages",
        "quality_gate_status",
        "wheel_install_status",
        "canonical_roundtrip_status",
        "relationship_status",
        "transfer_bundle_status",
        "forbidden_material_status",
        "offline_status",
        "vfp_evidence_status",
        "vfp_evidence",
        "final_status",
    )
    bind = _passing_bind()
    stages = _passing_stages()
    manifest = build_manifest(stages, bind)
    assert all(key in manifest for key in manifest_keys)
    assert manifest["final_status"] == "PASS"
