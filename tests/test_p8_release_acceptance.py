"""REQ-P8-002: objective tests for the one-command release acceptance."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tools.run_release_acceptance import (
    ENTRY_POINT,
    MANIFEST_DIGEST_SIDECAR,
    MANIFEST_FILENAME,
    REPO_ROOT,
    SECURITY_AUDIT_VARIABLE,
    StageResult,
    WINDOWS_MATRIX_VARIABLE,
    _git_clean,
    _git_commit,
    _manifest_content_hygiene,
    _mandatory_gate_statuses,
    _roundtrip_cwd,
    _run,
    _sanitized_roundtrip_environment,
    _wheel_install_command,
    _wheelhouse_install_command,
    assert_publishable_hygiene,
    build_manifest,
    finalize_publishable_evidence,
)
from tools.release_acceptance_roundtrip import installed_wheel_origin_facts

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
    "installed_wheel_origin",
    "mandatory_quality_gates",
    "publishable_artifact",
    "stages",
    "quality_gate_status",
    "wheel_install_status",
    "canonical_roundtrip_status",
    "relationship_status",
    "transfer_bundle_status",
    "forbidden_material_status",
    "offline_status",
    "installed_wheel_origin_status",
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


def _section(manifest: dict[str, object], key: str) -> dict[str, object]:
    section = manifest[key]
    assert isinstance(section, dict)
    return section


def _run_roundtrip(
    work_root: Path,
    *extra_arguments: str,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    if env_overrides:
        environment.update(env_overrides)
    return subprocess.run(  # noqa: S603 - fixed tool invocation
        [sys.executable, str(ROUNDTRIP_TOOL), "--work-root", str(work_root), *extra_arguments],
        cwd=str(work_root.parent),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _roundtrip_payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.returncode == 0, result.stderr[-2000:]
    payload: dict[str, object] = json.loads(result.stdout.strip())
    return payload


def test_canonical_roundtrip_runner_proves_the_full_public_workflow(
    tmp_path: Path,
) -> None:
    payload = _roundtrip_payload(
        _run_roundtrip(tmp_path / "work", "--expected-version", "1.0.0.dev0")
    )
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
    assert "installed_wheel_origin_verified" in facts
    assert "repository_source_shadowing" in facts
    assert "repo_root_in_pythonpath" in facts
    assert "repo_root_in_sys_path" in facts


def test_roundtrip_refuses_a_non_wheel_import_origin_when_required(tmp_path: Path) -> None:
    """Fail-closed import-origin proof: without the installed wheel the
    enforced acceptance path must refuse to run the canonical round trip."""
    result = _run_roundtrip(
        tmp_path / "roundtrip",
        "--expected-version",
        "1.0.0.dev0",
        "--require-installed-origin",
    )
    assert result.returncode != 0
    payload: dict[str, object] = json.loads(result.stdout.strip())
    assert payload["status"] == "FAIL"
    assert payload["error"] == "RuntimeError"


def test_roundtrip_reports_repository_path_poisoning_truthfully(tmp_path: Path) -> None:
    """Poisoning PYTHONPATH with the repository root is truthfully detected by
    the origin facts, and the enforced acceptance path refuses non-wheel
    origins (fail-closed): poisoning can never silently substitute the source
    checkout for the installed wheel."""
    result = _run_roundtrip(
        tmp_path / "poisoned",
        "--expected-version",
        "1.0.0.dev0",
        env_overrides={"PYTHONPATH": f"{REPO_ROOT}{os.pathsep}{tmp_path}"},
    )
    assert result.returncode == 0, result.stderr[-2000:]
    payload: dict[str, object] = json.loads(result.stdout.strip())
    facts: dict[str, object] = payload["facts"]  # type: ignore[index]
    assert facts["repo_root_in_sys_path"] is True
    assert facts["repo_root_in_pythonpath"] is True
    assert facts["installed_wheel_origin_verified"] is False
    assert facts["repository_source_shadowing"] is True
    enforced = _run_roundtrip(
        tmp_path / "enforced",
        "--expected-version",
        "1.0.0.dev0",
        "--require-installed-origin",
        env_overrides={"PYTHONPATH": f"{REPO_ROOT}{os.pathsep}{tmp_path}"},
    )
    assert enforced.returncode != 0
    enforced_payload: dict[str, object] = json.loads(enforced.stdout.strip())
    assert enforced_payload["status"] == "FAIL"


def test_roundtrip_facts_never_leak_sensitive_material(tmp_path: Path) -> None:
    payload = _roundtrip_payload(
        _run_roundtrip(tmp_path / "roundtrip", "--expected-version", "1.0.0.dev0")
    )
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
            "installed_wheel_origin_verified": True,
            "repository_source_shadowing": False,
            "import_origin": "ACCEPTANCE_VENV_SITE_PACKAGES",
            "repo_root_in_pythonpath": False,
            "repo_root_in_sys_path": False,
            "cwd_outside_repository": True,
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


def _ci_mandatory() -> dict[str, object]:
    return {
        "execution_context": "CI_RELEASE_ACCEPTANCE",
        "windows_python_matrix": "PASS",
        "security_advisory_audit": "PASS",
        "gates_source": "GITHUB_WORKFLOW_NEEDS",
    }


def _passing_hygiene() -> dict[str, object]:
    return {
        "hygiene": "PASS",
        "publishable_file_count": 4,
        "allowlist_ok": True,
        "forbidden_artifacts_absent": True,
        "canaries_absent": True,
        "absolute_private_paths_absent": True,
    }


def test_build_manifest_is_fail_closed() -> None:
    bind = _passing_bind()
    passing = _passing_stages()
    manifest = build_manifest(passing, bind, _ci_mandatory(), _passing_hygiene())
    assert manifest["final_status"] == "PASS"
    assert manifest["relationship_status"] == "PASS"
    assert manifest["forbidden_material_status"] == "PASS"
    assert manifest["offline_status"] == "PASS"
    assert manifest["installed_wheel_origin_status"] == "PASS"
    assert manifest["vfp_evidence_status"] == "NOT_RUN"
    assert _section(manifest, "publishable_artifact")["hygiene"] == "PASS"

    failing = dict(passing)
    failing["installed_wheel_contract"] = StageResult(
        "installed_wheel_contract", "FAIL", {"error": "RuntimeError"}
    )
    assert (
        build_manifest(failing, bind, _ci_mandatory(), _passing_hygiene())["final_status"] == "FAIL"
    )

    incomplete = {name: result for name, result in passing.items() if name != "no_vfp_standalone"}
    assert (
        build_manifest(incomplete, bind, _ci_mandatory(), _passing_hygiene())["final_status"]
        == "FAIL"
    )

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
            "installed_wheel_origin_verified": True,
            "repository_source_shadowing": False,
        },
    )
    assert (
        build_manifest(weak_bundle, bind, _ci_mandatory(), _passing_hygiene())[
            "forbidden_material_status"
        ]
        == "FAIL"
    )
    assert (
        build_manifest(weak_bundle, bind, _ci_mandatory(), _passing_hygiene())["final_status"]
        == "FAIL"
    )

    shadowed = dict(passing)
    shadowed["canonical_roundtrip"] = StageResult(
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
            "installed_wheel_origin_verified": False,
            "repository_source_shadowing": True,
        },
    )
    shadowed_manifest = build_manifest(shadowed, bind, _ci_mandatory(), _passing_hygiene())
    assert shadowed_manifest["installed_wheel_origin_status"] == "FAIL"
    assert shadowed_manifest["final_status"] == "FAIL"


def test_manifest_fails_closed_without_mandatory_platform_and_security_gates() -> None:
    bind = _passing_bind()
    stages = _passing_stages()
    hygiene = _passing_hygiene()

    local = dict(_ci_mandatory())
    local.update(
        {
            "execution_context": "LOCAL_PRECHECK",
            "windows_python_matrix": "NOT_RUN_LOCAL_PRECHECK",
            "security_advisory_audit": "NOT_RUN_LOCAL_PRECHECK",
            "gates_source": "LOCAL_MAINTAINER_PRECHECK",
        }
    )
    local_manifest = build_manifest(stages, bind, local, hygiene)
    assert local_manifest["final_status"] == "LOCAL_PRECHECK"
    assert _section(local_manifest, "mandatory_quality_gates")["windows_python_matrix"] == (
        "NOT_RUN_LOCAL_PRECHECK"
    )

    failed_windows = dict(_ci_mandatory())
    failed_windows["windows_python_matrix"] = "FAIL"
    assert build_manifest(stages, bind, failed_windows, hygiene)["final_status"] == "FAIL"

    skipped_windows = dict(_ci_mandatory())
    skipped_windows["windows_python_matrix"] = "skipped"
    assert build_manifest(stages, bind, skipped_windows, hygiene)["final_status"] == "FAIL"

    failed_security = dict(_ci_mandatory())
    failed_security["security_advisory_audit"] = "failure"
    assert build_manifest(stages, bind, failed_security, hygiene)["final_status"] == "FAIL"

    dirty_hygiene = dict(_passing_hygiene())
    dirty_hygiene["hygiene"] = "FAIL"
    assert build_manifest(stages, bind, _ci_mandatory(), dirty_hygiene)["final_status"] == "FAIL"


def test_mandatory_gate_statuses_read_only_workflow_controlled_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(WINDOWS_MATRIX_VARIABLE, raising=False)
    monkeypatch.delenv(SECURITY_AUDIT_VARIABLE, raising=False)
    local = _mandatory_gate_statuses()
    assert local["execution_context"] == "LOCAL_PRECHECK"
    assert local["windows_python_matrix"] == "NOT_RUN_LOCAL_PRECHECK"

    monkeypatch.setenv(WINDOWS_MATRIX_VARIABLE, "success")
    monkeypatch.setenv(SECURITY_AUDIT_VARIABLE, "success")
    ci = _mandatory_gate_statuses()
    assert ci["execution_context"] == "CI_RELEASE_ACCEPTANCE"
    assert ci["windows_python_matrix"] == "PASS"
    assert ci["security_advisory_audit"] == "PASS"

    monkeypatch.setenv(SECURITY_AUDIT_VARIABLE, "failure")
    broken = _mandatory_gate_statuses()
    assert broken["security_advisory_audit"] == "FAIL"
    assert broken["execution_context"] == "CI_RELEASE_ACCEPTANCE"


def test_manifest_serialization_is_deterministic_and_privacy_safe() -> None:
    bind = _passing_bind()
    stages = _passing_stages()
    first = build_manifest(stages, bind, _ci_mandatory(), _passing_hygiene())
    second = build_manifest(stages, bind, _ci_mandatory(), _passing_hygiene())
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
    assert _manifest_content_hygiene(json.dumps(first, indent=2, sort_keys=True)) is True


def test_release_acceptance_workflow_contract() -> None:
    document = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert document["permissions"] == {"contents": "read"}
    triggers = document.get(True) or document.get("on")
    assert set(triggers) <= {"push", "pull_request", "workflow_dispatch"}
    assert not set(triggers) & {"pull_request_target", "workflow_run", "repository_dispatch"}
    jobs = document["jobs"]
    assert set(jobs) == {
        "windows-release-matrix",
        "security-advisory-audit",
        "release-acceptance",
    }
    sha_pinned = re.compile(r"^[^@\s]+@[0-a-f]{40}$".replace("0-", "0-9a-f"))
    for name, job in jobs.items():
        assert job["runs-on"] in {"ubuntu-latest", "windows-latest"}, name
        for step in job["steps"]:
            uses = step.get("uses")
            if isinstance(uses, str):
                assert sha_pinned.match(uses), uses
    matrix = jobs["windows-release-matrix"]
    assert matrix["runs-on"] == "windows-latest"
    versions = matrix["strategy"]["matrix"]["python-version"]
    assert versions == ["3.10", "3.11", "3.12", "3.13", "3.14"]
    matrix_runs = "\n".join(
        step.get("run", "") for step in matrix["steps"] if isinstance(step, dict)
    )
    assert "python -m build" in matrix_runs
    assert "check_wheel_metadata.py" in matrix_runs
    assert "site-packages" in matrix_runs
    assert "check_p7_installed_wheel.py" in matrix_runs
    assert "check_p7_no_vfp_smoke.py" in matrix_runs
    assert "pip check" in matrix_runs
    audit = jobs["security-advisory-audit"]
    audit_runs = "\n".join(step.get("run", "") for step in audit["steps"] if isinstance(step, dict))
    assert "pip-audit==2.10.1" in audit_runs
    assert "pip_audit --no-deps -r requirements/p7-offline-wheelhouse.txt" in audit_runs
    acceptance = jobs["release-acceptance"]
    assert acceptance["needs"] == ["windows-release-matrix", "security-advisory-audit"]
    env = acceptance["env"]
    assert env["DBF_MANDATORY_WINDOWS_MATRIX_RESULT"] == (
        "${{ needs.windows-release-matrix.result }}"
    )
    assert env["DBF_MANDATORY_SECURITY_AUDIT_RESULT"] == (
        "${{ needs.security-advisory-audit.result }}"
    )
    runs = "\n".join(step.get("run", "") for step in acceptance["steps"] if isinstance(step, dict))
    assert "tools/run_release_acceptance.py" in runs
    assert "--work-root" in runs
    assert "--output-dir" in runs
    serialized = json.dumps(document)
    for forbidden in ("id-token", "attestations", "gh-action-pypi-publish"):
        assert forbidden not in serialized
    for step in acceptance["steps"]:
        if str(step.get("uses", "")).startswith("actions/upload-artifact"):
            path = str(step["with"]["path"])
            assert "${{ runner.temp }}" in path
            assert "p8-release-acceptance-publishable" in path


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
        "installed_wheel_origin",
        "mandatory_quality_gates",
        "publishable_artifact",
        "stages",
        "quality_gate_status",
        "wheel_install_status",
        "canonical_roundtrip_status",
        "relationship_status",
        "transfer_bundle_status",
        "forbidden_material_status",
        "offline_status",
        "installed_wheel_origin_status",
        "vfp_evidence_status",
        "vfp_evidence",
        "final_status",
    )
    bind = _passing_bind()
    stages = _passing_stages()
    manifest = build_manifest(stages, bind, _ci_mandatory(), _passing_hygiene())
    assert all(key in manifest for key in manifest_keys)
    assert manifest["final_status"] == "PASS"


def test_run_env_propagates_environment_to_the_child() -> None:
    import os as os_module

    marker_command = [
        sys.executable,
        "-c",
        "import os, sys; sys.exit(0 if os.environ.get('DBF_P8_ENV_PROBE') == '1' else 1)",
    ]
    with_env = dict(os_module.environ)
    with_env["DBF_P8_ENV_PROBE"] = "1"
    assert _run(marker_command, cwd=REPO_ROOT, env=with_env) == 0
    without_env = dict(os_module.environ)
    without_env.pop("DBF_P8_ENV_PROBE", None)
    assert _run(marker_command, cwd=REPO_ROOT, env=without_env) != 0


def test_offline_install_commands_pin_no_index_and_no_cache() -> None:
    venv_python = Path("acceptance-venv/Scripts/python.exe")
    wheelhouse = Path("wheelhouse")
    wheelhouse_manifest = Path("requirements/p7-offline-wheelhouse.txt")
    wheel_path = Path("p7-evidence/dist/dbf_anonymizer-1.0.0.dev0-py3-none-any.whl")
    closure = _wheelhouse_install_command(venv_python, wheelhouse, wheelhouse_manifest)
    assert "--no-index" in closure
    assert "--find-links" in closure
    assert "--no-cache-dir" in closure
    assert str(wheelhouse_manifest) in closure
    wheel = _wheel_install_command(venv_python, wheel_path)
    assert wheel == [
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-cache-dir",
        "--no-deps",
        str(wheel_path),
    ]


def test_sanitized_roundtrip_environment_removes_the_repository_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTHONPATH", f"{REPO_ROOT}{os.pathsep}{Path(os.sep)}")
    env = _sanitized_roundtrip_environment()
    entries = [
        Path(entry).resolve() for entry in env.get("PYTHONPATH", "").split(os.pathsep) if entry
    ]
    assert REPO_ROOT.resolve() not in entries
    monkeypatch.delenv("PYTHONPATH", raising=False)
    env = _sanitized_roundtrip_environment()
    assert "PYTHONPATH" not in env


def test_roundtrip_cwd_is_outside_the_repository(tmp_path: Path) -> None:
    outside = _roundtrip_cwd(tmp_path)
    assert REPO_ROOT.resolve() not in Path(outside).resolve().parents
    inside = _roundtrip_cwd(REPO_ROOT / "build" / "p8-work")
    assert REPO_ROOT.resolve() not in Path(inside).resolve().parents
    if inside != REPO_ROOT / "build" / "p8-work":
        import shutil

        shutil.rmtree(inside, ignore_errors=True)


def test_installed_wheel_origin_facts_verdicts(tmp_path: Path) -> None:
    venv_site = tmp_path / "venv" / "Lib" / "site-packages" / "dbf_anonymizer" / "__init__.py"
    verified = installed_wheel_origin_facts(
        module_file=str(venv_site),
        installed_version="1.0.0.dev0",
        expected_version="1.0.0.dev0",
        repo_root=REPO_ROOT,
        pythonpath="",
        cwd=tmp_path,
    )
    assert verified["installed_wheel_origin_verified"] is True
    assert verified["repository_source_shadowing"] is False
    assert verified["import_origin"] == "ACCEPTANCE_VENV_SITE_PACKAGES"

    source_origin = REPO_ROOT / "src" / "dbf_anonymizer" / "__init__.py"
    shadowed = installed_wheel_origin_facts(
        module_file=str(source_origin),
        installed_version="1.0.0.dev0",
        expected_version="1.0.0.dev0",
        repo_root=REPO_ROOT,
        pythonpath=str(REPO_ROOT),
        cwd=REPO_ROOT,
    )
    assert shadowed["installed_wheel_origin_verified"] is False
    assert shadowed["repository_source_shadowing"] is True
    assert shadowed["import_origin"] == "OTHER"
    assert shadowed["repo_root_in_pythonpath"] is True
    assert shadowed["cwd_outside_repository"] is False

    wrong_version = installed_wheel_origin_facts(
        module_file=str(venv_site),
        installed_version="9.9.9",
        expected_version="1.0.0.dev0",
        repo_root=REPO_ROOT,
        pythonpath="",
        cwd=tmp_path,
    )
    assert wrong_version["installed_wheel_origin_verified"] is False
    assert wrong_version["installed_version_matches_candidate"] is False


def test_publishable_artifact_hygiene_is_fail_closed(tmp_path: Path) -> None:
    output_dir = tmp_path / "publishable"
    candidate = output_dir / "release-candidate"
    candidate.mkdir(parents=True)
    candidates = ("dbf_anonymizer-1.0.0.dev0-py3-none-any.whl", "dbf_anonymizer-1.0.0.dev0.tar.gz")
    (output_dir / "release-acceptance-evidence.json").write_text("{}", encoding="utf-8")
    (output_dir / "release-acceptance-evidence.sha256").write_text(
        "a" * 64 + "\n", encoding="utf-8"
    )
    (candidate / candidates[0]).write_bytes(b"wheel")
    (candidate / candidates[1]).write_bytes(b"sdist")
    facts = assert_publishable_hygiene(output_dir, candidates)
    assert facts["hygiene"] == "PASS"

    def violation(name: str, content: bytes | str = b"") -> None:
        path = output_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        assert assert_publishable_hygiene(output_dir, candidates)["hygiene"] == "FAIL"
        path.unlink()

    violation("dictionary.sqlite3")
    violation("roundtrip/oracle/north/data.dbf")
    violation("recovered/south/data.dbf")
    violation("acceptance-venv/pyvenv.cfg")
    violation("wheelhouse/dbfbridge-1.1.1-py3-none-any.whl")
    violation("runtime-contract/api/protected/recovery.sqlite3")
    violation("roundtrip/vault/dictionary.sqlite3-wal")
    violation("release-candidate/recovery.sqlite3")
    violation(
        "release-acceptance-evidence.json",
        json.dumps({"leak": "PARENT-1"}),
    )
    violation(
        "release-acceptance-evidence.json",
        json.dumps({"path": "C:\\Users\\private\\data"}),
    )
    extra = output_dir / "unexpected.txt"
    extra.write_text("x", encoding="utf-8")
    assert assert_publishable_hygiene(output_dir, candidates)["allowlist_ok"] is False
    extra.unlink()
    assert assert_publishable_hygiene(output_dir, candidates)["hygiene"] == "PASS"


def test_publishable_hygiene_accepts_alternate_stable_candidate_names(tmp_path: Path) -> None:
    """Candidate distribution names come from explicit build facts: the
    hygiene allowlist contains no hardcoded dev0 assumption, so a future
    stable-style candidate is accepted when it IS the expected candidate."""
    output_dir = tmp_path / "publishable"
    candidate = output_dir / "release-candidate"
    candidate.mkdir(parents=True)
    stable_candidates = ("dbf_anonymizer-1.0.0-py3-none-any.whl", "dbf_anonymizer-1.0.0.tar.gz")
    (output_dir / "release-acceptance-evidence.json").write_text("{}", encoding="utf-8")
    (output_dir / "release-acceptance-evidence.sha256").write_text(
        "b" * 64 + "\n", encoding="utf-8"
    )
    (candidate / stable_candidates[0]).write_bytes(b"stable wheel")
    (candidate / stable_candidates[1]).write_bytes(b"stable sdist")
    facts = assert_publishable_hygiene(output_dir, stable_candidates)
    assert facts["hygiene"] == "PASS"
    assert facts["publishable_file_count"] == 4
    unexpected_distribution = candidate / "dbfbridge-2.0.0-py3-none-any.whl"
    unexpected_distribution.write_bytes(b"third")
    assert assert_publishable_hygiene(output_dir, stable_candidates)["hygiene"] == "FAIL"
    unexpected_distribution.unlink()
    unexpected_filename = output_dir / "release-acceptance-evidence.old.json"
    unexpected_filename.write_text("{}", encoding="utf-8")
    assert assert_publishable_hygiene(output_dir, stable_candidates)["allowlist_ok"] is False
    unexpected_filename.unlink()
    assert assert_publishable_hygiene(output_dir, stable_candidates)["hygiene"] == "PASS"
    dev_names = ("dbf_anonymizer-1.0.0.dev0-py3-none-any.whl", "dbf_anonymizer-1.0.0.dev0.tar.gz")
    assert assert_publishable_hygiene(output_dir, dev_names)["hygiene"] == "FAIL"


def test_finalize_publishable_count_equals_actual_final_files(tmp_path: Path) -> None:
    """The two-pass finalization writes the manifest/sidecar, then verifies the
    manifest's own claims against the ACTUAL final tree: the declared
    publishable_file_count must equal the real number of final files and the
    exact file identities must match."""
    output_dir = tmp_path / "publishable"
    candidate = output_dir / "release-candidate"
    candidate.mkdir(parents=True)
    candidate_names = (
        "dbf_anonymizer-1.0.0.dev0-py3-none-any.whl",
        "dbf_anonymizer-1.0.0.dev0.tar.gz",
    )
    (candidate / candidate_names[0]).write_bytes(b"wheel")
    (candidate / candidate_names[1]).write_bytes(b"sdist")
    pre = assert_publishable_hygiene(output_dir, candidate_names)
    pre_files = pre["publishable_files"]
    assert isinstance(pre_files, list)
    expected_final_hygiene = {
        "hygiene": pre["hygiene"],
        "publishable_file_count": len(pre_files) + 2,
        "publishable_files": sorted([*pre_files, MANIFEST_FILENAME, MANIFEST_DIGEST_SIDECAR]),
        "allowlist_ok": pre["allowlist_ok"],
        "forbidden_artifacts_absent": pre["forbidden_artifacts_absent"],
        "canaries_absent": pre["canaries_absent"],
        "absolute_private_paths_absent": pre["absolute_private_paths_absent"],
    }
    manifest = build_manifest(
        _passing_stages(), _passing_bind(), _ci_mandatory(), expected_final_hygiene
    )
    hygiene, digest, final = finalize_publishable_evidence(output_dir, candidate_names, manifest)
    assert final == "PASS"
    actual_files = sorted(
        path.relative_to(output_dir).as_posix() for path in output_dir.rglob("*") if path.is_file()
    )
    assert hygiene["publishable_file_count"] == 4
    section = manifest["publishable_artifact"]
    assert isinstance(section, dict)
    assert section["publishable_file_count"] == len(actual_files)
    assert section["publishable_files"] == sorted(hygiene["publishable_files"])  # type: ignore[arg-type]
    assert actual_files == sorted(
        [
            "release-acceptance-evidence.json",
            "release-acceptance-evidence.sha256",
            f"release-candidate/{candidate_names[0]}",
            f"release-candidate/{candidate_names[1]}",
        ]
    )
    sidecar_digest = (
        (output_dir / "release-acceptance-evidence.sha256").read_text(encoding="utf-8").split()[0]
    )
    assert sidecar_digest == digest
    import hashlib

    assert (
        hashlib.sha256((output_dir / "release-acceptance-evidence.json").read_bytes()).hexdigest()
        == digest
    )


def test_finalize_fails_closed_on_an_inconsistent_final_tree(tmp_path: Path) -> None:
    """An unexpected extra publishable file makes the final verification refuse
    the manifest claims: the verdict becomes FAIL and the rewritten manifest
    records the consistency failure."""
    output_dir = tmp_path / "publishable"
    candidate = output_dir / "release-candidate"
    candidate.mkdir(parents=True)
    candidate_names = ("dbf_anonymizer-1.0.0-py3-none-any.whl", "dbf_anonymizer-1.0.0.tar.gz")
    (candidate / candidate_names[0]).write_bytes(b"stable wheel")
    (candidate / candidate_names[1]).write_bytes(b"stable sdist")
    (candidate / "surprise-extra.whl").write_bytes(b"unexpected third distribution")
    pre = assert_publishable_hygiene(output_dir, candidate_names)
    pre_files = pre["publishable_files"]
    assert isinstance(pre_files, list)
    expected_final_hygiene = {
        "hygiene": pre["hygiene"],
        "publishable_file_count": len(pre_files) + 2,
        "publishable_files": sorted([*pre_files, MANIFEST_FILENAME, MANIFEST_DIGEST_SIDECAR]),
        "allowlist_ok": pre["allowlist_ok"],
        "forbidden_artifacts_absent": pre["forbidden_artifacts_absent"],
        "canaries_absent": pre["canaries_absent"],
        "absolute_private_paths_absent": pre["absolute_private_paths_absent"],
    }
    manifest = build_manifest(
        _passing_stages(), _passing_bind(), _ci_mandatory(), expected_final_hygiene
    )
    hygiene, digest, final = finalize_publishable_evidence(output_dir, candidate_names, manifest)
    assert final == "FAIL"
    assert hygiene["allowlist_ok"] is False
    rewritten = json.loads(
        (output_dir / "release-acceptance-evidence.json").read_text(encoding="utf-8")
    )
    assert rewritten["final_status"] == "FAIL"
    section = rewritten["publishable_artifact"]
    assert section["consistency"] == "FINAL_TREE_VERIFICATION_FAILED"
    sidecar_digest = (
        (output_dir / "release-acceptance-evidence.sha256").read_text(encoding="utf-8").split()[0]
    )
    assert sidecar_digest == digest
