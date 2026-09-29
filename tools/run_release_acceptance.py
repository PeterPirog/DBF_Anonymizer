"""REQ-P8-002 one-command release acceptance (maintainer and CI entry point).

Executes the complete release acceptance for one exact source revision from a
clean commit and produces the machine-readable release-acceptance evidence
manifest (``release-acceptance-evidence.json`` plus its SHA-256 sidecar):

 1. source_binding            fail-closed clean-tree check + exact commit/version bind
 2. quality_gates             ruff format/lint, strict mypy, compileall, full pytest
 3. public_contract_freeze    P8-001 frozen 1.0 contract snapshot test + snapshot hash
 4. dependency_audit          pip check + exact pinned dbfbridge acceptance artifact
 5. release_build             reproducible two-build evidence bundle (P7-008),
                              independent fail-closed verifier with trusted digest,
                              and the copied release candidate (wheel + sdist)
 6. offline_fresh_wheel       wheelhouse validation + fresh venv ``--no-index``
                              install of the exact release wheel + pip/pin checks
 7. installed_wheel_contract  installed-wheel recovery-boundary contract + full
                              nine-command standalone runtime contract (sentinels)
 8. canonical_roundtrip       synthetic PK/FK dataset through the complete public
                              workflow, logical oracle and DATA_ONLY content scan,
                              executed from the INSTALLED wheel under sentinels
 9. no_vfp_standalone         hosted no-VFP import-purity + standalone smoke
10. evidence_manifest         deterministic fail-closed aggregation, final verdict

ONLINE PREPARATION covers stages 1-6 (including the PyPI wheelhouse download
performed by the accepted P7-008 evidence tool).  The OFFLINE RUNTIME
ACCEPTANCE phase covers stages 7-9: local wheels only, ``--no-index``,
controlled pip cache, no runtime HTTP, no Git and no package installation
after the environment has been prepared.

Fail-closed: any failed stage makes ``final_status`` FAIL and the command
exits non-zero.  A failing test NEVER regenerates any snapshot or evidence.

Usage (maintainer):
    python tools/run_release_acceptance.py --output-dir build/p8-release-acceptance
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_SNAPSHOT = REPO_ROOT / "contracts" / "public-contract-1.0.json"
ACCEPTANCE_PIN = REPO_ROOT / "requirements" / "p0-dbfbridge-tested.txt"
WHEELHOUSE_MANIFEST = REPO_ROOT / "requirements" / "p7-offline-wheelhouse.txt"
RUNTIME_REQUIREMENT = "dbfbridge[write]>=1.1.0,<2"
ENTRY_POINT = "tools/run_release_acceptance.py"

MANIFEST_SCHEMA_VERSION = "1.0"
MANIFEST_KIND = "dbf-anonymizer-release-acceptance-manifest"
MANIFEST_FILENAME = "release-acceptance-evidence.json"
MANIFEST_DIGEST_SIDECAR = "release-acceptance-evidence.sha256"
CANDIDATE_DIRECTORY = "release-candidate"

VFP_STATUS_NO_RUN = "NOT_RUN"
VFP_STATUS_AVAILABLE_NOT_REQUIRED = "AVAILABLE_BUT_NOT_REQUIRED"

_BIND_KEYS = (
    "source_commit",
    "package_version",
    "python_version",
    "platform",
    "public_contract_sha256",
    "installed_dbfbridge_main",
    "acceptance_pin",
    "trusted_vfp_runtime_declared",
)


class StageResult:
    def __init__(self, name: str, status: str, facts: dict[str, object]) -> None:
        self.name = name
        self.status = status
        self.facts = facts

    def as_dict(self) -> dict[str, object]:
        return {"status": self.status, "facts": self.facts}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _env() -> dict[str, str]:
    return dict(os.environ)


def _fail(message: str) -> None:
    raise RuntimeError(message)


def _run(command: list[str], *, cwd: Path = REPO_ROOT, env: dict[str, str] | None = None) -> int:
    completed = subprocess.run(  # noqa: S603 - fixed maintainer tool arguments
        command, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    return completed.returncode


def _run_json(
    command: list[str], *, cwd: Path = REPO_ROOT, env: dict[str, str] | None = None
) -> tuple[int, str]:
    completed = subprocess.run(  # noqa: S603 - fixed maintainer tool arguments
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        check=False,
        env=env,
    )
    return completed.returncode, completed.stdout.strip()


def _git_clean(repo_root: Path = REPO_ROOT) -> tuple[bool, str]:
    completed = subprocess.run(  # noqa: S603 - fixed read-only git probe
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "", completed.stdout.strip()


def _git_commit(repo_root: Path = REPO_ROOT) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed read-only git probe
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return completed.stdout.strip()


def _package_version() -> str:
    try:
        return metadata.version("dbf-anonymizer")
    except metadata.PackageNotFoundError:
        for line in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
            if line.startswith("version = "):
                return line.split("=", 1)[1].strip().strip('"')
    _fail("package version not resolvable")
    raise AssertionError  # pragma: no cover - defensive


def _acceptance_python(work_root: Path) -> Path:
    candidate = work_root / "acceptance-venv" / "Scripts" / "python.exe"
    if not candidate.is_file():
        candidate = work_root / "acceptance-venv" / "bin" / "python"
    if not candidate.is_file():
        _fail("acceptance venv missing; the offline fresh-wheel stage must run first")
    return candidate


def _command_facts(
    commands: list[tuple[str, list[str]]], cwd: Path = REPO_ROOT, **extra: object
) -> dict[str, object]:
    facts: dict[str, object] = {}
    for label, command in commands:
        code = _run(command, cwd=cwd)
        if code != 0:
            _fail(f"{label} failed (exit {code})")
        facts[label] = "PASS"
    facts.update(extra)
    return facts


def stage_source_binding(work_root: Path) -> dict[str, object]:
    del work_root
    clean, status = _git_clean()
    if not clean:
        _fail(f"release acceptance requires an exact clean commit; git status: {status}")
    commit = _git_commit()
    if len(commit) != 40:
        _fail("source commit not resolvable")
    direct_url = metadata.distribution("dbfbridge").read_text("direct_url.json")
    if direct_url is not None:
        _fail("dbfbridge must come from the public wheelhouse, not a VCS/local direct URL")
    return {
        "cleanliness": "CLEAN",
        "source_commit": commit,
        "package_version": _package_version(),
        "python_version": platform.python_version(),
        "platform": f"{platform.system()}-{platform.machine()}",
        "public_contract_sha256": _sha256(CONTRACT_SNAPSHOT),
        "installed_dbfbridge": metadata.version("dbfbridge"),
        "dbfbridge_vcs_or_local_url": False,
    }


def stage_quality_gates(work_root: Path) -> dict[str, object]:
    del work_root
    return _command_facts(
        [
            ("ruff_format", [sys.executable, "-m", "ruff", "format", "--check", "."]),
            ("ruff_lint", [sys.executable, "-m", "ruff", "check", "."]),
            ("mypy_strict", [sys.executable, "-m", "mypy", "--strict", "src/dbf_anonymizer"]),
            ("compileall", [sys.executable, "-m", "compileall", "-q", "src", "tests", "tools"]),
            ("full_test_suite", [sys.executable, "-m", "pytest", "-ra"]),
        ]
    )


def stage_public_contract_freeze(work_root: Path) -> dict[str, object]:
    del work_root
    code = _run([sys.executable, "-m", "pytest", "tests/test_p8_contract_freeze.py", "-ra"])
    if code != 0:
        _fail(f"REQ-P8-001 contract freeze test failed (exit {code}); snapshot not regenerated")
    return {
        "freeze_test": "PASS",
        "public_contract_sha256": _sha256(CONTRACT_SNAPSHOT),
        "snapshot_auto_update": "NEVER",
    }


def stage_dependency_audit(work_root: Path) -> dict[str, object]:
    del work_root
    pin_lines = [
        line.strip()
        for line in ACCEPTANCE_PIN.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if len(pin_lines) != 1:
        _fail("acceptance pin file must contain exactly one requirement line")
    facts = _command_facts(
        [
            ("pip_check", [sys.executable, "-m", "pip", "check"]),
            (
                "acceptance_pin",
                [sys.executable, str(REPO_ROOT / "tools" / "check_acceptance_pin.py")],
            ),
        ],
        acceptance_pin=pin_lines[0],
        installed_dbfbridge=metadata.version("dbfbridge"),
        dbfbridge_vcs_or_local_url=False,
    )
    return facts


def _read_p7_manifest(evidence_root: Path) -> dict[str, Any]:
    manifest_path = evidence_root / "release-evidence.manifest.json"
    if not manifest_path.is_file():
        _fail("P7-008 release evidence manifest missing")
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    return manifest


def stage_release_build(work_root: Path) -> dict[str, object]:
    workflow_name = _env().get("DBF_ACCEPTANCE_WORKFLOW_NAME", "local-deterministic-acceptance")
    run_id = _env().get("DBF_ACCEPTANCE_RUN_ID", "local")
    run_event = _env().get("DBF_ACCEPTANCE_RUN_EVENT", "local")
    evidence_root = work_root / "p7-evidence"
    code = _run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "build_release_evidence.py"),
            "--output-dir",
            str(evidence_root),
            "--workflow-name",
            workflow_name,
            "--run-id",
            run_id,
            "--run-event",
            run_event,
        ]
    )
    if code != 0:
        _fail(f"reproducible release evidence build failed (exit {code})")
    p7 = _read_p7_manifest(evidence_root)
    if p7["tamper_detection_selftest"]["result"] != "PASS":
        _fail("release evidence tamper self-test did not pass")
    digest_sidecar = (
        (evidence_root / "release-evidence.manifest.sha256").read_text(encoding="utf-8").split()
    )
    if len(digest_sidecar) != 2:
        _fail("unexpected release-evidence digest sidecar layout")
    digest = digest_sidecar[0]
    code, _ = _run_json(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "verify_release_evidence.py"),
            "--manifest",
            str(evidence_root / "release-evidence.manifest.json"),
            "--evidence-root",
            str(evidence_root),
            "--expected-manifest-sha256",
            digest,
        ]
    )
    if code != 0:
        _fail("independent release-evidence verifier rejected the bundle")
    wheel_name = str(p7["artifacts"]["wheel"]["filename"])
    sdist_name = str(p7["artifacts"]["sdist"]["filename"])
    wheel_sha = str(p7["artifacts"]["wheel"]["sha256"])
    sdist_sha = str(p7["artifacts"]["sdist"]["sha256"])
    candidate_dir = work_root / CANDIDATE_DIRECTORY
    candidate_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(evidence_root / wheel_name, candidate_dir / Path(wheel_name).name)
    shutil.copyfile(evidence_root / sdist_name, candidate_dir / Path(sdist_name).name)
    if _sha256(candidate_dir / Path(wheel_name).name) != wheel_sha:
        _fail("copied release candidate wheel hash drift")
    if _sha256(candidate_dir / Path(sdist_name).name) != sdist_sha:
        _fail("copied release candidate sdist hash drift")
    provenance: dict[str, Any] = p7["dependency_provenance"]
    dbfbridge_entries = [
        entry
        for entry in provenance["wheelhouse_artifacts"]
        if "dbfbridge" in str(entry["filename"])
    ]
    if len(dbfbridge_entries) != 1:
        _fail("exactly one dbfbridge wheelhouse artifact expected")
    return {
        "wheel_filename": wheel_name,
        "wheel_sha256": wheel_sha,
        "sdist_filename": sdist_name,
        "sdist_sha256": sdist_sha,
        "release_evidence_manifest_sha256": digest,
        "reproducible_two_build_evidence": "PASS",
        "tamper_selftest": "PASS",
        "independent_verifier": "PASS",
        "wheelhouse_dbfbridge": dbfbridge_entries[0],
        "release_candidate_copied": True,
        "release_candidate_hashes_reverified": True,
    }


def stage_offline_fresh_wheel(work_root: Path) -> dict[str, object]:
    from tools.check_p7_offline_wheelhouse import validate_wheelhouse

    evidence_root = work_root / "p7-evidence"
    p7 = _read_p7_manifest(evidence_root)
    wheel_name = str(p7["artifacts"]["wheel"]["filename"])
    wheelhouse = work_root / "wheelhouse"
    if wheelhouse.exists():
        shutil.rmtree(wheelhouse)
    shutil.copytree(evidence_root / "wheelhouse", wheelhouse)
    validate_wheelhouse(WHEELHOUSE_MANIFEST, wheelhouse)
    venv_dir = work_root / "acceptance-venv"
    if venv_dir.exists():
        shutil.rmtree(venv_dir)
    code = _run([sys.executable, "-m", "venv", str(venv_dir)])
    if code != 0:
        _fail(f"fresh venv creation failed (exit {code})")
    venv_python = _acceptance_python(work_root)
    preparation_env = _env()
    preparation_env["PIP_NO_CACHE_DIR"] = "1"
    code = _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "-r",
            str(WHEELHOUSE_MANIFEST),
        ],
        env=preparation_env,
    )
    if code != 0:
        _fail(f"offline wheelhouse install failed (exit {code})")
    code = _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-cache-dir",
            "--no-deps",
            str(evidence_root / wheel_name),
        ]
    )
    if code != 0:
        _fail(f"exact release wheel install failed (exit {code})")
    facts = _command_facts(
        [
            ("pip_check", [str(venv_python), "-m", "pip", "check"]),
            (
                "acceptance_pin",
                [str(venv_python), str(REPO_ROOT / "tools" / "check_acceptance_pin.py")],
            ),
        ],
        install_mode="NO_INDEX_LOCAL_WHEELHOUSE_ONLY",
        runtime_install_after_preparation="NONE",
        installed_from_exact_release_wheel=Path(wheel_name).name,
    )
    code, identity = _run_json(
        [
            str(venv_python),
            "-c",
            (
                "import importlib.metadata as m, json; d=m.distribution('dbfbridge');"
                "print(json.dumps({'version': m.version('dbfbridge'),"
                "'direct_url': d.read_text('direct_url.json')}))"
            ),
        ]
    )
    if code != 0:
        _fail("fresh-venv dbfbridge identity probe failed")
    fresh: dict[str, Any] = json.loads(identity)
    if fresh["direct_url"] is not None:
        _fail("fresh-venv dbfbridge carries a VCS/local direct URL")
    facts["fresh_dbfbridge_version"] = fresh["version"]
    facts["fresh_dbfbridge_vcs_or_local_url"] = False
    return facts


def stage_installed_wheel_contract(work_root: Path) -> dict[str, object]:
    venv_python = _acceptance_python(work_root)
    return _command_facts(
        [
            (
                "installed_wheel_boundary",
                [str(venv_python), str(REPO_ROOT / "tools" / "check_p7_installed_wheel.py")],
            ),
            (
                "standalone_runtime_contract",
                [
                    str(venv_python),
                    str(REPO_ROOT / "tools" / "check_p7_offline_runtime.py"),
                    "--work-root",
                    str(work_root / "runtime-contract"),
                ],
            ),
        ],
        execution_origin="INSTALLED_SITE_PACKAGES",
    )


def stage_canonical_roundtrip(work_root: Path) -> dict[str, object]:
    venv_python = _acceptance_python(work_root)
    env = _env()
    env["PYTHONPATH"] = str(REPO_ROOT)
    code, output = _run_json(
        [
            str(venv_python),
            str(REPO_ROOT / "tools" / "release_acceptance_roundtrip.py"),
            "--work-root",
            str(work_root / "roundtrip"),
        ],
        env=env,
    )
    if code != 0:
        _fail(f"canonical round trip failed (exit {code})")
    payload: dict[str, Any] = json.loads(output)
    if payload.get("status") != "PASS":
        _fail("canonical round trip reported non-PASS")
    facts: dict[str, object] = dict(payload["facts"])
    if facts["network_attempts"] != 0 or facts["process_attempts"] != 0:
        _fail("offline sentinels observed forbidden runtime activity")
    return facts


def stage_no_vfp_standalone(work_root: Path) -> dict[str, object]:
    venv_python = _acceptance_python(work_root)
    code = _run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "check_p7_no_vfp_smoke.py"),
            "--python",
            str(venv_python),
        ]
    )
    if code != 0:
        _fail(f"no-VFP standalone smoke failed (exit {code})")
    return {"no_vfp_path": "PASSED_WITHOUT_VFP", "trusted_vfp_not_required": True}


STAGES = (
    ("source_binding", stage_source_binding),
    ("quality_gates", stage_quality_gates),
    ("public_contract_freeze", stage_public_contract_freeze),
    ("dependency_audit", stage_dependency_audit),
    ("release_build", stage_release_build),
    ("offline_fresh_wheel", stage_offline_fresh_wheel),
    ("installed_wheel_contract", stage_installed_wheel_contract),
    ("canonical_roundtrip", stage_canonical_roundtrip),
    ("no_vfp_standalone", stage_no_vfp_standalone),
)


def _fact(stages: dict[str, StageResult], name: str, key: str, default: object = None) -> object:
    result = stages.get(name)
    if result is None:
        return default
    return result.facts.get(key, default)


def build_manifest(stages: dict[str, StageResult], bind: dict[str, Any]) -> dict[str, object]:
    stage_view: dict[str, object] = {name: result.as_dict() for name, result in stages.items()}
    vfp_declared = bool(bind.get("trusted_vfp_runtime_declared", False))

    def status_of(name: str) -> str:
        return stages.get(name, StageResult(name, "NOT_RUN", {})).status

    quality_status = status_of("quality_gates")
    freeze_status = status_of("public_contract_freeze")
    roundtrip_status = status_of("canonical_roundtrip")
    no_vfp_status = status_of("no_vfp_standalone")
    wheel_install_ok = (
        status_of("offline_fresh_wheel") == "PASS"
        and status_of("installed_wheel_contract") == "PASS"
    )
    roundtrip_ok = roundtrip_status == "PASS"
    relationship_status = (
        "PASS"
        if roundtrip_ok
        and _fact(stages, "canonical_roundtrip", "assurance_level") == "DECLARED_RELATIONS_VERIFIED"
        else "FAIL"
    )
    transfer_status = (
        "PASS"
        if roundtrip_ok and _fact(stages, "canonical_roundtrip", "standalone_verified") is True
        else "FAIL"
    )
    forbidden_status = (
        "PASS"
        if roundtrip_ok
        and _fact(stages, "canonical_roundtrip", "forbidden_basenames_absent") is True
        and _fact(stages, "canonical_roundtrip", "bundle_allowlist_ok") is True
        and _fact(stages, "canonical_roundtrip", "canaries_absent_in_bundle") is True
        else "FAIL"
    )
    offline_status = (
        "PASS"
        if roundtrip_ok
        and _fact(stages, "canonical_roundtrip", "network_attempts") == 0
        and _fact(stages, "canonical_roundtrip", "process_attempts") == 0
        and status_of("installed_wheel_contract") == "PASS"
        else "FAIL"
    )
    final = (
        "PASS"
        if len(stages) == len(STAGES)
        and all(result.status == "PASS" for result in stages.values())
        and quality_status == "PASS"
        and freeze_status == "PASS"
        and wheel_install_ok
        and roundtrip_ok
        and relationship_status == "PASS"
        and transfer_status == "PASS"
        and forbidden_status == "PASS"
        and offline_status == "PASS"
        and no_vfp_status == "PASS"
        else "FAIL"
    )
    wheelhouse_entry = _fact(stages, "release_build", "wheelhouse_dbfbridge")
    wheelhouse_entry = wheelhouse_entry if isinstance(wheelhouse_entry, dict) else {}
    manifest: dict[str, object] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": MANIFEST_KIND,
        "requirement": "REQ-P8-002",
        "entry_point": ENTRY_POINT,
        "source_commit": bind.get("source_commit"),
        "package_version": bind.get("package_version"),
        "python_version": bind.get("python_version"),
        "platform": bind.get("platform"),
        "release_candidate": {
            "wheel_filename": _fact(stages, "release_build", "wheel_filename"),
            "wheel_sha256": _fact(stages, "release_build", "wheel_sha256"),
            "sdist_filename": _fact(stages, "release_build", "sdist_filename"),
            "sdist_sha256": _fact(stages, "release_build", "sdist_sha256"),
            "release_evidence_manifest_sha256": _fact(
                stages, "release_build", "release_evidence_manifest_sha256"
            ),
            "reproducible_two_build_evidence": _fact(
                stages, "release_build", "reproducible_two_build_evidence", "NOT_RUN"
            ),
            "tamper_selftest": _fact(stages, "release_build", "tamper_selftest", "NOT_RUN"),
            "independent_verifier": _fact(stages, "release_build", "independent_verifier"),
        },
        "public_contract": {
            "filename": "contracts/public-contract-1.0.json",
            "sha256": bind.get("public_contract_sha256"),
            "freeze_test": freeze_status,
            "snapshot_auto_update": "NEVER",
        },
        "dbfbridge_provenance": {
            "runtime_requirement": RUNTIME_REQUIREMENT,
            "acceptance_pin": bind.get("acceptance_pin"),
            "installed_version_main": bind.get("installed_dbfbridge_main"),
            "installed_version_fresh": _fact(
                stages, "offline_fresh_wheel", "fresh_dbfbridge_version"
            ),
            "wheelhouse_artifact": wheelhouse_entry.get("filename"),
            "wheelhouse_sha256": wheelhouse_entry.get("sha256"),
            "origin": "PUBLIC_PYPI_OFFLINE_WHEELHOUSE",
            "vcs_url": None,
            "local_path_dependency": False,
        },
        "stages": stage_view,
        "quality_gate_status": quality_status,
        "wheel_install_status": "PASS" if wheel_install_ok else "FAIL",
        "canonical_roundtrip_status": roundtrip_status,
        "relationship_status": relationship_status,
        "transfer_bundle_status": transfer_status,
        "forbidden_material_status": forbidden_status,
        "offline_status": offline_status,
        "no_vfp_standalone_status": no_vfp_status,
        "vfp_evidence_status": (
            VFP_STATUS_NO_RUN if not vfp_declared else VFP_STATUS_AVAILABLE_NOT_REQUIRED
        ),
        "vfp_evidence": {
            "status": VFP_STATUS_NO_RUN if not vfp_declared else VFP_STATUS_AVAILABLE_NOT_REQUIRED,
            "trusted_real_vfp9_runtime_declared": vfp_declared,
            "capabilities_vfp_index_backend": _fact(
                stages, "canonical_roundtrip", "capabilities_vfp_index_backend"
            ),
            "real_vfp9_execution_claimed": False,
            "trusted_lane": "p6-trusted-vfp-acceptance.yml (workflow_dispatch main-only)",
        },
        "final_status": final,
    }
    return manifest


def _write_manifest(output_dir: Path, manifest: dict[str, object]) -> str:
    serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    manifest_path = output_dir / MANIFEST_FILENAME
    manifest_path.write_text(serialized, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    (output_dir / MANIFEST_DIGEST_SIDECAR).write_text(digest + "\n", encoding="utf-8", newline="\n")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in (
        "p7-evidence",
        "wheelhouse",
        "acceptance-venv",
        CANDIDATE_DIRECTORY,
        "runtime-contract",
        "roundtrip",
    ):
        stale_path = output_dir / stale
        if stale_path.exists():
            shutil.rmtree(stale_path)

    stages: dict[str, StageResult] = {}
    bind: dict[str, Any] = {}
    for name, runner in STAGES:
        try:
            facts = runner(output_dir)
        except Exception as error:  # noqa: BLE001 - fail-closed aggregation, no fail-open
            stages[name] = StageResult(name, "FAIL", {"error": type(error).__name__})
            break
        stages[name] = StageResult(name, "PASS", facts)
        if name == "source_binding":
            bind.update(
                {
                    "source_commit": facts["source_commit"],
                    "package_version": facts["package_version"],
                    "python_version": facts["python_version"],
                    "platform": facts["platform"],
                    "public_contract_sha256": facts["public_contract_sha256"],
                    "installed_dbfbridge_main": facts["installed_dbfbridge"],
                    "trusted_vfp_runtime_declared": (
                        _env().get("DBF_ANONYMIZER_REAL_VFP9_AVAILABLE") == "1"
                    ),
                }
            )
        if name == "dependency_audit":
            bind["acceptance_pin"] = facts["acceptance_pin"]

    complete = len(stages) == len(STAGES) and all(key in bind for key in _BIND_KEYS)
    manifest = build_manifest(stages, bind)
    digest = _write_manifest(output_dir, manifest)
    final = str(manifest["final_status"])
    print(
        json.dumps(
            {
                "final_status": final,
                "manifest": MANIFEST_FILENAME,
                "manifest_sha256": digest,
                "stages_completed": len(stages),
            },
            sort_keys=True,
        )
    )
    return 0 if final == "PASS" and complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
