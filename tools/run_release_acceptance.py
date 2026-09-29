"""REQ-P8-002 one-command release acceptance (maintainer and CI entry point).

Executes the complete release acceptance for one exact source revision from a
clean commit and produces the machine-readable release-acceptance evidence
manifest plus its SHA-256 sidecar in a PUBLISHABLE output directory, while
all private/ephemeral acceptance work happens in a separate task-owned work
root:

    PRIVATE WORK ROOT (--work-root, never uploaded):
      p7-evidence/ wheelhouse/ acceptance-venv/ roundtrip/ runtime-contract/
    PUBLISHABLE OUTPUT (--output-dir, the only uploaded artifact):
      release-acceptance-evidence.json + .sha256 sidecar + release-candidate/

Stages:

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
                              executed from the INSTALLED wheel under sentinels,
                              with an objective import-origin proof that fails
                              closed unless ``dbf_anonymizer`` resolves from the
                              acceptance venv site-packages (never from the
                              source checkout, editable install or PYTHONPATH)
 9. no_vfp_standalone         hosted no-VFP import-purity + standalone smoke

ONLINE PREPARATION covers stages 1-6 (including the PyPI wheelhouse download
performed by the accepted P7-008 evidence tool).  The OFFLINE RUNTIME
ACCEPTANCE phase covers stages 7-9: local wheels only, ``--no-index``,
``--no-cache-dir``, no runtime HTTP, no Git and no package installation
after the environment has been prepared.

Mandatory platform/security gates (REQ-P7-006 contract: every declared
Windows Python version plus the pip-audit advisory audit) are enforced in the
authoritative CI release-acceptance workflow: the Windows matrix and the
security audit are jobs of the SAME workflow and their ``needs.*.result``
values are passed into this command as privacy-safe environment indicators.
The manifest records them truthfully.  Without those indicators (an ordinary
maintainer invocation) the command truthfully reports
``final_status: LOCAL_PRECHECK`` — never a release-candidate PASS.

Fail-closed: any failed stage makes ``final_status`` FAIL and the command
exits non-zero.  A failing test NEVER regenerates any snapshot or evidence.

Usage (maintainer):
    python tools/run_release_acceptance.py ^
        --work-root   build/p8-release-acceptance-work ^
        --output-dir  build/p8-release-acceptance-publishable
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
import tempfile
from importlib import metadata
from pathlib import Path
from typing import Any

try:  # package context (pytest import) ...
    from tools.acceptance_fixtures import BINARY_CANARIES, TEXT_CANARIES
except ImportError:  # ... or direct script execution from the tools directory
    from acceptance_fixtures import BINARY_CANARIES, TEXT_CANARIES  # type: ignore[no-redef]

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

WINDOWS_MATRIX_VARIABLE = "DBF_MANDATORY_WINDOWS_MATRIX_RESULT"
SECURITY_AUDIT_VARIABLE = "DBF_MANDATORY_SECURITY_AUDIT_RESULT"
GATES_SOURCE_CI = "GITHUB_WORKFLOW_NEEDS"
GATES_SOURCE_LOCAL = "LOCAL_MAINTAINER_PRECHECK"

PRIVATE_WORK_SUBDIRS = (
    "p7-evidence",
    "wheelhouse",
    "acceptance-venv",
    "runtime-contract",
    "roundtrip",
)

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


class AcceptancePaths:
    """Private (ephemeral) work root and publishable output directory."""

    def __init__(self, work_root: Path, output_dir: Path) -> None:
        self.work_root = work_root
        self.output_dir = output_dir

    @property
    def p7_evidence(self) -> Path:
        return self.work_root / "p7-evidence"

    @property
    def wheelhouse(self) -> Path:
        return self.work_root / "wheelhouse"

    @property
    def acceptance_venv(self) -> Path:
        return self.work_root / "acceptance-venv"

    @property
    def roundtrip(self) -> Path:
        return self.work_root / "roundtrip"

    @property
    def runtime_contract(self) -> Path:
        return self.work_root / "runtime-contract"

    @property
    def candidate(self) -> Path:
        return self.output_dir / CANDIDATE_DIRECTORY

    def acceptance_python(self) -> Path:
        candidate = self.acceptance_venv / "Scripts" / "python.exe"
        if not candidate.is_file():
            candidate = self.acceptance_venv / "bin" / "python"
        if not candidate.is_file():
            _fail("acceptance venv missing; the offline fresh-wheel stage must run first")
        return candidate


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _env() -> dict[str, str]:
    return dict(os.environ)


def _fail(message: str) -> None:
    raise RuntimeError(message)


def _run(command: list[str], *, cwd: Path = REPO_ROOT, env: dict[str, str] | None = None) -> int:
    completed = subprocess.run(  # noqa: S603 - fixed maintainer tool arguments
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
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


def _wheelhouse_install_command(
    venv_python: Path, wheelhouse: Path, wheelhouse_manifest: Path
) -> list[str]:
    """Offline wheelhouse closure install (no index, no cache)."""
    return [
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        "--no-cache-dir",
        "-r",
        str(wheelhouse_manifest),
    ]


def _wheel_install_command(venv_python: Path, wheel_path: Path) -> list[str]:
    """Exact release-wheel install (no index, no cache, no deps)."""
    return [
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-cache-dir",
        "--no-deps",
        str(wheel_path),
    ]


def _sanitized_roundtrip_environment() -> dict[str, str]:
    """Environment for the installed-wheel round trip: no repository paths.

    The repository root is removed from ``PYTHONPATH`` and ``NO_PROXY``-style
    hygiene is preserved otherwise.  The child never receives a PYTHONPATH
    entry that points into the source checkout.
    """
    env = _env()
    pythonpath = env.get("PYTHONPATH", "")
    kept = [
        entry
        for entry in pythonpath.split(os.pathsep)
        if entry and Path(entry).resolve() != REPO_ROOT.resolve()
    ]
    if kept:
        env["PYTHONPATH"] = os.pathsep.join(kept)
    else:
        env.pop("PYTHONPATH", None)
    return env


def _roundtrip_cwd(work_root: Path) -> Path:
    """Task-owned working directory OUTSIDE the repository for the child."""
    if REPO_ROOT.resolve() not in work_root.resolve().parents:
        work_root.mkdir(parents=True, exist_ok=True)
        return work_root

    return Path(tempfile.mkdtemp(prefix="dbf-p8-roundtrip-cwd-"))


def stage_source_binding(paths: AcceptancePaths) -> dict[str, object]:
    del paths
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


def stage_quality_gates(paths: AcceptancePaths) -> dict[str, object]:
    del paths
    return _command_facts(
        [
            ("ruff_format", [sys.executable, "-m", "ruff", "format", "--check", "."]),
            ("ruff_lint", [sys.executable, "-m", "ruff", "check", "."]),
            ("mypy_strict", [sys.executable, "-m", "mypy", "--strict", "src/dbf_anonymizer"]),
            ("compileall", [sys.executable, "-m", "compileall", "-q", "src", "tests", "tools"]),
            ("full_test_suite", [sys.executable, "-m", "pytest", "-ra"]),
        ]
    )


def stage_public_contract_freeze(paths: AcceptancePaths) -> dict[str, object]:
    del paths
    code = _run([sys.executable, "-m", "pytest", "tests/test_p8_contract_freeze.py", "-ra"])
    if code != 0:
        _fail(f"REQ-P8-001 contract freeze test failed (exit {code}); snapshot not regenerated")
    return {
        "freeze_test": "PASS",
        "public_contract_sha256": _sha256(CONTRACT_SNAPSHOT),
        "snapshot_auto_update": "NEVER",
    }


def stage_dependency_audit(paths: AcceptancePaths) -> dict[str, object]:
    del paths
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


def _read_p7_manifest(paths: AcceptancePaths) -> dict[str, Any]:
    manifest_path = paths.p7_evidence / "release-evidence.manifest.json"
    if not manifest_path.is_file():
        _fail("P7-008 release evidence manifest missing")
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    return manifest


def stage_release_build(paths: AcceptancePaths) -> dict[str, object]:
    workflow_name = _env().get("DBF_ACCEPTANCE_WORKFLOW_NAME", "local-deterministic-acceptance")
    run_id = _env().get("DBF_ACCEPTANCE_RUN_ID", "local")
    run_event = _env().get("DBF_ACCEPTANCE_RUN_EVENT", "local")
    code = _run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "build_release_evidence.py"),
            "--output-dir",
            str(paths.p7_evidence),
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
    p7 = _read_p7_manifest(paths)
    if p7["tamper_detection_selftest"]["result"] != "PASS":
        _fail("release evidence tamper self-test did not pass")
    digest_parts = (
        (paths.p7_evidence / "release-evidence.manifest.sha256").read_text(encoding="utf-8").split()
    )
    if len(digest_sidecar := digest_parts) != 2:
        _fail("unexpected release-evidence digest sidecar layout")
    digest = digest_sidecar[0]
    code, _ = _run_json(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "verify_release_evidence.py"),
            "--manifest",
            str(paths.p7_evidence / "release-evidence.manifest.json"),
            "--evidence-root",
            str(paths.p7_evidence),
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
    paths.candidate.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(paths.p7_evidence / wheel_name, paths.candidate / Path(wheel_name).name)
    shutil.copyfile(paths.p7_evidence / sdist_name, paths.candidate / Path(sdist_name).name)
    if _sha256(paths.candidate / Path(wheel_name).name) != wheel_sha:
        _fail("copied release candidate wheel hash drift")
    if _sha256(paths.candidate / Path(sdist_name).name) != sdist_sha:
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


def stage_offline_fresh_wheel(paths: AcceptancePaths) -> dict[str, object]:
    try:
        from tools.check_p7_offline_wheelhouse import validate_wheelhouse
    except ImportError:  # direct script execution from the tools directory
        from check_p7_offline_wheelhouse import validate_wheelhouse

    p7 = _read_p7_manifest(paths)
    wheel_name = str(p7["artifacts"]["wheel"]["filename"])
    if paths.wheelhouse.exists():
        shutil.rmtree(paths.wheelhouse)
    shutil.copytree(paths.p7_evidence / "wheelhouse", paths.wheelhouse)
    validate_wheelhouse(WHEELHOUSE_MANIFEST, paths.wheelhouse)
    if paths.acceptance_venv.exists():
        shutil.rmtree(paths.acceptance_venv)
    code = _run([sys.executable, "-m", "venv", str(paths.acceptance_venv)])
    if code != 0:
        _fail(f"fresh venv creation failed (exit {code})")
    venv_python = paths.acceptance_python()
    preparation_env = _env()
    preparation_env["PIP_NO_CACHE_DIR"] = "1"
    code = _run(
        _wheelhouse_install_command(venv_python, paths.wheelhouse, WHEELHOUSE_MANIFEST),
        env=preparation_env,
    )
    if code != 0:
        _fail(f"offline wheelhouse install failed (exit {code})")
    code = _run(_wheel_install_command(venv_python, paths.p7_evidence / wheel_name))
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
        pip_cache="DISABLED_NO_CACHE_DIR",
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


def stage_installed_wheel_contract(paths: AcceptancePaths) -> dict[str, object]:
    venv_python = paths.acceptance_python()
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
                    str(paths.runtime_contract),
                ],
            ),
        ],
        execution_origin="INSTALLED_SITE_PACKAGES",
    )


def stage_canonical_roundtrip(paths: AcceptancePaths) -> dict[str, object]:
    venv_python = paths.acceptance_python()
    env = _sanitized_roundtrip_environment()
    code, output = _run_json(
        [
            str(venv_python),
            str(REPO_ROOT / "tools" / "release_acceptance_roundtrip.py"),
            "--work-root",
            str(paths.roundtrip),
            "--expected-version",
            _package_version(),
            "--require-installed-origin",
        ],
        cwd=_roundtrip_cwd(paths.work_root),
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
    if facts["installed_wheel_origin_verified"] is not True:
        _fail("canonical round trip did not prove the installed-wheel import origin")
    return facts


def stage_no_vfp_standalone(paths: AcceptancePaths) -> dict[str, object]:
    venv_python = paths.acceptance_python()
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


def _mandatory_gate_statuses() -> dict[str, object]:
    """Truthful Windows/security gate statuses from workflow-controlled inputs."""
    windows = _env().get(WINDOWS_MATRIX_VARIABLE)
    security = _env().get(SECURITY_AUDIT_VARIABLE)
    if windows is None and security is None:
        return {
            "execution_context": "LOCAL_PRECHECK",
            "windows_python_matrix": "NOT_RUN_LOCAL_PRECHECK",
            "security_advisory_audit": "NOT_RUN_LOCAL_PRECHECK",
            "gates_source": "LOCAL_MAINTAINER_PRECHECK",
        }
    return {
        "execution_context": "CI_RELEASE_ACCEPTANCE",
        "windows_python_matrix": "PASS" if windows == "success" else "FAIL",
        "security_advisory_audit": "PASS" if security == "success" else "FAIL",
        "gates_source": GATES_SOURCE_CI,
    }


def assert_publishable_hygiene(output_dir: Path) -> dict[str, object]:
    """Fail-closed publishable-artifact hygiene (privacy-safe allowlist only)."""
    files = [
        path.relative_to(output_dir).as_posix()
        for path in sorted(output_dir.rglob("*"))
        if path.is_file()
    ]
    allowlisted = (
        {
            MANIFEST_FILENAME,
            MANIFEST_DIGEST_SIDECAR,
        }
        | {
            f"{CANDIDATE_DIRECTORY}/{name}"
            for name in (
                "dbf_anonymizer-1.0.0.dev0-py3-none-any.whl",
                "dbf_anonymizer-1.0.0.dev0.tar.gz",
            )
        }
        | {f"{CANDIDATE_DIRECTORY}/{name}" for name in _candidate_names()}
    )
    allowlist_ok = all(name in allowlisted for name in files)
    forbidden_fragments = (
        "dictionary.sqlite3",
        "recovery.sqlite3",
        ".sqlite3-wal",
        ".sqlite3-shm",
        ".sqlite3-journal",
        "oracle",
        "recovered",
        "acceptance-venv",
        "wheelhouse",
        "runtime-contract",
        "roundtrip",
        "protected",
    )
    forbidden_absent = not any(
        fragment in name.lower() for name in files for fragment in forbidden_fragments
    )
    evidence_files = [output_dir / name for name in files if name.endswith((".json", ".sha256"))]
    canaries_absent = not any(
        canary in path.read_bytes() for path in evidence_files for canary in _content_canaries()
    )
    absolute_paths_absent = not any(
        _has_absolute_machine_path(path.read_text(encoding="utf-8"))
        for path in evidence_files
        if path.suffix == ".json"
    )
    return {
        "hygiene": "PASS"
        if allowlist_ok and forbidden_absent and canaries_absent and absolute_paths_absent
        else "FAIL",
        "publishable_file_count": len(files),
        "publishable_files": files,
        "allowlist_ok": allowlist_ok,
        "forbidden_artifacts_absent": forbidden_absent,
        "canaries_absent": canaries_absent,
        "absolute_private_paths_absent": absolute_paths_absent,
    }


def _content_canaries() -> tuple[bytes, ...]:
    text = [canary.encode("utf-8") for canary in TEXT_CANARIES]
    return tuple(text) + tuple(BINARY_CANARIES)


def _has_absolute_machine_path(text: str) -> bool:
    import re

    return re.search(r"[A-Za-z]:[\\/]", text) is not None


def _candidate_names() -> tuple[str, ...]:
    wheel = _env().get("DBF_ACCEPTANCE_WHEEL_FILENAME")
    sdist = _env().get("DBF_ACCEPTANCE_SDIST_FILENAME")
    if wheel and sdist:
        return (Path(wheel).name, Path(sdist).name)
    return ()


def _manifest_content_hygiene(serialized: str) -> bool:
    """The serialized manifest must contain no canary values and no machine paths."""
    lowered = serialized.lower()
    canaries_absent = not any(canary in lowered for canary in TEXT_CANARIES)
    binary_absent = not any(
        canary.decode("utf-8", "ignore") in serialized for canary in BINARY_CANARIES
    )
    return canaries_absent and binary_absent and not _has_absolute_machine_path(serialized)


def build_manifest(
    stages: dict[str, StageResult],
    bind: dict[str, Any],
    mandatory: dict[str, object],
    hygiene: dict[str, object],
) -> dict[str, object]:
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
    origin_ok = (
        roundtrip_ok
        and _fact(stages, "canonical_roundtrip", "installed_wheel_origin_verified") is True
        and _fact(stages, "canonical_roundtrip", "repository_source_shadowing") is False
    )
    ubuntu_full_acceptance = (
        "PASS"
        if quality_status == "PASS"
        and roundtrip_ok
        and no_vfp_status == "PASS"
        and wheel_install_ok
        and origin_ok
        else "FAIL"
    )
    windows_ok = mandatory["windows_python_matrix"] == "PASS"
    security_ok = mandatory["security_advisory_audit"] == "PASS"
    hygiene_ok = hygiene.get("hygiene") == "PASS"
    internal_ok = (
        len(stages) == len(STAGES)
        and all(result.status == "PASS" for result in stages.values())
        and quality_status == "PASS"
        and freeze_status == "PASS"
        and wheel_install_ok
        and roundtrip_ok
        and relationship_status == "PASS"
        and transfer_status == "PASS"
        and forbidden_status == "PASS"
        and offline_status == "PASS"
        and origin_ok
        and no_vfp_status == "PASS"
        and ubuntu_full_acceptance == "PASS"
        and hygiene_ok
    )
    execution_context = str(mandatory["execution_context"])
    if not internal_ok:
        final = "FAIL"
    elif execution_context == "CI_RELEASE_ACCEPTANCE" and windows_ok and security_ok:
        final = "PASS"
    elif execution_context == "CI_RELEASE_ACCEPTANCE":
        final = "FAIL"
    else:
        final = "LOCAL_PRECHECK"
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
        "execution_context": mandatory["execution_context"],
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
        "installed_wheel_origin": {
            "verified": _fact(stages, "canonical_roundtrip", "installed_wheel_origin_verified")
            is True,
            "repository_source_shadowing": _fact(
                stages, "canonical_roundtrip", "repository_source_shadowing"
            )
            is True,
            "import_origin": _fact(stages, "canonical_roundtrip", "import_origin"),
            "pythonpath_contains_repo_root": _fact(
                stages, "canonical_roundtrip", "repo_root_in_pythonpath"
            ),
            "sys_path_contains_repo_root": _fact(
                stages, "canonical_roundtrip", "repo_root_in_sys_path"
            ),
            "cwd_outside_repository": _fact(
                stages, "canonical_roundtrip", "cwd_outside_repository"
            ),
        },
        "mandatory_quality_gates": {
            "windows_python_matrix": mandatory["windows_python_matrix"],
            "security_advisory_audit": mandatory["security_advisory_audit"],
            "ubuntu_full_acceptance": ubuntu_full_acceptance,
            "gates_source": mandatory["gates_source"],
        },
        "publishable_artifact": {
            "hygiene": hygiene.get("hygiene"),
            "publishable_file_count": hygiene.get("publishable_file_count"),
            "allowlist_ok": hygiene.get("allowlist_ok"),
            "forbidden_artifacts_absent": hygiene.get("forbidden_artifacts_absent"),
            "canaries_absent": hygiene.get("canaries_absent"),
            "absolute_private_paths_absent": hygiene.get("absolute_private_paths_absent"),
            "private_work_root_scope": "NOT_PUBLISHED",
        },
        "stages": stage_view,
        "quality_gate_status": quality_status,
        "wheel_install_status": "PASS" if wheel_install_ok else "FAIL",
        "canonical_roundtrip_status": roundtrip_status,
        "relationship_status": relationship_status,
        "transfer_bundle_status": transfer_status,
        "forbidden_material_status": forbidden_status,
        "offline_status": offline_status,
        "installed_wheel_origin_status": "PASS" if origin_ok else "FAIL",
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


def _stale_cleanup(paths: AcceptancePaths) -> None:
    for directory in PRIVATE_WORK_SUBDIRS:
        stale = paths.work_root / directory
        if stale.exists():
            shutil.rmtree(stale)
    for stale in (
        paths.candidate,
        paths.output_dir / MANIFEST_FILENAME,
        paths.output_dir / MANIFEST_DIGEST_SIDECAR,
    ):
        if stale.is_dir():
            shutil.rmtree(stale)
        elif stale.exists():
            stale.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    paths = AcceptancePaths(work_root=args.work_root, output_dir=args.output_dir)
    paths.work_root.mkdir(parents=True, exist_ok=True)
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    _stale_cleanup(paths)

    stages: dict[str, StageResult] = {}
    bind: dict[str, Any] = {}
    for name, runner in STAGES:
        try:
            facts = runner(paths)
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
        if name == "release_build":
            _env()["DBF_ACCEPTANCE_WHEEL_FILENAME"] = str(facts["wheel_filename"])
            _env()["DBF_ACCEPTANCE_SDIST_FILENAME"] = str(facts["sdist_filename"])

    mandatory = _mandatory_gate_statuses()
    complete = len(stages) == len(STAGES) and all(key in bind for key in _BIND_KEYS)
    if complete:
        hygiene = assert_publishable_hygiene(paths.output_dir)
        manifest = build_manifest(stages, bind, mandatory, hygiene)
        serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        if not _manifest_content_hygiene(serialized):
            manifest["publishable_artifact"]["hygiene"] = "FAIL"  # type: ignore[index]
            manifest["final_status"] = "FAIL"  # type: ignore[index]
            serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        digest = _write_manifest(paths.output_dir, manifest)
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
        return 0 if final in {"PASS", "LOCAL_PRECHECK"} else 1
    print(
        json.dumps(
            {
                "final_status": "FAIL",
                "manifest": MANIFEST_FILENAME,
                "stages_completed": len(stages),
            },
            sort_keys=True,
        )
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
