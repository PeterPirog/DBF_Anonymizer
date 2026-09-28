"""REQ-P7-008 release evidence builder.

Produces the objective release evidence bundle for one exact source revision,
bound to the exact Git commit object:

0. FAIL-CLOSED SOURCE CLEANLINESS: the repository working tree must be
   objectively clean (``git status --porcelain=v1 --untracked-files=all``
   output must be empty: no modified/staged/deleted/renamed/conflicted tracked
   files and no non-ignored untracked files).  There is no --allow-dirty
   escape hatch.
1. EXACT COMMIT EXPORT: the recorded commit (``git rev-parse HEAD``) is
   exported via ``git archive --format=tar`` into a uniquely owned task TEMP
   tree.  BOTH independent builds run from that exported committed snapshot —
   never from the mutable working directory — so no working-tree or untracked
   content can enter the release artifact while the manifest still records
   clean HEAD as the source.
2. TWO independent, clean, task-owned build directories each run the standard
   ``python -m build --sdist`` against the exported source (isolated backend
   environments constrained by requirements/p7-release-build-constraints.txt
   and a fixed SOURCE_DATE_EPOCH derived from the same exact commit).
3. Each sdist is canonically rewritten for determinism (metadata-only
   normalization: GNU tar format, every member mtime = SOURCE_DATE_EPOCH,
   uid/gid = 0, empty uname/gname, normalized modes, members sorted by name,
   gzip mtime = SOURCE_DATE_EPOCH). File contents are never altered.
4. The wheel is built FROM the canonicalized sdist (``python -m build --wheel
   <sdist>``) with SOURCE_DATE_EPOCH, so the wheel provably derives from the
   exact release sdist.
5. The final sdist and wheel SHA-256 values of both independent builds MUST be
   equal; any difference aborts the run (fail-closed).
6. The exact runtime wheelhouse (requirements/p7-offline-wheelhouse.txt from
   the exported commit) is downloaded from public PyPI; every artifact
   filename + SHA-256 is recorded.
7. Distribution metadata is validated: twine check, wheel metadata/content
   gate (tools/check_wheel_metadata.py) and the sdist PKG-INFO identity.
8. Fresh-wheel smoke: a fresh venv OUTSIDE the repository working tree
   installs the pinned dbfbridge acceptance closure from the evidence
   wheelhouse (--no-index) plus the EXACT release wheel (--no-deps), then runs
   pip check, the pinned-acceptance check (tools/check_acceptance_pin.py),
   the installed-wheel contract (tools/check_p7_installed_wheel.py) and the
   full nine-command standalone runtime contract
   (tools/check_p7_offline_runtime.py) with network/process sentinels.
9. A deterministic CycloneDX 1.5 SBOM (tools/generate_release_sbom.py) covers
   the release closure and is hashed into the manifest.
10. A deterministic machine-readable release evidence manifest (schema 1.0)
   is written, recording the exact commit SHA, the cleanliness result and the
   source-export protocol.  AFTER the manifest reaches its final form, its
   SHA-256 is written to release-evidence.manifest.sha256 (no recursive
   self-hash inside the JSON).  The fail-closed verifier
   (tools/verify_release_evidence.py) must then accept the bundle WITH the
   trusted expected digest, and a tamper self-test proves the verifier rejects
   tampered copies (artifact, SBOM, manifest hash, private-path injection,
   coherent artifact+manifest substitution against the trusted digest).

The tool prints the release identity (commit SHA, version, Python/build-tool
versions, architecture SHA-256, artifact filenames and hashes, manifest
digest) and exits non-zero on any failure. It is release/dev tooling only: no
runtime behavior of dbf-anonymizer is altered and no SBOM tooling becomes a
runtime dependency.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.check_p7_offline_wheelhouse import validate_wheelhouse  # noqa: E402
from tools.generate_release_sbom import (  # noqa: E402
    _sdist_identity,
    _wheel_identity,
    build_sbom,
    render_sbom,
)

ARCHITECTURE_SHA256 = "483932970d44770b05fcfad7430b85820d771458110f004b0397bd5d56398615"
ACCEPTANCE_PIN = "requirements/p0-dbfbridge-tested.txt"
WHEELHOUSE_MANIFEST = "requirements/p7-offline-wheelhouse.txt"
BUILD_CONSTRAINTS = "requirements/p7-release-build-constraints.txt"
EXPECTED_RUNTIME_REQUIREMENT = "dbfbridge[write]>=1.1.0,<2"
MANIFEST_SCHEMA_VERSION = "1.0"
MANIFEST_KIND = "dbf-anonymizer-release-evidence-manifest"
MANIFEST_FILENAME = "release-evidence.manifest.json"
MANIFEST_DIGEST_SIDECAR = "release-evidence.manifest.sha256"
SOURCE_EXPORT_MODE = (
    "git archive --format=tar <recorded-commit> extracted into a task-owned temp "
    "tree; the working directory is not the build source and no .git data is copied"
)
SDIST_CANONICALIZATION = (
    "metadata-only deterministic normalization of the standard setuptools sdist: "
    "GNU tar format, every member mtime set to SOURCE_DATE_EPOCH, uid/gid set to 0, "
    "uname/gname cleared, directory modes 0755 and file modes 0644, members sorted "
    "by name, gzip header mtime set to SOURCE_DATE_EPOCH at compresslevel 9; file "
    "contents are byte-identical to the standard build output"
)
TAMPER_CASES = ("artifact", "sbom", "manifest_hash", "private_path", "coherent_substitution")


class ReleaseEvidenceError(Exception):
    """Raised on any release-evidence failure; the tool exits non-zero."""


def _fail(message: str) -> None:
    raise ReleaseEvidenceError(message)


def _run(
    command: list[str | Path],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    remove_env: tuple[str, ...] = (),
) -> str:
    full_env = {**os.environ, "PYTHONUTF8": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    for name in remove_env:
        full_env.pop(name, None)
    if env:
        full_env.update(env)
    completed = subprocess.run(  # noqa: S603 - fixed command list, no shell
        [os.fspath(part) for part in command],
        env=full_env,
        cwd=None if cwd is None else os.fspath(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        _fail(
            f"command failed ({completed.returncode}): "
            f"{' '.join(os.fspath(part) for part in command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git_stdout(repo_root: Path, *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        ["git", *arguments],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        _fail(
            f"git {' '.join(arguments)} failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    return completed.stdout


def _assert_clean_source_tree(repo_root: Path) -> str:
    """Fail closed unless the working tree is objectively clean.

    Any ``git status --porcelain=v1 --untracked-files=all`` output — modified,
    staged, deleted, renamed or conflicted tracked files, or ANY non-ignored
    untracked file — aborts release evidence generation.  There is no
    --allow-dirty escape hatch and package-relevant untracked files are never
    silently ignored.
    """
    stdout = _git_stdout(repo_root, "status", "--porcelain=v1", "--untracked-files=all")
    entries = [line for line in stdout.splitlines() if line.strip()]
    if entries:
        _fail(
            "repository working tree is not clean; release evidence must be built "
            "from an exact clean commit:\n" + "\n".join(entries)
        )
    return "PASS"


def _export_commit_source(repo_root: Path, commit: str, destination: Path) -> Path:
    """Export the exact recorded commit object into a task-owned temp tree.

    The exported snapshot is the build source: only committed content (never
    working-tree modifications, never untracked files, never ``.git`` data)
    can enter the release artifact.
    """
    if destination.exists():
        _fail(f"export destination already exists: {destination}")
    completed = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        ["git", "archive", "--format=tar", commit],
        cwd=str(repo_root),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        _fail(
            f"git archive {commit} failed ({completed.returncode}): "
            f"{completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    destination.mkdir(parents=True)
    resolved_destination = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(resolved_destination) or member.name.startswith("/"):
                _fail(f"unsafe member in commit export: {member.name!r}")
        archive.extractall(destination, filter="data")
    if (destination / ".git").exists():
        _fail("commit export must not contain .git data")
    return destination


def _unique_file(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        _fail(f"expected exactly one {pattern} in {directory}, found {matches}")
    return matches[0]


def _read_version(pyproject: Path) -> str:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _read_runtime_requirement(pyproject: Path) -> str:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    dependencies = [str(item) for item in data["project"]["dependencies"]]
    if dependencies != [EXPECTED_RUNTIME_REQUIREMENT]:
        _fail(f"runtime dependency contract changed in pyproject.toml: {dependencies!r}")
    return dependencies[0]


def _read_acceptance_version(pin_file: Path) -> str:
    lines = [
        line.strip()
        for line in pin_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(lines) != 1 or not lines[0].startswith("dbfbridge[write]=="):
        _fail(f"acceptance pin file must hold exactly one dbfbridge[write]== pin: {lines!r}")
    return lines[0].split("==", 1)[1]


def canonicalize_sdist(source: Path, destination: Path, epoch: int) -> None:
    with tarfile.open(source, "r:gz") as archive_in:
        entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
        for member in archive_in.getmembers():
            payload = archive_in.extractfile(member)
            data = payload.read() if payload is not None else None
            if member.isfile() and data is None:
                _fail(f"cannot read sdist member: {member.name}")
            entries.append((member, data))
    entries.sort(key=lambda pair: pair[0].name)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive_out:
        for member, data in entries:
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mode = 0o755 if member.isdir() else 0o644
            if member.isfile() and data is not None:
                member.size = len(data)
                archive_out.addfile(member, io.BytesIO(data))
            else:
                archive_out.addfile(member)
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=epoch
    ) as gz:
        gz.write(raw.getvalue())
    destination.write_bytes(compressed.getvalue())


def _build_environment_env(repo_root: Path, epoch: int, task_root: Path) -> dict[str, str]:
    # PIP_CONSTRAINT is parsed by pip with whitespace splitting, so the
    # constraints file must be referenced from a space-free task-owned path.
    constraints_copy = task_root / "build-constraints.txt"
    shutil.copyfile(repo_root / BUILD_CONSTRAINTS, constraints_copy)
    return {
        "SOURCE_DATE_EPOCH": str(epoch),
        "PIP_CONSTRAINT": str(constraints_copy),
        "PIP_CACHE_DIR": str(task_root / "pip-cache"),
        "PYTHONHASHSEED": "0",
    }


def build_once(
    source_root: Path,
    task_root: Path,
    epoch: int,
    index: int,
) -> tuple[Path, Path]:
    """Run one independent sdist+wheel build from the exported committed source.

    ``source_root`` must be the exact-commit export produced by
    ``_export_commit_source`` — never the mutable working tree.
    """
    build_dir = task_root / f"build-{index}"
    sdist_out = build_dir / "sdist-out"
    wheel_out = build_dir / "wheel-out"
    canonical_dir = build_dir / "canonical"
    for directory in (sdist_out, wheel_out, canonical_dir):
        directory.mkdir(parents=True)
    build_env = _build_environment_env(source_root, task_root=task_root, epoch=epoch)

    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--outdir",
            sdist_out,
            str(source_root),
        ],
        env=build_env,
    )
    raw_sdist = _unique_file(sdist_out, "*.tar.gz")
    canonical_sdist = canonical_dir / raw_sdist.name
    canonicalize_sdist(raw_sdist, canonical_sdist, epoch)

    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--outdir",
            wheel_out,
            str(canonical_sdist),
        ],
        env=build_env,
    )
    wheel = _unique_file(wheel_out, "*.whl")
    return canonical_sdist, wheel


def _build_reproducible_artifacts(
    repo_root: Path,
    task_root: Path,
    evidence_root: Path,
    epoch: int,
) -> tuple[Path, Path, dict[str, list[str]], dict[str, str]]:
    dist_dir = evidence_root / "dist"
    dist_dir.mkdir(parents=True)
    hashes: dict[str, list[str]] = {"sdist": [], "wheel": []}
    names: dict[str, str] = {}
    for index in (1, 2):
        sdist_path, wheel_path = build_once(repo_root, task_root, epoch, index)
        names.setdefault("sdist", sdist_path.name)
        names.setdefault("wheel", wheel_path.name)
        if sdist_path.name != names["sdist"] or wheel_path.name != names["wheel"]:
            _fail("independent builds produced different artifact filenames")
        hashes["sdist"].append(_sha256(sdist_path))
        hashes["wheel"].append(_sha256(wheel_path))
    if hashes["sdist"][0] != hashes["sdist"][1]:
        _fail(f"sdist is not reproducible: {hashes['sdist'][0]} != {hashes['sdist'][1]}")
    if hashes["wheel"][0] != hashes["wheel"][1]:
        _fail(f"wheel is not reproducible: {hashes['wheel'][0]} != {hashes['wheel'][1]}")
    sdist_target = dist_dir / names["sdist"]
    wheel_target = dist_dir / names["wheel"]
    shutil.copyfile(task_root / "build-1" / "canonical" / names["sdist"], sdist_target)
    shutil.copyfile(task_root / "build-1" / "wheel-out" / names["wheel"], wheel_target)
    final_sdist_hash = _sha256(sdist_target)
    final_wheel_hash = _sha256(wheel_target)
    if final_sdist_hash != hashes["sdist"][0] or final_wheel_hash != hashes["wheel"][0]:
        _fail("copied release artifacts do not match the verified build hashes")
    return sdist_target, wheel_target, hashes, names


def _download_wheelhouse(
    repo_root: Path,
    task_root: Path,
    evidence_root: Path,
    wheel_path: Path,
) -> list[dict[str, str]]:
    wheelhouse_dir = evidence_root / "wheelhouse"
    wheelhouse_dir.mkdir(parents=True)
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--no-deps",
            "--no-cache-dir",
            "--dest",
            wheelhouse_dir,
            "--requirement",
            str(repo_root / WHEELHOUSE_MANIFEST),
        ],
        env={"PIP_CACHE_DIR": str(task_root / "pip-cache")},
    )
    shutil.copyfile(wheel_path, wheelhouse_dir / wheel_path.name)
    validate_wheelhouse(repo_root / WHEELHOUSE_MANIFEST, wheelhouse_dir)
    entries: list[dict[str, str]] = []
    for wheel in sorted(wheelhouse_dir.glob("*.whl"), key=lambda path: path.name):
        if wheel.name == wheel_path.name:
            continue
        name, version = _wheel_identity(wheel)
        entries.append(
            {
                "name": name,
                "version": version,
                "filename": f"wheelhouse/{wheel.name}",
                "sha256": _sha256(wheel),
            }
        )
    if not entries:
        _fail("no dependency wheels recorded from the wheelhouse")
    return entries


def _validate_metadata(
    source_root: Path,
    sdist_path: Path,
    wheel_path: Path,
) -> dict[str, str]:
    _run(
        [
            sys.executable,
            "-m",
            "twine",
            "check",
            str(sdist_path),
            str(wheel_path),
        ]
    )
    _run([sys.executable, str(REPO_ROOT / "tools" / "check_wheel_metadata.py"), str(wheel_path)])
    sdist_name, sdist_version = _sdist_identity(sdist_path)
    wheel_name, wheel_version = _wheel_identity(wheel_path)
    if (sdist_name, sdist_version) != (
        "dbf-anonymizer",
        _read_version(source_root / "pyproject.toml"),
    ):
        _fail(f"sdist identity mismatch: {sdist_name} {sdist_version}")
    if (wheel_name, wheel_version) != (sdist_name, sdist_version):
        _fail(
            f"wheel identity {wheel_name}=={wheel_version} does not match "
            f"sdist {sdist_name}=={sdist_version}"
        )
    return {
        "twine_check": "PASS",
        "wheel_metadata_check": "PASS",
        "sdist_pkg_info_check": "PASS",
    }


def _fresh_wheel_smoke(
    repo_root: Path,
    task_root: Path,
    evidence_root: Path,
    wheel_path: Path,
    acceptance_version: str,
) -> dict[str, object]:
    venv_dir = task_root / "fresh-venv"
    work_dir = task_root / "smoke-work"
    runtime_root = task_root / "smoke-runtime"
    work_dir.mkdir(parents=True)
    _run([sys.executable, "-m", "venv", str(venv_dir)])
    venv_python = venv_dir / "Scripts" / "python.exe"
    if not venv_python.is_file():
        venv_python = venv_dir / "bin" / "python"
    if not venv_python.is_file():
        _fail(f"fresh venv python not found under {venv_dir}")

    wheelhouse_dir = evidence_root / "wheelhouse"
    _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse_dir),
            "--no-cache-dir",
            f"dbfbridge[write]=={acceptance_version}",
        ],
        remove_env=("PYTHONPATH",),
    )
    _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-cache-dir",
            str(wheel_path),
        ],
        remove_env=("PYTHONPATH",),
    )
    _run(
        [str(venv_python), "-m", "pip", "check"],
        remove_env=("PYTHONPATH",),
    )
    _run(
        [str(venv_python), str(repo_root / "tools" / "check_acceptance_pin.py")],
        remove_env=("PYTHONPATH",),
    )
    _run(
        [str(venv_python), str(repo_root / "tools" / "check_p7_installed_wheel.py")],
        remove_env=("PYTHONPATH",),
    )

    runtime_script = work_dir / "check_p7_offline_runtime.py"
    shutil.copyfile(repo_root / "tools" / "check_p7_offline_runtime.py", runtime_script)
    runtime_stdout = _run(
        [
            str(venv_python),
            str(runtime_script),
            "--work-root",
            str(runtime_root),
            "--repository-root",
            str(repo_root),
        ],
        cwd=work_dir,
        remove_env=("PYTHONPATH",),
    )
    runtime_evidence = json.loads(runtime_stdout.strip().splitlines()[-1])
    if runtime_evidence.get("cli_complete_workflow") != "PASS":
        _fail(f"fresh-wheel runtime contract failed: {runtime_evidence}")
    if (
        runtime_evidence.get("network_attempts") != 0
        or runtime_evidence.get("process_attempts") != 0
    ):
        _fail(f"fresh-wheel runtime touched a forbidden boundary: {runtime_evidence}")

    installed_stdout = _run(
        [
            str(venv_python),
            "-c",
            "import importlib.metadata as metadata; print(metadata.version('dbfbridge'))",
        ]
    )
    installed_dbfbridge = installed_stdout.strip().splitlines()[-1]
    if installed_dbfbridge != acceptance_version:
        _fail(f"smoke venv dbfbridge {installed_dbfbridge} != acceptance {acceptance_version}")
    return {
        "result": "PASS",
        "wheel_install_mode": "--no-deps exact release wheel",
        "dependency_install_mode": "--no-index from the evidence wheelhouse",
        "import_origin": "site-packages",
        "source_tree_import": "BLOCKED",
        "network_attempts": 0,
        "process_attempts": 0,
        "pip_check": "PASS",
        "cli_complete_workflow": str(runtime_evidence.get("cli_complete_workflow")),
        "installed_dbfbridge_version": installed_dbfbridge,
        "package_version": str(runtime_evidence.get("package_version")),
    }


def _run_verifier(
    evidence_root: Path,
    manifest_path: Path,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    stdout = _run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "verify_release_evidence.py"),
            "--manifest",
            str(manifest_path),
            "--evidence-root",
            str(evidence_root),
            "--expected-manifest-sha256",
            expected_manifest_sha256,
        ]
    )
    return dict(json.loads(stdout.strip().splitlines()[-1]))


def _tamper_selftest(
    task_root: Path,
    evidence_root: Path,
    manifest_path: Path,
    trusted_manifest_digest: str,
) -> dict[str, object]:
    """Prove the verifier fails closed on every tampering scenario.

    Cases ``artifact``/``sbom``/``manifest_hash``/``private_path`` make the
    tampered copy internally self-consistent (the copy's own manifest digest is
    supplied as the expected value) so each rejection is attributable to the
    intended tamper.  The ``coherent_substitution`` case rewrites the wheel AND
    every manifest reference to it AND the copy's own digest — internally
    self-consistent, yet still rejected against the TRUSTED digest of the real
    manifest.  That is exactly why the external manifest digest/attestation
    layer exists.
    """
    cases_root = task_root / "tamper-cases"
    cases_root.mkdir(parents=True)
    for case in TAMPER_CASES:
        case_dir = cases_root / case
        shutil.copytree(evidence_root, case_dir)
        case_manifest = case_dir / manifest_path.name
        document = json.loads(case_manifest.read_text(encoding="utf-8"))
        document["tamper_detection_selftest"] = {"result": "PASS", "cases": list(TAMPER_CASES)}
        if case == "artifact":
            wheel_name = document["artifacts"]["wheel"]["filename"]
            wheel_copy = case_dir / wheel_name
            payload = bytearray(wheel_copy.read_bytes())
            payload[-1] ^= 0x01
            wheel_copy.write_bytes(bytes(payload))
        elif case == "sbom":
            sbom_copy = case_dir / document["sbom"]["filename"]
            sbom_document = json.loads(sbom_copy.read_text(encoding="utf-8"))
            sbom_document["version"] = 2
            sbom_copy.write_text(
                json.dumps(sbom_document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        elif case == "manifest_hash":
            document["artifacts"]["sdist"]["sha256"] = "0" * 64
        elif case == "private_path":
            document["workflow_identity"]["run_id"] = "C:\\Users\\attacker\\private\\run-12345"
        elif case == "coherent_substitution":
            wheel_name = document["artifacts"]["wheel"]["filename"]
            wheel_copy = case_dir / wheel_name
            payload = bytearray(wheel_copy.read_bytes())
            payload[-1] ^= 0x01
            wheel_copy.write_bytes(bytes(payload))
            substituted = _sha256(wheel_copy)
            document["artifacts"]["wheel"]["sha256"] = substituted
            document["reproducibility"]["wheel_sha256_build_1"] = substituted
            document["reproducibility"]["wheel_sha256_build_2"] = substituted
        else:  # pragma: no cover - exhaustive over TAMPER_CASES
            _fail(f"unknown tamper case: {case}")
        case_manifest.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        case_digest = _sha256_bytes(case_manifest.read_bytes())
        expected = trusted_manifest_digest if case == "coherent_substitution" else case_digest
        completed = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "verify_release_evidence.py"),
                "--manifest",
                str(case_manifest),
                "--evidence-root",
                str(case_dir),
                "--expected-manifest-sha256",
                expected,
            ],
            capture_output=True,
            check=False,
        )
        if completed.returncode == 0:
            _fail(f"tamper self-test case {case!r} was NOT rejected by the verifier")
    return {"result": "PASS", "cases": list(TAMPER_CASES)}


def build_release_evidence(
    output_dir: Path,
    *,
    source_date_epoch: int | None,
    workflow_name: str,
    run_id: str,
    run_event: str,
) -> dict[str, object]:
    evidence_root = output_dir.resolve()
    if evidence_root.exists():
        _fail(f"output directory already exists: {evidence_root}")
    evidence_root.mkdir(parents=True)

    commit = _git_stdout(REPO_ROOT, "rev-parse", "HEAD").strip()
    if len(commit) != 40 or not all(char in "0123456789abcdef" for char in commit):
        _fail(f"git rev-parse HEAD returned an unexpected value: {commit!r}")

    cleanliness = _assert_clean_source_tree(REPO_ROOT)

    task_root = Path(tempfile.gettempdir()) / (
        f"dbf-anonymizer-p7-008-release-{os.getpid()}-{uuid.uuid4().hex}"
    )
    task_root.mkdir(parents=True)
    try:
        source_root = _export_commit_source(REPO_ROOT, commit, task_root / "source-export")

        # Every build-relevant input is read from the exact-commit export,
        # never from the mutable working tree.
        pyproject = source_root / "pyproject.toml"
        version = _read_version(pyproject)
        runtime_requirement = _read_runtime_requirement(pyproject)
        acceptance_version = _read_acceptance_version(source_root / ACCEPTANCE_PIN)
        if source_date_epoch is None:
            source_date_epoch = int(
                _git_stdout(REPO_ROOT, "show", "-s", "--format=%ct", commit).strip()
            )

        sdist_path, wheel_path, hashes, names = _build_reproducible_artifacts(
            source_root, task_root, evidence_root, epoch=source_date_epoch
        )
        wheelhouse_entries = _download_wheelhouse(source_root, task_root, evidence_root, wheel_path)
        metadata_validation = _validate_metadata(source_root, sdist_path, wheel_path)
        smoke = _fresh_wheel_smoke(
            REPO_ROOT, task_root, evidence_root, wheel_path, acceptance_version
        )

        sbom_document = build_sbom(
            application_name="dbf-anonymizer",
            application_version=version,
            git_commit_sha=commit,
            source_date_epoch=source_date_epoch,
            wheelhouse_manifest=source_root / WHEELHOUSE_MANIFEST,
            wheelhouse_dir=evidence_root / "wheelhouse",
            architecture_sha256=ARCHITECTURE_SHA256,
            exclude_filenames=frozenset({wheel_path.name}),
        )
        sbom_path = evidence_root / "release-sbom.cdx.json"
        sbom_path.write_bytes(render_sbom(sbom_document))

        manifest_path = evidence_root / MANIFEST_FILENAME
        manifest: dict[str, object] = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "kind": MANIFEST_KIND,
            "package": {"name": "dbf-anonymizer", "version": version},
            "source": {
                "git_commit_sha": commit,
                "architecture_sha256": ARCHITECTURE_SHA256,
                "cleanliness_check": cleanliness,
                "source_export_mode": SOURCE_EXPORT_MODE,
            },
            "build_environment": {
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "platform_system": platform.system(),
                "build_backend": "setuptools.build_meta",
                "source_date_epoch": source_date_epoch,
                "tool_versions": {
                    "build": _installed_version("build"),
                    "setuptools": "84.0.0",
                    "wheel": "0.48.0",
                    "pip": _installed_version("pip"),
                    "twine": _installed_version("twine"),
                },
            },
            "reproducibility": {
                "result": "PASS",
                "independent_builds": 2,
                "sdist_sha256_build_1": hashes["sdist"][0],
                "sdist_sha256_build_2": hashes["sdist"][1],
                "wheel_sha256_build_1": hashes["wheel"][0],
                "wheel_sha256_build_2": hashes["wheel"][1],
                "sdist_canonicalization": SDIST_CANONICALIZATION,
            },
            "artifacts": {
                "sdist": {"filename": f"dist/{names['sdist']}", "sha256": _sha256(sdist_path)},
                "wheel": {"filename": f"dist/{names['wheel']}", "sha256": _sha256(wheel_path)},
            },
            "metadata_validation": metadata_validation,
            "fresh_wheel_smoke": smoke,
            "dependency_provenance": {
                "runtime_requirement": runtime_requirement,
                "runtime_requirement_source": "pyproject.toml",
                "acceptance_pin_file": ACCEPTANCE_PIN,
                "acceptance_artifact": {
                    "name": "dbfbridge[write]",
                    "version": acceptance_version,
                },
                "wheelhouse_manifest": WHEELHOUSE_MANIFEST,
                "provenance_source": (
                    "public PyPI simple index resolved with the exact pinned versions; "
                    "artifact filenames and SHA-256 recorded below"
                ),
                "wheelhouse_artifacts": wheelhouse_entries,
                "resolved_runtime_closure": [
                    {"name": entry["name"], "version": entry["version"]}
                    for entry in wheelhouse_entries
                ],
            },
            "sbom": {
                "format": "CycloneDX",
                "spec_version": "1.5",
                "filename": sbom_path.name,
                "sha256": _sha256(sbom_path),
            },
            "tamper_detection_selftest": {"result": "PENDING", "cases": []},
            "workflow_identity": {
                "name": workflow_name,
                "run_id": run_id,
                "event": run_event,
            },
        }
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        # The trusted digest is bound to the manifest AFTER it reaches its
        # final form; there is no recursive self-hash inside the JSON.
        selftest = _tamper_selftest(
            task_root, evidence_root, manifest_path, _sha256_bytes(manifest_path.read_bytes())
        )
        manifest["tamper_detection_selftest"] = selftest
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest_digest = _sha256_bytes(manifest_path.read_bytes())
        (evidence_root / MANIFEST_DIGEST_SIDECAR).write_text(
            f"{manifest_digest}  {MANIFEST_FILENAME}\n", encoding="utf-8"
        )

        verification = _run_verifier(evidence_root, manifest_path, manifest_digest)
        if verification.get("result") != "PASS":
            _fail(f"final evidence verification failed: {verification}")

        build_environment = manifest["build_environment"]
        assert isinstance(build_environment, dict)
        summary = {
            "release_evidence": "PASS",
            "git_commit_sha": commit,
            "package_version": version,
            "architecture_sha256": ARCHITECTURE_SHA256,
            "python": platform.python_version(),
            "build_tools": build_environment["tool_versions"],
            "source_cleanliness": cleanliness,
            "source_export_mode": SOURCE_EXPORT_MODE,
            "sdist_filename": f"dist/{names['sdist']}",
            "sdist_sha256": _sha256(sdist_path),
            "wheel_filename": f"dist/{names['wheel']}",
            "wheel_sha256": _sha256(wheel_path),
            "sbom_filename": sbom_path.name,
            "sbom_sha256": _sha256(sbom_path),
            "manifest_filename": manifest_path.name,
            "manifest_sha256": manifest_digest,
            "manifest_digest_sidecar": MANIFEST_DIGEST_SIDECAR,
            "verifier": verification,
        }
        return summary
    finally:
        shutil.rmtree(task_root, ignore_errors=True)


def _installed_version(distribution: str) -> str:
    import importlib.metadata

    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError as error:
        _fail(f"required release tooling is not installed: {distribution}")
        raise error  # pragma: no cover - _fail raises


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-date-epoch", type=int, default=None)
    parser.add_argument("--workflow-name", default="local-deterministic-build")
    parser.add_argument("--run-id", default="local")
    parser.add_argument("--run-event", default="local")
    args = parser.parse_args()
    evidence = build_release_evidence(
        args.output_dir,
        source_date_epoch=args.source_date_epoch,
        workflow_name=args.workflow_name,
        run_id=args.run_id,
        run_event=args.run_event,
    )
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
