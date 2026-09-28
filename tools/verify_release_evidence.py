"""Fail-closed verifier for the REQ-P7-008 release evidence bundle.

Usage:
    python tools/verify_release_evidence.py --manifest <release-evidence.manifest.json> \
        --evidence-root <dir containing the files named by the manifest> \
        [--expected-manifest-sha256 <64hex trusted manifest digest>]

Integrity model (two layers):

1. MANIFEST DIGEST BINDING (verified FIRST, before any manifest content is
   trusted): the verifier recomputes the SHA-256 of the exact manifest bytes
   and compares it against (a) the trusted ``--expected-manifest-sha256`` value
   when supplied, and (b) the sidecar file ``release-evidence.manifest.sha256``
   when present.  At least one binding must exist: verification without any
   expected digest and without the sidecar fails closed.  A malformed expected
   digest or a mismatching sidecar also fails.
2. INTERNAL SELF-CONSISTENCY: every recorded SHA-256 (sdist, wheel, SBOM,
   wheelhouse wheels) is recomputed, the manifest schema and cross-consistency
   are validated, and the whole evidence bundle is scanned for private paths
   and credential-shaped material.

Layer 1 alone cannot authenticate anything mutable: an attacker can rewrite
both the manifest and the sidecar coherently.  The trusted binding is the
externally recorded digest (the value attested by the privileged CI
attestation job).  Any mismatch, missing file or unexpected value fails the
process (exit 1): verification never best-efforts a tampered bundle.

Exit codes: 0 = verified; 1 = verification failure; 2 = usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import NoReturn, cast

SCHEMA_VERSION = "1.0"
MANIFEST_KIND = "dbf-anonymizer-release-evidence-manifest"
MANIFEST_FILENAME = "release-evidence.manifest.json"
MANIFEST_DIGEST_SIDECAR = "release-evidence.manifest.sha256"
SBOM_FILENAME = "release-sbom.cdx.json"
SBOM_FORMAT = "CycloneDX"
SBOM_SPEC_VERSION = "1.5"
ARCHITECTURE_SHA256 = "483932970d44770b05fcfad7430b85820d771458110f004b0397bd5d56398615"
EXPECTED_TAMPER_CASES = (
    "artifact",
    "sbom",
    "manifest_hash",
    "private_path",
    "coherent_substitution",
)
REQUIRED_TOP_LEVEL_KEYS = (
    "schema_version",
    "kind",
    "package",
    "source",
    "build_environment",
    "reproducibility",
    "artifacts",
    "metadata_validation",
    "fresh_wheel_smoke",
    "dependency_provenance",
    "sbom",
    "tamper_detection_selftest",
    "workflow_identity",
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
WINDOWS_ABSOLUTE_PATH = re.compile(r"\b[A-Za-z]:[\\/]")
UNC_PATH = re.compile(r"\\\\")
POSIX_PRIVATE_ROOT = re.compile(r"(?i)\b(/home/|/root/|/Users/)\b")
FILE_URI = re.compile(r"(?i)\bfile://")
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
GITHUB_TOKEN = re.compile(r"\bghp_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
FORBIDDEN_CONTENT_PATTERNS = (
    WINDOWS_ABSOLUTE_PATH,
    UNC_PATH,
    POSIX_PRIVATE_ROOT,
    FILE_URI,
    PRIVATE_KEY_BLOCK,
    GITHUB_TOKEN,
    AWS_ACCESS_KEY,
    SLACK_TOKEN,
)


class VerificationFailure(Exception):
    """Raised when any evidence check fails; always aborts the verification."""


def _fail(message: str) -> NoReturn:
    raise VerificationFailure(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest_bytes(manifest_bytes: bytes, manifest_path: Path) -> dict[str, object]:
    document: object
    try:
        document = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{manifest_path.name} is not valid JSON: {error}")
    if not isinstance(document, dict):
        _fail("manifest root must be a JSON object")
    return cast(dict[str, object], document)


def _section(document: dict[str, object], key: str) -> dict[str, object]:
    value = document.get(key)
    if not isinstance(value, dict):
        _fail(f"manifest {key} section must be an object: {value!r}")
    return cast(dict[str, object], value)


def _artifact_entry(document: dict[str, object], key: str) -> tuple[str, str]:
    artifacts = _section(document, "artifacts")
    if key not in artifacts:
        _fail(f"manifest artifacts.{key} missing")
    entry = artifacts[key]
    if not isinstance(entry, dict):
        _fail(f"manifest artifacts.{key} must be an object")
    filename = entry.get("filename")
    digest = entry.get("sha256")
    if not isinstance(filename, str) or not filename:
        _fail(f"manifest artifacts.{key}.filename missing")
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        _fail(f"manifest artifacts.{key}.sha256 is not a lowercase 64-hex value")
    return filename, digest


def _assert_relative_filename(filename: str, label: str) -> None:
    if (
        WINDOWS_ABSOLUTE_PATH.search(filename)
        or filename.startswith("/")
        or filename.startswith("\\")
        or ".." in filename
    ):
        _fail(f"{label} filename is not a clean relative path: {filename!r}")


def _verify_hashed_file(evidence_root: Path, filename: str, digest: str, label: str) -> Path:
    _assert_relative_filename(filename, label)
    path = evidence_root / filename
    if not path.is_file():
        _fail(f"{label} artifact missing: {filename}")
    actual = _sha256(path)
    if actual != digest:
        _fail(f"{label} SHA-256 mismatch for {filename}: manifest {digest} != actual {actual}")
    return path


def _parse_manifest_digest_sidecar(sidecar: Path, manifest_name: str) -> str:
    try:
        text = sidecar.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        _fail(f"manifest digest sidecar is unreadable: {error}")
    parts = text.strip().split()
    if len(parts) != 2 or not SHA256_PATTERN.fullmatch(parts[0]) or parts[1] != manifest_name:
        _fail(
            "manifest digest sidecar is malformed (expected '<64hex>  "
            f"{manifest_name}'): {text.strip()!r}"
        )
    return parts[0]


def verify_evidence(
    manifest_path: Path,
    evidence_root: Path,
    expected_manifest_sha256: str | None = None,
) -> dict[str, object]:
    """Layer 1 (manifest digest binding) is enforced before any manifest
    content is trusted; layer 2 is the internal self-consistency proof."""
    if not manifest_path.is_file():
        _fail(f"manifest file missing: {manifest_path}")
    manifest_bytes = manifest_path.read_bytes()
    actual_manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if expected_manifest_sha256 is not None:
        if not SHA256_PATTERN.fullmatch(expected_manifest_sha256):
            _fail(
                "malformed --expected-manifest-sha256: must be a lowercase 64-hex value, "
                f"got {expected_manifest_sha256!r}"
            )
        if expected_manifest_sha256 != actual_manifest_digest:
            _fail(
                "manifest digest mismatch against the trusted expected value: "
                f"expected {expected_manifest_sha256} != actual {actual_manifest_digest}"
            )
    sidecar = evidence_root / MANIFEST_DIGEST_SIDECAR
    if sidecar.is_file():
        recorded = _parse_manifest_digest_sidecar(sidecar, manifest_path.name)
        if recorded != actual_manifest_digest:
            _fail(
                f"manifest digest mismatch against the sidecar {MANIFEST_DIGEST_SIDECAR}: "
                f"sidecar {recorded} != actual {actual_manifest_digest}"
            )
    elif expected_manifest_sha256 is None:
        _fail(
            "missing manifest integrity binding: no "
            f"{MANIFEST_DIGEST_SIDECAR} sidecar and no --expected-manifest-sha256"
        )
    document = _load_manifest_bytes(manifest_bytes, manifest_path)
    if document.get("schema_version") != SCHEMA_VERSION:
        _fail(f"unsupported manifest schema_version: {document.get('schema_version')!r}")
    if document.get("kind") != MANIFEST_KIND:
        _fail(f"unexpected manifest kind: {document.get('kind')!r}")
    for key in REQUIRED_TOP_LEVEL_KEYS:
        if key not in document:
            _fail(f"manifest key missing: {key}")

    package = _section(document, "package")
    if package.get("name") != "dbf-anonymizer":
        _fail(f"unexpected package name: {package.get('name')!r}")
    if not isinstance(package.get("version"), str) or not package["version"]:
        _fail("manifest package.version missing")

    source = _section(document, "source")
    commit = source.get("git_commit_sha")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        _fail("manifest source.git_commit_sha must be a 40-hex commit SHA")
    if source.get("architecture_sha256") != ARCHITECTURE_SHA256:
        _fail("manifest source.architecture_sha256 is not the immutable architecture hash")
    if source.get("cleanliness_check") != "PASS":
        _fail(
            "manifest source.cleanliness_check must be PASS: the build source must come "
            "from an objectively clean committed tree"
        )
    export_mode = source.get("source_export_mode")
    if not isinstance(export_mode, str) or "git archive" not in export_mode:
        _fail(
            "manifest source.source_export_mode must describe the exact commit-object "
            f"export protocol: {export_mode!r}"
        )

    build_environment = _section(document, "build_environment")
    for key in ("python_version", "build_backend", "source_date_epoch", "tool_versions"):
        if key not in build_environment:
            _fail(f"build_environment.{key} missing")
    tool_versions = build_environment.get("tool_versions")
    if not isinstance(tool_versions, dict) or not {"build", "setuptools", "wheel"} <= set(
        tool_versions
    ):
        _fail("build_environment.tool_versions must record build/setuptools/wheel versions")

    repro = _section(document, "reproducibility")
    if repro.get("result") != "PASS":
        _fail(f"reproducibility result is not PASS: {repro.get('result')!r}")
    if repro.get("independent_builds") != 2:
        _fail("reproducibility must record exactly two independent builds")
    for artifact_key in ("sdist", "wheel"):
        first = repro.get(f"{artifact_key}_sha256_build_1")
        second = repro.get(f"{artifact_key}_sha256_build_2")
        for label, value in (("build_1", first), ("build_2", second)):
            if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                _fail(f"reproducibility.{artifact_key}_{label} is not a lowercase 64-hex value")
        if first != second:
            _fail(f"the two independent {artifact_key} builds produced different hashes")
    canonicalization = repro.get("sdist_canonicalization")
    if not isinstance(canonicalization, str) or not canonicalization.strip():
        _fail("reproducibility.sdist_canonicalization must describe the normalization")

    metadata_validation = _section(document, "metadata_validation")
    for key in ("twine_check", "wheel_metadata_check", "sdist_pkg_info_check"):
        if metadata_validation.get(key) != "PASS":
            _fail(f"metadata_validation.{key} is not PASS: {metadata_validation.get(key)!r}")

    smoke = _section(document, "fresh_wheel_smoke")
    if smoke.get("result") != "PASS":
        _fail(f"fresh wheel smoke result is not PASS: {smoke.get('result')!r}")
    for key in ("pip_check", "cli_complete_workflow"):
        if smoke.get(key) != "PASS":
            _fail(f"fresh_wheel_smoke.{key} is not PASS")
    if smoke.get("import_origin") != "site-packages":
        _fail(f"fresh wheel import origin is not site-packages: {smoke.get('import_origin')!r}")
    if smoke.get("source_tree_import") != "BLOCKED":
        _fail("fresh wheel smoke must prove source-tree import is blocked")
    for key in ("network_attempts", "process_attempts"):
        if smoke.get(key) != 0:
            _fail(f"fresh_wheel_smoke.{key} must be zero")

    provenance = _section(document, "dependency_provenance")
    requirement = provenance.get("runtime_requirement")
    normalized = str(requirement).replace(" ", "")
    if normalized not in {"dbfbridge[write]>=1.1.0,<2", "dbfbridge[write]<2,>=1.1.0"}:
        _fail(f"runtime requirement changed: {requirement!r}")
    acceptance = provenance.get("acceptance_artifact")
    if not isinstance(acceptance, dict):
        _fail("dependency_provenance.acceptance_artifact must be an object")
    if acceptance.get("name") != "dbfbridge[write]":
        _fail("acceptance artifact must be dbfbridge[write]")
    acceptance_version = acceptance.get("version")
    if not isinstance(acceptance_version, str) or not re.fullmatch(
        r"\d+(\.\d+)*", acceptance_version
    ):
        _fail("acceptance artifact version missing")
    parts = tuple(int(part) for part in acceptance_version.split("."))
    if not (1, 1, 0) <= parts < (2,):
        _fail(f"acceptance artifact version {acceptance_version} violates >=1.1.0,<2")
    if not isinstance(provenance.get("acceptance_pin_file"), str):
        _fail("dependency_provenance.acceptance_pin_file missing")

    entries = provenance.get("wheelhouse_artifacts")
    if not isinstance(entries, list) or not entries:
        _fail("dependency_provenance.wheelhouse_artifacts must be a non-empty list")
    closure: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            _fail("wheelhouse artifact entry must be an object")
        name = entry.get("name")
        version = entry.get("version")
        filename = entry.get("filename")
        digest = entry.get("sha256")
        if not isinstance(name, str) or not name:
            _fail(f"incomplete wheelhouse artifact entry: {entry!r}")
        if not isinstance(version, str) or not version:
            _fail(f"incomplete wheelhouse artifact entry: {name!r}")
        if not isinstance(filename, str) or not filename:
            _fail(f"incomplete wheelhouse artifact entry: {name!r}")
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            _fail(f"wheelhouse artifact {name} sha256 is not 64-hex")
        if not filename.startswith("wheelhouse/") or ".." in filename:
            _fail(f"wheelhouse artifact filename must sit under wheelhouse/: {filename!r}")
        _verify_hashed_file(evidence_root, filename, digest, f"wheelhouse {name}")
        closure[name] = version
    if not closure:
        _fail("no runtime dependency recorded")

    sbom_section = _section(document, "sbom")
    if sbom_section.get("format") != SBOM_FORMAT:
        _fail(f"SBOM format must be {SBOM_FORMAT}: {sbom_section.get('format')!r}")
    if sbom_section.get("spec_version") != SBOM_SPEC_VERSION:
        _fail(f"SBOM spec_version must be {SBOM_SPEC_VERSION}")
    if sbom_section.get("filename") != SBOM_FILENAME:
        _fail(f"unexpected SBOM filename: {sbom_section.get('filename')!r}")
    sbom_digest = sbom_section.get("sha256")
    if not isinstance(sbom_digest, str) or not SHA256_PATTERN.fullmatch(sbom_digest):
        _fail("manifest sbom.sha256 is not a 64-hex value")
    sbom_path = _verify_hashed_file(evidence_root, SBOM_FILENAME, sbom_digest, "SBOM")
    try:
        sbom_document: object = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        _fail(f"SBOM is not valid JSON: {error}")
    if not isinstance(sbom_document, dict):
        _fail("SBOM root must be an object")
    sbom = sbom_document
    if sbom.get("bomFormat") != SBOM_FORMAT:
        _fail(f"SBOM bomFormat mismatch: {sbom.get('bomFormat')!r}")
    if sbom.get("specVersion") != SBOM_SPEC_VERSION:
        _fail(f"SBOM specVersion mismatch: {sbom.get('specVersion')!r}")
    serial = sbom.get("serialNumber")
    if not isinstance(serial, str) or not serial.startswith("urn:uuid:"):
        _fail(f"SBOM serialNumber missing or malformed: {serial!r}")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        _fail("SBOM metadata missing")
    sbom_component = metadata.get("component")
    if not isinstance(sbom_component, dict):
        _fail("SBOM metadata.component missing")
    if (
        sbom_component.get("name") != package["name"]
        or sbom_component.get("version") != package["version"]
    ):
        _fail("SBOM application component does not match the manifest package identity")
    components = sbom.get("components")
    if not isinstance(components, list):
        _fail("SBOM components missing")
    inventory: dict[str, str] = {}
    for component in components:
        if not isinstance(component, dict):
            _fail("SBOM component must be an object")
        name = component.get("name")
        version = component.get("version")
        hashes = component.get("hashes")
        if not isinstance(name, str) or not isinstance(version, str):
            _fail(f"SBOM component missing name/version: {component!r}")
        if not isinstance(hashes, list) or not any(
            isinstance(item, dict) and item.get("alg") == "SHA-256" and item.get("content")
            for item in hashes
        ):
            _fail(f"SBOM component {name} lacks a SHA-256 hash")
        inventory[str(name)] = str(version)
    if inventory != closure:
        _fail(f"SBOM inventory {inventory} != manifest dependency closure {closure}")

    selftest = _section(document, "tamper_detection_selftest")
    if selftest.get("result") != "PASS":
        _fail("tamper detection self-test did not pass")
    cases = selftest.get("cases")
    if not isinstance(cases, list) or sorted(str(case) for case in cases) != sorted(
        EXPECTED_TAMPER_CASES
    ):
        _fail(f"tamper self-test cases must be exactly {sorted(EXPECTED_TAMPER_CASES)}")

    workflow_identity = _section(document, "workflow_identity")
    name = workflow_identity.get("name")
    if not isinstance(name, str) or not name.strip():
        _fail("workflow_identity.name missing")

    for artifact_key in ("sdist", "wheel"):
        filename, digest = _artifact_entry(document, artifact_key)
        _verify_hashed_file(evidence_root, filename, digest, artifact_key)

    _scan_forbidden_content(evidence_root)

    return {
        "result": "PASS",
        "manifest": manifest_path.name,
        "manifest_digest": actual_manifest_digest,
        "manifest_digest_source": (
            "expected-manifest-sha256 argument"
            if expected_manifest_sha256 is not None
            else MANIFEST_DIGEST_SIDECAR
        ),
        "sdist_verified": True,
        "wheel_verified": True,
        "wheelhouse_artifacts_verified": sorted(closure),
        "sbom_verified": True,
    }


def _scan_forbidden_content(evidence_root: Path) -> None:
    for path in sorted(evidence_root.rglob("*.json")):
        text = path.read_text(encoding="utf-8", errors="strict")
        _assert_clean_text(text, path.name)
    for artifact in sorted(evidence_root.rglob("*.whl")):
        with zipfile.ZipFile(artifact) as archive:
            for name in archive.namelist():
                _assert_clean_text(name, f"{artifact.name}::{name}")
    for artifact in sorted(evidence_root.rglob("*.tar.gz")):
        with tarfile.open(artifact, "r:gz") as archive:
            for member in archive.getmembers():
                _assert_clean_text(member.name, f"{artifact.name}::{member.name}")


def _assert_clean_text(text: str, label: str) -> None:
    for pattern in FORBIDDEN_CONTENT_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            _fail(f"forbidden content {match.group(0)!r} in {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument(
        "--expected-manifest-sha256",
        default=None,
        help=(
            "trusted SHA-256 of the exact release-evidence.manifest.json bytes; "
            "verified before any manifest content is trusted"
        ),
    )
    args = parser.parse_args()
    try:
        evidence = verify_evidence(args.manifest, args.evidence_root, args.expected_manifest_sha256)
    except VerificationFailure as failure:
        print(f"release evidence verification FAILED: {failure}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
