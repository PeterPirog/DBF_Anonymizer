"""Deterministic CycloneDX 1.5 SBOM generator for the REQ-P7-008 release evidence.

Usage:
    python tools/generate_release_sbom.py
        --output <release-sbom.cdx.json>
        --application-version <version>
        --git-commit-sha <40-hex commit>
        --source-date-epoch <unix seconds>
        --wheelhouse-manifest requirements/p7-offline-wheelhouse.txt
        --wheelhouse-dir <dir holding the exact dependency wheels>
        [--architecture-sha256 <hash>]

The SBOM inventories the application component plus the exact pinned runtime
closure (the wheels named by the offline wheelhouse manifest, hashed from the
concrete artifact files). Output is deterministic: identical inputs produce
byte-identical JSON (sorted keys, fixed ordering, epoch-derived timestamp,
uuid5 serial number derived from the application identity and commit). The
generator is stdlib-only and release/dev-only: it is never a runtime
dependency and must preserve REQ-P7-004 offline runtime semantics.
"""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import re
import tarfile
import uuid
import zipfile
from pathlib import Path

CYCLONEDX_SPEC_VERSION = "1.5"
SBOM_FILENAME = "release-sbom.cdx.json"
SBOM_FORMAT = "CycloneDX"
TOOL_NAME = "dbf-anonymizer-release-evidence"


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{_normalize_name(name)}@{version}"


def _wheel_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata_files = [
            item for item in archive.namelist() if item.endswith(".dist-info/METADATA")
        ]
        if len(metadata_files) != 1:
            raise SystemExit(f"{path.name}: expected exactly one METADATA file")
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_files[0]))
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise SystemExit(f"{path.name}: wheel metadata missing Name or Version")
    return _normalize_name(name), version


def _sdist_identity(path: Path) -> tuple[str, str]:
    with tarfile.open(path, "r:gz") as archive:
        metadata_members = [
            member
            for member in archive.getmembers()
            if member.isfile() and member.name.endswith(".egg-info/PKG-INFO")
        ]
        if len(metadata_members) != 1:
            raise SystemExit(f"{path.name}: expected exactly one egg-info PKG-INFO")
        payload_file = archive.extractfile(metadata_members[0])
        if payload_file is None:
            raise SystemExit(f"{path.name}: PKG-INFO member is not a regular file")
        payload = email.parser.BytesParser().parsebytes(payload_file.read())
    name = payload.get("Name")
    version = payload.get("Version")
    if not name or not version:
        raise SystemExit(f"{path.name}: sdist PKG-INFO missing Name or Version")
    return _normalize_name(name), version


def _wheelhouse_pins(manifest: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        requirement = line.split("#", 1)[0].strip()
        if not requirement:
            continue
        if requirement.count("==") != 1:
            raise SystemExit(f"offline wheelhouse requirement is not an exact pin: {requirement}")
        raw_name, version = requirement.split("==", 1)
        name = _normalize_name(raw_name.split("[", 1)[0].strip())
        if not version or name in pins:
            raise SystemExit(f"invalid offline wheelhouse requirement: {requirement}")
        pins[name] = version.strip()
    return pins


def _iso8601(epoch: int) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(epoch, tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_sbom(
    *,
    application_name: str,
    application_version: str,
    git_commit_sha: str,
    source_date_epoch: int,
    wheelhouse_manifest: Path,
    wheelhouse_dir: Path,
    architecture_sha256: str | None,
    exclude_filenames: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Build the deterministic CycloneDX JSON document as a plain dictionary."""
    pins = _wheelhouse_pins(wheelhouse_manifest)
    components: list[dict[str, object]] = []
    for wheel in sorted(wheelhouse_dir.glob("*.whl"), key=lambda path: path.name):
        if wheel.name in exclude_filenames:
            continue
        name, version = _wheel_identity(wheel)
        if name not in pins:
            raise SystemExit(
                f"wheelhouse artifact is not a pinned runtime dependency: {wheel.name}"
            )
        expected_version = pins[name]
        if version != expected_version:
            raise SystemExit(
                f"wheelhouse artifact {wheel.name} carries version {version}, "
                f"expected pinned {expected_version}"
            )
        content = hashlib.sha256(wheel.read_bytes()).hexdigest()
        components.append(
            {
                "bom-ref": _purl(name, version),
                "type": "library",
                "name": name,
                "version": version,
                "scope": "required",
                "hashes": [{"alg": "SHA-256", "content": content}],
                "purl": _purl(name, version),
                "properties": [{"name": "dbf_anonymizer:wheelhouse_artifact", "value": wheel.name}],
            }
        )
    observed = {component["name"]: component["version"] for component in components}  # type: ignore[index]
    if observed != pins:
        raise SystemExit(f"SBOM inventory does not match the pinned closure: {observed} != {pins}")

    application_ref = _purl(application_name, application_version)
    serial_source = f"{application_ref}|{git_commit_sha}"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, serial_source)
    metadata_properties = [
        {"name": "dbf_anonymizer:git_commit_sha", "value": git_commit_sha},
        {"name": "dbf_anonymizer:source_date_epoch", "value": str(source_date_epoch)},
    ]
    if architecture_sha256:
        metadata_properties.append(
            {"name": "dbf_anonymizer:architecture_sha256", "value": architecture_sha256}
        )
    document: dict[str, object] = {
        "bomFormat": SBOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": _iso8601(source_date_epoch),
            "lifecycles": [{"phase": "build"}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": TOOL_NAME,
                        "version": application_version,
                    }
                ]
            },
            "component": {
                "bom-ref": application_ref,
                "type": "application",
                "name": application_name,
                "version": application_version,
                "scope": "required",
                "purl": application_ref,
            },
            "properties": metadata_properties,
        },
        "components": components,
        "dependencies": [
            {
                "ref": application_ref,
                "dependsOn": sorted(component["bom-ref"] for component in components),
            }  # type: ignore[index]
        ],
    }
    return document


def render_sbom(document: dict[str, object]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--application-version", required=True)
    parser.add_argument("--git-commit-sha", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--wheelhouse-manifest", required=True, type=Path)
    parser.add_argument("--wheelhouse-dir", required=True, type=Path)
    parser.add_argument(
        "--exclude-filename",
        action="append",
        default=[],
        help="wheel filename inside the wheelhouse to exclude from the component list",
    )
    parser.add_argument("--architecture-sha256", default=None)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", args.git_commit_sha):
        raise SystemExit("--git-commit-sha must be a 40-character hex SHA")
    document = build_sbom(
        application_name="dbf-anonymizer",
        application_version=args.application_version,
        git_commit_sha=args.git_commit_sha,
        source_date_epoch=args.source_date_epoch,
        wheelhouse_manifest=args.wheelhouse_manifest,
        wheelhouse_dir=args.wheelhouse_dir,
        architecture_sha256=args.architecture_sha256,
        exclude_filenames=frozenset(args.exclude_filename),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(render_sbom(document))
    print(f"SBOM written: {args.output} ({len(document['components'])} dependency components)")  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
