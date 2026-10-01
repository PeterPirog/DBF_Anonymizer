"""Validate the exact REQ-P7-004 offline runtime wheelhouse."""

from __future__ import annotations

import argparse
import email.parser
import json
import re
import zipfile
from pathlib import Path

EXPECTED_RUNTIME_PINS = {
    "aenum": "3.1.17",
    "dbf": "0.99.11",
    "dbfbridge": "1.1.1",
    "dbfread": "2.0.7",
}
EXPECTED_APPLICATION = {"dbf-anonymizer": "1.0.0"}


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _manifest_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        requirement = line.split("#", 1)[0].strip()
        if not requirement:
            continue
        if requirement.count("==") != 1:
            raise AssertionError(f"offline requirement is not an exact pin: {requirement}")
        raw_name, version = requirement.split("==", 1)
        name = _normalize_name(raw_name.split("[", 1)[0].strip())
        if not version or name in pins:
            raise AssertionError(f"invalid offline requirement: {requirement}")
        pins[name] = version.strip()
    return pins


def _wheel_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata_files = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_files) != 1:
            raise AssertionError(f"{path.name}: expected one METADATA file")
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_files[0]))
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise AssertionError(f"{path.name}: missing Name or Version metadata")
    return _normalize_name(name), version


def validate_wheelhouse(manifest: Path, wheelhouse: Path) -> dict[str, object]:
    pins = _manifest_pins(manifest)
    if pins != EXPECTED_RUNTIME_PINS:
        raise AssertionError(
            f"offline runtime pins changed: expected {EXPECTED_RUNTIME_PINS}, got {pins}"
        )

    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels:
        raise AssertionError("offline wheelhouse contains no wheels")
    observed: dict[str, str] = {}
    filenames: list[str] = []
    for wheel in wheels:
        name, version = _wheel_identity(wheel)
        if name in observed:
            raise AssertionError(f"duplicate wheel distribution: {name}")
        observed[name] = version
        filenames.append(wheel.name)

    expected = EXPECTED_RUNTIME_PINS | EXPECTED_APPLICATION
    if observed != expected:
        raise AssertionError(
            f"offline wheelhouse is not the exact runtime closure: "
            f"expected {expected}, got {observed}"
        )
    return {
        "manifest": manifest.name,
        "runtime_pins": pins,
        "wheel_count": len(wheels),
        "wheels": filenames,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("wheelhouse", type=Path)
    args = parser.parse_args()
    evidence = validate_wheelhouse(args.manifest, args.wheelhouse)
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
