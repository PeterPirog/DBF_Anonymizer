"""Wheel metadata/content verifier for the clean-slate 1.0 package boundary.

Usage: python tools/check_wheel_metadata.py <path-to-wheel> [<wheel> ...]

Verifies the built distribution carries the immutable 1.0 identity, the exact
public dbfbridge dependency contract, and only the intended runtime package
members. REQ-P1-002 adds typed models/PEP 561 metadata; REQ-P1-003 adds the
stable public error contract.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

EXPECTED_NAME = "dbf-anonymizer"
EXPECTED_VERSION_PREFIX = "1.0.0.dev"
EXPECTED_DBFBRIDGE_REQUIREMENT = "dbfbridge[write]>=1.1.0,<2"


def _fail(message: str) -> None:
    raise SystemExit(f"wheel metadata check FAILED: {message}")


def check_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            _fail(f"expected exactly one METADATA, found {metadata_names}")
        metadata = archive.read(metadata_names[0]).decode("utf-8")

    fields: dict[str, list[str]] = {}
    for line in metadata.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields.setdefault(key, []).append(value)

    name = fields.get("Name", [""])[0]
    if name != EXPECTED_NAME:
        _fail(f"distribution name is {name!r}, expected {EXPECTED_NAME!r}")

    version = fields.get("Version", [""])[0]
    if not version.startswith(EXPECTED_VERSION_PREFIX):
        _fail(f"version {version!r} is not the 1.0 development baseline")

    requirements = fields.get("Requires-Dist", [])
    dbfbridge_requirements = [
        r for r in requirements if r.split(";")[0].strip().replace(" ", "").startswith("dbfbridge")
    ]
    normalized = [r.split(";")[0].strip().replace(" ", "") for r in dbfbridge_requirements]
    if normalized != ["dbfbridge[write]<2,>=1.1.0"] and normalized != [
        "dbfbridge[write]>=1.1.0,<2"
    ]:
        _fail(
            "dbfbridge dependency contract mismatch: "
            f"{dbfbridge_requirements!r} != [{EXPECTED_DBFBRIDGE_REQUIREMENT!r}]"
        )

    vcs_requirements = [r for r in requirements if "@" in r]
    if vcs_requirements:
        _fail(f"Git/VCS URL dependency present: {vcs_requirements!r}")

    direct_dbf = [
        r for r in requirements if r.split(";")[0].split("[")[0].strip() == "dbf"
    ]
    if direct_dbf:
        _fail(f"direct dbf dependency present: {direct_dbf!r} (must stay transitive)")

    with zipfile.ZipFile(wheel) as archive:
        members = archive.namelist()
    required_members = {
        "dbf_anonymizer/__init__.py",
        "dbf_anonymizer/cli.py",
        "dbf_anonymizer/__main__.py",
        "dbf_anonymizer/models.py",
        "dbf_anonymizer/errors.py",
        "dbf_anonymizer/verification.py",
        "dbf_anonymizer/py.typed",
    }
    missing = [name for name in required_members if not any(n == name for n in members)]
    if missing:
        _fail(f"wheel is missing required runtime members: {missing}")
    forbidden_prefixes = (
        "tests/",
        "tools/",
        "requirements/",
        "docs/",
        "benchmark",
        "AGENTS.md",
        "INTERNAL_RAG",
        ".agents",
        ".opencode",
    )
    forbidden_suffixes = (
        ".dbf", ".fpt", ".cdx", ".idx", ".dbc", ".dct", ".dcx",
        ".sqlite3", "-wal", "-shm",
    )
    leaked = [
        name
        for name in members
        if name.startswith(forbidden_prefixes)
        or name.endswith(forbidden_suffixes)
        or name.endswith("/LICENSES.md")
    ]
    if leaked:
        _fail(f"wheel contains forbidden members: {leaked}")

    print(f"wheel metadata check PASSED: {wheel.name}")
    print(f"  Name={name}  Version={version}")
    print(f"  Requires-Dist: {dbfbridge_requirements[0]}")
    print(f"  wheel members: {len(members)}; runtime package files verified")


def main() -> int:
    wheels = [Path(arg) for arg in sys.argv[1:]]
    if not wheels:
        _fail("no wheel path given")
    for wheel in wheels:
        check_wheel(wheel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
