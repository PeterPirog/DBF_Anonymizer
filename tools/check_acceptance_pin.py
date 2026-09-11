"""P0 acceptance-artifact pin checker (REQ-P0-002 evidence helper).

Usage: python tools/check_acceptance_pin.py

Fails (exit 1) unless:

- ``requirements/p0-dbfbridge-tested.txt`` contains exactly one requirement
  line with the exact public pin ``dbfbridge[write]==<version>``;
- the pinned version satisfies the runtime range ``>=1.1.0,<2``;
- the dbfbridge distribution actually installed in the running environment
  is EXACTLY the pinned version (no drift between the tested artifact and
  the acceptance environment).

There is no fallback: a missing/unresolvable pinned public artifact is an
acceptance failure, never a reason to switch sources.
"""

from __future__ import annotations

import importlib.metadata
import sys
from pathlib import Path

PIN_FILE = Path(__file__).resolve().parents[1] / "requirements" / "p0-dbfbridge-tested.txt"
EXPECTED_PACKAGE = "dbfbridge[write]"
RUNTIME_RANGE_MIN = (1, 1, 0)
RUNTIME_RANGE_MAX_EXCLUSIVE = (2,)


def _fail(message: str) -> None:
    raise SystemExit(f"acceptance pin check FAILED: {message}")


def _read_pin() -> str:
    if not PIN_FILE.is_file():
        _fail(f"acceptance pin file is missing: {PIN_FILE}")
    requirement_lines = [
        line.strip()
        for line in PIN_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(requirement_lines) != 1:
        _fail(f"acceptance pin must contain exactly one requirement line, found {requirement_lines!r}")
    pin = requirement_lines[0].replace(" ", "")
    if pin.count("==") != 1 or not pin.startswith(EXPECTED_PACKAGE + "=="):
        _fail(f"acceptance pin must be an exact {EXPECTED_PACKAGE}==<version> pin, found {pin!r}")
    if pin != f"{EXPECTED_PACKAGE}=={pin.split('==', 1)[1]}":
        _fail(f"acceptance pin is not normalized: {pin!r}")
    return pin


def main() -> int:
    pin = _read_pin()
    pinned_version = pin.split("==", 1)[1]
    try:
        parsed = tuple(int(part) for part in pinned_version.split("."))
    except ValueError:
        _fail(f"pinned dbfbridge version {pinned_version!r} is not a plain release version")
    if not (RUNTIME_RANGE_MIN <= parsed < RUNTIME_RANGE_MAX_EXCLUSIVE):
        _fail(f"pinned dbfbridge {pinned_version} does not satisfy the runtime range >=1.1.0,<2")

    installed = importlib.metadata.version("dbfbridge")
    if installed != pinned_version:
        _fail(
            f"installed dbfbridge {installed!r} is not exactly the pinned "
            f"acceptance artifact {pinned_version!r}"
        )

    print("acceptance pin check PASSED:")
    print(f"  pin       = {pin}")
    print(f"  installed = dbfbridge {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
