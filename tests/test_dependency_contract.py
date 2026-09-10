"""P0 dependency-contract evidence for REQ-P0-002.

Proves, from inside the running process, that the DBF/FPT boundary is exactly
one compatible public ``dbfbridge`` distribution:

- the installed ``dbfbridge`` version satisfies ``>=1.1.0,<2``;
- the public ``dbfbridge`` namespace is importable and matches that version;
- no repository-local shadow ``dbfbridge`` package/module exists;
- the imported ``dbfbridge`` origin belongs to the installed distribution;
- exactly one effective ``dbfbridge`` origin/version exists in the process.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path

import dbfbridge

REPO_ROOT = Path(__file__).resolve().parents[1]


def _parse_version(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in version.split("."):
        digits = ""
        for char in chunk:
            if char.isdigit():
                digits += char
            else:
                break
        parts.append(int(digits))
    return tuple(parts)


def _parsed_version() -> tuple[int, ...]:
    return _parse_version(importlib.metadata.version("dbfbridge"))


def test_installed_dbfbridge_satisfies_pinned_range() -> None:
    version = _parsed_version()
    assert version >= (1, 1, 0)
    assert version < (2,)


def test_package_imported_through_public_dbfbridge_namespace() -> None:
    assert dbfbridge.__version__ == importlib.metadata.version("dbfbridge")


def test_no_repository_local_dbfbridge_shadow() -> None:
    for candidate in (
        REPO_ROOT / "dbfbridge",
        REPO_ROOT / "src" / "dbfbridge",
        REPO_ROOT / "src" / "dbf_anonymizer" / "dbfbridge",
        REPO_ROOT / "dbfbridge.py",
        REPO_ROOT / "src" / "dbfbridge.py",
    ):
        assert not candidate.exists(), f"repository-local dbfbridge shadow: {candidate}"


def test_imported_dbfbridge_origin_is_the_installed_distribution() -> None:
    distribution = importlib.metadata.distribution("dbfbridge")
    distribution_root = Path(distribution.locate_file("")).resolve()
    imported_root = Path(dbfbridge.__file__).resolve()
    assert distribution_root != Path("")  # located in a real installation tree
    assert imported_root.is_relative_to(distribution_root)


def test_exactly_one_effective_dbfbridge_origin_in_process() -> None:
    providers: dict[str, str] = {}
    for dist in importlib.metadata.distributions():
        top_levels = {str(item).split("\\")[0].split("/")[0] for item in (dist.files or [])}
        if "dbfbridge" in top_levels or "dbfbridge" in (dist.read_text("top_level.txt") or ""):
            providers[dist.metadata["Name"]] = dist.version
    assert providers == {"dbfbridge": importlib.metadata.version("dbfbridge")}


def test_no_vcs_url_dependency_for_dbfbridge() -> None:
    requirements = [
        requirement
        for requirement in (importlib.metadata.requires("dbf-anonymizer") or [])
        if requirement.split(";")[0].strip().replace(" ", "").startswith("dbfbridge")
    ]
    assert requirements, "dbf-anonymizer metadata carries no dbfbridge requirement"
    for requirement in requirements:
        assert "@" not in requirement, requirement
        # setuptools normalizes constraint order and spacing; compare the
        # normalized string so the contract stays exactly the pinned range.
        normalized = requirement.split(";")[0].strip().replace(" ", "")
        assert normalized in {"dbfbridge[write]>=1.1.0,<2", "dbfbridge[write]<2,>=1.1.0"}, (
            requirement
        )


# ---------------------------------------------------------------------------
# P0 acceptance-artifact pin (requirements/p0-dbfbridge-tested.txt)
# ---------------------------------------------------------------------------

PIN_FILE = REPO_ROOT / "requirements" / "p0-dbfbridge-tested.txt"
ACCEPTANCE_PACKAGE = "dbfbridge[write]"


def _read_acceptance_pin() -> str:
    """Parse the acceptance pin file into its single exact requirement line."""
    assert PIN_FILE.is_file(), f"acceptance pin file is missing: {PIN_FILE}"
    requirement_lines = [
        line.strip()
        for line in PIN_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert len(requirement_lines) == 1, (
        f"acceptance pin must contain exactly one requirement line, got {requirement_lines!r}"
    )
    normalized = requirement_lines[0].replace(" ", "")
    assert normalized.count("==") == 1 and normalized.startswith(ACCEPTANCE_PACKAGE + "=="), (
        f"acceptance pin must be an exact {ACCEPTANCE_PACKAGE}==<version> pin, got {normalized!r}"
    )
    return normalized


def test_acceptance_pin_is_exact() -> None:
    pin = _read_acceptance_pin()
    assert pin == "dbfbridge[write]==1.1.0", pin


def test_acceptance_pin_satisfies_runtime_range() -> None:
    pin = _read_acceptance_pin()
    pinned_version = tuple(int(part) for part in pin.split("==", 1)[1].split("."))
    assert (1, 1, 0) <= pinned_version < (2,), pin


def test_installed_dbfbridge_is_exactly_the_pinned_acceptance_artifact() -> None:
    pin = _read_acceptance_pin()
    pinned_version = pin.split("==", 1)[1]
    installed = importlib.metadata.version("dbfbridge")
    assert installed == pinned_version, (
        f"installed dbfbridge {installed!r} is not exactly the pinned "
        f"acceptance artifact {pinned_version!r}"
    )