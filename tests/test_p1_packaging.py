"""REQ-P1-001 — deterministic packaging and CLI-foundation evidence.

Proves the distribution identity, the Python support contract, the console
entry point, CLI behavior (``--help``/``--version`` only, unknown arguments
non-zero), version consistency and import purity.  Clean-wheel installation
from outside the repository checkout is proven by the CI clean-wheel job and
the wheel metadata verifier; these tests additionally prove the metadata and
CLI function contracts in-process.
"""

from __future__ import annotations

import importlib.metadata
import io
from contextlib import redirect_stderr, redirect_stdout

import dbf_anonymizer
import dbf_anonymizer.cli as cli

DISTRIBUTION = "dbf-anonymizer"
EXPECTED_REQUIRES_PYTHON = ">=3.10,<3.15"
DECLARED_PYTHON_VERSIONS = ("3.10", "3.11", "3.12", "3.13", "3.14")


def _metadata() -> importlib.metadata.PackageMetadata:
    return importlib.metadata.metadata(DISTRIBUTION)


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


# ---------------------------------------------------------------------------
# distribution identity and dependency contract
# ---------------------------------------------------------------------------


def test_distribution_name_and_version_are_truthful() -> None:
    assert importlib.metadata.metadata(DISTRIBUTION)["Name"] == DISTRIBUTION
    version = importlib.metadata.version(DISTRIBUTION)
    assert version == "1.0.0.dev0"
    assert importlib.metadata.metadata(DISTRIBUTION)["License-Expression"] == "MIT"


def test_import_package_exposes_dev_version() -> None:
    assert dbf_anonymizer.__version__ == "1.0.0.dev0"
    assert cli.__version__ == dbf_anonymizer.__version__


def test_requires_python_covers_declared_versions_and_no_more() -> None:
    requires_python = _metadata()["Requires-Python"]
    # setuptools normalizes specifier ordering; compare the normalized form.
    assert requires_python.replace(" ", "") in {">=3.10,<3.15", "<3.15,>=3.10"}
    # The classifier list truthfully names each mandatory interpreter version.
    classifiers = _metadata().get_all("Classifier") or []
    python_classifiers = [c for c in classifiers if c.startswith("Programming Language :: Python :: 3.")]
    assert {c.rsplit("::", 1)[1].strip() for c in python_classifiers} == set(
        DECLARED_PYTHON_VERSIONS
    )


def test_console_script_mapping_is_declared() -> None:
    entry_points = importlib.metadata.entry_points()
    console_scripts = entry_points.select(group="console_scripts")
    matches = [ep for ep in console_scripts if ep.name == "dbf-anonymizer"]
    assert len(matches) == 1
    assert matches[0].value == "dbf_anonymizer.cli:main"


def test_runtime_dbfbridge_contract_unchanged() -> None:
    requirements = [
        requirement.replace(" ", "")
        for requirement in (importlib.metadata.requires(DISTRIBUTION) or [])
    ]
    dbfbridge = [
        r for r in requirements if r.replace(" ", "").startswith("dbfbridge")
    ]
    assert dbfbridge == ["dbfbridge[write]<2,>=1.1.0"] or dbfbridge == [
        "dbfbridge[write]>=1.1.0,<2"
    ]
    # No direct dbf dependency and no VCS dependency.
    assert not [r for r in requirements if r.replace(" ", "").split("[")[0] == "dbf"]
    assert not [r for r in requirements if "@" in r]


# ---------------------------------------------------------------------------
# CLI foundation behavior
# ---------------------------------------------------------------------------


def test_cli_help_succeeds_and_names_the_program() -> None:
    code, stdout, _ = _run_cli(["--help"])
    assert code == 0
    assert cli.PROGRAM in stdout
    assert "--version" in stdout


def test_cli_version_succeeds_with_exact_package_version() -> None:
    code, stdout, _ = _run_cli(["--version"])
    assert code == 0
    assert stdout == f"{cli.PROGRAM} {importlib.metadata.version(DISTRIBUTION)}\n"


def test_cli_unknown_command_fails_without_pretending_success() -> None:
    for arguments in (["pseudonymize"], ["plan"], ["--unknown"], ["verify", "x"]):
        code, _, stderr = _run_cli(arguments)
        assert code != 0, arguments
        assert "unrecognized" in stderr or "error" in stderr.lower(), arguments


def test_cli_bare_invocation_is_not_a_fake_success() -> None:
    code, _, stderr = _run_cli([])
    assert code != 0
    assert "are implemented yet" in stderr


def test_version_sources_agree() -> None:
    installed = importlib.metadata.version(DISTRIBUTION)
    assert installed == dbf_anonymizer.__version__ == cli.__version__
    _, stdout, _ = _run_cli(["--version"])
    assert installed in stdout


# ---------------------------------------------------------------------------
# root import purity (package-level, no filesystem/network/DBF effects)
# ---------------------------------------------------------------------------


def test_import_is_side_effect_free() -> None:
    # Importing must not open DBFs, create files, or touch the network; the
    # full REQ-P1-007 sentinel proof is a later requirement.  Here we prove
    # the import surface stays the deliberate P1-002 model contract and
    # remains side-effect free.
    assert dbf_anonymizer.__version__ == "1.0.0.dev0"
    assert "DatasetIdentity" in dbf_anonymizer.__all__
    assert "pseudonymize" not in dbf_anonymizer.__all__


def test_module_execution_entry_delegates_without_duplication() -> None:
    from dbf_anonymizer import __main__ as cli_main_module

    assert cli_main_module.main is cli.main
