"""REQ-P7-009 example-suite contract: the examples/ recipes stay executable.

The examples are downstream-consumer code and must not rot:

1. every canonical example runs end to end against task-owned TEMP synthetic
   data (no network, no VFP, no production dataset, nothing outside the test
   TEMP/repository);
2. the consumer adapter executes a synthetic host workflow (a focused check,
   not a duplicate of the P8 acceptance suite);
3. examples import ONLY supported public DBF_Anonymizer surfaces (the
   package root, plus the documented ``relationships`` schema loader) and
   only the public ``dbfbridge`` dependency — no private module, no DBF/FPT
   parser, no vault reading, no network/transport/COM/async import;
4. the example configuration JSON files parse and match the synthetic demo
   dataset the CLI recipe uses.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

import dbf_anonymizer as public
from tests.test_p7_transport_boundary import FORBIDDEN_TRANSPORT_ROOTS, _import_roots

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"

#: The canonical executable examples (the progressive learning path).
CANONICAL_EXAMPLES = (
    "basic_workflow.py",
    "relationship_workflow.py",
    "recovery_workflow.py",
    "data_only_bundle.py",
    "external_metadata.py",
)

#: The ONLY supported DBF_Anonymizer import surfaces for consumer examples:
#: the public package root plus the documented relationships loader namespace.
ALLOWED_DBF_ANONYMIZER_IMPORTS = frozenset({"dbf_anonymizer", "dbf_anonymizer.relationships"})

#: Extra forbidden import roots beyond the transport frameworks: no network,
#: no async API, no COM/VFP automation, no direct ``dbf`` library, and no
#: SQLite vault access from example code.
FORBIDDEN_EXAMPLE_ROOTS = FORBIDDEN_TRANSPORT_ROOTS | frozenset(
    {
        "socket",
        "ssl",
        "urllib",
        "urllib3",
        "http",
        "ftplib",
        "smtplib",
        "asyncio",
        "win32com",
        "pythoncom",
        "sqlite3",
        "dbf",
    }
)


def _example_sources() -> dict[str, str]:
    sources = {
        path.name: path.read_text(encoding="utf-8") for path in sorted(EXAMPLES_DIR.glob("*.py"))
    }
    assert sources, "no examples found"
    return sources


def _run_example(example: str, work_root: Path) -> str:
    completed = subprocess.run(  # noqa: S603 - task-owned synthetic example run
        [sys.executable, str(EXAMPLES_DIR / example), str(work_root)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    assert completed.returncode == 0, f"{example} failed:\n{completed.stdout}\n{completed.stderr}"
    return completed.stdout


# ---------------------------------------------------------------------------
# 1. Executable canonical examples (task-owned TEMP synthetic data)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("example", CANONICAL_EXAMPLES)
def test_canonical_example_runs_on_synthetic_temp_data(example: str, tmp_path: Path) -> None:
    stdout = _run_example(example, tmp_path / "work")
    assert stdout.strip(), f"{example} printed no summary"


def test_basic_workflow_outcome(tmp_path: Path) -> None:
    stdout = _run_example("basic_workflow.py", tmp_path / "work")
    assert "verification status: PASS" in stdout
    assert "assurance level: GLOBAL_EXACT_VALUE" in stdout


def test_relationship_workflow_proves_the_declared_fk(tmp_path: Path) -> None:
    stdout = _run_example("relationship_workflow.py", tmp_path / "work")
    assert "verification status: PASS" in stdout
    assert "assurance level: DECLARED_RELATIONS_VERIFIED" in stdout


def test_recovery_workflow_proves_both_authorization_paths(tmp_path: Path) -> None:
    stdout = _run_example("recovery_workflow.py", tmp_path / "work")
    assert "ENABLED:  canonical_verified=True" in stdout
    assert "DISABLED: typed refusal RECOVERY_NOT_PERMITTED" in stdout


def test_data_only_workflow_proves_the_transferable_bundle(tmp_path: Path) -> None:
    stdout = _run_example("data_only_bundle.py", tmp_path / "work")
    assert "bundle verified standalone:   True" in stdout
    assert "NOT anonymous" in stdout


def test_external_metadata_workflow_proves_the_injected_envelope(tmp_path: Path) -> None:
    stdout = _run_example("external_metadata.py", tmp_path / "work")
    assert "verification status: PASS" in stdout
    assert "assurance level: VFP_METADATA_VERIFIED" in stdout
    assert "does NOT by itself prove that an output CDX/IDX was rebuilt" in stdout


def test_consumer_adapter_runs_a_synthetic_host_workflow(tmp_path: Path) -> None:
    """A focused synthetic end-to-end host call through the thin adapter."""
    from examples import consumer_adapter, synthetic_dataset

    source = synthetic_dataset.create_single_table_dataset(tmp_path / "source")
    result = consumer_adapter.run_consumer_workflow(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
    )
    assert result.preflight.ready is True
    assert result.pseudonymization is not None
    assert result.verification is not None
    assert result.verification.status is public.VerificationStatus.PASS


def test_synthetic_dataset_helper_is_deterministic(tmp_path: Path) -> None:
    from examples import synthetic_dataset

    first = synthetic_dataset.create_related_dataset(tmp_path / "first")
    second = synthetic_dataset.create_related_dataset(tmp_path / "second")
    for relative in ("people.dbf", "orders.dbf"):
        assert (first / relative).read_bytes() == (second / relative).read_bytes()


def _run_cli(*arguments: str) -> int:
    completed = subprocess.run(  # noqa: S603 - task-owned CLI recipe run
        [
            sys.executable,
            "-c",
            "import sys; from dbf_anonymizer.cli import main; sys.exit(main())",
            *arguments,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    return completed.returncode


def test_complete_cli_workflow_recipe(tmp_path: Path) -> None:
    """The documented CLI recipe (operations.md) works end to end with the
    shipped example configuration files on synthetic data only."""
    created = subprocess.run(  # noqa: S603 - task-owned synthetic dataset creation
        [sys.executable, str(EXAMPLES_DIR / "synthetic_dataset.py"), str(tmp_path / "source")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert created.returncode == 0, created.stderr
    work = tmp_path
    source = str(work / "source")
    output = str(work / "output")
    vault = str(work / "protected" / "recovery.sqlite3")
    policy = str(EXAMPLES_DIR / "config" / "policy-data-only.json")
    relationships = str(EXAMPLES_DIR / "config" / "relationships.json")
    commands = (
        ("capabilities", "--json"),
        (
            "plan",
            source,
            output,
            vault,
            "--policy",
            policy,
            "--relationships",
            relationships,
            "--json",
        ),
        (
            "preflight",
            source,
            output,
            vault,
            "--policy",
            policy,
            "--relationships",
            relationships,
            "--json",
        ),
        (
            "pseudonymize",
            source,
            output,
            vault,
            "--policy",
            policy,
            "--relationships",
            relationships,
            "--json",
        ),
        (
            "verify",
            source,
            output,
            vault,
            "--policy",
            policy,
            "--relationships",
            relationships,
            "--json",
        ),
        (
            "recover",
            output,
            vault,
            str(work / "recovered"),
            "--recovery-policy",
            "enabled",
            "--json",
        ),
        (
            "export-bundle",
            source,
            output,
            vault,
            str(work / "bundle"),
            "--policy",
            policy,
            "--relationships",
            relationships,
            "--json",
        ),
        ("verify-bundle", str(work / "bundle"), "--json"),
        ("self-test", "--json"),
    )
    for command in commands:
        code = _run_cli(*command)
        assert code == 0, f"CLI command failed ({code}): {command[0]}"


# ---------------------------------------------------------------------------
# 2. Structural boundary: consumer-code imports only
# ---------------------------------------------------------------------------


def test_examples_import_only_supported_public_surfaces() -> None:
    for name, text in _example_sources().items():
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("dbf_anonymizer"):
                        assert alias.name in ALLOWED_DBF_ANONYMIZER_IMPORTS, (
                            f"{name}: private/internal import {alias.name!r}"
                        )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.startswith("dbf_anonymizer"):
                    assert module in ALLOWED_DBF_ANONYMIZER_IMPORTS, (
                        f"{name}: private/internal import {module!r}"
                    )


def test_examples_use_no_forbidden_runtime_roots() -> None:
    for name, text in _example_sources().items():
        roots = _import_roots(text)
        forbidden = sorted(roots & FORBIDDEN_EXAMPLE_ROOTS)
        assert not forbidden, f"{name}: forbidden import roots {forbidden}"


def test_examples_are_synchronous_consumer_code() -> None:
    for name, text in _example_sources().items():
        tree = ast.parse(text)
        assert not any(
            isinstance(node, (ast.AsyncFunctionDef, ast.Await)) for node in ast.walk(tree)
        ), f"{name}: examples must stay synchronous"


def test_examples_contain_no_private_paths_or_secrets() -> None:
    """Example sources hardcode no machine-private absolute paths and no
    secret-looking material; workspaces come from the runtime TEMP only."""
    for name, text in _example_sources().items():
        assert "C:\\" not in text and "C:/" not in text, name
        assert "Users/" not in text and "/home/" not in text, name
        for secret_pattern in ("-----BEGIN", "ghp_", "AKIA", "password=", "token="):
            assert secret_pattern not in text, f"{name}: {secret_pattern}"


def test_examples_never_print_vault_rows_or_original_canaries(tmp_path: Path) -> None:
    """The canonical stdout is privacy-safe: no synthetic canary value and no
    vault-row vocabulary appears in the printed summaries."""
    for example in CANONICAL_EXAMPLES:
        stdout = _run_example(example, tmp_path / f"work-{example}")
        assert "SYNTH-" not in stdout, example
        assert "INSERT INTO" not in stdout and "SELECT " not in stdout, example


# ---------------------------------------------------------------------------
# 3. Example configuration files (CLI recipe support)
# ---------------------------------------------------------------------------


def test_example_config_files_parse_and_match_the_demo_dataset(tmp_path: Path) -> None:
    from examples import synthetic_dataset

    policy = json.loads(
        (EXAMPLES_DIR / "config" / "policy-data-only.json").read_text(encoding="utf-8")
    )
    assert policy["schema_version"] == 1
    assert policy["indexes"] == {"profile": "DATA_ONLY"}
    relationships = json.loads(
        (EXAMPLES_DIR / "config" / "relationships.json").read_text(encoding="utf-8")
    )
    assert relationships == synthetic_dataset.policy_relationship_document()

    # The declared members must match the real synthetic demo dataset: build
    # a plan with BOTH configuration files and pass preflight.
    source = synthetic_dataset.create_related_dataset(tmp_path / "source")
    plan = public.build_plan(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
        policy=policy,
        relationship_document=relationships,
    )
    assert public.preflight(plan).ready
