"""REQ-P7-009 example-suite contract: the examples/ recipes stay executable.

The examples are downstream-consumer code and must not rot:

1. every canonical example runs end to end against task-owned TEMP synthetic
   data (no network, no VFP, no production dataset, nothing outside the test
   TEMP/repository); the printed summaries stay privacy-safe: the exact test
   TEMP path, any drive-qualified path form and any user-profile fragment
   must NOT appear in stdout or stderr;
2. an explicitly supplied example workspace is REFUSED fail-closed when it
   already exists — before any DBF/FPT write, sentinel bytes preserved;
3. the consumer adapter executes a synthetic host workflow (a focused check,
   not a duplicate of the P8 acceptance suite);
4. the DOCUMENTED worked CLI recipe (the marker-marked block in
   ``docs/operations.md``) is extracted, validated for operation-binding
   consistency and executed end to end — the automated run cannot silently
   diverge from the documentation.  (Functional ``dbf_anonymizer.cli:main``
   coverage; the installed console entry point itself is proven by
   ``tests/test_p1_packaging.py::test_console_script_mapping_is_declared``
   and the installed-wheel probes in ``tests/test_p7_transport_boundary.py``.)
5. examples import ONLY supported public DBF_Anonymizer surfaces (the
   package root, plus the documented ``relationships`` schema loader) and
   only the public ``dbfbridge`` dependency — no private module, no DBF/FPT
   parser, no vault reading, no network/transport/COM/async import;
6. the example configuration JSON files parse and match the synthetic demo
   dataset the CLI recipe uses.
"""

from __future__ import annotations

import ast
import json
import re
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
    "progress_cancellation.py",
    "data_only_bundle.py",
    "external_metadata.py",
    "field_semantics_workflow.py",
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

#: The documented worked CLI recipe block marker (docs/operations.md).
CLI_RECIPE_MARKER = "p7-009-cli-recipe"

#: The CLI commands that reconstruct the plan/operation identity and must
#: therefore carry the SAME --policy/--relationships inputs when the
#: documented recipe uses them.
PLAN_RECONSTRUCTING_COMMANDS = ("plan", "preflight", "pseudonymize", "verify", "export-bundle")

#: The CLI commands that work on durable artifacts and must NOT re-derive a
#: plan from policy/relationship documents (the production CLI does not even
#: accept those options for them).
ARTIFACT_COMMANDS = ("capabilities", "recover", "verify-bundle", "self-test")


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
    completed = subprocess.run(  # noqa: S603 - task-owned synthetic example run
        [sys.executable, str(EXAMPLES_DIR / example), str(tmp_path / "work")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    assert completed.returncode == 0, f"{example} failed:\n{completed.stdout}\n{completed.stderr}"
    assert completed.stdout.strip(), f"{example} printed no summary"
    # Privacy-safe stdout/stderr: the exact test TEMP path, any drive-qualified
    # path form and any user-profile fragment must NOT appear.
    for stream in (completed.stdout, completed.stderr):
        assert str(tmp_path) not in stream, example
        assert re.search(r"[A-Za-z]:[\\/]", stream) is None, example
        assert "Users/" not in stream and "Users\\" not in stream, example


def test_basic_workflow_outcome(tmp_path: Path) -> None:
    stdout = _run_example("basic_workflow.py", tmp_path / "work")
    assert "verification status: PASS" in stdout
    assert "assurance level: GLOBAL_EXACT_VALUE" in stdout
    assert "SOURCE role:" in stdout and "VAULT role:" in stdout


def test_relationship_workflow_proves_the_declared_fk(tmp_path: Path) -> None:
    stdout = _run_example("relationship_workflow.py", tmp_path / "work")
    assert "verification status: PASS" in stdout
    assert "assurance level: DECLARED_RELATIONS_VERIFIED" in stdout


def test_recovery_workflow_proves_both_authorization_paths(tmp_path: Path) -> None:
    stdout = _run_example("recovery_workflow.py", tmp_path / "work")
    assert "ENABLED:  canonical_verified=True" in stdout
    assert "DISABLED: typed refusal RECOVERY_NOT_PERMITTED" in stdout


def test_progress_cancellation_example_is_deterministic(tmp_path: Path) -> None:
    stdout = _run_example("progress_cancellation.py", tmp_path / "work")
    assert "verification status: PASS" in stdout
    assert "cancellation code: OPERATION_CANCELLED" in stdout
    assert "no COMPLETED event, no published output" in stdout
    assert "phases in order:" in stdout


def test_data_only_workflow_proves_the_transferable_bundle(tmp_path: Path) -> None:
    stdout = _run_example("data_only_bundle.py", tmp_path / "work")
    assert "bundle verified standalone:   True" in stdout
    assert "NOT anonymous" in stdout


def test_external_metadata_workflow_proves_the_injected_envelope(tmp_path: Path) -> None:
    stdout = _run_example("external_metadata.py", tmp_path / "work")
    assert "verification status: PASS" in stdout
    assert "assurance level: VFP_METADATA_VERIFIED" in stdout
    assert "does NOT cause relational assurance" in stdout
    assert "does NOT by itself prove that an output CDX/IDX was rebuilt" in stdout


def test_field_semantics_workflow_proves_the_field_facts(tmp_path: Path) -> None:
    stdout = _run_example("field_semantics_workflow.py", tmp_path / "work")
    assert "C/V cross-type proof passed" in stdout
    assert "VARCHAR SHARES THE TEXT DOMAIN (proven above)" in stdout
    assert "NULL and empty values stay identities" in stdout
    assert "deleted records: marker + physical order preserved, content transformed" in stdout
    assert "memo/FPT: freshly written, masked, no canary in output DBF/FPT or bundle" in stdout
    assert "verification status: PASS" in stdout
    assert "recovery: canonical_verified=True" in stdout
    assert "bundle verified standalone: True" in stdout


def test_field_semantics_fixture_provides_a_cross_type_shared_value(tmp_path: Path) -> None:
    """NON-VACUITY GUARD: the advanced fixture really carries THE SAME
    non-empty logical value in a Character and a Varchar field (also inside
    the deleted record), plus the NULL/empty/distinct/memo coverage."""
    import dbfbridge
    from examples import synthetic_dataset

    source = synthetic_dataset.create_field_semantics_dataset(tmp_path / "source")
    records = tuple(
        dbfbridge.iter_records(source / "registry.dbf", include_deleted=True, memo="inline")
    )
    by_id = {record.values["ID"]: record for record in records}
    shared = by_id[1].values["NAME"]
    assert (
        shared == by_id[1].values["VARVAL"] == by_id[3].values["NAME"] == by_id[3].values["VARVAL"]
    )
    assert isinstance(shared, str) and shared != ""
    assert by_id[2].values["NAME"] is None and by_id[2].values["VARVAL"] is None
    assert by_id[4].values["VARVAL"] == ""
    assert by_id[4].values["NAME"] not in (None, "", shared)
    assert by_id[3].deleted is True
    assert all(
        isinstance(by_id[identifier].values["NOTE"], str) and by_id[identifier].values["NOTE"]
        for identifier in (1, 2, 3, 4)
    )


def test_varchar_character_shared_domain_value_level_proof(tmp_path: Path) -> None:
    """VALUE-LEVEL C/V CROSS-TYPE REGRESSION: after the public workflow the
    SAME original logical text in a Character and a Varchar field yields the
    SAME pseudonym — also for the deleted record.  Public dbfbridge reads
    only; no SQLite mapping inspection."""
    import dbfbridge
    from examples import synthetic_dataset

    source = synthetic_dataset.create_field_semantics_dataset(tmp_path / "source")
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan = public.build_plan(source, output, vault)
    assert public.preflight(plan).ready
    result = public.pseudonymize(plan)
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS

    records = tuple(
        dbfbridge.iter_records(output / "registry.dbf", include_deleted=True, memo="inline")
    )
    by_id = {record.values["ID"]: record for record in records}
    pseudonym = by_id[1].values["NAME"]
    assert (
        pseudonym
        == by_id[1].values["VARVAL"]
        == by_id[3].values["NAME"]
        == by_id[3].values["VARVAL"]
    )
    assert pseudonym not in (None, "")
    assert by_id[2].values["NAME"] is None and by_id[2].values["VARVAL"] is None
    assert by_id[4].values["VARVAL"] == ""
    assert by_id[4].values["NAME"] not in (None, "", pseudonym)


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
    """The DOCUMENTED worked CLI recipe (the marker-marked block in
    ``docs/operations.md``) is extracted verbatim, validated for
    operation-binding consistency, and executed end to end — the automated
    run cannot silently diverge from the documentation."""
    recipe = _documented_cli_recipe_lines()
    work = tmp_path / "demo-work"
    executed: set[str] = set()
    for line in recipe:
        normalized = line.replace("$work", str(work)).replace("\\", "/")
        tokens = [token.strip('"') for token in normalized.split()]
        program = tokens[0]
        if program == "python":
            # The demo-dataset creation line of the recipe itself.
            assert tokens[1].endswith("synthetic_dataset.py"), line
            created = subprocess.run(  # noqa: S603 - task-owned documented recipe step
                [sys.executable, *tokens[1:]],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
            )
            assert created.returncode == 0, f"recipe step failed: {line}\n{created.stderr}"
            continue
        assert program == "dbf-anonymizer", f"unexpected recipe line: {line}"
        command = tokens[1]
        executed.add(command)
        code = _run_cli(*tokens[1:])
        assert code == 0, f"documented recipe command failed ({code}): {line}"
    assert executed == set(public_commands()), f"recipe commands mismatch: {executed}"


def public_commands() -> tuple[str, ...]:
    from dbf_anonymizer.cli import COMMANDS

    return COMMANDS


def _documented_cli_recipe_lines() -> list[str]:
    """Extract the EXACT dbf-anonymizer/python command lines of the ONE
    documented worked recipe (deliberately narrow, deterministic extraction:
    only the marker-marked fenced block, only real command lines)."""
    text = (REPO_ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    recipe: list[str] = []
    inside = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```") and CLI_RECIPE_MARKER in stripped:
            assert not inside, "the documented CLI recipe marker must appear once"
            inside = True
            continue
        if inside and stripped.startswith("```"):
            inside = False
            continue
        if inside and stripped and not stripped.startswith("#") and not stripped.startswith("$"):
            recipe.append(stripped)
    assert not inside, "the documented CLI recipe block is not closed"
    assert recipe, "the documented worked CLI recipe is missing from operations.md"
    return recipe


def test_documented_cli_recipe_is_operation_binding_consistent() -> None:
    """The documented worked recipe must keep the completed-operation identity
    intact: every plan-reconstructing command carries the SAME policy and
    relationship inputs, and the artifact commands carry none (the production
    CLI does not accept them there).  Removing ``--policy`` or
    ``--relationships`` from the documented ``export-bundle`` command FAILS
    this test."""
    recipe = _documented_cli_recipe_lines()
    commands: dict[str, list[str]] = {}
    dataset_created = False
    for line in recipe:
        tokens = [token.strip('"') for token in line.split()]
        if tokens[0] == "python":
            assert tokens[1].replace("\\", "/").endswith("examples/synthetic_dataset.py"), line
            dataset_created = True
            continue
        assert tokens[0] == "dbf-anonymizer", f"unexpected recipe line: {line}"
        commands[tokens[1]] = tokens[2:]
    assert dataset_created, "the recipe must create its synthetic demo dataset"
    assert set(commands) == set(public_commands()), commands
    config_arguments = (
        "examples/config/policy-data-only.json",
        "examples/config/relationships.json",
    )
    for command in PLAN_RECONSTRUCTING_COMMANDS:
        arguments = commands[command]
        for required in ("--policy", "--relationships"):
            assert required in arguments, f"{command}: missing {required}"
            index = arguments.index(required)
            value = arguments[index + 1].replace("\\", "/")
            assert value in config_arguments, f"{command}: unexpected {required} {value!r}"
            assert (REPO_ROOT / value).is_file(), f"{command}: {value} does not exist"
    for command in ARTIFACT_COMMANDS:
        arguments = commands[command]
        for forbidden in ("--policy", "--relationships"):
            assert forbidden not in arguments, f"{command} must not carry {forbidden}"


# ---------------------------------------------------------------------------
# 1b. Fail-closed example workspaces (examples-only safety policy)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("example", CANONICAL_EXAMPLES)
def test_example_refuses_an_existing_workspace_before_any_write(
    example: str, tmp_path: Path
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    sentinel = existing / "sentinel.txt"
    sentinel.write_bytes(b"SENTINEL-BYTES-KEEP")
    completed = subprocess.run(  # noqa: S603 - task-owned fail-closed refusal probe
        [sys.executable, str(EXAMPLES_DIR / example), str(existing)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert completed.returncode != 0, f"{example} reused an existing workspace"
    assert "refused" in completed.stdout + completed.stderr, example
    assert sentinel.read_bytes() == b"SENTINEL-BYTES-KEEP", example
    assert not list(existing.glob("*.dbf")), example
    assert not list(existing.glob("*.fpt")), example


def test_synthetic_helper_refuses_existing_dataset_roots(tmp_path: Path) -> None:
    """The helper functions themselves are fail-closed: an existing root is
    never reused and nothing is written before the refusal."""
    from examples import synthetic_dataset

    existing = tmp_path / "dataset"
    existing.mkdir()
    sentinel = existing / "sentinel.txt"
    sentinel.write_bytes(b"KEEP")
    for create in (
        synthetic_dataset.create_single_table_dataset,
        synthetic_dataset.create_related_dataset,
        synthetic_dataset.create_field_semantics_dataset,
    ):
        with pytest.raises(FileExistsError):
            create(existing)
    assert sentinel.read_bytes() == b"KEEP"
    assert not list(existing.glob("*.dbf"))


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
