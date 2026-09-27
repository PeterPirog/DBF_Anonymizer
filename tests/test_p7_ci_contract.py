"""REQ-P7-006 CI contract: structural workflow evidence.

Parses every version-controlled workflow YAML with PyYAML and proves the
comprehensive gate matrix structurally:

* bounded permissions and untrusted-trigger isolation (no
  ``pull_request_target``/``workflow_run``, hosted runners only, so untrusted
  pull-request code can never execute on a trusted self-hosted VFP runner);
* the trusted real-VFP acceptance tool never runs inside CI (manual/trusted
  execution only);
* format / lint / strict typecheck / compile gates exist;
* package build + twine + wheel-metadata + dependency/security audit gates
  exist;
* a Windows job covers EVERY Python minor version declared by
  ``requires-python``;
* the required test families (unit / integration / privacy / relationship /
  recovery / transfer-bundle / malformed-adversarial) are integrated as
  explicit CI steps;
* cross-platform (Linux and Windows) no-VFP hosted smoke exists;
* the accepted P0 package-boundary jobs are preserved.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

BOUNDARY_WORKFLOW = "p0-package-boundary.yml"
GATES_WORKFLOW = "p7-comprehensive-gates.yml"

ACCEPTED_BOUNDARY_JOBS = (
    "dbfbridge-floor-compatibility",
    "clean-wheel-boundary",
    "packaging-versions",
    "p4-windows-concurrency-locking",
    "p7-windows-offline-wheelhouse",
    "tests",
)

HOSTED_RUNNERS = frozenset({"ubuntu-latest", "windows-latest"})
ALLOWED_TRIGGERS = frozenset({"push", "pull_request", "workflow_dispatch"})


def _load_workflows() -> dict[str, dict[Any, Any]]:
    workflows: dict[str, dict[Any, Any]] = {}
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        workflows[path.name] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return workflows


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML parses the bare "on:" key as boolean True.
    triggers: Any = workflow.get(True)
    if triggers is None:
        triggers = workflow.get("on") or {}
    assert isinstance(triggers, dict)
    return triggers


def _jobs(workflow: dict[Any, Any]) -> dict[str, dict[str, Any]]:
    return dict(workflow.get("jobs") or {})


def _step_runs(workflow: dict[str, Any]) -> list[str]:
    runs: list[str] = []
    for job in _jobs(workflow).values():
        for step in job.get("steps") or []:
            run = step.get("run")
            if isinstance(run, str):
                runs.append(run)
    return runs


def _python_matrix(job: dict[str, Any]) -> set[str]:
    strategy = job.get("strategy") or {}
    matrix = strategy.get("matrix") or {}
    versions = matrix.get("python-version")
    if versions is None:
        return set()
    if isinstance(versions, str):
        return {versions}
    return {str(version) for version in versions}


def _declared_python_minors() -> set[str]:
    """The Python minor versions declared by pyproject requires-python."""
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    match = re.search(r"requires-python\s*=\s*\">=(\d+)\.(\d+),<(\d+)\.(\d+)\"", text)
    assert match, "pyproject must declare a bounded requires-python range"
    low = (int(match.group(1)), int(match.group(2)))
    high = (int(match.group(3)), int(match.group(4)))
    minors: set[str] = set()
    major = low[0]
    minor = low[1]
    while (major, minor) < (high[0], high[1]):
        minors.add(f"{major}.{minor}")
        minor += 1
        if minor > 20:  # pragma: no cover - defensive bound
            break
    return minors


def _all_workflows() -> dict[str, dict[str, Any]]:
    workflows = _load_workflows()
    assert workflows, "no workflow YAML files found"
    return workflows


def test_workflows_are_version_controlled_and_parse() -> None:
    workflows = _load_workflows()
    assert BOUNDARY_WORKFLOW in workflows
    assert GATES_WORKFLOW in workflows
    for name, document in workflows.items():
        assert isinstance(document, dict), name
        assert isinstance(_jobs(document), dict), name


def test_all_workflows_declare_bounded_permissions() -> None:
    for name, document in _load_workflows().items():
        permissions = document.get("permissions")
        assert permissions == {"contents": "read"}, name
        for job_name, job in _jobs(document).items():
            job_permissions = job.get("permissions")
            assert job_permissions in (None, {"contents": "read"}), f"{name}:{job_name}"


def test_no_untrusted_trigger_reaches_any_runner() -> None:
    """No pull_request_target/workflow_run trigger may exist anywhere, so
    untrusted pull-request code can never execute in an elevated context."""
    for name, document in _load_workflows().items():
        triggers = _triggers(document)
        assert isinstance(triggers, dict), name
        unexpected = set(triggers) - ALLOWED_TRIGGERS
        assert not unexpected, f"{name}: untrusted triggers {unexpected}"


def _resolved_runs_on(job: dict[str, Any]) -> set[str]:
    """The concrete runner labels of one job (matrix expressions resolved)."""
    runs_on = job.get("runs-on")
    if isinstance(runs_on, str) and "${{" in runs_on:
        strategy = job.get("strategy") or {}
        matrix = strategy.get("matrix") or {}
        if "matrix.os" in str(runs_on):
            os_values = matrix.get("os")
            if os_values is None:
                os_values = [
                    include.get("os")
                    for include in matrix.get("include") or []
                    if isinstance(include, dict) and include.get("os")
                ]
            return {str(value) for value in os_values}
        return set()
    return {str(runs_on)}


def test_only_hosted_runners_are_used() -> None:
    """Every job runs on a disposable hosted runner (Linux/Windows), so no
    untrusted pull-request code can ever reach a trusted self-hosted VFP9
    runner; real VFP acceptance stays manual and trusted (see the next
    test)."""
    for name, document in _load_workflows().items():
        for job_name, job in _jobs(document).items():
            resolved = _resolved_runs_on(job)
            assert resolved, f"{name}:{job_name}: unresolved runs-on"
            unexpected = resolved - HOSTED_RUNNERS
            assert not unexpected, f"{name}:{job_name}: {unexpected}"


def test_trusted_real_vfp_acceptance_never_runs_in_ci() -> None:
    """The real-VFP acceptance tool is MANUAL and trusted-only: no workflow
    may invoke it or declare the VFP availability sentinel."""
    for name, runs in {
        workflow: _step_runs(document) for workflow, document in _load_workflows().items()
    }.items():
        for run in runs:
            assert "run_real_vfp9_acceptance" not in run, name
            assert "DBF_ANONYMIZER_REAL_VFP9_AVAILABLE" not in run, name
            assert "DBF_ANONYMIZER_REAL_VFP9_BACKEND_FACTORY" not in run, name


def test_format_lint_typecheck_and_compile_gates_exist() -> None:
    runs = "\n".join(run for document in _load_workflows().values() for run in _step_runs(document))
    assert "ruff format --check ." in runs
    assert "ruff check ." in runs
    assert "mypy --strict src/dbf_anonymizer" in runs
    assert "compileall -q src tests tools" in runs


def test_package_twine_metadata_and_audit_gates_exist() -> None:
    runs = "\n".join(run for document in _load_workflows().values() for run in _step_runs(document))
    assert "python -m build" in runs
    assert "twine check" in runs
    assert "check_wheel_metadata.py" in runs
    assert "pip-audit" in runs
    assert "pip check" in runs
    assert "check_p7_offline_wheelhouse.py" in runs
    assert "check_p7_installed_wheel.py" in runs


def test_windows_jobs_cover_every_declared_python_version() -> None:
    declared = _declared_python_minors()
    assert declared == {"3.10", "3.11", "3.12", "3.13", "3.14"}
    covered: set[str] = set()
    for document in _load_workflows().values():
        for job_name, job in _jobs(document).items():
            runs_on = job.get("runs-on")
            if runs_on == "windows-latest":
                covered |= _python_matrix(job)
    assert declared <= covered, f"missing Windows versions: {declared - covered}"


def test_category_gates_integrate_every_required_test_family() -> None:
    document = _load_workflows()[GATES_WORKFLOW]
    runs = "\n".join(_step_runs(document))
    for family, test_file in (
        ("unit", "test_p1_errors.py"),
        ("integration", "test_public_workflow_acceptance.py"),
        ("property", "test_p2_global_adversarial.py"),
        ("privacy", "test_p7_privacy_diagnostics.py"),
        ("relationship", "test_p3_relationship_verification.py"),
        ("recovery", "test_p5_recovery.py"),
        ("transfer-bundle", "test_p5_transfer_bundle.py"),
        ("malformed-input", "test_p2_global_adversarial.py"),
    ):
        assert test_file in runs, f"missing {family} gate"


def test_transfer_contamination_gate_is_explicit() -> None:
    document = _load_workflows()[GATES_WORKFLOW]
    contamination_jobs = [
        job_name
        for job_name, job in _jobs(document).items()
        if "contamination" in str(job.get("name", "")).lower()
    ]
    assert contamination_jobs, "the DATA_ONLY contamination job is missing"
    runs = "\n".join(_step_runs(document))
    assert "test_p6_data_only.py" in runs
    assert "test_p5_transfer_bundle.py" in runs
    assert "test_p6_idx.py" in runs


def test_cross_platform_no_vfp_smoke_exists() -> None:
    document = _load_workflows()[GATES_WORKFLOW]
    smoke_jobs = [
        job
        for job in _jobs(document).values()
        if "check_p7_no_vfp_smoke.py"
        in "\n".join(
            step.get("run", "") for step in (job.get("steps") or []) if isinstance(step, dict)
        )
    ]
    assert smoke_jobs, "the no-VFP smoke job is missing"
    operating_systems: set[str] = set()
    for job in smoke_jobs:
        operating_systems |= _resolved_runs_on(job)
    assert {"ubuntu-latest", "windows-latest"} <= operating_systems


def test_accepted_package_boundary_jobs_are_preserved() -> None:
    document = _load_workflows()[BOUNDARY_WORKFLOW]
    assert set(_jobs(document)) >= set(ACCEPTED_BOUNDARY_JOBS)
