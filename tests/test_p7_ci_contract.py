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
TRUSTED_WORKFLOW = "p6-trusted-vfp-acceptance.yml"
TRUSTED_JOB = "real-vfp9-acceptance"
TRUSTED_RUNNER_VARIABLE = "vars.DBF_TRUSTED_VFP9_RUNNER_LABELS"
ARCHITECTURE_SHA256 = "483932970d44770b05fcfad7430b85820d771458110f004b0397bd5d56398615"

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
    """The concrete runner labels of one job (matrix expressions resolved).

    A ``vars.*`` reference is reported as the authoritative repository
    configuration point itself (``vars.<NAME>``) — the trusted runner label
    is deliberately NOT committed as a literal in this repository.
    """
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
        if re.search(r"\bvars\.\w+", runs_on):
            match = re.search(r"vars\.\w+", runs_on)
            assert match is not None
            return {match.group(0)}
        return set()
    return {str(runs_on)}


def test_ordinary_workflows_cannot_target_the_trusted_vfp_runner() -> None:
    """UNTRUSTED ZONE: every ordinary workflow (push/pull_request/dispatch on
    hosted runners) runs ONLY on disposable hosted Linux/Windows runners and
    never on the trusted self-hosted VFP9 machine — untrusted pull-request
    code can therefore never reach the trusted machine."""
    for name, document in _load_workflows().items():
        if name == TRUSTED_WORKFLOW:
            continue
        for job_name, job in _jobs(document).items():
            resolved = _resolved_runs_on(job)
            assert resolved, f"{name}:{job_name}: unresolved runs-on"
            unexpected = resolved - HOSTED_RUNNERS
            assert not unexpected, f"{name}:{job_name}: {unexpected}"


def test_dedicated_trusted_vfp_workflow_exists() -> None:
    """TRUSTED ZONE: the real-VFP9 acceptance lane exists as its own
    version-controlled workflow, separate from every ordinary workflow."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    assert _jobs(document), "the trusted VFP workflow has no jobs"


def test_trusted_vfp_workflow_is_dispatch_only() -> None:
    """The trusted lane may only be dispatched manually: no pull_request, no
    pull_request_target, no workflow_run and no push trigger may start it,
    so untrusted pull-request code can never schedule work on the trusted
    machine."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    triggers = _triggers(document)
    assert set(triggers) == {"workflow_dispatch"}
    assert document.get("name") is not None
    assert "trusted" in str(document.get("name", "")).lower()


def test_trusted_vfp_workflow_targets_the_authoritative_runner_configuration() -> None:
    """The trusted job's runner label comes from the authoritative repository
    variable (configured together with the trusted runner provisioning), and
    NO invented literal runner label is committed to the repository."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    job = _jobs(document)[TRUSTED_JOB]
    runs_on = str(job.get("runs-on"))
    assert TRUSTED_RUNNER_VARIABLE in runs_on, runs_on
    for name, document in _load_workflows().items():
        for job_name, job in _jobs(document).items():
            if name == TRUSTED_WORKFLOW:
                continue
            resolved = _resolved_runs_on(job)
            for label in resolved:
                assert not label.startswith("vars."), (
                    f"{name}:{job_name}: untrusted workflow targets a "
                    f"trusted-runner configuration: {label}"
                )


def test_trusted_vfp_workflow_never_executes_untrusted_pr_code() -> None:
    """The trusted workflow must never check out pull-request code: no
    ``github.event.pull_request`` reference anywhere, and a trust guard
    refuses every ref except the protected main branch."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    for step in (
        step
        for job in _jobs(document).values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict)
    ):
        run = str(step.get("run", ""))
        assert "github.event.pull_request" not in run
        assert "pull_request" not in run
        if str(step.get("uses", "")):
            assert "github.event.pull_request.head.sha" not in str(step.get("with", {}))
    runs = "\n".join(_step_runs(document))
    assert "refs/heads/main" in runs, "the trust guard must pin the trusted ref"


def test_trusted_vfp_workflow_invokes_the_established_acceptance_tool() -> None:
    """The trusted lane delegates ALL real-VFP semantics to the established
    REQ-P6-003 acceptance runner tool — no second acceptance protocol exists
    in the repository workflows."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    runs = "\n".join(_step_runs(document))
    assert "tools/run_real_vfp9_acceptance.py" in runs
    assert "run_real_vfp9_acceptance.py" in runs
    for name, runs_ in {
        workflow: "\n".join(_step_runs(document_))
        for workflow, document_ in _load_workflows().items()
        if workflow != TRUSTED_WORKFLOW
    }.items():
        assert "run_real_vfp9_acceptance" not in runs_, name


def test_trusted_vfp_workflow_verifies_exact_revision_identity() -> None:
    """The trusted lane records the exact HEAD and verifies it against
    origin/main plus the canonical immutable architecture hash."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    job = _jobs(document)[TRUSTED_JOB]
    job_texts: list[str] = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        job_texts.append(str(step.get("run", "")))
        step_env = step.get("env") or {}
        job_texts.extend(str(value) for value in step_env.values())
    text = "\n".join(job_texts)
    assert "git rev-parse HEAD" in text
    assert "origin/main" in text
    assert "--expected-head" in text
    assert "--expected-branch main" in text
    assert "--expected-architecture-sha256" in text
    assert ARCHITECTURE_SHA256 in text


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
