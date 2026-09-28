"""REQ-P7-006 CI contract: structural workflow evidence + platform-policy spec.

Parses every version-controlled workflow YAML with PyYAML and proves the
comprehensive gate matrix structurally:

* bounded permissions and untrusted-trigger isolation (no
  ``pull_request_target``/``workflow_run`` anywhere; ordinary checked-in
  workflows target only hosted Linux/Windows runners);
* the TWO-TRUST-ZONE model: an ordinary (untrusted) zone and a DEDICATED
  trusted real-VFP lane that is workflow_dispatch-only, refuses every ref
  except the main branch, never checks out caller-provided refs, requires the
  platform-authorized runner-group boundary (``runs-on`` ``group``+``labels``
  bound to authoritative repository variables — fail-closed, no invented
  names), and invokes the established REQ-P6-003 acceptance tool with exact
  revision/architecture identity;
* a machine-readable PLATFORM POLICY SPECIFICATION exists that states the
  required external runner-group configuration.  That file is explicitly a
  SPECIFICATION, not proof: platform isolation and real-VFP execution remain
  EXTERNAL, live-verified evidence for the requirements that explicitly
  demand them;
* the acceptance contract describes green mandatory jobs for the reviewed
  change WITHOUT claiming execution on an exact HEAD SHA: hosted
  ``pull_request`` workflows execute the prospective merge ref
  (``refs/pull/<N>/merge``), so an exact-HEAD claim would be admissible only
  if a hosted workflow objectively enforced such a checkout;
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

Immutable acceptance semantics (REQ-P7-006): the acceptance evidence is
version-controlled workflows and green mandatory jobs.  Real-VFP9 execution
is CONDITIONAL evidence for requirements that explicitly demand it (especially
REQ-P6-003) — the ABSENCE of a provisioned trusted self-hosted VFP runner
never invalidates the repository-side CI/isolation acceptance, and this
module forbids any policy field that turns live VFP execution or external
runner provisioning into an additional mandatory REQ-P7-006 closure gate.

Evidence classes (deliberately distinguished):
A. repository structural evidence — what this module asserts from YAML/JSON
   committed to the repository;
B. external platform policy evidence — runner-group configuration and real
   trusted-runner execution, verifiable ONLY from live GitHub configuration
   and a dispatched run; this module can require the SPECIFICATION and its
   fail-closed wiring, but can never fabricate the external proof.
"""

from __future__ import annotations

import json
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
TRUSTED_GROUP_VARIABLE = "vars.DBF_TRUSTED_VFP9_RUNNER_GROUP"
TRUSTED_LABELS_VARIABLE = "vars.DBF_TRUSTED_VFP9_RUNNER_LABELS"
TRUSTED_POLICY_SPEC = ".github/trusted-vfp-runner-policy.json"
TRUSTED_WORKFLOW_PATH = ".github/workflows/p6-trusted-vfp-acceptance.yml"
# REQ-P7-008: the dedicated PRIVILEGED release lane is the only workflow that
# may hold id-token/attestations/publication authority; it is trigger-isolated
# from pull_request execution (see test_p7_release_ci_contract.py).
PRIVILEGED_RELEASE_WORKFLOW = "dbf-release-publish.yml"
PRIVILEGED_RELEASE_POLICY_SPEC = ".github/release-publishing-policy.json"
CANONICAL_SELECTED_WORKFLOW_TEMPLATE = (
    "<FINAL_OWNER>/DBF_Anonymizer/.github/workflows/p6-trusted-vfp-acceptance.yml@refs/heads/main"
)
ARCHITECTURE_SHA256 = "483932970d44770b05fcfad7430b85820d771458110f004b0397bd5d56398615"
IMMUTABLE_ACCEPTANCE_EVIDENCE = "version-controlled workflows and green mandatory jobs"
FORBIDDEN_EXACT_HEAD_WORDING = "exact reviewed HEAD"
EXACT_REVISION_CLAIM = re.compile(r"\bexact\b[^.]*\b(?:HEAD|SHA)\b", re.IGNORECASE)

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
# The privileged release lane never executes for untrusted pull-request code;
# its only authorized triggers are an explicit release publication or a
# deliberate main/tag dispatch.
ALLOWED_PRIVILEGED_RELEASE_TRIGGERS = frozenset({"release", "workflow_dispatch"})
FORBIDDEN_TRIGGERS = frozenset({"pull_request_target", "workflow_run", "repository_dispatch"})
ALLOWED_JOB_PERMISSIONS = (None, {"contents": "read"})
ALLOWED_PRIVILEGED_RELEASE_JOB_PERMISSIONS = (
    {"contents": "read"},
    {"contents": "read", "id-token": "write", "attestations": "write"},
    {"contents": "read", "id-token": "write"},
)


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


def _trusted_policy() -> dict[str, Any]:
    """Parse the machine-readable trusted runner policy SPECIFICATION."""
    spec_path = REPO_ROOT / TRUSTED_POLICY_SPEC
    policy = json.loads(spec_path.read_text(encoding="utf-8"))
    assert isinstance(policy, dict)
    return policy


def _all_workflows() -> dict[str, dict[str, Any]]:
    workflows = _load_workflows()
    assert workflows, "no workflow YAML files found"
    return workflows


def _hosted_pull_request_workflows() -> dict[str, dict[str, Any]]:
    """The ordinary hosted workflows triggered by ``pull_request`` (never the
    dispatch-only trusted lane)."""
    return {
        name: document
        for name, document in _load_workflows().items()
        if name != TRUSTED_WORKFLOW and "pull_request" in _triggers(document)
    }


def _hosted_workflows_pin_head_sha_checkout() -> bool:
    """Whether any hosted pull_request workflow OBJECTIVELY enforces a checkout
    of the PR head SHA via an explicit ``ref:``.  With the default checkout
    GitHub executes the prospective merge ref ``refs/pull/<N>/merge`` instead
    of the branch HEAD."""
    for document in _hosted_pull_request_workflows().values():
        for job in _jobs(document).values():
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                if not str(step.get("uses", "")).startswith("actions/checkout"):
                    continue
                ref = (step.get("with") or {}).get("ref")
                if ref is not None and "head.sha" in str(ref):
                    return True
    return False


def test_workflows_are_version_controlled_and_parse() -> None:
    workflows = _load_workflows()
    assert BOUNDARY_WORKFLOW in workflows
    assert GATES_WORKFLOW in workflows
    for name, document in workflows.items():
        assert isinstance(document, dict), name
        assert isinstance(_jobs(document), dict), name


def test_all_workflows_declare_bounded_permissions() -> None:
    """Every workflow declares top-level ``contents: read``.  Ordinary jobs may
    hold no elevated permissions at all; the dedicated PRIVILEGED release lane
    (REQ-P7-008) is the ONLY place where ``id-token: write`` /
    ``attestations: write`` may appear, in exactly the enumerated minimal
    combinations."""
    for name, document in _load_workflows().items():
        permissions = document.get("permissions")
        assert permissions == {"contents": "read"}, name
        for job_name, job in _jobs(document).items():
            job_permissions = job.get("permissions")
            if name == PRIVILEGED_RELEASE_WORKFLOW:
                assert job_permissions in ALLOWED_PRIVILEGED_RELEASE_JOB_PERMISSIONS, (
                    f"{name}:{job_name}"
                )
            else:
                assert job_permissions in ALLOWED_JOB_PERMISSIONS, f"{name}:{job_name}"


def test_id_token_and_attestation_authority_are_exclusively_privileged() -> None:
    """No workflow except the dedicated privileged release lane may reference
    ``id-token`` or ``attestations`` authority anywhere in its document."""
    for name, document in _load_workflows().items():
        if name == PRIVILEGED_RELEASE_WORKFLOW:
            continue
        serialized = json.dumps(document)
        assert "id-token" not in serialized, name
        assert "attestations" not in serialized, name
        assert "gh-action-pypi-publish" not in serialized, name


def test_no_untrusted_trigger_reaches_any_runner() -> None:
    """No pull_request_target/workflow_run/repository_dispatch trigger may
    exist anywhere, so untrusted pull-request code can never execute in an
    elevated context.  Ordinary workflows may only use the hosted trigger set;
    the privileged release lane is restricted to release/workflow_dispatch and
    can therefore never start from a pull_request event."""
    for name, document in _load_workflows().items():
        triggers = _triggers(document)
        assert isinstance(triggers, dict), name
        assert not set(triggers) & FORBIDDEN_TRIGGERS, f"{name}: untrusted triggers"
        allowed = (
            ALLOWED_PRIVILEGED_RELEASE_TRIGGERS
            if name == PRIVILEGED_RELEASE_WORKFLOW
            else ALLOWED_TRIGGERS
        )
        unexpected = set(triggers) - allowed
        assert not unexpected, f"{name}: unexpected triggers {unexpected}"


def _resolved_runs_on(job: dict[str, Any]) -> set[str]:
    """The concrete runner targeting of one job (matrix expressions resolved).

    A ``vars.*`` reference is reported as ``vars:<NAME>`` — the authoritative
    repository configuration point itself (runner group/label values are
    deliberately NOT committed as literals in this repository).
    """
    runs_on = job.get("runs-on")
    if isinstance(runs_on, dict):
        serialized = json.dumps(runs_on)
        matches = re.findall(r"vars\.\w+", serialized)
        return {f"vars:{match}" for match in matches}
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
    """UNTRUSTED ZONE — REPOSITORY STRUCTURAL EVIDENCE (class A): every
    ordinary checked-in workflow (push/pull_request/dispatch) targets ONLY
    disposable hosted Linux/Windows runners; none of them targets a
    trusted-runner configuration (``vars``-bound group/labels).

    This structural evidence does NOT by itself prove that no future
    PR-modified workflow could target a repository-level self-hosted runner:
    that platform-level authorization is required from the external
    runner-group policy (see
    ``test_trusted_vfp_platform_policy_specification_exists``) and remains
    EXTERNAL evidence (class B) until verified from live GitHub
    configuration."""
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
    pull_request_target, no workflow_run, no push and no repository_dispatch
    trigger may start it.  This is workflow defense in depth (LAYER 2,
    repository structural evidence): it removes every automated scheduling
    path from this file, but by itself it does NOT establish the platform
    authorization boundary that protects the runner from other workflow
    files — that boundary is the external runner-group policy (LAYER 1)."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    triggers = _triggers(document)
    assert set(triggers) == {"workflow_dispatch"}
    for forbidden_trigger in (
        "pull_request",
        "pull_request_target",
        "workflow_run",
        "push",
        "repository_dispatch",
    ):
        assert forbidden_trigger not in triggers, forbidden_trigger
    assert document.get("name") is not None
    assert "trusted" in str(document.get("name", "")).lower()


def test_trusted_vfp_job_requires_platform_authorized_runner_group() -> None:
    """The trusted job targets a PLATFORM-AUTHORIZED runner group (GitHub
    runs-on ``group`` + ``labels`` mapping, per the official workflow syntax),
    with both values bound to the authoritative repository variables so the
    lane is FAIL-CLOSED while they are unset.  NO group or label name is
    committed to the repository — a label is routing, not authorization; the
    authorization boundary is the external runner-group policy (see the
    platform-policy specification test)."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    job = _jobs(document)[TRUSTED_JOB]
    runs_on = job.get("runs-on")
    assert isinstance(runs_on, dict), f"trusted runs-on must be a mapping: {runs_on!r}"
    assert "group" in runs_on and "labels" in runs_on, runs_on
    group_value = str(runs_on["group"])
    labels_value = str(runs_on["labels"])
    assert TRUSTED_GROUP_VARIABLE in group_value, group_value
    assert TRUSTED_LABELS_VARIABLE in labels_value, labels_value
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


def test_trusted_lane_fails_closed_without_external_routing_configuration() -> None:
    """FAIL-CLOSED (repository structural evidence): while either
    authoritative repository variable is unset the trusted job cannot be
    scheduled — the ``runs-on`` mapping contains ONLY the two controlled
    variable expressions, with no literal runner identity and no
    fallback/default targeting, so the inert lane produces no evidence."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    runs_on = _jobs(document)[TRUSTED_JOB]["runs-on"]
    assert isinstance(runs_on, dict)
    assert runs_on["group"] == "${{ vars.DBF_TRUSTED_VFP9_RUNNER_GROUP }}"
    assert runs_on["labels"] == "${{ vars.DBF_TRUSTED_VFP9_RUNNER_LABELS }}"
    serialized = json.dumps(runs_on)
    for forbidden_fragment in ("ubuntu", "windows-latest", "self-hosted", "||"):
        assert forbidden_fragment not in serialized, forbidden_fragment
    targeting = _trusted_policy()["layer_2_workflow_defense_in_depth"]["runner_targeting"]
    assert targeting["fallback_or_default_values"] == "forbidden"
    assert "cannot be scheduled" in targeting["fail_closed"]


def test_trusted_guard_refuses_non_main_refs_before_checkout() -> None:
    """The FIRST step of the trusted job is a shell trust guard that refuses
    every ref except refs/heads/main and every event except
    workflow_dispatch — and it runs BEFORE any checkout action."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    job = _jobs(document)[TRUSTED_JOB]
    steps = [step for step in (job.get("steps") or []) if isinstance(step, dict)]
    assert steps, "the trusted job has no steps"
    guard = steps[0]
    assert not str(guard.get("uses", "")), "the trust guard must run before any action"
    run = str(guard.get("run", ""))
    assert "refs/heads/main" in run
    assert "throw" in run
    assert "workflow_dispatch" in run
    checkout_positions = [
        index
        for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith("actions/checkout")
    ]
    assert checkout_positions, "the trusted job never checks out the revision"
    assert min(checkout_positions) > 0, "the trust guard must precede checkout"


def test_trusted_checkout_checks_out_no_caller_controlled_ref() -> None:
    """The trusted checkout declares no explicit ``ref``: it checks out the
    dispatched main revision only — never a caller-provided SHA or branch,
    never ``github.event.pull_request.head.sha``."""
    document = _load_workflows()[TRUSTED_WORKFLOW]
    checkout_steps = [
        step
        for job in _jobs(document).values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and str(step.get("uses", "")).startswith("actions/checkout")
    ]
    assert checkout_steps, "the trusted workflow has no checkout step"
    for step in checkout_steps:
        with_block = step.get("with") or {}
        assert "ref" not in with_block, with_block
        assert "github.event.pull_request.head.sha" not in json.dumps(with_block)
    for run in _step_runs(document):
        assert "github.event.pull_request" not in run
        assert "pull_request" not in run


def test_actions_are_sha_pinned() -> None:
    """Every ``uses:`` step in every version-controlled workflow is pinned to
    an exact 40-character commit SHA (mutable tags are forbidden)."""
    sha_pinned = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
    for name, document in _load_workflows().items():
        for job_name, job in _jobs(document).items():
            for step in job.get("steps") or []:
                uses = step.get("uses")
                if isinstance(uses, str):
                    assert sha_pinned.match(uses), f"{name}:{job_name}: {uses}"


def test_trusted_vfp_platform_policy_specification_exists() -> None:
    """The machine-readable REQUIRED-CONFIGURATION specification for the
    platform runner-group boundary exists and is explicitly marked as a
    SPECIFICATION (never evidence).  This is repository structural evidence
    (class A); the live GitHub runner-group configuration and the real
    trusted-runner execution remain EXTERNAL evidence (class B)."""
    policy = _trusted_policy()
    assert policy["evidence_status"] == "SPECIFICATION_NOT_PROOF"
    assert policy["requirement"] == "REQ-P7-006"
    layer1 = policy["layer_1_platform_authorization"]
    assert layer1["required"] is True
    assert layer1["mechanism"] == "organization_or_enterprise_runner_group"
    assert layer1["repository_access"]["policy"] == "selected_repositories"
    assert layer1["repository_access"]["public_repository_access"] == (
        "deliberate_override_required"
    )
    assert layer1["workflow_access"]["policy"] == "restricted_to_workflows"
    assert layer1["workflow_access"]["pinned_ref"] == "refs/heads/main"
    layer2 = policy["layer_2_workflow_defense_in_depth"]
    assert layer2["workflow"] == TRUSTED_WORKFLOW_PATH
    assert layer2["triggers"]["allowed_exactly"] == ["workflow_dispatch"]
    assert layer2["runner_targeting"]["group_source"] == TRUSTED_GROUP_VARIABLE
    assert layer2["runner_targeting"]["labels_source"] == TRUSTED_LABELS_VARIABLE
    assert layer2["runner_targeting"]["committed_literal_group_or_label"] == ("forbidden")
    assert policy["stable_topology_constraints"]["live_runner_group_policy_verified"] is False
    assert policy["stable_topology_constraints"]["trusted_vfp_execution_evidence"] is False


def test_canonical_selected_workflow_is_fully_qualified_template() -> None:
    """GitHub runner-group workflow restrictions require a fully qualified
    workflow identity (owner/repository/path@ref).  The specification holds
    ONE canonical fully-qualified template with the explicit ``<FINAL_OWNER>``
    placeholder (never guessed), plus the explanatory note that live
    configuration must replace the placeholder before verification."""
    policy = _trusted_policy()
    canonical = policy["canonical_selected_workflow"]
    assert canonical["fully_qualified_template"] == CANONICAL_SELECTED_WORKFLOW_TEMPLATE
    assert canonical["placeholder"] == "<FINAL_OWNER>"
    assert "actual owner" in canonical["placeholder_note"]
    assert canonical["selected_workflows_exactly"] == [CANONICAL_SELECTED_WORKFLOW_TEMPLATE]
    assert canonical["pinned_ref"] == "refs/heads/main"
    assert canonical["workflow_file"] == TRUSTED_WORKFLOW_PATH
    assert (
        "<FINAL_OWNER>"
        in policy["layer_1_platform_authorization"]["repository_access"]["allowlist_exactly"][0]
    )
    assert (
        CANONICAL_SELECTED_WORKFLOW_TEMPLATE
        in policy["layer_1_platform_authorization"]["workflow_access"][
            "selected_workflows_exactly"
        ][0]
    )


def test_policy_separates_p7_006_acceptance_from_conditional_vfp_evidence() -> None:
    """The specification separates the immutable REQ-P7-006 repository
    CI/isolation acceptance (version-controlled workflows + green mandatory
    jobs) from the CONDITIONAL real-VFP9 execution evidence that only
    requirements explicitly demanding it (especially REQ-P6-003) may use."""
    policy = _trusted_policy()
    separation = policy["acceptance_separation"]
    repository_acceptance = separation["req_p7_006_repository_ci_isolation_acceptance"]
    assert repository_acceptance["requirement"] == "REQ-P7-006"
    assert repository_acceptance["immutable_acceptance_evidence"] == IMMUTABLE_ACCEPTANCE_EVIDENCE
    assert repository_acceptance["live_vfp_execution_dependency"] == "none"
    assert any("isolate" in criterion for criterion in repository_acceptance["criteria"])
    conditional = separation["conditional_real_vfp_execution_evidence"]
    assert conditional["requirement"] == "REQ-P6-003"
    assert conditional["evidence_class"] == "conditional"
    assert conditional["tool"] == "tools/run_real_vfp9_acceptance.py"
    assert conditional["platform_boundary_required_before_any_execution"] == (
        "layer_1_platform_authorization"
    )


def test_policy_does_not_overstate_the_tested_hosted_revision() -> None:
    """Evidence-semantics regression: the hosted ``pull_request`` workflows
    execute the prospective merge ref (``refs/pull/<N>/merge``), not the PR
    branch HEAD itself, so the REQ-P7-006 acceptance contract must describe
    green mandatory jobs for the reviewed change WITHOUT claiming execution on
    an exact HEAD SHA.  Such a claim would be admissible only if a hosted
    workflow objectively enforced a head-SHA checkout (see
    ``_hosted_workflows_pin_head_sha_checkout``); none does, so no acceptance
    criterion may assert an exact-HEAD/SHA execution identity for hosted PR
    CI."""
    policy = _trusted_policy()
    repository_acceptance = policy["acceptance_separation"][
        "req_p7_006_repository_ci_isolation_acceptance"
    ]
    assert repository_acceptance["immutable_acceptance_evidence"] == IMMUTABLE_ACCEPTANCE_EVIDENCE
    assert FORBIDDEN_EXACT_HEAD_WORDING not in json.dumps(policy)
    assert _hosted_pull_request_workflows(), "no hosted pull_request workflow found"
    if not _hosted_workflows_pin_head_sha_checkout():
        for criterion in repository_acceptance["criteria"]:
            assert not EXACT_REVISION_CLAIM.search(criterion), criterion


def test_absence_of_live_vfp_execution_does_not_invalidate_p7_006() -> None:
    """REQ-P7-006 is a repository CI/isolation acceptance: the specification
    must state explicitly that a missing provisioned trusted self-hosted VFP
    runner does NOT make REQ-P7-006 PARTIAL when the isolation contract is
    objectively present and no unsafe execution occurs."""
    policy = _trusted_policy()
    repository_acceptance = policy["acceptance_separation"][
        "req_p7_006_repository_ci_isolation_acceptance"
    ]
    note = repository_acceptance["note"]
    assert "does NOT make REQ-P7-006 PARTIAL" in note
    assert "isolation contract" in note
    assert "External runner provisioning is NOT a mandatory REQ-P7-006 closure stage" in note
    assert "does not invalidate this repository-side acceptance" in note


def test_real_vfp_execution_remains_conditional_evidence_for_p6_003() -> None:
    """Real VFP9 execution stays CONDITIONAL acceptance evidence for the
    requirements that explicitly demand it (REQ-P6-003) — never a mandatory
    REQ-P7-006 closure stage."""
    policy = _trusted_policy()
    conditional = policy["acceptance_separation"]["conditional_real_vfp_execution_evidence"]
    note = conditional["note"]
    assert "CONDITIONAL acceptance evidence" in note
    assert "REQ-P6-003" in note
    assert "NOT a REQ-P7-006 closure gate" in note
    assert "NOT required to close REQ-P7-006" in note


def test_policy_does_not_invent_additional_p7_006_closure_gates() -> None:
    """The immutable REQ-P7-006 acceptance contract is version-controlled
    workflows + green mandatory jobs + trusted-VFP isolation.  The policy
    must NOT define an additional mandatory closure stage (no two-stage
    lifecycle status machine) and must NOT claim that REQ-P7-006 stays
    PARTIAL after a merge or that live VFP execution is required to close
    it."""
    policy = _trusted_policy()
    for forbidden_key in ("lifecycle", "acceptance_requires_all_of", "until_then"):
        assert forbidden_key not in policy, forbidden_key
    serialized = json.dumps(policy)
    for forbidden_fragment in (
        "remains PARTIAL/BLOCKED",
        "requirement_remains_partial_after_enabling_merge",
        "next_requirement_blocked_until_full_pass",
        "full_pass_only_when",
    ):
        assert forbidden_fragment not in serialized, forbidden_fragment


def test_policy_does_not_claim_verified_branch_protection() -> None:
    """The specification must not overstate platform enforcement: it does not
    assert branch-protection enforcement; effective required-status-check
    enforcement is an external setting verified from live platform
    configuration."""
    note = _trusted_policy()["branch_protection_note"]
    assert "does not assert GitHub branch-protection enforcement" in note
    assert "verified from live platform configuration" in note


def test_volatile_external_facts_are_marked_not_live_evidence() -> None:
    """Point-in-time external observations (runner counts) carry provenance
    and are explicitly marked NOT_LIVE_EVIDENCE, so a static repository JSON
    file never masquerades as continuously live GitHub state."""
    policy = _trusted_policy()
    observation = policy["external_observation"]
    assert observation["evidence_status"] == "NOT_LIVE_EVIDENCE"
    assert observation["observed_at"] is not None
    assert "GitHub REST API" in observation["observation_method"]
    assert observation["observed"]["self_hosted_runners_registered"] == 0
    stable = policy["stable_topology_constraints"]
    assert stable["repository_visibility"] == "public"
    assert stable["owner_type"] == "user"
    assert stable["organization_runner_groups_available"] is False
    assert stable["live_runner_group_policy_verified"] is False
    assert stable["trusted_vfp_execution_evidence"] is False


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


def test_property_gate_executes_the_p7_007_adversarial_property_suite() -> None:
    """REQ-P7-007 CI integration: the mandatory
    ``Property / adversarial / malformed inputs`` gate executes the
    deterministic P7-007 property/adversarial evidence file."""
    document = _load_workflows()[GATES_WORKFLOW]
    property_step = [
        step
        for job in _jobs(document).values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and "adversarial / malformed inputs" in str(step.get("name", ""))
    ]
    assert property_step, "the mandatory property/adversarial gate is missing"
    runs = "\n".join(step.get("run", "") for step in property_step)
    assert "tests/test_p7_adversarial_properties.py" in runs


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
