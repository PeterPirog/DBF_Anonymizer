"""REQ-P7-008 release CI/publishing contract: structural workflow evidence.

Proves, from version-controlled YAML/JSON:

* a NON-PRIVILEGED release-evidence validation workflow exists and safely
  exercises the release machinery on pull_request without any publication
  authority;
* a dedicated PRIVILEGED release workflow exists that can never execute for
  untrusted pull_request code (no pull_request/pull_request_target/
  workflow_run trigger, ref guard refusing everything but main/tag refs
  BEFORE any checkout, no caller-provided ref anywhere);
* publication authority (id-token: write, attestations: write, the PyPI
  publishing action) lives EXCLUSIVELY in that privileged workflow, SHA-pinned
  and minimally permissioned;
* the PyPI publication job is FAIL-CLOSED behind the authoritative repository
  variable gate and re-verifies the evidence bundle before publishing;
* the machine-readable release-publishing policy SPECIFICATION exists and is
  truthful: SPECIFICATION_NOT_PROOF, PyPI Trusted Publishing explicitly NOT
  externally configured/verified, no publication performed;
* SBOM/release tooling is stdlib-only, never a runtime dependency, and leaves
  the REQ-P7-004 offline runtime closure and the dbfbridge contract intact;
* the evidence builder uses SOURCE_DATE_EPOCH, pinned backends, two
  independent build directories and final-artifact SHA-256 comparison.

Evidence classes (deliberately distinguished):
A. repository structural evidence — asserted here from committed files;
B. external live configuration (PyPI Trusted Publishing, authorized release
   runs) — never fabricated; the policy records it as unverified.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
EVIDENCE_WORKFLOW = "p7-release-evidence.yml"
PRIVILEGED_WORKFLOW = "dbf-release-publish.yml"
POLICY_SPEC = ".github/release-publishing-policy.json"
GATE_VARIABLE = "vars.DBF_PYPI_TRUSTED_PUBLISHING_ENABLED"
PYPI_PUBLISH_ACTION = "pypa/gh-action-pypi-publish"
PYPI_PUBLISH_SHA = "76f52bc884231f62b9a034ebfe128415bbaabdfc"
ATTEST_ACTION = "actions/attest-build-provenance"
ATTEST_SHA = "4d101475d8b20a2381f78447822ac1eab6504dd8"
UPLOAD_ARTIFACT_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_ARTIFACT_SHA = "d3f86a106a0bac45b974a628896c90dbdf5c8093"
EVIDENCE_TOOL = "tools/build_release_evidence.py"
VERIFIER_TOOL = "tools/verify_release_evidence.py"
SBOM_TOOL = "tools/generate_release_sbom.py"
ARCHITECTURE_SHA256 = "126af414b2ba6497760a866475b2517b5470ce3b9681da3863401156bf235587"
#: The obsolete architecture digest: in the CURRENT release builder/verifier it
#: may appear ONLY as the explicitly HISTORICAL material (tamper case /
#: historical verification mode), never as a current identity binding.
HISTORICAL_ARCHITECTURE_SHA256 = "483932970d44770b05fcfad7430b85820d771458110f004b0397bd5d56398615"

ALLOWED_PRIVILEGED_TRIGGERS = frozenset({"release", "workflow_dispatch"})
FORBIDDEN_TRIGGERS = frozenset(
    {"pull_request", "pull_request_target", "workflow_run", "repository_dispatch"}
)
SHA_PINNED = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
STDLIB_ALLOWED_ROOTS = frozenset(
    {
        "__future__",
        "argparse",
        "ast",
        "datetime",
        "email",
        "gzip",
        "hashlib",
        "io",
        "json",
        "os",
        "pathlib",
        "platform",
        "re",
        "shutil",
        "subprocess",
        "sys",
        "tarfile",
        "tempfile",
        "tomllib",
        "typing",
        "uuid",
        "zipfile",
    }
)


def _load(name: str) -> dict[str, Any]:
    document = yaml.safe_load((WORKFLOW_DIR / name).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _triggers(document: dict[str, Any]) -> dict[str, Any]:
    triggers: Any = document.get(True)  # type: ignore[call-overarg] - PyYAML parses a bare "on:" as True.
    if triggers is None:
        triggers = document.get("on") or {}
    assert isinstance(triggers, dict)
    return triggers


def _jobs(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return dict(document.get("jobs") or {})


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [step for step in (job.get("steps") or []) if isinstance(step, dict)]


def _runs(document: dict[str, Any]) -> str:
    return "\n".join(
        str(step.get("run", "")) for job in _jobs(document).values() for step in _steps(job)
    )


def _uses(document: dict[str, Any]) -> list[str]:
    return [str(step.get("uses")) for job in _jobs(document).values() for step in _steps(job)]


def _policy() -> dict[str, Any]:
    policy = json.loads((REPO_ROOT / POLICY_SPEC).read_text(encoding="utf-8"))
    assert isinstance(policy, dict)
    return policy


# ---------------------------------------------------------------------------
# Non-privileged release-evidence validation workflow
# ---------------------------------------------------------------------------


def test_release_evidence_workflow_exists_and_is_non_privileged() -> None:
    document = _load(EVIDENCE_WORKFLOW)
    assert document.get("permissions") == {"contents": "read"}
    for job_name, job in _jobs(document).items():
        assert job.get("permissions") in (None, {"contents": "read"}), job_name
    serialized = json.dumps(document)
    assert "id-token" not in serialized
    assert "attestations" not in serialized
    assert PYPI_PUBLISH_ACTION not in serialized
    assert ATTEST_ACTION not in serialized


def test_release_evidence_workflow_executes_the_release_machinery() -> None:
    document = _load(EVIDENCE_WORKFLOW)
    runs = _runs(document)
    assert EVIDENCE_TOOL in runs
    uses = "\n".join(_uses(document))
    assert f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}" in uses
    assert "release-evidence-" in runs or "release-evidence" in json.dumps(document)


# ---------------------------------------------------------------------------
# Privileged release workflow isolation
# ---------------------------------------------------------------------------


def test_privileged_release_workflow_triggers_exclude_untrusted_events() -> None:
    document = _load(PRIVILEGED_WORKFLOW)
    triggers = _triggers(document)
    assert set(triggers) == ALLOWED_PRIVILEGED_TRIGGERS
    for forbidden in FORBIDDEN_TRIGGERS:
        assert forbidden not in triggers, forbidden


def test_privileged_workflow_never_references_pull_request_context() -> None:
    document = _load(PRIVILEGED_WORKFLOW)
    serialized = json.dumps(document)
    assert "pull_request" not in serialized
    for job_name, job in _jobs(document).items():
        for step in _steps(job):
            with_block = json.dumps(step.get("with") or {})
            assert "github.event.pull_request" not in with_block, job_name


def test_privileged_jobs_guard_the_ref_before_checkout() -> None:
    document = _load(PRIVILEGED_WORKFLOW)
    for job_name, job in _jobs(document).items():
        steps = _steps(job)
        assert steps, job_name
        guard = steps[0]
        assert not str(guard.get("uses", "")), f"{job_name}: guard must precede actions"
        run = str(guard.get("run", ""))
        assert "refs/heads/main" in run and "refs/tags" in run, job_name
        assert "exit 1" in run, job_name
        checkout_positions = [
            index
            for index, step in enumerate(steps)
            if str(step.get("uses", "")).startswith("actions/checkout")
        ]
        # A privileged job without a checkout (e.g. the attestation job, which
        # only downloads workflow artifacts) is acceptable; when a checkout
        # exists it must always follow the trust guard.
        assert all(position > 0 for position in checkout_positions), (
            f"{job_name}: checkout must follow the guard"
        )
        for step in steps:
            with_block = step.get("with") or {}
            assert "ref" not in with_block, f"{job_name}: caller-provided ref {with_block}"


def test_privileged_jobs_are_minimally_permissioned() -> None:
    document = _load(PRIVILEGED_WORKFLOW)
    assert document.get("permissions") == {"contents": "read"}
    expected = {
        "build-reproducible-release": {"contents": "read"},
        "attest-release-artifacts": {
            "contents": "read",
            "id-token": "write",
            "attestations": "write",
        },
        "publish-pypi": {"contents": "read", "id-token": "write"},
    }
    jobs = _jobs(document)
    assert set(jobs) == set(expected)
    for job_name, permissions in expected.items():
        assert jobs[job_name].get("permissions") == permissions, job_name


def test_privileged_actions_are_sha_pinned() -> None:
    document = _load(PRIVILEGED_WORKFLOW)
    uses = "\n".join(_uses(document))
    assert f"{ATTEST_ACTION}@{ATTEST_SHA}" in uses
    assert f"{PYPI_PUBLISH_ACTION}@{PYPI_PUBLISH_SHA}" in uses
    assert f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}" in uses
    assert f"actions/download-artifact@{DOWNLOAD_ARTIFACT_SHA}" in uses
    for job in _jobs(document).values():
        for step in _steps(job):
            action = step.get("uses")
            if isinstance(action, str):
                assert SHA_PINNED.match(action), action


def test_publication_job_is_fail_closed_behind_the_gate_variable() -> None:
    document = _load(PRIVILEGED_WORKFLOW)
    publish = _jobs(document)["publish-pypi"]
    condition = str(publish.get("if", ""))
    assert GATE_VARIABLE in condition, condition
    assert "== 'true'" in condition, condition
    publish_runs = _runs({"jobs": {"publish-pypi": publish}})
    assert VERIFIER_TOOL in publish_runs, "publication must re-verify evidence first"
    publish_uses = "\n".join(str(step.get("uses", "")) for step in _steps(publish))
    assert f"{PYPI_PUBLISH_ACTION}@{PYPI_PUBLISH_SHA}" in publish_uses
    serialized = json.dumps(document).lower()
    assert "password" not in serialized
    assert "api_token" not in serialized
    assert "pypi_api_token" not in serialized


def test_publication_job_requires_the_pypi_environment() -> None:
    """The publication approval boundary: ONLY the publish-pypi job is bound
    to the GitHub Environment ``pypi`` — the PyPI-side Trusted Publisher
    identity must match it exactly."""
    document = _load(PRIVILEGED_WORKFLOW)
    publish = _jobs(document)["publish-pypi"]
    assert publish.get("environment") == "pypi"


def test_publication_environment_is_exclusive_to_the_publish_job() -> None:
    """The build and attestation stages stay executable independently of the
    PyPI publication approval boundary: neither may gain the ``pypi``
    environment (no publication authorization outside the publish job)."""
    document = _load(PRIVILEGED_WORKFLOW)
    for job_name in ("build-reproducible-release", "attest-release-artifacts"):
        job = _jobs(document)[job_name]
        assert "environment" not in job, f"{job_name} must not carry an environment"


def test_release_policy_binds_the_exact_publisher_identity() -> None:
    """The release policy records the REQUIRED future PyPI Trusted Publisher
    identity (specification, NOT proof of configuration)."""
    identity = _policy()["publication"]["publisher_identity"]
    assert identity["pypi_project"] == "dbf-anonymizer"
    assert identity["github_owner"] == "PeterPirog"
    assert identity["github_repository"] == "DBF_Anonymizer"
    assert identity["workflow_filename"] == PRIVILEGED_WORKFLOW.rsplit("/", 1)[-1]
    assert identity["github_environment"] == "pypi"
    lowered = json.dumps(identity).lower()
    assert "not proof of configuration" in lowered


# ---------------------------------------------------------------------------
# Release-publishing policy specification
# ---------------------------------------------------------------------------


def test_release_publishing_policy_specification_exists() -> None:
    policy = _policy()
    assert policy["specification_id"] == "DBF-RELEASE-PUBLISHING-POLICY"
    assert policy["specification_version"] == "1.0"
    assert policy["requirement"] == "REQ-P7-008"
    assert policy["evidence_status"] == "SPECIFICATION_NOT_PROOF"


def test_release_policy_truthfully_records_external_configuration_status() -> None:
    policy = _policy()
    external = policy["evidence_classes"]["external_live_configuration_evidence"]
    assert external["pypi_trusted_publishing_configured"] is False
    assert external["publication_performed"] is False
    assert "has NOT been externally configured" in external["note_details"]
    publication = policy["publication"]
    assert publication["external_configuration_verified"] is False
    assert publication["mechanism"] == "github_oidc_trusted_publishing"
    assert publication["workflow_file"] == ".github/workflows/dbf-release-publish.yml"
    assert publication["allowed_triggers_exactly"] == ["release", "workflow_dispatch"]
    for forbidden in FORBIDDEN_TRIGGERS | {"push"}:
        assert forbidden in publication["forbidden_triggers"], forbidden
    assert publication["fail_closed_gate_variable"] == GATE_VARIABLE
    assert publication["publisher_action"] == f"{PYPI_PUBLISH_ACTION}@{PYPI_PUBLISH_SHA}"
    assert "fail-closed" in publication["fail_closed_note"].lower()


def test_release_policy_requires_ref_guard_and_minimal_permissions() -> None:
    policy = _policy()
    publication = policy["publication"]
    assert "refs/heads/main" in publication["ref_guard"]
    assert "refs/tags" in publication["ref_guard"]
    assert publication["permissions"] == {"contents": "read", "id-token": "write"}
    attestation = policy["attestation"]
    assert attestation["mechanism"] == "github_artifact_attestations"
    assert attestation["action"] == f"{ATTEST_ACTION}@{ATTEST_SHA}"
    assert attestation["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert "private signing key" in attestation["note"].lower()
    integrity = policy["integrity"]
    assert integrity["verifier_tool"] == VERIFIER_TOOL
    assert integrity["evidence_manifest"] == "release-evidence.manifest.json"


def test_release_policy_invariants_forbid_untrusted_publication() -> None:
    invariants = "\n".join(_policy()["invariants"])
    assert "pull_request execution" in invariants
    assert "pull_request_target" in invariants
    assert "workflow_run" in invariants
    assert "fail-closed" in invariants
    assert "no private signing key" in invariants


# ---------------------------------------------------------------------------
# Tooling boundaries
# ---------------------------------------------------------------------------


def test_sbom_and_verifier_tooling_are_stdlib_only() -> None:
    """The SBOM generator and the fail-closed verifier stay stdlib-only, so
    SBOM tooling never becomes a runtime or dev dependency."""
    for name in (SBOM_TOOL, VERIFIER_TOOL):
        tree = ast.parse((REPO_ROOT / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root in STDLIB_ALLOWED_ROOTS, f"{name}: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if not module:
                    continue
                root = module.split(".")[0]
                assert root in STDLIB_ALLOWED_ROOTS | {"tools"}, f"{name}: {module}"


def test_committed_evidence_bundle_is_pinned_against_eol_conversion() -> None:
    """The release evidence JSON files are text but their SHA-256 values are
    recorded in the manifest, so Windows autocrlf checkout conversion must be
    disabled for the whole evidence subtree via .gitattributes."""
    attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "tests/fixtures/p7_release_evidence/**" in attributes
    assert "-text" in attributes
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == ["dbfbridge[write]>=1.1.0,<2"]
    dev = data["project"]["optional-dependencies"]["dev"]
    assert not [item for item in dev if "cyclonedx" in item or "spdx" in item]
    offline_pins = [
        line.split("#", 1)[0].strip()
        for line in (REPO_ROOT / "requirements" / "p7-offline-wheelhouse.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.split("#", 1)[0].strip()
    ]
    assert offline_pins == [
        "dbfbridge[write]==1.1.1",
        "dbfread==2.0.7",
        "dbf==0.99.11",
        "aenum==3.1.17",
    ]


def test_evidence_builder_uses_the_deterministic_two_build_protocol() -> None:
    source = (REPO_ROOT / EVIDENCE_TOOL).read_text(encoding="utf-8")
    assert "SOURCE_DATE_EPOCH" in source
    assert "PIP_CONSTRAINT" in source
    assert 'f"build-{index}"' in source
    assert "for index in (1, 2)" in source
    assert "canonicalize_sdist" in source
    for recorded in (
        "sdist_sha256_build_1",
        "sdist_sha256_build_2",
        "wheel_sha256_build_1",
        "wheel_sha256_build_2",
    ):
        assert recorded in source, recorded
    assert ARCHITECTURE_SHA256 in source
    assert "pypa/gh-action-pypi-publish" not in source
    assert "attest-build-provenance" not in source
    sbom_source = (REPO_ROOT / SBOM_TOOL).read_text(encoding="utf-8")
    assert '"bomFormat"' in sbom_source or "bomFormat" in sbom_source
    assert "1.5" in sbom_source
    verifier_source = (REPO_ROOT / VERIFIER_TOOL).read_text(encoding="utf-8")
    assert "VerificationFailure" in verifier_source
    assert ARCHITECTURE_SHA256 in verifier_source


def test_release_tools_bind_current_architecture_and_isolate_history() -> None:
    """CURRENT release builder/verifier must bind the live architecture digest
    and may reference the obsolete digest ONLY as explicitly HISTORICAL
    material (a reintroduction as a current identity binding must fail)."""
    import re

    builder_source = (REPO_ROOT / EVIDENCE_TOOL).read_text(encoding="utf-8")
    verifier_source = (REPO_ROOT / VERIFIER_TOOL).read_text(encoding="utf-8")
    for label, tool_source in (("builder", builder_source), ("verifier", verifier_source)):
        assert "CURRENT_ARCHITECTURE_SHA256" in tool_source, label
        assert "HISTORICAL_ARCHITECTURE_SHA256" in tool_source, label
        stale_occurrences = [
            match.start()
            for match in re.finditer(re.escape(HISTORICAL_ARCHITECTURE_SHA256), tool_source)
        ]
        assert stale_occurrences, label
        for position in stale_occurrences:
            line = tool_source[:position].rsplit("\n", 1)[-1]
            # Every obsolete-digest occurrence sits on a line that names it
            # HISTORICAL explicitly (constant definition or historical-mode
            # reference), never as a plain current binding.
            assert "HISTORICAL" in line, f"{label}: stale digest outside HISTORICAL context"
        # The current digest appears as the operational constant, never on a
        # line that would call it historical.
        current_lines = [
            tool_source[: match.start()].rsplit("\n", 1)[-1]
            for match in re.finditer(re.escape(ARCHITECTURE_SHA256), tool_source)
        ]
        assert current_lines, label
        for line in current_lines:
            assert "HISTORICAL" not in line, line


def test_release_build_source_is_bound_to_the_exact_commit_object() -> None:
    """REQ-P7-008 exact-source provenance: the tool must fail closed on a dirty
    tree and build BOTH independent builds from an exact git-archive export of
    the recorded commit — never from the mutable working tree."""
    source = (REPO_ROOT / EVIDENCE_TOOL).read_text(encoding="utf-8")
    assert "--porcelain=v1" in source
    assert "--untracked-files=all" in source
    assert "git archive" in source
    assert "_assert_clean_source_tree" in source
    assert "_export_commit_source" in source
    # No escape hatch: the dirty-tree refusal is unconditional (no CLI flag,
    # no snake_case bypass option anywhere in the tool source).
    assert 'add_argument("--allow-dirty"' not in source
    assert "allow_dirty" not in source
    assert "must not contain .git data" in source  # the export rejects .git data


def test_verifier_supports_the_trusted_manifest_digest_binding() -> None:
    verifier_source = (REPO_ROOT / VERIFIER_TOOL).read_text(encoding="utf-8")
    assert "--expected-manifest-sha256" in verifier_source
    assert "release-evidence.manifest.sha256" in verifier_source
    assert "missing manifest integrity binding" in verifier_source
    tool_source = (REPO_ROOT / EVIDENCE_TOOL).read_text(encoding="utf-8")
    assert "release-evidence.manifest.sha256" in tool_source
    assert "--expected-manifest-sha256" in tool_source
    assert "coherent_substitution" in tool_source


def test_attestation_subjects_include_manifest_digest_and_sbom() -> None:
    document = _load(PRIVILEGED_WORKFLOW)
    attest = _jobs(document)["attest-release-artifacts"]
    subject_steps = [step for step in _steps(attest) if ATTEST_ACTION in str(step.get("uses", ""))]
    assert subject_steps, "attestation step missing"
    subjects = str(subject_steps[0].get("with", {}).get("subject-path", ""))
    for required in (
        "evidence/dist/*.tar.gz",
        "evidence/dist/*.whl",
        "evidence/release-evidence.manifest.json",
        "evidence/release-evidence.manifest.sha256",
        "evidence/release-sbom.cdx.json",
    ):
        assert required in subjects, required


def test_pr_validation_has_no_attestation_or_publication_authority() -> None:
    document = _load(EVIDENCE_WORKFLOW)
    serialized = json.dumps(document)
    assert "id-token" not in serialized
    assert "attestations" not in serialized
    assert PYPI_PUBLISH_ACTION not in serialized
    assert ATTEST_ACTION not in serialized
    assert document.get("permissions") == {"contents": "read"}


def test_release_policy_records_manifest_digest_and_source_binding() -> None:
    policy = _policy()
    integrity = policy["integrity"]
    assert integrity["manifest_digest_sidecar"] == "release-evidence.manifest.sha256"
    assert integrity["verifier_digest_option"] == "--expected-manifest-sha256"
    for subject in (
        "evidence/release-evidence.manifest.json",
        "evidence/release-evidence.manifest.sha256",
        "evidence/release-sbom.cdx.json",
    ):
        assert subject in integrity["attestation_subjects"], subject
    assert "no recursive self-hash" in integrity["manifest_digest_binding"]
    assert "does NOT provide a signed attestation" in integrity["pr_validation_provides"] or (
        "no id-token" in integrity["pr_validation_provides"]
    )
    source_binding = policy["source_binding"]
    assert "--porcelain=v1" in source_binding["cleanliness_check"]
    assert "no --allow-dirty" in source_binding["cleanliness_check"]
    assert "git archive" in source_binding["source_export"]
    assert "never from the mutable working tree" in source_binding["source_export"]
