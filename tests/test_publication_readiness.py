import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PATHS = (
    ROOT / ".env.example",
    ROOT / ".github",
    ROOT / "benchmarks",
    ROOT / "docs",
    ROOT / "src",
    ROOT / "tests",
    ROOT / "CONTRIBUTING.md",
    ROOT / "CHANGELOG.md",
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "pyproject.toml",
)
def _public_text_files():
    for path in PUBLIC_PATHS:
        if path.is_file():
            yield path
            continue
        for item in path.rglob("*"):
            if item.is_file() and item.suffix.casefold() in {
                ".md",
                ".py",
                ".toml",
                ".yml",
                ".yaml",
            }:
                yield item


def test_public_tree_contains_no_personal_email_or_user_profile_path():
    email = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
    user_profile = re.compile(r"(?:[A-Z]:\\Users\\|/home/)[^\\/\s]+")
    findings = []
    for path in _public_text_files():
        if path.resolve() == Path(__file__).resolve():
            continue
        content = path.read_text(encoding="utf-8")
        if email.search(content):
            findings.append(f"{path.relative_to(ROOT)}: email")
        if user_profile.search(content):
            findings.append(f"{path.relative_to(ROOT)}: user profile path")
    assert not findings, "\n".join(findings)


def test_example_environment_uses_fictional_paths_and_blank_salt():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert r"DBF_ANON_SOURCE=C:\Data\LegacyDB" in example
    assert r"DBF_ANON_OUTPUT=C:\DBF_Work\LegacyDB_anonymized" in example
    assert "DBF_ANON_SALT=\n" in example


def test_local_agent_context_is_not_part_of_public_repository():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "DBF_Anonymizer_specyfikacja_dla_AI*.md" in ignored


def test_self_hosted_vfp_job_never_runs_for_pull_requests():
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    condition = workflow.split("  vfp-self-hosted:", 1)[1].split(
        "    runs-on:", 1
    )[0]
    assert "github.event_name == 'workflow_dispatch'" in condition
    assert "github.event_name == 'push'" in condition
    assert "pull_request_target" not in workflow
