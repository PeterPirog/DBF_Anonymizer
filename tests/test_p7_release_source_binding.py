"""REQ-P7-008 exact-source provenance tests (temporary git repositories).

Proves the fail-closed source binding of tools/build_release_evidence.py:

* ``_assert_clean_source_tree`` accepts an objectively clean committed tree and
  rejects ANY ``git status --porcelain=v1 --untracked-files=all`` output:
  modified tracked files, staged modifications, and non-ignored untracked
  files (including package-relevant ones under ``src/``);
* gitignored ordinary build outputs do NOT create false failures;
* ``_export_commit_source`` derives the build input from the exact recorded
  commit object (not the mutable working tree): exported bytes match
  ``git show <commit>:<path>``, an untracked file never leaks into the export,
  exporting an OLDER commit yields the OLDER content, and no ``.git`` data is
  copied.

The tests run entirely inside deterministic temporary git repositories under
task-owned pytest TEMP and never touch the user/global git configuration
(identity is supplied per-invocation via ``git -c`` flags).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.build_release_evidence import (
    ReleaseEvidenceError,
    _assert_clean_source_tree,
    _export_commit_source,
)

GIT_IDENTITY = (
    "-c",
    "user.name=P7-008 Test Runner",
    "-c",
    "user.email=p7-008-test-runner@example.invalid",
)


def _git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *GIT_IDENTITY, *arguments],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise AssertionError(f"git {arguments} failed: {completed.stderr}")
    return completed


def _init_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0.0.0"\n', encoding="utf-8"
    )
    package = repo / "src" / "fixture"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VERSION = 1\n", encoding="utf-8")
    (repo / ".gitignore").write_text("build/\n*.egg-info/\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "initial commit")
    status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    assert not status.stdout.strip(), status.stdout
    return repo


def test_clean_committed_source_is_accepted(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    assert _assert_clean_source_tree(repo) == "PASS"


def test_modified_tracked_file_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    tracked = repo / "src" / "fixture" / "__init__.py"
    tracked.write_text("VERSION = 2\n", encoding="utf-8")
    with pytest.raises(ReleaseEvidenceError) as expected:
        _assert_clean_source_tree(repo)
    assert "not clean" in str(expected.value)
    assert "src/fixture/__init__.py" in str(expected.value)
    tracked.write_text("VERSION = 1\n", encoding="utf-8")
    assert _assert_clean_source_tree(repo) == "PASS"


def test_staged_modification_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    tracked = repo / "src" / "fixture" / "__init__.py"
    tracked.write_text("VERSION = 2\n", encoding="utf-8")
    _git(repo, "add", "src/fixture/__init__.py")
    with pytest.raises(ReleaseEvidenceError):
        _assert_clean_source_tree(repo)


def test_untracked_package_relevant_file_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    untracked = repo / "src" / "fixture" / "extra.py"
    untracked.write_text("LEAK = 'untracked'\n", encoding="utf-8")
    with pytest.raises(ReleaseEvidenceError) as expected:
        _assert_clean_source_tree(repo)
    assert "src/fixture/extra.py" in str(expected.value)
    untracked.unlink()
    assert _assert_clean_source_tree(repo) == "PASS"


def test_ignored_build_outputs_do_not_fail(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    build_dir = repo / "build"
    build_dir.mkdir()
    (build_dir / "bdist.tmp").write_text("ignored build output\n", encoding="utf-8")
    (repo / "src" / "fixture.egg-info").mkdir()
    (repo / "src" / "fixture.egg-info" / "PKG-INFO").write_text("Metadata\n", encoding="utf-8")
    assert not _git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout.strip()
    assert _assert_clean_source_tree(repo) == "PASS"


def test_export_contains_exactly_the_commit_object(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD").stdout.strip()
    leaked = repo / "src" / "fixture" / "untracked_leak.py"
    leaked.write_text("LEAK = 'untracked'\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0.9.9"\n', encoding="utf-8"
    )

    export = _export_commit_source(repo, commit, tmp_path / "export")
    assert (export / "pyproject.toml").is_file()
    # The export is the committed snapshot: no untracked file, no .git data,
    # and the committed pyproject bytes (not the modified working-tree bytes).
    assert not (export / "src" / "fixture" / "untracked_leak.py").exists()
    assert not (export / ".git").exists()
    committed_bytes = _git(repo, "show", f"{commit}:pyproject.toml").stdout
    assert (export / "pyproject.toml").read_text(encoding="utf-8") == committed_bytes


def test_export_binds_content_to_the_recorded_commit_object(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    first = _git(repo, "rev-parse", "HEAD").stdout.strip()
    package = repo / "src" / "fixture" / "__init__.py"
    package.write_text("VERSION = 2\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "second commit")
    second = _git(repo, "rev-parse", "HEAD").stdout.strip()
    assert first != second

    export_first = _export_commit_source(repo, first, tmp_path / "export-first")
    export_second = _git(repo, "show", f"{second}:src/fixture/__init__.py").stdout
    assert (export_first / "src" / "fixture" / "__init__.py").read_text(
        encoding="utf-8"
    ) == "VERSION = 1\n"
    assert export_second == "VERSION = 2\n"


def test_export_refuses_existing_destination(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    export_root = tmp_path / "export"
    export_root.mkdir()
    with pytest.raises(ReleaseEvidenceError):
        _export_commit_source(repo, "HEAD", export_root)
