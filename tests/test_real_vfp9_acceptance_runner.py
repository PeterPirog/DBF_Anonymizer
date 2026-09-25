"""Negative provenance tests for the manual real-VFP9 acceptance runner."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.run_real_vfp9_acceptance as runner


_TEST_HEAD = "a" * 40


def _configure_git_provenance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    status: str = "",
    branch: str = runner.EXPECTED_BRANCH,
    head: str = _TEST_HEAD,
    remote_head: str = _TEST_HEAD,
) -> tuple[Path, list[tuple[str, ...]]]:
    architecture = tmp_path / runner.ARCHITECTURE_FILENAME
    architecture_bytes = b"immutable architecture\n"
    architecture.write_bytes(architecture_bytes)
    monkeypatch.setattr(runner, "ARCHITECTURE_PATH", architecture)
    monkeypatch.setattr(
        runner,
        "ARCHITECTURE_SHA256",
        hashlib.sha256(architecture_bytes).hexdigest(),
    )
    calls: list[tuple[str, ...]] = []
    replies = {
        ("status", "--porcelain", "--untracked-files=all"): status,
        ("branch", "--show-current"): branch,
        ("rev-parse", "HEAD"): head,
        ("rev-parse", runner.EXPECTED_REMOTE_REF): remote_head,
    }

    def fake_git(*args: str) -> str:
        calls.append(args)
        return replies[args]

    monkeypatch.setattr(runner, "_run_git", fake_git)
    return architecture, calls


@pytest.mark.parametrize(
    "status",
    (
        " M tools/run_real_vfp9_acceptance.py",
        "M  tools/run_real_vfp9_acceptance.py",
        "?? hostile.py",
        "?? tests/conftest.py",
    ),
    ids=("tracked-modification", "staged-modification", "python", "conftest"),
)
def test_git_provenance_rejects_every_worktree_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: str
) -> None:
    _architecture, calls = _configure_git_provenance(
        monkeypatch, tmp_path, status=status
    )

    with pytest.raises(SystemExit, match="worktree changes or untracked files"):
        runner._verified_git_state()

    assert calls == [("status", "--porcelain", "--untracked-files=all")]


def test_git_provenance_accepts_clean_head_and_canonical_architecture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _architecture, calls = _configure_git_provenance(monkeypatch, tmp_path)

    assert runner._verified_git_state() == (runner.EXPECTED_BRANCH, _TEST_HEAD)

    assert calls == [
        ("status", "--porcelain", "--untracked-files=all"),
        ("branch", "--show-current"),
        ("rev-parse", "HEAD"),
        ("rev-parse", runner.EXPECTED_REMOTE_REF),
    ]


def test_git_provenance_rejects_wrong_architecture_hash_without_path_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    architecture, _calls = _configure_git_provenance(monkeypatch, tmp_path)
    architecture.write_bytes(b"tampered architecture\n")

    with pytest.raises(SystemExit, match="architecture file hash") as caught:
        runner._verified_git_state()

    assert str(tmp_path) not in str(caught.value)


def test_git_provenance_rejects_extra_untracked_file_alongside_architecture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _architecture, _calls = _configure_git_provenance(
        monkeypatch, tmp_path, status="?? unexpected.txt"
    )

    with pytest.raises(SystemExit, match="worktree changes or untracked files"):
        runner._verified_git_state()


def test_git_provenance_rejects_wrong_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _architecture, _calls = _configure_git_provenance(
        monkeypatch, tmp_path, branch="main"
    )

    with pytest.raises(SystemExit, match="not running on the PR #43 branch"):
        runner._verified_git_state()


def test_git_provenance_rejects_head_not_at_remote_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _architecture, _calls = _configure_git_provenance(
        monkeypatch, tmp_path, remote_head="b" * 40
    )

    with pytest.raises(SystemExit, match="not the exact pushed PR branch commit"):
        runner._verified_git_state()


def test_hostile_python_and_pytest_environment_is_neutralized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTHONHOME", "hostile-home")
    monkeypatch.setenv("PYTHONPATH", "hostile-package")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--ignore=tests/test_p6_vfp_indexed.py")
    monkeypatch.setenv("PYTEST_PLUGINS", "hostile_plugin")

    env = runner._acceptance_environment(Path("vfp9.exe"))

    assert "PYTHONHOME" not in env
    assert env["PYTHONPATH"].split(os.pathsep) == [
        str(runner.SOURCE_ROOT),
        str(runner.REPO_ROOT),
    ]
    assert env["PYTEST_ADDOPTS"] == ""
    assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert "PYTEST_PLUGINS" not in env


def test_foreign_package_origin_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    foreign_package = tmp_path / "site-packages" / "dbf_anonymizer" / "__init__.py"
    foreign_package.parent.mkdir(parents=True)
    foreign_package.write_text("", encoding="ascii")
    completed = SimpleNamespace(returncode=0, stdout=str(foreign_package))
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: completed)

    with pytest.raises(SystemExit, match="would not import"):
        runner._verify_source_origin({})


def test_evidence_destination_outside_system_temp_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    system_temp = tmp_path / "system-temp"
    system_temp.mkdir()
    outside = tmp_path / "outside" / "evidence.json"
    monkeypatch.setattr(runner.tempfile, "gettempdir", lambda: str(system_temp))

    with pytest.raises(SystemExit, match="directly inside system TEMP"):
        runner._verified_output_path(outside)
