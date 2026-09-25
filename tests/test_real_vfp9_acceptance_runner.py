"""Negative provenance tests for the manual real-VFP9 acceptance runner."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.run_real_vfp9_acceptance as runner


def test_git_provenance_rejects_every_untracked_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def dirty_git(*args: str) -> str:
        calls.append(args)
        return "?? local-evidence.json"

    monkeypatch.setattr(runner, "_run_git", dirty_git)

    with pytest.raises(SystemExit, match="untracked files are present"):
        runner._verified_git_state()

    assert calls == [("status", "--porcelain", "--untracked-files=all")]


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
    assert env["PYTHONNOUSERSITE"] == "1"


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
