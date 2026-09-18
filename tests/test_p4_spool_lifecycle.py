"""BLOCKER 4 regressions: the complete sensitive SQLite spool lifecycle.

The ephemeral pass-1 spool is original-bearing Zone B state.  Its artifact
set is the main ``pass1-state.sqlite3`` database plus every SQLite sidecar
(``-wal``, ``-shm``, rollback journal).  The lifecycle: refuse ANY residue at
startup, restrict the main artifact to the owner where the platform permits
(truthful on Windows — no POSIX guarantee is claimed), clean up EVERY known
artifact and verify their absence, and surface cleanup failures as typed,
value-free errors.  No secure-deletion claim is made.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from unittest import mock

from dbf_anonymizer import VaultError
from dbf_anonymizer.engine.state import (
    MAX_SQL_BATCH,
    PASS1_STATE_FILENAME,
    PassOneSpool,
    spool_artifacts,
)

_MAIN = PASS1_STATE_FILENAME
_WAL = PASS1_STATE_FILENAME + "-wal"
_SHM = PASS1_STATE_FILENAME + "-shm"
_JOURNAL = PASS1_STATE_FILENAME + "-journal"
_ALL = (_MAIN, _WAL, _SHM, _JOURNAL)


def _residue(vault_dir: Path, names: tuple[str, ...]) -> None:
    vault_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        (vault_dir / name).write_bytes(b"leftover-crash-residue")


# ---------------------------------------------------------------------------
# Startup: ANY known residue is refused, never silently reused
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "names",
    [
        (_MAIN,),
        (_WAL,),
        (_SHM,),
        (_JOURNAL,),
        (_MAIN, _WAL),
        (_MAIN, _JOURNAL),
        (_WAL, _SHM),
        (_WAL, _JOURNAL, _SHM),
        _ALL,
    ],
)
def test_any_known_residue_is_refused(tmp_path: Path, names: tuple[str, ...]) -> None:
    vault_dir = tmp_path / "vault"
    _residue(vault_dir, names)
    with pytest.raises(VaultError) as excinfo:
        PassOneSpool(vault_dir)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"] == "ENGINE_SPOOL_LEFTOVER_REFUSED"
    )
    # The residue is untouched (no silent reuse, no silent wipe).
    for name in names:
        assert (vault_dir / name).is_file()


# ---------------------------------------------------------------------------
# Permissions: owner-restricted main artifact where the platform permits
# ---------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="no POSIX mode semantics")
def test_posix_main_spool_mode_is_owner_restricted(tmp_path: Path) -> None:
    spool = PassOneSpool(tmp_path / "vault")
    try:
        mode = os.stat(tmp_path / "vault" / _MAIN).st_mode & 0o777
        assert mode == 0o600
    finally:
        spool.cleanup()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows truthfulness")
def test_windows_makes_no_posix_mode_claim(tmp_path: Path) -> None:
    """On Windows the hardening is best-effort: the spool exists and works,
    and the test asserts NOTHING about POSIX modes (no unverified claim)."""
    spool = PassOneSpool(tmp_path / "vault")
    try:
        assert (tmp_path / "vault" / _MAIN).is_file()
        # The platform may or may not expose POSIX-like modes; whatever it
        # reports is recorded, never claimed as a guarantee.
        mode = os.stat(tmp_path / "vault" / _MAIN).st_mode & 0o777
        assert mode >= 0  # the stat probe itself must not fail
    finally:
        spool.cleanup()


def test_live_spool_writes_no_sidecar_artifacts(tmp_path: Path) -> None:
    """journal_mode=OFF: the LIVE spool only ever has its main artifact."""
    spool = PassOneSpool(tmp_path / "vault")
    try:
        for index in range(MAX_SQL_BATCH + 5):
            spool.observe_text(f"VALUE-{index:05d}", byte_width=12)
        spool.flush()
        assert spool_artifacts(tmp_path / "vault") == [tmp_path / "vault" / _MAIN]
        mode = spool.internal_connection().execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]
        assert str(mode).lower() == "off"
    finally:
        spool.cleanup()


# ---------------------------------------------------------------------------
# Cleanup: every artifact removed and absence verified
# ---------------------------------------------------------------------------
def test_cleanup_removes_every_known_artifact(tmp_path: Path) -> None:
    spool = PassOneSpool(tmp_path / "vault")
    spool.observe_text("SOMETHING", byte_width=8)
    spool.flush()
    assert (tmp_path / "vault" / _MAIN).is_file()
    spool.cleanup()
    assert spool_artifacts(tmp_path / "vault") == []
    assert spool.size_bytes() == 0


def test_cleanup_after_reopen_refuses_and_keeps_residue(tmp_path: Path) -> None:
    """A closed spool never re-cleans: the residue contract stays truthful."""
    vault_dir = tmp_path / "vault"
    spool = PassOneSpool(vault_dir)
    spool.cleanup()
    _residue(vault_dir, (_MAIN,))  # fresh residue appears AFTER closure
    spool.cleanup()  # no-op on a closed spool
    assert (vault_dir / _MAIN).is_file()


def test_injected_cleanup_failure_is_surfaced(tmp_path: Path) -> None:
    spool = PassOneSpool(tmp_path / "vault")
    spool.observe_text("SOMETHING", byte_width=8)
    spool.flush()
    real_unlink = Path.unlink
    calls = {"count": 0}

    def failing_unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name == _MAIN:
            calls["count"] += 1
            raise OSError("injected unlink failure")
        real_unlink(self, missing_ok=missing_ok)

    with pytest.raises(VaultError) as excinfo:
        with mock.patch.object(
            Path, "unlink", failing_unlink
        ):
            spool.cleanup()
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_SPOOL_CLEANUP_FAILED"
    )
    # The artifact that could not be removed stays (truthful, no lie).
    assert (tmp_path / "vault" / _MAIN).is_file()
    assert calls["count"] >= 1
    # The error boundary carries no path, no artifact name, no values.
    boundary = str(excinfo.value) + repr(excinfo.value) + str(
        excinfo.value.to_dict()
    )
    assert str(tmp_path) not in boundary
    assert _MAIN not in boundary
    assert "SOMETHING" not in boundary


# ---------------------------------------------------------------------------
# No spool artifact ever under source/output (covered end-to-end here too)
# ---------------------------------------------------------------------------
def test_no_spool_artifact_under_source_or_output(tmp_path: Path) -> None:
    from dbf_anonymizer import build_plan
    from dbf_anonymizer.engine import run_two_pass

    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    (source_root / "north").mkdir(parents=True)
    from support.numeric_tables import numeric_field, write_numeric_table

    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("NAME", "C", 8),),
        [{"NAME": "ALFA"}, {"NAME": "BETA"}],
    )
    plan = build_plan(
        str(source_root),
        str(output_root),
        str(tmp_path / "vault" / "dictionary.sqlite3"),
    )
    result = run_two_pass(plan)
    assert result.tables_written == ("north/customers.dbf",)
    for tree in (source_root, output_root):
        for artifact in spool_artifacts(tree):
            raise AssertionError(f"spool artifact escaped into {tree.name}: {artifact.name}")
        assert not list(tree.rglob(PASS1_STATE_FILENAME + "*"))