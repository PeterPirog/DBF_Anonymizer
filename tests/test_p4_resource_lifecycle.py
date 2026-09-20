"""Full-engine resource acquisition and independent cleanup regressions."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import dbfbridge
import pytest

import dbf_anonymizer.engine.run as run_module
import dbf_anonymizer.engine.state as state_module
from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.engine.state import (
    PASS1_STATE_FILENAME,
    PassOneSpool,
    RelationEvidenceShard,
    spool_artifacts,
)
from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError, VaultError
from dbf_anonymizer.models import Plan
from dbf_anonymizer.vault.store import VaultDatabase
from support.numeric_tables import numeric_field, write_numeric_table

_RESIDUES = (
    PASS1_STATE_FILENAME,
    PASS1_STATE_FILENAME + "-wal",
    PASS1_STATE_FILENAME + "-shm",
    PASS1_STATE_FILENAME + "-journal",
)


def _plan(tmp_path: Path) -> tuple[Plan, Path, Path, Path]:
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_table(
        source,
        "people.dbf",
        (numeric_field("NAME", "C", 8),),
        [{"NAME": "ALFA"}, {"NAME": "BETA"}, {"NAME": "GAMMA"}],
    )
    return build_plan(str(source), str(output), str(vault_path)), source, output, vault_path


def _open_vault(
    plan: Plan, vault_path: Path, *, create: bool = False
) -> VaultDatabase:
    return VaultDatabase.open(
        vault_path,
        create=create,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version=str(dbfbridge.__version__) if create else None,
    )


def _create_vault(plan: Plan, vault_path: Path) -> None:
    with _open_vault(plan, vault_path, create=True) as vault:
        vault.verify()


def _assert_vault_reopens(plan: Plan, vault_path: Path) -> None:
    with _open_vault(plan, vault_path) as vault:
        vault.verify()


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _assert_no_output(output: Path) -> None:
    assert not output.exists() or not any(path.is_file() for path in output.rglob("*"))


def _detail(error: VaultError) -> str | None:
    return error.context.detail_code


def _assert_safe_boundary(error: VaultError, tmp_path: Path) -> None:
    boundary = str(error) + repr(error) + str(error.to_dict())
    assert str(tmp_path) not in boundary
    assert "ALFA" not in boundary
    assert "SYNTHETIC-ORIGINAL" not in boundary


@pytest.mark.parametrize("residue_name", _RESIDUES)
@pytest.mark.parametrize("preexisting_vault", (False, True))
def test_run_refuses_known_residue_before_vault_open(
    tmp_path: Path,
    residue_name: str,
    preexisting_vault: bool,
) -> None:
    plan, source, output, vault_path = _plan(tmp_path)
    before = _tree_hashes(source)
    if preexisting_vault:
        _create_vault(plan, vault_path)
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    residue = vault_path.parent / residue_name
    residue.write_bytes(b"SYNTHETIC-ORIGINAL")

    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)

    assert _detail(excinfo.value) == "ENGINE_SPOOL_LEFTOVER_REFUSED"
    assert residue.read_bytes() == b"SYNTHETIC-ORIGINAL"
    assert _tree_hashes(source) == before
    _assert_no_output(output)
    _assert_safe_boundary(excinfo.value, tmp_path)
    if preexisting_vault:
        _assert_vault_reopens(plan, vault_path)
    else:
        assert not vault_path.exists()


def test_spool_schema_failure_cleans_partial_artifacts_and_closes_vault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, source, output, vault_path = _plan(tmp_path)
    before = _tree_hashes(source)

    def fail_after_main_file_created(_self: PassOneSpool) -> None:
        raise RuntimeError("SYNTHETIC-ORIGINAL initialization failure")

    monkeypatch.setattr(PassOneSpool, "_create_schema", fail_after_main_file_created)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)

    assert _detail(excinfo.value) == "ENGINE_SPOOL_INITIALIZATION_FAILED"
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert spool_artifacts(vault_path.parent) == []
    assert _tree_hashes(source) == before
    _assert_no_output(output)
    _assert_safe_boundary(excinfo.value, tmp_path)
    _assert_vault_reopens(plan, vault_path)


def test_constructor_cleanup_failure_is_typed_and_keeps_initial_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_directory = tmp_path / "vault"
    real_unlink = Path.unlink

    def fail_schema(_self: PassOneSpool) -> None:
        raise RuntimeError("SYNTHETIC-ORIGINAL initialization failure")

    def fail_main_unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name == PASS1_STATE_FILENAME:
            raise OSError("synthetic unlink failure")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(PassOneSpool, "_create_schema", fail_schema)
    monkeypatch.setattr(Path, "unlink", fail_main_unlink)
    with pytest.raises(VaultError) as excinfo:
        PassOneSpool(vault_directory)

    assert _detail(excinfo.value) == "ENGINE_SPOOL_INITIALIZATION_CLEANUP_FAILED"
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert (vault_directory / PASS1_STATE_FILENAME).is_file()
    _assert_safe_boundary(excinfo.value, tmp_path)
    monkeypatch.setattr(Path, "unlink", real_unlink)
    (vault_directory / PASS1_STATE_FILENAME).unlink()


def test_evidence_shard_create_failure_is_typed_and_cleans_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "evidence.sqlite3"

    def fail_connect(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.OperationalError("private create failure")

    monkeypatch.setattr(state_module.sqlite3, "connect", fail_connect)
    with pytest.raises(VaultError) as excinfo:
        RelationEvidenceShard(path)

    assert _detail(excinfo.value) == "ENGINE_SPOOL_EVIDENCE_SHARD_CREATE_FAILED"
    assert not path.exists()
    _assert_safe_boundary(excinfo.value, tmp_path)


def test_evidence_shard_create_cleanup_failure_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "evidence.sqlite3"
    real_unlink = Path.unlink

    def fail_connect(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.OperationalError("private create failure")

    def fail_unlink(self: Path, missing_ok: bool = False) -> None:
        if self == path:
            raise OSError("private unlink failure")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(state_module.sqlite3, "connect", fail_connect)
    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(VaultError) as excinfo:
        RelationEvidenceShard(path)

    assert _detail(excinfo.value) == (
        "ENGINE_SPOOL_EVIDENCE_SHARD_CREATE_CLEANUP_FAILED"
    )
    assert path.is_file()
    _assert_safe_boundary(excinfo.value, tmp_path)
    monkeypatch.setattr(Path, "unlink", real_unlink)
    path.unlink()


def test_evidence_shard_close_failure_is_typed_and_still_unlinked(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evidence.sqlite3"
    shard = RelationEvidenceShard(path)
    connection = shard._connection

    class CloseFailingConnection:
        def __getattr__(self, name: str) -> object:
            return getattr(connection, name)

        def close(self) -> None:
            connection.close()
            raise sqlite3.OperationalError("private close failure")

    shard._connection = CloseFailingConnection()  # type: ignore[assignment]
    with pytest.raises(VaultError) as excinfo:
        shard.cleanup()

    assert _detail(excinfo.value) == "ENGINE_SPOOL_EVIDENCE_SHARD_CLOSE_FAILED"
    assert not path.exists()
    _assert_safe_boundary(excinfo.value, tmp_path)


def test_evidence_shard_unlink_failure_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "evidence.sqlite3"
    shard = RelationEvidenceShard(path)
    shard.close()
    real_unlink = Path.unlink

    def fail_unlink(self: Path, missing_ok: bool = False) -> None:
        if self == path:
            raise OSError("private unlink failure")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(VaultError) as excinfo:
        shard.cleanup()

    assert _detail(excinfo.value) == "ENGINE_SPOOL_EVIDENCE_SHARD_CLEANUP_FAILED"
    assert path.is_file()
    _assert_safe_boundary(excinfo.value, tmp_path)
    monkeypatch.setattr(Path, "unlink", real_unlink)
    path.unlink()


def test_vault_close_failure_does_not_skip_spool_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _source, _output, vault_path = _plan(tmp_path)
    real_spool_cleanup = PassOneSpool.cleanup
    real_vault_close = VaultDatabase.close
    spool_calls: list[bool] = []

    def tracked_spool_cleanup(self: PassOneSpool) -> None:
        spool_calls.append(True)
        real_spool_cleanup(self)

    def close_then_fail(self: VaultDatabase) -> None:
        real_vault_close(self)
        raise VaultError(
            ErrorCode.VAULT_UNAVAILABLE,
            context=ErrorContext(
                operation="vault", detail_code="CLOSE_FAILED_INJECTED"
            ),
        )

    monkeypatch.setattr(PassOneSpool, "cleanup", tracked_spool_cleanup)
    monkeypatch.setattr(VaultDatabase, "close", close_then_fail)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)

    assert _detail(excinfo.value) == "ENGINE_VAULT_CLOSE_FAILED"
    assert spool_calls == [True]
    assert spool_artifacts(vault_path.parent) == []
    _assert_safe_boundary(excinfo.value, tmp_path)
    monkeypatch.setattr(VaultDatabase, "close", real_vault_close)
    _assert_vault_reopens(plan, vault_path)


def test_spool_cleanup_failure_does_not_skip_vault_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _source, _output, vault_path = _plan(tmp_path)
    real_spool_cleanup = PassOneSpool.cleanup
    real_vault_close = VaultDatabase.close
    vault_calls: list[bool] = []

    def cleanup_then_fail(self: PassOneSpool) -> None:
        real_spool_cleanup(self)
        raise VaultError(
            ErrorCode.VAULT_STATE_INVALID,
            context=ErrorContext(
                operation="engine", detail_code="ENGINE_SPOOL_CLEANUP_FAILED_INJECTED"
            ),
        )

    def tracked_vault_close(self: VaultDatabase) -> None:
        vault_calls.append(self._read_only)
        real_vault_close(self)

    monkeypatch.setattr(PassOneSpool, "cleanup", cleanup_then_fail)
    monkeypatch.setattr(VaultDatabase, "close", tracked_vault_close)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)

    assert _detail(excinfo.value) == "ENGINE_SPOOL_CLEANUP_FAILED"
    # Pass 2 owns and closes one read-only connection; final resource cleanup
    # still closes the authoritative writable vault after spool cleanup fails.
    assert vault_calls == [True, False]
    assert spool_artifacts(vault_path.parent) == []
    _assert_safe_boundary(excinfo.value, tmp_path)
    monkeypatch.setattr(VaultDatabase, "close", real_vault_close)
    _assert_vault_reopens(plan, vault_path)


def test_both_cleanup_failures_are_reported_after_both_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _source, _output, vault_path = _plan(tmp_path)
    real_spool_cleanup = PassOneSpool.cleanup
    real_vault_close = VaultDatabase.close

    def cleanup_then_fail(self: PassOneSpool) -> None:
        real_spool_cleanup(self)
        raise RuntimeError("synthetic spool cleanup failure")

    def close_then_fail(self: VaultDatabase) -> None:
        real_vault_close(self)
        raise RuntimeError("synthetic vault close failure")

    monkeypatch.setattr(PassOneSpool, "cleanup", cleanup_then_fail)
    monkeypatch.setattr(VaultDatabase, "close", close_then_fail)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)

    assert _detail(excinfo.value) == "ENGINE_MULTIPLE_RESOURCE_CLEANUP_FAILED"
    cleanup_failures = getattr(excinfo.value, "_resource_cleanup_failures")
    assert [resource for resource, _error in cleanup_failures] == ["spool", "vault"]
    assert spool_artifacts(vault_path.parent) == []
    _assert_safe_boundary(excinfo.value, tmp_path)
    monkeypatch.setattr(VaultDatabase, "close", real_vault_close)
    _assert_vault_reopens(plan, vault_path)


def test_operation_and_cleanup_failures_both_remain_identifiable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, source, output, vault_path = _plan(tmp_path)
    before = _tree_hashes(source)
    real_spool_cleanup = PassOneSpool.cleanup
    real_vault_close = VaultDatabase.close
    vault_calls: list[bool] = []

    def fail_operation(*_args: object, **_kwargs: object) -> None:
        raise MappingError(
            ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
            context=ErrorContext(
                operation="engine", detail_code="ENGINE_OPERATION_FAILED_INJECTED"
            ),
        )

    def cleanup_then_fail(self: PassOneSpool) -> None:
        real_spool_cleanup(self)
        raise VaultError(
            ErrorCode.VAULT_STATE_INVALID,
            context=ErrorContext(
                operation="engine", detail_code="ENGINE_SPOOL_CLEANUP_FAILED_INJECTED"
            ),
        )

    def tracked_vault_close(self: VaultDatabase) -> None:
        vault_calls.append(True)
        real_vault_close(self)

    monkeypatch.setattr(run_module, "run_pass_one", fail_operation)
    monkeypatch.setattr(PassOneSpool, "cleanup", cleanup_then_fail)
    monkeypatch.setattr(VaultDatabase, "close", tracked_vault_close)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)

    assert _detail(excinfo.value) == "ENGINE_SPOOL_CLEANUP_FAILED"
    assert isinstance(excinfo.value.__cause__, MappingError)
    assert (
        excinfo.value.__cause__.context.detail_code
        == "ENGINE_OPERATION_FAILED_INJECTED"
    )
    cleanup_failures = getattr(excinfo.value, "_resource_cleanup_failures")
    assert len(cleanup_failures) == 1
    assert isinstance(cleanup_failures[0][1], VaultError)
    assert vault_calls == [True]
    assert spool_artifacts(vault_path.parent) == []
    assert _tree_hashes(source) == before
    _assert_no_output(output)
    _assert_safe_boundary(excinfo.value, tmp_path)
    monkeypatch.setattr(VaultDatabase, "close", real_vault_close)
    _assert_vault_reopens(plan, vault_path)
