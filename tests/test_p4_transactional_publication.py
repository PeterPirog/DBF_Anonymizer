"""REQ-P4-009 lock, staging, stale-state and idempotent retry evidence."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from dbf_anonymizer import (
    CancellationError,
    PathError,
    PublicationError,
    VaultError,
    build_plan,
)
from dbf_anonymizer.engine import run as run_module
from dbf_anonymizer.engine import locking as locking_module
from dbf_anonymizer.engine import pass2 as pass2_module
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.engine.locking import DestinationLock
from dbf_anonymizer.engine import publication as publication_module
from dbf_anonymizer.engine.state import PASS1_STATE_FILENAME, spool_artifacts
from dbf_anonymizer.errors import ErrorCode
from dbf_anonymizer.vault.store import VaultDatabase, new_writer_token
from tests.support.numeric_tables import numeric_field, write_numeric_table


MEMO_CANARY = "P4009-PRIVATE-MEMO-CANARY"


def _write_source(source: Path) -> None:
    fields = (
        numeric_field("NAME", "C", 32),
        numeric_field("NOTE", "M", 4),
    )
    write_numeric_table(
        source,
        "north/data.dbf",
        fields,
        [{"NAME": "PRIVATE-NORTH", "NOTE": MEMO_CANARY}],
    )
    write_numeric_table(
        source,
        "south/data.dbf",
        fields,
        [{"NAME": "PRIVATE-SOUTH", "NOTE": "SECOND-" + MEMO_CANARY}],
    )


def _hash_tree(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _plan(tmp_path: Path):
    source = tmp_path / "source"
    _write_source(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    return build_plan(source, output, vault), source, output, vault


def _vault_counts(plan: object, vault_path: Path) -> tuple[int, int, int, int]:
    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,  # type: ignore[attr-defined]
        expected_policy_fingerprint=plan.policy.policy_fingerprint,  # type: ignore[attr-defined]
        expected_relationship_fingerprint=(
            plan.relationships.relationship_fingerprint  # type: ignore[attr-defined]
        ),
    ) as vault:
        connection = vault._internal_connection()
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "operations",
                "text_mappings",
                "numeric_key_mappings",
                "memo_recovery",
            )
        )  # type: ignore[return-value]


def test_completed_operation_retry_is_read_only_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    first = run_two_pass(plan, workers=2)
    output_before = _hash_tree(output)
    mtimes_before = {
        path.relative_to(output).as_posix(): path.stat().st_mtime_ns
        for path in output.rglob("*")
        if path.is_file()
    }
    vault_before = _vault_counts(plan, vault)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("completed retry entered a transformation pass")

    monkeypatch.setattr(run_module, "run_pass_one", forbidden)
    monkeypatch.setattr(run_module, "run_pass_two", forbidden)
    second = run_two_pass(plan, workers=4)

    assert second.reused_existing is True
    assert dataclasses.replace(second, reused_existing=False) == first
    assert _hash_tree(output) == output_before
    assert {
        path.relative_to(output).as_posix(): path.stat().st_mtime_ns
        for path in output.rglob("*")
        if path.is_file()
    } == mtimes_before
    assert _vault_counts(plan, vault) == vault_before
    assert vault_before[0] == 1
    assert _hash_tree(source) == source_before


def test_completed_operation_retry_refuses_sensitive_residue(tmp_path: Path) -> None:
    plan, _source, output, vault = _plan(tmp_path)
    run_two_pass(plan, workers=2)
    output_before = _hash_tree(output)
    residue = vault.parent / PASS1_STATE_FILENAME
    residue.write_bytes(b"SYNTHETIC-SENSITIVE-RESIDUE")

    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan, workers=2)

    assert excinfo.value.to_dict()["context"]["detail_code"] == (
        "ENGINE_SPOOL_LEFTOVER_REFUSED"
    )
    assert residue.read_bytes() == b"SYNTHETIC-SENSITIVE-RESIDUE"
    assert _hash_tree(output) == output_before


def test_conflicting_operation_and_unknown_target_fail_closed(tmp_path: Path) -> None:
    plan, _source, output, _vault = _plan(tmp_path)
    first = run_two_pass(plan)
    before = _hash_tree(output)
    with pytest.raises(PathError) as conflicting:
        run_two_pass(plan, operation_id="vop-conflicting-operation")
    assert conflicting.value.code is ErrorCode.DESTINATION_CONFLICT
    assert _hash_tree(output) == before
    assert first.operation_id is not None

    other = tmp_path / "other"
    other_plan, _source2, other_output, _vault2 = _plan(other)
    other_output.mkdir(parents=True)
    marker = other_output / "unknown.txt"
    marker.write_text("operator-owned", encoding="ascii")
    with pytest.raises(PathError) as unknown:
        run_two_pass(other_plan)
    assert unknown.value.code is ErrorCode.DESTINATION_CONFLICT
    assert marker.read_text(encoding="ascii") == "operator-owned"


@pytest.mark.parametrize(
    "fault_point",
    [
        "LOCK_ACQUIRED",
        "AFTER_OPERATION_START",
        "AFTER_FIRST_TABLE_STAGED",
        "AFTER_ALL_TABLES_STAGED",
        "AFTER_STAGED_STATE",
        "BEFORE_STAGING_PROMOTION",
    ],
)
def test_controlled_prepublication_fault_cleans_only_owned_state(
    tmp_path: Path, fault_point: str
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)

    def inject(point: str) -> None:
        if point == fault_point:
            raise RuntimeError("deterministic fault")

    with pytest.raises(RuntimeError, match="deterministic fault"):
        run_two_pass(plan, workers=2, fault_inject=inject)
    assert not output.exists()
    assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging"))
    assert _hash_tree(source) == source_before
    if vault.exists():
        assert _vault_counts(plan, vault)[0] == 0
        assert spool_artifacts(vault.parent) == []


def test_output_staging_contains_only_pseudonymized_dataset_material(
    tmp_path: Path,
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    inspected = False

    def inspect(point: str) -> None:
        nonlocal inspected
        if point != "AFTER_ALL_TABLES_STAGED":
            return
        roots = tuple(tmp_path.glob(".dbf-anonymizer-*.staging"))
        assert len(roots) == 1
        root = roots[0]
        files = tuple(path for path in root.rglob("*") if path.is_file())
        assert files
        assert not any(
            path.suffix.lower() in {".sqlite3", ".db", ".wal", ".shm", ".journal"}
            for path in files
        )
        for path in files:
            assert MEMO_CANARY.encode("ascii") not in path.read_bytes()
        inspected = True
        raise RuntimeError("inspection complete")

    with pytest.raises(RuntimeError, match="inspection complete"):
        run_two_pass(plan, workers=2, fault_inject=inspect)
    assert inspected
    assert not output.exists()
    assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging"))
    assert _hash_tree(source) == source_before
    assert MEMO_CANARY.encode("ascii") in vault.read_bytes()


def test_promotion_failure_never_exposes_partial_dataset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, _source, output, vault = _plan(tmp_path)
    real_replace = publication_module.os.replace

    def fail_dataset_promotion(source: object, destination: object) -> None:
        assert isinstance(source, (str, Path))
        if Path(source).name == "dataset":
            raise OSError("injected promotion failure")
        real_replace(source, destination)  # type: ignore[arg-type]

    monkeypatch.setattr(publication_module.os, "replace", fail_dataset_promotion)
    with pytest.raises(PublicationError) as excinfo:
        run_two_pass(plan, workers=2)
    assert excinfo.value.code is ErrorCode.PUBLICATION_INCOMPLETE
    assert not output.exists()
    assert _vault_counts(plan, vault)[0] == 0


def test_fault_after_promotion_is_stale_not_silently_retried(tmp_path: Path) -> None:
    plan, source, output, vault = _plan(tmp_path)
    before = _hash_tree(source)

    def inject(point: str) -> None:
        if point == "AFTER_STAGING_PROMOTION":
            raise RuntimeError("post-promotion fault")

    with pytest.raises(RuntimeError, match="post-promotion fault"):
        run_two_pass(plan, fault_inject=inject)
    assert output.is_dir()
    assert _hash_tree(source) == before
    with pytest.raises(PublicationError) as stale:
        run_two_pass(plan)
    assert stale.value.code is ErrorCode.PUBLICATION_INCOMPLETE
    assert stale.value.to_dict()["context"]["detail_code"] == "STALE_OPERATION_DETECTED"
    assert _vault_counts(plan, vault)[0] == 1


def test_fault_after_complete_is_safe_idempotent_retry(tmp_path: Path) -> None:
    plan, _source, output, _vault = _plan(tmp_path)

    def inject(point: str) -> None:
        if point == "AFTER_OPERATION_COMPLETE":
            raise RuntimeError("caller lost completion")

    with pytest.raises(RuntimeError, match="caller lost completion"):
        run_two_pass(plan, fault_inject=inject)
    before = _hash_tree(output)
    retry = run_two_pass(plan)
    assert retry.reused_existing
    assert _hash_tree(output) == before


def test_hard_exit_leaves_detectable_stale_transaction(tmp_path: Path) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    project = Path(__file__).resolve().parents[1]
    script = f"""
import os
from dbf_anonymizer import build_plan
from dbf_anonymizer.engine import run_two_pass
plan = build_plan({str(source)!r}, {str(output)!r}, {str(vault)!r})
def fault(point):
    if point == 'AFTER_FIRST_TABLE_STAGED':
        os._exit(73)
run_two_pass(plan, workers=1, fault_inject=fault)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=project,
        env={**os.environ, "PYTHONPATH": str(project / "src")},
        capture_output=True,
        timeout=120,
    )
    assert completed.returncode == 73, completed.stderr.decode("utf-8", "replace")
    assert not output.exists()
    assert _hash_tree(source) == source_before
    staging = tuple(tmp_path.glob(".dbf-anonymizer-*.staging"))
    assert len(staging) == 1
    assert not tuple(staging[0].rglob("*.sqlite3"))
    assert not tuple(staging[0].rglob("*-wal"))
    with VaultDatabase.open(
        vault,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
    ) as reopened:
        reopened.verify(full=True)
        assert [row["state"] for row in reopened.operations()] == ["STARTED"]
    with pytest.raises(PublicationError) as stale:
        run_two_pass(plan)
    assert stale.value.to_dict()["context"]["detail_code"] == "STALE_OPERATION_DETECTED"
    assert _hash_tree(source) == source_before


def test_destination_lock_has_real_os_ownership(tmp_path: Path) -> None:
    lock_path = tmp_path / "target.lock"
    with DestinationLock(lock_path):
        with pytest.raises(PublicationError) as conflict:
            with DestinationLock(lock_path):
                pass
    assert conflict.value.to_dict()["context"]["detail_code"] == "DESTINATION_LOCK_HELD"
    with DestinationLock(lock_path):
        pass


def test_destination_lock_refuses_nonregular_path(tmp_path: Path) -> None:
    lock_path = tmp_path / "target.lock"
    lock_path.mkdir()

    with pytest.raises(PublicationError) as excinfo:
        with DestinationLock(lock_path):
            pass

    assert excinfo.value.to_dict()["context"]["detail_code"] == (
        "DESTINATION_LOCK_INVALID"
    )


def test_destination_lock_refuses_symlink_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path = tmp_path / "target.lock"
    real_lstat = locking_module.os.lstat

    def symlink_lstat(path: object) -> os.stat_result:
        if Path(path) == lock_path:  # type: ignore[arg-type]
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return real_lstat(path)  # type: ignore[arg-type]

    monkeypatch.setattr(locking_module.os, "lstat", symlink_lstat)

    with pytest.raises(PublicationError) as excinfo:
        with DestinationLock(lock_path):
            pass

    assert excinfo.value.to_dict()["context"]["detail_code"] == (
        "DESTINATION_LOCK_INVALID"
    )


def test_lock_stream_close_failure_is_typed(tmp_path: Path) -> None:
    lock = DestinationLock(tmp_path / "target.lock")
    lock.__enter__()
    stream = lock._stream
    assert stream is not None

    class CloseFailingStream:
        @property
        def closed(self) -> bool:
            return stream.closed

        def fileno(self) -> int:
            return stream.fileno()

        def seek(self, offset: int) -> int:
            return stream.seek(offset)

        def close(self) -> None:
            stream.close()
            raise OSError("private close failure")

    lock._stream = CloseFailingStream()  # type: ignore[assignment]
    with pytest.raises(PublicationError) as excinfo:
        lock.close()

    assert excinfo.value.to_dict()["context"]["detail_code"] == (
        "DESTINATION_LOCK_RELEASE_FAILED"
    )
    assert lock._stream is None


def test_lock_release_failure_preserves_operation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = RuntimeError("operation failed")

    def fail_release(_stream: object) -> None:
        raise OSError("release failed")

    monkeypatch.setattr(DestinationLock, "_release", staticmethod(fail_release))
    with pytest.raises(PublicationError) as excinfo:
        with DestinationLock(tmp_path / "target.lock"):
            raise original

    assert excinfo.value.__cause__ is original
    assert excinfo.value.to_dict()["context"]["detail_code"] == (
        "DESTINATION_LOCK_RELEASE_FAILED"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file-lock evidence")
def test_windows_destination_lock_is_owned_across_processes(tmp_path: Path) -> None:
    lock_path = tmp_path / "windows-target.lock"
    project = Path(__file__).resolve().parents[1]
    script = f"""
from pathlib import Path
from dbf_anonymizer.engine.locking import DestinationLock
from dbf_anonymizer.errors import PublicationError
try:
    with DestinationLock(Path({str(lock_path)!r})):
        raise SystemExit(2)
except PublicationError as error:
    detail = error.to_dict()['context']['detail_code']
    raise SystemExit(0 if detail == 'DESTINATION_LOCK_HELD' else 3)
"""
    with DestinationLock(lock_path):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=project,
            env={**os.environ, "PYTHONPATH": str(project / "src")},
            capture_output=True,
            timeout=120,
        )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_same_vault_writer_lease_remains_authoritative(tmp_path: Path) -> None:
    plan, source, _output, vault_path = _plan(tmp_path)
    with VaultDatabase.open(
        vault_path,
        create=True,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version="1.1.1",
    ) as vault:
        token = new_writer_token()
        vault.acquire_writer_lease(token)
        with pytest.raises(VaultError) as conflict:
            run_two_pass(plan)
        assert conflict.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        vault.release_writer_lease(token)
    assert _hash_tree(source)


def test_concurrent_same_target_runs_refuse_the_second_writer(tmp_path: Path) -> None:
    plan, _source, output, _vault = _plan(tmp_path)
    acquired = threading.Event()
    release = threading.Event()

    def hold_destination_lock(point: str) -> None:
        if point == "LOCK_ACQUIRED":
            acquired.set()
            assert release.wait(timeout=30)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(
            run_two_pass, plan, workers=2, fault_inject=hold_destination_lock
        )
        assert acquired.wait(timeout=30)
        try:
            with pytest.raises(PublicationError) as conflict:
                run_two_pass(plan)
        finally:
            release.set()
        result = first.result(timeout=30)

    assert conflict.value.to_dict()["context"]["detail_code"] == (
        "DESTINATION_LOCK_HELD"
    )
    assert result.output_fingerprint is not None
    assert output.is_dir()


def test_concurrent_different_targets_refuse_the_second_vault_writer(
    tmp_path: Path,
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    other_plan = build_plan(source, tmp_path / "other-output", vault)
    writer_started = threading.Event()
    release = threading.Event()

    def hold_writer_lease(point: str) -> None:
        if point == "AFTER_OPERATION_START":
            writer_started.set()
            assert release.wait(timeout=30)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(
            run_two_pass, plan, workers=2, fault_inject=hold_writer_lease
        )
        assert writer_started.wait(timeout=30)
        try:
            with pytest.raises(VaultError) as conflict:
                run_two_pass(other_plan)
        finally:
            release.set()
        result = first.result(timeout=30)

    assert conflict.value.code is ErrorCode.VAULT_WRITER_CONFLICT
    assert result.output_fingerprint is not None
    assert output.is_dir()
    assert not (tmp_path / "other-output").exists()


def test_parallel_worker_failure_leaves_no_completed_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    barrier = threading.Barrier(2)
    failure_released = threading.Event()
    sibling_stopped = threading.Event()
    captured_stop: list[threading.Event] = []
    real_checkpoint = pass2_module._worker_checkpoint

    def capture_checkpoint(stop: threading.Event) -> None:
        if not captured_stop:
            captured_stop.append(stop)
        real_checkpoint(stop)

    def fail_one_worker(*args: object, **kwargs: object):
        destination = Path(args[0])  # type: ignore[arg-type]
        barrier.wait(timeout=30)
        if destination.parent.name == "00000000":
            failure_released.set()
            raise RuntimeError("deterministic worker failure")
        assert failure_released.wait(timeout=30)
        assert captured_stop[0].wait(timeout=30)
        cancel_check = kwargs["cancel_check"]
        assert callable(cancel_check)
        try:
            cancel_check()
        except CancellationError:
            sibling_stopped.set()
            raise
        raise AssertionError("sibling worker ignored the coordinator stop")

    monkeypatch.setattr(pass2_module, "_worker_checkpoint", capture_checkpoint)
    monkeypatch.setattr(pass2_module, "write_fresh_table", fail_one_worker)
    with pytest.raises(RuntimeError, match="deterministic worker failure"):
        run_two_pass(plan, workers=2)

    assert sibling_stopped.is_set()
    assert not output.exists()
    assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging"))
    assert _vault_counts(plan, vault)[0] == 0
    assert _hash_tree(source) == source_before


def test_worker_cleanup_failure_preserves_original_cause_and_privacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    real_cleanup = pass2_module.RelationEvidenceShard.cleanup

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("PRIVATE-WORKER-FAILURE")

    def cleanup_then_fail(shard: object) -> None:
        real_cleanup(shard)  # type: ignore[arg-type]
        raise OSError("PRIVATE-CLEANUP-FAILURE")

    monkeypatch.setattr(pass2_module, "write_fresh_table", fail_write)
    monkeypatch.setattr(
        pass2_module.RelationEvidenceShard, "cleanup", cleanup_then_fail
    )

    with pytest.raises(PublicationError) as excinfo:
        run_two_pass(plan, workers=1)

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert excinfo.value.to_dict()["context"]["detail_code"] == (
        "ENGINE_WORKER_CLEANUP_FAILED"
    )
    serialized = json.dumps(excinfo.value.to_dict(), sort_keys=True)
    assert "PRIVATE-WORKER-FAILURE" not in serialized
    assert "PRIVATE-CLEANUP-FAILURE" not in serialized
    assert not output.exists()
    assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging"))
    assert _vault_counts(plan, vault)[0] == 0
    assert _hash_tree(source) == source_before


def test_cancellation_after_table_staging_leaves_no_completed_publication(
    tmp_path: Path,
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    staged = False

    def progress(event: object) -> None:
        nonlocal staged
        if (
            getattr(event, "phase_code", None) == "PASS2_WRITE"
            and getattr(event, "event_code", None) == "PROGRESS"
        ):
            staged = True

    with pytest.raises(CancellationError):
        run_two_pass(
            plan,
            workers=1,
            progress=progress,
            cancel_check=lambda: staged,
        )

    assert staged
    assert not output.exists()
    assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging"))
    assert _vault_counts(plan, vault)[0] == 0
    assert _hash_tree(source) == source_before
