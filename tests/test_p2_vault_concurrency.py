"""REQ-P2-003 — single logical writer authority and concurrent-writer evidence.

The authority is durable SQLite state (the ``writer_authority`` lease row of
the same dictionary), not an in-process lock: competing connections, threads
AND processes acquire it through ``BEGIN IMMEDIATE`` and the conditional
update admits exactly one writer. Deterministic synchronization (barriers,
queues, process handoff sequencing) is used; there is NO timing/sleep-based
correctness evidence, and the tests are Windows-CI safe.
"""

from __future__ import annotations

import multiprocessing
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from dbf_anonymizer import ErrorCode, VaultError
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    new_writer_token,
)
from support.vault_process_worker import attempt_acquire, attempt_create
from support.vault_sessions import (
    error_boundary_payload,
    file_sha256,
    sidecar_inventory,
    writer_session,
)

SOURCE_FP = "src-" + "4" * 60
POLICY_FP = "pol-" + "5" * 60
RELATIONSHIP_FP = "rel-" + "6" * 60
DBFBRIDGE_VERSION = "1.1.0"


def _open(tmp_path: Path, *, create: bool = False) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / "dictionary.sqlite3",
        create=create,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version=DBFBRIDGE_VERSION,
    )


def _reopen_existing(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / "dictionary.sqlite3",
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


def test_first_writer_acquires_and_second_is_rejected(tmp_path: Path) -> None:
    with _open(tmp_path, create=True) as creator:
        with writer_session(creator), creator.transaction():
            creator.begin_operation()
    first = _reopen_existing(tmp_path)
    second = _reopen_existing(tmp_path)
    try:
        token_a = new_writer_token()
        token_b = new_writer_token()
        tick_a = first.acquire_writer_lease(token_a)
        assert tick_a >= 1
        # The competing connection fails deterministically with a typed error.
        with pytest.raises(VaultError) as excinfo:
            second.acquire_writer_lease(token_b)
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert excinfo.value.context.detail_code == "WRITER_LEASE_HELD"
        # The authority remains with the first writer (durable, shared state).
        assert first.stale_writer_lease() == token_a
        assert second.stale_writer_lease() == token_a

        # Release returns authority cleanly; the next writer acquires it and
        # the durable tick advances exactly once per successful acquire.
        first.release_writer_lease(token_a)
        tick_b = second.acquire_writer_lease(token_b)
        assert tick_b == tick_a + 1
        with pytest.raises(VaultError) as excinfo:
            first.acquire_writer_lease(token_a)
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
    finally:
        first.close()
        second.close()


def test_non_holder_cannot_release_the_authority(tmp_path: Path) -> None:
    with _open(tmp_path, create=True) as creator:
        with writer_session(creator), creator.transaction():
            creator.begin_operation()
    holder = _reopen_existing(tmp_path)
    stranger = _reopen_existing(tmp_path)
    try:
        token = new_writer_token()
        stranger_token = new_writer_token()
        holder.acquire_writer_lease(token)
        with pytest.raises(VaultError) as excinfo:
            stranger.release_writer_lease(stranger_token)
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert excinfo.value.context.detail_code == "NOT_LEASE_HOLDER"
        # The authority was not disturbed.
        assert stranger.stale_writer_lease() == token
    finally:
        holder.close()
        stranger.close()


def test_stale_lease_is_explicit_and_reclaimable_by_token(tmp_path: Path) -> None:
    # A crashed writer (its connection vanishes without release) leaves an
    # EXPLICIT durable stale lease: readable, and reclaimable only by naming
    # the stored token.
    crashed_token = new_writer_token()
    with _open(tmp_path, create=True) as creator:
        creator.acquire_writer_lease(crashed_token)
    # Simulated crash: the first connection is gone; a fresh connection sees
    # the stale lease and must NOT acquire authority silently.
    survivor = _reopen_existing(tmp_path)
    try:
        assert survivor.stale_writer_lease() == crashed_token
        fresh_token = new_writer_token()
        with pytest.raises(VaultError) as excinfo:
            survivor.acquire_writer_lease(fresh_token)
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        # Wrong-token recovery is refused.
        with pytest.raises(VaultError):
            survivor.release_writer_lease(fresh_token)
        # Naming the stored stale token reclaims authority deterministically.
        survivor.release_writer_lease(crashed_token)
        assert survivor.stale_writer_lease() is None
        assert survivor.acquire_writer_lease(fresh_token) >= 1
    finally:
        survivor.close()


def test_stale_lease_blocks_mutations_until_reclaimed(tmp_path: Path) -> None:
    crashed_token = new_writer_token()
    with _open(tmp_path, create=True) as creator:
        creator.acquire_writer_lease(crashed_token)
    survivor = _reopen_existing(tmp_path)
    try:
        with pytest.raises(VaultError) as excinfo:
            with survivor.transaction():
                survivor.begin_operation()
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        # The defined reclaim path restores mutation authority.
        survivor.release_writer_lease(crashed_token)
        with writer_session(survivor), survivor.transaction():
            survivor.begin_operation()
        assert len(survivor.operations()) == 1
    finally:
        survivor.close()


def test_concurrent_writers_admit_exactly_one(tmp_path: Path) -> None:
    # Genuinely concurrent competing writers on separate threads and
    # connections; a barrier maximizes overlap. SQLite serializes the lease
    # transaction, so EXACTLY one acquire succeeds — every time.
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    with _open(tmp_path, create=True) as creator:
        creator.close()

    attempts = 4
    barrier = threading.Barrier(attempts)
    results: list[tuple[str, str]] = []
    results_lock = threading.Lock()

    def _attempt() -> None:
        token = new_writer_token()
        outcome = "UNEXPECTED"
        database = VaultDatabase.open(
            dictionary,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
        )
        try:
            barrier.wait()  # deterministic overlap point
            try:
                database.acquire_writer_lease(token)
                outcome = "ACQUIRED"
            except VaultError as error:
                outcome = (
                    "CONFLICT"
                    if error.code is ErrorCode.VAULT_WRITER_CONFLICT
                    else f"UNEXPECTED:{error.code.value}"
                )
        except BaseException:  # barrier/thread failure must not hang the suite
            outcome = "UNEXPECTED:BARRIER"
        finally:
            database.close()
            with results_lock:
                results.append((token, outcome))

    threads = [threading.Thread(target=_attempt) for _index in range(attempts)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    acquired = [token for token, outcome in results if outcome == "ACQUIRED"]
    conflicts = [token for token, outcome in results if outcome == "CONFLICT"]
    unexpected = [outcome for _token, outcome in results if outcome.startswith("UNEXPECTED")]
    assert not unexpected, results
    assert len(acquired) == 1, results
    assert len(conflicts) == attempts - 1, results
    # The durable lease records the single winner.
    check = _reopen_existing(tmp_path)
    try:
        assert check.stale_writer_lease() == acquired[0]
        assert check.writer_acquire_tick() == 1
    finally:
        check.release_writer_lease(acquired[0])
        check.close()


def test_process_level_second_writer_is_rejected(tmp_path: Path) -> None:
    # Process-level evidence (Windows-compatible spawn): the durable lease is
    # not merely thread-local — a separate PROCESS cannot acquire authority
    # while the parent holds it, and can acquire after a clean handoff.
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    with _open(tmp_path, create=True) as creator:
        creator.close()

    context = multiprocessing.get_context("spawn")
    payload = {
        "dictionary": str(dictionary),
        "source_fingerprint": SOURCE_FP,
        "policy_fingerprint": POLICY_FP,
        "relationship_fingerprint": RELATIONSHIP_FP,
        "token": new_writer_token(),
    }

    # Phase 1: the parent holds the authority -> the child process is rejected.
    holder = _reopen_existing(tmp_path)
    holder_token = new_writer_token()
    holder.acquire_writer_lease(holder_token)
    result_queue = context.Queue()
    process = context.Process(
        target=attempt_acquire, args=(payload, result_queue)
    )
    process.start()
    process.join(timeout=120)
    assert process.exitcode == 0
    first_result = result_queue.get(timeout=30)
    assert first_result["outcome"] == "CONFLICT", first_result
    assert first_result["detail"] == "VAULT_WRITER_CONFLICT"
    holder.release_writer_lease(holder_token)
    holder.close()

    # Phase 2: authority released -> the child process acquires it.
    payload["token"] = new_writer_token()
    result_queue = context.Queue()
    process = context.Process(
        target=attempt_acquire, args=(payload, result_queue)
    )
    process.start()
    process.join(timeout=120)
    assert process.exitcode == 0
    second_result = result_queue.get(timeout=30)
    assert second_result["outcome"] == "ACQUIRED", second_result


# ---------------------------------------------------------------------------
# Concurrent vault CREATION is atomic (TOCTOU: the loser can never delete,
# truncate, convert or replace the winner's dictionary)
# ---------------------------------------------------------------------------
def test_concurrent_thread_creation_admits_exactly_one(
    tmp_path: Path,
) -> None:
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    contenders = 4
    barrier = threading.Barrier(contenders)
    results: list[tuple[str, str]] = []
    results_lock = threading.Lock()

    def _contend() -> None:
        outcome = "UNEXPECTED"
        try:
            barrier.wait()  # deterministic overlap point
            try:
                vault = VaultDatabase.open(
                    dictionary,
                    create=True,
                    expected_source_fingerprint=SOURCE_FP,
                    expected_policy_fingerprint=POLICY_FP,
                    expected_relationship_fingerprint=RELATIONSHIP_FP,
                    dbfbridge_version=DBFBRIDGE_VERSION,
                )
            except VaultError as error:
                outcome = (
                    "CONFLICT"
                    if error.code is ErrorCode.VAULT_STATE_INVALID
                    else f"UNEXPECTED:{error.code.value}"
                )
            else:
                winner_id = vault.vault_id
                vault.close()
                outcome = f"CREATED:{winner_id}"
        except BaseException:  # barrier/thread failure must not hang the suite
            outcome = "UNEXPECTED:BARRIER"
        with results_lock:
            results.append(("winner", outcome))

    threads = [threading.Thread(target=_contend) for _index in range(contenders)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    created = [outcome for _t, outcome in results if outcome.startswith("CREATED")]
    conflicts = [outcome for _t, outcome in results if outcome == "CONFLICT"]
    unexpected = [outcome for _t, outcome in results if outcome.startswith("UNEXPECTED")]
    assert not unexpected, results
    assert len(created) == 1, results
    assert len(conflicts) == contenders - 1, results

    # The winner's dictionary exists, is reopenable, integral and stable.
    winner_vault_id = created[0].split(":", 1)[1]
    reopened = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    try:
        assert reopened.vault_id == winner_vault_id
        reopened.verify(full=True)
    finally:
        reopened.close()
    # No stray databases or sidecars remain.
    assert _sqlite_files(tmp_path) == ["vault/dictionary.sqlite3"]
    assert sidecar_inventory(dictionary.parent) == []


def test_concurrent_process_creation_admits_exactly_one(
    tmp_path: Path,
) -> None:
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    context = multiprocessing.get_context("spawn")
    creation_payload = {
        "dictionary": str(dictionary),
        "source_fingerprint": SOURCE_FP,
        "policy_fingerprint": POLICY_FP,
        "relationship_fingerprint": RELATIONSHIP_FP,
        "dbfbridge_version": DBFBRIDGE_VERSION,
    }
    result_queue = context.Queue()
    processes = [
        context.Process(target=attempt_create, args=(creation_payload, result_queue))
        for _index in range(3)
    ]
    for process in processes:
        process.start()
    outcomes: list[dict[str, str]] = []
    for process in processes:
        process.join(timeout=180)
        assert process.exitcode == 0
        outcomes.append(result_queue.get(timeout=60))

    created = [entry for entry in outcomes if entry["outcome"] == "CREATED"]
    conflicts = [entry for entry in outcomes if entry["outcome"] == "CONFLICT"]
    errors = [entry for entry in outcomes if entry["outcome"] == "ERROR"]
    assert not errors, outcomes
    assert len(created) == 1, outcomes
    assert len(conflicts) == len(processes) - 1, outcomes
    assert conflicts[0]["detail"] == "VAULT_STATE_INVALID", outcomes

    # The losing processes never deleted or replaced the winner's file: the
    # dictionary is intact, integral and reopenable with a stable vault_id.
    winner_hash = file_sha256(dictionary)
    reopened = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    try:
        assert reopened.vault_id == created[0]["detail"]
        reopened.verify(full=True)
    finally:
        reopened.close()
    assert file_sha256(dictionary) == winner_hash
    assert _sqlite_files(tmp_path) == ["vault/dictionary.sqlite3"]
    assert sidecar_inventory(dictionary.parent) == []


def _sqlite_files(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".sqlite", ".sqlite3"}
    )


def test_readers_coexist_without_the_writer_lease(tmp_path: Path) -> None:
    with _open(tmp_path, create=True) as creator:
        with writer_session(creator), creator.transaction():
            creator.begin_operation()
        creator.acquire_writer_lease(new_writer_token())
        # Readers never need the lease: a separate connection reads while the
        # writer authority is durably held.
        reader = _reopen_existing(tmp_path)
        competing = _reopen_existing(tmp_path)
        try:
            stored = reader.operations()
            assert len(stored) == 1
            with pytest.raises(VaultError) as excinfo:
                competing.acquire_writer_lease(new_writer_token())
            assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        finally:
            reader.close()
            competing.close()


def test_writer_lease_requires_a_bounded_token(tmp_path: Path) -> None:
    with _open(tmp_path, create=True) as vault:
        with pytest.raises(ValueError):
            vault.acquire_writer_lease("")
        with pytest.raises(ValueError):
            vault.acquire_writer_lease("has whitespace")
        assert vault.stale_writer_lease() is None


# ---------------------------------------------------------------------------
# Operational failures are never masqueraded as writer conflicts (Defect D)
# ---------------------------------------------------------------------------
class _FailingExecuteConnection:
    """Delegating connection proxy that injects OperationalError on demand."""

    def __init__(self, inner: sqlite3.Connection, fail_when: Any) -> None:
        self._inner = inner
        self._fail_when = fail_when

    def execute(self, sql: str, *parameters: Any) -> object:
        if self._fail_when(sql):
            raise sqlite3.OperationalError("injected storage failure")
        return self._inner.execute(sql, *parameters)

    def close(self) -> None:
        self._inner.close()

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def test_operational_error_is_not_a_writer_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _open(tmp_path, create=True) as creator:
        creator.close()
    vault = _reopen_existing(tmp_path)
    proxy = _FailingExecuteConnection(
        vault._internal_connection(), lambda sql: "UPDATE writer_authority" in sql
    )
    monkeypatch.setattr(vault, "_connection", proxy)
    try:
        with pytest.raises(VaultError) as excinfo:
            vault.acquire_writer_lease(new_writer_token())
        assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
        assert excinfo.value.context.detail_code == "WRITER_LEASE_STORAGE_FAILURE"
        payload = error_boundary_payload(excinfo.value)
        assert "injected storage failure" not in payload
        assert str(tmp_path) not in payload
        assert vault.stale_writer_lease() is None
    finally:
        monkeypatch.undo()
        if not vault.closed:
            vault.close()


def test_release_operational_error_is_not_a_writer_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _open(tmp_path, create=True) as vault:
        token = new_writer_token()
        vault.acquire_writer_lease(token)

        proxy = _FailingExecuteConnection(
            vault._internal_connection(),
            lambda sql: "UPDATE writer_authority" in sql and "owner_token = NULL" in sql,
        )
        monkeypatch.setattr(vault, "_connection", proxy)
        with pytest.raises(VaultError) as excinfo:
            vault.release_writer_lease(token)
        assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
        assert excinfo.value.context.detail_code == "WRITER_LEASE_STORAGE_FAILURE"
        payload = error_boundary_payload(excinfo.value)
        assert "injected storage failure" not in payload
