"""REQ-P2-003 — single logical writer authority and concurrent-writer evidence.

The authority is durable SQLite state (the ``writer_authority`` lease row of
the same dictionary), not an in-process lock: competing connections — same
process or separate threads — acquire it through ``BEGIN IMMEDIATE`` and the
conditional update admits exactly one writer. Deterministic synchronization
(barriers) is used; there is NO timing/sleep-based correctness evidence, and
the tests are Windows-CI safe.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from dbf_anonymizer import ErrorCode, VaultError
from dbf_anonymizer.vault import VaultDatabase, new_writer_token

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


def test_first_writer_acquires_and_second_is_rejected(tmp_path: Path) -> None:
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    with _open(tmp_path, create=True) as creator:
        with creator.transaction():
            creator.begin_operation()
    first = VaultDatabase.open(dictionary)
    second = VaultDatabase.open(dictionary)
    try:
        token_a = new_writer_token()
        token_b = new_writer_token()
        assert first.acquire_writer_lease(token_a) == 1
        # The competing connection fails deterministically with a typed error.
        with pytest.raises(VaultError) as excinfo:
            second.acquire_writer_lease(token_b)
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert excinfo.value.context.detail_code == "WRITER_LEASE_HELD"
        # The authority remains with the first writer (durable, shared state).
        assert first.stale_writer_lease() == token_a
        assert second.stale_writer_lease() == token_a

        # Release returns authority cleanly; the next writer acquires it.
        first.release_writer_lease(token_a)
        assert second.acquire_writer_lease(token_b) == 2
        with pytest.raises(VaultError) as excinfo:
            first.acquire_writer_lease(token_a)
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
    finally:
        first.close()
        second.close()


def test_non_holder_cannot_release_the_authority(tmp_path: Path) -> None:
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    with _open(tmp_path, create=True) as creator:
        with creator.transaction():
            creator.begin_operation()
    holder = VaultDatabase.open(dictionary)
    stranger = VaultDatabase.open(dictionary)
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
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    crashed_token = new_writer_token()
    with _open(tmp_path, create=True) as creator:
        creator.acquire_writer_lease(crashed_token)
    # Simulated crash: the first connection is gone; a fresh connection sees
    # the stale lease and must NOT acquire authority silently.
    survivor = VaultDatabase.open(dictionary)
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
        database = VaultDatabase.open(dictionary)
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
    check = VaultDatabase.open(dictionary)
    try:
        assert check.stale_writer_lease() == acquired[0]
        assert check.writer_acquire_tick() == 1
    finally:
        check.release_writer_lease(acquired[0])
        check.close()


def test_readers_coexist_without_the_writer_lease(tmp_path: Path) -> None:
    dictionary = tmp_path / "vault" / "dictionary.sqlite3"
    with _open(tmp_path, create=True) as creator:
        with creator.transaction():
            creator.begin_operation()
        creator.acquire_writer_lease(new_writer_token())
        # Readers never need the lease: a separate connection reads while the
        # writer authority is durably held.
        reader = VaultDatabase.open(dictionary)
        competing = VaultDatabase.open(dictionary)
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