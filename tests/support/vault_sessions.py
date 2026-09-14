"""Shared helpers for the Phase-2 vault evidence tests."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from dbf_anonymizer.errors import AnonymizerError
from dbf_anonymizer.vault import VaultDatabase, new_writer_token


@contextmanager
def writer_session(vault: VaultDatabase) -> Iterator[str]:
    """Acquire the durable writer lease for *vault* and release it after use.

    Every ordinary vault mutation must run inside an authorized transaction,
    which requires the lease; this helper keeps the evidence tests explicit
    and deterministic.
    """
    token = new_writer_token()
    vault.acquire_writer_lease(token)
    try:
        yield token
    finally:
        vault.release_writer_lease(token)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sidecar_inventory(directory: Path) -> list[str]:
    """Names of all SQLite sidecar/rollforward artifacts in *directory*."""
    return sorted(
        name
        for name in os.listdir(directory)
        if name.endswith(("-wal", "-shm", "-journal"))
    )


def error_boundary_payload(error: BaseException) -> str:
    """The full public error boundary: str + repr + to_dict serialization."""
    if isinstance(error, AnonymizerError):
        serialized = json.dumps(error.to_dict(), sort_keys=True)
    else:
        serialized = ""
    return f"{str(error)}|{repr(error)}|{serialized}"


class FailingExecuteConnection:
    """Delegating connection proxy that injects sqlite3.Error on demand.

    Used as a deterministic failure-injection seam: replace
    ``vault._connection`` with this proxy; ``execute`` raises the configured
    exception when *fail_when* matches the SQL text; everything else is
    delegated to the real connection.
    """

    def __init__(
        self,
        inner: sqlite3.Connection,
        fail_when: Callable[[str], bool],
        exception: type[Exception] | None = None,
    ) -> None:
        self._inner = inner
        self._fail_when = fail_when
        self._exception = exception or sqlite3.OperationalError

    def execute(self, sql: str, *parameters: Any) -> object:
        if self._fail_when(sql):
            raise self._exception("injected storage failure")
        return self._inner.execute(sql, *parameters)

    def close(self) -> None:
        self._inner.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def install_failing_execute(
    vault: VaultDatabase,
    fail_when: Callable[[str], bool],
    monkeypatch: Any = None,
    exception: type[Exception] | None = None,
) -> FailingExecuteConnection:
    """Wrap the vault's connection so matching statements fail (test seam)."""
    proxy = FailingExecuteConnection(
        vault._internal_connection(), fail_when, exception
    )
    if monkeypatch is not None:
        monkeypatch.setattr(vault, "_connection", proxy)
    return proxy
