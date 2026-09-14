"""Shared helpers for the Phase-2 vault evidence tests."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

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
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def sidecar_inventory(directory: Path) -> list[str]:
    """Names of all SQLite sidecar/rollforward artifacts in *directory*."""
    return sorted(
        name
        for name in os.listdir(directory)
        if name.endswith(("-wal", "-shm", "-journal"))
    )


def vault_file_sha256(vault: VaultDatabase) -> str:
    """SHA-256 of the dictionary file behind *vault* (non-mutating check)."""
    import hashlib

    return hashlib.sha256(vault.path.read_bytes()).hexdigest()


def error_boundary_payload(error: BaseException) -> str:
    """The full public error boundary: str + repr + to_dict serialization."""
    from dbf_anonymizer.errors import AnonymizerError

    if isinstance(error, AnonymizerError):
        serialized = json.dumps(error.to_dict(), sort_keys=True)
    else:
        serialized = ""
    return f"{str(error)}|{repr(error)}|{serialized}"
