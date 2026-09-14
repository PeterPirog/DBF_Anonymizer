"""Spawn-mode multiprocessing worker for the writer-authority evidence.

This module exists so the REQ-P2-003 process-level test can run a REAL second
process on Windows (spawn) without the child needing to import a pytest test
module. The worker never leaks raw exception text: outcomes are reported as
typed code names only.
"""

from __future__ import annotations

from multiprocessing.queues import Queue
from pathlib import Path


def attempt_acquire(payload: dict[str, str], results: Queue) -> None:
    """Try once to acquire the vault writer lease; report a typed outcome."""
    from dbf_anonymizer import ErrorCode, VaultError
    from dbf_anonymizer.vault import VaultDatabase

    try:
        vault = VaultDatabase.open(
            Path(payload["dictionary"]),
            expected_source_fingerprint=payload["source_fingerprint"],
            expected_policy_fingerprint=payload["policy_fingerprint"],
            expected_relationship_fingerprint=payload["relationship_fingerprint"],
        )
    except Exception as error:  # noqa: BLE001 - typed outcome only
        results.put(
            {
                "outcome": "ERROR",
                "detail": type(error).__name__,
            }
        )
        return
    try:
        vault.acquire_writer_lease(payload["token"])
        results.put({"outcome": "ACQUIRED", "detail": ""})
    except VaultError as error:
        results.put(
            {
                "outcome": "CONFLICT"
                if error.code is ErrorCode.VAULT_WRITER_CONFLICT
                else "ERROR",
                "detail": error.code.value,
            }
        )
    except Exception as error:  # noqa: BLE001 - typed name only
        results.put({"outcome": "ERROR", "detail": type(error).__name__})
    finally:
        vault.close()


def attempt_create(payload: dict[str, str], results: Queue) -> None:
    """Try once to CREATE the dictionary; report a typed outcome.

    The losing creator must fail with the typed ``VAULT_STATE_INVALID``
    (``ALREADY_EXISTS``) classification and must never touch the winner's
    file (no open, truncate, journal conversion or unlink).
    """
    from dbf_anonymizer import ErrorCode, VaultError
    from dbf_anonymizer.vault import VaultDatabase

    try:
        vault = VaultDatabase.open(
            Path(payload["dictionary"]),
            create=True,
            expected_source_fingerprint=payload["source_fingerprint"],
            expected_policy_fingerprint=payload["policy_fingerprint"],
            expected_relationship_fingerprint=payload["relationship_fingerprint"],
            dbfbridge_version=payload["dbfbridge_version"],
        )
    except VaultError as error:
        results.put(
            {
                "outcome": "CONFLICT"
                if error.code is ErrorCode.VAULT_STATE_INVALID
                else "ERROR",
                "detail": error.code.value,
            }
        )
        return
    except Exception as error:  # noqa: BLE001 - typed name only
        results.put({"outcome": "ERROR", "detail": type(error).__name__})
        return
    try:
        results.put({"outcome": "CREATED", "detail": vault.vault_id})
    finally:
        vault.close()
