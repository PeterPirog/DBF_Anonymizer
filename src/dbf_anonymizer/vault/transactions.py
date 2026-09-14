"""Explicit, deterministic, fail-closed transaction boundary (REQ-P2-003).

Vault connections are opened with ``isolation_level=None`` so Python's sqlite3
driver never performs hidden autocommit bookkeeping: every multi-step vault
mutation runs inside an explicit :class:`VaultTransaction`, which issues
``BEGIN IMMEDIATE`` on entry and exactly one of ``COMMIT`` (success) or
``ROLLBACK`` (any exception) on exit.

Every transaction-control failure has a deterministic, typed, privacy-safe
outcome (classified by exception TYPE only — SQLite text is never parsed or
propagated):

* ``BEGIN IMMEDIATE`` failure  -> ``VAULT_UNAVAILABLE`` /
  ``TRANSACTION_BEGIN_FAILED`` (no transaction was opened);
* authority-check failure after begin -> the unit rolls itself back; a failing
  rollback poisons the owner (``TRANSACTION_ROLLBACK_FAILED``);
* ``COMMIT`` failure -> a best-effort rollback is attempted and the owner is
  POISONED (``TRANSACTION_COMMIT_FAILED``): the connection state can no longer
  be trusted, so it must not accept further ordinary operations;
* ``ROLLBACK`` failure while an operation exception is in flight -> the
  ORIGINAL exception keeps propagating (deterministic Python-3.10-compatible
  policy) and the rollback failure is recorded through ``on_poison`` — never
  silently lost;
* a poisoned owner refuses every further ordinary operation until it is
  closed and reopened (which revalidates the whole vault from scratch).

A failure in the middle of a sequence of dependent inserts therefore rolls the
whole intended transaction back — a closed/crashed/interrupted transaction
leaves no partially committed logical object (proven by the crash-injection
tests that re-open the database and check the committed state).
"""

from __future__ import annotations

import sqlite3
from types import TracebackType
from typing import Callable

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VaultError

__all__ = ["VaultTransaction"]


def _transaction_failure(code: ErrorCode, detail_code: str) -> VaultError:
    """Privacy-safe, registry-controlled transaction-control failure."""
    return VaultError(
        code,
        context=ErrorContext(operation="vault", detail_code=detail_code),
    )


class VaultTransaction:
    """One ``BEGIN IMMEDIATE`` .. ``COMMIT``/``ROLLBACK`` unit of vault work.

    The transaction is deterministic: entering always begins (never relying on
    implicit transaction promotion), a clean exit always commits exactly once,
    and any exception always rolls back before the original exception is
    re-raised. Re-entrant/nested use is refused rather than silently merged.

    ``on_begin`` (used by the store's authorized transaction path) runs INSIDE
    the ``BEGIN IMMEDIATE`` lock right after begin: when it raises, the unit
    rolls back and the original failure propagates — so an authority check can
    never be bypassed by a race between the check and the physical lock.

    ``on_poison`` is called exactly once when a control failure leaves the
    connection state uncertain (failed COMMIT or failed ROLLBACK): the owner
    must then refuse all further ordinary operations until closed/reopened.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        on_begin: Callable[[], None] | None = None,
        on_poison: Callable[[VaultError], None] | None = None,
    ) -> None:
        self._connection = connection
        self._on_begin = on_begin
        self._on_poison = on_poison
        self._active = False

    @property
    def active(self) -> bool:
        """True while the unit is between __enter__ and __exit__."""
        return self._active

    def __enter__(self) -> "VaultTransaction":
        if self._active:
            raise ValueError("vault transaction already active")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise _transaction_failure(
                ErrorCode.VAULT_UNAVAILABLE, "TRANSACTION_BEGIN_FAILED"
            ) from None
        self._active = True
        if self._on_begin is not None:
            try:
                self._on_begin()
            except BaseException:
                # A with-statement never runs __exit__ when __enter__ raises;
                # the unit therefore rolls itself back here so a failed
                # authority check can never leave an open write transaction.
                self._active = False
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    if self._on_poison is not None:
                        self._on_poison(
                            _transaction_failure(
                                ErrorCode.VAULT_STATE_INVALID,
                                "TRANSACTION_ROLLBACK_FAILED",
                            )
                        )
                raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if not self._active:
            return
        self._active = False
        if exc_type is None:
            try:
                self._connection.execute("COMMIT")
            except sqlite3.Error:
                # A failed commit leaves the transactional state uncertain:
                # fail closed — best-effort discard, then poison the owner.
                self._best_effort_rollback()
                if self._on_poison is not None:
                    self._on_poison(
                        _transaction_failure(
                            ErrorCode.VAULT_UNAVAILABLE, "TRANSACTION_COMMIT_FAILED"
                        )
                    )
                raise _transaction_failure(
                    ErrorCode.VAULT_UNAVAILABLE, "TRANSACTION_COMMIT_FAILED"
                ) from None
            return
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            # The operation exception keeps propagating (never replaced), but
            # the rollback failure is not silently lost: the owner is poisoned
            # because the connection state can no longer be trusted.
            self._active = False
            if self._on_poison is not None:
                self._on_poison(
                    _transaction_failure(
                        ErrorCode.VAULT_STATE_INVALID, "TRANSACTION_ROLLBACK_FAILED"
                    )
                )

    def _best_effort_rollback(self) -> None:
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
