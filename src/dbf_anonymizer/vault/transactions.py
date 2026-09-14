"""Explicit, deterministic transaction boundary for the vault (REQ-P2-003).

Vault connections are opened with ``isolation_level=None`` so Python's sqlite3
driver never performs hidden autocommit bookkeeping: every multi-step vault
mutation runs inside an explicit :class:`VaultTransaction`, which issues
``BEGIN IMMEDIATE`` on entry and exactly one of ``COMMIT`` (success) or
``ROLLBACK`` (any exception) on exit.

A failure in the middle of a sequence of dependent inserts therefore rolls the
whole intended transaction back — a closed/crashed/interrupted transaction
leaves no partially committed logical object (proven by the crash-injection
tests that re-open the database and check the committed state).
"""

from __future__ import annotations

import sqlite3
from types import TracebackType
from typing import Callable

__all__ = ["VaultTransaction"]


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
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        on_begin: Callable[[], None] | None = None,
    ) -> None:
        self._connection = connection
        self._on_begin = on_begin
        self._active = False

    @property
    def active(self) -> bool:
        """True while the unit is between __enter__ and __exit__."""
        return self._active

    def __enter__(self) -> "VaultTransaction":
        if self._active:
            raise ValueError("vault transaction already active")
        self._connection.execute("BEGIN IMMEDIATE")
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
                    pass
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
            self._connection.execute("COMMIT")
            return
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            # The connection is already broken; SQLite discards the uncommitted
            # work when the connection closes, so the rollback intent holds.
            pass
