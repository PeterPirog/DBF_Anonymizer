"""Reversible Date/DateTime shift allocation on the vault foundation.

This module is the REQ-P2-008 boundary binding the PURE temporal kernels of
:mod:`dbf_anonymizer.transforms.temporal` to the protected SQLite vault.  It
introduces NO second temporal table, NO offset sidecar file, NO JSON
recovery manifest and NO public recovery pipeline; the frozen
``temporal_parameters`` rows of the one authoritative vault are the only
place where a temporal offset exists.

Lifecycle (in spirit like the global-text foundation):

    COLLECT -> FINALIZE CONSTRAINTS -> ALLOCATE/PERSIST OFFSET
    -> SHIFT -> REUSE

* COLLECT gathers only the bounded information required to prove a common
  shift: the MIN/MAX observed calendar ordinals (two integers) — never the
  temporal values themselves, never a dataset-sized retention;
* FINALIZE computes the domain-wide feasible integer offset interval
  ``[LOGICAL_MIN_ORDINAL - min_observed, LOGICAL_MAX_ORDINAL - max_observed]``
  and FAILS CLOSED when only offset 0 would fit (a successful temporal
  pseudonymization must actually shift);
* ALLOCATE selects a fresh offset uniformly from the complete feasible
  NON-ZERO set with an OS-backed CSPRNG (``secrets.randbelow`` via the
  private deterministic injection seam for tests) and persists it in ONE
  authorized ``BEGIN IMMEDIATE`` unit; the offset exists only in the vault
  and is considered allocated only after that unit has COMMITTED;
* SHIFT applies the kernel to each logical value (NULL stays NULL;
  DateTime keeps its exact time-of-day);
* REUSE: the same compatible vault reuses the exact persisted offset across
  reopen; a persisted offset incompatible with the finalized constraints
  fails closed and is never silently replaced or remapped.

The domain identity is value-independent and stable across reopen: a
bounded digest of the optional bounded domain NAME (the dataset-level
default is the fixed pseudo-name ``DATASET``), never of source values.
"""

from __future__ import annotations

import secrets
from datetime import date, datetime
from typing import Callable

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError, VaultError
from dbf_anonymizer.transforms import temporal as temporal_kernels
from dbf_anonymizer.vault.mappings import (
    create_domain,
    set_temporal_parameter,
    temporal_parameter,
)
from dbf_anonymizer.vault.schema import VAULT_TABLE_DOMAIN_KIND_TEMPORAL
from dbf_anonymizer.vault.store import VaultDatabase, _sha16

__all__ = ["TemporalShiftDomain"]


def _only_zero_feasible() -> MappingError:
    """Stable typed failure when only offset 0 would fit the whole domain."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(
            operation="transform", detail_code="TEMPORAL_ONLY_ZERO_FEASIBLE"
        ),
    )


def _not_finalized() -> MappingError:
    """Stable typed failure for shifting before the offset was allocated."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(
            operation="transform", detail_code="TEMPORAL_NOT_FINALIZED"
        ),
    )


def _offset_incompatible() -> VaultError:
    """Stable typed failure for an incompatible persisted domain offset."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code="TEMPORAL_OFFSET_INCOMPATIBLE"),
    )


def _recovery_invalid() -> VaultError:
    """Stable typed failure for missing/corrupt temporal recovery state."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code="TEMPORAL_RECOVERY_INVALID"),
    )


class TemporalShiftDomain:
    """One reversible Date/DateTime shift domain (REQ-P2-008 unit).

    The instance collects the bounded calendar-extrema constraint set of ONE
    temporal domain, finalizes the domain-wide feasible non-zero offset set,
    selects a fresh offset with the OS-backed CSPRNG (uniformly, without
    modulo bias, never 0, never source-derived), persists it exclusively in
    the protected vault and shifts logical values through the pure kernels.
    Recovery is the exact inverse shift through the persisted offset.
    """

    def __init__(
        self,
        database: VaultDatabase,
        *,
        domain_name: str | None = None,
        _random_below: Callable[[int], int] | None = None,
    ) -> None:
        from dbf_anonymizer.vault.store import _validate_token

        if domain_name is not None:
            _validate_token(domain_name, field_name="temporal domain name")
        self._database = database
        self._domain_id = "dom-" + _sha16(
            "TEMPORAL\x00" + (domain_name if domain_name is not None else "DATASET")
        )
        self._random_below = _random_below if _random_below is not None else secrets.randbelow
        self._min_ordinal: int | None = None
        self._max_ordinal: int = 0
        self._offset: int | None = None
        self._finalized = False

    @property
    def domain_id(self) -> str:
        """The stable, value-independent temporal domain identifier."""
        return self._domain_id

    def observe(self, value: object) -> None:
        """Collect ONE occurrence's bounded constraint (calendar ordinal).

        Only the extrema are retained — never the temporal values themselves,
        so the collector is O(1) memory per domain.  ``None`` (a NULL date or
        DateTime) contributes no calendar constraint.  Unsupported
        representations fail closed at collection time.
        """
        if self._finalized:
            raise ValueError("observe() requires an unfinalized temporal domain")
        if value is None:
            return  # NULL: no calendar constraint, no ordinal
        ordinal = temporal_kernels.temporal_ordinal(value)
        if self._min_ordinal is None:
            self._min_ordinal = ordinal
            self._max_ordinal = ordinal
            return
        if ordinal < self._min_ordinal:
            self._min_ordinal = ordinal
        if ordinal > self._max_ordinal:
            self._max_ordinal = ordinal

    def finalize(self) -> int:
        """Allocate (or validate the persisted) domain offset; returns it.

        The domain-wide feasible interval is derived from the collected
        extrema; a fresh offset is selected uniformly from the feasible
        NON-ZERO set (an all-zero-feasible domain fails closed) and is
        persisted in ONE authorized transaction.  The returned offset is
        authoritative only after that unit has COMMITTED; a compatible
        persisted offset from an earlier operation is REUSED unchanged, an
        incompatible one fails closed.
        """
        min_observed = self._min_ordinal
        if min_observed is None:
            # A domain with no non-NULL temporal occurrence still receives a
            # valid non-zero offset over the FULL logical calendar range.
            min_observed = temporal_kernels.LOGICAL_MIN_ORDINAL
            max_observed = temporal_kernels.LOGICAL_MAX_ORDINAL
        else:
            max_observed = self._max_ordinal
        lower, upper = temporal_kernels.temporal_feasible_interval(
            min_observed, max_observed
        )
        count = temporal_kernels.temporal_nonzero_count(lower, upper)
        if count <= 0:
            # Adversarial domain spanning both calendar extremes: the only
            # domain-wide feasible offset would be 0 — never silently used.
            raise _only_zero_feasible()
        fresh_offset = temporal_kernels.temporal_offset_at(
            lower, upper, self._random_below(count)
        )
        with self._database.transaction():
            existing = temporal_parameter(self._database, self._domain_id)
            if existing is None:
                create_domain(
                    self._database,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
                    domain_id=self._domain_id,
                )
                set_temporal_parameter(self._database, self._domain_id, offset_days=fresh_offset)
                offset = fresh_offset
            else:
                offset = int(existing)
        if not lower <= offset <= upper:
            raise _offset_incompatible()
        self._offset = offset
        self._finalized = True
        return offset
    def shifted(self, value: object) -> date | datetime | None:
        """The shifted logical value of one occurrence (COLLECT is closed).

        Requires a finalized (committed and persisted) domain offset; NULL
        stays NULL; DateTime time-of-day is never touched.
        """
        if not self._finalized or self._offset is None:
            raise _not_finalized()
        return temporal_kernels.temporal_shift(value, self._offset)

    def recover(self, value: object) -> date | datetime | None:
        """The original logical value of one shifted value (INTERNAL).

        The recovery always uses the PERSISTED vault offset of the domain
        (deterministic reuse across reopen); missing recovery state fails
        closed.  ``None`` needs no recovery row and stays ``None``.
        """
        if self._offset is None:
            persisted = temporal_parameter(self._database, self._domain_id)
            if persisted is None:
                raise _recovery_invalid()
            self._offset = int(persisted)
        return temporal_kernels.temporal_recover(value, self._offset)