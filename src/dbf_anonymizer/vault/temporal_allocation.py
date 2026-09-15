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


def _corrupt_state() -> VaultError:
    """Stable typed failure for corrupt persisted temporal state."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code="TEMPORAL_STATE_INVALID"),
    )


def _temporal_identity_material(domain_name: str | None) -> str:
    """The bounded identity material of one temporal domain (REQ-P2-008).

    Dataset-level and explicitly named temporal domains are DIFFERENT
    identity namespaces, so a named domain can never collide with the
    dataset-level default — not even when its name is ``DATASET`` or
    ``DEFAULT``.  The material is value-independent, never contains source
    values or private paths, is stable across reopen and deterministically
    distinct for distinct names BEFORE any hashing.
    """
    if domain_name is None:
        return "TEMPORAL\x00DEFAULT\x00V1"
    return "TEMPORAL\x00NAMED\x00" + domain_name


def _empty_domain() -> MappingError:
    """Stable typed failure for shifting a value outside an EMPTY domain."""
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(operation="transform", detail_code="TEMPORAL_EMPTY_DOMAIN"),
    )


def _persisted_temporal_state(database: VaultDatabase, domain_id: str) -> int | None:
    """The authoritative persisted temporal-state inspector.

    ONE validation point for every consumer (allocation AND recovery):
    returns ``None`` when no state exists at all (a fresh domain), the
    persisted offset when the state is valid, and FAILS CLOSED on any
    corrupt state — a mapping-domain row whose kind is not ``TEMPORAL``, or
    a persisted ``offset_days`` that is not an INTEGER storage class
    (SQLite dynamic typing admits hostile TEXT/REAL/BLOB rows) or is zero.
    Values never reach errors.
    """
    row = database._internal_connection().execute(
        "SELECT d.domain_kind, t.offset_days, typeof(t.offset_days) FROM mapping_domains d "
        "LEFT JOIN temporal_parameters t ON t.domain_id = d.domain_id "
        "WHERE d.domain_id = ?",
        (domain_id,),
    ).fetchone()
    if row is None:
        return None  # no state at all: a fresh domain
    kind, offset = str(row[0]), row[1]
    if kind != VAULT_TABLE_DOMAIN_KIND_TEMPORAL:
        # A temporal identity under TEXT/NUMERIC_KEY/... is corrupt state.
        raise _corrupt_state()
    if offset is None or row[2] != "integer":
        raise _corrupt_state()  # a marked domain without a valid parameter
    if int(offset) == 0:
        raise _corrupt_state()  # zero is never a valid reversible shift
    return int(offset)


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
        self._domain_id = "dom-" + _sha16(_temporal_identity_material(domain_name))
        self._random_below = _random_below if _random_below is not None else secrets.randbelow
        self._min_ordinal: int | None = None
        self._max_ordinal: int = 0
        self._offset: int | None = None
        self._finalized = False
        self._empty = False

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

    def finalize(self) -> int | None:
        """Allocate (or reuse the persisted) domain offset; returns it.

        Lifecycle order (REUSE BEFORE RANDOMNESS): the persisted temporal
        state is inspected FIRST — a valid compatible persisted offset is
        REUSED exactly without touching the CSPRNG; otherwise a fresh offset
        is selected uniformly from the feasible NON-ZERO set and persisted in
        ONE authorized transaction.  The returned offset is authoritative
        only after that unit has COMMITTED.

        An EMPTY domain (every observed D/T occurrence was NULL, or nothing
        was observed at all) is a VALID finalized domain: no artificial
        ``date.min``/``date.max`` constraint is invented and no secret offset
        is needed or created for NULL values — ``finalize`` returns ``None``
        and no temporal parameter exists.
        """
        if self._min_ordinal is None:
            # EMPTY domain: NULL-only or no occurrences at all.  There is no
            # non-NULL value to pseudonymize and therefore no calendar
            # constraint requiring a secret shift.
            self._finalized = True
            self._empty = True
            self._offset = None
            return None
        lower, upper = temporal_kernels.temporal_feasible_interval(
            self._min_ordinal, self._max_ordinal
        )
        count = temporal_kernels.temporal_nonzero_count(lower, upper)
        if count <= 0:
            # Adversarial NON-EMPTY domain spanning both calendar extremes:
            # the only domain-wide feasible offset would be 0 — this is a
            # DIFFERENT constraint set from an EMPTY domain and fails closed.
            raise _only_zero_feasible()
        with self._database.transaction():
            persisted = _persisted_temporal_state(self._database, self._domain_id)
            if persisted is not None:
                offset = persisted  # REUSE: the CSPRNG is never consulted
            else:
                fresh_offset = temporal_kernels.temporal_offset_at(
                    lower, upper, self._random_below(count)
                )
                create_domain(
                    self._database,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
                    domain_id=self._domain_id,
                )
                set_temporal_parameter(self._database, self._domain_id, offset_days=fresh_offset)
                offset = fresh_offset
        if not lower <= offset <= upper:
            raise _offset_incompatible()
        self._offset = offset
        self._finalized = True
        return offset

    def shifted(self, value: object) -> date | datetime | None:
        """The shifted logical value of one occurrence (COLLECT is closed).

        Requires a finalized domain.  NULL stays NULL.  After an EMPTY
        (all-NULL) finalization any NON-NULL temporal value was never part of
        the finalized constraints and fails closed.  DateTime time-of-day is
        never touched.
        """
        if self._empty:
            if value is None:
                return None
            raise _empty_domain()
        if not self._finalized or self._offset is None:
            raise _not_finalized()
        return temporal_kernels.temporal_shift(value, self._offset)

    def recover(self, value: object) -> date | datetime | None:
        """The original logical value of one shifted value (INTERNAL).

        ``recover(None) -> None`` unconditionally: a NULL needs no recovery
        state and no secret offset.  Non-NULL recovery uses the PERSISTED
        vault offset of the domain (deterministic reuse across reopen);
        missing, zero, wrong-kind or otherwise corrupt state fails closed.
        """
        if value is None:
            return None  # the NULL invariant never requires recovery state
        if self._offset is None:
            persisted = _persisted_temporal_state(self._database, self._domain_id)
            if persisted is None:
                raise _recovery_invalid()
            self._offset = persisted
        return temporal_kernels.temporal_recover(value, self._offset)