"""Secure global text mapping allocation (REQ-P2-004/005/006).

This module implements the INTERNAL pseudonymization foundation for the
default ONE global text mapping domain of a dataset. It is a consumer of the
pure shared text-domain model (:mod:`dbf_anonymizer.transforms.text`) and of
the existing SQLite vault storage foundation (:mod:`dbf_anonymizer.vault`);
it adds NO second mapping database, NO raw writable SQLite surface and NO new
schema.

Lifecycle (immutable architectural property — collect, finalize, allocate,
reuse):

* COLLECT — :meth:`GlobalTextDomainMapping.observe` records every occurrence
  constraint ``(encoding, logical byte width)`` of an exact non-empty decoded
  original. NULL and ``""`` are never observed and never mapped (they stay
  preserved identities, never normal sensitive mapping rows).
* FINALIZE — :meth:`GlobalTextDomainMapping.finalize` freezes the constraint
  set: the strictest width per original is the minimum over ALL occurrences
  (encounter order never changes the semantics), the safe alphabet is proven
  for the union of participating encodings, and every persisted mapping of
  the domain is validated against the finalized constraints. Allocation
  before finalization is impossible, and later observation is refused.
* ALLOCATE/PERSIST — :meth:`GlobalTextDomainMapping.pseudonym_for` allocates
  one CSPRNG pseudonym per unallocated original and persists it inside one
  authorized :class:`~dbf_anonymizer.vault.transactions.VaultTransaction`
  (the durable single-writer lease is verified inside ``BEGIN IMMEDIATE``).
* REUSE — the same original always reuses its persisted mapping (same vault
  reopen, same field, same table, any directory); a reused mapping is
  revalidated against the finalized constraints and is NEVER silently
  remapped.

Security properties (proven by the dedicated evidence tests):

* production randomness comes exclusively from the OS CSPRNG
  (``secrets.randbelow``); the private ``_random_below`` keyword seam exists
  ONLY for deterministic tests and never becomes public API, serialized
  configuration, recovery metadata or transfer data;
* pseudonyms are never predictably derived from the original value, a public
  salt, a sequence counter, ``random.Random`` or any reversible arithmetic;
* collision handling is TRUTHFUL: the admissible token space, the occupied
  tokens and the self-excluded token are known exactly, so a random
  collision is separated from true domain exhaustion; a bounded CSPRNG probe
  phase is followed by an exact uniform completion strategy over the
  remaining free tokens — the loop is finite by construction, no arbitrary
  attempt budget raises exhaustion and no unbounded retry loop exists;
* a candidate equal to the sensitive original is forbidden and counts
  against the effective available capacity;
* failures are stable typed application errors; public errors, logs and
  serialized payloads never contain the original value, the pseudonym, SQL
  text, raw SQLite messages or private paths.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable, Iterable

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError
from dbf_anonymizer.transforms.text import (
    candidate_alphabet,
    is_safe_token,
    max_encoded_byte_length,
    reduced_strictest,
    token_at,
    token_index,
    token_space,
)
from dbf_anonymizer.vault.mappings import (
    VAULT_TABLE_DOMAIN_KIND_TEXT,
    add_text_mapping,
    create_domain,
    get_text_pseudonym,
    mapping_domains,
    text_mapping_rows,
)
from dbf_anonymizer.vault.store import VaultDatabase

__all__ = [
    "GLOBAL_TEXT_DOMAIN_ID",
    "GLOBAL_TEXT_PROBE_BUDGET",
    "GlobalTextDomainMapping",
]

#: Bounded CSPRNG probe budget (PHASE R). A documented PERFORMANCE bound for
#: sparse domains — NEVER an exhaustion decision: when the budget runs out,
#: the exact deterministic completion phase allocates with certainty.
GLOBAL_TEXT_PROBE_BUDGET = 64

_DETAIL_NO_SAFE_ALPHABET = "GLOBAL_TEXT_NO_SAFE_ALPHABET"
_DETAIL_WIDTH_INFEASIBLE = "GLOBAL_TEXT_WIDTH_INFEASIBLE"
_DETAIL_DOMAIN_EXHAUSTED = "GLOBAL_TEXT_DOMAIN_EXHAUSTED"
_DETAIL_PERSISTED_PREFIX = "GLOBAL_TEXT_PERSISTED"
_DETAIL_REUSED_PREFIX = "GLOBAL_TEXT_REUSED"


def _global_text_domain_id() -> str:
    """The stable privacy-safe identity of the default global text domain.

    A bounded digest of a fixed, value-independent constant: reopening the
    vault (or meeting the same original in any table, field or directory)
    resolves to the SAME domain, and no source value, path or salt is
    involved. Distinct originals never influence the domain identity.
    """
    digest = hashlib.sha256(
        b"dbf_anonymizer/REQ-P2-005/GLOBAL_TEXT_DOMAIN/v1"
    ).hexdigest()[:16]
    return "dom-" + digest


#: Stable domain identity of the ONE default global text mapping domain.
GLOBAL_TEXT_DOMAIN_ID = _global_text_domain_id()


def _mapping_failure(code: ErrorCode, detail_code: str) -> MappingError:
    """Privacy-safe, registry-controlled mapping failure (no values exposed)."""
    return MappingError(
        code,
        context=ErrorContext(operation="mapping", detail_code=detail_code),
    )


def _jth_free_index(total: int, blocked: Iterable[int], j: int) -> int:
    """The index of the ``j``-th free token in ``[0, total)`` (exact, finite).

    ``blocked`` must hold unique indices below *total*. Walking the sorted
    blocked indices costs ``O(len(blocked))`` — the exact completion
    strategy of the allocation algorithm when random probes become
    inefficient; it never scans the (possibly astronomically large) free
    token space itself and is finite by construction.
    """
    previous = -1
    remaining = j
    for index in sorted(blocked):
        gap = index - previous - 1
        if remaining < gap:
            return previous + 1 + remaining
        remaining -= gap
        previous = index
    return previous + 1 + remaining


class GlobalTextDomainMapping:
    """The one global text mapping domain of a dataset (REQ-P2-004/005/006).

    The instance binds ONE existing :class:`~dbf_anonymizer.vault.VaultDatabase`
    (the dataset's single authoritative dictionary) to the stable global
    text domain identity. It is NOT thread-safe and must not be shared
    between threads; the durable single-writer lease of the vault
    serializes all allocation. One writer should use one instance at a time;
    the database-level bijection indexes remain the hard guarantee.

    The optional keyword-only ``_random_below`` parameter is the PRIVATE
    randomness injection seam for deterministic tests. It must never become
    public API, serialized configuration, recovery metadata or transfer
    data; production always uses the OS CSPRNG (``secrets.randbelow``).
    """

    def __init__(
        self,
        database: VaultDatabase,
        *,
        domain_id: str = GLOBAL_TEXT_DOMAIN_ID,
        _random_below: Callable[[int], int] | None = None,
    ) -> None:
        self._database = database
        self._domain_id = domain_id
        self._random_below: Callable[[int], int] = _random_below or secrets.randbelow
        self._strictest: dict[str, int] = {}
        self._encodings: set[str] = set()
        self._finalized = False
        self._alphabet: str | None = None
        self._base = 0
        #: Occupied pseudonyms of the domain (validated safe tokens only),
        #: mapped to their character length (equal to their encoded byte
        #: length under every participating encoding for safe tokens).
        self._used: dict[str, int] = {}

    # -- state -----------------------------------------------------------------
    @property
    def finalized(self) -> bool:
        """True once the constraint set is frozen (allocation is possible)."""
        return self._finalized

    @property
    def domain_id(self) -> str:
        """The stable global text domain identity of this mapping."""
        return self._domain_id

    @property
    def alphabet(self) -> str | None:
        """The proven safe alphabet, or ``None`` before finalization."""
        return self._alphabet

    @property
    def observed_originals(self) -> tuple[str, ...]:
        """The exact collected originals in deterministic (sorted) order."""
        return tuple(sorted(self._strictest))

    def strictest_width_of(self, original: str) -> int | None:
        """The finalized strictest logical byte width of *original*.

        ``None`` when the original was not observed in this dataset scan.
        """
        return self._strictest.get(original)

    # -- COLLECT -----------------------------------------------------------------
    def observe(self, original: str, *, encoding: str, byte_width: int) -> None:
        """Record one occurrence constraint of an exact non-empty original.

        Constraint collection is closed after :meth:`finalize` (the
        lifecycle makes pre-finalization allocation and post-finalization
        observation impossible). ``original`` must be the EXACT decoded
        value: no normalization of any kind is applied, so Varchar
        significant trailing spaces stay identity-significant. NULL and the
        empty string are preserved by identity and must never be observed
        (they never create a normal sensitive mapping row).
        """
        if self._finalized:
            raise ValueError("constraint collection is closed after finalize")
        if not isinstance(original, str):
            raise TypeError("original must be a decoded str value")
        if original == "":
            raise ValueError("NULL and empty values stay preserved and are not mapped")
        if not isinstance(encoding, str) or not encoding:
            raise ValueError("encoding must be a non-empty encoding name")
        if isinstance(byte_width, bool) or not isinstance(byte_width, int):
            raise TypeError("byte_width must be an int")
        if byte_width < 0:
            raise ValueError("byte_width must be non-negative")
        previous = self._strictest.get(original)
        self._strictest[original] = reduced_strictest(previous, byte_width)
        self._encodings.add(encoding)

    # -- FINALIZE ------------------------------------------------------------------
    def finalize(self) -> None:
        """Freeze the constraint set and prepare allocation.

        Computes the proven safe alphabet for the union of participating
        encodings, ensures the global text domain row exists in the vault
        (idempotent; requires the writer lease only when it must be
        created), loads every persisted mapping of the domain and validates
        each one against the finalized constraints. Incompatible persisted
        state fails CLOSED with a stable typed error — a persisted original
        is never silently remapped. Calling :meth:`finalize` twice is
        refused; observation is impossible afterwards.
        """
        if self._finalized:
            raise ValueError("constraint set is already finalized")
        alphabet = candidate_alphabet(frozenset(self._encodings))
        if not alphabet:
            # The participating encodings cannot be PROVEN single-byte safe
            # in the live codec registry (unknown codec names, or code pages
            # never established by the public dependency): fail closed
            # instead of guessing — no codec aliases are ever invented here.
            raise _mapping_failure(
                ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE, _DETAIL_NO_SAFE_ALPHABET
            )
        self._alphabet = alphabet
        self._base = len(alphabet)
        for width in self._strictest.values():
            if width <= 0:
                # A zero-width field cannot hold any pseudonym: an impossible
                # constraint, independent of occupancy — fail closed here.
                raise _mapping_failure(
                    ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE, _DETAIL_WIDTH_INFEASIBLE
                )
        self._ensure_domain()
        self._load_and_validate_persisted()
        self._finalized = True

    def _ensure_domain(self) -> None:
        """Create the global text domain row when missing (idempotent)."""
        if _has_domain(self._database, self._domain_id):
            return
        with self._database.transaction():
            # Re-checked inside the transactional commit boundary.
            if not _has_domain(self._database, self._domain_id):
                create_domain(
                    self._database,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=self._domain_id,
                )

    def _load_and_validate_persisted(self) -> None:
        """Load persisted mappings and validate them against this finalization.

        A persisted mapping whose pseudonym is not a safe token, equals its
        original, or no longer fits the strictest width of an original that
        participates in this dataset run fails CLOSED with a stable typed
        error. A persisted original is NEVER silently remapped.
        """
        for original, pseudonym, _stored_length in text_mapping_rows(
            self._database, self._domain_id
        ):
            self._validate_pseudonym(
                original, pseudonym, self._strictest.get(original), _DETAIL_PERSISTED_PREFIX
            )
            self._used[pseudonym] = len(pseudonym)

    # -- ALLOCATE / REUSE -----------------------------------------------------------
    def pseudonym_for(self, original: str) -> str:
        """The persisted pseudonym of *original*, allocating it when needed.

        Reuse: the persisted mapping is returned unchanged after
        revalidation against the finalized constraint set — the generator is
        not called and the mapping is never remapped. Allocation: a fresh
        CSPRNG pseudonym is persisted inside one authorized vault
        transaction (deterministic commit boundary; the single-writer lease
        must be held by the vault instance).
        """
        if not self._finalized:
            raise ValueError(
                "pseudonym allocation requires the finalized constraint set"
            )
        if not isinstance(original, str):
            raise TypeError("original must be a decoded str value")
        if original == "":
            raise ValueError("NULL and empty values stay preserved and are not mapped")
        width = self._strictest.get(original)
        if width is None:
            raise ValueError(
                "original was not observed in this dataset scan; "
                "every occurrence must be collected before finalize"
            )
        existing = get_text_pseudonym(self._database, self._domain_id, original)
        if existing is not None:
            self._validate_pseudonym(original, existing, width, _DETAIL_REUSED_PREFIX)
            return existing
        return self._allocate(original, width)

    def _allocate(self, original: str, width: int) -> str:
        """Persist one fresh CSPRNG mapping inside one authorized transaction.

        Occupancy is re-verified against the persisted vault state inside
        every allocation transaction (an ``O(persisted rows)`` reconciliation
        of this storage foundation; bounded-memory allocation batching
        remains REQ-P4-002 scope).
        """
        with self._database.transaction():
            # Occupancy is reconciled with the PERSISTED vault state inside
            # the commit boundary: rows committed by a previous operation of
            # the same writer (crash resume, seed completion) are part of the
            # exact occupied-token bookkeeping — exhaustion accounting is
            # never computed from stale state.
            self._sync_used()
            fresh = get_text_pseudonym(self._database, self._domain_id, original)
            if fresh is not None:
                self._validate_pseudonym(
                    original, fresh, width, _DETAIL_REUSED_PREFIX
                )
                return fresh
            candidate = self._select_candidate(original, width)
            length = max_encoded_byte_length(candidate, self._encodings)
            if length is None:  # pragma: no cover - safe tokens are provable
                raise _mapping_failure(
                    ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE, _DETAIL_NO_SAFE_ALPHABET
                )
            add_text_mapping(
                self._database,
                self._domain_id,
                original,
                candidate,
                logical_byte_length=length,
            )
            self._used[candidate] = len(candidate)
            return candidate

    def _sync_used(self) -> None:
        """Reconcile occupied-token bookkeeping with the persisted vault rows.

        Every persisted mapping of the domain is revalidated against the
        finalized constraints and registered as occupied. This makes the
        exact exhaustion accounting truthful even when rows were persisted
        outside this instance's own allocation stream (e.g. a previous
        operation of the same writer).
        """
        for original, pseudonym, _stored_length in text_mapping_rows(
            self._database, self._domain_id
        ):
            self._validate_pseudonym(
                original, pseudonym, self._strictest.get(original), _DETAIL_PERSISTED_PREFIX
            )
            self._used[pseudonym] = len(pseudonym)

    def _select_candidate(self, original: str, width: int) -> str:
        """Truthful collision-safe CSPRNG selection of one free token.

        The admissible token space (lengths ``1..width``), the occupied
        tokens and the self-excluded token are known EXACTLY, so true domain
        exhaustion is distinguished from a random collision: exhaustion is
        raised only when no admissible unused candidate actually exists.
        PHASE R probes the CSPRNG within a documented budget (a performance
        bound, never an exhaustion decision); PHASE C completes
        deterministically by exact uniform choice among the remaining free
        tokens, which guarantees finite completion without sequence/counter
        semantics and without deriving anything from the original.
        """
        assert self._alphabet is not None
        total = token_space(width, self._base)
        blocked: set[int] = set()
        for pseudonym, length in self._used.items():
            if length <= width:
                blocked.add(token_index(pseudonym, self._alphabet))
        if is_safe_token(original, self._alphabet) and len(original) <= width:
            # Self-exclusion counts against the effective available capacity.
            blocked.add(token_index(original, self._alphabet))
        available = total - len(blocked)
        if available <= 0:
            raise _mapping_failure(
                ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_DOMAIN_EXHAUSTED
            )
        for _ in range(GLOBAL_TEXT_PROBE_BUDGET):
            candidate = token_at(self._random_below(total), width, self._alphabet)
            if candidate == original or candidate in self._used:
                continue  # random collision or forbidden self-candidate
            return candidate
        return token_at(
            _jth_free_index(total, blocked, self._random_below(available)),
            width,
            self._alphabet,
        )

    # -- persisted/reused validation ---------------------------------------------------
    def _validate_pseudonym(
        self, original: str, pseudonym: str, width: int | None, prefix: str
    ) -> None:
        """Fail-closed validation of a persisted or reused mapping.

        ``prefix`` selects the stable detail-code family of the failure; the
        original value and the pseudonym are never part of any error.
        """
        assert self._alphabet is not None
        if not is_safe_token(pseudonym, self._alphabet):
            raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, prefix + "_UNSAFE")
        if pseudonym == original:
            raise _mapping_failure(
                ErrorCode.MAPPING_CONFLICT, prefix + "_SELF_MAPPING"
            )
        length = max_encoded_byte_length(pseudonym, self._encodings)
        if length is None or length != len(pseudonym):
            raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, prefix + "_UNSAFE")
        if width is not None and length > width:
            # A later stricter constraint may never silently invalidate an
            # existing mapping: fail closed, keep the persisted mapping.
            raise _mapping_failure(
                ErrorCode.MAPPING_CONFLICT, prefix + "_INCOMPATIBLE"
            )


def _has_domain(database: VaultDatabase, domain_id: str) -> bool:
    return any(
        row["domain_id"] == domain_id for row in mapping_domains(database)
    )