"""CSPRNG-backed numeric key-domain allocation (REQ-P3-005).

The reversible-bijective pseudonymization service for explicitly declared
numeric key domains, built EXCLUSIVELY on the existing vault schema 1.0
foundations (:data:`~dbf_anonymizer.vault.schema.VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY`,
the ``numeric_key_mappings`` table and its named bijection indexes) — it adds
NO second SQLite database, NO JSON recovery mappings, NO per-table mapping
files and NO schema change.

Lifecycle (the numeric counterpart of the global text domain):

* COLLECT — :meth:`NumericKeyDomainMapping.observe_original` records every
  exact distinct ORIGINAL key value of the relation; NULL is never observed
  and never mapped (it stays a preserved identity).  Every original must be
  a genuine ``int`` (never ``bool``/float) inside the member's verified
  readable range.
* FINALIZE — :meth:`NumericKeyDomainMapping.finalize` freezes the domain:
  the vault domain row is ensured (``NUMERIC_KEY`` kind, fail closed on any
  other kind), every persisted row is corruption-hardened and validated
  (canonical TEXT, in-range, never self-mapped, never silently remapped)
  and the EXACT feasibility of the complete residual allocation problem is
  proven against the shared candidate domain.
* ALLOCATE — :meth:`NumericKeyDomainMapping.pseudonym_for` reuses the
  persisted mapping unchanged (no randomness is consumed for reuse) or
  allocates a fresh CSPRNG-chosen free token, persisted inside one
  authorized :class:`~dbf_anonymizer.vault.transactions.VaultTransaction`
  (the durable single-writer lease is verified inside ``BEGIN IMMEDIATE``).
* RECOVER — :meth:`NumericKeyDomainMapping.original_for` is the typed
  reverse lookup (pseudonym -> original) analogous to the text recovery
  path.

Security properties:

* production randomness comes exclusively from the OS CSPRNG
  (``secrets.randbelow``); the private ``_random_below`` keyword seam exists
  ONLY for deterministic tests and never becomes public API or serialized
  configuration;
* pseudonyms are never predictably derived from the original, a public salt,
  a sequence counter or any reversible arithmetic; a bounded CSPRNG probe
  phase is followed by an exact uniform completion over the remaining free
  tokens (finite by construction; the token universe is never materialized);
* a candidate equal to the sensitive original is forbidden;
* failures are stable typed application errors; public errors never contain
  the original value, the pseudonym, SQL text, raw SQLite messages or paths.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable

from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError
from dbf_anonymizer.transforms.numeric_keys import (
    NumericKeyDomain,
    canonical_integer_text,
    free_token_count,
    jth_free_token,
    parse_canonical_integer_text,
    plan_numeric_bijection,
)
from dbf_anonymizer.vault.mappings import (
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    add_numeric_key_mapping,
    create_domain,
    get_numeric_original,
    get_numeric_pseudonym,
    mapping_domains,
    numeric_mapping_rows,
)
from dbf_anonymizer.vault.store import VaultDatabase

__all__ = [
    "NUMERIC_KEY_PROBE_BUDGET",
    "NumericKeyDomainMapping",
    "numeric_key_domain_id",
]

#: Bounded CSPRNG probe budget (performance bound for sparse domains, never
#: an exhaustion decision): when it runs out, the exact deterministic
#: completion phase allocates with certainty.
NUMERIC_KEY_PROBE_BUDGET = 64

_DETAIL_DOMAIN_EXHAUSTED = "NUMERIC_KEY_DOMAIN_EXHAUSTED"
_DETAIL_NO_COMPLETION = "NUMERIC_KEY_NO_COMPLETION"
_DETAIL_RANGE_INFEASIBLE = "NUMERIC_KEY_RANGE_INFEASIBLE"
_DETAIL_PERSISTED_PREFIX = "NUMERIC_KEY_PERSISTED"
_DETAIL_REUSED_PREFIX = "NUMERIC_KEY_REUSED"
_DETAIL_NOT_FINALIZED = "NUMERIC_KEY_NOT_FINALIZED"
_DETAIL_DOMAIN_KIND_CONFLICT = "NUMERIC_KEY_DOMAIN_KIND_CONFLICT"
_DETAIL_UNKNOWN_ORIGINAL = "NUMERIC_KEY_ORIGINAL_UNOBSERVED"
_DETAIL_CORRUPT = "NUMERIC_MAPPING_CORRUPT"


def _mapping_failure(code: ErrorCode, detail_code: str) -> MappingError:
    """Privacy-safe, registry-controlled numeric mapping failure."""
    return MappingError(
        code,
        context=ErrorContext(operation="mapping", detail_code=detail_code),
    )


def numeric_key_domain_id(document_fingerprint: str, relation_id: str) -> str:
    """The stable privacy-safe identity of one declared numeric key domain.

    A bounded digest over fixed, value-independent inputs — the canonical
    relationship fingerprint of the document and the stable relation id — so
    each declared numeric key relation resolves deterministically to ONE
    domain identity shared by its parent and all foreign members, across
    processes and runs, with no process randomness and no Python hash
    randomization involved.  No source value, path or salt enters it.
    """
    digest = hashlib.sha256(
        b"dbf_anonymizer/REQ-P3-005/NUMERIC_KEY_DOMAIN/v1\x00"
        + document_fingerprint.encode("utf-8")
        + b"\x00"
        + relation_id.encode("utf-8")
    ).hexdigest()[:16]
    return "dom-" + digest


class NumericKeyDomainMapping:
    """One explicitly declared numeric key mapping domain of a dataset.

    The instance binds ONE existing :class:`~dbf_anonymizer.vault.VaultDatabase`
    (the dataset's single authoritative dictionary) to one stable numeric
    key domain identity and its verified representable domain.  It is NOT
    thread-safe; the durable single-writer lease of the vault serializes all
    allocation.

    The optional keyword-only ``_random_below`` parameter is the PRIVATE
    randomness injection seam for deterministic tests.  Production always
    uses the OS CSPRNG (``secrets.randbelow``).
    """

    def __init__(
        self,
        database: VaultDatabase,
        *,
        domain_id: str,
        domain: NumericKeyDomain,
        _random_below: Callable[[int], int] | None = None,
    ) -> None:
        self._database = database
        self._domain_id = domain_id
        self._domain = domain
        self._random_below: Callable[[int], int] = _random_below or secrets.randbelow
        self._originals: set[int] = set()
        self._finalized = False
        #: Occupied pseudonyms of the domain (validated, in-range ints).
        self._used: set[int] = set()
        #: The originals of the persisted mapping rows (fixed assignments).
        self._persisted_originals: set[int] = set()

    # -- state -----------------------------------------------------------------
    @property
    def finalized(self) -> bool:
        """True once the domain is frozen (allocation is possible)."""
        return self._finalized

    @property
    def domain_id(self) -> str:
        """The stable numeric key domain identity of this mapping."""
        return self._domain_id

    @property
    def domain(self) -> NumericKeyDomain:
        """The frozen representable domain of this mapping."""
        return self._domain

    @property
    def observed_originals(self) -> tuple[int, ...]:
        """The exact collected originals in deterministic (sorted) order."""
        return tuple(sorted(self._originals))

    # -- COLLECT ------------------------------------------------------------------
    def observe_original(self, original: int, *, original_range: tuple[int, int] | None = None) -> None:
        """Record one exact distinct ORIGINAL value of the relation.

        Constraint collection is closed after :meth:`finalize`.  NULL is
        never observed and never mapped (it stays a preserved identity);
        booleans are rejected as integers.  When the caller supplies the
        originating member's verified readable range, the value must fit it;
        every original must in any case fit at least one participating
        member's readable range.
        """
        if self._finalized:
            raise ValueError("original collection is closed after finalize")
        if isinstance(original, bool) or not isinstance(original, int):
            raise TypeError("an original numeric key value must be an exact int")
        if original_range is not None:
            low, high = original_range
            if not (isinstance(low, int) and isinstance(high, int)) or low > high:
                raise ValueError("the member original range must be a non-empty closed range")
            if not low <= original <= high:
                raise ValueError("the original does not fit its member's representable range")
        if not any(
            low <= original <= high for low, high in self._domain.member_original_ranges
        ):
            raise ValueError(
                "the original does not fit any participating member's "
                "representable range"
            )
        self._originals.add(original)

    # -- FINALIZE --------------------------------------------------------------------
    def finalize(self) -> None:
        """Freeze the domain and prepare allocation.

        Verifies the persisted domain row (fail closed on any other domain
        kind), loads every persisted mapping of the domain through the
        corruption-hardened storage APIs and validates each row against the
        frozen domain (canonical TEXT, in-range, never self-mapped).  The
        EXACT feasibility of the complete residual allocation problem is
        proven before any allocation can be requested; an infeasible problem
        fails closed here.  Calling :meth:`finalize` twice is refused and
        observation is impossible afterwards.
        """
        if self._finalized:
            raise ValueError("the numeric domain is already finalized")
        self._ensure_domain()
        self._validate_domain_kind()
        self._load_and_validate_persisted()
        unpersisted = [
            value for value in sorted(self._originals) if value not in self._persisted_originals
        ]
        if not plan_numeric_bijection(
            self._domain, unpersisted, sorted(self._used)
        ):
            raise _mapping_failure(
                ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_NO_COMPLETION
            )
        self._finalized = True

    def _ensure_domain(self) -> None:
        """Create the numeric domain row when missing (idempotent)."""
        if _has_domain(self._database, self._domain_id):
            return
        with self._database.transaction():
            # Re-checked inside the transactional commit boundary.
            if not _has_domain(self._database, self._domain_id):
                create_domain(
                    self._database,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
                    domain_id=self._domain_id,
                )

    def _validate_domain_kind(self) -> None:
        """Fail closed when the persisted domain row carries another kind."""
        for row in mapping_domains(self._database):
            if row["domain_id"] == self._domain_id:
                if row["domain_kind"] != VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY:
                    raise _mapping_failure(
                        ErrorCode.MAPPING_CONFLICT, _DETAIL_DOMAIN_KIND_CONFLICT
                    )
                return
        raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, _DETAIL_DOMAIN_KIND_CONFLICT)

    def _load_and_validate_persisted(self) -> None:
        """Load persisted mappings and validate them against this finalization.

        A persisted mapping whose pseudonym is outside the frozen domain,
        equals its original, or whose original is outside the verified
        member representations fails CLOSED with a stable typed error.
        Persisted mappings are FIXED: every later allocation happens around
        them; they are never silently remapped.
        """
        for original_text, pseudonym_text in numeric_mapping_rows(
            self._database, self._domain_id
        ):
            original = self._parse_original(original_text)
            pseudonym = self._parse_pseudonym(pseudonym_text)
            if pseudonym == original:
                raise _mapping_failure(
                    ErrorCode.MAPPING_CONFLICT, _DETAIL_PERSISTED_PREFIX + "_SELF_MAPPING"
                )
            self._used.add(pseudonym)
            self._persisted_originals.add(original)

    def _parse_original(self, text: str) -> int:
        """One persisted original validated as an exact representable int."""
        try:
            value = parse_canonical_integer_text(text)
        except (TypeError, ValueError) as exc:
            raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, _DETAIL_CORRUPT) from exc
        if not any(
            low <= value <= high for low, high in self._domain.member_original_ranges
        ):
            # An out-of-range persisted original (e.g. beyond the verified
            # readable Integer range) is corrupt state, never coerced.
            raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, _DETAIL_CORRUPT)
        return value

    def _parse_pseudonym(self, text: str) -> int:
        """One persisted pseudonym validated as an exact in-domain integer."""
        try:
            value = parse_canonical_integer_text(text)
        except (TypeError, ValueError) as exc:
            raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, _DETAIL_CORRUPT) from exc
        if not self._domain.contains_pseudonym(value):
            raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, _DETAIL_CORRUPT)
        return value

    # -- ALLOCATE / REUSE --------------------------------------------------------------
    def pseudonym_for(self, original: int) -> int:
        """The persisted pseudonym of *original*, allocating it when needed.

        Reuse: the persisted mapping is returned unchanged after
        revalidation against the frozen domain — no randomness is consumed
        and the mapping is never remapped.  Allocation: a fresh CSPRNG
        pseudonym is persisted inside one authorized vault transaction.
        """
        if not self._finalized:
            raise _mapping_failure(ErrorCode.MAPPING_CONFLICT, _DETAIL_NOT_FINALIZED)
        if isinstance(original, bool) or not isinstance(original, int):
            raise TypeError("an original numeric key value must be an exact int")
        if not any(
            low <= original <= high for low, high in self._domain.member_original_ranges
        ):
            raise _mapping_failure(
                ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE, _DETAIL_RANGE_INFEASIBLE
            )
        if original not in self._originals:
            raise _mapping_failure(
                ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE, _DETAIL_UNKNOWN_ORIGINAL
            )
        existing = get_numeric_pseudonym(
            self._database, self._domain_id, canonical_integer_text(original)
        )
        if existing is not None:
            value = self._parse_pseudonym(existing)
            if value == original:
                raise _mapping_failure(
                    ErrorCode.MAPPING_CONFLICT, _DETAIL_REUSED_PREFIX + "_SELF_MAPPING"
                )
            return value
        return self._allocate(original)

    def original_for(self, pseudonym: int) -> int | None:
        """The persisted ORIGINAL of one pseudonym (typed recovery direction).

        ``None`` when the pseudonym is unknown to this domain.  The returned
        value is revalidated against the frozen domain (canonical TEXT,
        in-range) before it can reach any consumer.
        """
        if isinstance(pseudonym, bool) or not isinstance(pseudonym, int):
            raise TypeError("a pseudonym numeric key value must be an exact int")
        text = get_numeric_original(
            self._database, self._domain_id, canonical_integer_text(pseudonym)
        )
        if text is None:
            return None
        return self._parse_original(text)

    def mapping_rows(self) -> tuple[tuple[int, int], ...]:
        """All persisted mappings of the domain (internal validation only).

        The enumeration exists for internal consistency validation; it never
        becomes public API, report content or any serialized boundary.
        """
        return tuple(
            (self._parse_original(original_text), self._parse_pseudonym(pseudonym_text))
            for original_text, pseudonym_text in numeric_mapping_rows(
                self._database, self._domain_id
            )
        )

    def _allocate(self, original: int) -> int:
        """Persist one fresh CSPRNG mapping inside one authorized transaction.

        Occupancy is re-verified against the persisted vault state inside
        every allocation transaction.  The candidate is a CSPRNG-chosen free
        token of the frozen domain (bounded probe phase, then an exact
        uniform completion over the remaining free tokens — every walk is
        bounded by the number of blocked tokens, never by the domain size),
        never the original itself and never an occupied token.
        """
        with self._database.transaction():
            self._sync_used()
            fresh = get_numeric_pseudonym(
                self._database, self._domain_id, canonical_integer_text(original)
            )
            if fresh is not None:
                value = self._parse_pseudonym(fresh)
                if value == original:
                    raise _mapping_failure(
                        ErrorCode.MAPPING_CONFLICT, _DETAIL_REUSED_PREFIX + "_SELF_MAPPING"
                    )
                return value
            candidate = self._select_candidate(original)
            add_numeric_key_mapping(
                self._database,
                self._domain_id,
                canonical_integer_text(original),
                canonical_integer_text(candidate),
            )
            self._used.add(candidate)
            self._persisted_originals.add(original)
            self._originals.add(original)
            return candidate

    def _sync_used(self) -> None:
        """Reconcile occupancy bookkeeping with the persisted vault rows."""
        for original_text, pseudonym_text in numeric_mapping_rows(
            self._database, self._domain_id
        ):
            original = self._parse_original(original_text)
            pseudonym = self._parse_pseudonym(pseudonym_text)
            if pseudonym == original:
                raise _mapping_failure(
                    ErrorCode.MAPPING_CONFLICT, _DETAIL_PERSISTED_PREFIX + "_SELF_MAPPING"
                )
            self._used.add(pseudonym)
            self._persisted_originals.add(original)

    def _select_candidate(self, original: int) -> int:
        """One CSPRNG-chosen free pseudonym token for *original*.

        A bounded probe phase draws uniform random indices over the free
        token space (the drawn token is rejected when it equals the
        sensitive original); when the probe budget runs out, an exact
        uniform completion selects the ``j``-th free token OTHER than the
        original — finite by construction, no sequence/counter semantics and
        nothing derived from the original value.
        """
        occupied = sorted(self._used)
        free = free_token_count(self._domain, occupied)
        for _ in range(NUMERIC_KEY_PROBE_BUDGET):
            candidate = jth_free_token(self._domain, occupied, self._random_below(free))
            if candidate != original:
                return candidate
        # Exact completion: the j-th free token other than the original.
        blocked = sorted(token for token in occupied if token != original)
        free_excluding = free_token_count(self._domain, blocked)
        if free_excluding < 1:
            raise _mapping_failure(
                ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_DOMAIN_EXHAUSTED
            )
        return jth_free_token(
            self._domain, blocked, self._random_below(free_excluding)
        )


def _has_domain(database: VaultDatabase, domain_id: str) -> bool:
    return any(row["domain_id"] == domain_id for row in mapping_domains(database))