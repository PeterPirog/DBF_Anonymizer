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
* PLAN — before any irreversible persistence, the allocator solves the
  COMPLETE unpersisted residual problem EXACTLY (a maximum flow over a
  compressed graph that scales with the observed originals and persisted
  mappings and never materializes the token universes of wide fields): every
  unpersisted original receives a plan entry against all fixed persisted
  mappings, every strictest width, the participating encodings, the bijection
  and every self-exclusion. Persisting any subset of the plan keeps the rest
  feasible, so ``pseudonym_for`` request order can never create a dead-end
  for a later stricter original and exhaustion is raised only when the
  remaining problem is genuinely infeasible with the fixed persisted set.
* ALLOCATE/PERSIST — :meth:`GlobalTextDomainMapping.pseudonym_for` follows
  the plan: a committed named token is taken exactly; a generic class slot
  receives a CSPRNG-chosen free token of that class (bounded probe phase,
  exact j-th-free completion), persisted inside one authorized
  :class:`~dbf_anonymizer.vault.transactions.VaultTransaction` (the durable
  single-writer lease is verified inside ``BEGIN IMMEDIATE``).
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
  tokens and the self-excluded token are known EXACTLY, and the plan keeps
  the COMPLETE residual problem feasible, so a random collision is separated
  from true domain exhaustion; a bounded CSPRNG probe phase is followed by
  an exact uniform completion over the remaining free tokens of the planned
  class — the loop is finite by construction, no arbitrary attempt budget
  raises exhaustion and no unbounded retry loop exists;
* a candidate equal to the sensitive original is forbidden and counts
  against the effective available capacity;
* failures are stable typed application errors; public errors, logs and
  serialized payloads never contain the original value, the pseudonym, SQL
  text, raw SQLite messages or private paths.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable, Iterable, Literal, TypeAlias

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
_DETAIL_NO_COMPLETION = "GLOBAL_TEXT_NO_COMPLETION"
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


#: One planned assignment: a fungible slot in one length class, or an exact
#: committed (reserved) token planned for this original.
_PlanEntry: TypeAlias = tuple[Literal["generic"], int] | tuple[Literal["named"], str]


def _jth_free_in_class(
    class_low: int, class_size: int, blocked: Iterable[int], j: int
) -> int:
    """The absolute index of the ``j``-th free token of one length class.

    ``blocked`` holds unique absolute indices inside the class block
    ``[class_low, class_low + class_size)``. Walking the sorted blocked
    indices costs ``O(len(blocked))`` — the exact completion strategy of the
    selection when random probes become inefficient; it never scans the
    (possibly astronomically large) class token space itself and is finite
    by construction.
    """
    previous = class_low - 1
    remaining = j
    for index in sorted(blocked):
        gap = index - previous - 1
        if remaining < gap:
            return previous + 1 + remaining
        remaining -= gap
        previous = index
    return previous + 1 + remaining


class _ResidualFlow:
    """Compact Dinic maximum flow over the compressed assignment graph.

    Pure structure: integer nodes, unit source capacities and (possibly
    astronomically large, but never enumerated) class capacities. The flow
    is exact, so ``max_flow`` equal to the demand proves that the complete
    residual assignment problem has a bijective solution.
    """

    __slots__ = ("_graph", "_levels", "_iter")

    def __init__(self, node_count: int) -> None:
        self._graph: list[list[list[int]]] = [[] for _ in range(node_count)]
        self._levels: list[int] = []
        self._iter: list[int] = []

    def add_edge(self, u: int, v: int, cap: int) -> None:
        forward_index = len(self._graph[u])
        backward_index = len(self._graph[v])
        self._graph[u].append([v, cap, backward_index])
        self._graph[v].append([u, 0, forward_index])

    def max_flow(self, source: int, sink: int, demand: int) -> int:
        """Maximum flow value, stopping early once *demand* is reached."""
        flow = 0
        while flow < demand and self._bfs(source, sink):
            self._iter = [0] * len(self._graph)
            flow += self._blocking_push(source, sink, demand - flow)
        return flow

    def routed_target(self, node: int) -> int | None:
        """The unique downstream node carrying this node's unit of flow.

        Valid after :meth:`max_flow` for source-adjacent originals with unit
        capacity: their single fully-consumed forward edge.
        """
        for edge in self._graph[node]:
            if edge[1] == 0:
                return edge[0]
        return None

    def _bfs(self, source: int, sink: int) -> bool:
        levels = [-1] * len(self._graph)
        levels[source] = 0
        queue = [source]
        while queue and levels[sink] == -1:
            next_queue: list[int] = []
            for node in queue:
                for edge in self._graph[node]:
                    target, cap = edge[0], edge[1]
                    if cap > 0 and levels[target] == -1:
                        levels[target] = levels[node] + 1
                        next_queue.append(target)
            queue = next_queue
        self._levels = levels
        return levels[sink] != -1

    def _blocking_push(self, source: int, sink: int, limit: int) -> int:
        graph = self._graph
        levels = self._levels
        iterator = self._iter
        total = 0
        path: list[list[int]] = []  # forward edge objects along the path
        node = source
        while True:
            if node == sink:
                bottleneck = min(edge[1] for edge in path)
                bottleneck = min(bottleneck, limit - total)
                for edge in path:
                    edge[1] -= bottleneck
                    graph[edge[0]][edge[2]][1] += bottleneck
                total += bottleneck
                if total >= limit:
                    return total
                node = source
                path.clear()
                continue
            edges = graph[node]
            index = iterator[node]
            while index < len(edges):
                edge = edges[index]
                if edge[1] > 0 and self._levels[edge[0]] == self._levels[node] + 1:
                    break
                index += 1
            iterator[node] = index
            if index < len(edges):
                path.append(edges[index])
                node = edges[index][0]
                continue
            if node == source:
                return total
            self._levels[node] = -1  # dead branch: pruned for this phase
            failed = path.pop()
            node = graph[failed[0]][failed[2]][0]  # retreat via the reverse edge


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
        #: The originals of the persisted mapping rows (fixed assignments).
        self._persisted_originals: set[str] = set()
        #: The GLOBAL assignment plan for the complete unpersisted residual
        #: problem: original -> ("generic", class length) for a slot in the
        #: fungible token pool of one length class, or ("named", token) for a
        #: reserved specific token (another unpersisted original's own value).
        #: The plan is a complete feasible witness computed from the WHOLE
        #: finalized constraint set, so persisting any subset of it keeps the
        #: remaining entries feasible — greedy per-call choices can never
        #: create a dead-end for a later stricter original.
        self._plan: dict[str, _PlanEntry] | None = None
        #: Reserved (named) tokens: every unpersisted original that is itself
        #: a free safe token within its own strictest width, mapped to its
        #: owner. Reserved tokens are excluded from generic selection.
        self._plan_reserved: dict[str, str] = {}
        #: Tokens committed by the current plan to a named-planned original;
        #: they stay excluded from generic selection until their consumer is
        #: persisted (a committed token can never be stolen by the pool).
        self._plan_promised: set[str] = set()
        #: Number of persisted rows NOT allocated by this instance when the
        #: current plan was built; a change means the fixed set changed and
        #: the residual must be replanned around it.
        self._plan_signature: int | None = None
        #: Originals allocated by THIS instance (excluded from replan
        #: triggers; their rows are the plan's own committed prefix).
        self._own_persisted: set[str] = set()

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
        error. A persisted original is NEVER silently remapped. Persisted
        mappings are FIXED: every later allocation is planned around them.
        """
        for original, pseudonym, _stored_length in text_mapping_rows(
            self._database, self._domain_id
        ):
            self._validate_pseudonym(
                original, pseudonym, self._strictest.get(original), _DETAIL_PERSISTED_PREFIX
            )
            self._used[pseudonym] = len(pseudonym)
            self._persisted_originals.add(original)

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
            # the same writer (crash resume, seed completion) are FIXED state
            # that every plan is built around — the global planning is never
            # computed from stale state.
            self._sync_used()
            self._ensure_plan()
            fresh = get_text_pseudonym(self._database, self._domain_id, original)
            if fresh is not None:
                self._validate_pseudonym(
                    original, fresh, width, _DETAIL_REUSED_PREFIX
                )
                return fresh
            entry = self._plan.get(original) if self._plan is not None else None
            if entry is None:
                # Defensive: replan once around the current fixed state.
                self._build_plan()
                entry = self._plan.get(original) if self._plan is not None else None
            if entry is None:
                # The complete residual problem (this original plus every
                # other finalized unpersisted original, against all fixed
                # persisted mappings) has no feasible bijective completion.
                raise _mapping_failure(
                    ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_NO_COMPLETION
                )
            candidate = self._select_candidate(original, entry)
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
            self._persisted_originals.add(original)
            self._own_persisted.add(original)
            # Maintain the plan bookkeeping: a committed named token leaves
            # the promise set; this original leaves the unpersisted set, so
            # its own value stops being a reserved token for itself (unless
            # another planned original is committed to it) and becomes
            # generic-eligible.
            if entry[0] == "named":
                self._plan_promised.discard(str(entry[1]))
            else:
                self._plan_reserved.pop(original, None)
            return candidate

    def _sync_used(self) -> None:
        """Reconcile occupied-token bookkeeping with the persisted vault rows.

        Every persisted mapping of the domain is revalidated against the
        finalized constraints and registered as occupied. This makes the
        global planning truthful even when rows were persisted outside this
        instance's own allocation stream (e.g. a previous operation of the
        same writer).
        """
        for original, pseudonym, _stored_length in text_mapping_rows(
            self._database, self._domain_id
        ):
            self._validate_pseudonym(
                original, pseudonym, self._strictest.get(original), _DETAIL_PERSISTED_PREFIX
            )
            self._used[pseudonym] = len(pseudonym)
            self._persisted_originals.add(original)

    def _current_plan_signature(self) -> int:
        """The fixed-set measure the plan keeper compares against.

        The number of persisted rows NOT allocated by this instance: a change
        means the fixed set changed and the residual must be replanned around
        it. The builder records the SAME measure so a rebuild triggered by an
        external prefix keeps the plan instead of rebuilding it on every later
        allocation.
        """
        return len(text_mapping_rows(self._database, self._domain_id)) - len(
            self._own_persisted
        )

    def _ensure_plan(self) -> None:
        """Keep the global assignment plan current (rebuild when state moved).

        The plan is a complete feasible witness for the WHOLE unpersisted
        residual problem against the FIXED persisted mappings. It is rebuilt
        when it does not exist yet or when the fixed set changed (persisted
        rows committed outside this instance's own allocation stream). This
        instance's own committed allocations never invalidate the plan: the
        plan was a completion, so persisting any subset of it keeps the rest
        feasible — request order can never create a dead-end.
        """
        signature = self._current_plan_signature()
        if self._plan is not None and signature == self._plan_signature:
            return
        self._build_plan()

    def _build_plan(self) -> None:
        """Plan the complete finalized residual problem (exact, finite).

        The assignment problem is solved EXACTLY as a maximum flow on a
        compressed graph whose size scales with the number of observed
        originals and persisted mappings — the (astronomically large) token
        universes of wide fields are never materialized:

        * nodes: source, sink, one node per unpersisted original, one node
          per participating length class (fungible free token pool), and one
          node per RESERVED token — the free self-value of an unpersisted
          original, which that original itself may never receive;
        * edges: source -> original (1); original -> class ``l`` for every
          ``l <= strictest width``; original -> reserved token of another
          original when its length fits; class -> sink with capacity equal
          to the free NON-reserved tokens of that class; reserved -> sink
          with capacity 1.
        * the owner of a reserved token is never adjacent to it, so the
          self-exclusion is structural; fungible class capacity keeps the
          Hall-style feasibility of the shared preflight model.
        """
        assert self._alphabet is not None
        unpersisted = [
            original
            for original in self._strictest
            if original not in self._persisted_originals
        ]
        if not unpersisted:
            self._plan = {}
            self._plan_reserved = {}
            self._plan_signature = self._current_plan_signature()
            return
        max_width = max(self._strictest[original] for original in unpersisted)
        free_of_length = self._free_count_by_length()
        reserved = self._reserved_tokens(unpersisted)
        reserved_by_length: dict[int, int] = {}
        for token in reserved:
            reserved_by_length[len(token)] = reserved_by_length.get(len(token), 0) + 1

        network = _ResidualFlow(2 + len(unpersisted) + max_width + len(reserved))
        source, sink = 0, 1
        original_node = {
            original: 2 + index for index, original in enumerate(unpersisted)
        }
        class_node_of_length: dict[int, int] = {}
        token_node_of: dict[str, int] = {}
        offset = 2 + len(unpersisted)
        for length in range(1, max_width + 1):
            class_node_of_length[length] = offset
            offset += 1
        for token in sorted(reserved):
            token_node_of[token] = offset
            offset += 1
        for original in unpersisted:
            network.add_edge(source, original_node[original], 1)
            width = self._strictest[original]
            for length in range(1, width + 1):
                network.add_edge(original_node[original], class_node_of_length[length], 1)
            for token in sorted(reserved):
                if len(token) <= width and token != original:
                    network.add_edge(
                        original_node[original], token_node_of[token], 1
                    )
        for length in range(1, max_width + 1):
            generic = free_of_length[length] - reserved_by_length.get(length, 0)
            if generic > 0:
                network.add_edge(class_node_of_length[length], sink, generic)
        for node in token_node_of.values():
            network.add_edge(node, sink, 1)

        flow = network.max_flow(source, sink, len(unpersisted))
        if flow < len(unpersisted):
            # The remaining finalized problem is genuinely infeasible with
            # the already-fixed persisted mappings: no ordering of
            # ``pseudonym_for`` could ever complete it.
            self._plan = {}
            self._plan_reserved = {}
            self._plan_signature = self._current_plan_signature()
            raise _mapping_failure(
                ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_NO_COMPLETION
            )
        class_length_of_node = {
            node: length for length, node in class_node_of_length.items()
        }
        token_of_node = {node: token for token, node in token_node_of.items()}
        plan: dict[str, _PlanEntry] = {}
        for original in unpersisted:
            target = network.routed_target(original_node[original])
            if target is None:  # pragma: no cover - flow == demand guarantees
                raise _mapping_failure(
                    ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_NO_COMPLETION
                )
            assigned_class = class_length_of_node.get(target)
            if assigned_class is not None:
                plan[original] = ("generic", assigned_class)
            else:
                plan[original] = ("named", token_of_node[target])
        self._plan = plan
        self._plan_reserved = dict(reserved)
        self._plan_promised = {
            str(entry[1]) for entry in plan.values() if entry[0] == "named"
        }
        self._plan_signature = self._current_plan_signature()

    def _free_count_by_length(self) -> dict[int, int]:
        """Free tokens per length class: ``base^l`` minus occupied tokens."""
        assert self._alphabet is not None
        occupied_of_length: dict[int, int] = {}
        for pseudonym, length in self._used.items():
            occupied_of_length[length] = occupied_of_length.get(length, 0) + 1
        widest_observed = max(self._strictest.values(), default=0)
        widest_occupied = max(occupied_of_length, default=0)
        return {
            length: self._base**length - occupied_of_length.get(length, 0)
            for length in range(1, max(widest_observed, widest_occupied) + 1)
        }

    def _reserved_tokens(self, unpersisted: list[str]) -> dict[str, str]:
        """The free self-values of *unpersisted* originals (reserved tokens).

        The reserved token of an original is its own value: the original may
        never receive it as its pseudonym, while every OTHER original with a
        fitting width may. Reserved tokens are fungible for everyone else.
        """
        assert self._alphabet is not None
        reserved: dict[str, str] = {}
        for original in unpersisted:
            width = self._strictest[original]
            if (
                is_safe_token(original, self._alphabet)
                and 1 <= len(original) <= width
                and original not in self._used
            ):
                reserved[original] = original
        return reserved

    # -- plan-driven candidate selection ------------------------------------------
    def _select_candidate(self, original: str, entry: _PlanEntry) -> str:
        """One safe pseudonym for *original* under its planned assignment.

        A named entry is a reserved token planned for this original — a
        fixed, exact token. A generic entry reserves a slot in the fungible
        free pool of ONE length class; the CSPRNG chooses the actual token
        among that class's free non-reserved tokens (PHASE R, bounded by the
        documented probe budget), and the exact completion phase picks the
        ``j``-th such token by walking the blocked indices of the class —
        finite by construction, no sequence/counter semantics and nothing
        derived from the original value. Every admissible choice preserves
        the plan's global feasibility, so no random collision can create a
        dead-end for a later stricter original.
        """
        assert self._alphabet is not None
        if entry[0] == "named":
            token = entry[1]
            if token in self._used:  # pragma: no cover - plan reserved it free
                raise _mapping_failure(
                    ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_NO_COMPLETION
                )
            return token
        length = entry[1]
        class_low = token_space(length - 1, self._base)
        class_size = self._base**length
        blocked: set[str] = set()
        for pseudonym, pseudonym_length in self._used.items():
            if pseudonym_length == length:
                blocked.add(pseudonym)
        blocked.update(
            token
            for token in self._plan_reserved
            if len(token) == length
        )
        blocked.update(
            token
            for token in self._plan_promised
            if len(token) == length
        )
        free_non_reserved = class_size - len(blocked)
        if free_non_reserved <= 0:  # pragma: no cover - plan guarantees supply
            raise _mapping_failure(
                ErrorCode.MAPPING_CAPACITY_EXHAUSTED, _DETAIL_NO_COMPLETION
            )
        for _ in range(GLOBAL_TEXT_PROBE_BUDGET):
            candidate = token_at(
                class_low + self._random_below(class_size), length, self._alphabet
            )
            if candidate == original or candidate in blocked:
                continue  # random collision or forbidden candidate
            return candidate
        # Exact completion: the j-th free non-reserved token of the class.
        blocked_indices = sorted(
            token_index(token, self._alphabet) for token in blocked
        )
        chosen = _jth_free_in_class(
            class_low, class_size, blocked_indices, self._random_below(free_non_reserved)
        )
        return token_at(chosen, length, self._alphabet)

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