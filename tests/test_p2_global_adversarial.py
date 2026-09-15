"""Independent adversarial verification evidence for PR #25 (commit 9b43332).

This module is the hostile-reviewer evidence for the global planning repair
(REQ-P2-004/005/006). It adds TEST-ONLY oracles that are algorithmically
independent of the production code:

* a MAX-FLOW ORACLE (DFS Ford-Fulkerson over a residual capacity dictionary)
  compared against the production ``_ResidualFlow`` Dinic implementation over
  many small deterministic graphs, including rerouting-through-reverse-edge
  cases, zero and astronomical capacities, alternative perfect matchings and
  graphs exactly one unit below demand;
* a brute-force scan oracle for ``_jth_free_in_class``;
* a PLANNING-SEMANTICS ORACLE that solves the abstract assignment problem
  CONCRETELY (bipartite matching over concrete free tokens, Kuhn's
  augmenting paths), so the production planner is checked in BOTH
  directions: a feasible residual problem is never reported exhausted and an
  infeasible one is never completed;
* the PARTIAL-PERSISTENCE invariant ("persisting ANY subset of a complete
  feasible plan leaves a feasible completion for the remainder") exercised
  over exhaustive subset/order matrices, with white-box audits of
  ``_plan_reserved``, ``_plan_promised``, ``_persisted_originals``,
  ``_own_persisted`` and ``_plan_signature`` transitions;
* crash/reopen/replan restart matrices with fresh (never replayed)
  randomness, reuse without generator calls, and a persisted prefix that
  forces the residual solver away from the original in-memory plan;
* CSPRNG candidate-selection audits: the exact probe bound, the exact
  completion bound (including reservation), probe- and exact-phase
  self-exclusion, and absence of production-side modulo arithmetic.

Everything in this file is evidence tooling. No oracle logic is copied into
production modules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

from dbf_anonymizer import ErrorCode, MappingError
from dbf_anonymizer.transforms.text import (
    SAFE_TEXT_ALPHABET,
    token_at,
    token_space,
)
from dbf_anonymizer.vault import (
    GLOBAL_TEXT_DOMAIN_ID,
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    mappings,
)
from dbf_anonymizer.vault.mappings import text_mapping_rows
from dbf_anonymizer.vault.text_allocation import (
    GLOBAL_TEXT_PROBE_BUDGET,
    GlobalTextDomainMapping,
    _ResidualFlow,
    _jth_free_in_class,
)
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60
DBFBRIDGE_VERSION = "1.1.0"

ALPHABET = SAFE_TEXT_ALPHABET
BASE = len(ALPHABET)

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer"


def _create(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version=DBFBRIDGE_VERSION,
    )


def _reopen(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


def _rows(vault: VaultDatabase) -> tuple[tuple[str, str, int], ...]:
    return text_mapping_rows(vault, GLOBAL_TEXT_DOMAIN_ID)


def _seed_rows(vault: VaultDatabase, rows: list[tuple[str, str, int]]) -> None:
    with writer_session(vault), vault.transaction():
        mappings.create_domain(
            vault,
            domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT,
            domain_id=GLOBAL_TEXT_DOMAIN_ID,
        )
        for original, pseudonym, length in rows:
            mappings.add_text_mapping(
                vault,
                GLOBAL_TEXT_DOMAIN_ID,
                original,
                pseudonym,
                logical_byte_length=length,
            )


def _seed_rows_excluding(free: list[str]) -> list[tuple[str, str, int]]:
    """Persisted rows occupying every one-character token except *free*."""
    return [
        (f"SEED-{index:02d}", token, 1)
        for index, token in enumerate(ALPHABET)
        if token not in free
    ]


class _Lcg:
    """Tiny deterministic test-side generator (never production code)."""

    def __init__(self, seed: int) -> None:
        self._state = (seed & ((1 << 64) - 1)) or 0x9E3779B97F4A7C15
        self.calls: list[int] = []

    def _next(self) -> int:
        self._state = (
            self._state * 6364136223846793005 + 1442695040888963407
        ) & ((1 << 64) - 1)
        return self._state

    def below(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        self.calls.append(bound)
        return self._next() % bound

    def shuffle(self, items: list[str]) -> list[str]:
        result = list(items)
        for index in range(len(result) - 1, 0, -1):
            swap = self.below(index + 1)
            result[index], result[swap] = result[swap], result[index]
        return result


class _CountingRandom:
    """Deterministic scripted seam recording every requested modulus."""

    def __init__(self, *values: int, cycle: bool = False) -> None:
        self._values = list(values)
        self._cycle = cycle
        self._position = 0
        self.moduli: list[int] = []

    def __call__(self, bound: int) -> int:
        self.moduli.append(bound)
        if self._position >= len(self._values):
            if not self._cycle or not self._values:
                raise AssertionError("scripted random stream exhausted unexpectedly")
            self._position = 0
        value = self._values[self._position]
        self._position += 1
        return value % bound

    @property
    def calls(self) -> list[int]:
        return list(self.moduli)


# ---------------------------------------------------------------------------
# SECTION 1 — independent maximum-flow oracle for _ResidualFlow
# ---------------------------------------------------------------------------


def _oracle_augmenting_path(
    residual: list[dict[int, int]], source: int, sink: int
) -> list[int] | None:
    """DFS augmenting path on the residual dict (Ford-Fulkerson style)."""
    parent: dict[int, int | None] = {source: None}
    stack = [source]
    while stack:
        node = stack.pop()
        if node == sink:
            path: list[int] = []
            while node is not None:
                path.append(node)
                node = parent[node]
            path.reverse()
            return path
        for neighbor, capacity in residual[node].items():
            if capacity > 0 and neighbor not in parent:
                parent[neighbor] = node
                stack.append(neighbor)
    return None


def _oracle_max_flow(
    graph: list[dict[int, int]], source: int, sink: int, demand: int
) -> int:
    """Independent reference: DFS augmentation on a residual dictionary.

    Deliberately a DIFFERENT algorithm family from the production Dinic
    implementation (no level graph, no blocking flow, dict adjacency).
    """
    residual = [dict(neighbors) for neighbors in graph]
    flow = 0
    while flow < demand:
        path = _oracle_augmenting_path(residual, source, sink)
        if path is None:
            return flow
        bottleneck = min(residual[u][v] for u, v in zip(path, path[1:]))
        for u, v in zip(path, path[1:]):
            residual[u][v] -= bottleneck
            residual[v][u] = residual[v].get(u, 0) + bottleneck
        flow += bottleneck
    return flow


class _PhaseCountingFlow(_ResidualFlow):
    """Instrumented production flow counting BFS phases."""

    def __init__(self, node_count: int) -> None:
        super().__init__(node_count)
        self.bfs_calls = 0

    def _bfs(self, source: int, sink: int) -> bool:
        self.bfs_calls += 1
        return super()._bfs(source, sink)


def _production_network(
    edges: list[tuple[int, int, int]], node_count: int
) -> _PhaseCountingFlow:
    network = _PhaseCountingFlow(node_count)
    for u, v, cap in edges:
        network.add_edge(u, v, cap)
    return network


def test_residual_flow_matches_independent_oracle_on_random_graphs() -> None:
    """production max_flow == oracle max_flow over many random small graphs."""
    lcg = _Lcg(0xA11CE)
    rerouted_cases = 0
    for case_index in range(500):
        node_count = 2 + lcg.below(6)
        edge_count = lcg.below(2 * node_count + 3)
        edges: list[tuple[int, int, int]] = []
        for _ in range(edge_count):
            u = lcg.below(node_count)
            v = lcg.below(node_count)
            if u == v:
                continue
            cap = 10**12 if lcg.below(8) == 0 else (0, 1, 1, 2, 3)[lcg.below(5)]
            edges.append((u, v, cap))
        demand = lcg.below(5)
        graph: list[dict[int, int]] = [dict() for _ in range(node_count)]
        for u, v, cap in edges:
            graph[u][v] = graph[u].get(v, 0) + cap
        oracle_true = _oracle_max_flow(graph, 0, node_count - 1, 10**18)
        network = _production_network(edges, node_count)
        production = network.max_flow(0, node_count - 1, demand)
        assert production == min(demand, oracle_true), (
            f"case {case_index}: nodes={node_count} edges={edges} "
            f"demand={demand} production={production} oracle={oracle_true}"
        )
        if network.bfs_calls >= 2 and production >= 1:
            rerouted_cases += 1
    # A later BFS phase means an augmenting path through edges OUTSIDE the
    # earlier level graph — i.e. through reverse residual edges created by
    # earlier augmentations. The differential set must exercise them.
    assert rerouted_cases >= 30, "oracle comparison must exercise rerouting"


def test_residual_flow_rerouting_through_reverse_edges() -> None:
    """A deterministic case where the FIRST phase commits badly.

    Phase-1 blocking flow routes a1 into b1 and strands a2; the TRUE maximum
    (2) is only reachable by pushing a's unit BACK through the reverse
    residual edge b1->a1 and re-routing a1 into b2. The oracle computes the
    same value independently.
    """
    # Nodes: 0=s, 1=a1, 2=a2, 3=b1, 4=b2, 5=t.
    edges = [
        (0, 1, 1),  # s -> a1
        (0, 2, 1),  # s -> a2
        (1, 3, 1),  # a1 -> b1
        (1, 4, 1),  # a1 -> b2
        (2, 3, 1),  # a2 -> b1
        (3, 5, 1),  # b1 -> t
        (4, 5, 1),  # b2 -> t
    ]
    graph: list[dict[int, int]] = [dict() for _ in range(6)]
    for u, v, cap in edges:
        graph[u][v] = graph[u].get(v, 0) + cap
    assert _oracle_max_flow(graph, 0, 5, 2) == 2
    network = _production_network(edges, 6)
    assert network.max_flow(0, 5, 2) == 2
    # The extracted routing must be the rerouted perfect assignment.
    assert network.routed_target(1) == 4  # a1 finally routed into b2
    assert network.routed_target(2) == 3  # a2 routed into b1


def test_residual_flow_infeasible_one_unit_below_demand() -> None:
    """An infeasible graph is reported truthfully one unit below demand."""
    edges = [
        (0, 1, 1),  # s -> a1
        (0, 2, 1),  # s -> a2
        (1, 3, 1),  # a1 -> b1
        (2, 3, 1),  # a2 -> b1
        (3, 5, 1),  # b1 -> t  (b2 -> t removed: one unit short)
    ]
    graph: list[dict[int, int]] = [dict() for _ in range(6)]
    for u, v, cap in edges:
        graph[u][v] = graph[u].get(v, 0) + cap
    assert _oracle_max_flow(graph, 0, 5, 2) == 1
    network = _production_network(edges, 6)
    assert network.max_flow(0, 5, 2) == 1


def test_residual_flow_zero_and_astronomical_capacities() -> None:
    """Zero-capacity edges are dead; astronomical capacities flow fully."""
    network = _production_network([(0, 1, 0), (0, 1, 0), (0, 2, 1), (2, 1, 1)], 3)
    assert network.max_flow(0, 2, 5) == 1  # only the cap-1 route survives
    huge = 10**40
    network = _production_network(
        [(0, 1, huge), (0, 2, huge), (1, 3, huge), (2, 3, huge)], 4
    )
    assert network.max_flow(0, 3, 2 * huge) == 2 * huge
    fresh = _production_network(
        [(0, 1, huge), (0, 2, huge), (1, 3, huge), (2, 3, huge)], 4
    )
    assert fresh.max_flow(0, 3, 10**18) == 10**18  # early termination at demand


@pytest.mark.parametrize(
    "capacities", [(1, 1, 1), (2, 1), (3,), (1, 2, 2), (4, 4)]
)
def test_residual_flow_assignment_graphs_alternative_matchings(
    capacities: tuple[int, ...],
) -> None:
    """Assignment-shaped graphs: several perfect matchings, any one found.

    The extracted ``routed_target`` plan must always be a valid flow
    decomposition: every original routed, class capacities respected.
    """
    originals = sum(capacities)
    classes = len(capacities)
    node_count = 2 + originals + classes
    class_node = [2 + originals + index for index in range(classes)]
    network = _ResidualFlow(node_count)
    for original in range(originals):
        network.add_edge(0, 2 + original, 1)
        for node in class_node:
            network.add_edge(2 + original, node, 1)
    for index, capacity in enumerate(capacities):
        network.add_edge(class_node[index], 1, capacity)
    flow = network.max_flow(0, 1, originals)
    assert flow == originals, capacities
    loads: dict[int, int] = {}
    for original in range(originals):
        target = network.routed_target(2 + original)
        assert target is not None and target >= 2, capacities
        loads[target] = loads.get(target, 0) + 1
    for index, capacity in enumerate(capacities):
        assert loads.get(class_node[index], 0) <= capacity, capacities


def test_residual_flow_routed_target_after_random_unit_flows() -> None:
    """routed_target remains a valid decomposition after arbitrary phases."""
    lcg = _Lcg(0x5EED)
    for _ in range(200):
        originals = 1 + lcg.below(4)
        capacities = [1 + lcg.below(3) for _ in range(1 + lcg.below(3))]
        if sum(capacities) < originals:
            capacities.append(originals - sum(capacities))
        classes = len(capacities)
        node_count = 2 + originals + classes
        class_node = [2 + originals + index for index in range(classes)]
        network = _ResidualFlow(node_count)
        for original in range(originals):
            network.add_edge(0, 2 + original, 1)
            for node in class_node:
                network.add_edge(2 + original, node, 1)
        for index, capacity in enumerate(capacities):
            network.add_edge(class_node[index], 1, capacity)
        flow = network.max_flow(0, 1, originals)
        assert flow == originals
        loads: dict[int, int] = {}
        for original in range(originals):
            target = network.routed_target(2 + original)
            assert target is not None and target >= 2
            loads[target] = loads.get(target, 0) + 1
        for index, capacity in enumerate(capacities):
            assert loads.get(class_node[index], 0) <= capacity


# ---------------------------------------------------------------------------
# SECTION 2 — brute-force oracle for _jth_free_in_class
# ---------------------------------------------------------------------------


def test_jth_free_in_class_matches_brute_force_scan() -> None:
    """The exact completion equals a brute-force scan for every valid j."""
    lcg = _Lcg(0xC0FFEE)
    for _ in range(400):
        class_size = 1 + lcg.below(12)
        class_low = lcg.below(30)
        blocked: set[int] = set()
        for _ in range(lcg.below(class_size + 1)):
            blocked.add(class_low + lcg.below(class_size))
        free = [
            index
            for index in range(class_low, class_low + class_size)
            if index not in blocked
        ]
        for j, expected in enumerate(free):
            chosen = _jth_free_in_class(class_low, class_size, sorted(blocked), j)
            assert chosen == expected, (class_low, class_size, sorted(blocked), j)


def test_jth_free_in_class_walks_the_whole_class_block() -> None:
    """Every free index is reachable in order; blocked indices never returned."""
    class_low, class_size = 40, 9  # a class block of the 36-symbol alphabet
    blocked = {41, 44, 48}
    free = [
        index
        for index in range(class_low, class_low + class_size)
        if index not in blocked
    ]
    for j, expected in enumerate(free):
        assert _jth_free_in_class(class_low, class_size, sorted(blocked), j) == expected


# ---------------------------------------------------------------------------
# SECTION 3 — planning semantics vs a concrete-token brute-force oracle
# ---------------------------------------------------------------------------

_TOKEN_CACHE: dict[int, list[str]] = {}


def _all_tokens(max_width: int) -> list[str]:
    """All concrete alphabet tokens with encoded length 1..max_width."""
    cached = _TOKEN_CACHE.get(max_width)
    if cached is None:
        tokens: list[str] = []
        for length in range(1, max_width + 1):
            low = token_space(length - 1, BASE)
            for index in range(BASE**length):
                tokens.append(token_at(low + index, length, ALPHABET))
        _TOKEN_CACHE[max_width] = tokens
        cached = tokens
    return cached


def _oracle_matching(
    widths: dict[str, int], occupied: set[str]
) -> tuple[bool, dict[str, str]]:
    """Concrete bipartite matching: distinct free tokens, len<=width, != own.

    Fully independent of the production planner: it enumerates CONCRETE
    tokens (never class capacities) and finds a perfect matching with
    Kuhn's augmenting-path algorithm.
    """
    tokens = _all_tokens(max(widths.values()))
    admissible: dict[str, list[str]] = {
        original: [
            token
            for token in tokens
            if len(token) <= width and token not in occupied and token != original
        ]
        for original, width in widths.items()
    }
    match: dict[str, str] = {}  # token -> original

    def try_assign(original: str, visited: set[str]) -> bool:
        for token in admissible[original]:
            if token in visited:
                continue
            visited.add(token)
            owner = match.get(token)
            if owner is None or try_assign(owner, visited):
                match[token] = original
                return True
        return False

    for original in widths:
        if not try_assign(original, set()):
            return False, {}
    return True, {original: token for token, original in match.items()}


def _run_scenario(
    tmp_path: Path,
    scenario_id: str,
    seed_rows: list[tuple[str, str, int]],
    originals: list[tuple[str, int]],
) -> None:
    """The production planner outcome must equal the oracle feasibility."""
    with _create(tmp_path / scenario_id) as vault:
        _seed_rows(vault, seed_rows)
        fixed_rows = {original: pseudonym for original, pseudonym, _l in _rows(vault)}
        occupied = set(fixed_rows.values())
        widths = dict(originals)
        feasible, _assignment = _oracle_matching(widths, occupied)
        lcg = _Lcg(0xF00D + (sum(ord(character) for character in scenario_id) & 0xFFFF))
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=lcg.below)
            for original, width in originals:
                allocator.observe(original, encoding="cp1250", byte_width=width)
            allocator.finalize()
            if not feasible:
                with pytest.raises(MappingError) as excinfo:
                    allocator.pseudonym_for(originals[0][0])
                assert excinfo.value.code is ErrorCode.MAPPING_CAPACITY_EXHAUSTED
                assert {o: p for o, p, _l in _rows(vault)} == fixed_rows
                return
            for original in lcg.shuffle([original for original, _w in originals]):
                allocator.pseudonym_for(original)
        rows = {original: pseudonym for original, pseudonym, _l in _rows(vault)}
        assert len(rows) == len(fixed_rows) + len(originals)
        assert len(set(rows.values())) == len(rows)  # global bijection
        for original, pseudonym in fixed_rows.items():
            assert rows[original] == pseudonym  # persisted rows never change
        for original, width in originals:
            pseudonym = rows[original]
            assert len(pseudonym) <= width, (scenario_id, original, pseudonym, width)
            assert pseudonym != original  # self-token forbidden
            assert pseudonym not in occupied  # no collision with fixed state


def test_planning_semantics_exact_capacity_with_self_token(tmp_path: Path) -> None:
    """Exact-capacity domain with a reserved self-token and competing users."""
    _run_scenario(
        tmp_path,
        "exact-capacity-self-token",
        _seed_rows_excluding(["C", "7"]),
        [("C", 1), ("FLEX-1", 1), ("FLEX-2", 1), ("WIDE-1", 2)],
    )


def test_planning_semantics_one_token_short_is_truthful(tmp_path: Path) -> None:
    """One token short: the residual problem is genuinely infeasible."""
    _run_scenario(
        tmp_path,
        "one-token-short",
        _seed_rows_excluding(["C"]),
        [("C", 1), ("FLEX-1", 1), ("FLEX-2", 1)],
    )


def test_planning_semantics_reserved_token_competing_users(tmp_path: Path) -> None:
    """Reserved self-tokens usable by several competing originals.

    All four free tokens are reserved self-values, so every original must
    receive SOMEONE ELSE'S token: a derangement is the only completion.
    """
    _run_scenario(
        tmp_path,
        "derangement",
        _seed_rows_excluding(["A", "B", "C", "D"]),
        [("A", 1), ("B", 1), ("C", 1), ("D", 1)],
    )


def test_planning_semantics_multiple_valid_perfect_assignments(
    tmp_path: Path,
) -> None:
    """Ample capacity: many perfect assignments; any one must complete."""
    _run_scenario(
        tmp_path,
        "ample",
        [],
        [(f"ORIG-{index:02d}", 1 + (index % 3)) for index in range(5)],
    )


def test_planning_semantics_occupied_self_value(tmp_path: Path) -> None:
    """A persisted pseudonym occupies an original's own value."""
    seed_rows = [("SEED-00", "C", 1)]
    seed_rows += [
        (f"SEED-{index + 1:02d}", token, 1)
        for index, token in enumerate(ALPHABET)
        if token not in ("C", "A")
    ]
    _run_scenario(
        tmp_path,
        "occupied-self-value",
        seed_rows,
        [("C", 1), ("FLEX-1", 1), ("WIDE-1", 2)],
    )


def test_planning_semantics_value_too_long_for_its_own_field(
    tmp_path: Path,
) -> None:
    """A value too long for its own field is NOT reserved and stays fungible."""
    _run_scenario(
        tmp_path,
        "long-value",
        _seed_rows_excluding(["C"]),
        [("CANDIDATE", 1), ("FLEX-1", 1), ("FLEX-2", 2)],
    )


def test_planning_semantics_greedy_trap(tmp_path: Path) -> None:
    """A domain that only a global plan can complete (nested width pools)."""
    _run_scenario(
        tmp_path,
        "greedy-trap",
        [],
        [(f"NARROW-{index:02d}", 1) for index in range(35)]
        + [("WIDE-1", 2), ("WIDE-2", 2)],
    )


@pytest.mark.parametrize("seed", list(range(24)))
def test_planning_semantics_random_scenarios_match_oracle(
    tmp_path: Path, seed: int
) -> None:
    """Deterministic random residual scenarios: feasible iff oracle feasible."""
    lcg = _Lcg(0xC0DE + seed)
    pool1 = list(ALPHABET)
    pool2 = [token_at(token_space(1, BASE) + index, 2, ALPHABET) for index in range(40)]
    originals: list[tuple[str, int]] = []
    for index in range(1 + lcg.below(5)):
        width = 1 + lcg.below(3)
        style = lcg.below(3)
        if style == 0:
            value = f"NON-TOKEN-{index}"
        elif style == 1:
            value = pool1[lcg.below(BASE)]
        else:
            value = pool2[lcg.below(len(pool2))]
        if any(value == existing for existing, _width in originals):
            value = f"ORIG-{index}"
        originals.append((value, width))
    seed_rows: list[tuple[str, str, int]] = []
    occupied: set[str] = set()
    for index in range(lcg.below(3)):
        pseudonym = (
            pool1[lcg.below(BASE)]
            if lcg.below(2) == 0
            else pool2[lcg.below(len(pool2))]
        )
        if pseudonym in occupied:
            continue
        occupied.add(pseudonym)
        seed_rows.append((f"SEED-{index:02d}", pseudonym, len(pseudonym)))
    # Sometimes a persisted pseudonym occupies an unpersisted original's value.
    if seed_rows and lcg.below(3) == 0:
        victim = originals[lcg.below(len(originals))][0]
        stolen = seed_rows[0]
        if len(victim) <= len(stolen[1]):
            seed_rows[0] = (stolen[0], victim, len(victim))
            occupied.discard(stolen[1])
            occupied.add(victim)
    _run_scenario(tmp_path, f"random-{seed}", seed_rows, originals)


# ---------------------------------------------------------------------------
# SECTION 4 — partial-persistence invariant over subset/order matrices
# ---------------------------------------------------------------------------


def _audit_plan_bookkeeping(allocator: GlobalTextDomainMapping) -> None:
    """White-box invariants of the mutable plan bookkeeping."""
    assert allocator._finalized
    plan = allocator._plan
    assert plan is not None
    for original, entry in plan.items():
        width = allocator._strictest[original]
        assert width is not None
        if entry[0] == "generic":
            assert 1 <= entry[1] <= width
        else:
            token = entry[1]
            assert token != original
            assert len(token) <= width
            if token in allocator._used:
                # A named token may only be occupied by its OWN consumer.
                assert original in allocator._persisted_originals
    persisted = {original for original, _p, _l in _rows(allocator._database)}
    assert allocator._persisted_originals == persisted
    assert allocator._own_persisted <= persisted
    unpersisted = set(allocator._strictest) - persisted
    for token in allocator._plan_reserved:
        assert token in unpersisted  # reserved keys are owners' self-values
        assert 1 <= len(token) <= allocator._strictest[token]
    for promised in allocator._plan_promised:
        assert promised not in allocator._used


def test_partial_persistence_every_subset_matrix(tmp_path: Path) -> None:
    """Persisting ANY subset of a feasible plan leaves a feasible completion.

    For a feasible state, EVERY subset of the unpersisted originals is
    persisted first in one permutation and the remainder in another; every
    run completes without false exhaustion and previously persisted mappings
    never change.
    """
    prefix_rows = _seed_rows_excluding(["A", "C"])
    originals = [("C", 1), ("FLEX-1", 1), ("WIDE-1", 2)]
    names = [original for original, _width in originals]
    lcg = _Lcg(0x1234)
    for mask in range(1 << len(names)):
        subset = [names[i] for i in range(len(names)) if mask >> i & 1]
        with _create(tmp_path / f"mask-{mask}") as vault:
            _seed_rows(vault, prefix_rows)
            with writer_session(vault):
                allocator = GlobalTextDomainMapping(vault, _random_below=None)
                for original, width in originals:
                    allocator.observe(original, encoding="cp1250", byte_width=width)
                allocator.finalize()
                assert allocator._plan is None  # plan appears at first request
                fixed = {o: p for o, p, _l in _rows(vault)}
                signature_seen: list[int] = []
                for original in lcg.shuffle(subset):
                    allocator.pseudonym_for(original)
                    _audit_plan_bookkeeping(allocator)
                    if allocator._plan_signature is not None:
                        signature_seen.append(allocator._plan_signature)
                rest = [name for name in names if name not in subset]
                for original in lcg.shuffle(rest):
                    allocator.pseudonym_for(original)
                    _audit_plan_bookkeeping(allocator)
                    if allocator._plan_signature is not None:
                        signature_seen.append(allocator._plan_signature)
            rows = {o: p for o, p, _l in _rows(vault)}
            assert len(rows) == len(prefix_rows) + len(names)
            assert len(set(rows.values())) == len(rows)
            for original, pseudonym in fixed.items():
                assert rows[original] == pseudonym
            for original, width in originals:
                assert len(rows[original]) <= width
                assert rows[original] != original
            if signature_seen:
                assert len(set(signature_seen)) == 1  # plan kept across own rows


def test_partial_persistence_generic_named_mixture_matrix(tmp_path: Path) -> None:
    """The tight class-1 domain (a forced named entry) persists in every order."""
    prefix_rows = _seed_rows_excluding(["A", "C"])
    originals = [("C", 1), ("FLEX-1", 1), ("WIDE-1", 2)]
    names = [original for original, _width in originals]
    lcg = _Lcg(0xBEEF)
    plans_with_named = 0
    for mask in range(1 << len(names)):
        subset = [names[i] for i in range(len(names)) if mask >> i & 1]
        with _create(tmp_path / f"mixture-{mask}") as vault:
            _seed_rows(vault, prefix_rows)
            with writer_session(vault):
                allocator = GlobalTextDomainMapping(
                    vault, _random_below=lambda bound: bound - 1
                )
                for original, width in originals:
                    allocator.observe(original, encoding="cp1250", byte_width=width)
                allocator.finalize()
                fixed = {o: p for o, p, _l in _rows(vault)}
                order = lcg.shuffle(subset)
                for position, original in enumerate(order):
                    allocator.pseudonym_for(original)
                    if position == 0:
                        plan = allocator._plan
                        assert plan is not None
                        if any(entry[0] == "named" for entry in plan.values()):
                            plans_with_named += 1
                    _audit_plan_bookkeeping(allocator)
                rest = [name for name in names if name not in subset]
                for original in lcg.shuffle(rest):
                    allocator.pseudonym_for(original)
                    _audit_plan_bookkeeping(allocator)
            rows = {o: p for o, p, _l in _rows(vault)}
            assert len(set(rows.values())) == len(rows)
            for original, pseudonym in fixed.items():
                assert rows[original] == pseudonym
            for original, width in originals:
                assert len(rows[original]) <= width
                assert rows[original] != original
    assert plans_with_named >= 1  # the matrix really exercises named planning


# ---------------------------------------------------------------------------
# SECTION 5 — crash / reopen / replan verification
# ---------------------------------------------------------------------------


def test_crash_reopen_cycle_completes_without_replay(tmp_path: Path) -> None:
    """Restart between allocations; fresh randomness per reopen; no replay."""
    dataset = [("C", 1), ("FLEX-1", 1), ("WIDE-1", 2), ("WIDE-2", 3), ("ORIG-9", 1)]
    names = [original for original, _width in dataset]
    seen: dict[str, str] = {}
    for restart in range(4):
        vault = _create(tmp_path) if restart == 0 else _reopen(tmp_path)
        lcg = _Lcg(0xABCD + restart * 7919)
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=lcg.below)
            for original, width in dataset:
                allocator.observe(original, encoding="cp1250", byte_width=width)
            allocator.finalize()
            assert lcg.calls == []  # finalization consumes no randomness
            # Reuse of persisted mappings must not call the generator at all.
            for original in names:
                if original in seen:
                    assert allocator.pseudonym_for(original) == seen[original]
            assert lcg.calls == []
            # Continue allocation in a restart-dependent order.
            order = names[restart:] + names[:restart]
            for original in order:
                if original in seen:
                    continue
                seen[original] = allocator.pseudonym_for(original)
            assert len(set(seen.values())) == len(seen)  # no duplicate pseudonym
        rows = {o: p for o, p, _l in _rows(vault)}
        for original, pseudonym in seen.items():
            assert rows.get(original) == pseudonym  # never remapped
        vault.close()
    assert set(seen) == set(names)
    for original, width in dataset:
        assert len(seen[original]) <= width
        assert seen[original] != original


def test_reopen_genuine_infeasibility_fails_closed(tmp_path: Path) -> None:
    """A persisted prefix that leaves no completion fails across reopen."""
    prefix = _seed_rows_excluding([])  # the whole class-1 pool is occupied
    with _create(tmp_path) as vault:
        _seed_rows(vault, prefix)
        vault.close()
    with _reopen(tmp_path) as vault:
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault)
            allocator.observe("STRANDED", encoding="cp1250", byte_width=1)
            allocator.finalize()
            with pytest.raises(MappingError) as excinfo:
                allocator.pseudonym_for("STRANDED")
            assert excinfo.value.code is ErrorCode.MAPPING_CAPACITY_EXHAUSTED
        assert len(_rows(vault)) == len(prefix)  # nothing was added


def test_persisted_prefix_forces_a_different_completion(tmp_path: Path) -> None:
    """The residual solver must leave the original in-memory plan.

    The in-memory plan routes FLEX-2 into the fungible class-1 pool. A
    persisted prefix of a previous operation then consumes the fungible
    class-1 tokens, so the replan must RE-ROUTE FLEX-2 onto the reserved
    self-token "C" (a different completion) instead of failing or reusing
    the stale plan.
    """
    prefix = _seed_rows_excluding(["A", "B", "C", "D", "E"])
    with _create(tmp_path) as vault:
        _seed_rows(vault, prefix)
        with writer_session(vault):
            first = GlobalTextDomainMapping(
                vault, _random_below=_CountingRandom(0, cycle=True)
            )
            first.observe("C", encoding="cp1250", byte_width=2)
            first.observe("FLEX-1", encoding="cp1250", byte_width=1)
            first.observe("FLEX-2", encoding="cp1250", byte_width=1)
            first.finalize()
            assert first.pseudonym_for("FLEX-1") == "A"
            plan_in_memory = dict(first._plan or {})
            assert plan_in_memory["FLEX-2"] == ("generic", 1)
            # A previous operation of the same writer persists two more rows,
            # consuming the fungible class-1 tokens "B" and "D".
            second = GlobalTextDomainMapping(
                vault, _random_below=_CountingRandom(1, 3)
            )
            second.observe("EXT-1", encoding="cp1250", byte_width=1)
            second.observe("EXT-2", encoding="cp1250", byte_width=1)
            second.finalize()
            assert second.pseudonym_for("EXT-1") == "B"
            assert second.pseudonym_for("EXT-2") == "D"
            # The first instance must replan around the new fixed rows; the
            # only completion now names FLEX-2 with the reserved token "C".
            assert first.pseudonym_for("C") == "E"
            assert first.pseudonym_for("FLEX-2") == "C"
        rows = {o: p for o, p, _l in _rows(vault)}
        assert len(set(rows.values())) == len(rows)
        assert rows["FLEX-2"] == "C"  # a DIFFERENT completion than planned
        assert rows["C"] == "E"
        assert len(rows["C"]) <= 2  # width respected


# ---------------------------------------------------------------------------
# SECTION 6 — CSPRNG and candidate-selection audit
# ---------------------------------------------------------------------------


def test_csprng_probe_and_exact_bounds_are_exact(tmp_path: Path) -> None:
    """randbelow receives the class size (probe) and the free count (exact)."""
    with _create(tmp_path) as vault:
        _seed_rows(vault, _seed_rows_excluding(["P", "Q"]))
        stream = _CountingRandom(*([0] * GLOBAL_TEXT_PROBE_BUDGET), 0)
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=stream.__call__)
            allocator.observe("Q", encoding="cp1250", byte_width=1)
            allocator.finalize()
            pseudonym = allocator.pseudonym_for("Q")
        assert pseudonym == "P"  # P is the only free NON-reserved class-1 token
        # PHASE R: exactly the documented probe budget, each with the exact
        # class-size bound 36...
        assert stream.calls[:GLOBAL_TEXT_PROBE_BUDGET] == [36] * GLOBAL_TEXT_PROBE_BUDGET
        # ...then ONE exact completion call with the free NON-reserved count:
        # 36 tokens - 34 occupied - 1 reserved self-token ("Q") = 1.
        assert len(stream.calls) == GLOBAL_TEXT_PROBE_BUDGET + 1
        assert stream.calls[-1] == 1


def test_csprng_exact_completion_excludes_self_token_for_every_j(
    tmp_path: Path,
) -> None:
    """Exhaustive exact-phase self-exclusion over all admissible j."""
    free = ["M", "P", "Q"]
    for j in range(2):  # free non-reserved tokens: M and P (Q is reserved)
        with _create(tmp_path / f"j-{j}") as vault:
            _seed_rows(vault, _seed_rows_excluding(free))
            stream = _CountingRandom(*([0] * GLOBAL_TEXT_PROBE_BUDGET), j)
            with writer_session(vault):
                allocator = GlobalTextDomainMapping(
                    vault, _random_below=stream.__call__
                )
                allocator.observe("Q", encoding="cp1250", byte_width=1)
                allocator.finalize()
                pseudonym = allocator.pseudonym_for("Q")
            assert pseudonym == ("M" if j == 0 else "P")
            assert pseudonym != "Q"  # self-token never selected in the exact phase
            assert stream.calls[-1] == 2  # the bound EXCLUDES the reserved token


def test_csprng_probe_budget_never_becomes_exhaustion(tmp_path: Path) -> None:
    """A full collision streak is a PERFORMANCE event, never exhaustion."""
    with _create(tmp_path) as vault:
        _seed_rows(vault, [("SEED-00", "A", 1)])
        stream = _CountingRandom(*([0] * GLOBAL_TEXT_PROBE_BUDGET), 0)
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=stream.__call__)
            allocator.observe("BUDGET-EDGE", encoding="cp1250", byte_width=1)
            allocator.finalize()
            pseudonym = allocator.pseudonym_for("BUDGET-EDGE")
            assert pseudonym == "B"  # first free token (blocked = {"A"})
            assert len(stream.calls) == GLOBAL_TEXT_PROBE_BUDGET + 1
            assert stream.calls[-1] == 35  # free non-reserved count of the class


def test_csprng_values_come_only_from_the_seam(tmp_path: Path) -> None:
    """Concrete pseudonym values are exclusively CSPRNG-seam selections.

    Two structurally identical originals planned into the same class receive
    the concrete tokens from the seam alone; production passes the exact
    class bound and applies no modulo arithmetic of its own.
    """
    with _create(tmp_path) as vault:
        stream = _CountingRandom(0, 1)
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=stream.__call__)
            allocator.observe("AAA-1", encoding="cp1250", byte_width=1)
            allocator.observe("ZZZ-2", encoding="cp1250", byte_width=1)
            allocator.finalize()
            first = allocator.pseudonym_for("AAA-1")
            second = allocator.pseudonym_for("ZZZ-2")
            assert first == "A" and second == "B"
            assert stream.calls == [36, 36]  # exactly the class-size bounds


def test_csprng_no_production_modulo_at_the_selection_seam() -> None:
    """Production selection applies no modulo bias of its own.

    The candidate selection derives tokens from ``randbelow`` results
    directly (``token_at(class_low + randbelow(class_size))`` and the
    j-th-free completion); a static check pins the absence of any ``%``
    operator in the selection/completion code.
    """
    source = (SRC_ROOT / "vault" / "text_allocation.py").read_text(encoding="utf-8")
    selection_start = source.index("def _select_candidate")
    selection_end = source.index("# -- persisted/reused validation")
    selection_code = source[selection_start:selection_end]
    assert "%" not in selection_code


# ---------------------------------------------------------------------------
# SECTION 7 — replan bookkeeping across an externally committed prefix
# ---------------------------------------------------------------------------


def test_replan_not_repeated_after_external_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rebuild triggered by an external prefix must not repeat per call.

    The recorded plan signature must measure the SAME quantity the keeper
    compares against (persisted rows minus this instance's own rows);
    otherwise every later allocation of the same live instance rebuilds the
    complete plan again — quadratic work repeated per request.
    """
    builds = {"count": 0}
    original_build = GlobalTextDomainMapping._build_plan
    target: dict[str, GlobalTextDomainMapping | None] = {"obj": None}

    def counting_build(self: GlobalTextDomainMapping) -> None:
        if target["obj"] is self:
            builds["count"] += 1
        original_build(self)

    monkeypatch.setattr(GlobalTextDomainMapping, "_build_plan", counting_build)
    prefix = _seed_rows_excluding(["A", "B", "C", "D", "E"])
    with _create(tmp_path) as vault:
        _seed_rows(vault, prefix)
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(
                vault, _random_below=_CountingRandom(2, cycle=True)
            )
            allocator.observe("C", encoding="cp1250", byte_width=2)
            allocator.observe("FLEX-1", encoding="cp1250", byte_width=1)
            allocator.observe("FLEX-2", encoding="cp1250", byte_width=1)
            allocator.observe("FLEX-3", encoding="cp1250", byte_width=1)
            allocator.finalize()
            target["obj"] = allocator
            builds["count"] = 0
            allocator.pseudonym_for("FLEX-1")  # first allocation: ONE build
            allocator.pseudonym_for("FLEX-2")  # plan kept: no rebuild
            assert builds["count"] == 1
            # An external operation persists two more rows (fixed set changed):
            # exactly ONE further replan is justified; own allocations must
            # then keep the plan without rebuilding again.
            second = GlobalTextDomainMapping(
                vault, _random_below=_CountingRandom(1, 3, cycle=True)
            )
            second.observe("EXT-1", encoding="cp1250", byte_width=1)
            second.observe("EXT-2", encoding="cp1250", byte_width=1)
            second.finalize()
            second.pseudonym_for("EXT-1")
            second.pseudonym_for("EXT-2")
            allocator.pseudonym_for("C")  # justified replan here
            assert builds["count"] == 2
            allocator.pseudonym_for("FLEX-3")  # later own allocation: NO rebuild
            assert builds["count"] == 2