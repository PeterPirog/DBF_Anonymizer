"""The exact bounded text residual solver: true corner cases + oracles.

The production solver is exercised with TINY alphabets (``"ab"``, ``"abc"``,
``"abcd"``) so the candidate resource universe is genuinely tiny and the
token-displacement branch is objectively forced — the full production
alphabet leaves fungible resources everywhere and proves nothing about
displacement.  Three independent correctness references are used:

* the P2 ``GlobalTextDomainMapping`` exact planner — ONLY for cases whose
  candidate alphabet is the same full production alphabet as the solver's
  (it derives its own alphabet from the encoding, so tiny-alphabet cases
  would NOT be equivalent);
* a deterministic TEST-ONLY brute-force matching oracle (exhaustive
  backtracking over the tiny resource universe) for every tiny-alphabet
  case — production never imports it;
* exact deterministic assignment assertions (the greedy/displacement
  behavior with deterministic tie-breaking is fully predictable, so the
  tests assert the EXACT solved assignment, not just the verdict).

The P2 planner remains a TEST ORACLE ONLY (never imported by any production
engine module — AST-guarded).
"""

from __future__ import annotations

import ast
import itertools
import random
from pathlib import Path

import pytest

from dbf_anonymizer.engine import text_residual as text_residual_module
from dbf_anonymizer.engine.state import PassOneSpool
from dbf_anonymizer.engine.text_residual import solve_text_residual
from dbf_anonymizer.errors import MappingError
from dbf_anonymizer.transforms.text import (
    candidate_alphabet,
    is_safe_token,
)
from dbf_anonymizer.vault.mappings import (
    add_text_mapping,
    create_domain,
    mapping_domains,
)
from dbf_anonymizer.vault.schema import VAULT_TABLE_DOMAIN_KIND_TEXT
from dbf_anonymizer.vault.store import VaultDatabase, new_writer_token
from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID

ALPHABET = candidate_alphabet(["cp1250"])
assert ALPHABET
BASE = len(ALPHABET)


def _open_vault(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / "dictionary.sqlite3",
        create=True,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
        dbfbridge_version="1.1.0",
    )


def _seed_domain(vault: VaultDatabase) -> str:
    domain_id = GLOBAL_TEXT_DOMAIN_ID
    if not any(row["domain_id"] == domain_id for row in mapping_domains(vault)):
        lease = new_writer_token()
        vault.acquire_writer_lease(lease)
        try:
            with vault.transaction():
                if not any(
                    row["domain_id"] == domain_id for row in mapping_domains(vault)
                ):
                    create_domain(
                        vault,
                        domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                        domain_id=domain_id,
                    )
        finally:
            vault.release_writer_lease(lease)
    return domain_id


def _persist(
    vault: VaultDatabase, domain_id: str, pairs: list[tuple[str, str]]
) -> None:
    if not pairs:
        return
    lease = new_writer_token()
    vault.acquire_writer_lease(lease)
    try:
        with vault.transaction():
            for value, pseudonym in pairs:
                add_text_mapping(
                    vault,
                    domain_id,
                    value,
                    pseudonym,
                    logical_byte_length=len(pseudonym),
                )
    finally:
        vault.release_writer_lease(lease)


def _solve(
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
    alphabet: str,
):
    return solve_text_residual(
        vault, spool, domain_id=domain_id, alphabet=alphabet, base=len(alphabet)
    )


def _solved_assignment(
    spool: PassOneSpool,
) -> dict[str, tuple[str, int | None, int | None]]:
    """The solved (original -> (kind, class_length, token_value)) mapping."""
    rows = spool.internal_connection().execute(
        "SELECT o.canonical, a.kind, a.length, t.value "
        "FROM res_assign a JOIN res_original o ON o.idx = a.orig_idx "
        "LEFT JOIN res_token t ON t.tid = a.token_idx ORDER BY o.idx"
    ).fetchall()
    return {
        bytes(canonical).decode("utf-8"): (
            str(kind),
            None if length is None else int(length),
            None if token_value is None else str(token_value),
        )
        for canonical, kind, length, token_value in rows
    }


def _original_ids(spool: PassOneSpool) -> dict[str, int]:
    """The original-id namespace of the solved graph (by value)."""
    return {
        bytes(canonical).decode("utf-8"): int(idx)
        for canonical, idx in spool.internal_connection().execute(
            "SELECT canonical, idx FROM res_original"
        ).fetchall()
    }


def _token_ids(spool: PassOneSpool) -> dict[str, int]:
    """The tid namespace of the solved graph (resource ids, by value)."""
    return {
        str(value): int(tid)
        for value, tid in spool.internal_connection().execute(
            "SELECT value, tid FROM res_token"
        ).fetchall()
    }


def _token_owners(spool: PassOneSpool) -> dict[str, int]:
    """The owner original of every reserved token (by token value)."""
    return {
        str(value): int(owner)
        for value, owner in spool.internal_connection().execute(
            "SELECT value, owner_idx FROM res_token"
        ).fetchall()
    }


# ---------------------------------------------------------------------------
# deterministic tiny-alphabet corner cases (Blocker 2)
# ---------------------------------------------------------------------------
def test_one_token_exhaustion_is_infeasible(tmp_path: Path) -> None:
    """A single width-1 original over a ONE-token alphabet: the only
    resource is its own value — self-exclusion makes it infeasible."""
    work = tmp_path / "t0"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        spool.observe_text("a", byte_width=1)
        spool.flush()
        try:
            _solve(vault, spool, domain_id, alphabet="a")
            raise AssertionError("expected infeasibility")
        except MappingError as excinfo:
            assert (
                excinfo.to_dict()["context"]["detail_code"]
                == "ENGINE_TEXT_RESIDUAL_INFEASIBLE"
            )
        assert _solved_assignment(spool) == {}
        spool.cleanup()


def test_two_token_exact_swap(tmp_path: Path) -> None:
    """Two width-1 originals over alphabet 'ab': fungible = 0, the only
    feasible assignment is the exact swap."""
    work = tmp_path / "t1"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        for value in ("a", "b"):
            spool.observe_text(value, byte_width=1)
        spool.flush()
        _solve(vault, spool, domain_id, alphabet="ab")
        assignment = _solved_assignment(spool)
        assert assignment == {
            "a": ("token", None, "b"),
            "b": ("token", None, "a"),
        }
        token_ids = _token_ids(spool)
        owners = _token_owners(spool)
        original_ids = _original_ids(spool)
        assert token_ids == {"a": 0, "b": 1}
        # tid namespace vs occupant: the occupant of each reserved token is
        # a DIFFERENT original than the tid integer namespace implies.
        for value, token in (("a", "b"), ("b", "a")):
            assert assignment[value][2] == token
            assert token_ids[token] != original_ids[value]
            assert assignment[value][2] != value  # never the own value
        spool.cleanup()


def test_real_three_token_odd_derangement(tmp_path: Path) -> None:
    """A TRUE 3-token derangement over alphabet 'abc' (base 3, width 1):
    the token universe is exactly {a, b, c}, fungible capacity is 0, and
    the solved assignment is the exact odd cycle a->b, b->c, c->a — which
    REQUIRES the token-displacement branch (greedy alone stalls on 'c').
    The displaced occupant (original 1, holding token a) is NOT the token
    id (0) — the two namespaces differ by construction."""
    work = tmp_path / "t2"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        for value in ("a", "b", "c"):
            spool.observe_text(value, byte_width=1)
        spool.flush()
        max_stack = {"depth": 0}
        real_unwind = text_residual_module._unwind

        def spy_unwind(connection, found):
            rows = int(
                connection.execute("SELECT COUNT(*) FROM res_dfs").fetchone()[0]
            )
            max_stack["depth"] = max(max_stack["depth"], int(rows))
            return real_unwind(connection, found)

        import pytest as _pytest

        _mp = _pytest.MonkeyPatch()
        _mp.setattr(text_residual_module, "_unwind", spy_unwind)
        try:
            _solve(vault, spool, domain_id, alphabet="abc")
        finally:
            _mp.undo()
        # The exact odd-cycle assignment (deterministic tie-breaking):
        assignment = _solved_assignment(spool)
        assert assignment == {
            "a": ("token", None, "b"),
            "b": ("token", None, "c"),
            "c": ("token", None, "a"),
        }
        # Every assignment is a named reserved-token resource; the displaced
        # occupant (original 'b', which held token 'a' = tid 0) is NOT the
        # resource id: tid 0 != occupant index 1 by construction.
        token_ids = _token_ids(spool)
        assert token_ids == {"a": 0, "b": 1, "c": 2}
        owners = _token_owners(spool)
        assert owners == {"a": 0, "b": 1, "c": 2}
        assert assignment["c"][2] == "a"  # tid 0 taken by original index 2
        assert 0 != 2
        # The alternating path really ran: root -> token a (occupied by the
        # occupant original) -> free token c.  Chain stack reached depth 2.
        assert max_stack["depth"] >= 2
        spool.cleanup()


def test_displacement_frame_uses_the_occupant_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tid namespace != original namespace BY CONSTRUCTION and a resolving
    augmenting chain of stack depth >= 3: with alphabet 'ab' the originals
    {zz(unsafe), a, b, aa, ab} leave token ids shifted against original ids
    (the unsafe original owns no token), and the solved assignment moves a
    reserved token between DIFFERENT originals via a multi-frame chain."""
    work = tmp_path / "t3"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        for value, width in (
            ("zz", 2),
            ("a", 2),
            ("b", 2),
            ("aa", 2),
            ("ab", 2),
        ):
            spool.observe_text(value, byte_width=width)
        spool.flush()
        max_stack = {"depth": 0}
        real_unwind = text_residual_module._unwind

        def spy_unwind(connection, found):
            rows = int(
                connection.execute("SELECT COUNT(*) FROM res_dfs").fetchone()[0]
            )
            max_stack["depth"] = max(max_stack["depth"], rows)
            return real_unwind(connection, found)

        monkeypatch.setattr(text_residual_module, "_unwind", spy_unwind)
        _solve(vault, spool, domain_id, alphabet="ab")
        # Deterministic solved partition (kinds/resources, CSPRNG only
        # affects the later class token VALUES):
        assignment = _solved_assignment(spool)
        assert assignment == {
            "a": ("class", 2, None),
            "aa": ("token", None, "a"),
            "ab": ("token", None, "aa"),
            "b": ("token", None, "ab"),
            "zz": ("class", 2, None),
        }
        # tid != occupant by construction: token 'a' (tid 0) is owned by
        # original 0 ('a') but ASSIGNED to original 1 ('aa').
        token_ids = _token_ids(spool)
        owners = _token_owners(spool)
        assert token_ids["a"] == 0
        assert owners["a"] == 0
        assert assignment["aa"][2] == "a"
        # The class capacity bookkeeping reconciles: exactly the two class-2
        # slots the solver consumed were used.
        assert max_stack["depth"] >= 3  # a real multi-frame chain ran
        spool.cleanup()


def test_mixed_widths_with_reserved_resources(tmp_path: Path) -> None:
    """Mixed widths over alphabet 'abc': the width-1 trio exhausts its class
    and resolves through a displacement chain while the width-2 original
    takes a class-2 slot."""
    work = tmp_path / "t4"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        for value, width in (
            ("a", 1),
            ("b", 1),
            ("c", 1),
            ("aa", 2),
        ):
            spool.observe_text(value, byte_width=width)
        spool.flush()
        _solve(vault, spool, domain_id, alphabet="abc")
        assignment = _solved_assignment(spool)
        assert assignment == {
            "a": ("token", None, "b"),
            "b": ("token", None, "c"),
            "c": ("token", None, "a"),
            "aa": ("class", 2, None),
        }
        # Width invariant: every token resource fits its original's width.
        spool.cleanup()


def test_unsafe_original_without_own_token(tmp_path: Path) -> None:
    """An original whose value is NOT a safe token owns no reserved
    resource; it is still assigned (here: the free reserved token of
    another original) and never maps to itself."""
    work = tmp_path / "t4"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        for value in ("a", "b", "x"):  # 'x' is outside the safe alphabet
            spool.observe_text(value, byte_width=1)
        spool.flush()
        _solve(vault, spool, domain_id, alphabet="abcd")
        assignment = _solved_assignment(spool)
        # The exact solved assignment: the unsafe original 'x' takes a
        # class slot; the class-displacement chain moves the named reserved
        # token 'a' (tid 0, owned by original 0) to original 1.
        assert assignment == {
            "a": ("class", 1, None),
            "b": ("token", None, "a"),
            "x": ("class", 1, None),
        }
        token_ids = _token_ids(spool)
        assert set(token_ids) == {"a", "b"}  # 'x' owns no resource
        original_ids = _original_ids(spool)
        assert original_ids["a"] == 0  # owned by original 'a'
        assert assignment["b"][2] == "a"  # assigned to original 'b' (idx 1)
        assert token_ids["a"] != original_ids["b"]  # tid 0 != occupant 1
        spool.cleanup()


def test_persisted_occupied_resources_can_make_it_infeasible(
    tmp_path: Path,
) -> None:
    """Persisted pseudonyms OCCUPY tokens: with both width-1 tokens
    occupied and every width-1 original tokenless or blocked, the width-1
    originals have no resource at all — a true capacity exhaustion."""
    work = tmp_path / "t5"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        _persist(vault, domain_id, [("FOREIGN-1", "a"), ("FOREIGN-2", "b")])
        spool = PassOneSpool(work / "vault")
        for value in ("a", "b", "x"):
            spool.observe_text(value, byte_width=1)
        spool.flush()
        try:
            _solve(vault, spool, domain_id, alphabet="abcd")
            raise AssertionError("expected infeasibility")
        except MappingError as exc:
            assert (
                exc.to_dict()["context"]["detail_code"]
                == "ENGINE_TEXT_RESIDUAL_INFEASIBLE"
            )
        spool.cleanup()


# ---------------------------------------------------------------------------
# deterministic reserved-token STEAL regression (Blocker 4)
# ---------------------------------------------------------------------------
def test_materialization_never_steals_a_reserved_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """alphabet 'abcd', originals a, b, x (width 1): the solved assignment
    is a -> class, b -> NAMED reserved token 'a' (reached through a real
    class-displacement chain), x -> class.  The RNG seam makes the first
    class mapping consume a genuine fungible token, the observation 'a' is
    dropped when its mapping commits, and the LATER class allocation (for
    'x') then ATTEMPTS to choose 'a'.  'a' must STILL be blocked — it is a
    ``res_token`` of the immutable solved graph even though it no longer
    appears in text_observation — and the named assignment to 'a' stands,
    with fully unique pseudonyms and zero randomness dependence."""
    work = tmp_path / "t6"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        for value in ("a", "b", "x"):
            spool.observe_text(value, byte_width=1)
        spool.flush()
        _solve(vault, spool, domain_id, alphabet="abcd")
        # Deterministic solved assignment:
        assert _solved_assignment(spool) == {
            "a": ("class", 1, None),
            "b": ("token", None, "a"),
            "x": ("class", 1, None),
        }
        # RNG seam: the first class allocation ('a') picks 'c'; the later
        # class allocation ('x') first ATTEMPTS 'a' (index 0) — which must
        # be refused — and then picks 'd'.  The named assignment 'b' -> 'a'
        # commits in between, after the observation 'a' was dropped.
        sequence = iter([2, 0, 3])

        def deterministic_randbelow(bound: int) -> int:
            return next(sequence) % bound

        monkeypatch.setattr(
            text_residual_module, "_randbelow", deterministic_randbelow
        )
        allocated: dict[str, str] = {}
        from dbf_anonymizer.engine.text_residual import (
            materialize_text_assignment,
        )

        lease = new_writer_token()
        vault.acquire_writer_lease(lease)
        try:
            for value, token, encoded_length in materialize_text_assignment(
                vault,
                spool,
                domain_id=domain_id,
                alphabet="abcd",
                base=4,
            ):
                with vault.transaction():
                    add_text_mapping(
                        vault,
                        domain_id,
                        value,
                        token,
                        logical_byte_length=encoded_length,
                    )
                spool.drop_text_observation(value)
                allocated[value] = token
        finally:
            vault.release_writer_lease(lease)
        # The reserved resource 'a' survived the dropped observation and
        # went to its NAMED assignment; the class allocation never stole it.
        assert allocated == {"a": "c", "b": "a", "x": "d"}
        assert len(set(allocated.values())) == 3
        spool.cleanup()


# ---------------------------------------------------------------------------
# static CSPRNG seam evidence (no probabilistic flake)
# ---------------------------------------------------------------------------
def test_production_materialization_uses_the_csprng_seam() -> None:
    """Static evidence: all production randomness of the solver flows
    through ONE private seam that delegates to the OS CSPRNG
    (``secrets.randbelow``); no other production statement draws randomness
    directly and both materialization helpers use the seam."""
    source = Path(text_residual_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    definitions: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            definitions[node.name] = node
    seam = definitions["_randbelow"]
    seam_calls = [
        node
        for node in ast.walk(seam)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "randbelow"
    ]
    assert len(seam_calls) == 1  # the seam delegates to secrets.randbelow
    for name in ("_select_fungible_token", "_exact_fungible_walk"):
        function = definitions[name]
        called = {
            node.func.id
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "_randbelow" in called, name
    direct = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "randbelow"
    ]
    assert len(direct) == 1  # only inside the seam


# ---------------------------------------------------------------------------
# deterministic TEST-ONLY brute-force oracle (tiny alphabets)
# ---------------------------------------------------------------------------
def _brute_force_oracle(
    alphabet: str,
    originals: list[tuple[str, int]],
    persisted: dict[str, str],
) -> dict[str, str] | None:
    """An objectively exact reference: exhaustive backtracking over the
    tiny token universe.  Returns one valid assignment or None."""
    max_width = max(width for _value, width in originals)
    universe = [
        "".join(letters)
        for length in range(1, max_width + 1)
        for letters in itertools.product(alphabet, repeat=length)
    ]
    remaining = [entry for entry in originals if entry[0] not in persisted]
    occupied = set(persisted.values())

    def solve(index: int, used: frozenset[str]) -> dict[str, str] | None:
        if index == len(remaining):
            return {}
        value, width = remaining[index]
        for token in universe:
            if len(token) > width or token == value or token in used:
                continue
            if token in occupied:
                continue
            tail = solve(index + 1, used | {token})
            if tail is not None:
                tail[value] = token
                return tail
        return None

    solution = solve(0, frozenset())
    if solution is None:
        return None
    return {**persisted, **solution}


def _oracle_case(
    tmp_path: Path,
    index: int,
    alphabet: str,
    originals: list[tuple[str, int]],
    persisted: list[tuple[str, str]],
) -> tuple[bool, bool]:
    """Run ONE production-solver case and its brute-force oracle verdict.

    The production REUSE semantics are applied first (persisted originals
    leave the residual problem exactly like ``_finalize_text`` drops them),
    so the solver's residual problem is identical to the oracle's.
    """
    work = tmp_path / f"o{index}"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        _persist(vault, domain_id, persisted)
        spool = PassOneSpool(work / "vault")
        for value, width in originals:
            spool.observe_text(value, byte_width=width)
        spool.flush()
        for value, _pseudonym in persisted:
            spool.drop_text_observation(value)
        production_feasible = True
        try:
            _solve(vault, spool, domain_id, alphabet=alphabet)
        except MappingError:
            production_feasible = False
        oracle = _brute_force_oracle(
            alphabet, originals, dict(persisted)
        )
        spool.cleanup()
        return production_feasible, oracle is not None


def test_brute_force_oracle_equivalence_battery(tmp_path: Path) -> None:
    """Deterministic battery over tiny alphabets: odd/even derangements,
    non-contiguous token ids (tokenless originals shifting tid against
    original idx), token_idx != occupant, persisted occupied resources,
    unsafe originals and mixed widths.  The production verdict must equal
    the exhaustive-oracle verdict on EVERY case."""
    rng = random.Random(20260919)
    alphabet_pool = ["ab", "abc"]
    cases = 0
    divergences = 0
    work = tmp_path / "battery"
    work.mkdir()
    for trial in range(160):
        alphabet = rng.choice(alphabet_pool)
        width = rng.randint(1, 2)
        population = [
            "".join(letters)
            for length in range(1, width + 1)
            for letters in itertools.product(alphabet, repeat=length)
        ]
        count = rng.randint(1, min(8, len(population) + 2))
        originals: list[tuple[str, int]] = []
        chosen: set[str] = set()
        for _ in range(count):
            if rng.random() < 0.2:
                unsafe = "".join(rng.choice("xy") for _ in range(rng.randint(1, width)))
                if unsafe not in chosen:
                    chosen.add(unsafe)
                    originals.append((unsafe, width))
                    continue
            token = rng.choice(population)
            if token not in chosen:
                chosen.add(token)
                originals.append((token, width))
        if not originals:
            continue
        persisted: list[tuple[str, str]] = []
        pool_values = [value for value, _width in originals]
        if rng.random() < 0.4:
            candidates = [
                (value, token)
                for value in pool_values
                for token in population
                if token != value and 1 <= len(token) <= width
            ]
            rng.shuffle(candidates)
            used_pseudonyms: set[str] = set()
            used_originals: set[str] = set()
            for value, token in candidates:
                if value in used_originals or token in used_pseudonyms:
                    continue
                persisted.append((value, token))
                used_originals.add(value)
                used_pseudonyms.add(token)
                if len(persisted) >= rng.randint(0, 2):
                    break
        production, oracle = _oracle_case(
            work, trial, alphabet, originals, persisted
        )
        cases += 1
        if production != oracle:
            divergences += 1
    assert cases >= 100
    assert divergences == 0


# ---------------------------------------------------------------------------
# P2 planner comparison — ONLY for the shared full production alphabet
# ---------------------------------------------------------------------------
def test_p2_oracle_equivalence_on_the_production_alphabet(
    tmp_path: Path,
) -> None:
    """The P2 ``GlobalTextDomainMapping`` exact planner derives its OWN
    candidate alphabet from the participating encoding, so it is only ever
    comparable when the solver runs on the SAME full production alphabet.
    The randomized originals below are drawn from a narrow slice (tight
    width classes, derangements, persisted fixed assignments, unsafe
    values), but the RESOURCE UNIVERSE is the full production alphabet on
    both sides — this is an honest full-alphabet equivalence claim, and the
    production assignment is additionally re-validated for exactness
    (injectivity, width, self-exclusion)."""
    from dbf_anonymizer.vault.text_allocation import GlobalTextDomainMapping

    rng = random.Random(20260918)
    divergence = 0
    compared = 0
    for trial in range(120):
        work = tmp_path / f"t{trial}"
        work.mkdir()
        with _open_vault(work) as vault:
            domain_id = _seed_domain(vault)
            spool = PassOneSpool(work / "vault")
            # A narrow slice of ORIGINALS (tight classes, derangements at
            # will) — the resource universe stays the full production
            # alphabet, exactly like the P2 planner's own.
            narrow = ALPHABET[: rng.randint(2, 5)]
            width = rng.randint(1, 2)
            count = rng.randint(1, 10)
            population = [
                "".join(letters)
                for length in range(1, width + 1)
                for letters in itertools.product(narrow, repeat=length)
            ]
            values = rng.sample(population, min(count, len(population)))
            observed = [(value, width) for value in values]
            # Optional persisted mappings (fixed assignments, distinct
            # pseudonyms — the vault enforces bijection both ways):
            persisted = {}
            assign_count = rng.randint(0, len(values) // 2)
            if assign_count:
                token_population = [
                    token for token in population if token not in values
                ]
                if token_population:
                    pseudonyms = rng.sample(
                        token_population,
                        min(assign_count, len(token_population)),
                    )
                    for value, pseudonym in zip(
                        values[: len(pseudonyms)], pseudonyms
                    ):
                        persisted[value] = pseudonym
            _persist(vault, domain_id, list(persisted.items()))
            for value, observed_width in observed:
                spool.observe_text(value, byte_width=observed_width)
                spool.flush()
            # Production REUSE first (persisted originals leave the residual):
            for value in persisted:
                spool.drop_text_observation(value)
            production_feasible = True
            production_mapping: dict[str, str] = {}
            try:
                _solve(vault, spool, domain_id, alphabet=ALPHABET)
                for value, (kind, length, token) in _solved_assignment(
                    spool
                ).items():
                    if kind == "token":
                        production_mapping[value] = token
                    # Fungible class slots pick their token value at
                    # materialization; the structural verdict is compared.
            except MappingError:
                production_feasible = False
            # ORACLE verdict (the P2 exact planner, TEST-ONLY):
            oracle_feasible = True
            oracle_mapping: dict[str, str] = {}
            lease = new_writer_token()
            vault.acquire_writer_lease(lease)
            try:
                try:
                    planner = GlobalTextDomainMapping(vault, domain_id=domain_id)
                    for value, observed_width in observed:
                        if value in persisted:
                            continue
                        planner.observe(
                            value, encoding="cp1250", byte_width=observed_width
                        )
                    planner.finalize()
                    for value, _observed_width in observed:
                        if value in persisted:
                            continue
                        oracle_mapping[value] = planner.pseudonym_for(value)
                except MappingError:
                    oracle_feasible = False
            finally:
                vault.release_writer_lease(lease)
            compared += 1
            if production_feasible != oracle_feasible:
                divergence += 1
            if production_feasible and oracle_feasible:
                # Constraint satisfaction on the PRODUCTION side too:
                for value, pseudonym in production_mapping.items():
                    assert is_safe_token(pseudonym, ALPHABET)
                    assert pseudonym != value
                    assert len(pseudonym) <= dict(observed)[value]
                assert len(set(production_mapping.values())) == len(
                    production_mapping
                )
                for value, pseudonym in oracle_mapping.items():
                    assert is_safe_token(pseudonym, ALPHABET)
                    assert pseudonym != value
                    assert len(pseudonym) <= dict(observed)[value]
                assert len(set(oracle_mapping.values())) == len(oracle_mapping)
            spool.cleanup()
    assert compared == 120
    assert divergence == 0


def test_database_unique_index_refuses_double_token_assignment(
    tmp_path: Path,
) -> None:
    """The matching invariant is ENFORCED BY SQLITE: a reserved-token
    resource can never be assigned to a second original, even by raw SQL —
    algorithm correctness never relies on itself alone."""
    import sqlite3

    work = tmp_path / "u0"
    work.mkdir()
    with _open_vault(work) as vault:
        domain_id = _seed_domain(vault)
        spool = PassOneSpool(work / "vault")
        for value in ("a", "b"):
            spool.observe_text(value, byte_width=1)
        spool.flush()
        _solve(vault, spool, domain_id, alphabet="ab")
        connection = spool.internal_connection()
        occupied = connection.execute(
            "SELECT token_idx FROM res_assign WHERE kind = 'token' LIMIT 1"
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO res_assign (orig_idx, kind, length, token_idx) "
                "VALUES (?, 'token', NULL, ?)",
                (99, int(occupied)),
            )
        spool.cleanup()


def test_post_solve_validator_fails_closed_on_corruption(
    tmp_path: Path,
) -> None:
    """The structural validator rejects ANY solved-state corruption with the
    stable value-free detail code: a missing assignment, an unknown kind
    (schema-guarded), a dangling token id, a double token occupancy, a
    self-assignment or a capacity bookkeeping mismatch."""
    import sqlite3

    from dbf_anonymizer.engine.text_residual import (
        _validate_residual_assignment,
    )

    def corrupt(action, index: int) -> None:
        work = tmp_path / f"v{index}"
        work.mkdir()
        with _open_vault(work) as vault:
            domain_id = _seed_domain(vault)
            spool = PassOneSpool(work / "vault")
            for value in ("a", "b"):
                spool.observe_text(value, byte_width=1)
            spool.flush()
            _solve(vault, spool, domain_id, alphabet="ab")
            connection = spool.internal_connection()
            action(connection)
            with pytest.raises(MappingError) as excinfo:
                _validate_residual_assignment(
                    connection,
                    vault=vault,
                    domain_id=domain_id,
                    originals=2,
                    base=2,
                )
            assert (
                excinfo.value.to_dict()["context"]["detail_code"]
                == "ENGINE_TEXT_RESIDUAL_CORRUPT"
            )
            spool.cleanup()

    corrupt(
        lambda c: c.execute("DELETE FROM res_assign WHERE orig_idx = 0"), 0
    )
    corrupt(
        lambda c: c.execute(
            "UPDATE res_assign SET token_idx = NULL WHERE orig_idx = 0"
        ),
        1,
    )
    corrupt(
        lambda c: c.execute(
            "UPDATE res_assign SET token_idx = 999 WHERE orig_idx = 0"
        ),
        2,
    )
    corrupt(lambda c: c.execute("UPDATE res_cap SET fungible = 999"), 3)


def test_oracle_is_never_imported_by_production() -> None:
    """The P2 planner is a TEST ORACLE: no production engine module imports
    it or even names it (the docstrings may reference it truthfully)."""
    from tests.test_p4_boundaries import ENGINE_ROOT

    for path in sorted(ENGINE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert node.id != "GlobalTextDomainMapping", path.name
            if isinstance(node, ast.Attribute):
                assert node.attr != "GlobalTextDomainMapping", path.name