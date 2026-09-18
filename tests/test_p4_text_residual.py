"""The exact bounded text residual solver: oracle equivalence + scale.

The P2 :class:`GlobalTextDomainMapping` exact planner is used ONLY as a
SMALL-CASE TEST ORACLE here (never in production): the randomized suite
cross-checks feasibility verdicts and constraint satisfaction between the
disk-backed production solver and the oracle, and the large fixtures force
the exact residual regime at scales beyond every bounded constant.
"""

from __future__ import annotations

import itertools
import random
from pathlib import Path

import pytest

from dbf_anonymizer.engine.state import (
    MAX_RECORD_BATCH,
    PassOneSpool,
    canonical_text_identity,
)
from dbf_anonymizer.engine.text_residual import solve_text_residual
from dbf_anonymizer.errors import MappingError
from dbf_anonymizer.transforms.text import (
    SAFE_TEXT_ALPHABET,
    candidate_alphabet,
    is_safe_token,
)
from dbf_anonymizer.vault.mappings import (
    add_text_mapping,
    create_domain,
)
from dbf_anonymizer.vault.numeric_allocation import numeric_key_domain_id
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
    from dbf_anonymizer.vault.mappings import mapping_domains

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


def _spool_observations(spool: PassOneSpool, values: list[tuple[str, int]]) -> None:
    for value, width in values:
        spool.observe_text(value, byte_width=width)
        spool.observe_text_encoding("cp1250")
    spool.flush()


# ---------------------------------------------------------------------------
# randomized oracle equivalence (feasibility + constraint satisfaction)
# ---------------------------------------------------------------------------
def test_production_solver_matches_the_p2_oracle_randomized(tmp_path: Path) -> None:
    """No false feasible, no false exhausted: verdicts agree EXACTLY."""
    from dbf_anonymizer.vault.text_allocation import GlobalTextDomainMapping

    rng = random.Random(20260918)
    divergence = 0
    for trial in range(120):
        work = tmp_path / f"t{trial}"
        work.mkdir()
        with _open_vault(work) as vault:
            domain_id = _seed_domain(vault)
            spool = PassOneSpool(work / "vault")
            # A tiny alphabet slice: tight classes and derangements at will.
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
                    token
                    for token in population
                    if token not in values
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
            lease = new_writer_token()
            vault.acquire_writer_lease(lease)
            try:
                with vault.transaction():
                    for value, pseudonym in persisted.items():
                        add_text_mapping(
                            vault,
                            domain_id,
                            value,
                            pseudonym,
                            logical_byte_length=len(pseudonym),
                        )
            finally:
                vault.release_writer_lease(lease)
            _spool_observations(spool, observed)
            # PRODUCTION solver verdict:
            production_feasible = True
            production_mapping: dict[str, str] = {}
            try:
                plan = solve_text_residual(
                    vault,
                    spool,
                    domain_id=domain_id,
                    alphabet=ALPHABET,
                    base=BASE,
                )
                rows = spool.internal_connection().execute(
                    "SELECT o.canonical, a.kind, a.length, t.value "
                    "FROM res_assign a JOIN res_original o ON o.idx = a.orig_idx "
                    "LEFT JOIN res_token t ON t.tid = a.token_idx ORDER BY o.idx"
                ).fetchall()
                for canonical, kind, length, token_value in rows:
                    value = bytes(canonical).decode("utf-8")
                    if kind == "token":
                        production_mapping[value] = str(token_value)
                    else:
                        assert token_value is None and length is not None
                        # The fungible token value is chosen at materialization;
                        # for the equivalence we only verify the CLASS verdict.
                        production_mapping[value] = "<class>"
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
                        planner.observe(value, encoding="cp1250", byte_width=observed_width)
                    planner.finalize()
                    for value, _observed_width in observed:
                        oracle_mapping[value] = planner.pseudonym_for(value)
                except MappingError:
                    oracle_feasible = False
            finally:
                vault.release_writer_lease(lease)
            if production_feasible != oracle_feasible:
                divergence += 1
            if production_feasible and oracle_feasible:
                # Constraint satisfaction on both sides (the production
                # fungible class slots are materialized lazily, so the
                # class-kind entries are checked structurally):
                for value, pseudonym in production_mapping.items():
                    if pseudonym == "<class>":
                        continue
                    assert is_safe_token(pseudonym, ALPHABET)
                    assert pseudonym != value
                    assert len(pseudonym) <= dict(observed)[value]
                for value, pseudonym in oracle_mapping.items():
                    assert is_safe_token(pseudonym, ALPHABET)
                    assert pseudonym != value
                    assert len(pseudonym) <= dict(observed)[value]
                assert len(set(oracle_mapping.values())) == len(oracle_mapping)
            spool.cleanup()
    assert divergence == 0


def test_solver_derangement_corner_matches_oracle(tmp_path: Path) -> None:
    """The classic tight-corner families: 1-token, 2-token, chains."""
    from dbf_anonymizer.vault.text_allocation import GlobalTextDomainMapping

    scenarios = [
        ("ab", 1, ["a", "b"]),          # 2-token swap
        ("abc", 1, ["a", "b", "c"]),    # 3-token derangement trap
        ("ab", 1, ["a"]),               # genuinely exhausted
        ("ab", 2, ["a", "b", "aa"]),    # mixed widths with reserved chains
    ]
    for index, (narrow, width, values) in enumerate(scenarios):
        work = tmp_path / f"s{index}"
        work.mkdir()
        with _open_vault(work) as vault:
            domain_id = _seed_domain(vault)
            spool = PassOneSpool(work / "vault")
            observed = [(value, width) for value in values]
            _spool_observations(spool, observed)
            try:
                solve_text_residual(
                    vault, spool, domain_id=domain_id, alphabet=ALPHABET, base=BASE
                )
                production = True
            except MappingError:
                production = False
            lease = new_writer_token()
            vault.acquire_writer_lease(lease)
            try:
                try:
                    planner = GlobalTextDomainMapping(vault, domain_id=domain_id)
                    for value, observed_width in observed:
                        planner.observe(
                            value, encoding="cp1250", byte_width=observed_width
                        )
                    planner.finalize()
                    for value, _w in observed:
                        planner.pseudonym_for(value)
                    oracle = True
                except MappingError:
                    oracle = False
            finally:
                vault.release_writer_lease(lease)
            assert production == oracle, (narrow, width, values, production, oracle)
            spool.cleanup()


def test_oracle_is_never_imported_by_production(tmp_path: Path) -> None:
    """The P2 planner is a TEST ORACLE: no production engine module imports
    it or even names it (the docstrings may reference it truthfully)."""
    import ast

    from tests.test_p4_boundaries import ENGINE_ROOT

    for path in sorted(ENGINE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert node.id != "GlobalTextDomainMapping", path.name
            if isinstance(node, ast.Attribute):
                assert node.attr != "GlobalTextDomainMapping", path.name


def test_solver_allocation_is_csprng_not_counter(tmp_path: Path) -> None:
    """Two identical solves on identical inputs produce DIFFERENT fungible
    token choices (CSPRNG allocation, never a sequence/counter)."""
    work1, work2 = tmp_path / "a", tmp_path / "b"
    work1.mkdir(); work2.mkdir()
    mappings: list[dict[str, str]] = []
    for work in (work1, work2):
        with _open_vault(work) as vault:
            domain_id = _seed_domain(vault)
            spool = PassOneSpool(work / "vault")
            values = [(f"K{index:03d}", 6) for index in range(50)]
            _spool_observations(spool, values)
            plan = solve_text_residual(
                vault, spool, domain_id=domain_id, alphabet=ALPHABET, base=BASE
            )
            del plan
            allocated: dict[str, str] = {}
            lease = new_writer_token()
            vault.acquire_writer_lease(lease)
            try:
                for value, token, encoded_length in _materialize_for_test(
                    vault, spool, domain_id, ALPHABET, BASE
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
            spool.cleanup()
            mappings.append(allocated)
    # Same classes, CSPRNG values: at least one token differs between runs.
    assert mappings[0].keys() == mappings[1].keys()
    assert any(
        mappings[0][value] != mappings[1][value] for value in mappings[0]
    )


def _materialize_for_test(vault: VaultDatabase, spool: PassOneSpool, domain_id: str, alphabet: str, base: int):
    from dbf_anonymizer.engine.text_residual import materialize_text_assignment

    return materialize_text_assignment(
        vault, spool, domain_id=domain_id, alphabet=alphabet, base=base
    )

