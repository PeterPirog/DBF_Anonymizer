"""Global-assignment regression evidence for the PR #25 repair (REQ-P2-004/005/006).

The reviewed PR #25 HEAD (a4863e7) allocated greedily per ``pseudonym_for``
call: a greedy choice could consume capacity that a later stricter finalized
original still needed, producing FALSE ``MAPPING_CAPACITY_EXHAUSTED`` errors
for domains that have a valid global bijective assignment.

The counterexamples below are deterministic and FAIL on the reviewed HEAD:

* COUNTEREXAMPLE A — nested width pools: 36 width-1 originals plus one
  width-2 original. Requesting WIDE first lets the greedy allocator take a
  one-character token, so the last narrow original falsely exhausts.
* COUNTEREXAMPLE B — self-token dead-end: 35 flexible width-1 originals plus
  the original ``"C"``. Greedy consumption of every token except ``"C"``
  leaves ``"C"`` with only its own forbidden self-token.

The repaired allocator plans the COMPLETE finalized residual problem (all
unpersisted originals, all fixed persisted mappings, all strictest widths,
self-exclusions, bijection) before persisting anything, so a feasible domain
stays feasible regardless of the request order, and exhaustion is raised only
when the remaining problem is genuinely infeasible.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

import dbf_anonymizer.transforms.text as text_kernels
from dbf_anonymizer import ErrorCode, MappingError
from dbf_anonymizer.vault import (
    GLOBAL_TEXT_DOMAIN_ID,
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    mappings,
)
from dbf_anonymizer.vault.text_allocation import GlobalTextDomainMapping
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60
DBFBRIDGE_VERSION = "1.1.0"


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


class _ScriptedRandom:
    """Deterministic private randomness seam; *cycle* repeats the script.

    A scripted value is consumed as ``value % bound`` so a single script can
    serve calls with varying moduli (values below the bound are unchanged).
    """

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


def _allocator(
    vault: VaultDatabase, stream: _ScriptedRandom | None = None
) -> GlobalTextDomainMapping:
    return GlobalTextDomainMapping(
        vault, _random_below=(stream.__call__ if stream is not None else None)
    )


def _seed_global_domain_rows(
    vault: VaultDatabase, rows: list[tuple[str, str, int]]
) -> None:
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


def _global_rows(vault: VaultDatabase) -> tuple[tuple[str, str, int], ...]:
    return mappings.text_mapping_rows(vault, GLOBAL_TEXT_DOMAIN_ID)


# ---------------------------------------------------------------------------
# COUNTEREXAMPLE A — nested width pools (must fail on reviewed HEAD a4863e7)
# ---------------------------------------------------------------------------
def test_counterexample_a_wide_first_must_not_steal_narrow_capacity(
    tmp_path: Path,
) -> None:
    narrow = [f"NARROW-{index:02d}" for index in range(36)]
    # Deterministic seam: under the reviewed greedy HEAD, WIDE requested
    # first selects the one-character token "A" (index 0 of the open width-2
    # space), and the narrow requests then consume "B".."9" — the 36th narrow
    # original falsely exhausts. The repaired allocator plans WIDE into the
    # width-2 pool, so the same stream serves all 37 originals.
    stream = _ScriptedRandom(0, *range(1, 36), 0, cycle=True)
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(
                vault, _random_below=stream.__call__
            )
            for original in narrow:
                allocator.observe(original, encoding="cp1250", byte_width=1)
            allocator.observe("WIDE-ORIGINAL", encoding="cp1250", byte_width=2)
            allocator.finalize()
            wide_pseudonym = allocator.pseudonym_for("WIDE-ORIGINAL")
            results = [allocator.pseudonym_for(original) for original in narrow]
        rows = dict((original, pseudonym) for original, pseudonym, _l in _global_rows(vault))
        assert len(rows) == 37
        assert len(set(rows.values())) == 37  # bijection
        for original in narrow:
            pseudonym = rows[original]
            assert len(pseudonym) == 1  # width-1 capacity respected
            assert pseudonym != original  # no self mapping
        assert rows["WIDE-ORIGINAL"] == wide_pseudonym
        assert len(wide_pseudonym) <= 2  # width-2 capacity respected
        assert wide_pseudonym != "WIDE-ORIGINAL"


def test_counterexample_a_narrow_first_order_independent(tmp_path: Path) -> None:
    # The same finalized domain is feasible regardless of the request order.
    narrow = [f"NARROW-{index:02d}" for index in range(36)]
    stream = _ScriptedRandom(*range(36), 0, cycle=True)
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=stream.__call__)
            for original in narrow:
                allocator.observe(original, encoding="cp1250", byte_width=1)
            allocator.observe("WIDE-ORIGINAL", encoding="cp1250", byte_width=2)
            allocator.finalize()
            results = [allocator.pseudonym_for(original) for original in narrow]
            wide_pseudonym = allocator.pseudonym_for("WIDE-ORIGINAL")
        rows = dict((original, pseudonym) for original, pseudonym, _l in _global_rows(vault))
        assert len(rows) == 37
        assert len(set(rows.values())) == 37
        assert all(len(rows[original]) == 1 for original in narrow)
        assert len(rows["WIDE-ORIGINAL"]) <= 2


# ---------------------------------------------------------------------------
# COUNTEREXAMPLE B — self-token dead-end (must fail on reviewed HEAD a4863e7)
# ---------------------------------------------------------------------------
def test_counterexample_b_self_token_dead_end_is_globally_solved(
    tmp_path: Path,
) -> None:
    # 35 flexible originals (none is a one-character token) plus the original
    # "C". Greedy consumption of every token except "C" leaves "C" with only
    # its own forbidden self-token; a valid complete assignment exists.
    flexible = [f"FLEX-{index:02d}" for index in range(35)]
    # "C" is alphabet index 2; the 35 scripted indices are exactly all other
    # one-character tokens, so under the old greedy algorithm the flexible
    # requests consume every token except "C" and "C" falsely exhausts.
    stream = _ScriptedRandom(*[v for v in range(36) if v != 2], cycle=True)
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=stream.__call__)
            for original in flexible:
                allocator.observe(original, encoding="cp1250", byte_width=1)
            allocator.observe("C", encoding="cp1250", byte_width=1)
            allocator.finalize()
            assigned = [allocator.pseudonym_for(original) for original in flexible]
            c_pseudonym = allocator.pseudonym_for("C")
        rows = dict((original, pseudonym) for original, pseudonym, _l in _global_rows(vault))
        assert len(rows) == 36
        assert len(set(rows.values())) == 36  # bijection, no duplicates
        assert all(len(pseudonym) == 1 for pseudonym in rows.values())
        assert rows["C"] == c_pseudonym and c_pseudonym != "C"  # never self-mapped
        for original in flexible:
            assert rows[original] == dict(zip(flexible, assigned))[original]
            assert rows[original] != original


# ---------------------------------------------------------------------------
# self-token original requested FIRST (order-independence matrix, case 3)
# ---------------------------------------------------------------------------
def test_self_token_original_first_still_feasible(tmp_path: Path) -> None:
    flexible = [f"FLEX-{index:02d}" for index in range(35)]
    stream = _ScriptedRandom(0, 1, 3, 4, 5, 6, 7, 9, cycle=True)
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault, _random_below=stream.__call__)
            allocator.observe("C", encoding="cp1250", byte_width=1)
            for original in flexible:
                allocator.observe(original, encoding="cp1250", byte_width=1)
            allocator.finalize()
            c_pseudonym = allocator.pseudonym_for("C")
            assigned = [allocator.pseudonym_for(original) for original in flexible]
        rows = dict((original, pseudonym) for original, pseudonym, _l in _global_rows(vault))
        assert len(rows) == 36 and len(set(rows.values())) == 36
        assert rows["C"] == c_pseudonym and c_pseudonym != "C"


# ---------------------------------------------------------------------------
# persisted prefix + remaining allocation (order-independence matrix, case 7)
# ---------------------------------------------------------------------------
def test_persisted_prefix_is_completed_regardless_of_request_order(
    tmp_path: Path,
) -> None:
    # A legitimate persisted prefix of an earlier operation (34 one-character
    # tokens) is FIXED and never remapped. The remaining finalized originals
    # — a flexible width-1 original, the self-token original "Q" (the token
    # "Q" is still free) and a width-2 original — must be planned around the
    # fixed prefix in EITHER request order.
    prefix = [
        (f"PREFIX-{index:02d}", ch, 1)
        for index, ch in enumerate(text_kernels.SAFE_TEXT_ALPHABET)
        if ch not in ("P", "Q")
    ]
    remaining = ("WIDE-ORIGINAL", "Q", "FLEX-00")
    for order in ((0, 1, 2), (2, 1, 0), (1, 2, 0)):
        with _create(tmp_path / f"order-{order[0]}-{order[1]}-{order[2]}") as vault:
            _seed_global_domain_rows(vault, list(prefix))
            with writer_session(vault):
                allocator = GlobalTextDomainMapping(vault)
                allocator.observe("WIDE-ORIGINAL", encoding="cp1250", byte_width=2)
                allocator.observe("Q", encoding="cp1250", byte_width=1)
                allocator.observe("FLEX-00", encoding="cp1250", byte_width=1)
                allocator.finalize()
                results = [allocator.pseudonym_for(remaining[i]) for i in order]
            rows = dict(
                (original, pseudonym) for original, pseudonym, _l in _global_rows(vault)
            )
            assert len(rows) == 34 + 3
            assert len(set(rows.values())) == 34 + 3
            for original in remaining:
                assert rows[original] != original  # no self mapping
            assert len(rows["Q"]) == 1
            assert len(rows["FLEX-00"]) == 1
            assert len(rows["WIDE-ORIGINAL"]) <= 2


def test_persisted_prefix_without_completion_fails_truthfully(
    tmp_path: Path,
) -> None:
    # A persisted prefix that leaves the remaining finalized problem with no
    # completion is genuinely infeasible: the typed exhaustion is truthful
    # (the prefix itself stays fixed and is never remapped).
    prefix = [
        (f"PREFIX-{index:02d}", ch, 1)
        for index, ch in enumerate(text_kernels.SAFE_TEXT_ALPHABET)
    ]
    with _create(tmp_path) as vault:
        _seed_global_domain_rows(vault, list(prefix))
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault)
            allocator.observe("STRANDED", encoding="cp1250", byte_width=1)
            allocator.finalize()
            with pytest.raises(MappingError) as excinfo:
                allocator.pseudonym_for("STRANDED")
            assert excinfo.value.code is ErrorCode.MAPPING_CAPACITY_EXHAUSTED
            rows = _global_rows(vault)
            assert len(rows) == 36  # the prefix is intact, nothing was added