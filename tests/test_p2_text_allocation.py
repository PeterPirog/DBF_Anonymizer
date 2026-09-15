"""REQ-P2-004/005/006 — secure global text mapping allocation evidence.

Covers the three text-domain requirements on top of the existing SQLite
vault foundation:

* REQ-P2-004 — CSPRNG boundary, private deterministic injection seam,
  fresh-vault controlled independence, same-vault close/reopen reuse
  (without a generator call), truthful collision handling (injected
  collision streaks, bounded probe budget with exact completion, no false
  exhaustion, no infinite loop) and exact domain exhaustion;
* REQ-P2-005 — the ONE global text mapping domain: the same exact non-empty
  original receives the same pseudonym across fields, tables and directory
  paths; distinct originals map bijectively; NULL and "" stay preserved and
  never create a normal sensitive mapping row; exact identity keeps
  ``"ABC"``, ``"ABC "``, ``"ABC  "`` and ``"abc"`` distinct;
* REQ-P2-006 — collect/finalize/allocate/reuse lifecycle (no allocation
  before finalization), order-independent strictest widths, persisted
  mappings revalidated (never silently remapped), actual encoded byte
  lengths, cp1250/cp852 fixture allocation, Mazovia/PIAST fail-closed
  handling of unprovable encodings, width-1/width-2 capacity boundaries,
  self-exclusion and privacy-safe typed errors.

Only synthetic state, committed synthetic fixtures and the public
``dbfbridge`` API are used; no production data is touched.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Callable

import pytest
from dbfbridge import iter_records, read_schema

import dbf_anonymizer.transforms.text as text_kernels
from dbf_anonymizer import ErrorCode, MappingError, VaultError
from dbf_anonymizer.vault import (
    GLOBAL_TEXT_DOMAIN_ID,
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    mappings,
    new_writer_token,
)
from dbf_anonymizer.vault.text_allocation import (
    GLOBAL_TEXT_PROBE_BUDGET,
    GlobalTextDomainMapping,
)
from support.vault_sessions import error_boundary_payload, writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60
DBFBRIDGE_VERSION = "1.1.0"

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "p0"

#: Synthetic privacy canaries that must never appear in any public error.
CANARY_ORIGINAL = "CANARY_ORIGINAL_SECRET_VALUE"
CANARY_PSEUDONYM = "CANARY_PSEUDONYM_SECRET_VALUE"


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
    """Deterministic private randomness injection seam for tests.

    Every call consumes the next scripted value and records the requested
    modulus, so the evidence can prove exactly which CSPRNG decisions the
    allocator made (and that reuse never calls the generator).
    """

    def __init__(self, *values: int) -> None:
        self._values = list(values)
        self.moduli: list[int] = []

    def __call__(self, bound: int) -> int:
        self.moduli.append(bound)
        if not self._values:
            raise AssertionError("scripted random stream exhausted unexpectedly")
        value = self._values.pop(0)
        assert 0 <= value < bound, f"scripted value {value} outside [0, {bound})"
        return value

    @property
    def calls(self) -> list[int]:
        return list(self.moduli)


def _allocator(
    vault: VaultDatabase, stream: _ScriptedRandom | None = None
) -> GlobalTextDomainMapping:
    return GlobalTextDomainMapping(
        vault, _random_below=(stream.__call__ if stream is not None else None)
    )


def _seed_global_domain_rows(
    vault: VaultDatabase, rows: list[tuple[str, str, int]]
) -> None:
    """Persist seed rows of the global text domain BEFORE finalization."""
    with writer_session(vault), vault.transaction():
        mappings.create_domain(
            vault,
            domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT,
            domain_id=GLOBAL_TEXT_DOMAIN_ID,
        )
        for original, pseudonym, length in rows:
            mappings.add_text_mapping(
                vault, GLOBAL_TEXT_DOMAIN_ID, original, pseudonym, logical_byte_length=length
            )


def _single_char_tokens_without(excluded: str) -> list[str]:
    return [ch for ch in text_kernels.SAFE_TEXT_ALPHABET if ch != excluded]


def _global_rows(vault: VaultDatabase) -> tuple[tuple[str, str, int], ...]:
    return mappings.text_mapping_rows(vault, GLOBAL_TEXT_DOMAIN_ID)


def get_text_pseudonym_of(vault: VaultDatabase, original: str) -> str | None:
    return mappings.get_text_pseudonym(vault, GLOBAL_TEXT_DOMAIN_ID, original)


def _text_domain_count(vault: VaultDatabase) -> int:
    return sum(
        1
        for row in mappings.mapping_domains(vault)
        if row["domain_kind"] == mappings.VAULT_TABLE_DOMAIN_KIND_TEXT
    )


# ---------------------------------------------------------------------------
# REQ-P2-004 — CSPRNG boundary, seam, freshness, reuse
# ---------------------------------------------------------------------------
def test_production_randomness_is_bound_to_the_os_csprng(tmp_path: Path) -> None:
    import dbf_anonymizer.vault.text_allocation as allocation_module

    with _create(tmp_path) as vault:
        allocator = _allocator(vault)
        assert allocator._random_below is secrets.randbelow
        assert allocation_module.GLOBAL_TEXT_PROBE_BUDGET > 0
        with writer_session(vault):
            allocator.observe(CANARY_ORIGINAL, encoding="cp1250", byte_width=6)
            allocator.finalize()
            pseudonym = allocator.pseudonym_for(CANARY_ORIGINAL)
        assert pseudonym != CANARY_ORIGINAL  # never the unchanged original
        assert text_kernels.is_safe_token(pseudonym, allocator.alphabet or "")
        assert len(pseudonym) <= 6


def test_fresh_vault_output_is_controlled_by_the_injected_random_stream(
    tmp_path: Path,
) -> None:
    originals = ["CUSTOMER-A", "CUSTOMER-B", "CUSTOMER-C"]
    mappings_a: dict[str, str] = {}
    mappings_b: dict[str, str] = {}
    mappings_c: dict[str, str] = {}
    with _create(tmp_path / "a") as vault:
        with writer_session(vault):
            allocator = _allocator(vault, _ScriptedRandom(0, 1, 2))
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=8)
            allocator.finalize()
            mappings_a = {o: allocator.pseudonym_for(o) for o in originals}
    with _create(tmp_path / "b") as vault:
        with writer_session(vault):
            allocator = _allocator(vault, _ScriptedRandom(0, 1, 2))
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=8)
            allocator.finalize()
            mappings_b = {o: allocator.pseudonym_for(o) for o in originals}
    with _create(tmp_path / "c") as vault:
        with writer_session(vault):
            allocator = _allocator(vault, _ScriptedRandom(10, 11, 12))
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=8)
            allocator.finalize()
            mappings_c = {o: allocator.pseudonym_for(o) for o in originals}
    # The fresh-vault output is a function of the RANDOM STREAM (proven by
    # identical streams -> identical fresh mappings); different controlled
    # streams -> different pseudonyms for the same originals (the mapping is
    # therefore NOT derived from the original values).
    assert mappings_a == mappings_b
    assert mappings_a != mappings_c
    assert set(mappings_a.values()).isdisjoint(set(mappings_c.values()))


def test_production_fresh_vaults_are_independently_randomized(tmp_path: Path) -> None:
    # Secondary (non-sole) evidence with the real OS CSPRNG: six originals in
    # a width-2 domain can never repeat the exact same six-token sample in a
    # second fresh vault in practice; the primary proof is the controlled
    # stream test above.
    originals = [f"PROD-{index:03d}" for index in range(6)]
    first: list[str] = []
    second: list[str] = []
    for root in ("p1", "p2"):
        with _create(tmp_path / root) as vault:
            with writer_session(vault):
                allocator = _allocator(vault)
                for original in originals:
                    allocator.observe(original, encoding="cp1250", byte_width=2)
                allocator.finalize()
                allocated = [allocator.pseudonym_for(o) for o in originals]
                if root == "p1":
                    first = allocated
                else:
                    second = allocated
    assert len(set(first)) == 6 and len(set(second)) == 6
    assert all(
        text_kernels.is_safe_token(p, text_kernels.SAFE_TEXT_ALPHABET)
        for p in first + second
    )
    assert first != second


def test_reopening_the_same_vault_reuses_persisted_mapping_without_generator(
    tmp_path: Path,
) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault, _ScriptedRandom(4, 5, 6))
            for original in ("KEY-1", "KEY-2", "KEY-3"):
                allocator.observe(original, encoding="cp1250", byte_width=9)
            allocator.finalize()
            allocated = [allocator.pseudonym_for(o) for o in ("KEY-1", "KEY-2", "KEY-3")]
            assert len(set(allocated)) == 3
    with _reopen(tmp_path) as reopened:
        # NO writer lease: reuse is read-only evidence on its own.
        stream = _ScriptedRandom()
        allocator = _allocator(reopened, stream)
        for original in ("KEY-1", "KEY-2", "KEY-3"):
            allocator.observe(original, encoding="cp1250", byte_width=9)
        allocator.finalize()
        reused = [allocator.pseudonym_for(o) for o in ("KEY-1", "KEY-2", "KEY-3")]
        assert reused == allocated
        assert stream.calls == []  # the generator is never called on reuse


def test_in_session_reuse_skips_the_generator(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            stream = _ScriptedRandom(2)
            allocator = _allocator(vault, stream)
            allocator.observe("REPEAT-ME", encoding="cp1250", byte_width=5)
            allocator.finalize()
            first = allocator.pseudonym_for("REPEAT-ME")
            calls_after_allocation = len(stream.calls)
            second = allocator.pseudonym_for("REPEAT-ME")
            assert first == second
            assert len(stream.calls) == calls_after_allocation


def test_injected_collision_streak_then_free_candidate(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        _seed_global_domain_rows(vault, [("SEED-0", "A", 1)])
        with writer_session(vault):
            stream = _ScriptedRandom(0, 0, 1)
            allocator = _allocator(vault, stream)
            allocator.observe("COLLIDER", encoding="cp1250", byte_width=1)
            allocator.finalize()
            pseudonym = allocator.pseudonym_for("COLLIDER")
        # The two injected candidates collide with the occupied token "A";
        # the third draw hits the free candidate "B". No exhaustion is ever
        # claimed for a random collision.
        assert pseudonym == "B"
        assert stream.calls == [36, 36, 36]


def test_bounded_probe_budget_never_raises_exhaustion(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        _seed_global_domain_rows(vault, [("SEED-0", "A", 1)])
        with writer_session(vault):
            # A full budget of collisions is a PERFORMANCE event, never an
            # exhaustion claim: the exact completion phase then allocates
            # with certainty from the remaining free tokens.
            collisions = [0] * GLOBAL_TEXT_PROBE_BUDGET
            stream = _ScriptedRandom(*collisions, 0)
            allocator = _allocator(vault, stream)
            allocator.observe("BUDGET-EDGE", encoding="cp1250", byte_width=2)
            allocator.finalize()
            pseudonym = allocator.pseudonym_for("BUDGET-EDGE")
            assert pseudonym == "B"  # first free token (blocked = {"A"} -> 0)
            assert len(stream.calls) == GLOBAL_TEXT_PROBE_BUDGET + 1
            assert stream.calls[-1] == 36 + 36 * 36 - 1  # the free-token count


def test_exact_full_exhaustion_is_typed_and_creates_no_row(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        rows = [
            (f"SEED-{index:02d}", ch, 1)
            for index, ch in enumerate(text_kernels.SAFE_TEXT_ALPHABET)
        ]
        _seed_global_domain_rows(vault, rows)
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe(CANARY_ORIGINAL, encoding="cp1250", byte_width=1)
            allocator.finalize()
            before = len(_global_rows(vault))
            with pytest.raises(MappingError) as excinfo:
                allocator.pseudonym_for(CANARY_ORIGINAL)
            assert excinfo.value.code is ErrorCode.MAPPING_CAPACITY_EXHAUSTED
            payload = error_boundary_payload(excinfo.value)
            assert CANARY_ORIGINAL not in payload
            assert CANARY_PSEUDONYM not in payload
            assert len(_global_rows(vault)) == before  # no row was created


def test_near_full_domain_with_exactly_one_free_candidate(tmp_path: Path) -> None:
    missing = "Q7"
    with _create(tmp_path) as vault:
        rows = [
            (f"SEED-{index:02d}", ch, 1)
            for index, ch in enumerate(_single_char_tokens_without(missing[0]))
        ]
        _seed_global_domain_rows(vault, rows)
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("LAST-FREE-SEEKER", encoding="cp1250", byte_width=1)
            allocator.finalize()
            assert allocator.pseudonym_for("LAST-FREE-SEEKER") == missing[0]


def test_self_exclusion_counts_against_available_capacity(tmp_path: Path) -> None:
    # The only otherwise free token equals the original itself: the domain
    # is exhausted (self-exclusion counts), never self-mapped.
    with _create(tmp_path) as vault:
        rows = [
            (f"SEED-{index:02d}", ch, 1)
            for index, ch in enumerate(_single_char_tokens_without("Q"))
        ]
        _seed_global_domain_rows(vault, rows)
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("Q", encoding="cp1250", byte_width=1)
            allocator.finalize()
            before = len(_global_rows(vault))
            with pytest.raises(MappingError) as excinfo:
                allocator.pseudonym_for("Q")
            assert excinfo.value.code is ErrorCode.MAPPING_CAPACITY_EXHAUSTED
            assert len(_global_rows(vault)) == before


def test_self_candidate_is_rejected_and_allocation_continues(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        free = ["Q", "R"]
        rows = [
            (f"SEED-{index:02d}", ch, 1)
            for index, ch in enumerate(text_kernels.SAFE_TEXT_ALPHABET)
            if ch not in free
        ]
        _seed_global_domain_rows(vault, rows)
        with writer_session(vault):
            # The only probe result is the forbidden self-candidate "Q"
            # (alphabet index 16); the budget runs out and the exact
            # completion phase picks the remaining free token "R".
            stream = _ScriptedRandom(*[16] * GLOBAL_TEXT_PROBE_BUDGET, 0)
            allocator = _allocator(vault, stream)
            allocator.observe("Q", encoding="cp1250", byte_width=1)
            allocator.finalize()
            assert allocator.pseudonym_for("Q") == "R"
            assert len(stream.calls) == GLOBAL_TEXT_PROBE_BUDGET + 1
            stored = {pseudonym for _o, pseudonym, _l in _global_rows(vault)}
            assert "Q" not in stored and "R" in stored


# ---------------------------------------------------------------------------
# REQ-P2-005 — the ONE global text mapping domain
# ---------------------------------------------------------------------------
def test_same_original_in_two_fields_shares_one_pseudonym(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        _seed_global_domain_rows(vault, [])  # the global domain row exists first
        with writer_session(vault):
            with vault.transaction():
                table_id = vault.register_table("data/customers.dbf", schema_fingerprint="fp-a")
                for name in ("NAME", "CITY"):
                    vault.register_field(
                        table_id,
                        name,
                        dbf_type="C",
                        width=10,
                        transform_action="PSEUDONYMIZE_REVERSIBLE",
                        mapping_domain_id=GLOBAL_TEXT_DOMAIN_ID,
                    )
            allocator = _allocator(vault)
            allocator.observe("JOINT-VALUE", encoding="cp1250", byte_width=10)
            allocator.observe("JOINT-VALUE", encoding="cp1250", byte_width=10)
            allocator.finalize()
            first = allocator.pseudonym_for("JOINT-VALUE")
            second = allocator.pseudonym_for("JOINT-VALUE")
            assert first == second
            assert len(_global_rows(vault)) == 1


def test_same_original_in_two_tables_and_directories_shares_one_pseudonym(
    tmp_path: Path,
) -> None:
    with _create(tmp_path) as vault:
        _seed_global_domain_rows(vault, [])  # the global domain row exists first
        with writer_session(vault), vault.transaction():
            north = vault.register_table("north/registry/orders.dbf", schema_fingerprint="fp-n")
            south = vault.register_table("south/registry/orders.dbf", schema_fingerprint="fp-s")
            for table_id in (north, south):
                vault.register_field(
                    table_id,
                    "KEY",
                    dbf_type="C",
                    width=8,
                    transform_action="PSEUDONYMIZE_REVERSIBLE",
                    mapping_domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("KEY0001", encoding="cp1250", byte_width=8)
            allocator.finalize()
            pseudonym = allocator.pseudonym_for("KEY0001")
            # Duplicate basenames in different directories stay ONE text domain:
            # the domain identity is the dataset-wide constant, never a
            # table/directory basename.
            text_domains = [
                row
                for row in mappings.mapping_domains(vault)
                if row["domain_kind"] == mappings.VAULT_TABLE_DOMAIN_KIND_TEXT
            ]
            assert [row["domain_id"] for row in text_domains] == [GLOBAL_TEXT_DOMAIN_ID]
            assert get_text_pseudonym_of(vault, "KEY0001") == pseudonym


def test_distinct_originals_map_bijectively(tmp_path: Path) -> None:
    originals = [f"NAME-{index:02d}" for index in range(12)]
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=7)
            allocator.finalize()
            pseudonyms = [allocator.pseudonym_for(o) for o in originals]
        assert len(set(pseudonyms)) == 12
        for original, pseudonym in zip(originals, pseudonyms):
            assert get_text_pseudonym_of(vault, original) == pseudonym
            assert mappings.get_text_original(vault, GLOBAL_TEXT_DOMAIN_ID, pseudonym) == original


def test_null_and_empty_never_create_mapping_rows(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            with pytest.raises(TypeError):
                allocator.observe(None, encoding="cp1250", byte_width=4)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                allocator.observe("", encoding="cp1250", byte_width=4)
            allocator.observe("REAL-VALUE", encoding="cp1250", byte_width=4)
            allocator.finalize()
            allocator.pseudonym_for("REAL-VALUE")
            with pytest.raises(TypeError):
                allocator.pseudonym_for(None)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                allocator.pseudonym_for("")
            rows = _global_rows(vault)
            assert [original for original, _p, _l in rows] == ["REAL-VALUE"]


def test_exact_identity_distinguishes_trailing_spaces_and_case(tmp_path: Path) -> None:
    originals = ("ABC", "ABC ", "ABC  ", "abc")
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=6)
            allocator.finalize()
            first = {o: allocator.pseudonym_for(o) for o in originals}
        assert len(set(first.values())) == 4  # no normalization of any kind
    with _reopen(tmp_path) as reopened:
        with writer_session(reopened):
            allocator = _allocator(reopened)
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=6)
            allocator.finalize()
            second = {o: allocator.pseudonym_for(o) for o in originals}
        assert second == first  # exact identity is stable across reopen


def test_global_domain_identity_is_stable_and_value_independent(tmp_path: Path) -> None:
    assert GLOBAL_TEXT_DOMAIN_ID.startswith("dom-")
    assert len(GLOBAL_TEXT_DOMAIN_ID) == len("dom-") + 16
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("ANY-1", encoding="cp1250", byte_width=4)
            allocator.finalize()
    with _reopen(tmp_path) as reopened:
        with writer_session(reopened):
            # Re-finalization is idempotent at the domain level: reopening
            # reuses the SAME stable domain row instead of creating another.
            allocator = _allocator(reopened)
            allocator.observe("ANY-1", encoding="cp1250", byte_width=4)
            allocator.finalize()
        text_domains = [
            row
            for row in mappings.mapping_domains(reopened)
            if row["domain_kind"] == mappings.VAULT_TABLE_DOMAIN_KIND_TEXT
        ]
        assert [row["domain_id"] for row in text_domains] == [GLOBAL_TEXT_DOMAIN_ID]


# ---------------------------------------------------------------------------
# REQ-P2-006 — constraints, finalization, byte feasibility
# ---------------------------------------------------------------------------
def test_allocation_is_refused_before_finalization(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            with pytest.raises(ValueError):
                allocator.pseudonym_for("TOO-EARLY")
            assert _global_rows(vault) == ()  # no mapping before finalization
            allocator.observe("TOO-EARLY", encoding="cp1250", byte_width=4)
            with pytest.raises(ValueError):
                allocator.pseudonym_for("TOO-EARLY")
            assert _global_rows(vault) == ()
            allocator.finalize()
            with pytest.raises(ValueError):
                allocator.observe("LATER", encoding="cp1250", byte_width=4)
            with pytest.raises(ValueError):
                allocator.finalize()


def test_strictest_width_is_order_independent(tmp_path: Path) -> None:
    results: list[int] = []
    for order in ("narrow-last", "narrow-first"):
        with _create(tmp_path / order) as vault:
            with writer_session(vault):
                allocator = _allocator(vault)
                widths = (2, 1) if order == "narrow-last" else (1, 2)
                for width in widths:
                    allocator.observe("ORDER-KEY", encoding="cp1250", byte_width=width)
                allocator.finalize()
                pseudonym = allocator.pseudonym_for("ORDER-KEY")
                assert len(pseudonym) == 1  # strictest width 1 in BOTH orders
                results.append(len(pseudonym))
    assert results == [1, 1]


def test_stricter_later_constraint_fails_closed_without_remap(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            # A deliberately LONG persisted pseudonym (full width-10 token)
            # becomes incompatible with the later stricter width-2 field.
            allocator = _allocator(vault, _ScriptedRandom(text_kernels.token_space(9, 36)))
            allocator.observe("WIDENED-KEY", encoding="cp1250", byte_width=10)
            allocator.finalize()
            first = allocator.pseudonym_for("WIDENED-KEY")
            assert len(first) == 10
    with _reopen(tmp_path) as reopened:
        with writer_session(reopened):
            allocator = _allocator(reopened)
            allocator.observe("WIDENED-KEY", encoding="cp1250", byte_width=2)
            with pytest.raises(MappingError) as excinfo:
                allocator.finalize()
            assert excinfo.value.code is ErrorCode.MAPPING_CONFLICT
            payload = error_boundary_payload(excinfo.value)
            assert "WIDENED-KEY" not in payload and first not in payload
            # The persisted mapping is NEVER silently remapped.
            assert get_text_pseudonym_of(reopened, "WIDENED-KEY") == first
            assert len(_global_rows(reopened)) == 1


def test_compatible_later_constraints_reuse_persisted_mapping(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault, _ScriptedRandom(3))
            allocator.observe("STABLE-KEY", encoding="cp1250", byte_width=8)
            allocator.finalize()
            first = allocator.pseudonym_for("STABLE-KEY")
    with _reopen(tmp_path) as reopened:
        stream = _ScriptedRandom()
        with writer_session(reopened):
            allocator = _allocator(reopened, stream)
            allocator.observe("STABLE-KEY", encoding="cp1250", byte_width=8)
            allocator.finalize()
            assert allocator.pseudonym_for("STABLE-KEY") == first
        assert stream.calls == []  # reuse, not a new allocation


def test_encoded_byte_lengths_are_validated_and_persisted(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("MIXED-1", encoding="cp1250", byte_width=6)
            allocator.observe("MIXED-1", encoding="cp852", byte_width=6)
            allocator.finalize()
            pseudonym = allocator.pseudonym_for("MIXED-1")
        rows = _global_rows(vault)
        assert len(rows) == 1
        stored_length = rows[0][2]
        assert stored_length == len(pseudonym.encode("cp1250", "strict"))
        assert stored_length == len(pseudonym.encode("cp852", "strict"))
        assert stored_length <= 6


def _text_fixture_fields(schema: object) -> dict[str, int]:
    return {
        field.name: field.length
        for field in schema.fields  # type: ignore[attr-defined]
        if field.dbf_type.upper() in {"C", "V"}  # type: ignore[attr-defined]
        and field.supported  # type: ignore[attr-defined]
        and not field.is_binary  # type: ignore[attr-defined]
        and not field.nocptrans  # type: ignore[attr-defined]
    }


def _allocate_fixture_domain(tmp_path: Path, fixture: Path) -> dict[str, str]:
    schema = read_schema(FIXTURES / fixture)
    encoding = schema.encoding
    widths = _text_fixture_fields(schema)
    allocated: dict[str, str] = {}
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            for record in iter_records(schema.path):
                for name, width in sorted(widths.items()):
                    value = record.values.get(name)
                    if isinstance(value, str) and value != "":
                        allocator.observe(value, encoding=encoding, byte_width=width)
            allocator.finalize()
            for original in allocator.observed_originals:
                pseudonym = allocator.pseudonym_for(original)
                strictest = allocator.strictest_width_of(original)
                assert strictest is not None
                assert len(pseudonym.encode(encoding, "strict")) <= strictest
                allocated[original] = pseudonym
        assert len(set(allocated.values())) == len(allocated)
    return allocated


def test_cp1250_fixture_domain_allocation(tmp_path: Path) -> None:
    allocated = _allocate_fixture_domain(tmp_path, Path("text/text_cp1250.dbf"))
    assert allocated  # the fixture contributed exact originals
    for original, pseudonym in allocated.items():
        assert pseudonym != original


def test_cp852_fixture_domain_allocation(tmp_path: Path) -> None:
    allocated = _allocate_fixture_domain(tmp_path, Path("text/text_cp852.dbf"))
    assert allocated
    for original, pseudonym in allocated.items():
        assert pseudonym != original
        assert text_kernels.is_safe_token(pseudonym, text_kernels.SAFE_TEXT_ALPHABET)


def test_mazovia_public_schema_representation_allocation(tmp_path: Path) -> None:
    schema = read_schema(FIXTURES / "text" / "text_mazovia.dbf")
    assert schema.encoding == "mazovia"  # the actual public representation
    # Reading the schema through the public boundary is the operation-time
    # step that establishes the dependency's own Mazovia codec; this package
    # invents no Python codec aliases of its own.
    encoding = schema.encoding
    widths = _text_fixture_fields(schema)
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            for record in iter_records(schema.path):
                for name, width in sorted(widths.items()):
                    value = record.values.get(name)
                    if isinstance(value, str) and value != "":
                        allocator.observe(value, encoding=encoding, byte_width=width)
            allocator.finalize()  # provable: full conservative alphabet
            assert allocator.alphabet == text_kernels.SAFE_TEXT_ALPHABET
            for original in allocator.observed_originals:
                pseudonym = allocator.pseudonym_for(original)
                strictest = allocator.strictest_width_of(original)
                assert strictest is not None
                assert len(pseudonym.encode(encoding, "strict")) <= strictest
        rows = _global_rows(vault)
        assert len({pseudonym for _o, pseudonym, _l in rows}) == len(rows)
    # The committed Mazovia table also decodes identically through the
    # dependency's public "piast" codec alias (representation evidence).
    assert list(iter_records(schema.path, encoding="piast"))[0].values["TEXT"] == (
        list(iter_records(schema.path))[0].values["TEXT"]
    )


def test_piast_public_alias_encoding_allocation(tmp_path: Path) -> None:
    # PIAST is the public codec alias of the same Mazovia OEM table: reading
    # the committed fixture through encoding="piast" (the p0-corpus style)
    # establishes the codec, and the allocation then proves byte feasibility
    # under the "piast" name exactly as under "mazovia".
    schema = read_schema(FIXTURES / "text" / "text_mazovia.dbf")
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            for record in iter_records(schema.path, encoding="piast"):
                value = record.values.get("TEXT")
                if isinstance(value, str) and value != "":
                    allocator.observe(value, encoding="piast", byte_width=64)
            allocator.finalize()
            for original in allocator.observed_originals:
                pseudonym = allocator.pseudonym_for(original)
                assert len(pseudonym.encode("piast", "strict")) <= 64
        assert len(_global_rows(vault)) == len(allocator.observed_originals)


def test_unknown_encoding_name_fails_closed(tmp_path: Path) -> None:
    # An encoding that no live codec registry can resolve (and that the
    # public dependency never establishes) cannot be proven safe: the
    # finalized constraint set fails CLOSED with a stable typed error —
    # including the mixed-domain case where one unprovable name poisons the
    # whole domain.
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("PROVABLE-1", encoding="cp1250", byte_width=6)
            allocator.observe("PROVABLE-1", encoding="no-such-codec", byte_width=6)
            with pytest.raises(MappingError) as excinfo:
                allocator.finalize()
            assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
            payload = error_boundary_payload(excinfo.value)
            assert "PROVABLE-1" not in payload
            assert _global_rows(vault) == ()


def test_zero_width_constraint_is_infeasible(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("IMPOSSIBLE", encoding="cp1250", byte_width=0)
            with pytest.raises(MappingError) as excinfo:
                allocator.finalize()
            assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE


def test_width1_full_capacity_through_the_allocator(tmp_path: Path) -> None:
    originals = [f"TOKEN-USER-{index:02d}" for index in range(36)]
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=1)
            allocator.observe("ONE-TOO-MANY", encoding="cp1250", byte_width=1)
            allocator.finalize()
            pseudonyms = [allocator.pseudonym_for(o) for o in originals]
            assert sorted(pseudonyms) == sorted(text_kernels.SAFE_TEXT_ALPHABET)
            with pytest.raises(MappingError) as excinfo:
                allocator.pseudonym_for("ONE-TOO-MANY")
            assert excinfo.value.code is ErrorCode.MAPPING_CAPACITY_EXHAUSTED


def test_width2_capacity_boundary_is_exact(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault)
            for index in range(40):
                allocator.observe(f"WIDE-{index:03d}", encoding="cp1250", byte_width=2)
            allocator.observe("SENTINEL-EXTRA", encoding="cp1250", byte_width=2)
            allocator.finalize()
            for index in range(40):
                allocator.pseudonym_for(f"WIDE-{index:03d}")
            used = {pseudonym for _o, pseudonym, _l in _global_rows(vault)}
            assert len(used) == 40
            remaining = [
                token
                for token in (
                    text_kernels.token_at(i, 2, text_kernels.SAFE_TEXT_ALPHABET)
                    for i in range(text_kernels.token_space(2, 36))
                )
                if token not in used
            ]
            assert len(remaining) == 36 * 36 + 36 - 40
            with vault.transaction():
                for index, token in enumerate(remaining):
                    mappings.add_text_mapping(
                        vault,
                        GLOBAL_TEXT_DOMAIN_ID,
                        f"SEED-{index:04d}",
                        token,
                        logical_byte_length=len(token),
                    )
            assert len(_global_rows(vault)) == 36 * 36 + 36
            with pytest.raises(MappingError) as excinfo:
                allocator.pseudonym_for("SENTINEL-EXTRA")
            assert excinfo.value.code is ErrorCode.MAPPING_CAPACITY_EXHAUSTED
            assert len(_global_rows(vault)) == 36 * 36 + 36


def test_near_full_width2_domain_yields_the_single_free_token(tmp_path: Path) -> None:
    free_token = text_kernels.token_at(777, 2, text_kernels.SAFE_TEXT_ALPHABET)
    with _create(tmp_path) as vault:
        rows = []
        index = 0
        for token_index in range(text_kernels.token_space(2, 36)):
            token = text_kernels.token_at(token_index, 2, text_kernels.SAFE_TEXT_ALPHABET)
            if token == free_token:
                continue
            rows.append((f"SEED-{index:04d}", token, len(token)))
            index += 1
        _seed_global_domain_rows(vault, rows)
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("LONE-SEEKER", encoding="cp1250", byte_width=2)
            allocator.finalize()
            assert allocator.pseudonym_for("LONE-SEEKER") == free_token


def test_allocation_requires_the_writer_lease(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        allocator = _allocator(vault)
        allocator.observe("UNLEASED", encoding="cp1250", byte_width=4)
        with pytest.raises(VaultError) as excinfo:
            allocator.finalize()
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        assert mappings.mapping_domains(vault) == ()  # nothing was created


def test_read_only_reuse_works_without_writer_lease(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault):
            allocator = _allocator(vault, _ScriptedRandom(9))
            allocator.observe("PERSISTED-1", encoding="cp1250", byte_width=5)
            allocator.finalize()
            first = allocator.pseudonym_for("PERSISTED-1")
    with _reopen(tmp_path) as reopened:  # no lease acquired at all
        stream = _ScriptedRandom()
        allocator = _allocator(reopened, stream)
        allocator.observe("PERSISTED-1", encoding="cp1250", byte_width=5)
        allocator.finalize()
        assert allocator.pseudonym_for("PERSISTED-1") == first
        assert stream.calls == []


def test_foreign_domain_rows_never_affect_the_global_domain(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        with writer_session(vault), vault.transaction():
            foreign = mappings.create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT
            )
            mappings.add_text_mapping(
                vault, foreign, "FOREIGN-ORIG", "not-a-token!", logical_byte_length=12
            )
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe("LOCAL-1", encoding="cp1250", byte_width=4)
            allocator.finalize()  # only the global domain is validated
            pseudonym = allocator.pseudonym_for("LOCAL-1")
        assert text_kernels.is_safe_token(pseudonym, text_kernels.SAFE_TEXT_ALPHABET)


def test_public_errors_never_leak_originals_or_pseudonyms(tmp_path: Path) -> None:
    captured: list[BaseException] = []
    with _create(tmp_path) as vault:
        rows = [
            (f"SEED-{index:02d}", ch, 1)
            for index, ch in enumerate(text_kernels.SAFE_TEXT_ALPHABET)
        ]
        _seed_global_domain_rows(vault, rows)
        with writer_session(vault):
            allocator = _allocator(vault)
            allocator.observe(CANARY_ORIGINAL, encoding="cp1250", byte_width=1)
            allocator.finalize()
            try:
                allocator.pseudonym_for(CANARY_ORIGINAL)
            except MappingError as error:
                captured.append(error)
    for error in captured:
        payload = error_boundary_payload(error)
        assert CANARY_ORIGINAL not in payload
        assert CANARY_PSEUDONYM not in payload
        assert "SEED-" not in payload
        assert "SELECT" not in payload and "sqlite" not in payload.lower()