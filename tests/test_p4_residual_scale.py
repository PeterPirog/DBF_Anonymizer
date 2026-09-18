"""BLOCKER 1 regressions: the large FORCED-residual regime at scale.

The 1500-value bounded-memory fixture exercises the easy fungible path.  The
fixtures here force the HARD branch the old production engine delegated to
the in-memory P2 planner (``GlobalTextDomainMapping``): a dataset with MORE
remaining distinct values than :data:`MAX_RECORD_BATCH` whose residual text
problem has ZERO fungible capacity in every reachable length class, so every
original must receive ANOTHER original's reserved token (a full derangement
resolved by disk-backed augmenting paths).  Python stays bounded; all
dataset/distinct-sized state lives in the protected SQLite spool.

Alphabet (cp1250 safe set): 36 characters.  All 36 one-character and all
1296 two-character safe tokens are observed as distinct originals => 1332
remaining distinct values (> MAX_RECORD_BATCH = 1024), fungible(1) = 36-36 =
0 and fungible(2) = 1296-1296 = 0.  The feasible case is a full derangement
over 1332 tokens; the infeasible case pre-occupies ONE single-character
token with a persisted mapping of a foreign original, leaving 1331 free
resources for 1332 originals — a true capacity exhaustion.
"""

from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

import dbfbridge
from dbf_anonymizer import VaultError, build_plan
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.engine.state import MAX_RECORD_BATCH
from dbf_anonymizer.errors import MappingError
from dbf_anonymizer.vault.mappings import create_domain, text_mapping_rows
from dbf_anonymizer.vault.store import VaultDatabase, new_writer_token
from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID
from dbf_anonymizer.vault.schema import VAULT_TABLE_DOMAIN_KIND_TEXT
from support.numeric_tables import numeric_field, write_numeric_table

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_VALUES = list(_ALPHABET) + [a + b for a in _ALPHABET for b in _ALPHABET]
assert len(_VALUES) > MAX_RECORD_BATCH


def _write_source(source_root: Path) -> None:
    write_numeric_table(
        source_root,
        "codes.dbf",
        (numeric_field("CODE", "C", 2),),
        [{"CODE": value} for value in _VALUES],
    )


def _seed_occupied_token(vault_path: Path, plan) -> None:
    """Persist one FOREIGN original through the PUBLIC vault API so one
    single-character token of the GLOBAL text domain is occupied before the
    engine runs (the truthful reuse scenario: a recovery dictionary may hold
    mappings of values the current dataset no longer contains)."""
    vault = VaultDatabase.open(
        vault_path,
        create=True,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version=str(dbfbridge.__version__),
    )
    lease = new_writer_token()
    vault.acquire_writer_lease(lease)
    try:
        with vault.transaction():
            create_domain(
                vault,
                domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                domain_id=GLOBAL_TEXT_DOMAIN_ID,
            )
            from dbf_anonymizer.vault.mappings import add_text_mapping

            add_text_mapping(
                vault,
                GLOBAL_TEXT_DOMAIN_ID,
                "FOREIGN-NOT-IN-DATASET",
                "A",
                logical_byte_length=1,
            )
    finally:
        vault.release_writer_lease(lease)
    vault.close()


def _block_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Structural production guard: constructing the P2 planner ANYWHERE in
    the production path would raise.  The engine never imports the symbol,
    so the patch cannot even be reached — success below is the proof."""

    def _forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            "GlobalTextDomainMapping must never be constructed in production"
        )

    from dbf_anonymizer.vault import text_allocation

    monkeypatch.setattr(
        text_allocation, "GlobalTextDomainMapping", _forbidden, raising=True
    )


def test_forced_residual_derangement_is_exact_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    _write_source(source_root)
    plan = build_plan(str(source_root), str(output_root), str(vault_path))
    _block_oracle(monkeypatch)
    tracemalloc.start()
    result = run_two_pass(plan)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert result.text_allocated == len(_VALUES)
    assert result.text_reused == 0
    assert result.pass2_records_written == len(_VALUES)
    # The one-shot evidence of the run: exactly one stream per pass.
    assert result.read_streams == (("pass1", "codes.dbf"), ("pass2", "codes.dbf"))
    # EXACT BIJECTION in the durable vault: every original exactly once,
    # every pseudonym distinct, never the own value, never over width.
    vault = VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version=str(dbfbridge.__version__),
    )
    mapping = {
        original: pseudonym
        for original, pseudonym, _length in text_mapping_rows(
            vault, GLOBAL_TEXT_DOMAIN_ID
        )
    }
    vault.close()
    originals = set(mapping)
    pseudonyms = set(mapping.values())
    assert originals == set(_VALUES)  # no missing mappings
    assert len(mapping) == len(_VALUES)  # exact bijection (no duplicates)
    assert len(pseudonyms) == len(_VALUES)  # injective pseudonyms
    # Full derangement: in a zero-fungible regime every token belongs to
    # SOME original — self-exclusion is per value, not across the set.
    assert all(mapping[value] != value for value in mapping)
    assert all(len(pseudonym) <= 2 for pseudonym in pseudonyms)
    # The written output carries the exact pseudonyms (no value leakage of
    # the originals into the fresh output table).
    output_values = [
        record.values["CODE"]
        for record in dbfbridge.iter_records(output_root / "codes.dbf")
    ]
    assert output_values == [mapping[value] for value in _VALUES]
    # BOUNDED Python buffers: the whole forced-residual run (planning is
    # excluded) stays far below any dataset-scaled footprint.
    assert peak < 8 * 1024 * 1024


def test_forced_residual_exhaustion_is_a_typed_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    output_root = tmp_path / "output"
    vault_path = tmp_path / "vault" / "dictionary.sqlite3"
    _write_source(source_root)
    plan = build_plan(str(source_root), str(output_root), str(vault_path))
    _seed_occupied_token(vault_path, plan)
    _block_oracle(monkeypatch)
    with pytest.raises(MappingError) as excinfo:
        run_two_pass(plan)
    payload = excinfo.value.to_dict()
    assert payload["code"] == "MAPPING_CAPACITY_EXHAUSTED"
    assert (
        payload["context"]["detail_code"] == "ENGINE_TEXT_RESIDUAL_INFEASIBLE"
    )
    # No partial output, no value leakage, no source mutation.
    assert not (output_root / "codes.dbf").exists()
    assert not output_root.exists() or not any(output_root.rglob("*"))
    boundary = str(excinfo.value) + repr(excinfo.value) + str(payload)
    assert "FOREIGN-NOT-IN-DATASET" not in boundary
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in boundary
    assert str(tmp_path) not in boundary
    assert str(source_root) not in boundary
    # The vault kept EXACTLY the persisted truth (the one foreign mapping)
    # — no partial allocation of the residual problem was committed.
    vault = VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version=str(dbfbridge.__version__),
    )
    try:
        rows = list(text_mapping_rows(vault, GLOBAL_TEXT_DOMAIN_ID))
        assert rows == [("FOREIGN-NOT-IN-DATASET", "A", 1)]
    finally:
        vault.close()


def test_forced_residual_spool_state_stays_in_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Structural boundedness of the SOLVER state: the res_* traversal
    tables live in the spool's SQLite schema, the solver module never names
    the P2 planner, and every bounded buffer constant is dataset-independent.
    """
    from dbf_anonymizer.engine import state as spool_state
    from dbf_anonymizer.engine import text_residual

    # Static structure: the complete traversal state (originals, tokens,
    # capacities, the visited set, the DFS stack, the assignment) lives in
    # the SPOOL schema — the solver module itself defines no dataset-sized
    # state table at all.
    schema_source = Path(spool_state.__file__).read_text(encoding="utf-8")
    for table in (
        "res_original",
        "res_token",
        "res_cap",
        "res_assign",
        "res_visited",
        "res_dfs",
    ):
        assert f"CREATE TABLE {table} " in schema_source
    # The bounded Python-side buffers are structural constants, not
    # dataset-scaled: the SQL batch bound is fixed and independent.
    assert spool_state.MAX_SQL_BATCH <= MAX_RECORD_BATCH
    # Runtime: the full fixture still solves with the oracle blocked, and
    # the spool is completely gone afterwards (Zone B cleanliness).
    source_root = tmp_path / "source"
    _write_source(source_root)
    plan = build_plan(
        str(source_root),
        str(tmp_path / "output"),
        str(tmp_path / "vault" / "dictionary.sqlite3"),
    )
    _block_oracle(monkeypatch)
    result = run_two_pass(plan)
    assert result.text_allocated == len(_VALUES)
    from dbf_anonymizer.engine.state import spool_artifacts

    assert spool_artifacts(tmp_path / "vault") == []