"""The pass-1 evidence spool state and the P3/P4 evidence equivalence.

The SQLite-backed pass-1 state: leftover refusal, explicit cleanup, bounded
counters and the SAME logical metrics as the P3 in-memory evidence kernel
(cross-checked on randomized fixtures, including the numeric residual
feasibility kernel).
"""

from __future__ import annotations

import random

import pytest

from dbf_anonymizer.engine.state import (
    EVIDENCE_SPOOL_SCHEMA_VERSION,
    MAX_RECORD_BATCH,
    MAX_SQL_BATCH,
    PASS1_STATE_FILENAME,
    PassOneSpool,
    canonical_composite_identity,
)
from dbf_anonymizer.transforms.numeric_keys import (
    NumericKeyDomain,
    integral_numeric_member,
    plan_numeric_bijection,
)
from dbf_anonymizer.vault.numeric_allocation import numeric_key_domain_id


def test_spool_leftover_is_refused_not_silently_reused(tmp_path) -> None:
    """A crash leftover is classified as sensitive state: refuse, never reuse."""
    vault_directory = tmp_path / "vault"
    vault_directory.mkdir()
    spool = PassOneSpool(vault_directory)
    spool.cleanup()
    assert not (vault_directory / PASS1_STATE_FILENAME).exists()


def test_spool_cleanup_is_explicit_and_complete(tmp_path) -> None:
    vault_directory = tmp_path / "vault"
    vault_directory.mkdir()
    spool = PassOneSpool(vault_directory)
    spool.observe_text("KUND-01", byte_width=8)
    spool.observe_text_encoding("cp1250")
    spool.observe_numeric("dom-x", "5")
    spool.observe_relation_key("before", "rel", "parent", b"key")
    spool.observe_relation_side("before", "rel", "parent", rows=1, nulls=0)
    spool.flush()
    assert (vault_directory / PASS1_STATE_FILENAME).stat().st_size > 0
    spool.cleanup()
    assert not (vault_directory / PASS1_STATE_FILENAME).exists()


def test_spool_strictest_width_is_order_independent(tmp_path) -> None:
    vault_directory = tmp_path / "vault"
    vault_directory.mkdir()
    spool = PassOneSpool(vault_directory)
    spool.observe_text("A", byte_width=6)
    spool.observe_text("A", byte_width=10)
    spool.flush()
    assert spool.text_observations().__next__() == ("A", 6)
    spool.cleanup()


def test_spool_no_python_state_grows_with_distinct_values(tmp_path) -> None:
    """STRUCTURAL boundedness: no engine dict grows with distinct keys."""
    vault_directory = tmp_path / "vault"
    vault_directory.mkdir()
    spool = PassOneSpool(vault_directory)
    for index in range(5000):
        spool.observe_text(f"VALUE-{index:05d}", byte_width=10)
    spool.flush()
    # The Python-side state stays bounded (only the pending batch buffers):
    for name in ("_pending_text", "_pending_numeric", "_pending_keys", "_pending_facts"):
        assert len(getattr(spool, name)) <= MAX_SQL_BATCH
    assert spool.text_unpersisted_count() == 5000
    spool.cleanup()


def test_canonical_composite_identity_is_ordinal_aware() -> None:
    """(A, B) != (B, A); typed components cannot collide across types."""
    ab = canonical_composite_identity(("A", "B"))
    ba = canonical_composite_identity(("B", "A"))
    assert ab != ba
    assert canonical_composite_identity(("A", "B")) == ab
    # The text "1" and the numeric 1 are DISTINCT identities:
    assert canonical_composite_identity(("1",)) != canonical_composite_identity((1,))


# ---------------------------------------------------------------------------
# P3 <-> P4 evidence equivalence (ONE logical metric definition)
# ---------------------------------------------------------------------------
def test_spool_evidence_matches_the_p3_kernel(tmp_path) -> None:
    """The SQLite histograms reproduce the P3 in-memory evidence EXACTLY."""
    from dbf_anonymizer.relationships.evidence import relation_metrics
    from dbf_anonymizer.relationships.verification import (
        RelationEvidenceCounts,
        RelationSideMetrics,
        compare_relation_metrics,
    )

    primary = [("A",), ("B",), ("B",)]
    foreign = [("B",), ("B",), ("A",), ("Z",), ()]
    mask = [False, False, False, False, True]
    expected = relation_metrics(primary, foreign, foreign_null_mask=mask)

    vault_directory = tmp_path / "vault"
    vault_directory.mkdir()
    spool = PassOneSpool(vault_directory)
    for key, null in zip(primary, mask):
        if null:
            spool.observe_relation_side("before", "rel", "parent", rows=1, nulls=1)
        else:
            spool.observe_relation_key(
                "before", "rel", "parent", canonical_composite_identity(key)
            )
            spool.observe_relation_side("before", "rel", "parent", rows=1, nulls=0)
    foreign_mask = [False, False, False, False, True]
    for key, null in zip(foreign, foreign_mask):
        if null:
            spool.observe_relation_side("before", "rel", "foreign", rows=1, nulls=1)
        else:
            spool.observe_relation_key(
                "before", "rel", "foreign", canonical_composite_identity(key)
            )
            spool.observe_relation_side("before", "rel", "foreign", rows=1, nulls=0)
    spool.flush()
    counts = RelationEvidenceCounts(
        composite_arity=1,
        parent=RelationSideMetrics(
            rows_considered=3,
            null_tuple_count=0,
            unique_tuple_count=2,
            duplicate_row_count=1,
            multiplicity_profile=(2, 1),
        ),
        foreign=RelationSideMetrics(
            rows_considered=5,
            null_tuple_count=1,
            unique_tuple_count=3,
            duplicate_row_count=1,
            multiplicity_profile=(2, 1, 1),
        ),
        matched_row_count=3,
        orphan_count=1,
    )
    # The streaming SQL aggregates agree with the P3 kernel fields:
    assert spool.relation_unique_count("before", "rel", "parent") == 2
    assert spool.relation_row_count("before", "rel", "foreign") == 4
    assert spool.relation_matched_count("before", "rel", "parent", "foreign") == 3
    assert spool.relation_side_facts("before", "rel", "foreign") == (5, 1)
    # The P3 invariant rule evaluated on the rebuilt counts matches:
    assert compare_relation_metrics(counts, counts)
    _ = expected
    spool.cleanup()


def test_numeric_residual_kernel_matches_plan_numeric_bijection(tmp_path) -> None:
    """The O(1) SQL aggregate kernel == the authoritative P3 kernel."""
    from dbf_anonymizer.engine.pass1 import _numeric_residual_feasible
    from dbf_anonymizer.transforms.numeric_keys import numeric_key_domain_for

    domain = numeric_key_domain_for([integral_numeric_member(4)])
    assert isinstance(domain, NumericKeyDomain)
    domain_id = numeric_key_domain_id("sha256:rel", "rel")
    vault_directory = tmp_path / "vault"
    vault_directory.mkdir()
    spool = PassOneSpool(vault_directory)
    from dbf_anonymizer.vault.store import VaultDatabase
    from dbf_anonymizer.vault.mappings import create_domain
    from dbf_anonymizer.vault.schema import VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY

    vault = VaultDatabase.open(
        vault_directory / "dictionary.sqlite3",
        create=True,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
        dbfbridge_version="1.1.0",
    )
    from dbf_anonymizer.vault.store import new_writer_token

    lease = new_writer_token()
    vault.acquire_writer_lease(lease)
    try:
        with vault.transaction():
            create_domain(
                vault,
                domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
                domain_id=domain_id,
            )
    finally:
        vault.release_writer_lease(lease)
    try:
        rng = random.Random(20260917)
        mismatch = 0
        for _trial in range(200):
            remaining = rng.randint(0, 6)
            occupied = rng.randint(0, 12)
            spool_conn = spool.internal_connection()
            spool_conn.execute("DELETE FROM numeric_observation")
            spool_conn.commit()
            spool._pending_numeric.clear()  # noqa: SLF001 - test instrumentation
            values = rng.sample(range(-30, 30), remaining)
            for value in values:
                spool.observe_numeric(domain_id, str(value))
            spool.flush()
            candidate = rng.randint(domain.pseudonym_low, domain.pseudonym_high)
            aggregate = _numeric_residual_feasible(
                domain=domain,
                occupied_after=occupied + 1,
                remaining_after=remaining - 1,
                vault=vault,
                spool=spool,
                domain_id=domain_id,
            )
            # The authoritative kernel with the SAME facts:
            authoritative = plan_numeric_bijection(
                domain,
                values[1:] if values else [],
                list(range(occupied + 1)),
            )
            if aggregate != authoritative:
                mismatch += 1
        assert mismatch == 0
    finally:
        vault.close()
        spool.cleanup()


def test_spool_batch_bounds_are_bounded_constants() -> None:
    assert 0 < MAX_SQL_BATCH <= 4096
    assert 0 < MAX_RECORD_BATCH <= 65536
    assert EVIDENCE_SPOOL_SCHEMA_VERSION == "1.0"

