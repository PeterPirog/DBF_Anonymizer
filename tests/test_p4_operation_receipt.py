"""The INTERNAL engine operation receipt (REQ-P4-009) contract evidence.

The receipt is the engine's private serialized fact store for completed
operations: it must round-trip deterministically, stay value-free, never
carry absolute paths or protected-state terminology into its serialized
form, and reject unknown receipt schema versions fail-closed.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from dbf_anonymizer.engine.directives import RelationPassSummary, TwoPassResult
from dbf_anonymizer.engine.publication import (
    RECEIPT_SCHEMA_VERSION,
    result_from_receipt,
    result_receipt,
)
from dbf_anonymizer.errors import ErrorCode, PublicationError


_PATH_CANARY = "C:\\private\\canary\\source.dbf"


def _summary() -> RelationPassSummary:
    return RelationPassSummary(
        relation_id="rel-customer",
        verified=True,
        before_rows=2,
        after_rows=2,
        before_nulls=0,
        after_nulls=0,
        before_unique=2,
        after_unique=2,
        matched_rows=2,
        orphan_count=0,
        parent_profile_equal=True,
        foreign_profile_equal=True,
    )


def _result(*, protected_state_created: bool) -> TwoPassResult:
    return TwoPassResult(
        tables_written=("north/data.dbf", "south/data.dbf"),
        pass1_records_scanned=4,
        pass1_deleted_scanned=1,
        pass2_records_written=4,
        text_allocated=3,
        text_reused=1,
        numeric_allocated={"dom-1": 2},
        temporal_offset_allocated=False,
        relations=(_summary(),),
        evidence_spool_bytes=512,
        read_streams=(("pass1", "north/data.dbf"), ("pass2", "north/data.dbf")),
        operation_id="vop-receipt-roundtrip",
        output_fingerprint="out-" + "a" * 64,
        reused_existing=False,
        protected_state_created=protected_state_created,
    )


def test_receipt_schema_version_is_versioned_and_rejects_unknown_versions() -> None:
    # The internal receipt schema is explicitly versioned; the current
    # version reflects the neutral protected-state fact introduced with the
    # public pseudonymize service.
    assert RECEIPT_SCHEMA_VERSION == "1.1"
    receipt = result_receipt(_result(protected_state_created=True))
    assert json.loads(receipt)["schema_version"] == "1.1"

    # Any unknown or missing version is rejected fail-closed, never parsed
    # best-effort into a partially trusted result.
    for version in ("1.0", "9.9", None):
        tampered = json.loads(receipt)
        if version is None:
            tampered.pop("schema_version")
        else:
            tampered["schema_version"] = version
        with pytest.raises(PublicationError) as caught:
            result_from_receipt(json.dumps(tampered))
        assert caught.value.code is ErrorCode.PUBLICATION_INCOMPLETE
        assert caught.value.context.detail_code == "OPERATION_RECEIPT_INVALID"


@pytest.mark.parametrize("protected_state_created", [True, False])
def test_receipt_round_trip_is_deterministic_and_complete(
    protected_state_created: bool,
) -> None:
    result = _result(protected_state_created=protected_state_created)
    receipt = result_receipt(result)
    restored = result_from_receipt(receipt)

    assert restored == dataclasses.replace(result, reused_existing=True)
    assert restored.protected_state_created is protected_state_created
    # Deterministic serialization: the same result always yields identical
    # canonical bytes, so receipt equality is evidence, not formatting luck.
    assert result_receipt(result) == receipt
    assert receipt == receipt.encode("ascii").decode("ascii")


def test_receipt_stays_private_and_neutral() -> None:
    receipt = result_receipt(_result(protected_state_created=True))

    # No protected-state terminology, no absolute path, no canary value.
    assert "vault" not in receipt.lower()
    assert _PATH_CANARY not in receipt
    assert "dictionary.sqlite3" not in receipt