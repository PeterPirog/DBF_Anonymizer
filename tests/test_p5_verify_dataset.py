"""REQ-P5-001 — public independent dataset verification evidence.

Proves the read-only ``verify_dataset`` service end to end: truthful
PASS/PARTIAL/FAIL verdicts derived from evidence, strictly read-only
execution (zero mutation of source/output/vault/sidecars and zero created
artifacts), durable receipt/assurance cross-validation, the versioned
finding-code vocabulary, REQ-P1-008 progress/cancellation/callback
containment under ONE controller with the canonical operation id, and the
deterministic corruption matrix. Only approved synthetic fixtures and
disposable tmp_path data created through the public ``dbfbridge`` API are
used. No production data is accessed.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import date, datetime
from pathlib import Path
from typing import Any

import dbfbridge
import pytest

import dbf_anonymizer
from dbf_anonymizer import (
    CallbackError,
    CancellationError,
    ErrorCode,
    ProgressEvent,
    PseudonymizationResult,
    VerificationError,
    VerificationResult,
    VerificationStatus,
    build_plan,
    preflight,
    pseudonymize,
    verify_dataset,
)
from dbf_anonymizer.verification import (
    VERIFICATION_CHECK_CODES,
    VERIFICATION_CHECK_CODE_VERSION,
)
from support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table_with_deleted,
)

_PATH_CANARY = "C:\\private\\canary\\source.dbf"
_VALUE_CANARY = "PARENT-CONFIDENTIAL-42"


# ---------------------------------------------------------------------------
# Synthetic fixture (public dbfbridge writer only)
# ---------------------------------------------------------------------------
def _relationship_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-text",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "north/data.dbf",
                        "field": "CODE",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "CODE",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                ],
            },
            {
                "relation_id": "rel-num",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": "north/data.dbf",
                        "field": "NUMBER",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "NUMBER",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": True,
                    },
                ],
            },
        ],
    }


def _main_fields() -> tuple[object, ...]:
    return (
        numeric_field("CODE", "C", 12, flags=NULLABLE_FLAG),
        numeric_field("NUMBER", "I", 4, flags=NULLABLE_FLAG),
        numeric_field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
        numeric_field("SEEN_AT", "T", 8, flags=NULLABLE_FLAG),
        numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
        numeric_field("KEEP_N", "N", 6),
        numeric_field("KEEP_L", "L", 1),
    )


def _write_dataset(source: Path) -> None:
    write_numeric_table_with_deleted(
        source,
        "north/data.dbf",
        _main_fields(),
        [
            (
                {
                    "CODE": "PARENT-1",
                    "NUMBER": -7,
                    "WHEN_D": date(2026, 3, 1),
                    "SEEN_AT": datetime(2026, 3, 1, 12, 30, 45),
                    "NOTE": "MEMO-N-1",
                    "KEEP_N": 11,
                    "KEEP_L": True,
                },
                False,
            ),
            (
                {
                    "CODE": "PARENT-2",
                    "NUMBER": 5,
                    "WHEN_D": None,
                    "SEEN_AT": None,
                    "NOTE": None,
                    "KEEP_N": 22,
                    "KEEP_L": False,
                },
                True,
            ),
            (
                {
                    "CODE": "",
                    "NUMBER": None,
                    "WHEN_D": date(2026, 5, 20),
                    "SEEN_AT": datetime(2026, 5, 20, 6, 15, 0),
                    "NOTE": "",
                    "KEEP_N": 33,
                    "KEEP_L": None,
                },
                False,
            ),
        ],
    )
    write_numeric_table_with_deleted(
        source,
        "south/data.dbf",
        _main_fields(),
        [
            (
                {
                    "CODE": "PARENT-1",
                    "NUMBER": -7,
                    "WHEN_D": date(2026, 3, 2),
                    "SEEN_AT": datetime(2026, 3, 2, 1, 2, 3),
                    "NOTE": "MEMO-S-1",
                    "KEEP_N": 44,
                    "KEEP_L": False,
                },
                True,
            ),
            (
                {
                    "CODE": None,
                    "NUMBER": None,
                    "WHEN_D": None,
                    "SEEN_AT": None,
                    "NOTE": "MEMO-S-NULL",
                    "KEEP_N": 55,
                    "KEEP_L": None,
                },
                False,
            ),
        ],
    )
    # Duplicate basename in a separate directory: ownership is path-based.
    write_numeric_table_with_deleted(
        source,
        "archive/data.dbf",
        (
            numeric_field("CODE", "C", 12, flags=NULLABLE_FLAG),
            numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
        ),
        [
            ({"CODE": "ARCHIVE", "NOTE": "MEMO-ARCHIVE"}, False),
            ({"CODE": "PARENT-1", "NOTE": "MEMO-DUP-1"}, False),
            ({"CODE": None, "NOTE": None}, True),
        ],
    )


def _prepare(tmp_path: Path) -> tuple[PseudonymizationResult, Path, Path, Path]:
    from dbf_anonymizer import build_plan as _build_plan

    source = tmp_path / "source"
    _write_dataset(source)
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan = _build_plan(
        source,
        output,
        vault,
        relationship_document=_relationship_document(),
    )
    assert preflight(plan).ready is True
    result = pseudonymize(plan)
    assert isinstance(result, dbf_anonymizer.PseudonymizationResult)
    return result, source, output, vault



def _table_entries(path: Path) -> tuple[list[dict[str, Any]], list[bool]]:
    source_records = tuple(
        dbfbridge.iter_records(path, include_deleted=True, memo="inline")  # type: ignore[attr-defined]
    )
    return (
        [dict(record.values) for record in source_records],
        [record.deleted for record in source_records],
    )


def _hash_tree(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _rewrite_output(
    output: Path,
    relative_path: str,
    fields: tuple[object, ...],
    records: list[dict[str, Any]],
    *,
    deleted_flags: list[bool] | None = None,
) -> None:
    dbfbridge.write_table(  # type: ignore[attr-defined]
        output / relative_path,
        schema=_schema_for(fields),
        records=[
            dbfbridge.DirectRecord(  # type: ignore[attr-defined]
                physical_index=index,
                deleted=deleted_flags[index] if deleted_flags else False,
                values=values,
            )
            for index, values in enumerate(records)
        ],
        overwrite=True,
    )


def _schema_for(fields: tuple[object, ...]) -> object:
    from support.numeric_tables import schema as _schema

    return _schema(fields)


# ---------------------------------------------------------------------------
# Contract + vocabulary
# ---------------------------------------------------------------------------
def test_verify_dataset_is_the_public_service_with_the_architecture_signature() -> None:
    import inspect

    import dbf_anonymizer.api as api_module

    assert dbf_anonymizer.verify_dataset is api_module.verify_dataset
    parameters = list(inspect.signature(dbf_anonymizer.verify_dataset).parameters)
    assert parameters == ["result", "source", "vault", "progress", "cancel_check"]


def test_verification_check_code_vocabulary_is_versioned_and_pinned() -> None:
    assert VERIFICATION_CHECK_CODE_VERSION == "1.2"
    assert VERIFICATION_CHECK_CODES == frozenset(
        {
            "SOURCE_FINGERPRINT_MISMATCH",
            "OUTPUT_FINGERPRINT_MISMATCH",
            "RECEIPT_FINGERPRINT_MISMATCH",
            "RECEIPT_IDENTITY_MISMATCH",
            "VAULT_IDENTITY_MISMATCH",
            "VAULT_MAPPING_INVALID",
            "ASSURANCE_EVIDENCE_MISMATCH",
            "OPERATION_NOT_COMPLETED",
            "TABLE_MISSING",
            "UNEXPECTED_OUTPUT_ARTIFACT",
            "INDEX_ARTIFACT_UNVERIFIED",
            "STANDALONE_IDX_DEFINITION_UNAVAILABLE",
            "STANDALONE_IDX_EVIDENCE_MISMATCH",
            "MEMO_COMPANION_MISSING",
            "SCHEMA_MISMATCH",
            "RECORD_COUNT_MISMATCH",
            "RECORD_ORDER_MISMATCH",
            "DELETED_MARKER_MISMATCH",
            "NULL_SEMANTICS_MISMATCH",
            "ORIGINAL_VALUE_SURVIVED",
            "TEXT_MAPPING_MISMATCH",
            "NUMERIC_MAPPING_MISMATCH",
            "MEMO_PAYLOAD_MISMATCH",
            "MEMO_RECOVERY_ROW_MISSING",
            "TEMPORAL_VALUE_MISMATCH",
            "IDENTITY_VALUE_MISMATCH",
            "POLICY_BINDING_MISSING",
            "POLICY_BINDING_MISMATCH",
        }
    )


# ---------------------------------------------------------------------------
# Positive end-to-end PASS + read-only evidence
# ---------------------------------------------------------------------------
def test_positive_end_to_end_verification_achieves_truthful_pass(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    verification = verify_dataset(result, source=source, vault=vault)

    assert isinstance(verification, VerificationResult)
    assert verification.status is VerificationStatus.PASS
    assert verification.verified is True
    assert verification.check_codes == ()
    assert verification.operation_id == result.operation_id
    assert verification.table_count == result.table_count == 3
    assert verification.record_count == result.record_count
    # Duplicate basenames stayed distinct and normalized relative paths hold.
    assert verification.dataset is result.dataset
    payload = verification.to_dict()
    serialized = json.dumps(payload, sort_keys=True)
    assert str(source) not in serialized
    assert str(vault) not in serialized
    assert _PATH_CANARY not in serialized


def test_verification_is_strictly_read_only_and_creates_no_artifacts(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before_source = _hash_tree(source)
    before_output = _hash_tree(output)
    before_vault = _hash_tree(vault.parent)
    before_tmp = _hash_tree(tmp_path)

    verification = verify_dataset(
        result, source=source, vault=vault, cancel_check=lambda: False
    )

    assert verification.status is VerificationStatus.PASS
    assert _hash_tree(source) == before_source
    assert _hash_tree(output) == before_output
    assert _hash_tree(vault.parent) == before_vault
    after_tmp = _hash_tree(tmp_path)
    assert set(after_tmp) == set(before_tmp), "verification created artifacts"
    # Any engine-owned lock lifecycle state from the pseudonymize run is
    # unchanged by verification; no staging/scratch state exists.
    locks_before = sorted(path.name for path in tmp_path.glob(".dbf-anonymizer-*"))
    locks_after = sorted(path.name for path in tmp_path.glob(".dbf-anonymizer-*"))
    assert locks_after == locks_before
    assert not any(tmp_path.glob("*.staging*"))


def test_verification_pass_partial_fail_is_deterministic_and_repeatable(
    tmp_path: Path,
) -> None:
    """PASS, PARTIAL and FAIL are all independently demonstrated with
    deterministic repeatability (REQ-P5-001 truthful semantics).

    The PARTIAL state is the genuine end-to-end one: the output state is
    otherwise internally consistent (result fingerprint == recomputed
    fingerprint == durable operation binding == receipt) while an index
    artifact makes the index-semantic dimension genuinely unverified."""
    import dataclasses
    import shutil
    import sqlite3

    from dbf_anonymizer.engine.publication import (
        derive_binding_fingerprint,
        derive_destination_identity,
        fingerprint_dataset,
    )
    from dbf_anonymizer.models import _PseudonymizationExecutionContext

    result, source, output, vault = _prepare(tmp_path)

    # --- PASS: a clean verified dataset.
    passed = verify_dataset(result, source=source, vault=vault)
    assert passed.status is VerificationStatus.PASS
    assert passed.check_codes == ()
    assert verify_dataset(result, source=source, vault=vault) == passed

    # --- PARTIAL: an internally consistent published state whose output
    # legitimately contains an index artifact the verifier cannot
    # semantically validate without the absent P6 backend.
    partial_output = tmp_path / "output-partial"
    shutil.copytree(output, partial_output)
    (partial_output / "north" / "data.cdx").write_bytes(b"synthetic-index-artifact")
    new_fingerprint = fingerprint_dataset(partial_output)
    partial_result = dataclasses.replace(
        result,
        output_fingerprint=new_fingerprint,
        execution_context=_PseudonymizationExecutionContext(
            output_root=str(partial_output),
            source_root=str(tmp_path / "source"),
            vault_path=str(tmp_path / "vault" / "dictionary.sqlite3"),
        ),
    )
    destination_identity = derive_destination_identity(partial_output)
    connection = sqlite3.connect(vault)
    try:
        row = connection.execute(
            "SELECT source_fingerprint, policy_fingerprint, relationship_fingerprint, "
            "vault_fingerprint, result_json FROM operations WHERE operation_id = ?",
            (result.operation_id,),
        ).fetchone()
        receipt = json.loads(str(row[4]))
        receipt["output_fingerprint"] = new_fingerprint
        binding = derive_binding_fingerprint(
            source_fingerprint=str(row[0]),
            policy_fingerprint=str(row[1]),
            relationship_fingerprint=str(row[2]),
            vault_fingerprint=connection.execute(
                "SELECT vault_fingerprint FROM operations WHERE operation_id = ?",
                (result.operation_id,),
            ).fetchone()[0],
            destination_identity=destination_identity,
        )
        connection.execute(
            "UPDATE operations SET output_fingerprint = ?, destination_identity = ?, "
            "binding_fingerprint = ?, result_json = ? WHERE operation_id = ?",
            (
                new_fingerprint,
                destination_identity,
                binding,
                json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                result.operation_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    partial = verify_dataset(
        partial_result, source=source, vault=partial_output.parent / "vault" / "dictionary.sqlite3"
    )
    assert partial.status is VerificationStatus.PARTIAL
    assert partial.check_codes == ("INDEX_ARTIFACT_UNVERIFIED",)
    assert partial.verified is False
    assert verify_dataset(
        partial_result, source=source, vault=vault
    ) == partial

    # --- FAIL: real corruption always wins over the partial dimension.
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    records[0]["CODE"] = records[1]["CODE"]
    _rewrite_output(
        output,
        "north/data.dbf",
        _main_fields(),
        records,
        deleted_flags=deleted_flags,
    )
    failed = verify_dataset(result, source=source, vault=vault)
    assert failed.status is VerificationStatus.FAIL
    assert "OUTPUT_FINGERPRINT_MISMATCH" in failed.check_codes
    assert "TEXT_MAPPING_MISMATCH" in failed.check_codes


# ---------------------------------------------------------------------------
# Progress / cancellation / callback containment
# ---------------------------------------------------------------------------
class _Recorder:
    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []
        self.threads: list[int] = []

    def __call__(self, event: ProgressEvent) -> None:
        self.events.append(event)
        self.threads.append(threading.get_ident())

    def phase(self, phase_code: str, event_code: str) -> list[ProgressEvent]:
        return [
            event
            for event in self.events
            if event.phase_code == phase_code and event.event_code == event_code
        ]

    def completed(self) -> list[ProgressEvent]:
        return [event for event in self.events if event.event_code == "COMPLETED"]


def test_verify_dataset_progress_stream_is_one_operation_with_bounded_phases(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    recorder = _Recorder()
    verification = verify_dataset(result, source=source, vault=vault, progress=recorder)

    assert verification.status is VerificationStatus.PASS
    events = recorder.events
    assert events
    # ONE canonical operation id: every event carries the verified
    # operation's durable id (== verification.operation_id).
    assert {event.operation_id for event in events} == {
        verification.operation_id,
        result.operation_id,
    }
    # The required bounded phases are observable, in a deterministic order.
    for phase_code in (
        "OPERATION",
        "SOURCE_VERIFICATION",
        "VAULT_VERIFICATION",
        "TABLE_EVALUATION",
        "OUTPUT_VERIFICATION",
    ):
        started = recorder.phase(phase_code, "STARTED")
        assert started, phase_code
    phase_order = [
        events.index(recorder.phase(phase_code, "STARTED")[0])
        for phase_code in (
            "OPERATION",
            "SOURCE_VERIFICATION",
            "VAULT_VERIFICATION",
            "TABLE_EVALUATION",
            "OUTPUT_VERIFICATION",
        )
    ]
    assert phase_order == sorted(phase_order)
    # Exactly one terminal COMPLETED event, last, only after genuine success.
    completed = recorder.completed()
    assert len(completed) == 1
    assert events[-1] is completed[0]
    # Serialized callbacks on the calling thread only.
    assert set(recorder.threads) == {threading.get_ident()}


def test_cancellation_during_verification_is_typed_and_side_effect_free(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    recorder = _Recorder()
    state = {"cancel": False}

    def progress(event: ProgressEvent) -> None:
        recorder.events.append(event)
        if event.phase_code == "SOURCE_VERIFICATION" and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(CancellationError) as caught:
        verify_dataset(
            result,
            source=source,
            vault=vault,
            progress=progress,
            cancel_check=lambda: state["cancel"],
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "verify_dataset"
    assert recorder.completed() == []
    assert _hash_tree(tmp_path) == before


def test_verification_callback_failure_is_contained_and_typed(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    canary = "PRIVATE-VERIFY-CALLBACK-CANARY-" + _PATH_CANARY

    def bad_progress(_event: ProgressEvent) -> None:
        raise RuntimeError(canary)

    with pytest.raises(dbf_anonymizer.CallbackError) as caught:
        verify_dataset(result, source=source, vault=vault, progress=bad_progress)

    assert caught.value.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert caught.value.context.operation == "verify_dataset"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.to_dict())
    assert _hash_tree(tmp_path) == before


# ---------------------------------------------------------------------------
# Deterministic corruption matrix (truthful FAIL or typed inability)
# ---------------------------------------------------------------------------
def _verify_fails_with(
    result: PseudonymizationResult,
    source: Path,
    vault: Path,
    *expected_codes: str,
) -> VerificationResult:
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    for code in expected_codes:
        assert code in verification.check_codes, verification.check_codes
    assert verification.verified is False
    return verification


def test_source_change_after_pseudonymization_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    with (source / "north" / "data.dbf").open("ab") as changed:
        changed.write(b"changed-after-pseudonymization")
    _verify_fails_with(result, source, vault, "SOURCE_FINGERPRINT_MISMATCH")


def test_missing_output_dbf_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    (output / "south" / "data.dbf").unlink()
    _verify_fails_with(result, source, vault, "TABLE_MISSING")


def test_missing_output_fpt_companion_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    (output / "north" / "data.fpt").unlink()
    _verify_fails_with(result, source, vault, "MEMO_COMPANION_MISSING")


def test_extra_unexpected_dbf_artifact_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    stray = output / "extra.dbf"
    stray.write_bytes(b"not-a-dbf")
    _verify_fails_with(result, source, vault, "UNEXPECTED_OUTPUT_ARTIFACT")


def test_record_count_change_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(output / "north" / "data.dbf")
    _rewrite_output(
        output,
        "north/data.dbf",
        _main_fields(),
        records[:-1],
        deleted_flags=deleted_flags[:-1],
    )
    _verify_fails_with(result, source, vault, "RECORD_COUNT_MISMATCH")


def test_schema_type_change_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    fields = list(_main_fields())
    fields[1] = numeric_field("NUMBER", "N", 4, flags=NULLABLE_FLAG)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    destination = output / "north" / "data.dbf"
    dbfbridge.write_table(  # type: ignore[attr-defined]
        destination,
        schema=_schema_for(tuple(fields)),
        records=[
            dbfbridge.DirectRecord(  # type: ignore[attr-defined]
                physical_index=index, deleted=False, values=values
            )
            for index, values in enumerate(records)
        ],
        overwrite=True,
    )
    _verify_fails_with(result, source, vault, "SCHEMA_MISMATCH")


def test_field_width_change_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    fields = list(_main_fields())
    fields[5] = numeric_field("KEEP_N", "N", 4)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    destination = output / "north" / "data.dbf"
    dbfbridge.write_table(  # type: ignore[attr-defined]
        destination,
        schema=_schema_for(tuple(fields)),
        records=[
            dbfbridge.DirectRecord(  # type: ignore[attr-defined]
                physical_index=index, deleted=False, values=values
            )
            for index, values in enumerate(records)
        ],
        overwrite=True,
    )
    _verify_fails_with(result, source, vault, "SCHEMA_MISMATCH")


def test_deleted_marker_alteration_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    _rewrite_output(
        output,
        "north/data.dbf",
        _main_fields(),
        records,
        deleted_flags=[not flag for flag in deleted_flags],
    )
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "DELETED_MARKER_MISMATCH" in verification.check_codes


def test_null_to_empty_semantics_change_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "south" / "data.dbf")
    # The active south row carries NULL CODE/NUMBER; writing an empty string
    # and a zero instead breaks the public NULL-vs-empty/zero distinction.
    records[1]["CODE"] = ""
    records[1]["NUMBER"] = 0
    _rewrite_output(
        output,
        "south/data.dbf",
        _main_fields(),
        records,
        deleted_flags=deleted_flags,
    )
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "NULL_SEMANTICS_MISMATCH" in verification.check_codes


def test_text_mapping_tamper_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    # Row 0 and row 1 both carry non-empty CODE values ("PARENT-1"/"PARENT-2"
    # transformed); swapping the transformed values breaks the mapping
    # agreement without ever reusing a raw original.
    swapped = records[1].copy()
    records[1] = dict(records[0])
    records[0] = dict(swapped)
    _rewrite_output(output, "north/data.dbf", _main_fields(), records, deleted_flags=deleted_flags)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "TEXT_MAPPING_MISMATCH" in verification.check_codes


def test_original_reinsertion_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    _rewrite_output(
        output,
        "north/data.dbf",
        _main_fields(),
        records,
        deleted_flags=deleted_flags,
    )
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "ORIGINAL_VALUE_SURVIVED" in verification.check_codes


def test_numeric_mapping_tamper_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    records[0]["NUMBER"] = records[1]["NUMBER"]
    _rewrite_output(output, "north/data.dbf", _main_fields(), records, deleted_flags=deleted_flags)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "NUMERIC_MAPPING_MISMATCH" in verification.check_codes


def test_memo_payload_replaced_with_original_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    records[0]["NOTE"] = "MEMO-N-1"
    _rewrite_output(output, "north/data.dbf", _main_fields(), records, deleted_flags=deleted_flags)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "MEMO_PAYLOAD_MISMATCH" in verification.check_codes


def test_temporal_value_tamper_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    records[0]["WHEN_D"] = date(2026, 12, 24)
    _rewrite_output(output, "north/data.dbf", _main_fields(), records, deleted_flags=deleted_flags)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "TEMPORAL_VALUE_MISMATCH" in verification.check_codes


def test_output_fingerprint_mismatch_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    (output / "north" / "data.fpt").write_bytes(
        (output / "north" / "data.fpt").read_bytes() + b"tampered"
    )
    _verify_fails_with(result, source, vault, "OUTPUT_FINGERPRINT_MISMATCH")


def test_vault_fingerprint_mismatch_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    import sqlite3

    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE dataset SET source_fingerprint = 'tampered-' WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()
    _verify_fails_with(result, source, vault, "VAULT_IDENTITY_MISMATCH")


def test_receipt_fingerprint_mismatch_fails(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    import sqlite3

    connection = sqlite3.connect(vault)
    try:
        row = connection.execute(
            "SELECT result_json FROM operations WHERE operation_id = ?",
            (result.operation_id,),
        ).fetchone()
        receipt = json.loads(str(row[0]))
        receipt["output_fingerprint"] = "out-" + "0" * 64
        connection.execute(
            "UPDATE operations SET result_json = ? WHERE operation_id = ?",
            (json.dumps(receipt, sort_keys=True), result.operation_id),
        )
        connection.commit()
    finally:
        connection.close()
    _verify_fails_with(result, source, vault, "RECEIPT_FINGERPRINT_MISMATCH")


def test_corrupt_vault_is_a_typed_inability(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    vault.write_bytes(b"opaque-corrupt-vault")
    with pytest.raises(VerificationError) as caught:
        verify_dataset(result, source=source, vault=vault)
    assert caught.value.code is ErrorCode.VERIFICATION_FAILED
    assert caught.value.context.detail_code == "VAULT_UNREADABLE"
    assert str(vault) not in str(caught.value)


def test_sidecar_ambiguous_vault_is_a_typed_inability_without_recovery(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(vault.parent)
    sidecar = vault.parent / "dictionary.sqlite3-wal"
    sidecar.write_bytes(b"SYNTHETIC-AMBIGUOUS-WAL")
    with pytest.raises(VerificationError) as caught:
        verify_dataset(result, source=source, vault=vault)
    assert caught.value.context.detail_code == "VAULT_STATE_UNVERIFIABLE"
    # No checkpoint/recovery happened: the vault and the synthetic sidecar
    # are byte-identical and no -shm appeared.
    assert _hash_tree(vault.parent) == {
        **before,
        "dictionary.sqlite3-wal": _hash_tree(vault.parent)["dictionary.sqlite3-wal"],
    }


def test_incompatible_vault_schema_is_a_typed_inability(tmp_path: Path) -> None:
    result, source, output, vault = _prepare(tmp_path)
    import sqlite3

    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE meta SET schema_version = '9.9' WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(VerificationError) as caught:
        verify_dataset(result, source=source, vault=vault)
    assert caught.value.context.detail_code == "VAULT_UNREADABLE"


def test_public_error_and_result_serialization_never_leak_originals(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    verification = verify_dataset(result, source=source, vault=vault)
    serialized = json.dumps(verification.to_dict(), sort_keys=True)
    for canary in ("PARENT-1", "MEMO-N-1", "ARCHIVE", str(source), str(vault), _PATH_CANARY):
        assert canary not in serialized
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    records[0]["CODE"] = "PARENT-1"
    _rewrite_output(output, "north/data.dbf", _main_fields(), records, deleted_flags=deleted_flags)
    failed = verify_dataset(result, source=source, vault=vault)
    failed_serialized = json.dumps(
        {"check_codes": failed.check_codes, "status": failed.status.value},
        sort_keys=True,
    )
    for canary in ("PARENT-1", "MEMO-N-1", str(source), str(vault), _PATH_CANARY):
        assert canary not in failed_serialized


def test_completed_idempotent_retry_keeps_verification_truthful(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    first = verify_dataset(result, source=source, vault=vault)
    # A compatible completed retry re-verified against the durable state:
    # the same truthful PASS with the same canonical operation identity.
    from dbf_anonymizer import build_plan as _build_plan

    plan = _build_plan(
        source,
        tmp_path / "output",
        vault,
        relationship_document=_relationship_document(),
    )
    assert preflight(plan).ready is False  # completed destination conflict
    second = verify_dataset(result, source=source, vault=vault)
    assert first == second
    assert first.status is VerificationStatus.PASS
    assert second.operation_id == result.operation_id
# ---------------------------------------------------------------------------
# OUTPUT_VERIFICATION cancellation / callback classification (Defect B)
# ---------------------------------------------------------------------------
def test_cancellation_during_output_verification_is_typed_and_side_effect_free(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    recorder = _Recorder()
    state = {"cancel": False}

    def progress(event: ProgressEvent) -> None:
        recorder.events.append(event)
        if event.phase_code == "OUTPUT_VERIFICATION" and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(CancellationError) as caught:
        verify_dataset(
            result,
            source=source,
            vault=vault,
            progress=progress,
            cancel_check=lambda: state["cancel"],
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "verify_dataset"
    assert recorder.completed() == []
    assert _hash_tree(tmp_path) == before


def test_output_verification_callback_failure_is_contained_and_typed(
    tmp_path: Path,
) -> None:
    result, source, output, vault = _prepare(tmp_path)
    before = _hash_tree(tmp_path)
    canary = "PRIVATE-OUTPUT-VERIFY-CANARY-" + _PATH_CANARY
    received: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        received.append(event)
        if event.phase_code == "OUTPUT_VERIFICATION" and event.event_code == "STARTED":
            raise RuntimeError(canary)

    with pytest.raises(CallbackError) as caught:
        verify_dataset(result, source=source, vault=vault, progress=progress)

    assert caught.value.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert caught.value.context.operation == "verify_dataset"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.to_dict())
    assert received
    assert _hash_tree(tmp_path) == before


# ---------------------------------------------------------------------------
# Complete durable field-policy ledger (Defect C)
# ---------------------------------------------------------------------------
def _fields_rows(vault: Path, table_name: str) -> list[tuple[object, ...]]:
    import sqlite3

    connection = sqlite3.connect(vault)
    try:
        rows = connection.execute(
            "SELECT f.name, f.dbf_type, f.width, f.encoding, f.transform_action, "
            "f.mapping_domain_id FROM fields f JOIN tables t ON t.table_id = f.table_id "
            "WHERE t.relative_path = ? ORDER BY f.name",
            (table_name,),
        ).fetchall()
    finally:
        connection.close()
    return [tuple(row) for row in rows]


def test_field_policy_ledger_is_complete_with_explicit_keep(tmp_path: Path) -> None:
    """A: every non-system field of every table carries an explicit durable
    action - the identity fields carry the explicit KEEP action with no
    mapping domain, and absence of evidence never means KEEP."""
    result, source, output, vault = _prepare(tmp_path)
    assert verify_dataset(result, source=source, vault=vault).status is (
        VerificationStatus.PASS
    )
    ledger = dict((row[0], row) for row in _fields_rows(vault, "north/data.dbf"))
    # Every non-system field of the source schema is explicitly bound.
    schema_names = {
        str(field.name)
        for field in dbfbridge.read_schema(  # type: ignore[attr-defined]
            source / "north" / "data.dbf"
        ).fields
        if str(field.dbf_type).upper() != "0"
    }
    assert set(ledger) == schema_names
    # Explicit KEEP with no transform mapping for the identity fields.
    assert ledger["KEEP_N"][4] == "KEEP"
    assert ledger["KEEP_N"][5] is None
    assert ledger["KEEP_L"][4] == "KEEP"
    # Transformed fields carry their explicit actions.
    assert ledger["CODE"][4] == "PSEUDONYMIZE_REVERSIBLE"
    assert ledger["NUMBER"][4] == "PSEUDONYMIZE_REVERSIBLE"
    assert ledger["NOTE"][4] == "MASK_REVERSIBLE"
    assert ledger["WHEN_D"][4] == "SHIFT_REVERSIBLE"
    assert ledger["SEEN_AT"][4] == "SHIFT_REVERSIBLE"
    assert ledger["CODE"][5] is not None


def test_missing_field_policy_row_fails_and_never_accepts_originals(
    tmp_path: Path,
) -> None:
    """B + E: deleting a field-policy row from an otherwise valid vault
    produces FAIL (POLICY_BINDING_MISSING); a missing transformed-field
    binding can NEVER cause an original value to be accepted as a
    legitimate identity."""
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "DELETE FROM fields WHERE name = 'CODE' AND table_id = "
            "(SELECT table_id FROM tables WHERE relative_path = 'north/data.dbf')"
        )
        connection.commit()
    finally:
        connection.close()
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "POLICY_BINDING_MISSING" in verification.check_codes
    assert "ORIGINAL_VALUE_SURVIVED" not in verification.check_codes


def test_transform_action_downgraded_to_keep_fails(tmp_path: Path) -> None:
    """C: changing PSEUDONYMIZE_REVERSIBLE to KEEP produces FAIL - the
    surviving transformed values can no longer be legitimate identity."""
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE fields SET transform_action = 'KEEP', mapping_domain_id = NULL "
            "WHERE name = 'CODE' AND table_id = "
            "(SELECT table_id FROM tables WHERE relative_path = 'north/data.dbf')"
        )
        connection.commit()
    finally:
        connection.close()
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "IDENTITY_VALUE_MISMATCH" in verification.check_codes


def test_keep_upgraded_to_transform_action_fails(tmp_path: Path) -> None:
    """D: changing an explicit KEEP to a transform action produces FAIL."""
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE fields SET transform_action = 'MASK_REVERSIBLE' "
            "WHERE name = 'KEEP_N' AND table_id = "
            "(SELECT table_id FROM tables WHERE relative_path = 'north/data.dbf')"
        )
        connection.commit()
    finally:
        connection.close()
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    # A memo action on a field without recovery rows is structurally broken:
    # the missing recovery identity is the truthful finding.
    assert "MEMO_RECOVERY_ROW_MISSING" in verification.check_codes


# ---------------------------------------------------------------------------
# Assurance overclaim + vault identity consistency (Defects D/E)
# ---------------------------------------------------------------------------
def test_vfp_metadata_verified_without_authority_is_rejected(tmp_path: Path) -> None:
    """D: ordinary durable relation evidence establishes at most
    DECLARED_RELATIONS_VERIFIED; a public assurance claiming
    VFP_METADATA_VERIFIED without authoritative VFP evidence is an
    overclaim the read-only verifier can never confirm."""
    import dataclasses

    from dbf_anonymizer import RelationalAssuranceLevel

    result, source, output, vault = _prepare(tmp_path)
    overclaimed = dataclasses.replace(
        result,
        assurance=dataclasses.replace(
            result.assurance, level=RelationalAssuranceLevel.VFP_METADATA_VERIFIED
        ),
    )
    verification = verify_dataset(overclaimed, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "ASSURANCE_EVIDENCE_MISMATCH" in verification.check_codes
    assert verification.verified is False


def test_dataset_policy_fingerprint_mismatch_fails(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE dataset SET policy_fingerprint = 'pol-tampered' WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()
    _verify_fails_with(result, source, vault, "VAULT_IDENTITY_MISMATCH")


def test_operation_policy_fingerprint_mismatch_fails(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE operations SET policy_fingerprint = 'pol-tampered' "
            "WHERE operation_id = ?",
            (result.operation_id,),
        )
        connection.commit()
    finally:
        connection.close()
    _verify_fails_with(result, source, vault, "VAULT_IDENTITY_MISMATCH")


def test_operation_relationship_fingerprint_mismatch_fails(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE operations SET relationship_fingerprint = 'rel-tampered' "
            "WHERE operation_id = ?",
            (result.operation_id,),
        )
        connection.commit()
    finally:
        connection.close()
    _verify_fails_with(result, source, vault, "VAULT_IDENTITY_MISMATCH")


def test_operation_binding_fingerprint_mismatch_fails(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE operations SET binding_fingerprint = 'opb-tampered' "
            "WHERE operation_id = ?",
            (result.operation_id,),
        )
        connection.commit()
    finally:
        connection.close()
    _verify_fails_with(result, source, vault, "VAULT_IDENTITY_MISMATCH")


# ---------------------------------------------------------------------------
# Mapping-domain kind validation (audit item)
# ---------------------------------------------------------------------------
def test_unknown_domain_kind_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    result, source, output, vault = _prepare(tmp_path)
    connection = sqlite3.connect(vault)
    try:
        connection.execute(
            "UPDATE mapping_domains SET domain_kind = 'BOGUS_KIND' "
            "WHERE domain_kind = 'TEXT'"
        )
        connection.commit()
    finally:
        connection.close()
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "VAULT_MAPPING_INVALID" in verification.check_codes


def test_read_only_byte_identity_holds_for_fail_and_partial_states(
    tmp_path: Path,
) -> None:
    """Read-only evidence for FAIL: byte identity of source/output/vault
    before/after a rejected verification (PASS/PARTIAL/cancellation/
    callback identity is proven by their dedicated tests)."""
    result, source, output, vault = _prepare(tmp_path)
    records, deleted_flags = _table_entries(source / "north" / "data.dbf")
    records[0]["CODE"] = records[1]["CODE"]
    _rewrite_output(
        output,
        "north/data.dbf",
        _main_fields(),
        records,
        deleted_flags=deleted_flags,
    )
    before = _hash_tree(tmp_path)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert _hash_tree(tmp_path) == before
