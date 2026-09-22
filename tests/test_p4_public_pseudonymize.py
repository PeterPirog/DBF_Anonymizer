"""REQ-P4-008/P4-009 public synchronous pseudonymize acceptance evidence."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

import dbfbridge
import pytest

import dbf_anonymizer
from dbf_anonymizer import (
    CallbackError,
    CancellationError,
    ErrorCode,
    PathError,
    ProgressEvent,
    Plan,
    PublicationError,
    PseudonymizationResult,
    RelationalAssuranceLevel,
    build_plan,
    preflight,
    pseudonymize,
)
from dbf_anonymizer.engine import pass2 as pass2_module
from dbf_anonymizer.engine import run as run_module
from dbf_anonymizer.engine.directives import RelationPassSummary
from dbf_anonymizer.engine.publication import DatasetStaging
from dbf_anonymizer.vault.store import VaultDatabase
from tests.support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table_with_deleted,
)


def _relationships() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-text",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": table,
                        "field": "TEXT_KEY",
                        "role": role,
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    }
                    for table, role in (
                        ("north/data.dbf", "PRIMARY"),
                        ("south/data.dbf", "FOREIGN"),
                    )
                ],
            }
        ],
    }


def _write_dataset(source: Path) -> None:
    fields = (
        numeric_field("TEXT_KEY", "C", 12, flags=NULLABLE_FLAG),
        numeric_field("NUMBER", "I", 4, flags=NULLABLE_FLAG),
        numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
    )
    write_numeric_table_with_deleted(
        source,
        "north/data.dbf",
        fields,
        [
            ({"TEXT_KEY": "PARENT-1", "NUMBER": -7, "NOTE": "MEMO-N-1"}, False),
            ({"TEXT_KEY": "PARENT-2", "NUMBER": 5, "NOTE": None}, True),
            ({"TEXT_KEY": "PARENT-3", "NUMBER": 99, "NOTE": ""}, False),
        ],
    )
    write_numeric_table_with_deleted(
        source,
        "south/data.dbf",
        fields,
        [
            ({"TEXT_KEY": "PARENT-1", "NUMBER": -7, "NOTE": "MEMO-S-1"}, True),
            ({"TEXT_KEY": "PARENT-1", "NUMBER": -7, "NOTE": ""}, False),
            ({"TEXT_KEY": "ORPHAN", "NUMBER": 1234, "NOTE": None}, False),
            ({"TEXT_KEY": None, "NUMBER": None, "NOTE": "MEMO-S-NULL"}, False),
        ],
    )
    write_numeric_table_with_deleted(
        source,
        "archive/memo.dbf",
        fields,
        [
            ({"TEXT_KEY": "ARCHIVE", "NUMBER": 42, "NOTE": "MEMO-ARCHIVE"}, False),
            ({"TEXT_KEY": None, "NUMBER": None, "NOTE": None}, True),
        ],
    )


def _plan(
    tmp_path: Path, *, name: str = "run", relationships: bool = True
) -> tuple[Plan, Path, Path, Path]:
    source = tmp_path / "source"
    if not source.exists():
        _write_dataset(source)
    output = tmp_path / f"output-{name}"
    vault = tmp_path / f"vault-{name}" / "dictionary.sqlite3"
    plan = build_plan(
        source,
        output,
        vault,
        relationship_document=_relationships() if relationships else None,
    )
    return plan, source, output, vault


def _hash_tree(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _logical_tree(root: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    result: dict[str, tuple[tuple[object, ...], ...]] = {}
    for path in sorted(root.rglob("*.dbf")):
        result[path.relative_to(root).as_posix()] = tuple(
            (
                record.physical_index,
                record.deleted,
                tuple(sorted(record.values.items())),
            )
            for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
                path, include_deleted=True, memo="inline"
            )
        )
    return result


class _ProgressRecorder:
    """Deterministic synchronous progress recorder (serialized, same thread)."""

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

    def completed_events(self) -> list[ProgressEvent]:
        return [event for event in self.events if event.event_code == "COMPLETED"]


def _vault_counts(plan: object, vault_path: Path) -> tuple[int, int, int, int]:
    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,  # type: ignore[attr-defined]
        expected_policy_fingerprint=plan.policy.policy_fingerprint,  # type: ignore[attr-defined]
        expected_relationship_fingerprint=(
            plan.relationships.relationship_fingerprint  # type: ignore[attr-defined]
        ),
    ) as vault:
        connection = vault._internal_connection()
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "operations",
                "text_mappings",
                "numeric_key_mappings",
                "memo_recovery",
            )
        )  # type: ignore[return-value]


def test_public_workers_one_and_many_publish_equivalent_rich_datasets(
    tmp_path: Path,
) -> None:
    serial_plan, source, serial_output, serial_vault = _plan(
        tmp_path, name="serial"
    )
    parallel_output = tmp_path / "output-parallel"
    parallel_plan = build_plan(
        source,
        parallel_output,
        serial_vault,
        relationship_document=_relationships(),
    )
    source_before = _hash_tree(source)

    serial = pseudonymize(serial_plan, workers=1)
    events: list[ProgressEvent] = []
    callback_threads: list[int] = []

    def progress(event: ProgressEvent) -> None:
        events.append(event)
        callback_threads.append(threading.get_ident())

    parallel = pseudonymize(
        parallel_plan,
        workers=3,
        progress=progress,
        cancel_check=lambda: False,
    )

    assert isinstance(serial, PseudonymizationResult)
    assert isinstance(parallel, PseudonymizationResult)
    assert serial.table_count == parallel.table_count == 3
    assert serial.record_count == parallel.record_count == 9
    assert serial.vault_created is True
    assert parallel.vault_created is False
    assert serial.output_path == "output-serial"
    assert parallel.output_path == "output-parallel"
    assert (
        serial.assurance.level
        is parallel.assurance.level
        is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    )
    assert serial.assurance.verified_relations == 1
    assert serial.assurance.evidence_fingerprint is not None
    assert serial.assurance.evidence_fingerprint == parallel.assurance.evidence_fingerprint
    assert _logical_tree(serial_output) == _logical_tree(parallel_output)
    assert _hash_tree(serial_output) == _hash_tree(parallel_output)
    assert _hash_tree(source) == source_before

    assert events
    assert len({event.operation_id for event in events}) == 1
    assert sum(event.event_code == "COMPLETED" for event in events) == 1
    assert events[-1].event_code == "COMPLETED"
    assert set(callback_threads) == {threading.get_ident()}
    assert all(isinstance(event, ProgressEvent) for event in events)

    serialized = json.dumps(parallel.to_dict(), sort_keys=True)
    assert str(source) not in serialized
    assert str(serial_vault) not in serialized
    assert "PARENT-1" not in serialized
    assert "MEMO-S-NULL" not in serialized
    assert str(parallel_output) not in repr(parallel)


def test_completed_retry_returns_equivalent_public_result_without_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, source, output, vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    first = pseudonymize(plan, workers=2)
    output_before = _hash_tree(output)
    mtimes_before = {
        path.relative_to(output).as_posix(): path.stat().st_mtime_ns
        for path in output.rglob("*")
        if path.is_file()
    }
    vault_before = _vault_counts(plan, vault)

    # Preflight classifies the completed state exactly: the only blocker is
    # the existing destination condition, and the vault passed the read-only
    # identity validation (no VAULT_REUSE_INCOMPATIBLE can hide here).
    check = preflight(plan)
    assert check.ready is False
    assert check.error_codes == ("DESTINATION_CONFLICT",)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("completed retry entered a transformation pass")

    monkeypatch.setattr(run_module, "run_pass_one", forbidden)
    monkeypatch.setattr(run_module, "run_pass_two", forbidden)
    retry_recorder = _ProgressRecorder()
    second = pseudonymize(plan, workers=3, progress=retry_recorder)

    # One coherent public operation stream: one operation id, exactly one
    # terminal COMPLETED (public-owned), and NO transformation-pass phase.
    retry_events = retry_recorder.events
    assert retry_events
    # The retry stream uses the SAME canonical durable operation id.
    assert second.operation_id == first.operation_id
    assert {event.operation_id for event in retry_events} == {second.operation_id}
    retry_completed = retry_recorder.completed_events()
    assert len(retry_completed) == 1
    assert retry_events[-1] is retry_completed[0]
    assert not retry_recorder.phase("PASS1_SCAN", "STARTED")
    assert not retry_recorder.phase("PASS2_WRITE", "STARTED")
    assert retry_recorder.phase("SOURCE_REVALIDATION", "STARTED")

    assert second == first
    assert second.vault_created is True
    assert _hash_tree(output) == output_before
    assert {
        path.relative_to(output).as_posix(): path.stat().st_mtime_ns
        for path in output.rglob("*")
        if path.is_file()
    } == mtimes_before
    assert _vault_counts(plan, vault) == vault_before
    assert _hash_tree(source) == source_before


def test_failed_preflight_refuses_before_output_or_vault_mutation(tmp_path: Path) -> None:
    plan, source, output, vault = _plan(tmp_path)
    with (source / "north" / "data.dbf").open("ab") as changed:
        changed.write(b"changed-after-planning")

    with pytest.raises(PublicationError) as caught:
        pseudonymize(plan)

    assert caught.value.code is ErrorCode.PUBLICATION_FAILED
    assert caught.value.context.detail_code == "PREFLIGHT_REJECTED"
    assert not output.exists()
    assert not vault.exists()


def test_unsafe_existing_target_fails_closed_before_any_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hostile existing-target regression for the public retry gate.

    A destination conflict is granted the engine-retry path ONLY when BOTH
    durable targets are structurally present AND the vault passed preflight's
    read-only identity validation (an incompatible vault emits
    ``VAULT_REUSE_INCOMPATIBLE`` and can never appear in a
    destination-conflict-only error set). Every unsafe existing-target state
    must refuse at the public gate, before ANY filesystem mutation — no
    engine entry, no lock, no staging, no vault mutation.
    """

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unsafe target reached the engine transformation pass")

    monkeypatch.setattr(run_module, "run_pass_one", forbidden)
    monkeypatch.setattr(run_module, "run_pass_two", forbidden)

    # 1. Unowned non-empty output directory with no vault at all.
    plan, source, output, vault = _plan(tmp_path / "unowned-output")
    output.mkdir(parents=True)
    marker = output / "operator-owned.txt"
    marker.write_text("operator-owned", encoding="ascii")
    source_before = _hash_tree(source)
    with pytest.raises(PublicationError) as unowned:
        pseudonymize(plan)
    assert unowned.value.context.detail_code == "PREFLIGHT_REJECTED"
    assert marker.read_text(encoding="ascii") == "operator-owned"
    assert not vault.exists()
    assert not any(output.parent.glob(".dbf-anonymizer-*"))
    assert _hash_tree(source) == source_before

    # 2. Vault target is a directory, output missing.
    plan, source, output, vault = _plan(tmp_path / "vault-dir")
    vault.mkdir(parents=True)
    source_before_vault_dir = _hash_tree(source)
    with pytest.raises(PublicationError) as vault_dir:
        pseudonymize(plan)
    assert vault_dir.value.context.detail_code == "PREFLIGHT_REJECTED"
    assert vault.is_dir()
    assert not output.exists()
    assert _hash_tree(source) == source_before_vault_dir

    # 3. Output target is a regular file, vault missing.
    plan, source, output, vault = _plan(tmp_path / "output-file")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"operator-owned-bytes")
    source_before_output_file = _hash_tree(source)
    with pytest.raises(PublicationError) as output_file:
        pseudonymize(plan)
    assert output_file.value.context.detail_code == "PREFLIGHT_REJECTED"
    assert output.read_bytes() == b"operator-owned-bytes"
    assert not vault.exists()
    assert _hash_tree(source) == source_before_output_file

    # 4. Foreign opaque vault + existing output: the read-only preflight
    #    identity validation rejects the reuse candidate, so the public gate
    #    refuses BEFORE the engine is entered at all (the transformation
    #    guards above stay silent) and nothing is touched.
    plan, source, output, vault = _plan(tmp_path / "foreign-vault")
    output.mkdir(parents=True)
    (output / "stale.dat").write_bytes(b"stale-operator-data")
    vault.parent.mkdir(parents=True, exist_ok=True)
    vault.write_bytes(b"opaque-foreign-vault")
    vault_before = vault.read_bytes()
    source_before_foreign = _hash_tree(source)
    check = preflight(plan)
    assert check.error_codes == ("DESTINATION_CONFLICT", "VAULT_REUSE_INCOMPATIBLE")
    with pytest.raises(PublicationError) as foreign:
        pseudonymize(plan)
    assert foreign.value.context.detail_code == "PREFLIGHT_REJECTED"
    assert vault.read_bytes() == vault_before
    assert (output / "stale.dat").read_bytes() == b"stale-operator-data"
    assert not any(output.parent.glob(".dbf-anonymizer-*"))
    assert _hash_tree(source) == source_before_foreign

    # 5. Foreign opaque vault with a missing output: incompatible reuse is
    #    refused at the gate even without any destination conflict.
    plan, source, output, vault = _plan(tmp_path / "opaque-vault-fresh")
    vault.parent.mkdir(parents=True, exist_ok=True)
    vault.write_bytes(b"opaque-unverifiable-vault")
    source_before_opaque = _hash_tree(source)
    with pytest.raises(PublicationError) as opaque:
        pseudonymize(plan)
    assert opaque.value.context.detail_code == "PREFLIGHT_REJECTED"
    assert vault.read_bytes() == b"opaque-unverifiable-vault"
    assert not output.exists()
    assert _hash_tree(source) == source_before_opaque


def test_hostile_unrelated_output_with_compatible_vault_is_not_completed_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A compatible existing vault plus hostile unrelated output must never
    be mistaken for a completed retry: preflight keeps ONLY the destination
    finding (the vault passed the read-only identity validation), the engine
    is entered and its durable operation binding refuses the unowned target
    before any mutation — without entering either transformation pass."""
    plan, source, output, vault = _plan(tmp_path / "hostile-output")
    vault.parent.mkdir(parents=True, exist_ok=True)
    compatible = VaultDatabase.open(
        vault,
        create=True,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
        dbfbridge_version=str(dbfbridge.__version__),
    )
    compatible.close()
    vault_before = vault.read_bytes()
    output.mkdir(parents=True)
    marker = output / "operator-owned.txt"
    marker.write_text("operator-owned", encoding="ascii")

    check = preflight(plan)
    assert check.ready is False
    assert check.error_codes == ("DESTINATION_CONFLICT",)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("hostile output entered a transformation pass")

    monkeypatch.setattr(run_module, "run_pass_one", forbidden)
    monkeypatch.setattr(run_module, "run_pass_two", forbidden)

    with pytest.raises(PathError) as unowned:
        pseudonymize(plan)

    assert unowned.value.code is ErrorCode.DESTINATION_CONFLICT
    assert marker.read_text(encoding="ascii") == "operator-owned"
    assert vault.read_bytes() == vault_before
    # The engine-owned lock lifecycle may leave its transient lock artifact;
    # the durable targets and the output tree itself stay untouched and no
    # staging residue exists.
    assert not any(output.parent.glob("*.staging*"))
    assert [p.name for p in output.iterdir()] == ["operator-owned.txt"]


def test_worker_contract_is_typed_bounded_and_checked_before_side_effects(
    tmp_path: Path,
) -> None:
    plan, _source, output, vault = _plan(tmp_path)
    with pytest.raises(TypeError):
        pseudonymize(object())  # type: ignore[arg-type]
    for workers in (True, 0, -1, 33):
        with pytest.raises(ValueError):
            pseudonymize(plan, workers=workers)
    assert not output.exists()
    assert not vault.exists()


def test_public_cancellation_during_write_has_no_result_or_completed_event(
    tmp_path: Path,
) -> None:
    plan, source, output, _vault = _plan(tmp_path)
    source_before = _hash_tree(source)
    state = {"cancel": False}
    events: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        events.append(event)
        if event.phase_code == "PASS2_WRITE" and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(CancellationError) as caught:
        pseudonymize(
            plan,
            workers=3,
            progress=progress,
            cancel_check=lambda: state["cancel"],
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "pseudonymize"
    assert not output.exists()
    assert not any(event.event_code == "COMPLETED" for event in events)
    assert _hash_tree(source) == source_before
    # The whole public stream stays ONE operation even across the passes.
    assert len({event.operation_id for event in events}) == 1


def test_public_callback_failures_are_contained_and_privacy_safe(
    tmp_path: Path,
) -> None:
    plan, _source, output, vault = _plan(tmp_path)
    canary = "PRIVATE-CALLBACK-CANARY-C:/secret/source.dbf"

    def bad_cancel() -> bool:
        raise RuntimeError(canary)

    with pytest.raises(CallbackError) as cancel_failure:
        pseudonymize(plan, cancel_check=bad_cancel)
    assert cancel_failure.value.code is ErrorCode.CANCEL_CALLBACK_FAILED
    assert cancel_failure.value.context.operation == "pseudonymize"
    assert canary not in str(cancel_failure.value)
    assert canary not in repr(cancel_failure.value.to_dict())
    assert not output.exists()
    assert not vault.exists()

    def bad_progress(_event: ProgressEvent) -> None:
        raise RuntimeError(canary)

    with pytest.raises(CallbackError) as progress_failure:
        pseudonymize(plan, progress=bad_progress)
    assert progress_failure.value.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert progress_failure.value.context.operation == "pseudonymize"
    assert canary not in str(progress_failure.value)
    assert canary not in repr(progress_failure.value.to_dict())
    assert not output.exists()


def test_public_progress_stream_is_one_operation_across_preflight_and_engine(
    tmp_path: Path,
) -> None:
    """One public pseudonymize invocation is ONE logical progress operation.

    The shared side-effect-free preflight evaluation and the engine passes
    run under ONE controller: one operation id, bounded preflight-stage
    events (source verification + table evaluation), the engine's
    SOURCE_REVALIDATION/PASS1/PASS2 phases, and exactly ONE terminal
    COMPLETED event emitted only after genuine publication — no intermediate
    preflight completion, no per-byte callback flood, serialized callbacks
    on the calling thread.
    """
    from dbf_anonymizer.progress import PROGRESS_QUANTUM_VERSION

    assert PROGRESS_QUANTUM_VERSION == "1.2"

    plan, _source, _output, _vault = _plan(tmp_path)
    recorder = _ProgressRecorder()
    result = pseudonymize(plan, workers=2, progress=recorder)
    assert isinstance(result, PseudonymizationResult)

    events = recorder.events
    assert events
    # ONE canonical operation id across preflight-stage AND engine events,
    # identical to the durable publication identity and the public result:
    # every ProgressEvent.operation_id == PseudonymizationResult.operation_id.
    assert {event.operation_id for event in events} == {result.operation_id}
    assert result.operation_id.startswith("vop-")
    assert len(result.operation_id) == len("vop-") + 32

    # Preflight-stage events are observable within the public invocation.
    assert recorder.phase("SOURCE_VERIFICATION", "STARTED")
    assert recorder.phase("TABLE_EVALUATION", "STARTED")
    assert recorder.phase("TABLE_EVALUATION", "PROGRESS")

    # The engine stages follow the shared preflight evaluation.
    revalidation_started = recorder.phase("SOURCE_REVALIDATION", "STARTED")
    assert len(revalidation_started) == 1
    preflight_table_index = events.index(recorder.phase("TABLE_EVALUATION", "STARTED")[0])
    revalidation_index = events.index(revalidation_started[0])
    assert preflight_table_index < revalidation_index
    assert recorder.phase("PASS1_SCAN", "STARTED")
    assert recorder.phase("PASS1_FINALIZE", "STARTED")
    assert recorder.phase("PASS2_WRITE", "STARTED")
    pass2_index = events.index(recorder.phase("PASS2_WRITE", "STARTED")[0])
    assert revalidation_index < pass2_index

    # Exactly ONE terminal COMPLETED event: last, operation phase, after the
    # engine phases — never an intermediate preflight completion.
    completed = recorder.completed_events()
    assert len(completed) == 1
    assert events[-1] is completed[0]
    assert completed[0].phase_code == "OPERATION"
    assert events.index(completed[0]) > pass2_index

    # Serialized callbacks on the calling thread only.
    assert set(recorder.threads) == {threading.get_ident()}
    # Bounded, privacy-safe events: normalized relative paths only.
    for event in events:
        assert event.table_path is None or (
            not Path(event.table_path).is_absolute() and "\\" not in event.table_path
        )


def test_public_source_revalidation_reports_bounded_progress(tmp_path: Path) -> None:
    """The engine's pre-execution source re-scan reports bounded per-artifact
    progress through the SAME controller (reusing the fingerprint kernel's
    hooks/quanta — never a per-byte callback flood)."""
    plan, source, _output, _vault = _plan(tmp_path)
    recorder = _ProgressRecorder()
    pseudonymize(plan, progress=recorder)

    revalidation_progress = recorder.phase("SOURCE_REVALIDATION", "PROGRESS")
    assert revalidation_progress
    # Bounded: one event per in-scope artifact (DBF plus memo companions),
    # never per byte.
    in_scope = [
        path
        for path in source.rglob("*")
        if path.is_file() and path.suffix.lower() in {".dbf", ".fpt", ".cdx", ".idx"}
    ]
    assert len(revalidation_progress) == len(in_scope)
    counts = [event.completed_units for event in revalidation_progress]
    assert counts == sorted(counts)
    assert all(event.total_units == len(in_scope) for event in revalidation_progress)
    assert all(event.table_path is not None for event in revalidation_progress)
    # One STARTED precedes the progress events of its phase.
    started = recorder.phase("SOURCE_REVALIDATION", "STARTED")
    assert events_index(recorder, started[0]) < events_index(
        recorder, revalidation_progress[0]
    )


def events_index(recorder: _ProgressRecorder, event: ProgressEvent) -> int:
    return recorder.events.index(event)


def test_cancellation_inside_pseudonymize_preflight_is_typed_and_side_effect_free(
    tmp_path: Path,
) -> None:
    """Cancellation observed during the internal pseudonymize-preflight stage
    is the typed public cancellation attributed to the PUBLIC operation, and
    no output, vault, staging or lock artifact exists afterwards."""
    plan, _source, output, vault = _plan(tmp_path)
    recorder = _ProgressRecorder()
    state = {"cancel": False}

    def progress(event: ProgressEvent) -> None:
        recorder.events.append(event)
        if event.phase_code == "OPERATION" and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(CancellationError) as caught:
        pseudonymize(
            plan,
            progress=progress,
            cancel_check=lambda: state["cancel"],
        )

    assert caught.value.code is ErrorCode.OPERATION_CANCELLED
    assert caught.value.context.operation == "pseudonymize"
    assert not output.exists()
    assert not vault.exists()
    # Nothing was created anywhere: the vault directory either does not exist
    # or stayed empty, and no lock/staging artifact appeared.
    assert not vault.parent.exists() or list(vault.parent.iterdir()) == []
    assert not any(output.parent.glob(".dbf-anonymizer-*"))
    assert recorder.completed_events() == []


def test_progress_callback_failure_inside_preflight_is_contained_and_typed(
    tmp_path: Path,
) -> None:
    """A progress callback failure during the internal preflight stage is
    classified as PROGRESS_CALLBACK_FAILED attributed to the PUBLIC
    operation, leaks none of the raw callback message and creates no
    transformation state."""
    plan, _source, output, vault = _plan(tmp_path)
    canary = "PRIVATE-PREFLIGHT-CALLBACK-CANARY-C:/secret/source.dbf"
    received: list[ProgressEvent] = []

    def progress(event: ProgressEvent) -> None:
        received.append(event)
        raise RuntimeError(canary)

    with pytest.raises(CallbackError) as caught:
        pseudonymize(plan, progress=progress)

    assert caught.value.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert caught.value.context.operation == "pseudonymize"
    assert caught.value.context.detail_code == "PROGRESS_CALLBACK"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)
    assert canary not in json.dumps(caught.value.to_dict(), sort_keys=True)
    assert received  # the failure happened on the public operation stream
    assert caught.value.context is not None
    assert not output.exists()
    assert not vault.exists()
    assert not any(output.parent.glob(".dbf-anonymizer-*"))


def test_cancellation_requested_after_promotion_does_not_reclassify_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, _source, output, _vault = _plan(tmp_path)
    state = {"promoted": False, "late_polls": 0}
    real_promote = DatasetStaging.promote

    def promote(staging: DatasetStaging) -> None:
        real_promote(staging)
        state["promoted"] = True

    def cancel_check() -> bool:
        if state["promoted"]:
            state["late_polls"] += 1
            return True
        return False

    monkeypatch.setattr(DatasetStaging, "promote", promote)
    result = pseudonymize(plan, cancel_check=cancel_check)

    assert isinstance(result, PseudonymizationResult)
    assert output.is_dir()
    assert state == {"promoted": True, "late_polls": 0}


def test_public_assurance_reports_global_and_failed_declared_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    global_plan, _source, _output, _vault = _plan(
        tmp_path / "global", relationships=False
    )
    global_result = pseudonymize(global_plan)
    assert global_result.assurance.level is RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    assert global_result.assurance.declared_relations == 0
    assert global_result.assurance.evidence_fingerprint is None

    declared_plan, _source, _output, _vault = _plan(tmp_path / "failed")
    real_compare = pass2_module._compare_relations

    def failed_compare(
        engine_plan: Any, spool: Any
    ) -> list[RelationPassSummary]:
        summaries = real_compare(engine_plan, spool)
        return [dataclasses.replace(summary, verified=False) for summary in summaries]

    monkeypatch.setattr(pass2_module, "_compare_relations", failed_compare)
    failed_result = pseudonymize(declared_plan)

    assert failed_result.assurance.level is RelationalAssuranceLevel.INCOMPLETE
    assert failed_result.assurance.verified_relations == 0
    assert failed_result.assurance.failed_relations == 1
    assert failed_result.assurance.incomplete_relations == 0
    assert failed_result.assurance.evidence_fingerprint is not None


def test_root_export_and_api_identity_are_exact() -> None:
    import dbf_anonymizer.api as api_module

    assert dbf_anonymizer.pseudonymize is api_module.pseudonymize
    assert "pseudonymize" in dbf_anonymizer.__all__


def test_canonical_operation_id_kernel_is_deterministic_and_retry_stable(
    tmp_path: Path,
) -> None:
    """The durable operation id is derived by ONE pure kernel from identity
    digests available before execution: deterministic, bounded stable
    ``vop-`` vocabulary, stable for exact compatible retries, and dependent
    on every identity input. Destination canonicalization is the ONE shared
    helper (never duplicated)."""
    from dbf_anonymizer.engine.publication import (
        derive_destination_identity,
        derive_operation_id,
    )

    def identifier(
        source: str = "src-a",
        policy: str = "pol-a",
        relationships: str = "rel-a",
        destination_identity: str = "dst-a",
    ) -> str:
        return derive_operation_id(
            source_fingerprint=source,
            policy_fingerprint=policy,
            relationship_fingerprint=relationships,
            destination_identity=destination_identity,
        )

    first = identifier()
    assert first == identifier()
    assert first.startswith("vop-")
    assert len(first) == len("vop-") + 32
    assert all(character in "0123456789abcdef" for character in first[4:])
    for changed in (
        {"source": "src-b"},
        {"policy": "pol-b"},
        {"relationships": "rel-b"},
        {"destination_identity": "dst-b"},
    ):
        assert identifier(**changed) != first

    # The ONE canonical destination identity: stable for the same root and
    # distinct for different roots.
    assert derive_destination_identity(tmp_path / "out-a") == (
        derive_destination_identity(tmp_path / "out-a")
    )
    assert derive_destination_identity(tmp_path / "out-a") != (
        derive_destination_identity(tmp_path / "out-b")
    )


def test_public_adaptation_failure_after_engine_return_emits_no_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deterministic failure AFTER the engine returned but BEFORE the public
    result exists: the shared public controller must NOT already have
    emitted COMPLETED — the public operation owns its terminal event and a
    failed adaptation never reports success."""
    import dbf_anonymizer.api as api_module

    plan, _source, _output, _vault = _plan(tmp_path)
    recorder = _ProgressRecorder()

    def failing_adaptation(relationships: object, evidence: object) -> object:
        raise RuntimeError("synthetic public adaptation failure")

    monkeypatch.setattr(
        api_module,
        "_derive_relational_assurance_from_bounded_evidence",
        failing_adaptation,
    )

    with pytest.raises(RuntimeError, match="synthetic public adaptation failure"):
        pseudonymize(plan, progress=recorder)

    assert recorder.events
    assert recorder.completed_events() == []
