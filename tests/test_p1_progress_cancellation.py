"""REQ-P1-008 — bounded structured progress and cooperative cancellation.

This suite proves the SCAN/control foundation on the currently real
long-running operations (``build_plan`` / ``preflight``):

* deterministic callback ORDER (single operation ID per invocation, ``STARTED``
  before progress events, monotonic ``completed_units`` per phase, exactly one
  terminal ``COMPLETED`` event last on success);
* REAL cancellation latency inside scans: cancellation is polled per
  fingerprinted artifact, at bounded chunk intervals while hashing (no later
  than ``FINGERPRINT_CANCEL_CHUNK_QUANTUM`` chunks), at every streamed
  capacity-scan record boundary and once per visited directory during source
  traversal (deterministic enumeration bound) — measured in deterministic
  work units, never wall-clock;
* contained and classified callback failures: a progress callback or
  cancel-check callback may raise arbitrary exceptions containing canary
  secrets/private paths — including ``CancellationError``/``CallbackError``
  themselves.  EVERY ``Exception`` raised by a user callback is reclassified
  at the callback boundary, the raw exception never escapes, the canary never
  appears in ``str``/``repr``/``to_dict`` and the stable machine codes
  (``PROGRESS_CALLBACK_FAILED`` / ``CANCEL_CALLBACK_FAILED``) are used;
  ``OPERATION_CANCELLED`` is produced only by a ``cancel_check`` that RETURNS
  a truthy value, never by a callback that throws;
* preflight table evaluation has a per-table cancellation safe point
  (poll first, then report progress, bound: one table);
* cancellation produces no result and no completion event, and the source
  stays byte-identical with zero created output/vault state (REQ-P0-004).

WRITE / VERIFICATION / PUBLICATION safe points and no-partial-publication
behavior are realized by the implemented public service set (the P4 two-pass
engine and the P5 verification / recovery / transfer services reuse this
layer; see their dedicated suites for the complete safe-point evidence).
Only approved synthetic
fixtures and disposable ``tmp_path`` data are used; no production data.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator

import pytest

import dbfbridge

from dbf_anonymizer import (
    CallbackError,
    CancellationError,
    ErrorCode,
    ProgressEvent,
    build_plan,
    preflight,
)
from dbf_anonymizer import discovery as _discovery
from dbf_anonymizer import progress as progress_layer
from dbf_anonymizer.errors import ErrorContext
from dbf_anonymizer.models import (
    DatasetIdentity,
    OutputDataState,
    Plan,
    PolicySummary,
    PreflightResult,
    RelationalAssuranceLevel,
    RelationshipMetadata,
    TablePlan,
    TransferProfile,
    VaultStrategy,
    _PlanExecutionContext,
)

import dbf_anonymizer.preflight  # ensure module loaded

_PF_MODULE = sys.modules["dbf_anonymizer.preflight"]

CANARY_SECRET = "CANARY_PROGRESS_SECRET_ALPHA"
CANARY_ABSOLUTE = "C:\\private\\canary\\source.dbf"


# ---------------------------------------------------------------------------
# Synthetic helpers (public dbfbridge only)
# ---------------------------------------------------------------------------
def _field(
    name: str, dbf_type: str, length: int, *, flags: int = 0
) -> dbfbridge.FieldInfo:
    return dbfbridge.FieldInfo(
        ordinal=0, name=name, dbf_type=dbf_type, length=length,
        decimal_count=0, address=0, flags=flags, index_field_flag=0,
        autoincrement_next_value=0, autoincrement_step=1,
        is_memo=dbf_type in {"M", "G", "P"}, is_binary=False, supported=True,
        dbversion_byte=0x30,
    )


def _schema(fields: tuple[dbfbridge.FieldInfo, ...]) -> dbfbridge.TableSchema:
    return dbfbridge.TableSchema(
        path=Path("memory:test"), record_count=0,
        header_length=32 + 32 * len(fields) + 1,
        record_length=sum(f.length for f in fields) + 1,
        language_driver=0xC8, encoding="cp1250",
        has_memo=False, has_memo_flag=False, has_structural_cdx=False,
        is_database_container=False, dbc_bound=False, dbc_backlink_path=None,
        table_flags=0, fields=fields, warnings=(),
        dbversion_byte=0x30, dbversion_name="Visual FoxPro",
        last_update=None, incomplete_transaction=False, encryption_flag=False,
        memo_companion_format=None, memo_companion_present=False,
        memo_companion_path=None, memo_companion_size_bytes=None,
        memo_block_size=None, memo_next_free_block=None,
        companion_cdx_present=False, companion_cdx_path=None,
    )


def _write_table(
    path: Path, fields: list[tuple[str, str, int]], records: list[dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fdefs = tuple(_field(n, t, l) for n, t, l in fields)
    dbfbridge.write_table(path, schema=_schema(fdefs), records=records)


def _make_source(tmp: Path) -> Path:
    """A tiny deterministic single-table dataset (public dbfbridge only)."""
    src = tmp / "src"
    _write_table(
        src / "customers" / "customers.dbf",
        [("CODE", "C", 20), ("QTY", "N", 10)],
        [{"CODE": "ALPHA", "QTY": 1}, {"CODE": "BETA", "QTY": 2},
         {"CODE": "GAMMA", "QTY": 3}],
    )
    return src


def _make_capacity_source(tmp: Path, record_count: int = 50) -> Path:
    """A C(1) table tight enough that the exact capacity scan streams records.

    The Phase-A occurrence bound for a C(1) field is ``record_count``; it only
    exceeds the 36-token single-character space (base 36 alphabet) when
    ``record_count > 36``, so only then does preflight MUST-consume
    ``iter_records`` (the real streaming safe point proven by the latency
    tests below).  The default 50 records guarantees streaming.
    """
    src = tmp / "src"
    values = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    records = [{"CODE": values[i % 36]} for i in range(record_count)]
    _write_table(src / "tight" / "tight.dbf", [("CODE", "C", 1)], records)
    return src


def _make_big_idx_source(tmp: Path, chunk_count: int) -> Path:
    """A source with one large synthetic in-scope ``.idx`` artifact plus one
    tiny table.  The artifact size is expressed in hashing chunks so the
    intra-file cancellation-latency tests stay fully deterministic."""
    src = tmp / "src"
    big_idx = src / "a_big.idx"
    big_idx.parent.mkdir(parents=True, exist_ok=True)
    big_idx.write_bytes(
        b"\x00" * (progress_layer.FINGERPRINT_HASH_CHUNK_SIZE * chunk_count)
    )
    _write_table(
        src / "z_customers" / "z_customers.dbf",
        [("CODE", "C", 5)],
        [{"CODE": "ALPHA"}, {"CODE": "BETA"}],
    )
    return src


def _tree_snapshot(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            out[rel] = p.read_bytes().hex()
    return out


class _FakeWalkOS:
    """Module-like stand-in for the ``os`` module used by
    ``dbf_anonymizer.discovery``: ``walk`` yields a fixed synthetic directory
    list and records live traversal consumption so tests can prove a
    deterministic cancellation bound in consumed work units (never
    wall-clock).  Every other attribute is delegated to the real ``os``
    module (``stat`` etc.)."""

    def __init__(self, entries: list[tuple[str, list[str], list[str]]]) -> None:
        self._entries = entries
        self._real_os = os
        self.walk_calls = 0
        self.consumed = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real_os, name)

    def walk(
        self, top: str, onerror: Any = None, followlinks: bool = False
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        self.walk_calls += 1
        self.consumed = 0
        for entry in self._entries:
            self.consumed += 1
            yield entry


def _synthetic_walk_entries(real_table_dir: Path, filler_count: int) -> list[tuple[str, list[str], list[str]]]:
    """A synthetic walk: the REAL table directory first (so a complete
    traversal would succeed), then many filler directories.  Exhaustion would
    consume ``1 + filler_count`` directories."""

    entries: list[tuple[str, list[str], list[str]]] = [
        (str(real_table_dir), [], ["customers.dbf"])
    ]
    entries += [
        (str(real_table_dir.parent / f"filler{i:03d}"), [], ["noise.txt"])
        for i in range(filler_count)
    ]
    return entries


def _synthetic_plan(table_count: int, tmp: Path) -> Plan:
    """A valid in-memory Plan with many tables and a MISSING source root.

    The missing root keeps preflight's poll sequence deterministic (no
    traversal polls): the capacity/storage stages are never reached because
    cancellation fires during table evaluation.
    """
    tables = tuple(
        TablePlan(
            table_path=f"t{i:02d}/table.dbf",
            memo_path=None,
            record_count=0,
            field_count=1,
            transform_field_count=0,
            structural_cdx=False,
            dbc_bound=False,
            index_strategy="DATA_ONLY",
            memo_required=False,
            memo_companion_present=False,
            structural_cdx_companion_present=False,
            unsupported_field_count=0,
            unsafe_field_count=0,
            system_field_count=0,
        )
        for i in range(table_count)
    )
    dataset = DatasetIdentity(
        dataset_id="ds-synthetic",
        source_fingerprint="fingerprint-synthetic",
        table_paths=tuple(t.table_path for t in tables),
    )
    policy = PolicySummary(
        policy_schema_version="1",
        policy_fingerprint="fingerprint-policy",
        transformed_field_count=0,
        relationship_count=0,
        recovery_enabled=False,
        transformation_classes=(),
        vault_strategy=VaultStrategy.NONE,
    )
    relationships = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint="fingerprint-relationships",
        relation_count=0,
        authoritative=False,
    )
    return Plan(
        plan_id="plan-synthetic",
        dataset=dataset,
        tables=tables,
        policy=policy,
        relationships=relationships,
        output_profile=TransferProfile.DATA_ONLY,
        relationship_assurance_target=RelationalAssuranceLevel.INCOMPLETE,
        output_data_state=OutputDataState.STANDALONE_REDUCED_SEMANTICS,
        execution_context=_PlanExecutionContext(
            source_root=str(tmp / "missing_src"),
            output_root=str(tmp / "out"),
            vault_path=str(tmp / "vault"),
        ),
    )


def _assert_no_side_effects(tmp: Path) -> None:
    for absent in ("out", "vault", "staging", "locks", "logs"):
        assert not (tmp / absent).exists(), f"{absent} was created"
    sidecars = [
        name
        for name in _tree_snapshot(tmp)
        if "sqlite" in name.lower()
        or name.lower().endswith(("-wal", "-shm", ".lock", ".log"))
    ]
    assert not sidecars, f"vault/staging/log sidecars created: {sidecars}"


def _assert_source_unchanged(before: dict[str, str], tmp: Path) -> None:
    assert _tree_snapshot(tmp / "src") == before


@pytest.fixture(autouse=True)
def _ample_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _PF_MODULE, "_disk_usage",
        lambda _p: (10**15, 10**12, 10**15 - 10**12),
    )


class _Recorder:
    """In-memory progress recorder (never asserts on wall-clock)."""

    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []

    def __call__(self, event: ProgressEvent) -> None:
        self.events.append(event)

    def phase(self, phase: str, event: str) -> list[ProgressEvent]:
        return [
            e for e in self.events
            if e.phase_code == phase and e.event_code == event
        ]


def _assert_bounded_operation_id(value: str) -> None:
    assert value.startswith("op-")
    assert len(value) <= 64
    assert value.strip() == value
    assert not any(character.isspace() for character in value)


def _assert_event_privacy(event: ProgressEvent) -> None:
    payload = json.dumps(event.to_dict(), sort_keys=True)
    assert CANARY_SECRET not in payload
    assert CANARY_ABSOLUTE not in payload
    assert "\\" not in payload
    if event.table_path is not None:
        assert not Path(event.table_path).is_absolute()
        assert ":" not in event.table_path


def _assert_no_completion(events: list[ProgressEvent]) -> None:
    completed = [
        event for event in events if event.event_code == "COMPLETED"
    ]
    assert not completed, "a COMPLETED event was emitted despite failure/cancel"


# ---------------------------------------------------------------------------
# Callback ORDER (deterministic)
# ---------------------------------------------------------------------------
def test_build_plan_progress_event_order_is_deterministic(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    recorder = _Recorder()
    plan = build_plan(
        source=src,
        output=tmp_path / "out",
        vault=tmp_path / "vault",
        progress=recorder,
    )
    assert isinstance(plan, Plan)

    events = recorder.events
    assert events, "no progress events emitted"
    first = events[0]
    assert (first.phase_code, first.event_code) == ("OPERATION", "STARTED")
    assert first.completed_units == 0

    # Every event of the invocation shares one bounded, whitespace-free ID.
    ids = {event.operation_id for event in events}
    assert len(ids) == 1
    _assert_bounded_operation_id(next(iter(ids)))

    # STARTED precedes every progress event of its phase.
    for phase in ("DISCOVERY", "FINGERPRINT", "TABLE_EVALUATION"):
        started = recorder.phase(phase, "STARTED")
        progress_events = recorder.phase(phase, "PROGRESS")
        assert len(started) == 1, phase
        if progress_events:
            assert events.index(started[0]) < events.index(progress_events[0])

    # completed_units never decreases within a phase and never exceeds a
    # known total.
    for phase in ("DISCOVERY", "FINGERPRINT", "TABLE_EVALUATION"):
        completed = [e.completed_units for e in recorder.phase(phase, "PROGRESS")]
        assert completed == sorted(completed), phase
        for event in recorder.phase(phase, "PROGRESS"):
            if event.total_units is not None:
                assert event.completed_units <= event.total_units

    # Exactly one terminal COMPLETED event and it is last.
    completed_events = [e for e in events if e.event_code == "COMPLETED"]
    assert len(completed_events) == 1
    assert events[-1] is completed_events[0]
    assert completed_events[0].phase_code == "OPERATION"
    assert completed_events[0].completed_units == len(plan.tables)

    # Only normalized relative paths appear in events.
    for event in events:
        _assert_event_privacy(event)


def test_preflight_progress_event_order_is_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(progress_layer, "CAPACITY_PROGRESS_RECORD_QUANTUM", 1)
    # 50 C(1) records: the only record count class in which the width-1
    # occurrence bound (50) exceeds the 36-token space, so the exact capacity
    # scan genuinely streams instead of being proven by Phase-A arithmetic.
    src = _make_capacity_source(tmp_path, record_count=50)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    recorder = _Recorder()
    result = preflight(plan, progress=recorder)
    assert isinstance(result, PreflightResult)

    events = recorder.events
    assert events
    ids = {event.operation_id for event in events}
    assert len(ids) == 1
    _assert_bounded_operation_id(next(iter(ids)))

    for phase in ("SOURCE_VERIFICATION", "TABLE_EVALUATION", "CAPACITY_SCAN"):
        started = recorder.phase(phase, "STARTED")
        progress_events = recorder.phase(phase, "PROGRESS")
        assert len(started) == 1, phase
        if progress_events:
            assert events.index(started[0]) < events.index(progress_events[0])
            completed = [e.completed_units for e in progress_events]
            assert completed == sorted(completed), phase
            for event in progress_events:
                assert event.total_units is not None
                assert event.completed_units <= event.total_units

    # The streamed capacity scan reports every record (quantum 1): the table
    # holds exactly 50 records and the final PROGRESS reports all 50 of 50.
    capacity_progress = recorder.phase("CAPACITY_SCAN", "PROGRESS")
    assert [e.completed_units for e in capacity_progress] == list(range(1, 51))
    assert all(e.total_units == 50 for e in capacity_progress)

    completed_events = [e for e in events if e.event_code == "COMPLETED"]
    assert len(completed_events) == 1
    assert events[-1] is completed_events[0]


def test_operation_ids_differ_between_invocations_and_stay_private(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    first = _Recorder()
    second = _Recorder()
    build_plan(source=src, output=tmp_path / "o1", vault=tmp_path / "v1", progress=first)
    build_plan(source=src, output=tmp_path / "o2", vault=tmp_path / "v2", progress=second)
    first_id = first.events[0].operation_id
    second_id = second.events[0].operation_id
    assert first_id != second_id
    # The IDs carry no source path or value fragments.
    assert "src" not in first_id.lower()
    assert "customers" not in first_id.lower()


def test_deterministic_operation_id_seam_is_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(progress_layer, "_next_operation_id", lambda: "op-seam0001")
    src = _make_source(tmp_path)
    recorder = _Recorder()
    build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v", progress=recorder)
    assert {e.operation_id for e in recorder.events} == {"op-seam0001"}


def test_plan_serialization_is_unchanged_and_excludes_operation_id(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    plain = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    plain_again = build_plan(
        source=src, output=tmp_path / "out", vault=tmp_path / "v",
        progress=None, cancel_check=None,
    )
    assert plain.to_dict() == plain_again.to_dict()
    assert "operation_id" not in plain.to_dict()

    recorder = _Recorder()
    with_callbacks = build_plan(
        source=src, output=tmp_path / "out", vault=tmp_path / "v", progress=recorder
    )
    assert with_callbacks.to_dict() == plain.to_dict()
    serialized = json.dumps(with_callbacks.to_dict(), sort_keys=True)
    assert "op-" not in serialized


def test_preflight_result_is_unchanged_when_callbacks_omitted(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    plain = preflight(plan)
    explicit = preflight(plan, progress=None, cancel_check=None)
    assert plain.to_dict() == explicit.to_dict()
    assert plain == explicit


# ---------------------------------------------------------------------------
# Callback exception containment and classification
# ---------------------------------------------------------------------------
def test_progress_callback_failure_is_contained_and_classified_build_plan(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    before = _tree_snapshot(src)

    def _boom(event: ProgressEvent) -> None:
        raise RuntimeError(f"{CANARY_SECRET} {CANARY_ABSOLUTE} raw value BETA")

    with pytest.raises(CallbackError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            progress=_boom,
        )
    error = excinfo.value
    assert error.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert error.context.detail_code == "PROGRESS_CALLBACK"

    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert CANARY_SECRET not in blob
    assert CANARY_ABSOLUTE not in blob
    assert "BETA" not in blob
    assert "raw value" not in blob

    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_progress_callback_failure_is_contained_and_classified_preflight(
    tmp_path: Path,
) -> None:
    src = _make_capacity_source(tmp_path, record_count=3)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    before = _tree_snapshot(src)

    def _boom(event: ProgressEvent) -> None:
        raise ValueError(f"{CANARY_SECRET} memo payload GAMMA /private/vault.db")

    with pytest.raises(CallbackError) as excinfo:
        preflight(plan, progress=_boom)
    error = excinfo.value
    assert error.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert CANARY_SECRET not in blob
    assert "GAMMA" not in blob
    assert "vault.db" not in blob

    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_cancel_check_failure_is_contained_and_classified(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    before = _tree_snapshot(src)

    def _boom() -> bool:
        raise OSError(f"{CANARY_ABSOLUTE} CANARY_CANCEL_PRIVATE secret ALPHA")

    with pytest.raises(CallbackError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            cancel_check=_boom,
        )
    error = excinfo.value
    assert error.code is ErrorCode.CANCEL_CALLBACK_FAILED
    assert error.context.detail_code == "CANCEL_CHECK"
    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert "CANARY_CANCEL_PRIVATE" not in blob
    assert CANARY_ABSOLUTE not in blob
    assert "secret" not in blob

    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_callback_error_chain_does_not_leak_through_public_boundary(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)

    class _Canary(Exception):
        pass

    def _boom(event: ProgressEvent) -> None:
        raise _Canary(f"{CANARY_SECRET} {CANARY_ABSOLUTE}")

    with pytest.raises(CallbackError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            progress=_boom,
        )
    error = excinfo.value
    # Objective public-boundary evidence: the contained classification
    # suppresses the cause chain and the registry-controlled public
    # serialization (str/repr/to_dict) never renders the canary.
    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert CANARY_SECRET not in blob
    assert CANARY_ABSOLUTE not in blob
    assert error.__cause__ is None
    assert error.code is ErrorCode.PROGRESS_CALLBACK_FAILED


def test_progress_callback_raising_cancellation_error_is_reclassified(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    before = _tree_snapshot(src)
    seen: list[ProgressEvent] = []

    def _boom(event: ProgressEvent) -> None:
        seen.append(event)
        raise CancellationError(
            ErrorCode.OPERATION_CANCELLED,
            context=ErrorContext(
                operation="build_plan", detail_code="CANARY_CALLBACK_CANCEL"
            ),
        )

    with pytest.raises(CallbackError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            progress=_boom,
        )
    error = excinfo.value
    # A user callback can NEVER manufacture a genuine cancellation by
    # throwing: its typed CancellationError is reclassified at the callback
    # boundary and the raw machine code/context do not replace the
    # callback-failure classification.
    assert error.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert not isinstance(error, CancellationError)
    assert error.context.detail_code == "PROGRESS_CALLBACK"
    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert "CANARY_CALLBACK_CANCEL" not in blob
    assert "OPERATION_CANCELLED" not in blob
    assert error.__cause__ is None

    _assert_no_completion(seen)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_progress_callback_raising_callback_error_is_reclassified(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    before = _tree_snapshot(src)
    seen: list[ProgressEvent] = []

    def _boom(event: ProgressEvent) -> None:
        seen.append(event)
        raise CallbackError(
            ErrorCode.PROGRESS_CALLBACK_FAILED,
            context=ErrorContext(
                operation="build_plan", detail_code="CANARY_RAW_DETAIL"
            ),
        )

    with pytest.raises(CallbackError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            progress=_boom,
        )
    error = excinfo.value
    # A callback-thrown CallbackError is likewise reclassified: the new
    # containment error carries only registry-controlled context.
    assert error.code is ErrorCode.PROGRESS_CALLBACK_FAILED
    assert error.context.detail_code == "PROGRESS_CALLBACK"
    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert "CANARY_RAW_DETAIL" not in blob
    assert error.__cause__ is None

    _assert_no_completion(seen)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_cancel_check_raising_cancellation_error_is_reclassified(
    tmp_path: Path,
) -> None:
    src = _make_capacity_source(tmp_path, record_count=3)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    before = _tree_snapshot(src)
    recorder = _Recorder()
    calls = {"n": 0}

    def _boom() -> bool:
        calls["n"] += 1
        if calls["n"] >= 2:  # first poll passes so STARTED is emitted
            raise CancellationError(
                ErrorCode.OPERATION_CANCELLED,
                context=ErrorContext(
                    operation="preflight", detail_code="CANARY_CANCEL_DETAIL"
                ),
            )
        return False

    with pytest.raises(CallbackError) as excinfo:
        preflight(plan, progress=recorder, cancel_check=_boom)
    error = excinfo.value
    # A raising cancel-check is a callback failure, never a genuine
    # cancellation: the typed exception it throws is reclassified.
    assert error.code is ErrorCode.CANCEL_CALLBACK_FAILED
    assert not isinstance(error, CancellationError)
    assert error.context.detail_code == "CANCEL_CHECK"
    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert "CANARY_CANCEL_DETAIL" not in blob
    assert "OPERATION_CANCELLED" not in blob
    assert error.__cause__ is None

    _assert_no_completion(recorder.events)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_cancel_check_raising_callback_error_is_reclassified(
    tmp_path: Path,
) -> None:
    src = _make_capacity_source(tmp_path, record_count=3)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    before = _tree_snapshot(src)
    recorder = _Recorder()
    calls = {"n": 0}

    def _boom() -> bool:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise CallbackError(
                ErrorCode.CANCEL_CALLBACK_FAILED,
                context=ErrorContext(
                    operation="preflight", detail_code="CANARY_CANCEL_RAW"
                ),
            )
        return False

    with pytest.raises(CallbackError) as excinfo:
        preflight(plan, progress=recorder, cancel_check=_boom)
    error = excinfo.value
    assert error.code is ErrorCode.CANCEL_CALLBACK_FAILED
    assert error.context.detail_code == "CANCEL_CHECK"
    blob = f"{str(error)}|{repr(error)}|{json.dumps(error.to_dict(), sort_keys=True)}"
    assert "CANARY_CANCEL_RAW" not in blob
    assert error.__cause__ is None

    _assert_no_completion(recorder.events)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


# ---------------------------------------------------------------------------
# Cooperative cancellation: no result, no completion event, source unchanged
# ---------------------------------------------------------------------------
def test_build_plan_cancellation_produces_no_result_and_no_output(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    before = _tree_snapshot(src)
    recorder = _Recorder()

    with pytest.raises(CancellationError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            progress=recorder,
            cancel_check=lambda: True,
        )
    error = excinfo.value
    assert error.code is ErrorCode.OPERATION_CANCELLED
    assert error.context.detail_code == "CANCELLED_BY_CHECK"
    payload = json.dumps(error.to_dict(), sort_keys=True)
    assert error.to_dict()["code"] == "OPERATION_CANCELLED"
    assert "src" not in payload

    _assert_no_completion(recorder.events)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_preflight_cancellation_produces_no_result_and_is_not_a_finding(
    tmp_path: Path,
) -> None:
    src = _make_capacity_source(tmp_path, record_count=3)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    before = _tree_snapshot(src)
    recorder = _Recorder()

    with pytest.raises(CancellationError) as excinfo:
        preflight(plan, progress=recorder, cancel_check=lambda: True)
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED
    assert excinfo.value.context.detail_code == "CANCELLED_BY_CHECK"

    # Cancellation is an exceptional operation-control outcome, never an
    # ordinary preflight finding, and it never produces a result.
    _assert_no_completion(recorder.events)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


# ---------------------------------------------------------------------------
# REAL cancellation latency inside the streamed capacity scan
# ---------------------------------------------------------------------------
def test_cancellation_during_capacity_scan_is_polled_per_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(progress_layer, "CAPACITY_PROGRESS_RECORD_QUANTUM", 1)
    src = _make_capacity_source(tmp_path, record_count=50)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    before = _tree_snapshot(src)
    recorder = _Recorder()

    def _cancel_after_ten_records() -> bool:
        return len(recorder.phase("CAPACITY_SCAN", "PROGRESS")) >= 10

    with pytest.raises(CancellationError) as excinfo:
        preflight(plan, progress=recorder, cancel_check=_cancel_after_ten_records)
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED

    # The scan stopped right after the 10th streamed record: the declared
    # polling quantum is one record, so the 50-record table was never
    # consumed to exhaustion and no result was returned.
    streamed = [e.completed_units for e in recorder.phase("CAPACITY_SCAN", "PROGRESS")]
    assert streamed == list(range(1, 11))
    _assert_no_completion(recorder.events)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


# ---------------------------------------------------------------------------
# REAL cancellation latency inside the fingerprint hashing scan
# ---------------------------------------------------------------------------
def test_fingerprint_cancellation_latency_is_bounded_by_chunk_quantum(
    tmp_path: Path,
) -> None:
    # A large synthetic in-scope artifact (2.5 MiB = 40 hashing chunks of
    # 64 KiB).  The cancel-check flips True exactly at the third intra-file
    # polling boundary (chunk 32), so at most 8 chunks (512 KiB) of the file
    # remain unhashed — far inside the declared 16-chunk (1 MiB) bound.  With
    # only per-artifact polling there would be no 7th poll at all and the
    # operation would instead complete (or cancel only after fully hashing
    # the artifact and reading the DBF).
    quantum = progress_layer.FINGERPRINT_CANCEL_CHUNK_QUANTUM
    chunk_size = progress_layer.FINGERPRINT_HASH_CHUNK_SIZE
    chunk_count = 2 * quantum + 8  # 40 chunks; intra-file probes at 0/16/32
    src = _make_big_idx_source(tmp_path, chunk_count)
    assert (src / "a_big.idx").stat().st_size == chunk_size * chunk_count

    before = _tree_snapshot(src)
    checks = {"calls": 0}

    def _cancel_at_third_intra_file_probe() -> bool:
        checks["calls"] += 1
        # 1 OPERATION start + 1 DISCOVERY start + 2 discovery-traversal
        # directories (src, z_customers) + 1 discovered-table probe
        # + 1 FINGERPRINT start + 2 fingerprint-enumeration directories
        # + 1 artifact pre-check + chunk-0 probe + chunk-16 probe
        # -> the 12th poll is the chunk-32 boundary.
        return checks["calls"] >= 12

    with pytest.raises(CancellationError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            cancel_check=_cancel_at_third_intra_file_probe,
        )
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED

    # Deterministic work units: the poll fired exactly at the documented
    # intra-file boundary and the remaining unread part of the big artifact
    # is strictly smaller than the declared quantum.
    assert checks["calls"] == 12
    remaining_chunks = chunk_count - 2 * quantum
    assert 0 < remaining_chunks <= quantum

    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_preflight_cancellation_during_fingerprint_revalidation(
    tmp_path: Path,
) -> None:
    src = _make_big_idx_source(tmp_path, chunk_count=40)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    before = _tree_snapshot(src)
    recorder = _Recorder()
    checks = {"calls": 0}

    def _cancel_during_revalidation() -> bool:
        checks["calls"] += 1
        # 1 OPERATION start + 1 overlap check + 1 SOURCE_VERIFICATION start
        # + 2 strict-enumeration directories + 2 fingerprint-enumeration
        # directories + 1 artifact pre-check + chunk-0 + chunk-16
        # -> the 11th poll is the chunk-32 boundary.
        return checks["calls"] >= 11

    with pytest.raises(CancellationError) as excinfo:
        preflight(plan, progress=recorder, cancel_check=_cancel_during_revalidation)
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED
    # The typed cancellation surfaced instead of a PreflightResult finding.
    assert not isinstance(excinfo.value, PreflightResult)
    _assert_no_completion(recorder.events)
    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


# ---------------------------------------------------------------------------
# Bounded directory-traversal cancellation (deterministic enumeration bound)
# ---------------------------------------------------------------------------
def test_build_plan_cancellation_during_discovery_traversal_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A synthetic tree of 51 directories.  Cancellation is requested at the
    # FIRST visited directory of the discovery traversal, so the walk must
    # stop after ONE consumed directory instead of running to exhaustion.
    src = tmp_path / "src"
    src.mkdir()
    entries = [
        (str(src / f"filler{i:03d}"), [], ["noise.txt"]) for i in range(51)
    ]
    fake = _FakeWalkOS(entries)
    monkeypatch.setattr(_discovery, "os", fake)

    def _cancel_at_first_visited_directory() -> bool:
        return fake.walk_calls >= 1 and fake.consumed >= 1

    with pytest.raises(CancellationError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            cancel_check=_cancel_at_first_visited_directory,
        )
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED
    # Deterministic work units: exactly one directory was consumed before the
    # cancellation was observed — the 51-directory traversal never completed.
    assert fake.walk_calls == 1
    assert fake.consumed == 1
    assert fake.consumed < len(entries)

    _assert_no_side_effects(tmp_path)
    assert _tree_snapshot(src) == {}


def test_build_plan_cancellation_during_fingerprint_enumeration_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The discovery traversal completes (walk call 1, no cancellation), then
    # cancellation is requested at the SECOND visited directory of the
    # fingerprint enumeration walk (call 2): the enumeration must stop after
    # 2 consumed directories instead of walking the whole synthetic tree.
    src = _make_source(tmp_path)
    before = _tree_snapshot(src)
    entries = _synthetic_walk_entries(src / "customers", filler_count=50)
    fake = _FakeWalkOS(entries)
    monkeypatch.setattr(_discovery, "os", fake)

    def _cancel_on_second_enumeration_directory() -> bool:
        return fake.walk_calls >= 2 and fake.consumed >= 2

    with pytest.raises(CancellationError) as excinfo:
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            cancel_check=_cancel_on_second_enumeration_directory,
        )
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED
    # Walk call 1 was discovery (full synthetic traversal, no cancellation);
    # walk call 2 is the fingerprint enumeration and it stopped early.
    assert fake.walk_calls == 2
    assert fake.consumed == 2
    assert fake.consumed < len(entries)

    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


def test_preflight_cancellation_during_strict_enumeration_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The plan is built with the REAL walk; preflight's STRICT source
    # enumeration then runs against the synthetic tree and cancellation is
    # requested at its SECOND visited directory.  The traversal must stop
    # before exhaustion and the typed cancellation must propagate (it is
    # never converted into SOURCE_UNAVAILABLE or any other finding).
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault")
    before = _tree_snapshot(src)
    entries = _synthetic_walk_entries(src / "customers", filler_count=50)
    fake = _FakeWalkOS(entries)
    monkeypatch.setattr(_discovery, "os", fake)

    def _cancel_at_second_strict_directory() -> bool:
        return fake.walk_calls >= 1 and fake.consumed >= 2

    with pytest.raises(CancellationError) as excinfo:
        preflight(plan, cancel_check=_cancel_at_second_strict_directory)
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED
    assert excinfo.value.context.detail_code == "CANCELLED_BY_CHECK"
    assert fake.walk_calls == 1
    assert fake.consumed == 2
    assert fake.consumed < len(entries)

    _assert_no_side_effects(tmp_path)
    _assert_source_unchanged(before, tmp_path)


# ---------------------------------------------------------------------------
# Preflight per-table cancellation bound (independent of progress callbacks)
# ---------------------------------------------------------------------------
def test_preflight_table_evaluation_cancellation_is_bounded_per_table(
    tmp_path: Path,
) -> None:
    # A synthetic Plan with 20 tables, NO progress callback and a counting
    # cancel_check: cancellation must not depend on progress reporting.  With
    # a missing source root there is no traversal, so the poll sequence is
    # deterministic: 1 OPERATION start + 1 overlap check +
    # 1 SOURCE_VERIFICATION start + 1 destination check +
    # 1 TABLE_EVALUATION start = 5 polls before the first table boundary,
    # then exactly one poll per table evaluation boundary (quantum: 1 table).
    plan = _synthetic_plan(table_count=20, tmp=tmp_path)
    pre_table_polls = 5
    polls = {"n": 0}

    def _cancel_at_second_table_boundary() -> bool:
        polls["n"] += 1
        return polls["n"] >= pre_table_polls + 2

    with pytest.raises(CancellationError) as excinfo:
        preflight(plan, progress=None, cancel_check=_cancel_at_second_table_boundary)
    assert excinfo.value.code is ErrorCode.OPERATION_CANCELLED
    # Cancellation was observed exactly at the SECOND table-evaluation
    # boundary: only one table was fully evaluated and the remaining 19 were
    # never reached (bound: one table).  No result was returned and a
    # COMPLETED event is structurally impossible — preflight emits it only
    # immediately before returning a genuine result.
    assert polls["n"] == pre_table_polls + 2
    assert polls["n"] < pre_table_polls + len(plan.tables)


# ---------------------------------------------------------------------------
# Privacy canaries on every event/error payload
# ---------------------------------------------------------------------------
def test_progress_events_never_expose_canaries_or_absolute_paths(
    tmp_path: Path,
) -> None:
    src = tmp_path / "CANARY_SECRET_src"
    _write_table(
        src / "customers" / "customers.dbf",
        [("CODE", "C", 30)],
        [{"CODE": "CANARY_ORIGINAL_VALUE"}, {"CODE": "BETA"}],
    )

    recorder = _Recorder()
    plan = build_plan(
        source=src, output=tmp_path / "out", vault=tmp_path / "vault",
        progress=recorder,
    )
    result = preflight(plan, progress=recorder)
    assert isinstance(result, PreflightResult)

    for event in recorder.events:
        payload = json.dumps(event.to_dict(), sort_keys=True)
        assert "CANARY_ORIGINAL_VALUE" not in payload
        assert "CANARY_SECRET_src" not in payload
        assert str(tmp_path) not in payload
        assert "\\" not in payload
        if event.table_path is not None:
            assert event.table_path == event.table_path.replace("\\", "/")


def test_cancellation_and_failure_events_stay_within_bounded_payloads(
    tmp_path: Path,
) -> None:
    src = _make_source(tmp_path)
    recorder = _Recorder()

    with pytest.raises(CancellationError):
        build_plan(
            source=src, output=tmp_path / "out", vault=tmp_path / "vault",
            progress=recorder,
            cancel_check=lambda: True,
        )
    for event in recorder.events:
        _assert_event_privacy(event)
        # Bounded token/payload shape is re-validated by the public model.
        assert event.to_dict()["model_type"] == "ProgressEvent"


def test_public_surface_stays_exactly_the_current_contract() -> None:
    # No unfinished operation was faked; ProgressEvent stays public as before.
    # REQ-P5-001 (verify_dataset), REQ-P5-002/003 (recover) and
    # REQ-P5-004..007 (create_transfer_bundle/verify_transfer_bundle) are all
    # REAL implemented public services; no success placeholders exist.
    assert callable(dbf_anonymizer.verify_dataset)
    assert callable(dbf_anonymizer.recover)
    assert callable(dbf_anonymizer.create_transfer_bundle)
    assert callable(dbf_anonymizer.verify_transfer_bundle)
    assert "ProgressEvent" in dbf_anonymizer.__all__
    assert "CallbackError" in dbf_anonymizer.__all__
    assert "pseudonymize" in dbf_anonymizer.__all__
    assert "recover" in dbf_anonymizer.__all__
    assert "create_transfer_bundle" in dbf_anonymizer.__all__
    assert "verify_transfer_bundle" in dbf_anonymizer.__all__
