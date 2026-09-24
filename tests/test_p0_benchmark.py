"""REQ-P0-005 — the final direct-read/direct-write pipeline benchmark harness.

Proves that the benchmark harness exercises the REAL public production
pipeline (build_plan -> pseudonymize -> verify_dataset), produces a closed,
versioned, privacy-safe machine-readable JSON result with a deterministic
Markdown summary derived from that single source of truth, performs NO
alternative DBF/FPT parsing/writing, keeps the source byte-identical,
observes truthful byte/time/memory counters and truthfully reports the
still-absent P6 index backend as NOT_APPLICABLE.  Only approved synthetic
fixtures and disposable tmp_path workspaces are used; no production data.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import dbf_anonymizer  # noqa: E402
import tools.final_pipeline_benchmark as bench  # noqa: E402
from dbf_anonymizer import VerificationStatus  # noqa: E402
from dbf_anonymizer import api as api_module  # noqa: E402
from dbf_anonymizer.errors import (  # noqa: E402
    ErrorContext,
    ErrorCode,
    PublicationError,
)
from tests.support.numeric_tables import (  # noqa: E402
    numeric_field,
    write_numeric_table,
)

_TINY_WORKLOAD = {"customers": 60, "orders": 30, "archived": 20}
_SMALL_WORKLOAD = {"customers": 160, "orders": 80, "archived": 40}

# Deterministic first-record canaries of the synthetic workload (the
# benchmark artifacts must never carry them).
_ORIGINAL_TEXT_CANARY = "SYNTHETIC-000000000"
_KEY_CANARY = "CUST000000000"
_MEMO_CANARY = "BENCH-MEMO-00"

_FORBIDDEN_TOKENS = (
    "reverse",
    "offset",
    "salt",
    "original",
    "operation_id",
    "mapping",
    "rowid",
    _ORIGINAL_TEXT_CANARY,
    _KEY_CANARY,
    _MEMO_CANARY,
)


def _serialized(report: dict[str, object]) -> str:
    return json.dumps(report, sort_keys=True, ensure_ascii=True)


def _int_of(report: dict[str, object], field: str) -> int:
    value = report[field]
    assert isinstance(value, int)
    return value


def _float_of(report: dict[str, object], field: str) -> float:
    value = report[field]
    assert isinstance(value, (int, float))
    return float(value)


@pytest.fixture(scope="module")
def benchmark(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One tiny deterministic benchmark run shared by schema/privacy/bytes tests."""
    workspace = tmp_path_factory.mktemp("p0-bench")
    run = bench.run_final_pipeline_benchmark(
        workspace, customers=60, orders=30, archived=20, workers=1
    )
    return SimpleNamespace(run=run, workspace=workspace, report=run.report)


# ---------------------------------------------------------------------------
# A/B: the benchmark invokes the REAL production service paths
# ---------------------------------------------------------------------------
def test_benchmark_invokes_the_real_public_pseudonymize_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine_calls: list[object] = []
    real_run_two_pass = api_module.run_two_pass

    def counting_run_two_pass(*args: object, **kwargs: object) -> object:
        engine_calls.append("called")
        return real_run_two_pass(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(api_module, "run_two_pass", counting_run_two_pass)
    workspace = tmp_path / "bench"
    run = bench.run_final_pipeline_benchmark(
        workspace, customers=40, orders=20, archived=10, workers=1
    )
    # Exactly ONE invocation through the real production engine, through the
    # public pseudonymize service (the harness never runs a second pass).
    assert engine_calls == ["called"]
    assert run.pseudonymization.operation_id.startswith("vop-")
    assert run.pseudonymization.vault_created is True
    assert run.report["record_count"] == 70
    assert run.report["table_count"] == 3


def test_benchmark_invokes_the_real_public_verify_dataset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_verify_dataset = bench.verify_dataset
    calls: list[object] = []

    def counting_verify_dataset(*args: object, **kwargs: object) -> object:
        calls.append("called")
        return real_verify_dataset(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(bench, "verify_dataset", counting_verify_dataset)
    workspace = tmp_path / "bench"
    run = bench.run_final_pipeline_benchmark(
        workspace, customers=40, orders=20, archived=10, workers=1
    )
    # Exactly ONE real verification of the real output through the public
    # verify_dataset service; the verdict is the genuine PASS evidence.
    assert calls == ["called"]
    assert run.verification.status is VerificationStatus.PASS
    assert _float_of(run.report, "verification_seconds") > 0


# ---------------------------------------------------------------------------
# A2. a transient OS-level publication interruption restarts the measurement
# ---------------------------------------------------------------------------
def test_transient_publication_interruption_restarts_in_a_fresh_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WinError-5-style interruption of the atomic promotion rename (the
    classic Windows antivirus/indexer handle race) must kill only the one
    attempt — which published nothing — and the fresh attempt must deliver
    the complete truthful measurement."""
    import dbf_anonymizer.engine.publication as publication_module

    real_atomic_replace = publication_module.atomic_replace
    observed: list[str] = []

    def transiently_failing_replace(
        source: object, destination: object
    ) -> object:
        if not observed:
            observed.append("failed")
            raise PermissionError(5, "simulated transient handle race")
        observed.append("ok")
        return real_atomic_replace(source, destination)  # type: ignore[arg-type]

    monkeypatch.setattr(
        publication_module, "atomic_replace", transiently_failing_replace
    )
    workspace = tmp_path / "bench"
    run = bench.run_final_pipeline_benchmark(
        workspace, customers=40, orders=20, archived=10, workers=1
    )
    assert observed == ["failed", "ok"]
    assert run.workspace.name == "attempt-2"
    assert (workspace / "attempt-1").is_dir()
    bench._validate_report_shape(run.report)
    assert run.report["record_count"] == 70
    assert run.verification.status is VerificationStatus.PASS


def test_permanent_publication_interruption_surfaces_after_bounded_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure that never recovers surfaces as the original typed public
    failure after the bounded retry budget, with nothing published."""
    import dbf_anonymizer.engine.publication as publication_module

    attempts: list[int] = []

    def always_failing_replace(source: object, destination: object) -> object:
        attempts.append(1)
        raise PermissionError(5, "simulated permanent handle race")

    monkeypatch.setattr(
        publication_module, "atomic_replace", always_failing_replace
    )
    workspace = tmp_path / "bench"
    with pytest.raises(PublicationError) as excinfo:
        bench.run_final_pipeline_benchmark(
            workspace, customers=40, orders=20, archived=10, workers=1
        )
    assert len(attempts) == 1 + bench.MAX_TRANSIENT_PUBLICATION_RETRIES
    assert excinfo.value.context.detail_code == "STAGING_PROMOTION_FAILED"
    for index in range(1, len(attempts) + 1):
        assert (workspace / f"attempt-{index}").is_dir()
    assert not (workspace / "attempt-1" / "output").exists()


def test_non_transient_publication_failure_is_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the typed transient rename detail qualifies for a restart; any
    other typed publication failure surfaces immediately."""
    import dbf_anonymizer.engine.publication as publication_module

    calls: list[int] = []

    def typed_non_transient_replace(source: object, destination: object) -> object:
        calls.append(1)
        raise PublicationError(
            ErrorCode.PUBLICATION_INCOMPLETE,
            context=ErrorContext(
                operation="publication", detail_code="STAGING_CLEANUP_FAILED"
            ),
        )

    monkeypatch.setattr(
        publication_module, "atomic_replace", typed_non_transient_replace
    )
    workspace = tmp_path / "bench"
    with pytest.raises(PublicationError) as excinfo:
        bench.run_final_pipeline_benchmark(
            workspace, customers=40, orders=20, archived=10, workers=1
        )
    assert len(calls) == 1
    assert excinfo.value.context.detail_code == "STAGING_CLEANUP_FAILED"
    assert not (workspace / "attempt-2").exists()


# ---------------------------------------------------------------------------
# C. no alternative DBF/FPT parser or writer exists in the harness
# ---------------------------------------------------------------------------
def test_harness_creates_no_alternative_dbf_parser_or_writer() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "final_pipeline_benchmark.py"
    ).read_text(encoding="utf-8")
    # The synthetic workload is built through the reviewed tests.support
    # public writer boundary; the harness itself never touches DBF/FPT bytes.
    assert "dbfbridge." in source  # version metadata only
    for forbidden in (
        "dbfbridge.write_table",
        "dbfbridge.iter_records",
        "dbfbridge.FieldInfo",
        "dbfbridge.TableSchema",
        "dbfbridge.DirectRecord",
        "struct.",
        "open(source",
        "read_bytes()[:",
    ):
        assert forbidden not in source, forbidden
    # The only dbfbridge usage is the version read for the report.
    dbfbridge_uses = [
        line.strip() for line in source.splitlines() if "dbfbridge." in line
    ]
    assert dbfbridge_uses == ['"dbfbridge_version": dbfbridge.__version__,']


# ---------------------------------------------------------------------------
# D. source files are byte-identical before and after the benchmark
# ---------------------------------------------------------------------------
def test_source_files_remain_byte_identical_after_benchmark(
    benchmark: SimpleNamespace,
) -> None:
    """The deterministic workload is rebuilt in a fresh directory and must
    equal the post-benchmark source tree byte for byte; the harness itself
    additionally raises if any source byte changed."""
    reference = benchmark.workspace / "reference-source"
    bench.write_benchmark_workload(reference, customers=60, orders=30, archived=20)
    reference_hashes = {
        path.relative_to(reference).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(reference.rglob("*"))
        if path.is_file()
    }
    actual_hashes = {
        path.relative_to(benchmark.run.workspace / "source").as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted((benchmark.run.workspace / "source").rglob("*"))
        if path.is_file()
    }
    assert actual_hashes == reference_hashes
    assert reference_hashes
    # The reported measurement always describes its own attempt workspace.
    assert benchmark.run.workspace.name.startswith("attempt-")


# ---------------------------------------------------------------------------
# E/F/G/H/I/N. closed schema, privacy and NOT_APPLICABLE index backend
# ---------------------------------------------------------------------------
def test_report_follows_the_exact_closed_schema(benchmark: SimpleNamespace) -> None:
    report = benchmark.report
    assert sorted(report) == sorted(bench.REPORT_FIELDS)
    assert report["benchmark_schema_version"] == "1.0"
    assert report["workload_id"] == bench.WORKLOAD_ID
    assert report["workload_version"] == "1.0"
    assert report["index_backend_applicable"] is False
    assert report["index_backend_seconds"] is None
    assert isinstance(report["platform"], str)
    assert report["platform"]
    assert report["python_version"].count(".") >= 1


def test_report_contains_no_absolute_paths(benchmark: SimpleNamespace) -> None:
    serialized = _serialized(benchmark.report)
    assert "\\" not in serialized
    assert str(benchmark.workspace) not in serialized
    # POSIX roots have an empty drive component; an empty substring would
    # match every position, so the drive check applies only when one exists.
    drive = benchmark.workspace.drive
    if drive:
        assert drive.lower() not in serialized.lower()


def test_report_never_leaks_originals_memos_or_recovery_parameters(
    benchmark: SimpleNamespace,
) -> None:
    for text in (
        json.dumps(benchmark.report, sort_keys=True, ensure_ascii=True),
        bench.render_markdown(benchmark.report),
    ):
        for token in _FORBIDDEN_TOKENS:
            assert token not in text, token


def test_report_never_leaks_transformed_output_values(
    benchmark: SimpleNamespace,
) -> None:
    """No transformed (pseudonym/masked-memo) output value can act as
    reverse evidence inside the benchmark artifacts either."""
    from tests.support.numeric_tables import field_values

    output = benchmark.run.workspace / "output" / "north" / "customers.dbf"
    samples: list[str] = []
    for field_name in ("CUST_ID", "NAME", "NOTE"):
        for value in field_values(output, field_name=field_name):
            if value is None or value == "":
                continue
            rendered = str(value)
            # Trivial single-digit/short renderings cannot distinguish a
            # genuine value leak from ordinary metric digits; only distinct
            # transformed strings of realistic length count.
            if len(rendered) < 6 or rendered.isdigit():
                continue
            samples.append(rendered)
            if len(samples) >= 6:
                break
        if len(samples) >= 6:
            break
    assert len(samples) >= 3
    for text in (
        json.dumps(benchmark.report, sort_keys=True, ensure_ascii=True),
        bench.render_markdown(benchmark.report),
    ):
        for value in samples:
            assert value not in text, value


# ---------------------------------------------------------------------------
# J. derived throughput  K. real filesystem byte counters
# ---------------------------------------------------------------------------
def test_records_per_second_is_mathematically_derived(
    benchmark: SimpleNamespace,
) -> None:
    report = benchmark.report
    assert float(report["wall_seconds"]) > 0
    # The rounded values must satisfy the documented derivation within the
    # rounding tolerance of both rounded quantities (5e-7 each) — the same
    # bound the harness itself enforces, so it holds on slow environments too.
    tolerance = 0.01 + 5e-7 * (
        float(report["wall_seconds"]) + float(report["records_per_second"])
    )
    assert (
        abs(
            float(report["records_per_second"]) * float(report["wall_seconds"])
            - int(report["record_count"])
        )
        < tolerance
    )


def test_byte_counters_reflect_actual_filesystem_artifacts(
    benchmark: SimpleNamespace,
) -> None:
    report = benchmark.report
    workspace = benchmark.run.workspace
    vault_file = workspace / "vault" / "dictionary.sqlite3"
    expected_sqlite = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = workspace / "vault" / (vault_file.name + suffix)
        if candidate.is_file():
            expected_sqlite += candidate.stat().st_size
    assert report["source_bytes"] == bench._tree_bytes(workspace / "source")
    assert report["output_bytes"] == bench._tree_bytes(workspace / "output")
    assert report["vault_bytes"] == bench._tree_bytes(workspace / "vault")
    assert report["sqlite_bytes"] == expected_sqlite
    assert _int_of(report, "source_bytes") > 0
    assert _int_of(report, "output_bytes") > 0
    assert _int_of(report, "vault_bytes") > 0


# ---------------------------------------------------------------------------
# L/M/N/P. measured memory, observed transient rule, truthful applicability
# ---------------------------------------------------------------------------
def test_peak_memory_is_measured_not_constant(
    tmp_path: Path,
) -> None:
    small = bench.run_final_pipeline_benchmark(
        tmp_path / "small", customers=40, orders=20, archived=10, workers=1
    )
    larger = bench.run_final_pipeline_benchmark(
        tmp_path / "larger", customers=160, orders=80, archived=40, workers=1
    )
    small_peak = _int_of(small.report, "peak_memory_bytes")
    larger_peak = _int_of(larger.report, "peak_memory_bytes")
    assert small_peak > 0
    assert larger_peak > 0
    assert larger_peak != small_peak
    # The observed transient footprint grows with the workload too.
    assert _int_of(larger.report, "temporary_peak_bytes") >= _int_of(
        small.report, "temporary_peak_bytes"
    )


def test_temporary_peak_bytes_is_observed_using_the_documented_rule(
    benchmark: SimpleNamespace,
) -> None:
    report = benchmark.report
    temporary_peak = _int_of(report, "temporary_peak_bytes")
    assert temporary_peak > 0
    # The documented rule observes engine-owned transient artifacts (staging
    # trees, engine lock files, the pass1 spool and evidence shards) — the
    # final output and vault sizes are explicitly excluded.
    assert temporary_peak != _int_of(report, "output_bytes")
    assert temporary_peak != _int_of(report, "vault_bytes")


# ---------------------------------------------------------------------------
# O/P. deterministic workload identity; timings allowed to vary
# ---------------------------------------------------------------------------
def test_workload_identity_is_deterministic_across_runs(
    tmp_path: Path,
) -> None:
    first = bench.run_final_pipeline_benchmark(
        tmp_path / "first", customers=60, orders=30, archived=20, workers=1
    )
    second = bench.run_final_pipeline_benchmark(
        tmp_path / "second", customers=60, orders=30, archived=20, workers=1
    )
    for field in (
        "workload_id",
        "workload_version",
        "workload_source_fingerprint",
        "table_count",
        "record_count",
        "source_bytes",
        "output_bytes",
        "vault_bytes",
        "sqlite_bytes",
        "workers",
    ):
        assert first.report[field] == second.report[field]
    # Timing values are allowed (and expected) to vary between runs; only
    # their finiteness and non-negativity are contractual.
    for field in (
        "wall_seconds",
        "sqlite_seconds",
        "dbf_fpt_write_seconds",
        "verification_seconds",
        "records_per_second",
    ):
        assert _float_of(first.report, field) >= 0
        assert _float_of(second.report, field) >= 0


# ---------------------------------------------------------------------------
# Q. the committed baseline profile agrees with its generated summary
# ---------------------------------------------------------------------------
def test_committed_baseline_is_closed_schema_and_privacy_safe() -> None:
    baseline_json = Path(__file__).resolve().parents[1] / "benchmarks" / (
        "final-pipeline-baseline.json"
    )
    baseline_md = Path(__file__).resolve().parents[1] / "benchmarks" / (
        "final-pipeline-baseline.md"
    )
    report = json.loads(baseline_json.read_text(encoding="utf-8"))
    bench._validate_report_shape(report)
    assert report["index_backend_applicable"] is False
    assert report["index_backend_seconds"] is None
    serialized = json.dumps(report, sort_keys=True, ensure_ascii=True)
    assert "\\" not in serialized
    for token in _FORBIDDEN_TOKENS:
        assert token not in serialized
    # The committed summary is exactly the deterministic rendering of the
    # committed JSON (one source of truth, no independent numbers).
    assert baseline_md.read_text(encoding="utf-8") == bench.render_markdown(report)


# ---------------------------------------------------------------------------
# R. the public 1.0 API surface stays exactly as established
# ---------------------------------------------------------------------------
def test_public_api_surface_remains_unchanged_by_the_benchmark() -> None:
    assert "benchmark" not in dbf_anonymizer.__all__ and all(
        "benchmark" not in name.lower() for name in dbf_anonymizer.__all__
    )
    # Importing the harness must not add exports to the public package.
    import importlib

    importlib.reload(bench)
    assert all(
        "benchmark" not in name.lower() for name in dbf_anonymizer.__all__
    )


# ---------------------------------------------------------------------------
# CLI acceptance path: real JSON + Markdown artifacts from a disposable run
# ---------------------------------------------------------------------------
def test_cli_writes_machine_and_human_artifacts_from_a_disposable_workspace(
    tmp_path: Path,
) -> None:
    output = tmp_path / "out" / "benchmark.json"
    summary = tmp_path / "out" / "benchmark.md"
    exit_code = bench.main(
        [
            "--customers",
            "40",
            "--orders",
            "20",
            "--archived",
            "10",
            "--workers",
            "1",
            "--output",
            str(output),
            "--summary",
            str(summary),
        ]
    )
    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    bench._validate_report_shape(report)
    assert summary.read_text(encoding="utf-8") == bench.render_markdown(report)
    serialized = output.read_text(encoding="utf-8")
    assert str(tmp_path) not in serialized
    # ensure_ascii JSON escaping renders any leaked backslash path component
    # as a doubled backslash; the closed result carries no such component.
    assert "\\\\" not in serialized
    for token in _FORBIDDEN_TOKENS:
        assert token not in serialized
        assert token not in summary.read_text(encoding="utf-8")