"""The reproducible FINAL direct-read/direct-write pipeline benchmark harness (REQ-P0-005).

This tool measures the REAL public production pipeline end to end:

    build_plan -> pseudonymize (public service) -> verify_dataset (public service)

It is NOT a second pseudonymization/verification implementation, it performs
no DBF/FPT parsing or writing of its own (the synthetic workload is created
through the reviewed public ``tests.support`` dbfbridge writer boundary) and
it never touches raw DBF/FPT bytes.  All timing/metric instrumentation is
HARNESS-LOCAL: production code is untouched and the instrumentation exists
only while this harness measures one run, so disabled behavior is identical
to production.

Metric definitions (truthful, documented, never fabricated):

* ``wall_seconds`` — ``time.perf_counter`` around the public
  ``pseudonymize`` operation (its internal preflight is inside it).
* ``records_per_second`` — mathematically derived: ``record_count /
  wall_seconds``.
* ``dbf_fpt_write_seconds`` — cumulative wall time of the actual fresh
  DBF/FPT writing performed by the production pass2 kernel
  (``write_fresh_table``), observed through a timing wrapper around that
  SAME production function (never an artificial writer loop).
* ``sqlite_seconds`` — CUMULATIVE wall time spent inside the SQLite API
  operations the measured DBF_Anonymizer pipeline actually performs during
  pseudonymize + verify_dataset, including connection creation/open,
  connection and cursor ``execute``/``executemany``/``executescript``,
  ``fetchone``/``fetchmany``/``fetchall``, cursor iteration/row stepping,
  cursor ``close``, ``commit``, ``rollback``, connection transaction exit
  and connection ``close``.  Every connection enters through
  ``sqlite3.connect`` (the ONE clean instrumentation boundary) and every
  cursor handed out stays wrapped, so later fetch/stepping work remains
  timed.  Worker threads run concurrently, so this is cumulative ACTIVITY
  time that can legitimately exceed ``wall_seconds``; it is never an
  exclusive process wall time and is measured, never estimated by
  subtraction.
* ``verification_seconds`` — ``time.perf_counter`` around the public
  ``verify_dataset`` operation (not included in ``wall_seconds``).
* ``peak_memory_bytes`` — ``tracemalloc`` peak of Python allocations
  during the measured window (pseudonymize + verify_dataset). This is the
  truthful, cross-platform, stdlib-only Python-level peak (no Windows
  ctypes/psapi); it is a lower bound on true process RSS.
* ``temporary_peak_bytes`` — the maximum over samples taken every 25 ms of
  the total byte size of all ENGINE-OWNED TRANSIENT artifacts: the staging
  trees AND regular lock artifacts matching ``.dbf-anonymizer-*`` beside
  the destination, plus the pass1 spool state file (``pass1-state.sqlite3``)
  and its ``-wal``/``-shm``/``-journal`` sidecars (regular files) and the
  ``.pass2-evidence-*`` shard directories beside the vault.  A regular
  file contributes its ``st_size``; a directory contributes the recursive
  sum of its regular files; artifacts that vanish during sampling
  contribute what was observable instead of failing the run.  Final output
  and durable vault bytes are EXCLUDED, so this sampled peak is a
  documented approximation of the transient footprint, never the final
  output size.
* ``index_backend_applicable`` / ``index_backend_seconds`` — P6 does not
  exist yet, so the benchmark truthfully reports ``false`` / ``null``:
  explicitly NOT_APPLICABLE, never ``0.0``.
* ``sqlite_bytes`` — final byte size of the durable SQLite vault file and
  its sidecars. ``vault_bytes`` — total bytes under the vault directory.
  ``output_bytes`` / ``source_bytes`` — total bytes of the respective
  trees.

The result is a CLOSED, versioned machine-readable JSON document
(``BENCHMARK_SCHEMA_VERSION``); ``render_markdown`` derives a deterministic
human summary from exactly that JSON (one source of truth — no second
independently maintained dataset of benchmark numbers). The harness also
PROVES source immutability: every source file is hashed before and after
the run and any difference fails the benchmark.

Workspace layout: every measurement attempt runs in its own nested attempt
directory (``<workspace>/attempt-1``, then ``attempt-2`` …). An attempt that
dies from the TYPED transient publication interruption
(``PUBLICATION_INCOMPLETE``/``STAGING_PROMOTION_FAILED`` — an OS-level
rename interruption such as a Windows antivirus/indexer briefly holding the
freshly written staging tree) is restarted in a fresh attempt directory at
most :data:`MAX_TRANSIENT_PUBLICATION_RETRIES` times. The atomic rename
published nothing when it failed, so the fresh attempt is a complete,
independent measurement; any other failure surfaces immediately.

Usage:
    python tools/final_pipeline_benchmark.py --customers 2500 --orders 1500 \
        --archived 800 --workers 4 --output bench.json --summary bench.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform as platform_module
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _TOOLS_DIR.parent
for _entry in (str(_PROJECT_ROOT), str(_PROJECT_ROOT / "src")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import dbf_anonymizer  # noqa: E402
import dbfbridge  # noqa: E402
from dbf_anonymizer import build_plan, pseudonymize, verify_dataset  # noqa: E402
from dbf_anonymizer.engine import pass2 as pass2_module  # noqa: E402
from dbf_anonymizer.engine.state import (  # noqa: E402
    PASS1_STATE_FILENAME,
    PASS2_EVIDENCE_PREFIX,
)
from dbf_anonymizer.errors import ErrorCode, PublicationError  # noqa: E402
from tests.support.numeric_tables import (  # noqa: E402
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table,
    write_numeric_table_with_deleted,
)

BENCHMARK_SCHEMA_VERSION = "1.0"
WORKLOAD_ID = "final-pipeline-synthetic-v1"
WORKLOAD_VERSION = "1.0"

#: A measurement attempt killed by a TRANSIENT OS-level publication
#: interruption (for example a Windows antivirus/indexer briefly holding the
#: freshly written staging tree, ``WinError 5`` on the atomic rename) is
#: restarted in a FRESH nested attempt workspace at most this many times.
#: The atomic rename is atomic: the interrupted attempt published nothing,
#: so a fresh attempt is a complete, independent measurement — never a
#: partial or fabricated one. Any other failure surfaces immediately.
MAX_TRANSIENT_PUBLICATION_RETRIES = 2

#: The closed machine-readable field set of one benchmark result.
REPORT_FIELDS: tuple[str, ...] = (
    "benchmark_schema_version",
    "workload_id",
    "workload_version",
    "package_version",
    "dbfbridge_version",
    "python_version",
    "platform",
    "workers",
    "table_count",
    "record_count",
    "source_bytes",
    "output_bytes",
    "vault_bytes",
    "sqlite_bytes",
    "temporary_peak_bytes",
    "wall_seconds",
    "records_per_second",
    "peak_memory_bytes",
    "sqlite_seconds",
    "dbf_fpt_write_seconds",
    "verification_seconds",
    "index_backend_applicable",
    "index_backend_seconds",
    "workload_source_fingerprint",
)

#: The deterministic relation document of the synthetic workload.
RELATIONSHIP_DOCUMENT: dict[str, object] = {
    "metadata_schema_version": "1.0",
    "relations": [
        {
            "relation_id": "rel-customer",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "members": [
                {
                    "table": "north/customers.dbf",
                    "field": "CUST_ID",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "C",
                    "byte_width": 14,
                    "encoding": "cp1250",
                    "nullable": False,
                },
                {
                    "table": "south/orders.dbf",
                    "field": "CUST_ID",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "C",
                    "byte_width": 14,
                    "encoding": "cp1250",
                    "nullable": False,
                },
            ],
        }
    ],
}

_ENGINE_TRANSIENT_PREFIX = ".dbf-anonymizer-"
_SPOOL_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
_SAMPLE_INTERVAL_SECONDS = 0.025


class BenchmarkError(RuntimeError):
    """The benchmark could not produce trustworthy evidence."""


def _tree_bytes(root: Path) -> int:
    """Total byte size of all regular files under root (strict)."""
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_file():
            try:
                total += path.stat().st_size
            except OSError:
                raise BenchmarkError(f"unreadable tree entry: {path.name}") from None
    return total


def _transient_tree_bytes(root: Path) -> int:
    """Recursive byte sum of regular files under a transient DIRECTORY.

    The walk holds each directory enumeration handle for the SHORTEST
    possible time (one ``os.scandir`` block per directory, closed before any
    recursion into collected children) and reads sizes from the directory
    data the enumeration already carries.  A benchmark sampler that held
    enumeration handles on the live staging tree could make the production
    atomic promotion rename fail transiently on Windows (``WinError 5``),
    which would be the instrumentation CHANGING observed production
    behavior — this walk shape keeps that interference window negligible.
    Entries that vanish during the walk (concurrent engine cleanup) are
    tolerated and contribute nothing instead of failing the measurement.
    Symlinks/reparse aliases are never followed.
    """
    total = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def _transient_entry_bytes(entry: Path) -> int:
    """Bytes of ONE engine-owned transient artifact, file OR directory.

    The production engine owns both kinds of transient artifacts: regular
    files (the ``pass1-state.sqlite3`` spool, its ``-wal``/``-shm``/
    ``-journal`` sidecars, regular engine lock files) and directories
    (staging trees and ``.pass2-evidence-*`` shard directories).  A regular
    file contributes its actual ``st_size``; a directory contributes the
    recursive sum of its regular files; an artifact that disappears
    concurrently (``FileNotFoundError``/``OSError`` race with ordinary
    engine cleanup) contributes nothing instead of corrupting the run.
    Symlinks/reparse-like aliases are never followed.
    """
    try:
        info = entry.stat(follow_symlinks=False)
    except OSError:
        return 0
    if stat.S_ISDIR(info.st_mode):
        return _transient_tree_bytes(entry)
    if stat.S_ISREG(info.st_mode):
        return info.st_size
    return 0


def _tree_hashes(root: Path) -> dict[str, str]:
    """sha256 of every regular file under root, keyed by relative path."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# ---------------------------------------------------------------------------
# Synthetic deterministic workload (public dbfbridge writer only)
# ---------------------------------------------------------------------------
def _memo_text(index: int) -> str:
    return f"BENCH-MEMO-{index % 7:02d}"


def write_benchmark_workload(
    source_root: Path, *, customers: int, orders: int, archived: int
) -> None:
    """Write the deterministic redistributable synthetic workload.

    Exercises the architecture meaningfully: multiple DBF tables, FPT memo
    data, nullable fields, deleted records, fresh DBF/FPT writing through
    the public writer and one declared PRIMARY/FOREIGN relation.
    """
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (
            numeric_field("CUST_ID", "C", 14),
            numeric_field("NAME", "C", 24, flags=NULLABLE_FLAG),
            numeric_field("NOTE", "M", 4),
            numeric_field("AMT", "N", 9),
            numeric_field("ACTIVE", "L", 1),
        ),
        [
            {
                "CUST_ID": f"CUST{index:09d}",
                "NAME": f"SYNTHETIC-{index:09d}",
                "NOTE": _memo_text(index),
                "AMT": (index % 10000) + 1,
                "ACTIVE": "T" if index % 2 == 0 else "F",
            }
            for index in range(customers)
        ],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (
            numeric_field("CUST_ID", "C", 14),
            numeric_field("ORD_N", "N", 9),
            numeric_field("NOTE", "M", 4),
            numeric_field("WHEN_D", "D", 8, flags=NULLABLE_FLAG),
        ),
        [
            {
                "CUST_ID": f"CUST{index % max(customers, 1):09d}",
                "ORD_N": index + 1,
                "NOTE": _memo_text(index + 3),
                "WHEN_D": "20260301",
            }
            for index in range(orders)
        ],
    )
    entries: list[tuple[dict[str, object], bool]] = []
    for index in range(archived):
        entries.append(
            (
                {
                    "LEG_ID": f"LEG{index:08d}",
                    "NOTE": _memo_text(index + 5),
                    "AMT": index + 1,
                },
                index % 5 == 4,
            )
        )
    write_numeric_table_with_deleted(
        source_root,
        "archive/data.dbf",
        (numeric_field("LEG_ID", "C", 12), numeric_field("NOTE", "M", 4), numeric_field("AMT", "N", 9)),
        entries,
    )


# ---------------------------------------------------------------------------
# Optional, harness-local instrumentation
# ---------------------------------------------------------------------------
class _SqliteCollector:
    """Thread-safe cumulative SQLite API wall-time collector.

    ``sqlite_seconds`` is CUMULATIVE activity time: worker threads run
    concurrently, so the total can legitimately EXCEED ``wall_seconds``.
    It is never an exclusive process wall time and never derived by
    subtraction.  The clock is injectable so tests can produce
    deterministic, threshold-free evidence with a monotonic fake clock.
    """

    __slots__ = ("_clock", "_lock", "total_seconds")

    def __init__(self) -> None:
        self._clock = time.perf_counter
        self._lock = threading.Lock()
        self.total_seconds = 0.0

    def now(self) -> float:
        return self._clock()

    def add(self, seconds: float) -> None:
        with self._lock:
            self.total_seconds += seconds


class _TimedCursor:
    """Times every SQLite cursor API call, including fetch and stepping.

    ``sqlite3.Cursor.execute``/``executemany``/``executescript`` return the
    cursor ITSELF, so the wrapper must return itself for those calls —
    otherwise a later ``.fetchall()`` on the returned object would bypass
    the timing wrapper.  Unlisted attribute access is forwarded unchanged.
    """

    __slots__ = ("_collector", "_cursor")

    def __init__(self, cursor: Any, collector: _SqliteCollector) -> None:
        object.__setattr__(self, "_cursor", cursor)
        object.__setattr__(self, "_collector", collector)

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            result = self._cursor.execute(*args, **kwargs)
            # sqlite3.Cursor.execute returns the cursor itself: keep the
            # caller inside the timed wrapper (real return semantics).
            return self if result is self._cursor else result
        finally:
            self._collector.add(self._collector.now() - started)

    def executemany(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            result = self._cursor.executemany(*args, **kwargs)
            return self if result is self._cursor else result
        finally:
            self._collector.add(self._collector.now() - started)

    def executescript(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            result = self._cursor.executescript(*args, **kwargs)
            return self if result is self._cursor else result
        finally:
            self._collector.add(self._collector.now() - started)

    def fetchone(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            return self._cursor.fetchone(*args, **kwargs)
        finally:
            self._collector.add(self._collector.now() - started)

    def fetchmany(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            return self._cursor.fetchmany(*args, **kwargs)
        finally:
            self._collector.add(self._collector.now() - started)

    def fetchall(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            return self._cursor.fetchall(*args, **kwargs)
        finally:
            self._collector.add(self._collector.now() - started)

    def close(self) -> None:
        started = self._collector.now()
        try:
            return self._cursor.close()
        finally:
            self._collector.add(self._collector.now() - started)

    def __iter__(self) -> "_TimedCursor":
        # sqlite3.Cursor is its own iterator; row stepping happens in
        # __next__, which is timed below (cursor iteration coverage).
        return self

    def __next__(self) -> Any:
        started = self._collector.now()
        try:
            return next(self._cursor)
        finally:
            self._collector.add(self._collector.now() - started)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_cursor", "_collector"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._cursor, name, value)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_cursor"), name)


def _timed_connect(
    real_connect: Any, collector: _SqliteCollector
) -> Any:
    """Build the instrumented ``sqlite3.connect`` replacement.

    The connection OPEN itself is part of ``sqlite_seconds``.
    """

    def connecting(*args: Any, **kwargs: Any) -> Any:
        started = collector.now()
        try:
            return _TimedConnection(real_connect(*args, **kwargs), collector)
        finally:
            collector.add(collector.now() - started)

    return connecting


class _TimedConnection:
    """A forwarding proxy that TIMES the real production SQLite activity.

    Every method still calls the REAL sqlite3 connection/cursor: the
    pipeline semantics are unchanged; only wall time is observed.  Cursor
    objects handed out remain wrapped so their later fetch/iteration work
    is timed as well.  Connection open and close are part of the metric.
    """

    __slots__ = ("_collector", "_connection")

    def __init__(self, connection: Any, collector: _SqliteCollector) -> None:
        object.__setattr__(self, "_connection", connection)
        object.__setattr__(self, "_collector", collector)

    def cursor(self, *args: Any, **kwargs: Any) -> _TimedCursor:
        return _TimedCursor(self._connection.cursor(*args, **kwargs), self._collector)

    def execute(self, *args: Any, **kwargs: Any) -> _TimedCursor:
        started = self._collector.now()
        try:
            return _TimedCursor(self._connection.execute(*args, **kwargs), self._collector)
        finally:
            self._collector.add(self._collector.now() - started)

    def executemany(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            return self._connection.executemany(*args, **kwargs)
        finally:
            self._collector.add(self._collector.now() - started)

    def executescript(self, *args: Any, **kwargs: Any) -> Any:
        started = self._collector.now()
        try:
            return self._connection.executescript(*args, **kwargs)
        finally:
            self._collector.add(self._collector.now() - started)

    def commit(self) -> None:
        started = self._collector.now()
        try:
            return self._connection.commit()
        finally:
            self._collector.add(self._collector.now() - started)

    def rollback(self) -> None:
        started = self._collector.now()
        try:
            return self._connection.rollback()
        finally:
            self._collector.add(self._collector.now() - started)

    def close(self) -> None:
        started = self._collector.now()
        try:
            return self._connection.close()
        finally:
            self._collector.add(self._collector.now() - started)

    def __enter__(self) -> "_TimedConnection":
        self._connection.__enter__()
        return self

    def __exit__(self, *args: Any) -> Any:
        started = self._collector.now()
        try:
            return self._connection.__exit__(*args)
        finally:
            self._collector.add(self._collector.now() - started)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_connection", "_collector"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._connection, name, value)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_connection"), name)


class _WriteCollector:
    """Thread-safe cumulative fresh DBF/FPT write-time collector."""

    __slots__ = ("_lock", "total_seconds")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_seconds = 0.0

    def add(self, seconds: float) -> None:
        with self._lock:
            self.total_seconds += seconds


class _TransientSampler:
    """Observe engine-owned transient artifact bytes every interval.

    temporary_peak_bytes = the MAXIMUM observed total byte size of all
    engine-owned transient artifacts (staging trees, engine lock files,
    pass1 spool state files + sidecars, .pass2-evidence-* shard
    directories). Final output and vault bytes are excluded; artifacts
    deleted during the run count only while observed (documented sampling
    approximation).
    """

    def __init__(self, destination_parent: Path, vault_dir: Path) -> None:
        self._destination_parent = destination_parent
        self._vault_dir = vault_dir
        self._lock = threading.Lock()
        self._peak = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _observed_bytes(self) -> int:
        total = 0
        try:
            for entry in self._destination_parent.iterdir():
                if entry.name.startswith(_ENGINE_TRANSIENT_PREFIX):
                    total += _transient_entry_bytes(entry)
        except OSError:
            pass
        try:
            for entry in self._vault_dir.iterdir():
                if entry.name == PASS1_STATE_FILENAME or entry.name.startswith(
                    PASS1_STATE_FILENAME + "-"
                ) or entry.name.startswith(PASS2_EVIDENCE_PREFIX):
                    total += _transient_entry_bytes(entry)
        except OSError:
            pass
        return total

    def _sample(self) -> None:
        observed = self._observed_bytes()
        with self._lock:
            if observed > self._peak:
                self._peak = observed

    def _loop(self) -> None:
        while not self._stop.wait(_SAMPLE_INTERVAL_SECONDS):
            self._sample()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="bench-transient", daemon=True)
        self._thread.start()

    def stop(self) -> int:
        self._sample()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        with self._lock:
            return self._peak


def _observe_transient_bytes(destination_parent: Path, vault_dir: Path) -> int:
    """One synchronous transient observation (used by tests and the final sample)."""
    sampler = _TransientSampler(destination_parent, vault_dir)
    return sampler._observed_bytes()


# ---------------------------------------------------------------------------
# The benchmark run
# ---------------------------------------------------------------------------
@dataclass
class BenchmarkRun:
    """One benchmark run: the closed JSON report plus the REAL public results.

    ``workspace`` is the nested attempt directory that actually produced the
    measurement (``<root>/attempt-1`` for the first attempt), so consumers
    always inspect exactly the tree the reported numbers describe.
    """

    report: dict[str, object]
    pseudonymization: Any
    verification: Any
    workspace: Path


def run_final_pipeline_benchmark(
    workspace: Path,
    *,
    customers: int = 2500,
    orders: int = 1500,
    archived: int = 800,
    workers: int = 4,
) -> BenchmarkRun:
    """Run the REAL public production pipeline once and measure it truthfully.

    The measurement runs in a nested attempt workspace
    (``<workspace>/attempt-1``).  If an attempt dies from the typed transient
    publication interruption (see :data:`MAX_TRANSIENT_PUBLICATION_RETRIES`),
    the whole measurement is restarted in a FRESH nested attempt directory —
    the interrupted attempt published nothing and its numbers are discarded.
    """
    workspace = Path(workspace)
    last_error: PublicationError | None = None
    for attempt in range(1 + MAX_TRANSIENT_PUBLICATION_RETRIES):
        attempt_root = workspace / f"attempt-{attempt + 1}"
        try:
            return _run_benchmark_once(
                attempt_root,
                customers=customers,
                orders=orders,
                archived=archived,
                workers=workers,
            )
        except PublicationError as error:
            if not _is_transient_publication_interruption(error):
                raise
            last_error = error
    assert last_error is not None
    raise last_error


def _is_transient_publication_interruption(error: PublicationError) -> bool:
    """Whether a typed public failure is the retriable transient rename case.

    Only the typed ``PUBLICATION_INCOMPLETE`` failure carrying the
    ``STAGING_PROMOTION_FAILED`` detail qualifies: the atomic rename raised
    ``OSError`` WITHOUT renaming anything (the primitive is atomic), so no
    output was published and a fresh attempt is a complete measurement.
    """
    return (
        error.code is ErrorCode.PUBLICATION_INCOMPLETE
        and error.context.detail_code == "STAGING_PROMOTION_FAILED"
    )


def _run_benchmark_once(
    workspace: Path,
    *,
    customers: int,
    orders: int,
    archived: int,
    workers: int,
) -> BenchmarkRun:
    """One complete measurement attempt in its own fresh workspace."""
    workspace = Path(workspace)
    source_root = workspace / "source"
    output_root = workspace / "output"
    vault_dir = workspace / "vault"
    vault_path = vault_dir / "dictionary.sqlite3"

    # --- deterministic synthetic workload (NOT part of the measured window)
    write_benchmark_workload(
        source_root, customers=customers, orders=orders, archived=archived
    )
    source_hashes_before = _tree_hashes(source_root)
    source_bytes = sum(
        (workspace / "source" / name).stat().st_size for name in source_hashes_before
    )

    plan = build_plan(
        str(source_root),
        str(output_root),
        str(vault_path),
        relationship_document=RELATIONSHIP_DOCUMENT,
    )

    sqlite_collector = _SqliteCollector()
    write_collector = _WriteCollector()

    connecting = _timed_connect(sqlite3.connect, sqlite_collector)

    real_write_fresh_table = pass2_module.write_fresh_table

    def timed_write_fresh_table(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        try:
            return real_write_fresh_table(*args, **kwargs)
        finally:
            write_collector.add(time.perf_counter() - started)

    sampler = _TransientSampler(workspace, vault_dir)
    real_connect = sqlite3.connect
    try:
        sqlite3.connect = connecting
        pass2_module.write_fresh_table = timed_write_fresh_table
        sampler.start()
        tracemalloc.start()
        try:
            started = time.perf_counter()
            pseudonymization = pseudonymize(plan, workers=workers)
            wall_seconds = time.perf_counter() - started
            verification_started = time.perf_counter()
            verification = verify_dataset(
                pseudonymization, source=source_root, vault=vault_path
            )
            verification_seconds = time.perf_counter() - verification_started
            _current, peak_memory_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    finally:
        sqlite3.connect = real_connect
        pass2_module.write_fresh_table = real_write_fresh_table
        temporary_peak_bytes = sampler.stop()

    # --- objective pipeline facts (public result models; never serialized)
    if verification.status.name != "PASS":
        raise BenchmarkError(
            "the benchmark refuses to report without a genuinely passing verification"
        )
    record_count = int(pseudonymization.record_count)
    if record_count <= 0:
        raise BenchmarkError("the benchmark produced no pseudonymized records")

    # --- source immutability proof (the harness itself fails on any change)
    source_hashes_after = _tree_hashes(source_root)
    if source_hashes_after != source_hashes_before:
        raise BenchmarkError("source files are not byte-identical after the benchmark")

    output_bytes = _tree_bytes(output_root)
    vault_bytes = _tree_bytes(vault_dir)
    sqlite_bytes = 0
    for sidecar in ("",) + _SPOOL_SIDECAR_SUFFIXES:
        vault_file = vault_dir / (vault_path.name + sidecar)
        if vault_file.is_file():
            sqlite_bytes += vault_file.stat().st_size

    if wall_seconds <= 0:
        raise BenchmarkError("unmeasurable wall time")
    records_per_second = record_count / wall_seconds

    report: dict[str, object] = {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "workload_id": WORKLOAD_ID,
        "workload_version": WORKLOAD_VERSION,
        "package_version": dbf_anonymizer.__version__,
        "dbfbridge_version": dbfbridge.__version__,
        "python_version": platform_module.python_version(),
        "platform": platform_module.platform()[:128],
        "workers": workers,
        "table_count": int(pseudonymization.table_count),
        "record_count": record_count,
        "source_bytes": source_bytes,
        "output_bytes": output_bytes,
        "vault_bytes": vault_bytes,
        "sqlite_bytes": sqlite_bytes,
        "temporary_peak_bytes": temporary_peak_bytes,
        "wall_seconds": round(wall_seconds, 6),
        "records_per_second": round(records_per_second, 6),
        "peak_memory_bytes": peak_memory_bytes,
        "sqlite_seconds": round(sqlite_collector.total_seconds, 6),
        "dbf_fpt_write_seconds": round(write_collector.total_seconds, 6),
        "verification_seconds": round(verification_seconds, 6),
        # P6 does not exist yet: the index backend is truthfully NOT
        # applicable — never reported as 0.0.
        "index_backend_applicable": False,
        "index_backend_seconds": None,
        "workload_source_fingerprint": plan.dataset.source_fingerprint,
    }
    _validate_report_shape(report)
    return BenchmarkRun(
        report=report,
        pseudonymization=pseudonymization,
        verification=verification,
        workspace=workspace,
    )


def _validate_report_shape(report: dict[str, object]) -> None:
    """The closed, versioned result contract (fail-closed, privacy-safe)."""
    if tuple(sorted(report)) != tuple(sorted(REPORT_FIELDS)):
        raise BenchmarkError("benchmark result does not match the closed schema")
    for name in (
        "benchmark_schema_version",
        "workload_id",
        "workload_version",
        "package_version",
        "dbfbridge_version",
        "python_version",
        "platform",
        "workload_source_fingerprint",
    ):
        value = report[name]
        if not isinstance(value, str) or not value or len(value) > 128:
            raise BenchmarkError(f"unbounded or missing string field: {name}")
    for name in ("workers", "table_count", "record_count", "source_bytes",
                 "output_bytes", "vault_bytes", "sqlite_bytes",
                 "temporary_peak_bytes", "peak_memory_bytes"):
        value = report[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BenchmarkError(f"non-integer or negative numeric field: {name}")
    for name in (
        "wall_seconds",
        "records_per_second",
        "sqlite_seconds",
        "dbf_fpt_write_seconds",
        "verification_seconds",
    ):
        value = report[name]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise BenchmarkError(f"non-numeric timing field: {name}")
        if not math.isfinite(float(value)):
            raise BenchmarkError(f"non-finite timing field: {name}")
        if float(value) < 0:
            raise BenchmarkError(f"negative timing field: {name}")
    if report["index_backend_applicable"] is not False:
        raise BenchmarkError("index backend must be explicitly not applicable without P6")
    if report["index_backend_seconds"] is not None:
        raise BenchmarkError("index backend timing must be null without P6")
    records_per_second_value = report["records_per_second"]
    wall_seconds_value = report["wall_seconds"]
    if not isinstance(records_per_second_value, (int, float)) or not isinstance(
        wall_seconds_value, (int, float)
    ):
        raise BenchmarkError("non-numeric timing field")
    record_count_value = report["record_count"]
    if not isinstance(record_count_value, int):
        raise BenchmarkError("non-integer record count")
    # The ROUNDED values must still satisfy the documented derivation within
    # the rounding tolerance of both rounded quantities (5e-7 each), so the
    # coherence bound scales with the measured magnitudes instead of failing
    # on long-running (slow-environment) baseline runs.
    tolerance = 0.01 + 5e-7 * (float(wall_seconds_value) + float(records_per_second_value))
    if abs(records_per_second_value * wall_seconds_value - record_count_value) > tolerance:
        raise BenchmarkError("records_per_second is not derived from record_count / wall_seconds")


def render_markdown(report: dict[str, object]) -> str:
    """Deterministic human summary derived from EXACTLY the JSON result."""
    lines = [
        f"# Final pipeline benchmark — {report['workload_id']}",
        "",
        "> Reference measurement only, NOT a performance guarantee. Timings are",
        "> environment-dependent and include the harness instrumentation",
        "> overhead (timing wrappers, sqlite activity observation and the",
        "> tracemalloc peak scan). Regenerate with",
        "> `python tools/final_pipeline_benchmark.py --output ... --summary ...`",
        "> from a fresh disposable workspace.",
        "",
        "## Workload facts",
        "",
        f"- workload: `{report['workload_id']}` (version {report['workload_version']})",
        f"- workload source fingerprint: `{report['workload_source_fingerprint']}`",
        f"- tables: {report['table_count']}",
        f"- records written: {report['record_count']}",
        f"- source bytes: {report['source_bytes']}",
        f"- workers: {report['workers']}",
        "",
        "## Environment",
        "",
        f"- package version: `{report['package_version']}`",
        f"- dbfbridge version: `{report['dbfbridge_version']}`",
        f"- python version: `{report['python_version']}`",
        f"- platform: `{report['platform']}`",
        "",
        "## Throughput",
        "",
        f"- wall (pseudonymize): {report['wall_seconds']} s",
        f"- records per second: {report['records_per_second']}",
        "",
        "## Memory",
        "",
        f"- peak memory (tracemalloc, pseudonymize + verification): {report['peak_memory_bytes']} bytes",
        "",
        "## Storage",
        "",
        f"- output bytes: {report['output_bytes']}",
        f"- vault bytes: {report['vault_bytes']}",
        f"- sqlite bytes: {report['sqlite_bytes']}",
        f"- temporary peak bytes (sampled engine-owned transient artifacts, files and directories): {report['temporary_peak_bytes']}",
        "",
        "## Timing",
        "",
        f"- sqlite time (CUMULATIVE SQLite API activity: open, execute, fetch, row stepping, commit, close — measured): {report['sqlite_seconds']} s",
        f"- DBF/FPT fresh write time (pass2 kernel, measured): {report['dbf_fpt_write_seconds']} s",
        f"- verification (public verify_dataset): {report['verification_seconds']} s",
        "",
        "## Index backend",
        "",
        "- applicable: NO (P6 index backend does not exist yet)",
        "- timing: NOT_APPLICABLE (null)",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=str, default=None)
    parser.add_argument("--customers", type=int, default=2500)
    parser.add_argument("--orders", type=int, default=1500)
    parser.add_argument("--archived", type=int, default=800)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--summary", type=str, default=None)
    arguments = parser.parse_args(argv)

    keep = arguments.workspace is not None
    with tempfile.TemporaryDirectory(prefix="dbf-bench-") as temporary:
        workspace = Path(arguments.workspace) if keep else Path(temporary) / "run"
        run = run_final_pipeline_benchmark(
            workspace,
            customers=arguments.customers,
            orders=arguments.orders,
            archived=arguments.archived,
            workers=arguments.workers,
        )
    # allow_nan=False: the machine artifact is STRICT JSON — schema drift can
    # never silently emit NaN/Infinity (the closed schema rejects them too).
    machine = json.dumps(
        run.report, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False
    )
    summary = render_markdown(run.report)
    if arguments.output:
        output_path = Path(arguments.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(machine + "\n", encoding="utf-8")
    if arguments.summary:
        summary_path = Path(arguments.summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(summary, encoding="utf-8")
    print(machine)
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())