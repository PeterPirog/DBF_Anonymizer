"""Powtarzalny mikrobenchmark budowy i odczytu mapowań SQLite."""
from __future__ import annotations

import argparse
import tempfile
import time
import tracemalloc
from pathlib import Path

from dbf_anonymizer.global_store import GlobalDictionaryStore


def run(count: int, batch_size: int) -> None:
    with tempfile.TemporaryDirectory(prefix="dbf-anonymizer-bench-") as directory:
        path = Path(directory) / "dictionary.sqlite3"
        values = [f"K{index:09d}" for index in range(count)]
        tracemalloc.start()
        started = time.perf_counter()
        with GlobalDictionaryStore(path) as store:
            store.initialize(options={}, salt="benchmark", text_encodings=["cp1250"])
            for offset in range(0, count, batch_size):
                store.add_text_values(
                    values[offset:offset + batch_size],
                    encoding="cp1250",
                    relative_path="benchmark.dbf",
                    field_name="ID",
                )
            store.assign_anonymous_values(salt="benchmark")
        build_seconds = time.perf_counter() - started

        started = time.perf_counter()
        with GlobalDictionaryStore(path, read_only=True) as store:
            for offset in range(0, count, batch_size):
                store.forward_many(values[offset:offset + batch_size])
        read_seconds = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"values={count}")
        print(f"batch_size={batch_size}")
        print(f"build_seconds={build_seconds:.3f}")
        print(f"build_values_per_second={count / build_seconds:.0f}")
        print(f"read_seconds={read_seconds:.3f}")
        print(f"read_values_per_second={count / read_seconds:.0f}")
        print(f"python_peak_mib={peak / 1024 / 1024:.1f}")
        print(f"sqlite_mib={path.stat().st_size / 1024 / 1024:.1f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=int, default=100_000)
    parser.add_argument("--batch-size", type=int, default=10_000)
    arguments = parser.parse_args()
    run(arguments.values, arguments.batch_size)
