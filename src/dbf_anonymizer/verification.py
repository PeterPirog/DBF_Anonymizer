"""Strumieniowe testy odwracalności DBF oraz kontrola tabel w VFP."""
from __future__ import annotations

import shutil
from itertools import zip_longest
from pathlib import Path
from typing import Any

from dbfbridge import export_dbf

from .jsonstream import iter_jsonl
from .schema import is_data_record
from .vfp import VfpError, companion_cdx, verify_vfp_open


def compare_dbf_canonical(
    source_dbf: Path,
    recovered_dbf: Path,
    work_root: Path,
    job_key: str,
) -> tuple[bool, dict[str, Any]]:
    """Porównuje rekordy eksportów bez wczytywania obu tabel do RAM."""

    comparison_root = work_root / "compare" / job_key
    source_out = comparison_root / "source"
    recovered_out = comparison_root / "recovered"
    for directory in (source_out, recovered_out):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True, exist_ok=True)

    for dbf, output in ((source_dbf, source_out), (recovered_dbf, recovered_out)):
        export_dbf(
            dbf,
            output,
            formats=("jsonl",),
            memo="inline",
            deleted="include",
            overwrite=True,
            validate=False,
        )

    source_records = (
        record
        for record in iter_jsonl(source_out / f"{source_dbf.stem}.jsonl")
        if is_data_record(record)
    )
    recovered_records = (
        record
        for record in iter_jsonl(recovered_out / f"{recovered_dbf.stem}.jsonl")
        if is_data_record(record)
    )
    sentinel = object()
    differences: list[dict[str, Any]] = []
    source_count = 0
    recovered_count = 0
    for index, pair in enumerate(
        zip_longest(source_records, recovered_records, fillvalue=sentinel),
        start=1,
    ):
        expected, actual = pair
        if expected is not sentinel:
            source_count += 1
        if actual is not sentinel:
            recovered_count += 1
        if len(differences) >= 20:
            continue
        if expected is sentinel or actual is sentinel:
            differences.append(
                {
                    "record": index,
                    "scope": "record_presence",
                    "expected": "missing" if expected is sentinel else "present",
                    "actual": "missing" if actual is sentinel else "present",
                }
            )
            continue
        keys = sorted(
            {
                key
                for key in (*expected.keys(), *actual.keys())
                if not key.startswith("__dbfbridge_")
            }
        )
        for key in keys:
            if expected.get(key) != actual.get(key):
                differences.append(
                    {
                        "record": index,
                        "field": key,
                        "expected": expected.get(key),
                        "actual": actual.get(key),
                    }
                )
                if len(differences) >= 20:
                    break

    matches = not differences and source_count == recovered_count
    return matches, {
        "record_count": source_count,
        "recovered_count": recovered_count,
        "summary": (
            f"{source_count} vs {recovered_count} rekordów, "
            f"{len(differences)} pierwszych różnic"
        ),
        "differences": differences,
    }


def verify_vfp_roundtrip(
    source_dbf: Path,
    anonymized_dbf: Path,
    recovered_dbf: Path,
    *,
    progid: str,
) -> list[str]:
    """Otwiera trzy wersje tabeli i sprawdza CDX/tagi w pełnym VFP."""

    if companion_cdx(source_dbf) is None:
        return []
    checks = {
        "source": verify_vfp_open(source_dbf, progid=progid),
        "anonymized": verify_vfp_open(anonymized_dbf, progid=progid),
        "recovered": verify_vfp_open(recovered_dbf, progid=progid),
    }
    source = checks["source"]
    errors: list[str] = []
    for name, check in checks.items():
        if check.tag_count <= 0:
            errors.append(f"[VFP_CDX_EMPTY] stage={name} dbf={check.dbf}")
        if check.records != source.records:
            errors.append(
                f"[VFP_RECORD_COUNT_MISMATCH] stage={name} "
                f"expected={source.records} actual={check.records}"
            )
        if set(check.tags) != set(source.tags):
            errors.append(
                f"[VFP_TAG_MISMATCH] stage={name} expected={source.tags!r} "
                f"actual={check.tags!r}"
            )
    return errors


__all__ = ["VfpError", "compare_dbf_canonical", "verify_vfp_roundtrip"]
