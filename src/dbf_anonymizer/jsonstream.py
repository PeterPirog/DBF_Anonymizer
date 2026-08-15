"""Ograniczone pamięciowo operacje na pośrednich plikach JSONL."""
from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TextIO


def iter_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """Czyta JSONL rekord po rekordzie, bez materializowania całej tabeli."""

    with Path(path).open("r", encoding="utf-8-sig", newline="") as infile:
        for line_number, line in enumerate(infile, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"[INVALID_JSONL] path={path} line={line_number}: {exc}"
                ) from exc


def batched(
    records: Iterable[dict[str, Any]],
    size: int = 5000,
) -> Iterator[list[dict[str, Any]]]:
    """Grupuje iterator w małe, ograniczone pamięciowo partie."""

    if size <= 0:
        raise ValueError("Rozmiar partii musi być dodatni")
    batch: list[dict[str, Any]] = []
    for record in records:
        batch.append(record)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


@contextmanager
def atomic_jsonl_writer(path: str | Path) -> Iterator[TextIO]:
    """Zapisuje JSONL do pliku tymczasowego i publikuje go atomowo."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as outfile:
            yield outfile
        temporary.replace(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_records(outfile: TextIO, records: Iterable[dict[str, Any]]) -> int:
    """Dopisuje rekordy do otwartego JSONL i zwraca ich liczbę."""

    count = 0
    for record in records:
        outfile.write(
            json.dumps(
                record,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        )
        outfile.write("\n")
        count += 1
    return count
