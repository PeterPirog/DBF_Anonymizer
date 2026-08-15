"""Wysokopoziomowy, równoległy pipeline anonimizacji katalogów DBF.

Wszystkie tabele i pola C korzystają z jednego globalnego słownika SQLite,
niezależnie od nazwy pliku, katalogu oraz nazwy pola. Kosztowne etapy DBF I/O
i rekonstrukcji są wykonywane w osobnych procesach.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from decimal import Decimal, InvalidOperation
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dbfbridge import export_dbf, reconstruct_dbf

from .anonymizer import (
    AnonymizeOptions,
    anonymize_records,
    recover_records,
)
from .dictionary import dictionary_filename, load_dictionary
from .global_store import (
    GlobalDictionaryError,
    GlobalDictionaryStore,
    global_dictionary_path,
)
from .schema import load_schema

logger = logging.getLogger(__name__)


@dataclass
class TableOutcome:
    """Wynik operacji dla jednej tabeli."""

    table: str
    relative_path: str
    status: str = "OK"
    records: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class AnonymizeResult:
    """Wynik anonymize_directory."""

    source: Path
    output: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    global_error_code: str | None = None
    global_error: str | None = None
    exit_code: int = 0

    @property
    def ok(self) -> int:
        return sum(1 for table in self.tables if table.status == "OK")

    @property
    def failed(self) -> int:
        return sum(1 for table in self.tables if table.status == "FAILED")

    def raise_for_errors(self) -> None:
        if self.failed:
            raise RuntimeError(f"Anonimizacja nie powiodła się dla {self.failed} tabel.")


@dataclass
class RecoveryResult:
    """Wynik make_dbf_recovery."""

    source: Path
    output: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    exit_code: int = 0

    @property
    def ok(self) -> int:
        return sum(1 for table in self.tables if table.status == "OK")

    @property
    def failed(self) -> int:
        return sum(1 for table in self.tables if table.status == "FAILED")

    def raise_for_errors(self) -> None:
        if self.failed:
            raise RuntimeError(f"Recovery nie powiodło się dla {self.failed} tabel.")


@dataclass
class SelfTestReport:
    """Wynik self_test — porównanie źródłowego i odtworzonego DBF."""

    source: Path
    anonymized: Path
    recovered: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    canonical_matches: int = 0
    canonical_mismatches: int = 0
    exit_code: int = 0

    @property
    def successful(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class _PreparedTable:
    """Metadane eksportu źródłowego przygotowanego w procesie roboczym."""

    source: str
    relative_path: str
    job_root: str
    jsonl_path: str
    schema_path: str
    records: int


def _iter_dbf_files(root: Path) -> list[Path]:
    """Rekurencyjnie znajduje pliki .dbf z danymi (pomija formularze VFP)."""

    skip_suffixes = {
        ".scx", ".sct", ".frx", ".frt", ".lbx", ".lbt",
        ".mnx", ".mnt", ".pjx", ".pjt", ".vcx", ".vct",
        ".dbc", ".dct", ".dcx", ".prg",
    }
    found: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not path.is_file() or path.suffix.lower() != ".dbf":
            continue
        stem = path.stem.lower()
        if any((path.parent / f"{stem}{suffix}").exists() for suffix in skip_suffixes):
            continue
        found.append(path)
    return found


def _relative_to(path: Path, root: Path) -> Path:
    return path.resolve().relative_to(root.resolve())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as infile:
        for line in infile:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    return records


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as outfile:
        for record in records:
            outfile.write(
                json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            )
            outfile.write("\n")
    temporary.replace(path)


def _schema_path_for_jsonl(jsonl_path: Path) -> Path:
    return jsonl_path.with_name(f"{jsonl_path.stem}_schema.json")


def _default_output_dir(source: Path, suffix: str) -> Path:
    return source.parent / f"{source.name}{suffix}"


def _job_key(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:20]
    return f"job_{digest}"


def _resolve_workers(workers: int | None, task_count: int) -> int:
    """Zwraca liczbę procesów; None/0 oznacza dobór automatyczny."""

    if workers is not None and workers < 0:
        raise ValueError("workers musi być >= 0 (0/None = automatycznie)")
    requested = workers or (os.cpu_count() or 1)
    return max(1, min(requested, max(1, task_count)))


def _validate_generated_path(source: Path, generated: Path, label: str) -> None:
    """Chroni katalog źródłowy przed przypadkowym usunięciem jako wynik."""

    if generated == source or generated in source.parents:
        raise ValueError(f"{label} nie może być katalogiem źródłowym ani jego nadrzędnym: {generated}")


def _prepare_directory(path: Path, overwrite: bool) -> None:
    if path.exists() and overwrite:
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _failed_outcome(source: str | Path, relative_path: str, exc: BaseException) -> TableOutcome:
    return TableOutcome(
        table=Path(source).name,
        relative_path=relative_path,
        status="FAILED",
        errors=[f"{Path(source).name}: {exc}"],
    )


def _blocked_outcome(prepared: _PreparedTable, exc: BaseException) -> TableOutcome:
    """Tabela wyeksportowana poprawnie, ale zablokowana przez błąd globalny."""
    return TableOutcome(
        table=Path(prepared.source).name,
        relative_path=prepared.relative_path,
        status="FAILED",
        records=prepared.records,
        errors=[f"{Path(prepared.source).name}: {exc}"],
    )


def _set_exit_code(outcomes: list[TableOutcome]) -> int:
    if any(item.status == "FAILED" for item in outcomes):
        return 1
    if any(item.status == "WARNING" for item in outcomes):
        return 2
    return 0


def _apply_reconstruct_result(outcome: TableOutcome, reconstruct_result: Any) -> None:
    for item in reconstruct_result.results:
        if item.status == "FAILED":
            outcome.status = "FAILED"
            outcome.errors.extend(item.errors or [f"reconstruct FAILED: {item.source}"])
        if item.warnings:
            outcome.warnings.extend(item.warnings)
    if outcome.status != "FAILED" and outcome.warnings:
        outcome.status = "WARNING"


def _numeric_width_context(
    schema: Any,
    records: list[dict[str, Any]],
) -> str | None:
    """Znajduje pierwszą wartość N/F, która nie mieści się w deklaracji pola.

    dbfbridge zgłasza taki błąd dopiero podczas zapisu i bez nazwy pola ani
    numeru rekordu. Kontekst jest obliczany wyłącznie po nieudanej rekonstrukcji,
    więc nie dodaje kosztu do poprawnych tabel.
    """

    data_records = [
        record for record in records
        if record.get("type") not in ("summary", "table")
    ]
    for record_index, record in enumerate(data_records, start=1):
        for field in schema.fields:
            if not field.is_numeric:
                continue
            value = record.get(field.name)
            if value in (None, ""):
                continue
            decimals = int(field.decimal or 0)
            try:
                number = Decimal(str(value))
            except (InvalidOperation, ValueError):
                continue
            rendered = format(number, f".{decimals}f")
            if len(rendered) > field.length:
                return (
                    f"record={record_index} field={field.name} "
                    f"dbf_type={field.dbf_type}({field.length},{decimals}) "
                    f"rendered={rendered!r} rendered_width={len(rendered)}"
                )
    return None


def _publish_reconstructed_table(
    staging_output: Path,
    output_parent: Path,
    table_stem: str,
    *,
    overwrite: bool,
) -> None:
    """Publikuje atomowo wyłącznie artefakty jednej tabeli DBF.

    Raporty dbfbridge pozostają w izolowanym katalogu zadania. Dzięki temu
    procesy rekonstruujące różne tabele w tym samym katalogu nie współdzielą
    ``reconstruction_report.jsonl`` ani jego pliku ``.partial``.
    """

    artifacts = sorted(
        (
            path for path in staging_output.iterdir()
            if path.is_file() and path.stem.casefold() == table_stem.casefold()
        ),
        key=lambda path: path.name.casefold(),
    )
    if not any(path.suffix.casefold() == ".dbf" for path in artifacts):
        raise FileNotFoundError(
            "[RECONSTRUCTED_DBF_MISSING] Rekonstrukcja nie utworzyła DBF "
            f"dla tabeli {table_stem!r} w {staging_output}"
        )

    output_parent.mkdir(parents=True, exist_ok=True)
    for source in artifacts:
        destination = output_parent / source.name
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Plik wynikowy już istnieje: {destination}")
        temporary = destination.with_name(
            f".{destination.name}.{os.getpid()}.partial"
        )
        temporary.unlink(missing_ok=True)
        try:
            shutil.copy2(source, temporary)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def _reconstruct_isolated(
    *,
    source_dir: Path,
    staging_output: Path,
    output_parent: Path,
    table_stem: str,
    relative_path: str,
    schema: Any,
    records: list[dict[str, Any]],
    overwrite: bool,
) -> Any:
    """Rekonstruuje tabelę bez współdzielenia plików roboczych między workerami."""

    staging_output.mkdir(parents=True, exist_ok=True)
    try:
        reconstruction = reconstruct_dbf(
            source=source_dir,
            output=staging_output,
            input_format="jsonl",
            memo="inline",
            overwrite=True,
        )
    except Exception as exc:
        numeric_context = _numeric_width_context(schema, records)
        context = f" path={relative_path}"
        if numeric_context:
            context += f" {numeric_context}"
        raise RuntimeError(
            f"[RECONSTRUCTION_FAILED]{context} "
            f"error_type={type(exc).__name__} error={exc}"
        ) from exc

    if not any(item.status == "FAILED" for item in reconstruction.results):
        _publish_reconstructed_table(
            staging_output,
            output_parent,
            table_stem,
            overwrite=overwrite,
        )
    return reconstruction


def _prepare_export_worker(
    source_path: str,
    relative_path: str,
    temp_root: str,
) -> _PreparedTable:
    """Eksportuje pojedynczy DBF do izolowanego katalogu zadania."""

    job_root = Path(temp_root) / _job_key(relative_path)
    export_dir = job_root / "source"
    export_dir.mkdir(parents=True, exist_ok=True)
    source = Path(source_path)
    export_dbf(
        source=source,
        output=export_dir,
        formats=("jsonl",),
        memo="inline",
        deleted="include",
        overwrite=True,
        validate=False,
    )
    jsonl_path = export_dir / f"{source.stem}.jsonl"
    schema_path = _schema_path_for_jsonl(jsonl_path)
    if not jsonl_path.is_file() or not schema_path.is_file():
        raise FileNotFoundError(f"Eksport nie wygenerował JSONL lub schematu dla {relative_path}")
    records = sum(
        1
        for record in _read_jsonl(jsonl_path)
        if record.get("type") not in ("summary", "table")
    )
    return _PreparedTable(
        source=str(source),
        relative_path=relative_path,
        job_root=str(job_root),
        jsonl_path=str(jsonl_path),
        schema_path=str(schema_path),
        records=records,
    )


def _anonymize_prepared_worker(
    prepared: _PreparedTable,
    output_root: str,
    dictionary_dir: str,
    options: AnonymizeOptions,
    overwrite: bool,
) -> TableOutcome:
    """Koduje przygotowany eksport wspólnym słownikiem i rekonstruuje DBF."""

    outcome = TableOutcome(
        table=Path(prepared.source).name,
        relative_path=prepared.relative_path,
        records=prepared.records,
    )
    schema = load_schema(Path(prepared.schema_path))
    records = _read_jsonl(Path(prepared.jsonl_path))
    data_records = [
        record for record in records if record.get("type") not in ("summary", "table")
    ]
    text_values = {
        record.get(field.name)
        for record in data_records
        for field in schema.fields
        if field.is_text and record.get(field.name) not in (None, "")
    }
    with GlobalDictionaryStore(
        global_dictionary_path(dictionary_dir), read_only=True
    ) as store:
        global_mapping = store.forward_many(text_values)

    anonymized, _ = anonymize_records(
        schema,
        records,
        options,
        global_text_mapping=global_mapping,
    )
    anonymous_dir = Path(prepared.job_root) / "anonymized"
    anonymous_jsonl = anonymous_dir / Path(prepared.jsonl_path).name
    anonymous_schema = _schema_path_for_jsonl(anonymous_jsonl)
    _write_jsonl(anonymous_jsonl, anonymized)
    shutil.copyfile(prepared.schema_path, anonymous_schema)

    output_parent = (Path(output_root) / Path(prepared.relative_path)).parent
    output_parent.mkdir(parents=True, exist_ok=True)
    reconstruction = _reconstruct_isolated(
        source_dir=anonymous_dir,
        staging_output=Path(prepared.job_root) / "reconstructed",
        output_parent=output_parent,
        table_stem=Path(prepared.source).stem,
        relative_path=prepared.relative_path,
        schema=schema,
        records=anonymized,
        overwrite=overwrite,
    )
    _apply_reconstruct_result(outcome, reconstruction)
    return outcome


def _recover_one_table_worker(
    source_path: str,
    relative_path: str,
    temp_root: str,
    output_root: str,
    dictionary_dir: str,
    overwrite: bool,
) -> TableOutcome:
    """Dekoduje pojedynczy DBF wspólnym słownikiem w izolowanym procesie."""

    source = Path(source_path)
    outcome = TableOutcome(table=source.name, relative_path=relative_path)
    job_root = Path(temp_root) / _job_key(relative_path)
    exported_dir = job_root / "exported"
    exported_dir.mkdir(parents=True, exist_ok=True)
    export_dbf(
        source=source,
        output=exported_dir,
        formats=("jsonl",),
        memo="inline",
        deleted="include",
        overwrite=True,
        validate=False,
    )
    jsonl_path = exported_dir / f"{source.stem}.jsonl"
    schema_path = _schema_path_for_jsonl(jsonl_path)
    if not jsonl_path.is_file() or not schema_path.is_file():
        raise FileNotFoundError(f"Eksport nie wygenerował JSONL lub schematu dla {relative_path}")

    schema = load_schema(schema_path)
    records = _read_jsonl(jsonl_path)
    outcome.records = sum(
        1 for record in records if record.get("type") not in ("summary", "table")
    )
    global_path = global_dictionary_path(dictionary_dir)
    if global_path.is_file():
        data_records = [
            record
            for record in records
            if record.get("type") not in ("summary", "table")
        ]
        anonymous_values = {
            record.get(field.name)
            for record in data_records
            for field in schema.fields
            if field.is_text and record.get(field.name) not in (None, "")
        }
        with GlobalDictionaryStore(global_path, read_only=True) as store:
            reverse_mapping = store.reverse_many(anonymous_values)
            table_dict = store.table_dictionary(schema, relative_path)
        recovered = recover_records(
            schema,
            records,
            table_dict,
            relative_path=relative_path,
            global_reverse_mapping=reverse_mapping,
        )
    else:
        # Kompatybilność ze słownikami JSON wersji 1/2.
        table_dict = load_dictionary(source.name, Path(dictionary_dir))
        if table_dict is None:
            raise FileNotFoundError(
                f"Brak słownika dla {source.name}: {dictionary_filename(source.name)}"
            )
        recovered = recover_records(
            schema,
            records,
            table_dict,
            relative_path=relative_path,
        )

    recovered_dir = job_root / "recovered"
    recovered_jsonl = recovered_dir / jsonl_path.name
    recovered_schema = _schema_path_for_jsonl(recovered_jsonl)
    _write_jsonl(recovered_jsonl, recovered)
    shutil.copyfile(schema_path, recovered_schema)

    output_parent = (Path(output_root) / Path(relative_path)).parent
    output_parent.mkdir(parents=True, exist_ok=True)
    reconstruction = _reconstruct_isolated(
        source_dir=recovered_dir,
        staging_output=job_root / "reconstructed",
        output_parent=output_parent,
        table_stem=source.stem,
        relative_path=relative_path,
        schema=schema,
        records=recovered,
        overwrite=overwrite,
    )
    _apply_reconstruct_result(outcome, reconstruction)
    return outcome


def _prepare_exports(
    dbf_files: list[Path],
    source: Path,
    temp_root: Path,
    workers: int | None,
) -> tuple[list[_PreparedTable], list[TableOutcome]]:
    jobs = [
        (str(path), _relative_to(path, source).as_posix(), str(temp_root))
        for path in dbf_files
    ]
    max_workers = _resolve_workers(workers, len(jobs))
    logger.info(
        "phase=export event=start files=%d workers=%d",
        len(jobs),
        max_workers,
    )
    prepared: list[_PreparedTable] = []
    failed: list[TableOutcome] = []

    if max_workers == 1:
        for job in jobs:
            try:
                prepared.append(_prepare_export_worker(*job))
                logger.info(
                    "phase=export event=file_done path=%s records=%d",
                    prepared[-1].relative_path,
                    prepared[-1].records,
                )
            except Exception as exc:
                logger.exception(
                    "phase=export event=file_failed path=%s error_type=%s error=%s",
                    job[1],
                    type(exc).__name__,
                    exc,
                )
                failed.append(_failed_outcome(job[0], job[1], exc))
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_prepare_export_worker, *job): job
                for job in jobs
            }
            for future in as_completed(futures):
                job = futures[future]
                try:
                    item = future.result()
                    prepared.append(item)
                    logger.info(
                        "phase=export event=file_done path=%s records=%d",
                        item.relative_path,
                        item.records,
                    )
                except Exception as exc:
                    logger.exception(
                        "phase=export event=file_failed path=%s error_type=%s error=%s",
                        job[1],
                        type(exc).__name__,
                        exc,
                    )
                    failed.append(_failed_outcome(job[0], job[1], exc))

    prepared.sort(key=lambda item: item.relative_path.casefold())
    logger.info(
        "phase=export event=done successful=%d failed=%d",
        len(prepared),
        len(failed),
    )
    return prepared, failed


def _run_prepared_anonymization(
    prepared: list[_PreparedTable],
    output: Path,
    dictionary_dir: Path,
    options: AnonymizeOptions,
    overwrite: bool,
    workers: int | None,
) -> list[TableOutcome]:
    max_workers = _resolve_workers(workers, len(prepared))
    logger.info(
        "phase=anonymize event=start files=%d workers=%d",
        len(prepared),
        max_workers,
    )
    outcomes: list[TableOutcome] = []

    if max_workers == 1:
        for item in prepared:
            try:
                outcome = _anonymize_prepared_worker(
                    item, str(output), str(dictionary_dir), options, overwrite
                )
                outcomes.append(outcome)
                logger.info(
                    "phase=anonymize event=file_done path=%s status=%s records=%d",
                    outcome.relative_path,
                    outcome.status,
                    outcome.records,
                )
            except Exception as exc:
                logger.exception(
                    "phase=anonymize event=file_failed path=%s error_type=%s error=%s",
                    item.relative_path,
                    type(exc).__name__,
                    exc,
                )
                outcomes.append(_failed_outcome(item.source, item.relative_path, exc))
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _anonymize_prepared_worker,
                    item,
                    str(output),
                    str(dictionary_dir),
                    options,
                    overwrite,
                ): item
                for item in prepared
            }
            for future in as_completed(futures):
                item = futures[future]
                try:
                    outcome = future.result()
                    outcomes.append(outcome)
                    logger.info(
                        "phase=anonymize event=file_done path=%s status=%s records=%d",
                        outcome.relative_path,
                        outcome.status,
                        outcome.records,
                    )
                except Exception as exc:
                    logger.exception(
                        "phase=anonymize event=file_failed path=%s error_type=%s error=%s",
                        item.relative_path,
                        type(exc).__name__,
                        exc,
                    )
                    outcomes.append(_failed_outcome(item.source, item.relative_path, exc))

    logger.info(
        "phase=anonymize event=done successful=%d failed=%d",
        sum(item.status != "FAILED" for item in outcomes),
        sum(item.status == "FAILED" for item in outcomes),
    )
    return outcomes


def _run_recovery(
    dbf_files: list[Path],
    source: Path,
    temp_root: Path,
    output: Path,
    dictionary_dir: Path,
    overwrite: bool,
    workers: int | None,
) -> list[TableOutcome]:
    jobs = [
        (
            str(path),
            _relative_to(path, source).as_posix(),
            str(temp_root),
            str(output),
            str(dictionary_dir),
            overwrite,
        )
        for path in dbf_files
    ]
    max_workers = _resolve_workers(workers, len(jobs))
    logger.info(
        "phase=recovery event=start files=%d workers=%d",
        len(jobs),
        max_workers,
    )
    outcomes: list[TableOutcome] = []

    if max_workers == 1:
        for job in jobs:
            try:
                outcome = _recover_one_table_worker(*job)
                outcomes.append(outcome)
                logger.info(
                    "phase=recovery event=file_done path=%s status=%s records=%d",
                    outcome.relative_path,
                    outcome.status,
                    outcome.records,
                )
            except Exception as exc:
                logger.exception(
                    "phase=recovery event=file_failed path=%s error_type=%s error=%s",
                    job[1],
                    type(exc).__name__,
                    exc,
                )
                outcomes.append(_failed_outcome(job[0], job[1], exc))
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_recover_one_table_worker, *job): job
                for job in jobs
            }
            for future in as_completed(futures):
                job = futures[future]
                try:
                    outcome = future.result()
                    outcomes.append(outcome)
                    logger.info(
                        "phase=recovery event=file_done path=%s status=%s records=%d",
                        outcome.relative_path,
                        outcome.status,
                        outcome.records,
                    )
                except Exception as exc:
                    logger.exception(
                        "phase=recovery event=file_failed path=%s error_type=%s error=%s",
                        job[1],
                        type(exc).__name__,
                        exc,
                    )
                    outcomes.append(_failed_outcome(job[0], job[1], exc))

    logger.info(
        "phase=recovery event=done successful=%d failed=%d",
        sum(item.status != "FAILED" for item in outcomes),
        sum(item.status == "FAILED" for item in outcomes),
    )
    return outcomes


def _build_global_dictionary(
    prepared: list[_PreparedTable],
    dictionary_dir: Path,
    options: AnonymizeOptions,
    *,
    overwrite: bool,
) -> Path:
    """Buduje atomowo jeden słownik SQLite dla wszystkich przygotowanych DBF."""
    final_path = global_dictionary_path(dictionary_dir)
    if final_path.exists() and not overwrite:
        raise FileExistsError(f"Globalny słownik już istnieje: {final_path}")

    temporary = final_path.with_name(
        f".{final_path.name}.build-{os.getpid()}.tmp"
    )
    temporary.unlink(missing_ok=True)
    try:
        ordered = sorted(prepared, key=lambda table: table.relative_path.casefold())
        schemas = {
            item.relative_path: load_schema(Path(item.schema_path))
            for item in ordered
        }
        encodings = sorted({schema.encoding for schema in schemas.values()})
        encoding_paths: dict[str, list[str]] = {}
        for relative_path, schema in schemas.items():
            encoding_paths.setdefault(schema.encoding, []).append(relative_path)
        logger.info(
            "phase=dictionary event=start files=%d encodings=%s path=%s",
            len(ordered),
            ",".join(encodings),
            final_path,
        )
        for encoding, paths in sorted(encoding_paths.items()):
            logger.info(
                "phase=dictionary event=encoding_detected encoding=%s files=%d "
                "sample_paths=%s",
                encoding,
                len(paths),
                ";".join(sorted(paths, key=str.casefold)[:8]),
            )
        with GlobalDictionaryStore(temporary) as store:
            store.initialize(
                options={
                    "memo_mode": options.memo_mode,
                    "date_offset_days": options.date_offset_days,
                    "text_mode": options.text_mode,
                },
                salt=options.salt,
                text_encodings=encodings,
            )
            domain = store.options()
            logger.info(
                "phase=dictionary event=text_domain_ready normalized_encodings=%s "
                "alphabet_size=%s",
                ",".join(domain.get("text_encodings", [])),
                domain.get("text_alphabet_size"),
            )
            for index, item in enumerate(ordered, start=1):
                schema = schemas[item.relative_path]
                records = [
                    record
                    for record in _read_jsonl(Path(item.jsonl_path))
                    if record.get("type") not in ("summary", "table")
                ]
                store.register_file(item.relative_path, Path(item.source).name)
                distinct_in_table = 0
                for field in schema.fields:
                    if field.is_text:
                        distinct_in_table += store.add_text_values(
                            (record.get(field.name) for record in records),
                            encoding=schema.encoding,
                            relative_path=item.relative_path,
                            field_name=field.name,
                        )
                if options.memo_mode == "mask":
                    for field in schema.fields:
                        if field.is_memo:
                            store.add_memo_values(
                                item.relative_path,
                                field.name,
                                (record.get(field.name) for record in records),
                            )
                # Ogranicza rozmiar transakcji przy dużej liczbie tabel.
                store.commit()
                logger.info(
                    "phase=dictionary event=table_scanned current=%d total=%d "
                    "path=%s records=%d distinct_field_values=%d encoding=%s",
                    index,
                    len(ordered),
                    item.relative_path,
                    len(records),
                    distinct_in_table,
                    schema.encoding,
                )
            store.assign_anonymous_values(salt=options.salt)

        # ``Path.replace`` korzysta z os.replace: stary słownik pozostaje na
        # miejscu aż do gotowości kompletnego pliku tymczasowego.
        temporary.replace(final_path)
        logger.info(
            "phase=dictionary event=done files=%d path=%s",
            len(ordered),
            final_path,
        )
        return final_path
    except Exception as exc:
        error_code = (
            exc.code if isinstance(exc, GlobalDictionaryError)
            else type(exc).__name__
        )
        if isinstance(exc, GlobalDictionaryError):
            logger.error(
                "phase=dictionary event=failed error_code=%s error=%s",
                error_code,
                exc,
            )
        else:
            logger.exception(
                "phase=dictionary event=failed error_code=%s error=%s",
                error_code,
                exc,
            )
        temporary.unlink(missing_ok=True)
        Path(f"{temporary}-journal").unlink(missing_ok=True)
        raise


def anonymize_directory(
    source_dir: str | Path,
    *,
    output_dir: str | Path | None = None,
    dictionary_dir: str | Path | None = None,
    memo_mode: str = "mask",
    date_offset_days: int = 0,
    salt: str = "",
    overwrite: bool = True,
    keep_temp: bool = False,
    workers: int | None = None,
) -> AnonymizeResult:
    """Anonimizuje katalog jednym słownikiem tekstowym dla całej bazy.

    workers=None lub workers=0 dobiera liczbę procesów automatycznie.
    workers=1 wymusza przetwarzanie sekwencyjne.
    """

    source = Path(source_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog źródłowy nie istnieje: {source}")
    _resolve_workers(workers, 1)

    output = (
        Path(output_dir).resolve()
        if output_dir
        else _default_output_dir(source, "_anonymized")
    )
    dict_dir = (
        Path(dictionary_dir).resolve()
        if dictionary_dir
        else _default_output_dir(source, "_dict")
    )
    _validate_generated_path(source, output, "Katalog wyjściowy")
    _validate_generated_path(source, dict_dir, "Katalog słowników")
    if output == dict_dir:
        raise ValueError("Katalog wyjściowy i katalog słowników muszą być różne")

    temp_root = source.parent / "var" / f"{source.name}_anon_temp_{os.getpid()}"
    if temp_root.exists():
        shutil.rmtree(temp_root)
    # Nie usuwaj poprzedniego wyniku ani słownika przed udanym eksportem i
    # zbudowaniem nowej mapy. SQLite jest podmieniany dopiero po ukończeniu build.
    output.parent.mkdir(parents=True, exist_ok=True)
    dict_dir.mkdir(parents=True, exist_ok=True)
    temp_root.mkdir(parents=True, exist_ok=True)

    result = AnonymizeResult(source=source, output=output, dictionary_dir=dict_dir)
    try:
        dbf_files = _iter_dbf_files(source)
        logger.info(
            "phase=pipeline event=start operation=anonymize source=%s output=%s "
            "dictionary_dir=%s dbf_files=%d requested_workers=%s overwrite=%s",
            source,
            output,
            dict_dir,
            len(dbf_files),
            workers if workers is not None else "auto",
            overwrite,
        )
        if not dbf_files:
            result.tables.append(
                TableOutcome(
                    table="-",
                    relative_path="-",
                    status="WARNING",
                    warnings=["Brak plików DBF z danymi w katalogu źródłowym."],
                )
            )
            result.exit_code = 2
            return result

        options = AnonymizeOptions(
            memo_mode=memo_mode,
            date_offset_days=date_offset_days,
            salt=salt,
        )
        prepared, export_failures = _prepare_exports(
            dbf_files,
            source,
            temp_root,
            workers,
        )

        dictionary_failures: list[TableOutcome] = []
        valid: list[_PreparedTable] = []
        if export_failures:
            # Nie wolno budować mapy na niepełnym zbiorze tabel: brakujący klucz
            # mógłby zerwać relację z jedną z tabel, których eksport się udał.
            exc = RuntimeError(
                "Przerwano anonimizację: nie udało się wyeksportować wszystkich "
                "tabel wymaganych przez globalny słownik"
            )
            result.global_error_code = "INCOMPLETE_EXPORT"
            result.global_error = str(exc)
            logger.error(
                "phase=pipeline event=blocked error_code=%s error=%s failed_exports=%d",
                result.global_error_code,
                result.global_error,
                len(export_failures),
            )
            dictionary_failures = [
                _blocked_outcome(item, exc)
                for item in prepared
            ]
        else:
            try:
                _build_global_dictionary(
                    prepared,
                    dict_dir,
                    options,
                    overwrite=overwrite,
                )
                valid = prepared
            except Exception as exc:
                # Bez kompletnej mapy globalnej żadnej tabeli nie wolno kodować,
                # bo relacje między tabelami przestałyby być jednoznaczne.
                dictionary_failures = [
                    _blocked_outcome(item, exc)
                    for item in prepared
                ]

                result.global_error_code = (
                    exc.code if isinstance(exc, GlobalDictionaryError)
                    else type(exc).__name__
                )
                result.global_error = str(exc)

        if valid:
            _prepare_directory(output, overwrite)

        processed = _run_prepared_anonymization(
            valid,
            output,
            dict_dir,
            options,
            overwrite,
            workers,
        )
        result.tables = sorted(
            [*export_failures, *dictionary_failures, *processed],
            key=lambda item: item.relative_path.casefold(),
        )
        result.exit_code = _set_exit_code(result.tables)
        logger.info(
            "phase=pipeline event=done operation=anonymize ok=%d failed=%d "
            "exit_code=%d global_error_code=%s",
            result.ok,
            result.failed,
            result.exit_code,
            result.global_error_code or "none",
        )
        return result
    finally:
        if not keep_temp:
            shutil.rmtree(temp_root, ignore_errors=True)


def make_dbf_recovery(
    anonymized_dir: str | Path,
    dictionary_dir: str | Path,
    *,
    output_dir: str | Path | None = None,
    overwrite: bool = True,
    keep_temp: bool = False,
    workers: int | None = None,
) -> RecoveryResult:
    """Odtwarza wszystkie DBF równolegle ze współdzielonych słowników."""

    source = Path(anonymized_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog zaanonimizowany nie istnieje: {source}")
    _resolve_workers(workers, 1)
    dict_dir = Path(dictionary_dir).resolve()
    if not dict_dir.is_dir():
        raise FileNotFoundError(f"Katalog słowników nie istnieje: {dict_dir}")

    output = (
        Path(output_dir).resolve()
        if output_dir
        else _default_output_dir(source, "_recovered")
    )
    _validate_generated_path(source, output, "Katalog wyjściowy")
    temp_root = source.parent / "var" / f"{source.name}_recover_temp_{os.getpid()}"
    if temp_root.exists():
        shutil.rmtree(temp_root)
    _prepare_directory(output, overwrite)
    temp_root.mkdir(parents=True, exist_ok=True)

    result = RecoveryResult(source=source, output=output, dictionary_dir=dict_dir)
    try:
        dbf_files = _iter_dbf_files(source)
        logger.info(
            "phase=pipeline event=start operation=recovery source=%s output=%s "
            "dictionary_dir=%s dbf_files=%d requested_workers=%s overwrite=%s",
            source,
            output,
            dict_dir,
            len(dbf_files),
            workers if workers is not None else "auto",
            overwrite,
        )
        if not dbf_files:
            return result
        result.tables = sorted(
            _run_recovery(
                dbf_files,
                source,
                temp_root,
                output,
                dict_dir,
                overwrite,
                workers,
            ),
            key=lambda item: item.relative_path.casefold(),
        )
        result.exit_code = _set_exit_code(result.tables)
        logger.info(
            "phase=pipeline event=done operation=recovery ok=%d failed=%d exit_code=%d",
            result.ok,
            result.failed,
            result.exit_code,
        )
        return result
    finally:
        if not keep_temp:
            shutil.rmtree(temp_root, ignore_errors=True)


def self_test(
    source_dir: str | Path,
    *,
    memo_mode: str = "mask",
    date_offset_days: int = 0,
    salt: str = "",
    keep_temp: bool = False,
    workers: int | None = None,
) -> SelfTestReport:
    """Wykonuje round-trip i porównuje tabele po ścieżkach względnych."""

    source = Path(source_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog źródłowy nie istnieje: {source}")
    _resolve_workers(workers, 1)

    work_root = source.parent / "var" / f"{source.name}_selftest_{os.getpid()}"
    if work_root.exists():
        shutil.rmtree(work_root)
    work_root.mkdir(parents=True, exist_ok=True)
    anonymous_dir = work_root / f"{source.name}_anonymized"
    dict_dir = work_root / f"{source.name}_dict"
    recovered_dir = work_root / f"{source.name}_recovered"

    logger.info(
        "phase=pipeline event=start operation=self_test source=%s "
        "requested_workers=%s",
        source,
        workers if workers is not None else "auto",
    )

    anonymous_result = anonymize_directory(
        source,
        output_dir=anonymous_dir,
        dictionary_dir=dict_dir,
        memo_mode=memo_mode,
        date_offset_days=date_offset_days,
        salt=salt,
        overwrite=True,
        keep_temp=keep_temp,
        workers=workers,
    )
    anonymous_result.raise_for_errors()
    recovery_result = make_dbf_recovery(
        anonymous_dir,
        dict_dir,
        output_dir=recovered_dir,
        overwrite=True,
        keep_temp=keep_temp,
        workers=workers,
    )
    recovery_result.raise_for_errors()

    report = SelfTestReport(
        source=source,
        anonymized=anonymous_dir,
        recovered=recovered_dir,
        dictionary_dir=dict_dir,
    )
    try:
        source_dbfs = {
            _relative_to(path, source).as_posix(): path
            for path in _iter_dbf_files(source)
        }
        recovered_dbfs = {
            _relative_to(path, recovered_dir).as_posix(): path
            for path in _iter_dbf_files(recovered_dir)
        }

        for relative_path, source_dbf in source_dbfs.items():
            outcome = TableOutcome(table=source_dbf.name, relative_path=relative_path)
            recovered_dbf = recovered_dbfs.get(relative_path)
            if recovered_dbf is None:
                outcome.status = "FAILED"
                outcome.errors.append(f"Brak odtworzonego pliku DBF: {relative_path}")
                report.canonical_mismatches += 1
                report.tables.append(outcome)
                continue

            try:
                matches, difference = _compare_dbf_canonical(
                    source_dbf,
                    recovered_dbf,
                    work_root,
                    relative_path,
                )
                outcome.records = difference["record_count"]
                if matches:
                    report.canonical_matches += 1
                else:
                    outcome.status = "FAILED"
                    outcome.errors.append(f"Różnice kanoniczne: {difference['summary']}")
                    for item in difference.get("differences", [])[:10]:
                        field_name = item.get("field", item.get("scope", "?"))
                        outcome.errors.append(
                            f"rekord {item['record']} pole {field_name}: "
                            f"expected={item['expected']!r} actual={item['actual']!r}"
                        )
                    report.canonical_mismatches += 1
            except Exception as exc:
                outcome.status = "FAILED"
                outcome.errors.append(f"Błąd porównania: {exc}")
                report.canonical_mismatches += 1
            report.tables.append(outcome)

        for relative_path, recovered_dbf in recovered_dbfs.items():
            if relative_path not in source_dbfs:
                report.tables.append(
                    TableOutcome(
                        table=recovered_dbf.name,
                        relative_path=relative_path,
                        status="WARNING",
                        warnings=["Dodatkowy plik DBF w recovered bez źródła"],
                    )
                )

        report.tables.sort(key=lambda item: item.relative_path.casefold())
        if report.canonical_mismatches:
            report.exit_code = 1
        elif any(item.status == "WARNING" for item in report.tables):
            report.exit_code = 2
        logger.info(
            "phase=pipeline event=done operation=self_test matches=%d "
            "mismatches=%d exit_code=%d",
            report.canonical_matches,
            report.canonical_mismatches,
            report.exit_code,
        )
        return report
    finally:
        if not keep_temp:
            shutil.rmtree(work_root, ignore_errors=True)


def _compare_dbf_canonical(
    source_dbf: Path,
    recovered_dbf: Path,
    work_root: Path,
    relative_path: str,
) -> tuple[bool, dict[str, Any]]:
    comparison_root = work_root / "compare" / _job_key(relative_path)
    source_out = comparison_root / "source"
    recovered_out = comparison_root / "recovered"
    for directory in (source_out, recovered_out):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True, exist_ok=True)

    export_dbf(
        source_dbf,
        source_out,
        formats=("jsonl",),
        memo="inline",
        deleted="include",
        overwrite=True,
        validate=False,
    )
    export_dbf(
        recovered_dbf,
        recovered_out,
        formats=("jsonl",),
        memo="inline",
        deleted="include",
        overwrite=True,
        validate=False,
    )

    source_records = [
        record
        for record in _read_jsonl(source_out / f"{source_dbf.stem}.jsonl")
        if record.get("type") not in ("summary", "table")
    ]
    recovered_records = [
        record
        for record in _read_jsonl(recovered_out / f"{recovered_dbf.stem}.jsonl")
        if record.get("type") not in ("summary", "table")
    ]

    data_keys: set[str] = set()
    for record in source_records + recovered_records:
        data_keys.update(
            key
            for key in record
            if not key.startswith("__dbfbridge_") and key != "__deleted__"
        )

    differences: list[dict[str, Any]] = []
    for index in range(max(len(source_records), len(recovered_records))):
        if index >= len(source_records):
            differences.append(
                {
                    "record": index + 1,
                    "scope": "missing_in_source",
                    "expected": "missing",
                    "actual": "present",
                }
            )
            continue
        if index >= len(recovered_records):
            differences.append(
                {
                    "record": index + 1,
                    "scope": "missing_in_recovered",
                    "expected": "present",
                    "actual": "missing",
                }
            )
            continue

        expected = source_records[index]
        actual = recovered_records[index]
        if expected.get("__deleted__", False) != actual.get("__deleted__", False):
            differences.append(
                {
                    "record": index + 1,
                    "field": "__deleted__",
                    "expected": expected.get("__deleted__"),
                    "actual": actual.get("__deleted__"),
                }
            )
        for key in sorted(data_keys):
            if expected.get(key) != actual.get(key):
                differences.append(
                    {
                        "record": index + 1,
                        "field": key,
                        "expected": expected.get(key),
                        "actual": actual.get(key),
                    }
                )
                if len(differences) >= 20:
                    break
        if len(differences) >= 20:
            break

    matches = not differences and len(source_records) == len(recovered_records)
    return matches, {
        "record_count": len(source_records),
        "recovered_count": len(recovered_records),
        "summary": (
            f"{len(source_records)} vs {len(recovered_records)} rekordów, "
            f"{len(differences)} różnic"
        ),
        "differences": differences,
    }
