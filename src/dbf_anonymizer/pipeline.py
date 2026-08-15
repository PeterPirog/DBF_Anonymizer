"""Transakcyjny, równoległy pipeline katalogów DBF.

Koordynacja procesów i publikacji jest oddzielona od strumieniowego JSONL,
SQLite, kontroli odwracalności oraz automatyzacji Visual FoxPro.
"""
from __future__ import annotations

import hashlib
import fnmatch
import logging
import os
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .anonymizer import AnonymizeOptions
from .atomicfs import DirectoryTransaction
from .global_store import GlobalDictionaryStore, global_dictionary_path
from .manifest import sha256_file, write_manifest
from .schema import load_schema
from .tableio import scan_table_into_store
from .verification import compare_dbf_canonical, verify_vfp_roundtrip
from .vfp import (
    STRUCTURAL_CDX_FLAG,
    companion_cdx,
    dbf_has_structural_index,
    dbf_table_flags,
    rebuild_companion_cdx,
    validate_vfp_executable,
)
from .worker_tasks import (
    PreparedTable as _PreparedTable,
    anonymize_prepared_worker as _anonymize_prepared_worker,
    numeric_width_context as _numeric_width_context,
    prepare_export_worker as _prepare_export_worker,
    publish_reconstructed_table as _publish_reconstructed_table,
    recover_one_table_worker as _recover_one_table_worker,
)

logger = logging.getLogger(__name__)


@dataclass
class TableOutcome:
    table: str
    relative_path: str
    status: str = "OK"
    records: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class AnonymizeResult:
    source: Path
    output: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    global_error_code: str | None = None
    global_error: str | None = None
    exit_code: int = 0

    @property
    def ok(self) -> int:
        return sum(table.status == "OK" for table in self.tables)

    @property
    def failed(self) -> int:
        return sum(table.status == "FAILED" for table in self.tables)

    def raise_for_errors(self) -> None:
        if self.failed:
            raise RuntimeError(f"Anonimizacja nie powiodła się dla {self.failed} tabel.")


@dataclass
class RecoveryResult:
    source: Path
    output: Path
    dictionary_dir: Path
    tables: list[TableOutcome] = field(default_factory=list)
    exit_code: int = 0

    @property
    def ok(self) -> int:
        return sum(table.status == "OK" for table in self.tables)

    @property
    def failed(self) -> int:
        return sum(table.status == "FAILED" for table in self.tables)

    def raise_for_errors(self) -> None:
        if self.failed:
            raise RuntimeError(f"Recovery nie powiodło się dla {self.failed} tabel.")


@dataclass
class SelfTestReport:
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


_VFP_PROJECT_SUFFIXES = {
    ".scx", ".sct", ".frx", ".frt", ".lbx", ".lbt", ".mnx", ".mnt",
    ".pjx", ".pjt", ".vcx", ".vct", ".dbc", ".dct", ".dcx", ".prg",
}

DEFAULT_EXCLUDED_DBF_PATTERNS = ("foxuser.dbf", "**/foxuser.dbf")


def _iter_dbf_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not path.is_file() or path.suffix.casefold() != ".dbf":
            continue
        stem = path.stem.casefold()
        if any(
            candidate.is_file()
            for candidate in path.parent.iterdir()
            if candidate.stem.casefold() == stem
            and candidate.suffix.casefold() in _VFP_PROJECT_SUFFIXES
        ):
            continue
        found.append(path)
    return found


def _matches_exclusion(relative_path: str, pattern: str) -> bool:
    relative = relative_path.replace("\\", "/").casefold()
    normalized = pattern.strip().replace("\\", "/").casefold()
    if not normalized:
        return False
    candidates = {normalized}
    if normalized.startswith("**/"):
        candidates.add(normalized[3:])
    return any(
        fnmatch.fnmatchcase(relative, candidate)
        or fnmatch.fnmatchcase(Path(relative).name, candidate)
        for candidate in candidates
    )


def _resolve_exclusion_patterns(
    exclude_patterns: tuple[str, ...] | list[str] | None,
    *,
    include_system_files: bool,
) -> tuple[str, ...]:
    patterns = [] if include_system_files else list(DEFAULT_EXCLUDED_DBF_PATTERNS)
    patterns.extend(exclude_patterns or ())
    return tuple(dict.fromkeys(pattern.strip() for pattern in patterns if pattern.strip()))


def _discover_dbf_files(
    root: Path,
    exclude_patterns: tuple[str, ...],
) -> tuple[list[Path], list[tuple[Path, str]]]:
    included: list[Path] = []
    excluded: list[tuple[Path, str]] = []
    for path in _iter_dbf_files(root):
        relative = _relative_to(path, root).as_posix()
        matched = next(
            (pattern for pattern in exclude_patterns if _matches_exclusion(relative, pattern)),
            None,
        )
        if matched is None:
            included.append(path)
        else:
            excluded.append((path, matched))
            logger.warning(
                "phase=discovery event=file_excluded path=%s pattern=%s",
                relative,
                matched,
            )
    return included, excluded


def _relative_to(path: Path, root: Path) -> Path:
    return path.resolve().relative_to(root.resolve())


def _default_output_dir(source: Path, suffix: str) -> Path:
    return source.parent / f"{source.name}{suffix}"


def _default_dictionary_dir(source: Path, output: Path) -> Path:
    """Zwraca katalog słownika obok faktycznego katalogu wynikowego."""
    return output.parent / f"{source.name}_dict"


def _job_key(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:20]
    return f"job_{digest}"


def _resolve_workers(workers: int | None, task_count: int) -> int:
    if workers is not None and workers < 0:
        raise ValueError("workers musi być >= 0 (0/None = automatycznie)")
    requested = workers or (os.cpu_count() or 1)
    return max(1, min(requested, max(1, task_count)))


def _validate_batch_size(batch_size: int) -> int:
    if batch_size <= 0:
        raise ValueError("batch_size musi być dodatni")
    return batch_size


def _validate_generated_path(source: Path, generated: Path, label: str) -> None:
    if generated == source or generated in source.parents:
        raise ValueError(
            f"{label} nie może być katalogiem źródłowym ani jego nadrzędnym: {generated}"
        )


def _failed_outcome(
    source: str | Path,
    relative_path: str,
    exc: BaseException,
) -> TableOutcome:
    return TableOutcome(
        table=Path(source).name,
        relative_path=relative_path,
        status="FAILED",
        errors=[
            f"[{_exception_code(exc)}] "
            f"path={relative_path} error_type={type(exc).__name__} error={exc}"
        ],
    )


def _blocked_outcome(prepared: _PreparedTable, exc: BaseException) -> TableOutcome:
    outcome = _failed_outcome(prepared.source, prepared.relative_path, exc)
    outcome.records = prepared.records
    return outcome


def _diagnostic_code(message: str, fallback: str) -> str:
    """Wyciąga stabilny kod ``[CODE]`` bez modyfikowania treści diagnostyki."""
    if message.startswith("[") and "]" in message:
        candidate = message[1:message.index("]")]
        if candidate and all(
            character.isupper() or character.isdigit() or character == "_"
            for character in candidate
        ):
            return candidate
    return fallback


def _exception_code(exc: BaseException) -> str:
    """Zwraca stabilny kod klasy albo prefiks ``[CODE]`` z komunikatu."""

    explicit = getattr(exc, "code", None)
    if explicit:
        return str(explicit)
    return _diagnostic_code(str(exc), type(exc).__name__)


def _log_returned_failure(phase: str, outcome: TableOutcome) -> None:
    """Loguje błędy zwrócone w ``TableOutcome`` przez proces roboczy.

    Wyjątki podniesione przez worker są logowane w gałęzi ``except``. Ta funkcja
    obsługuje odmienny przypadek: biblioteka rekonstrukcji zwróciła wynik
    ``FAILED`` zamiast podnieść wyjątek.
    """
    if outcome.status != "FAILED":
        return
    if not outcome.errors:
        outcome.errors.append(
            f"[WORKER_FAILED_WITHOUT_DETAILS] path={outcome.relative_path}"
        )
    error_count = len(outcome.errors)
    for error_index, error in enumerate(outcome.errors, start=1):
        logger.error(
            "phase=%s event=file_failed path=%s table=%s error_index=%d "
            "error_count=%d error_code=%s error=%r",
            phase,
            outcome.relative_path,
            outcome.table,
            error_index,
            error_count,
            _diagnostic_code(error, "WORKER_RETURNED_FAILED"),
            error,
        )


def _log_final_warnings(phase: str, outcomes: list[TableOutcome]) -> None:
    """Loguje wyłącznie ostrzeżenia, które pozostały po całej fazie/CDX."""

    for outcome in outcomes:
        warning_count = len(outcome.warnings)
        for warning_index, warning in enumerate(outcome.warnings, start=1):
            logger.warning(
                "phase=%s event=file_warning path=%s table=%s warning_index=%d "
                "warning_count=%d warning_code=%s warning=%r",
                phase,
                outcome.relative_path,
                outcome.table,
                warning_index,
                warning_count,
                _diagnostic_code(warning, "WORKER_RETURNED_WARNING"),
                warning,
            )


def _log_publication_blocked(
    operation: str,
    outcomes: list[TableOutcome],
    *,
    output: Path,
    dictionary_dir: Path | None = None,
) -> None:
    failed_paths = "|".join(
        item.relative_path
        for item in sorted(outcomes, key=lambda value: value.relative_path.casefold())
        if item.status == "FAILED"
    )
    logger.error(
        "phase=pipeline event=publication_blocked operation=%s failed=%d "
        "failed_paths=%s output=%s dictionary_dir=%s",
        operation,
        sum(item.status == "FAILED" for item in outcomes),
        failed_paths,
        output,
        dictionary_dir if dictionary_dir is not None else "-",
    )


def _set_exit_code(outcomes: list[TableOutcome]) -> int:
    if any(item.status == "FAILED" for item in outcomes):
        return 1
    if any(item.status == "WARNING" for item in outcomes):
        return 2
    return 0


def _preflight_source_cdx(
    dbf_files: list[Path],
    source_root: Path,
    *,
    vfp_executable: str | Path | None,
) -> list[TableOutcome]:
    """Wykrywa brak strukturalnego CDX przed kosztownymi etapami pipeline."""

    cdx_tables = [path for path in dbf_files if companion_cdx(path) is not None]
    if cdx_tables and vfp_executable is not None:
        executable = validate_vfp_executable(vfp_executable)
        logger.info(
            "phase=cdx event=vfp_executable_validated path=%s tables_with_cdx=%d",
            executable,
            len(cdx_tables),
        )

    failures: list[TableOutcome] = []
    for source_dbf in dbf_files:
        relative_path = _relative_to(source_dbf, source_root).as_posix()
        try:
            has_structural_cdx = dbf_has_structural_index(source_dbf)
        except Exception as exc:
            code = _diagnostic_code(str(exc), "CDX_PREFLIGHT_READ_FAILED")
            error = (
                f"[{code}] path={relative_path} phase=cdx_preflight "
                f"error_type={type(exc).__name__} detail={exc}"
            )
            failures.append(TableOutcome(
                table=source_dbf.name,
                relative_path=relative_path,
                status="FAILED",
                errors=[error],
            ))
            logger.exception(
                "phase=cdx event=preflight_failed path=%s error_code=%s error=%r",
                relative_path,
                code,
                error,
            )
            continue
        if not has_structural_cdx or companion_cdx(source_dbf):
            continue
        error = (
            f"[SOURCE_CDX_MISSING] path={relative_path} DBF ma flagę indeksu "
            "strukturalnego, ale brak pliku CDX o tym samym rdzeniu"
        )
        outcome = TableOutcome(
            table=source_dbf.name,
            relative_path=relative_path,
            status="FAILED",
            errors=[error],
        )
        failures.append(outcome)
        logger.error(
            "phase=cdx event=preflight_failed path=%s "
            "error_code=SOURCE_CDX_MISSING error=%r",
            relative_path,
            error,
        )
    logger.info(
        "phase=cdx event=preflight_done checked=%d with_cdx=%d missing=%d",
        len(dbf_files),
        len(cdx_tables),
        sum(
            _diagnostic_code(item.errors[0], "") == "SOURCE_CDX_MISSING"
            for item in failures
        ),
    )
    return failures


def apply_reconstruct_result(
    outcome: TableOutcome,
    result: Any,
    *,
    source_has_structural_cdx: bool | None = None,
) -> None:
    ignored_false_cdx_warning = False
    for item in result.results:
        if item.status == "FAILED":
            outcome.status = "FAILED"
            outcome.errors.extend(
                f"[DBFBRIDGE_RECONSTRUCTION_FAILED] source={item.source} error={error}"
                for error in (item.errors or ["unknown reconstruction failure"])
            )
            for difference in (getattr(item, "differences", None) or [])[:20]:
                outcome.errors.append(_safe_difference(difference))
        for warning in item.warnings or []:
            if warning.startswith((
                "Raw DBF SHA-256 differs",
                "Raw FPT SHA-256 differs",
            )):
                continue
            if (
                source_has_structural_cdx is False
                and _is_dbfbridge_cdx_warning(warning)
            ):
                ignored_false_cdx_warning = True
                continue
            outcome.warnings.append(warning)
    if ignored_false_cdx_warning:
        logger.info(
            "phase=reconstruct event=false_cdx_warning_ignored path=%s "
            "reason=table_flags_without_0x01",
            outcome.relative_path,
        )
    if outcome.status != "FAILED" and outcome.warnings:
        outcome.status = "WARNING"


def _is_dbfbridge_cdx_warning(warning: str) -> bool:
    return (
        "structural CDX index" in warning
        or "companion CDX file" in warning
    )


def _safe_difference(difference: dict[str, Any]) -> str:
    """Renderuje diagnostykę dbfbridge bez pola ``preview`` z danymi."""

    parts = [
        "[DBFBRIDGE_CANONICAL_DIFFERENCE]",
        f"scope={difference.get('scope', 'unknown')}",
        f"record={difference.get('record', 'unknown')}",
    ]
    if difference.get("field") is not None:
        parts.append(f"field={difference['field']}")
    for side in ("expected", "actual"):
        value = difference.get(side)
        if isinstance(value, dict):
            parts.extend(
                f"{side}_{key}={value.get(key)!r}"
                for key in ("type", "length", "sha256")
                if key in value
            )
        elif value is not None:
            # Statusy/boolean nie są danymi pól; wartości pól z dbfbridge są dict.
            parts.append(f"{side}={value!r}")
    return " ".join(parts)


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
    logger.info("phase=export event=start files=%d workers=%d", len(jobs), max_workers)
    prepared: list[_PreparedTable] = []
    failed: list[TableOutcome] = []
    if max_workers == 1:
        for job in jobs:
            try:
                prepared.append(_prepare_export_worker(*job))
            except Exception as exc:
                logger.exception(
                    "phase=export event=file_failed path=%s error_type=%s error=%s",
                    job[1], type(exc).__name__, exc,
                )
                failed.append(_failed_outcome(job[0], job[1], exc))
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_prepare_export_worker, *job): job for job in jobs}
            for future in as_completed(futures):
                job = futures[future]
                try:
                    prepared.append(future.result())
                except Exception as exc:
                    logger.exception(
                        "phase=export event=file_failed path=%s error_type=%s error=%s",
                        job[1], type(exc).__name__, exc,
                    )
                    failed.append(_failed_outcome(job[0], job[1], exc))
    prepared.sort(key=lambda item: item.relative_path.casefold())
    logger.info(
        "phase=export event=done successful=%d failed=%d",
        len(prepared), len(failed),
    )
    return prepared, failed


def _parallel_prepared(
    prepared: list[_PreparedTable],
    *,
    output: Path,
    dictionary_dir: Path,
    options: AnonymizeOptions,
    batch_size: int,
    workers: int | None,
) -> list[TableOutcome]:
    max_workers = _resolve_workers(workers, len(prepared))
    logger.info(
        "phase=anonymize event=start files=%d workers=%d batch_size=%d",
        len(prepared), max_workers, batch_size,
    )
    outcomes: list[TableOutcome] = []
    if max_workers == 1:
        for item in prepared:
            try:
                outcome = _anonymize_prepared_worker(
                    item, str(output), str(dictionary_dir), options, batch_size
                )
                _log_returned_failure("anonymize", outcome)
                outcomes.append(outcome)
            except Exception as exc:
                logger.exception(
                    "phase=anonymize event=file_failed path=%s error_type=%s error=%s",
                    item.relative_path, type(exc).__name__, exc,
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
                    batch_size,
                ): item
                for item in prepared
            }
            for future in as_completed(futures):
                item = futures[future]
                try:
                    outcome = future.result()
                    _log_returned_failure("anonymize", outcome)
                    outcomes.append(outcome)
                except Exception as exc:
                    logger.exception(
                        "phase=anonymize event=file_failed path=%s error_type=%s error=%s",
                        item.relative_path, type(exc).__name__, exc,
                    )
                    outcomes.append(_failed_outcome(item.source, item.relative_path, exc))
    logger.info(
        "phase=anonymize event=done successful=%d failed=%d",
        sum(item.status != "FAILED" for item in outcomes),
        sum(item.status == "FAILED" for item in outcomes),
    )
    return outcomes


def _parallel_recovery(
    dbf_files: list[Path],
    *,
    source: Path,
    temp_root: Path,
    output: Path,
    dictionary_dir: Path,
    batch_size: int,
    workers: int | None,
) -> list[TableOutcome]:
    jobs = [
        (
            str(path),
            _relative_to(path, source).as_posix(),
            str(temp_root),
            str(output),
            str(dictionary_dir),
            batch_size,
        )
        for path in dbf_files
    ]
    max_workers = _resolve_workers(workers, len(jobs))
    logger.info(
        "phase=recovery event=start files=%d workers=%d batch_size=%d",
        len(jobs), max_workers, batch_size,
    )
    outcomes: list[TableOutcome] = []
    if max_workers == 1:
        for job in jobs:
            try:
                outcome = _recover_one_table_worker(*job)
                _log_returned_failure("recovery", outcome)
                outcomes.append(outcome)
            except Exception as exc:
                logger.exception(
                    "phase=recovery event=file_failed path=%s error_type=%s error=%s",
                    job[1], type(exc).__name__, exc,
                )
                outcomes.append(_failed_outcome(job[0], job[1], exc))
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_recover_one_table_worker, *job): job for job in jobs}
            for future in as_completed(futures):
                job = futures[future]
                try:
                    outcome = future.result()
                    _log_returned_failure("recovery", outcome)
                    outcomes.append(outcome)
                except Exception as exc:
                    logger.exception(
                        "phase=recovery event=file_failed path=%s error_type=%s error=%s",
                        job[1], type(exc).__name__, exc,
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
    previous_dictionary: Path | None,
    reuse_dictionary: bool,
    batch_size: int,
) -> Path:
    """Buduje słownik w stagingu, zachowując poprzednie mapowania na żądanie."""
    final_path = global_dictionary_path(dictionary_dir)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = final_path.with_name(f".{final_path.name}.build-{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    ordered = sorted(prepared, key=lambda table: table.relative_path.casefold())
    schemas = {item.relative_path: load_schema(Path(item.schema_path)) for item in ordered}
    encodings = sorted({schema.encoding for schema in schemas.values()})
    try:
        has_previous = bool(
            reuse_dictionary and previous_dictionary and previous_dictionary.is_file()
        )
        if has_previous:
            shutil.copy2(previous_dictionary, temporary)
        with GlobalDictionaryStore(temporary) as store:
            settings = {
                "memo_mode": options.memo_mode,
                "date_offset_days": options.date_offset_days,
                "text_mode": options.text_mode,
            }
            if has_previous:
                store.prepare_incremental(
                    options=settings,
                    salt=options.salt,
                    text_encodings=encodings,
                )
                logger.info(
                    "phase=dictionary event=incremental_map_reused source=%s",
                    previous_dictionary,
                )
            else:
                store.initialize(
                    options=settings,
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
                store.register_file(item.relative_path, Path(item.source).name)
                record_count, value_count = scan_table_into_store(
                    store,
                    jsonl_path=item.jsonl_path,
                    schema=schema,
                    relative_path=item.relative_path,
                    memo_mode=options.memo_mode,
                    batch_size=batch_size,
                )
                if record_count != item.records:
                    raise RuntimeError(
                        f"[DICTIONARY_RECORD_COUNT_MISMATCH] path={item.relative_path} "
                        f"expected={item.records} actual={record_count}"
                    )
                store.commit()
                logger.info(
                    "phase=dictionary event=table_scanned current=%d total=%d "
                    "path=%s records=%d batched_field_values=%d encoding=%s",
                    index, len(ordered), item.relative_path, record_count,
                    value_count, schema.encoding,
                )
            store.assign_anonymous_values(salt=options.salt)
        os.replace(temporary, final_path)
        return final_path
    except Exception as exc:
        logger.exception(
            "phase=dictionary event=failed error_code=%s error=%s",
            _exception_code(exc), exc,
        )
        temporary.unlink(missing_ok=True)
        Path(f"{temporary}-journal").unlink(missing_ok=True)
        raise


def _rebuild_cdx(
    *,
    source_root: Path,
    source_dbf_files: list[Path],
    output_root: Path,
    outcomes: list[TableOutcome],
    vfp_progid: str,
) -> None:
    """Kopiuje definicje CDX i obowiązkowo wykonuje REINDEX w VFP."""
    by_path = {outcome.relative_path: outcome for outcome in outcomes}
    for source_dbf in source_dbf_files:
        relative_path = _relative_to(source_dbf, source_root).as_posix()
        outcome = by_path.get(relative_path)
        if outcome is None or outcome.status == "FAILED":
            continue
        source_cdx = companion_cdx(source_dbf)
        if source_cdx is None:
            try:
                flags = dbf_table_flags(source_dbf)
            except Exception as exc:
                code = _diagnostic_code(str(exc), "CDX_SOURCE_HEADER_READ_FAILED")
                outcome.status = "FAILED"
                outcome.errors.append(
                    f"[{code}] path={relative_path} phase=cdx_rebuild "
                    f"error_type={type(exc).__name__} detail={exc}"
                )
                logger.exception(
                    "phase=cdx event=source_header_read_failed path=%s "
                    "error_code=%s error_type=%s error=%s",
                    relative_path, code, type(exc).__name__, exc,
                )
                continue
            if flags & STRUCTURAL_CDX_FLAG:
                outcome.status = "FAILED"
                outcome.errors.append(
                    f"[SOURCE_CDX_MISSING] path={relative_path} "
                    "DBF ma flagę indeksu strukturalnego, ale brak pliku o tym samym rdzeniu"
                )
                logger.error(
                    "phase=cdx event=source_missing path=%s error_code=SOURCE_CDX_MISSING",
                    relative_path,
                )
            else:
                outcome.warnings = [
                    warning
                    for warning in outcome.warnings
                    if not _is_dbfbridge_cdx_warning(warning)
                ]
                if outcome.status == "WARNING" and not outcome.warnings:
                    outcome.status = "OK"
            continue
        target_dbf = output_root / Path(relative_path)
        logger.info(
            "phase=cdx event=reindex_start path=%s source_cdx=%s progid=%s",
            relative_path, source_cdx, vfp_progid,
        )
        try:
            verification = rebuild_companion_cdx(
                source_dbf,
                target_dbf,
                progid=vfp_progid,
            )
            assert verification is not None
            logger.info(
                "phase=cdx event=reindex_done path=%s records=%d tags=%d tag_names=%s",
                relative_path, verification.records, verification.tag_count,
                ",".join(verification.tags),
            )
            outcome.warnings = [
                warning
                for warning in outcome.warnings
                if "structural CDX index" not in warning
                and "companion CDX file" not in warning
            ]
            if outcome.status == "WARNING" and not outcome.warnings:
                outcome.status = "OK"
        except Exception as exc:
            outcome.status = "FAILED"
            outcome.errors.append(
                f"[CDX_REINDEX_FAILED] path={relative_path} "
                f"source_cdx={source_cdx} error_type={type(exc).__name__} error={exc}"
            )
            logger.exception(
                "phase=cdx event=reindex_failed path=%s source_cdx=%s "
                "error_type=%s error=%s",
                relative_path, source_cdx, type(exc).__name__, exc,
            )


def _manifest_tables(outcomes: list[TableOutcome]) -> list[dict[str, Any]]:
    return [
        {"path": item.relative_path, "records": item.records, "status": item.status}
        for item in sorted(outcomes, key=lambda value: value.relative_path.casefold())
    ]


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
    workers: int | None = 0,
    batch_size: int = 5000,
    reuse_dictionary: bool = True,
    vfp_progid: str = "VisualFoxPro.Application",
    vfp_executable: str | Path | None = None,
    exclude_patterns: tuple[str, ...] | list[str] | None = None,
    include_system_files: bool = False,
) -> AnonymizeResult:
    """Anonimizuje bazę i publikuje wynik oraz słownik po pełnym sukcesie."""
    source = Path(source_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog źródłowy nie istnieje: {source}")
    _resolve_workers(workers, 1)
    _validate_batch_size(batch_size)
    output = (
        Path(output_dir).resolve()
        if output_dir else _default_output_dir(source, "_anonymized")
    )
    dict_dir = (
        Path(dictionary_dir).resolve()
        if dictionary_dir else _default_dictionary_dir(source, output)
    )
    _validate_generated_path(source, output, "Katalog wyjściowy")
    _validate_generated_path(source, dict_dir, "Katalog słowników")
    if output == dict_dir:
        raise ValueError("Katalog wyjściowy i katalog słowników muszą być różne")
    if not overwrite and (output.exists() or dict_dir.exists()):
        raise FileExistsError("Katalog wyniku lub słownika już istnieje")

    temp_root = source.parent / "var" / f"{source.name}_anon_temp_{os.getpid()}"
    shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.mkdir(parents=True, exist_ok=True)
    transaction = DirectoryTransaction(output, dict_dir)
    transaction.prepare()
    output_stage = transaction.stage_for(output)
    dict_stage = transaction.stage_for(dict_dir)
    previous_dictionary = global_dictionary_path(dict_dir)
    result = AnonymizeResult(source=source, output=output, dictionary_dir=dict_dir)
    committed = False
    try:
        resolved_exclusions = _resolve_exclusion_patterns(
            exclude_patterns,
            include_system_files=include_system_files,
        )
        dbf_files, excluded_files = _discover_dbf_files(source, resolved_exclusions)
        logger.info(
            "phase=pipeline event=start operation=anonymize source=%s output=%s "
            "dictionary_dir=%s dbf_files=%d requested_workers=%s batch_size=%d "
            "reuse_dictionary=%s excluded_files=%d",
            source, output, dict_dir, len(dbf_files), workers or "auto",
            batch_size, reuse_dictionary, len(excluded_files),
        )
        if not dbf_files:
            result.tables = [TableOutcome(
                table="-", relative_path="-", status="WARNING",
                warnings=["Brak plików DBF z danymi w katalogu źródłowym."],
            )]
            result.exit_code = 2
            return result

        try:
            cdx_failures = _preflight_source_cdx(
                dbf_files,
                source,
                vfp_executable=vfp_executable,
            )
        except Exception as exc:
            cdx_failures = [
                _failed_outcome(path, _relative_to(path, source).as_posix(), exc)
                for path in dbf_files
                if companion_cdx(path) is not None
            ]
            result.global_error_code = _exception_code(exc)
            result.global_error = str(exc)
        if cdx_failures:
            if result.global_error is None:
                failure_codes = {
                    _diagnostic_code(error, "CDX_PREFLIGHT_FAILED")
                    for item in cdx_failures
                    for error in item.errors
                }
                if failure_codes == {"SOURCE_CDX_MISSING"}:
                    result.global_error_code = "SOURCE_CDX_MISSING"
                    result.global_error = (
                        "[SOURCE_CDX_MISSING] Wymagane pliki CDX nie istnieją; "
                        "anonimizacja została przerwana przed eksportem"
                    )
                else:
                    result.global_error_code = "CDX_PREFLIGHT_FAILED"
                    result.global_error = (
                        "[CDX_PREFLIGHT_FAILED] Nie udało się bezpiecznie "
                        "sprawdzić flag/CDX wszystkich tabel; codes="
                        + ",".join(sorted(failure_codes))
                    )
            result.tables = sorted(
                cdx_failures,
                key=lambda item: item.relative_path.casefold(),
            )
            result.exit_code = 1
            _log_publication_blocked(
                "anonymize",
                result.tables,
                output=output,
                dictionary_dir=dict_dir,
            )
            return result

        options = AnonymizeOptions(
            memo_mode=memo_mode,
            date_offset_days=date_offset_days,
            salt=salt,
        )
        prepared, export_failures = _prepare_exports(dbf_files, source, temp_root, workers)
        if export_failures:
            blocked = RuntimeError(
                "[INCOMPLETE_EXPORT] Nie udało się wyeksportować wszystkich tabel"
            )
            result.global_error_code = "INCOMPLETE_EXPORT"
            result.global_error = str(blocked)
            result.tables = sorted(
                [*export_failures, *(_blocked_outcome(item, blocked) for item in prepared)],
                key=lambda item: item.relative_path.casefold(),
            )
            result.exit_code = 1
            _log_publication_blocked(
                "anonymize",
                result.tables,
                output=output,
                dictionary_dir=dict_dir,
            )
            return result

        try:
            dictionary_path = _build_global_dictionary(
                prepared,
                dict_stage,
                options,
                previous_dictionary=(
                    previous_dictionary if previous_dictionary.is_file() else None
                ),
                reuse_dictionary=reuse_dictionary,
                batch_size=batch_size,
            )
        except Exception as exc:
            result.global_error_code = _exception_code(exc)
            result.global_error = str(exc)
            result.tables = [_blocked_outcome(item, exc) for item in prepared]
            result.exit_code = 1
            _log_publication_blocked(
                "anonymize",
                result.tables,
                output=output,
                dictionary_dir=dict_dir,
            )
            return result

        result.tables = sorted(
            _parallel_prepared(
                prepared,
                output=output_stage,
                dictionary_dir=dict_stage,
                options=options,
                batch_size=batch_size,
                workers=workers,
            ),
            key=lambda item: item.relative_path.casefold(),
        )
        if not any(item.status == "FAILED" for item in result.tables):
            _rebuild_cdx(
                source_root=source,
                source_dbf_files=dbf_files,
                output_root=output_stage,
                outcomes=result.tables,
                vfp_progid=vfp_progid,
            )
        _log_final_warnings("anonymize", result.tables)
        result.exit_code = _set_exit_code(result.tables)
        if result.exit_code == 1:
            _log_publication_blocked(
                "anonymize",
                result.tables,
                output=output,
                dictionary_dir=dict_dir,
            )
            return result

        write_manifest(
            output_stage,
            operation="anonymize",
            source=source,
            tables=_manifest_tables(result.tables),
            dictionary_sha256=sha256_file(dictionary_path),
            excluded_tables=[
                {
                    "path": _relative_to(path, source).as_posix(),
                    "pattern": pattern,
                }
                for path, pattern in excluded_files
            ],
        )
        try:
            dictionary_path.chmod(0o600)
        except OSError:
            logger.warning("phase=dictionary event=chmod_failed path=%s", dictionary_path)
        transaction.commit(overwrite=overwrite)
        committed = True
        logger.info(
            "phase=pipeline event=published operation=anonymize output=%s dictionary=%s",
            output, dict_dir,
        )
        return result
    finally:
        if not committed:
            transaction.abort()
        if not keep_temp:
            shutil.rmtree(temp_root, ignore_errors=True)


def make_dbf_recovery(
    anonymized_dir: str | Path,
    dictionary_dir: str | Path,
    *,
    output_dir: str | Path | None = None,
    overwrite: bool = True,
    keep_temp: bool = False,
    workers: int | None = 0,
    batch_size: int = 5000,
    vfp_progid: str = "VisualFoxPro.Application",
    vfp_executable: str | Path | None = None,
    exclude_patterns: tuple[str, ...] | list[str] | None = None,
    include_system_files: bool = False,
) -> RecoveryResult:
    """Odtwarza wszystkie DBF i publikuje katalog po pełnym sukcesie."""
    source = Path(anonymized_dir).resolve()
    dict_dir = Path(dictionary_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog zaanonimizowany nie istnieje: {source}")
    if not dict_dir.is_dir():
        raise FileNotFoundError(f"Katalog słowników nie istnieje: {dict_dir}")
    _resolve_workers(workers, 1)
    _validate_batch_size(batch_size)
    output = (
        Path(output_dir).resolve()
        if output_dir else _default_output_dir(source, "_recovered")
    )
    _validate_generated_path(source, output, "Katalog wyjściowy")
    if not overwrite and output.exists():
        raise FileExistsError(f"Katalog wynikowy już istnieje: {output}")

    temp_root = source.parent / "var" / f"{source.name}_recover_temp_{os.getpid()}"
    shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.mkdir(parents=True, exist_ok=True)
    transaction = DirectoryTransaction(output)
    transaction.prepare()
    output_stage = transaction.stage_for(output)
    result = RecoveryResult(source=source, output=output, dictionary_dir=dict_dir)
    committed = False
    try:
        resolved_exclusions = _resolve_exclusion_patterns(
            exclude_patterns,
            include_system_files=include_system_files,
        )
        dbf_files, excluded_files = _discover_dbf_files(source, resolved_exclusions)
        logger.info(
            "phase=pipeline event=start operation=recovery source=%s output=%s "
            "dictionary_dir=%s dbf_files=%d requested_workers=%s batch_size=%d "
            "excluded_files=%d",
            source, output, dict_dir, len(dbf_files), workers or "auto", batch_size,
            len(excluded_files),
        )
        if not dbf_files:
            return result
        try:
            cdx_failures = _preflight_source_cdx(
                dbf_files,
                source,
                vfp_executable=vfp_executable,
            )
        except Exception as exc:
            cdx_failures = [
                _failed_outcome(path, _relative_to(path, source).as_posix(), exc)
                for path in dbf_files
                if companion_cdx(path) is not None
            ]
        if cdx_failures:
            result.tables = sorted(
                cdx_failures,
                key=lambda item: item.relative_path.casefold(),
            )
            result.exit_code = 1
            _log_publication_blocked(
                "recovery",
                result.tables,
                output=output,
                dictionary_dir=dict_dir,
            )
            return result
        result.tables = sorted(
            _parallel_recovery(
                dbf_files,
                source=source,
                temp_root=temp_root,
                output=output_stage,
                dictionary_dir=dict_dir,
                batch_size=batch_size,
                workers=workers,
            ),
            key=lambda item: item.relative_path.casefold(),
        )
        if not any(item.status == "FAILED" for item in result.tables):
            _rebuild_cdx(
                source_root=source,
                source_dbf_files=dbf_files,
                output_root=output_stage,
                outcomes=result.tables,
                vfp_progid=vfp_progid,
            )
        _log_final_warnings("recovery", result.tables)
        result.exit_code = _set_exit_code(result.tables)
        if result.exit_code == 1:
            _log_publication_blocked(
                "recovery",
                result.tables,
                output=output,
                dictionary_dir=dict_dir,
            )
            return result
        dictionary_file = global_dictionary_path(dict_dir)
        write_manifest(
            output_stage,
            operation="recover",
            source=source,
            tables=_manifest_tables(result.tables),
            dictionary_sha256=(
                sha256_file(dictionary_file) if dictionary_file.is_file() else None
            ),
            excluded_tables=[
                {
                    "path": _relative_to(path, source).as_posix(),
                    "pattern": pattern,
                }
                for path, pattern in excluded_files
            ],
        )
        transaction.commit(overwrite=overwrite)
        committed = True
        logger.info("phase=pipeline event=published operation=recovery output=%s", output)
        return result
    finally:
        if not committed:
            transaction.abort()
        if not keep_temp:
            shutil.rmtree(temp_root, ignore_errors=True)


def self_test(
    source_dir: str | Path,
    *,
    memo_mode: str = "mask",
    date_offset_days: int = 0,
    salt: str = "",
    keep_temp: bool = False,
    workers: int | None = 0,
    batch_size: int = 5000,
    vfp_progid: str = "VisualFoxPro.Application",
    vfp_executable: str | Path | None = None,
    exclude_patterns: tuple[str, ...] | list[str] | None = None,
    include_system_files: bool = False,
) -> SelfTestReport:
    """Wykonuje round-trip, porównanie kanoniczne i test VFP/CDX."""
    source = Path(source_dir).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"Katalog źródłowy nie istnieje: {source}")
    _resolve_workers(workers, 1)
    _validate_batch_size(batch_size)
    work_root = source.parent / "var" / f"{source.name}_selftest_{os.getpid()}"
    shutil.rmtree(work_root, ignore_errors=True)
    work_root.mkdir(parents=True, exist_ok=True)
    anonymous_dir = work_root / f"{source.name}_anonymized"
    dict_dir = work_root / f"{source.name}_dict"
    recovered_dir = work_root / f"{source.name}_recovered"

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
        batch_size=batch_size,
        reuse_dictionary=False,
        vfp_progid=vfp_progid,
        vfp_executable=vfp_executable,
        exclude_patterns=exclude_patterns,
        include_system_files=include_system_files,
    )
    anonymous_result.raise_for_errors()
    recovery_result = make_dbf_recovery(
        anonymous_dir,
        dict_dir,
        output_dir=recovered_dir,
        overwrite=True,
        keep_temp=keep_temp,
        workers=workers,
        batch_size=batch_size,
        vfp_progid=vfp_progid,
        vfp_executable=vfp_executable,
        exclude_patterns=exclude_patterns,
        include_system_files=include_system_files,
    )
    recovery_result.raise_for_errors()

    report = SelfTestReport(
        source=source,
        anonymized=anonymous_dir,
        recovered=recovered_dir,
        dictionary_dir=dict_dir,
    )
    try:
        resolved_exclusions = _resolve_exclusion_patterns(
            exclude_patterns,
            include_system_files=include_system_files,
        )
        source_files, _ = _discover_dbf_files(source, resolved_exclusions)
        source_dbfs = {
            _relative_to(path, source).as_posix(): path for path in source_files
        }
        recovered_dbfs = {
            _relative_to(path, recovered_dir).as_posix(): path
            for path in _iter_dbf_files(recovered_dir)
        }
        for relative_path, source_dbf in source_dbfs.items():
            outcome = TableOutcome(table=source_dbf.name, relative_path=relative_path)
            recovered_dbf = recovered_dbfs.get(relative_path)
            anonymous_dbf = anonymous_dir / Path(relative_path)
            if recovered_dbf is None:
                outcome.status = "FAILED"
                outcome.errors.append(f"[RECOVERED_DBF_MISSING] path={relative_path}")
            else:
                try:
                    matches, difference = compare_dbf_canonical(
                        source_dbf,
                        recovered_dbf,
                        work_root,
                        _job_key(relative_path),
                    )
                    outcome.records = difference["record_count"]
                    if not matches:
                        outcome.status = "FAILED"
                        outcome.errors.append(
                            f"[CANONICAL_MISMATCH] {difference['summary']}"
                        )
                        for item in difference.get("differences", [])[:10]:
                            outcome.errors.append(
                                f"record={item['record']} "
                                f"field={item.get('field', item.get('scope', '?'))} "
                                f"expected={item['expected']!r} actual={item['actual']!r}"
                            )
                    if outcome.status != "FAILED" and companion_cdx(source_dbf):
                        vfp_errors = verify_vfp_roundtrip(
                            source_dbf,
                            anonymous_dbf,
                            recovered_dbf,
                            progid=vfp_progid,
                        )
                        if vfp_errors:
                            outcome.status = "FAILED"
                            outcome.errors.extend(vfp_errors)
                except Exception as exc:
                    outcome.status = "FAILED"
                    outcome.errors.append(
                        f"[SELF_TEST_TABLE_FAILED] path={relative_path} "
                        f"error_type={type(exc).__name__} error={exc}"
                    )
            if outcome.status == "FAILED":
                report.canonical_mismatches += 1
            else:
                report.canonical_matches += 1
            report.tables.append(outcome)

        for relative_path, recovered_dbf in recovered_dbfs.items():
            if relative_path not in source_dbfs:
                report.tables.append(TableOutcome(
                    table=recovered_dbf.name,
                    relative_path=relative_path,
                    status="WARNING",
                    warnings=["Dodatkowy DBF w recovered bez źródła"],
                ))
        report.tables.sort(key=lambda item: item.relative_path.casefold())
        report.exit_code = _set_exit_code(report.tables)
        logger.info(
            "phase=pipeline event=done operation=self_test matches=%d "
            "mismatches=%d exit_code=%d",
            report.canonical_matches, report.canonical_mismatches, report.exit_code,
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
    """Kompatybilny wrapper dla wcześniejszych importów/testów."""
    return compare_dbf_canonical(
        source_dbf,
        recovered_dbf,
        work_root,
        _job_key(relative_path),
    )
