"""Izolowane zadania procesów: eksport, transformacja i rekonstrukcja DBF."""
from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable

from dbfbridge import export_dbf, reconstruct_dbf

from .anonymizer import AnonymizeOptions, recover_records
from .dictionary import dictionary_filename, load_dictionary
from .global_store import GlobalDictionaryStore, global_dictionary_path
from .jsonstream import atomic_jsonl_writer, iter_jsonl, write_records
from .rawpatch import restore_identity_field_bytes
from .schema import is_data_record, load_schema
from .tableio import anonymize_jsonl, count_data_records, recover_jsonl


@dataclass(frozen=True)
class PreparedTable:
    source: str
    relative_path: str
    job_root: str
    jsonl_path: str
    schema_path: str
    records: int


def numeric_width_context(
    schema: Any,
    records: Iterable[dict[str, Any]],
) -> str | None:
    record_index = 0
    for record in records:
        if not is_data_record(record):
            continue
        record_index += 1
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


def publish_reconstructed_table(
    staging_output: Path,
    output_parent: Path,
    table_stem: str,
    *,
    overwrite: bool,
) -> None:
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
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.partial")
        temporary.unlink(missing_ok=True)
        try:
            shutil.copy2(source, temporary)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def prepare_export_worker(
    source_path: str,
    relative_path: str,
    temp_root: str,
) -> PreparedTable:
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
        raise FileNotFoundError(
            f"[EXPORT_ARTIFACT_MISSING] JSONL lub schemat: {relative_path}"
        )
    return PreparedTable(
        source=str(source),
        relative_path=relative_path,
        job_root=str(job_root),
        jsonl_path=str(jsonl_path),
        schema_path=str(schema_path),
        records=count_data_records(jsonl_path),
    )


def anonymize_prepared_worker(
    prepared: PreparedTable,
    output_root: str,
    dictionary_dir: str,
    options: AnonymizeOptions,
    batch_size: int,
) -> Any:
    # Import lokalny zapobiega cyklowi modułów; dataclass jest picklowalna.
    from .pipeline import TableOutcome

    outcome = TableOutcome(
        table=Path(prepared.source).name,
        relative_path=prepared.relative_path,
        records=prepared.records,
    )
    schema = load_schema(Path(prepared.schema_path))
    anonymous_dir = Path(prepared.job_root) / "anonymized"
    anonymous_jsonl = anonymous_dir / Path(prepared.jsonl_path).name
    anonymous_schema = _schema_path_for_jsonl(anonymous_jsonl)
    with GlobalDictionaryStore(
        global_dictionary_path(dictionary_dir), read_only=True
    ) as store:
        written = anonymize_jsonl(
            source_path=prepared.jsonl_path,
            target_path=anonymous_jsonl,
            schema=schema,
            store=store,
            options=options,
            batch_size=batch_size,
        )
    if written != prepared.records:
        raise RuntimeError(
            f"[ANONYMIZED_RECORD_COUNT_MISMATCH] expected={prepared.records} "
            f"actual={written} path={prepared.relative_path}"
        )
    shutil.copyfile(prepared.schema_path, anonymous_schema)
    reconstruction = _reconstruct_isolated(
        source_dir=anonymous_dir,
        staging_output=Path(prepared.job_root) / "reconstructed",
        output_parent=(Path(output_root) / Path(prepared.relative_path)).parent,
        table_stem=Path(prepared.source).stem,
        relative_path=prepared.relative_path,
        schema=schema,
        records_path=anonymous_jsonl,
        raw_records_path=Path(prepared.jsonl_path),
        schema_path=Path(prepared.schema_path),
    )
    _apply_reconstruct_result(outcome, reconstruction)
    return outcome


def recover_one_table_worker(
    source_path: str,
    relative_path: str,
    temp_root: str,
    output_root: str,
    dictionary_dir: str,
    batch_size: int,
) -> Any:
    from .pipeline import TableOutcome

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
        raise FileNotFoundError(
            f"[EXPORT_ARTIFACT_MISSING] JSONL lub schemat: {relative_path}"
        )
    schema = load_schema(schema_path)
    outcome.records = count_data_records(jsonl_path)
    recovered_dir = job_root / "recovered"
    recovered_jsonl = recovered_dir / jsonl_path.name
    recovered_schema = _schema_path_for_jsonl(recovered_jsonl)
    global_path = global_dictionary_path(dictionary_dir)
    if global_path.is_file():
        with GlobalDictionaryStore(global_path, read_only=True) as store:
            written = recover_jsonl(
                source_path=jsonl_path,
                target_path=recovered_jsonl,
                schema=schema,
                relative_path=relative_path,
                store=store,
                batch_size=batch_size,
            )
    else:
        table_dict = load_dictionary(source.name, Path(dictionary_dir))
        if table_dict is None:
            raise FileNotFoundError(
                f"Brak słownika dla {source.name}: {dictionary_filename(source.name)}"
            )
        recovered = recover_records(
            schema,
            list(iter_jsonl(jsonl_path)),
            table_dict,
            relative_path=relative_path,
        )
        with atomic_jsonl_writer(recovered_jsonl) as outfile:
            written = write_records(outfile, recovered)
    if written != outcome.records:
        raise RuntimeError(
            f"[RECOVERED_RECORD_COUNT_MISMATCH] expected={outcome.records} "
            f"actual={written} path={relative_path}"
        )
    shutil.copyfile(schema_path, recovered_schema)
    reconstruction = _reconstruct_isolated(
        source_dir=recovered_dir,
        staging_output=job_root / "reconstructed",
        output_parent=(Path(output_root) / Path(relative_path)).parent,
        table_stem=source.stem,
        relative_path=relative_path,
        schema=schema,
        records_path=recovered_jsonl,
        raw_records_path=jsonl_path,
        schema_path=schema_path,
    )
    _apply_reconstruct_result(outcome, reconstruction)
    return outcome


def _reconstruct_isolated(
    *,
    source_dir: Path,
    staging_output: Path,
    output_parent: Path,
    table_stem: str,
    relative_path: str,
    schema: Any,
    records_path: Path,
    raw_records_path: Path,
    schema_path: Path,
) -> Any:
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
        numeric_context = numeric_width_context(schema, iter_jsonl(records_path))
        context = f"path={relative_path}"
        if numeric_context:
            context += f" {numeric_context}"
        raise RuntimeError(
            f"[RECONSTRUCTION_FAILED] {context} "
            f"error_type={type(exc).__name__} error={exc}"
        ) from exc
    if not any(item.status == "FAILED" for item in reconstruction.results):
        reconstructed_dbfs = [
            path for path in staging_output.iterdir()
            if path.is_file()
            and path.suffix.casefold() == ".dbf"
            and path.stem.casefold() == table_stem.casefold()
        ]
        if len(reconstructed_dbfs) != 1:
            raise RuntimeError(
                f"[RECONSTRUCTED_DBF_AMBIGUOUS] table={table_stem} "
                f"count={len(reconstructed_dbfs)}"
            )
        restore_identity_field_bytes(reconstructed_dbfs[0], raw_records_path, schema_path)
        publish_reconstructed_table(
            staging_output,
            output_parent,
            table_stem,
            overwrite=True,
        )
    return reconstruction


def _apply_reconstruct_result(outcome: Any, result: Any) -> None:
    from .pipeline import apply_reconstruct_result

    apply_reconstruct_result(outcome, result)


def _schema_path_for_jsonl(jsonl_path: Path) -> Path:
    return jsonl_path.with_name(f"{jsonl_path.stem}_schema.json")


def _job_key(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:20]
    return f"job_{digest}"
