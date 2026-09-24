"""Phase 4 Direct Read / fresh Direct Write boundary (REQ-P4-001/P4-003).

The ONE production IO boundary of the two-pass engine.  Every production DBF
read goes through :func:`stream_table_records` (the public
``dbfbridge.iter_records`` Direct Read stream) and every production DBF/FPT
write goes through :func:`write_fresh_table` (the public
``dbfbridge.write_table`` boundary).  There is NO production path through
JSONL/CSV intermediates, no direct ``dbfread``/``dbf`` access, no private
``dbfbridge`` module, no raw record-byte rewriting and no source-artifact
copying as transformed output.

Public dbfbridge 1.1 capabilities this boundary relies on (audited by
runtime introspection of the pinned ``dbfbridge[write]==1.1.1`` acceptance
artifact):

* ``read_schema`` / ``inspect_table`` — public schema and field descriptors;
* ``iter_records(path, *, include_deleted, fields, memo, encoding,
  decode_errors, progress, cancel_check)`` — the streaming O(1)-memory
  Direct Read with deleted-record visibility (``include_deleted=True``
  yields deleted physical records with preserved physical indices) and
  per-record cooperative cancellation (a raising cancellation callable
  propagates its typed exception unchanged);
* ``DirectRecord(physical_index, deleted, values)`` — the typed logical
  record; outgoing records are newly constructed only from physical order,
  deletion state and transformed typed application values, with
  ``raw_record`` unset throughout the transform path;
* ``write_table(destination, *, schema, records, overwrite,
  staging_directory, progress, cancel_check)`` — fresh DBF/FPT creation from
  a lazily consumed record stream.

The public 1.1 contract exposes nullable ``C``/``V`` and numeric values as
typed logical values: ``None`` remains distinct from ``""`` and numeric zero.
Field projection and Direct Read -> Direct Write -> Direct Read preserve the
same distinction.  The engine never interprets payload appearance as NULL and
never constructs ``_NullFlags``; the public writer owns that system bitmap.
Nullable ``M``/``G``/``P`` use the same typed contract: ``None`` remains NULL,
while empty text/binary payloads remain non-NULL values for the bounded memo
vault pipeline.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence

import dbfbridge
from dbfbridge import (  # type: ignore[attr-defined]
    DirectRecord,
    TableSchema,
    WriteResult,
)

from dbf_anonymizer.errors import (
    CancellationError,
    CallbackError,
    DBFBridgeError,
    ErrorCode,
    ErrorContext,
    PathError,
    PublicationError,
)

__all__ = [
    "DirectSourceTable",
    "read_source_table",
    "standalone_output_schema",
    "vfp_indexed_output_schema",
    "stream_table_records",
    "write_fresh_table",
]

_ENGINE_OPERATION = "engine"


def engine_path_failure(
    detail_code: str, *, table_path: str | None = None
) -> PathError:
    """A stable typed, privacy-safe engine path refusal (no values)."""
    return PathError(
        ErrorCode.PATH_INVALID,
        context=ErrorContext(
            operation=_ENGINE_OPERATION,
            table_path=table_path,
            detail_code=detail_code,
        ),
    )


@dataclass(frozen=True)
class DirectSourceTable:
    """One source table bound through the public Direct Read boundary.

    ``absolute_path`` is INTERNAL engine state: it is never serialized,
    never logged and never part of any public model, progress event or
    manifest.
    """

    relative_path: str
    schema: TableSchema
    absolute_path: Path

    @property
    def has_memo_fields(self) -> bool:
        return any(field.is_memo for field in self.schema.fields)

    @property
    def memo_field_names(self) -> tuple[str, ...]:
        return tuple(
            str(field.name) for field in self.schema.fields if field.is_memo
        )


def read_source_table(
    source_root: Path,
    relative_path: str,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> DirectSourceTable:
    """Bind one source table through the public Direct Read boundary.

    Read-only: the source is never opened for writing, never reindexed and
    never mutated; no sidecar is created under the source tree.
    """
    if cancel_check is not None:
        cancel_check()
    absolute_path = source_root / relative_path
    try:
        schema = dbfbridge.read_schema(absolute_path)  # type: ignore[attr-defined]
    except (CancellationError, CallbackError):
        raise
    except Exception as exc:
        raise DBFBridgeError.from_exception(
            exc,
            context=ErrorContext(
                operation=_ENGINE_OPERATION,
                table_path=relative_path,
                detail_code="ENGINE_READ_SCHEMA_FAILED",
            ),
        ) from None
    return DirectSourceTable(
        relative_path=relative_path,
        schema=schema,
        absolute_path=absolute_path,
    )


def stream_table_records(
    table: DirectSourceTable,
    *,
    fields: Sequence[str] | None = None,
    include_deleted: bool = True,
    memo_policy: str = "skip",
    cancel_check: Callable[[], None] | None = None,
) -> Iterator[DirectRecord]:
    """The streaming Direct Read of one source table (O(1) memory).

    Deleted records are included by default (the production pipeline
    transforms active AND deleted records; P4-005 owns their final
    marker reconstruction).  The iteration is one pass, lazily consumed,
    with the cooperative cancellation callable invoked by the public reader
    at every physical record boundary.
    """
    try:
        yield from dbfbridge.iter_records(  # type: ignore[attr-defined]
            table.absolute_path,
            fields=list(fields) if fields is not None else None,
            include_deleted=include_deleted,
            memo=memo_policy,
            raw=False,
            encoding="auto",
            decode_errors="strict",
            cancel_check=cancel_check,
        )
    except (CancellationError, CallbackError):
        raise
    except Exception as exc:
        raise DBFBridgeError.from_exception(
            exc,
            context=ErrorContext(
                operation=_ENGINE_OPERATION,
                table_path=table.relative_path,
                detail_code="ENGINE_DIRECT_READ_FAILED",
            ),
        ) from None


def standalone_output_schema(schema: TableSchema) -> TableSchema:
    """Declare the PUBLIC standalone output schema of one fresh Direct Write
    (REQ-P6-002).

    Structural-CDX and DBC coupling are removed DECLARATIVELY through the
    public frozen ``dbfbridge.TableSchema`` dataclass constructor — the ONE
    supported public way to construct a standalone write schema:

    * the structural-CDX table flag (and companion-CDX metadata) is cleared,
      so the fresh DBF carries the standalone header state;
    * DBC binding and the DBC backlink are removed; the fresh output never
      claims DBC rules/triggers/relations, and no DBC/DCT/DCX companion is
      created or copied;
    * no DBF header is edited manually, no raw byte is patched, no bytes are
      copied from the source DBF and no private dbfbridge module is used:
      the public ``dbfbridge.write_table`` owns every written byte.

    The reduced application semantics (no structural index validity, no DBC
    semantics) are reported by the planning/preflight/transfer layers; the
    authoritative ``VFP_INDEXED`` rebuild strategy (REQ-P6-003) delegates
    source-definition discovery and staged-table rebuild to the injected
    backend separately from this data schema.
    """
    return dataclasses.replace(
        schema,
        has_structural_cdx=False,
        companion_cdx_present=False,
        companion_cdx_path=None,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
    )


def vfp_indexed_output_schema(schema: TableSchema) -> TableSchema:
    """Declare the PUBLIC VFP_INDEXED output schema of one fresh Direct Write
    (REQ-P6-003).

    The structural-CDX flag is PRESERVED so the fresh DBF header declares
    structural index presence. The companion-CDX metadata is CLEARED because
    the authoritative rebuild (via injected IndexBackend) will produce a
    fresh CDX in protected staging that corresponds to the pseudonymized data.

    * structural-CDX table flag is kept (source truth);
    * companion-CDX metadata is cleared (rebuild will produce fresh CDX);
    * DBC binding and the DBC backlink are removed; the fresh output never
      claims DBC rules/triggers/relations, and no DBC/DCT/DCX companion is
      created or copied;
    * no DBF header is edited manually, no raw byte is patched, no bytes are
      copied from the source DBF and no private dbfbridge module is used:
      the public ``dbfbridge.write_table`` owns every written byte.

    The authoritative backend reads source definitions and applies them to
    the protected staged table separately from this data schema.
    """
    return dataclasses.replace(
        schema,
        has_structural_cdx=schema.has_structural_cdx,
        companion_cdx_present=False,
        companion_cdx_path=None,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
    )


def write_fresh_table(
    destination: Path,
    schema: TableSchema,
    records: Iterator[DirectRecord],
    *,
    cancel_check: Callable[[], None] | None = None,
) -> WriteResult:
    """Write ONE fresh DBF/FPT through the public Direct Write boundary.

    ``records`` is a lazily consumed stream: the engine never materializes a
    whole table before writing.  A destination conflict fails closed (typed
    path refusal) instead of overwriting an existing artifact.
    """
    if destination.exists():
        raise engine_path_failure("ENGINE_OUTPUT_EXISTS", table_path=destination.name)
    try:
        result = dbfbridge.write_table(
            destination,
            schema=schema,
            records=records,
            overwrite=False,
            cancel_check=cancel_check,
        )
        assert isinstance(result, WriteResult)
        return result
    except (CancellationError, CallbackError):
        raise
    except Exception as exc:
        raise DBFBridgeError.from_exception(
            exc,
            context=ErrorContext(
                operation=_ENGINE_OPERATION,
                table_path=destination.name,
                detail_code="ENGINE_DIRECT_WRITE_FAILED",
            ),
        ) from exc
