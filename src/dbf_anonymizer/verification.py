"""Public independent dataset verification (REQ-P5-001).

``verify_dataset`` is the public REQ-P1-004/REQ-P1-008 service slice that
independently re-verifies a completed pseudonymization operation against its
three trust anchors — the SOURCE dataset, the PSEUDONYMIZED OUTPUT dataset
and the PROTECTED durable vault — using ONLY read-only public mechanisms:

* the source fingerprint is recomputed with the SAME canonical kernel used
  by ``build_plan``/P4 revalidation and must match the public result;
* the output dataset fingerprint is recomputed with the SAME publication
  kernel and must match the public result, the completed vault operation
  record and the stored receipt;
* the complete per-table record streams are compared in lockstep through the
  public dbfbridge Direct Read boundary (typed records, deleted markers,
  physical ordering, NULL semantics, Varchar semantics);
* every transformed-field postcondition is checked against the durable
  per-field policy application registered in the protected vault (the ONE
  authoritative record of what the capability matrix transformed): text and
  numeric mappings must agree with the durable mapping rows, memo payloads
  must equal the authoritative mask of the protected recovery payload, and
  temporal values must equal the reversible shift of the persisted offset;
  a sensitive original must never survive where policy required replacement
  (deleted records included);
* the protected mapping database is checked read-only (identity, completed
  operation, mapping bijections, NULL never mapped);
* the public relational assurance is cross-validated against the durable
  operation receipt (the P3/P4 evidence) — never simply trusted.

The verification is strictly READ-ONLY: it never writes, never checkpoints,
never recovers, never acquires writer authority and creates no artifacts.
The vault is read through an SQLite ``mode=ro&immutable=1`` snapshot (no
``-wal``/``-shm`` sidecar creation); ambiguous sidecar state makes the
mapping truth unverifiable without recovery and fails closed as a typed
inability. The record/policy scan is O(1) memory per record pair; vault
checks are bounded SQL aggregates; no table is ever materialized.

The finding-code vocabulary is versioned
(:data:`VERIFICATION_CHECK_CODE_VERSION`). Original values, memo payloads
and absolute private paths never appear in any public failure context,
result or log.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Callable, Sequence

import dbfbridge
from dbfbridge import TableSchema  # type: ignore[attr-defined]

from dbf_anonymizer.dictionary_identity import (
    connect_dictionary_readonly,
    dictionary_sidecars,
    read_dictionary_identity,
)
from dbf_anonymizer.discovery import (
    collect_fingerprint_entries,
    compute_source_fingerprint,
)
from dbf_anonymizer.engine.direct_io import (
    DirectSourceTable,
    read_source_table,
    stream_table_records,
)
from dbf_anonymizer.engine.publication import (
    fingerprint_dataset,
    result_from_receipt,
)
from dbf_anonymizer.errors import (
    CallbackError,
    CancellationError,
    DBFBridgeError,
    ErrorCode,
    ErrorContext,
    VaultError,
    VerificationError,
)
from dbf_anonymizer.models import (
    DatasetIdentity,
    PseudonymizationResult,
    RelationalAssurance,
    RelationalAssuranceLevel,
    VerificationResult,
    VerificationStatus,
)
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)
from dbf_anonymizer.relationships.assurance import bounded_evidence_fingerprint
from dbf_anonymizer.transforms.numeric_keys import canonical_integer_text
from dbf_anonymizer.transforms.temporal import temporal_shift
from dbf_anonymizer.vault.memo_allocation import mask_memo_value
from dbf_anonymizer.vault.schema import (
    VAULT_OPERATION_STATE_COMPLETED,
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
)

__all__ = [
    "VERIFICATION_CHECK_CODE_VERSION",
    "verify_dataset",
]

#: Versioned identity of the verification finding-code vocabulary. Every
#: finding is a stable, bounded, value-free machine code; a clean PASS
#: carries no finding. The authoritative PASS/PARTIAL/FAIL status lives on
#: the public :class:`~dbf_anonymizer.models.VerificationResult` model.
VERIFICATION_CHECK_CODE_VERSION = "1.0"

#: The exact bounded finding-code vocabulary (pinned by the snapshot test).
VERIFICATION_CHECK_CODES = frozenset(
    {
        "SOURCE_FINGERPRINT_MISMATCH",
        "OUTPUT_FINGERPRINT_MISMATCH",
        "RECEIPT_FINGERPRINT_MISMATCH",
        "RECEIPT_IDENTITY_MISMATCH",
        "VAULT_IDENTITY_MISMATCH",
        "VAULT_MAPPING_INVALID",
        "ASSURANCE_EVIDENCE_MISMATCH",
        "OPERATION_NOT_COMPLETED",
        "TABLE_MISSING",
        "UNEXPECTED_OUTPUT_ARTIFACT",
        "INDEX_ARTIFACT_UNVERIFIED",
        "MEMO_COMPANION_MISSING",
        "SCHEMA_MISMATCH",
        "RECORD_COUNT_MISMATCH",
        "RECORD_ORDER_MISMATCH",
        "DELETED_MARKER_MISMATCH",
        "NULL_SEMANTICS_MISMATCH",
        "ORIGINAL_VALUE_SURVIVED",
        "TEXT_MAPPING_MISMATCH",
        "NUMERIC_MAPPING_MISMATCH",
        "MEMO_PAYLOAD_MISMATCH",
        "MEMO_RECOVERY_ROW_MISSING",
        "TEMPORAL_VALUE_MISMATCH",
        "IDENTITY_VALUE_MISMATCH",
    }
)

#: Index artifacts that only a VFP/index backend (P6) could semantically
#: verify; their presence yields a truthful PARTIAL, never a fake PASS.
_INDEX_ARTIFACT_SUFFIXES = frozenset({".cdx", ".idx", ".dbc"})

_VERIFY_OPERATION = "verify_dataset"

_TEXT_EMPTY = ""


def _verification_failure(detail_code: str) -> VerificationError:
    """Stable typed, value-free verification inability (no original values)."""
    return VerificationError(
        ErrorCode.VERIFICATION_FAILED,
        context=ErrorContext(operation=_VERIFY_OPERATION, detail_code=detail_code),
    )


class _VerifyVault:
    """The dedicated strictly READ-ONLY verification reader for one vault.

    Opens the dictionary through the shared immutable ``mode=ro&immutable=1``
    kernel — no sidecar creation, no journal change, no recovery, no writer
    authority. Ambiguous SQLite sidecar state that cannot be validated
    without mutating/recovering the database is refused BEFORE any connection
    attempt. Every query is SELECT-only over the immutable committed
    snapshot; storage classes are validated by SQLite TYPE classification,
    never by parsing SQLite text.
    """

    def __init__(self, path: Path) -> None:
        if dictionary_sidecars(path):
            raise _verification_failure("VAULT_STATE_UNVERIFIABLE")
        try:
            self._connection = connect_dictionary_readonly(path)
            _vault_id, _schema_version, fingerprints = read_dictionary_identity(
                self._connection
            )
        except (sqlite3.DatabaseError, VaultError):
            raise _verification_failure("VAULT_UNREADABLE") from None
        self.source_fingerprint = fingerprints["source"]
        self.policy_fingerprint = fingerprints["policy"]
        self.relationship_fingerprint = fingerprints["relationship"]

    def close(self) -> None:
        self._connection.close()

    def completed_operation(
        self, operation_id: str
    ) -> dict[str, str | None] | None:
        row = self._connection.execute(
            "SELECT state, source_fingerprint, policy_fingerprint, "
            "relationship_fingerprint, vault_fingerprint, destination_identity, "
            "binding_fingerprint, output_fingerprint, result_json "
            "FROM operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            return None
        if not all(isinstance(value, (str, type(None))) for value in row):
            raise _verification_failure("VAULT_UNREADABLE")
        names = (
            "state",
            "source_fingerprint",
            "policy_fingerprint",
            "relationship_fingerprint",
            "vault_fingerprint",
            "destination_identity",
            "binding_fingerprint",
            "output_fingerprint",
            "result_json",
        )
        return {
            name: None if value is None else str(value)
            for name, value in zip(names, row)
        }

    def dataset_row(self) -> tuple[str, str, str]:
        row = self._connection.execute(
            "SELECT source_fingerprint, policy_fingerprint, relationship_fingerprint "
            "FROM dataset WHERE singleton = 1"
        ).fetchone()
        if row is None or not all(isinstance(value, str) for value in row):
            raise _verification_failure("VAULT_UNREADABLE")
        return (str(row[0]), str(row[1]), str(row[2]))

    def table_rows(self) -> dict[str, str]:
        rows = self._connection.execute(
            "SELECT table_id, relative_path FROM tables ORDER BY relative_path"
        ).fetchall()
        tables: dict[str, str] = {}
        for row in rows:
            if not isinstance(row[0], str) or not isinstance(row[1], str):
                raise _verification_failure("VAULT_UNREADABLE")
            tables[str(row[1])] = str(row[0])
        return tables

    def field_rows(
        self, table_id: str
    ) -> tuple[tuple[str, str, str, int, str | None, str | None], ...]:
        rows = self._connection.execute(
            "SELECT field_id, name, dbf_type, width, transform_action, "
            "mapping_domain_id FROM fields WHERE table_id = ? ORDER BY field_id",
            (table_id,),
        ).fetchall()
        for row in rows:
            if (
                not isinstance(row[0], str)
                or not isinstance(row[1], str)
                or not isinstance(row[2], str)
                or isinstance(row[3], bool)
                or not isinstance(row[3], int)
                or not isinstance(row[4], (str, type(None)))
                or not isinstance(row[5], (str, type(None)))
            ):
                raise _verification_failure("VAULT_UNREADABLE")
        return tuple(
            (str(row[0]), str(row[1]), str(row[2]), int(row[3]), row[4], row[5])
            for row in rows
        )

    def domain_kind(self, domain_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT domain_kind FROM mapping_domains WHERE domain_id = ?",
            (domain_id,),
        ).fetchone()
        if row is None:
            return None
        if not isinstance(row[0], str):
            raise _verification_failure("VAULT_UNREADABLE")
        return str(row[0])

    def text_original(self, domain_id: str, pseudonym_value: str) -> str | None:
        row = self._connection.execute(
            "SELECT original_value, typeof(original_value), typeof(pseudonym_value) "
            "FROM text_mappings WHERE domain_id = ? AND pseudonym_value = ?",
            (domain_id, pseudonym_value),
        ).fetchone()
        if row is None:
            return None
        if row[1] != "text" or row[2] != "text":
            raise _verification_failure("VAULT_UNREADABLE")
        return str(row[0])

    def numeric_original(self, domain_id: str, pseudonym_value: str) -> str | None:
        row = self._connection.execute(
            "SELECT original_value, typeof(original_value), typeof(pseudonym_value) "
            "FROM numeric_key_mappings WHERE domain_id = ? AND pseudonym_value = ?",
            (domain_id, pseudonym_value),
        ).fetchone()
        if row is None:
            return None
        if row[1] != "text" or row[2] != "text":
            raise _verification_failure("VAULT_UNREADABLE")
        return str(row[0])

    def domain_bijection(self, domain_id: str, table: str) -> tuple[int, int, int]:
        row = self._connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT original_value), "
            "COUNT(DISTINCT pseudonym_value) FROM "
            + table
            + " WHERE domain_id = ?",
            (domain_id,),
        ).fetchone()
        if row is None or not all(isinstance(value, int) for value in row):
            raise _verification_failure("VAULT_UNREADABLE")
        return (int(row[0]), int(row[1]), int(row[2]))

    def empty_text_originals(self, domain_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM text_mappings WHERE domain_id = ? AND original_value = ''",
            (domain_id,),
        ).fetchone()
        return row is not None

    def memo_recovery_row(
        self, table_id: str, physical_record_index: int, field_id: str
    ) -> tuple[bytes, str] | None:
        row = self._connection.execute(
            "SELECT original_payload, payload_kind, typeof(original_payload), "
            "typeof(payload_kind) FROM memo_recovery "
            "WHERE table_id = ? AND physical_record_index = ? AND field_id = ?",
            (table_id, physical_record_index, field_id),
        ).fetchone()
        if row is None:
            return None
        if row[2] != "blob" or row[3] != "text":
            raise _verification_failure("VAULT_UNREADABLE")
        kind = str(row[1])
        if kind not in ("TEXT", "BINARY"):
            raise _verification_failure("VAULT_UNREADABLE")
        return (bytes(row[0]), kind)

    def temporal_offset(self, domain_id: str | None) -> int | None:
        if domain_id is None:
            row = self._connection.execute(
                "SELECT domain_id, offset_days, typeof(offset_days) "
                "FROM temporal_parameters"
            ).fetchone()
        else:
            row = self._connection.execute(
                "SELECT domain_id, offset_days, typeof(offset_days) "
                "FROM temporal_parameters WHERE domain_id = ?",
                (domain_id,),
            ).fetchone()
        if row is None:
            return None
        if isinstance(row[1], bool) or not isinstance(row[1], int):
            raise _verification_failure("VAULT_UNREADABLE")
        offset = int(row[1])
        if offset == 0:
            raise _verification_failure("VAULT_UNREADABLE")
        return offset

    def domains(self) -> tuple[tuple[str, str], ...]:
        rows = self._connection.execute(
            "SELECT domain_id, domain_kind FROM mapping_domains ORDER BY domain_id"
        ).fetchall()
        for row in rows:
            if not isinstance(row[0], str) or not isinstance(row[1], str):
                raise _verification_failure("VAULT_UNREADABLE")
        return tuple((str(row[0]), str(row[1])) for row in rows)


class _Findings:
    """Deterministic aggregation of stable, value-free finding codes."""

    __slots__ = ("_codes",)

    def __init__(self) -> None:
        self._codes: set[str] = set()

    def add(self, code: str) -> None:
        self._codes.add(code)

    def codes(self) -> tuple[str, ...]:
        return tuple(sorted(self._codes))

    def __bool__(self) -> bool:
        return bool(self._codes)


def _output_table(output_root: Path, relative_path: str) -> DirectSourceTable:
    """Bind one OUTPUT table through the public Direct Read boundary."""
    absolute = output_root / relative_path
    try:
        schema = dbfbridge.read_schema(absolute)  # type: ignore[attr-defined]
    except (CancellationError, CallbackError):
        raise
    except Exception as exc:
        raise DBFBridgeError.from_exception(
            exc,
            context=ErrorContext(
                operation=_VERIFY_OPERATION,
                table_path=relative_path,
                detail_code="VERIFY_OUTPUT_SCHEMA_UNREADABLE",
            ),
        ) from None
    return DirectSourceTable(
        relative_path=relative_path, schema=schema, absolute_path=absolute
    )


def _schema_facts(
    table: DirectSourceTable,
) -> tuple[tuple[tuple[str, str, int, int, bool], ...], str, int]:
    """The compared logical schema facts of one table.

    Per-field logical facts (name, type, width, decimals, memo flag) in
    order plus the table-level encoding facts. Raw byte/header identity is
    NOT required: the public fresh writer legitimately normalizes physical
    representation while preserving these logical facts.
    """
    fields = tuple(
        (
            str(field.name),
            str(field.dbf_type).upper(),
            int(field.length),
            int(field.decimal_count),
            bool(field.is_memo),
        )
        for field in table.schema.fields
    )
    encoding = str(getattr(table.schema, "encoding", ""))
    language_driver = int(getattr(table.schema, "language_driver", -1))
    return (fields, encoding, language_driver)


def verify_dataset(
    result: PseudonymizationResult,
    *,
    source: str | Path,
    vault: str | Path,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> VerificationResult:
    """Independently verify one completed pseudonymization (REQ-P5-001).

    Strictly read-only: the source dataset, the pseudonymized output, the
    protected vault and its sidecars are never modified, and no staging,
    lock or verification artifact is created. The source fingerprint is
    recomputed with the canonical kernel, the output dataset fingerprint
    with the publication kernel, the record streams are compared through
    the public dbfbridge boundary against the durable per-field policy
    application registered in the vault, the mapping bijections and the
    completed operation receipt are validated read-only, and the public
    relational assurance is cross-validated against that durable receipt
    evidence — the PASS/PARTIAL/FAIL verdict is derived from evidence,
    never from preference.

    REQ-P1-008: ONE :class:`ProgressController`
    (``operation="verify_dataset"``) seeded with the verified operation's
    canonical id drives the bounded phases; cancellation is polled at every
    scan safe point (source hashing, table iteration, record streaming,
    memo verification, output hashing) and raises the typed
    :class:`~dbf_anonymizer.errors.CancellationError` with no terminal
    completion and no mutation. Callback failures remain contained and
    privacy-safe, attributed to the ``verify_dataset`` operation.

    An inability to verify (unreadable source, missing or ambiguous vault
    state) raises the existing typed
    :class:`~dbf_anonymizer.errors.VerificationError` contract; every
    dataset-level finding is a truthful FAIL/PARTIAL result with stable,
    versioned check codes.
    """
    if not isinstance(result, PseudonymizationResult):
        raise TypeError("verify_dataset requires a PseudonymizationResult")
    context = result.execution_context
    if context is None:
        raise _verification_failure("VERIFY_RESULT_CONTEXT_MISSING")
    source_root = Path(source)
    output_root = Path(context.output_root)
    vault_path = Path(vault)

    control = ProgressController(
        operation=_VERIFY_OPERATION,
        progress=progress,
        cancel_check=cancel_check,
        operation_id=result.operation_id,
    )
    control.start_phase(ProgressPhase.OPERATION)

    findings = _Findings()
    record_count = 0
    table_count = 0
    vault_reader = _VerifyVault(vault_path)
    try:
        record_count, table_count = _verify(
            result=result,
            control=control,
            findings=findings,
            source_root=source_root,
            output_root=output_root,
            vault_reader=vault_reader,
        )
    finally:
        vault_reader.close()

    # The authoritative PASS/PARTIAL/FAIL status (REQ-P5-001): FAIL wins,
    # then PARTIAL only for a genuinely unavailable verification dimension,
    # and a clean verified dataset is a truthful PASS.
    if findings:
        status = VerificationStatus.FAIL
        check_codes = findings.codes()
    elif _has_index_artifact(output_root):
        status = VerificationStatus.PARTIAL
        check_codes = ("INDEX_ARTIFACT_UNVERIFIED",)
    else:
        status = VerificationStatus.PASS
        check_codes = ()

    verification_result = VerificationResult(
        status=status,
        dataset=result.dataset,
        operation_id=result.operation_id,
        table_count=table_count,
        record_count=record_count,
        check_codes=check_codes,
        assurance=result.assurance,
    )
    # The single terminal completion is emitted only now — after the public
    # result genuinely exists (never after cancellation).
    control.complete(completed=table_count)
    return verification_result


def _iter_output_files(root: Path) -> Sequence[tuple[str, Path]]:
    """The canonical output inventory (the publication enumeration kernel)."""
    from dbf_anonymizer.engine.publication import _iter_dataset_files

    return tuple(_iter_dataset_files(root))


def _has_index_artifact(output_root: Path) -> bool:
    return any(
        Path(relative).suffix.lower() in _INDEX_ARTIFACT_SUFFIXES
        for relative, _path in _iter_output_files(output_root)
    )


def _expected_output_inventory(
    table_paths: Sequence[str], *, source_root: Path
) -> tuple[set[str], set[str]]:
    """The exact expected output inventory from the SOURCE topology.

    One expected output DBF per planned table at the SAME normalized
    relative path (duplicate basenames in separate directories stay
    distinct — ownership is never inferred from the basename alone), plus
    one FPT companion per table whose SOURCE schema requires a memo
    companion (read-only public dbfbridge schema facts only).
    """
    expected: set[str] = set()
    memo_companions: set[str] = set()
    for relative_path in table_paths:
        expected.add(relative_path)
        table = read_source_table(source_root, relative_path)
        if table.has_memo_fields:
            memo_relative = Path(relative_path).with_suffix(".fpt").as_posix()
            expected.add(memo_relative)
            memo_companions.add(memo_relative)
    return expected, memo_companions


def _verify(
    *,
    result: PseudonymizationResult,
    control: ProgressController,
    findings: _Findings,
    source_root: Path,
    output_root: Path,
    vault_reader: _VerifyVault,
) -> tuple[int, int]:
    """The bounded read-only verification pipeline (deterministic order)."""
    dataset: DatasetIdentity = result.dataset
    record_count = 0
    table_count = 0

    # --- SOURCE VERIFICATION: canonical fingerprint + strict topology --------
    control.start_phase(ProgressPhase.SOURCE_VERIFICATION)
    try:
        entries = collect_fingerprint_entries(
            source_root,
            strict=True,
            cancel_probe=control.check_cancelled,
            progress_probe=lambda done, total, rel: control.progress(
                ProgressPhase.SOURCE_VERIFICATION,
                completed=done,
                total=total,
                table_path=rel,
            ),
        )
        current_source = compute_source_fingerprint(entries)
    except (CancellationError, CallbackError):
        raise
    except OSError:
        raise _verification_failure("SOURCE_UNREADABLE") from None
    if current_source != result.dataset.source_fingerprint:
        findings.add("SOURCE_FINGERPRINT_MISMATCH")

    # --- TOPOLOGY: expected output inventory from the SOURCE topology --------
    expected_output, expected_memo_companions = _expected_output_inventory(
        dataset.table_paths, source_root=source_root
    )
    try:
        output_inventory = _iter_output_files(output_root)
    except Exception:
        raise _verification_failure("OUTPUT_UNREADABLE") from None
    output_paths = {relative for relative, _path in output_inventory}
    for relative in sorted(expected_output - output_paths):
        if relative in expected_memo_companions:
            findings.add("MEMO_COMPANION_MISSING")
        else:
            findings.add("TABLE_MISSING")
    for relative in sorted(output_paths - expected_output):
        if Path(relative).suffix.lower() in _INDEX_ARTIFACT_SUFFIXES:
            findings.add("INDEX_ARTIFACT_UNVERIFIED")
        else:
            findings.add("UNEXPECTED_OUTPUT_ARTIFACT")

    # --- VAULT VERIFICATION: identity, binding, receipt, mappings ------------
    control.start_phase(ProgressPhase.VAULT_VERIFICATION)
    _verify_vault(result, control, findings, vault_reader)

    # --- TABLE + RECORD VERIFICATION (per planned table, streamed) -----------
    control.start_phase(ProgressPhase.TABLE_EVALUATION, total=len(dataset.table_paths))
    for relative_path in dataset.table_paths:
        control.check_cancelled()
        if relative_path not in output_paths:
            # The topology step already recorded the precise finding; the
            # missing table cannot be scanned and stays out of the verified
            # totals (the aggregate mismatch then also reports truthfully).
            continue
        memo_relative = Path(relative_path).with_suffix(".fpt").as_posix()
        if memo_relative in expected_memo_companions and memo_relative not in (
            output_paths
        ):
            # A dangling memo companion cannot be streamed; the topology
            # finding is authoritative.
            continue
        table_count += 1
        record_count += _verify_table(
            relative_path=relative_path,
            source_root=source_root,
            output_root=output_root,
            vault_reader=vault_reader,
            findings=findings,
            checkpoint=control.check_cancelled,
        )
        control.bump(ProgressPhase.TABLE_EVALUATION, table_path=relative_path)

    # --- OUTPUT VERIFICATION: the complete publication fingerprint -----------
    control.start_phase(ProgressPhase.OUTPUT_VERIFICATION)
    try:
        current_output = fingerprint_dataset(
            output_root,
            checkpoint=control.check_cancelled,
            progress_probe=lambda done, total, rel: control.progress(
                ProgressPhase.OUTPUT_VERIFICATION,
                completed=done,
                total=total,
                table_path=rel,
            ),
        )
    except Exception:
        raise _verification_failure("OUTPUT_UNREADABLE") from None
    if current_output != result.output_fingerprint:
        findings.add("OUTPUT_FINGERPRINT_MISMATCH")

    # Aggregated truthfulness: the scanned totals must match the public claim.
    if table_count != result.table_count or record_count != result.record_count:
        findings.add("RECORD_COUNT_MISMATCH")
    return record_count, table_count


def _verify_vault(
    result: PseudonymizationResult,
    control: ProgressController,
    findings: _Findings,
    vault_reader: _VerifyVault,
) -> None:
    """Read-only durable-state verification (identity, receipt, mappings)."""
    dataset_row = vault_reader.dataset_row()
    if dataset_row[0] != result.dataset.source_fingerprint:
        findings.add("VAULT_IDENTITY_MISMATCH")
    if dataset_row[2] != result.assurance.relationship_fingerprint:
        findings.add("VAULT_IDENTITY_MISMATCH")

    operation = vault_reader.completed_operation(result.operation_id)
    if operation is None or operation["state"] != VAULT_OPERATION_STATE_COMPLETED:
        findings.add("OPERATION_NOT_COMPLETED")
        return
    if operation["source_fingerprint"] != result.dataset.source_fingerprint:
        findings.add("VAULT_IDENTITY_MISMATCH")
    if operation["output_fingerprint"] != result.output_fingerprint:
        findings.add("VAULT_IDENTITY_MISMATCH")
    receipt_json = operation["result_json"]
    if receipt_json is None:
        findings.add("RECEIPT_IDENTITY_MISMATCH")
        return
    try:
        receipt = result_from_receipt(receipt_json)
    except Exception:
        findings.add("RECEIPT_IDENTITY_MISMATCH")
        return
    if receipt.operation_id != result.operation_id:
        findings.add("RECEIPT_IDENTITY_MISMATCH")
    if receipt.output_fingerprint != result.output_fingerprint:
        findings.add("RECEIPT_FINGERPRINT_MISMATCH")

    # The public relational assurance is cross-validated against the DURABLE
    # receipt evidence (never simply trusted).
    _verify_assurance(result.assurance, receipt.relations, findings)

    # Mapping-domain invariants: bijection per domain + NULL never mapped.
    for domain_id, domain_kind in vault_reader.domains():
        control.check_cancelled()
        table = (
            "text_mappings"
            if domain_kind == VAULT_TABLE_DOMAIN_KIND_TEXT
            else "numeric_key_mappings"
        )
        count, distinct_originals, distinct_pseudonyms = (
            vault_reader.domain_bijection(domain_id, table)
        )
        if count != distinct_originals or count != distinct_pseudonyms:
            findings.add("VAULT_MAPPING_INVALID")
        if (
            domain_kind == VAULT_TABLE_DOMAIN_KIND_TEXT
            and vault_reader.empty_text_originals(domain_id)
        ):
            # NULL/empty is a preserved identity and is never mapped.
            findings.add("VAULT_MAPPING_INVALID")
        control.bump(ProgressPhase.VAULT_VERIFICATION)


def _verify_assurance(
    assurance: RelationalAssurance,
    receipt_relations: Sequence[object],
    findings: _Findings,
) -> None:
    """Cross-validate the public assurance against the durable receipt."""
    declared = assurance.declared_relations
    verified = sum(1 for item in receipt_relations if getattr(item, "verified", False))
    failed = len(receipt_relations) - verified
    expected_fingerprint = bounded_evidence_fingerprint(
        receipt_relations,  # type: ignore[arg-type]
        relationship_fingerprint=assurance.relationship_fingerprint or "",
    )
    if (
        verified != assurance.verified_relations
        or failed != assurance.failed_relations
        or (verified + failed) != declared
        or expected_fingerprint != assurance.evidence_fingerprint
    ):
        findings.add("ASSURANCE_EVIDENCE_MISMATCH")
        return
    if declared == 0:
        if assurance.level is not RelationalAssuranceLevel.GLOBAL_EXACT_VALUE:
            findings.add("ASSURANCE_EVIDENCE_MISMATCH")
    elif verified == declared and failed == 0:
        if assurance.level not in (
            RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED,
            RelationalAssuranceLevel.VFP_METADATA_VERIFIED,
        ):
            findings.add("ASSURANCE_EVIDENCE_MISMATCH")
    elif assurance.level is not RelationalAssuranceLevel.INCOMPLETE:
        findings.add("ASSURANCE_EVIDENCE_MISMATCH")


def _verify_table(
    *,
    relative_path: str,
    source_root: Path,
    output_root: Path,
    vault_reader: _VerifyVault,
    findings: _Findings,
    checkpoint: Callable[[], None],
) -> int:
    """One streamed source/output table comparison (O(1) memory).

    Compares logical schema facts and streams both sides in lockstep through
    the public dbfbridge boundary: physical order, deleted markers, record
    counts, NULL semantics and every transformed-field postcondition derived
    from the durable policy application (text/numeric/memo/temporal).
    """
    try:
        source_table = read_source_table(
            source_root, relative_path, cancel_check=checkpoint
        )
    except (CancellationError, CallbackError):
        raise
    except Exception:
        raise _verification_failure("SOURCE_UNREADABLE") from None
    output_table = _output_table(output_root, relative_path)
    if _schema_facts(source_table) != _schema_facts(output_table):
        findings.add("SCHEMA_MISMATCH")
        return 0

    memo_policy = "inline" if source_table.has_memo_fields else "skip"
    try:
        source_stream = stream_table_records(
            source_table,
            include_deleted=True,
            memo_policy=memo_policy,
            cancel_check=checkpoint,
        )
        output_stream = stream_table_records(
            output_table,
            include_deleted=True,
            memo_policy=memo_policy,
            cancel_check=checkpoint,
        )
    except (CancellationError, CallbackError):
        raise
    except Exception as exc:
        raise DBFBridgeError.from_exception(
            exc,
            context=ErrorContext(
                operation=_VERIFY_OPERATION,
                table_path=relative_path,
                detail_code="VERIFY_RECORD_STREAM_UNREADABLE",
            ),
        ) from None

    table_id = vault_reader.table_rows().get(relative_path)
    fields: dict[str, tuple[str, str, str | None, str | None]] = {}
    if table_id is not None:
        for field_id, name, dbf_type, _width, action, domain_id in (
            vault_reader.field_rows(table_id)
        ):
            fields[name] = (field_id, dbf_type, action, domain_id)
    scanned = 0
    try:
        for source_record, output_record in zip(source_stream, output_stream):
            checkpoint()
            scanned += 1
            if source_record.physical_index != output_record.physical_index:
                findings.add("RECORD_ORDER_MISMATCH")
                break
            if source_record.deleted != output_record.deleted:
                findings.add("DELETED_MARKER_MISMATCH")
            _verify_record_values(
                source_values=source_record.values,
                output_values=output_record.values,
                physical_index=source_record.physical_index,
                schema=source_table.schema,
                fields=fields,
                table_id=table_id,
                vault_reader=vault_reader,
                findings=findings,
            )
        extra_source = sum(1 for _record in source_stream)
        extra_output = sum(1 for _record in output_stream)
        if extra_source or extra_output:
            findings.add("RECORD_COUNT_MISMATCH")
    except (CancellationError, CallbackError):
        raise
    return scanned


def _verify_record_values(
    *,
    source_values: Mapping[str, object],
    output_values: Mapping[str, object],
    physical_index: int,
    schema: TableSchema,
    fields: dict[str, tuple[str, str, str | None, str | None]],
    table_id: str | None,
    vault_reader: _VerifyVault,
    findings: _Findings,
) -> None:
    """The per-field policy postcondition comparison of ONE record pair."""
    for field in schema.fields:
        name = str(field.name)
        dbf_type = str(field.dbf_type).upper()
        if dbf_type == "0":
            continue  # writer-owned system fields (the _NullFlags bitmap)
        binding = fields.get(name)
        if binding is None:
            # Unregistered field: logical identity is the verified postcondition.
            if source_values.get(name) != output_values.get(name):
                findings.add("IDENTITY_VALUE_MISMATCH")
            continue
        field_id, field_type, action, domain_id = binding
        source_value = source_values.get(name)
        output_value = output_values.get(name)
        if action == "MASK_REVERSIBLE":
            _verify_memo_value(
                dbf_type=field_type,
                source_value=source_value,
                output_value=output_value,
                physical_index=physical_index,
                table_id=table_id,
                field_id=field_id,
                vault_reader=vault_reader,
                findings=findings,
            )
        elif action == "SHIFT_REVERSIBLE":
            offset = vault_reader.temporal_offset(domain_id)
            if offset is None or output_value != temporal_shift(source_value, offset):
                findings.add("TEMPORAL_VALUE_MISMATCH")
        elif action == "PSEUDONYMIZE_REVERSIBLE":
            if (
                domain_id is not None
                and vault_reader.domain_kind(domain_id)
                == VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY
            ):
                _verify_numeric_value(
                    domain_id=domain_id,
                    source_value=source_value,
                    output_value=output_value,
                    vault_reader=vault_reader,
                    findings=findings,
                )
            else:
                _verify_text_value(
                    domain_id=domain_id or "",
                    source_value=source_value,
                    output_value=output_value,
                    vault_reader=vault_reader,
                    findings=findings,
                )
        else:
            # An unknown durable action is a broken contract, never a pass.
            findings.add("SCHEMA_MISMATCH")


def _verify_text_value(
    *,
    domain_id: str,
    source_value: object,
    output_value: object,
    vault_reader: _VerifyVault,
    findings: _Findings,
) -> None:
    if source_value is None or source_value == _TEXT_EMPTY:
        if output_value != source_value:
            findings.add("NULL_SEMANTICS_MISMATCH")
        return
    if output_value is None or not isinstance(output_value, str):
        findings.add("NULL_SEMANTICS_MISMATCH")
        return
    if output_value == source_value:
        findings.add("ORIGINAL_VALUE_SURVIVED")
        return
    if vault_reader.text_original(domain_id, output_value) != source_value:
        findings.add("TEXT_MAPPING_MISMATCH")


def _verify_numeric_value(
    *,
    domain_id: str,
    source_value: object,
    output_value: object,
    vault_reader: _VerifyVault,
    findings: _Findings,
) -> None:
    if source_value is None:
        if output_value is not None:
            findings.add("NULL_SEMANTICS_MISMATCH")
        return
    if output_value is None:
        findings.add("NULL_SEMANTICS_MISMATCH")
        return
    if isinstance(output_value, bool) or not isinstance(output_value, int):
        findings.add("NUMERIC_MAPPING_MISMATCH")
        return
    if output_value == source_value:
        findings.add("ORIGINAL_VALUE_SURVIVED")
        return
    if vault_reader.numeric_original(
        domain_id, canonical_integer_text(output_value)
    ) != canonical_integer_text(source_value):
        findings.add("NUMERIC_MAPPING_MISMATCH")


def _verify_memo_value(
    *,
    dbf_type: str,
    source_value: object,
    output_value: object,
    physical_index: int,
    table_id: str | None,
    field_id: str,
    vault_reader: _VerifyVault,
    findings: _Findings,
) -> None:
    if source_value is None:
        if output_value is not None:
            findings.add("NULL_SEMANTICS_MISMATCH")
        return
    if output_value is None:
        findings.add("NULL_SEMANTICS_MISMATCH")
        return
    if table_id is None:
        findings.add("MEMO_RECOVERY_ROW_MISSING")
        return
    recovery = vault_reader.memo_recovery_row(table_id, physical_index, field_id)
    if recovery is None:
        findings.add("MEMO_RECOVERY_ROW_MISSING")
        return
    original, payload_kind = recovery
    if payload_kind == "TEXT" and not isinstance(output_value, str):
        findings.add("MEMO_PAYLOAD_MISMATCH")
        return
    if payload_kind == "BINARY" and not isinstance(output_value, bytes):
        findings.add("MEMO_PAYLOAD_MISMATCH")
        return
    original_logical: object = (
        original.decode("utf-8") if payload_kind == "TEXT" else original
    )
    if original_logical != source_value:
        findings.add("MEMO_PAYLOAD_MISMATCH")
        return
    if output_value == original_logical:
        findings.add("MEMO_PAYLOAD_MISMATCH")
        return
    if output_value != mask_memo_value(dbf_type, original_logical):
        findings.add("MEMO_PAYLOAD_MISMATCH")