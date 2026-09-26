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

import hashlib
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
    derive_binding_fingerprint,
    derive_destination_identity,
    derive_vault_fingerprint,
    fingerprint_dataset,
    result_from_receipt,
)
from dbf_anonymizer.errors import (
    AnonymizerError,
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
    VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
)

__all__ = [
    "VERIFICATION_CHECK_CODE_VERSION",
    "verify_dataset",
]

#: Versioned identity of the verification finding-code vocabulary. Every
#: finding is a stable, bounded, value-free machine code with an explicit
#: SEVERITY: failures (corruption, privacy/policy violation, missing/changed
#: required data, mapping/receipt/identity mismatch) always win over
#: partials (a requested verification dimension is unavailable while every
#: verified invariant held). A clean PASS carries no finding. The
#: authoritative PASS/PARTIAL/FAIL status lives on the public
#: :class:`~dbf_anonymizer.models.VerificationResult` model.
VERIFICATION_CHECK_CODE_VERSION = "1.3"

#: The exact bounded finding-code vocabulary (pinned by the snapshot test).
VERIFICATION_CHECK_CODES = frozenset(
    {
        "SOURCE_FINGERPRINT_MISMATCH",
        "SOURCE_DBC_INVENTORY_MISMATCH",
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
        "STANDALONE_IDX_DEFINITION_UNAVAILABLE",
        "STANDALONE_IDX_EVIDENCE_MISMATCH",
        "MEMO_COMPANION_MISSING",
        "OUTPUT_DBC_COUPLING_PRESENT",
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
        "POLICY_BINDING_MISSING",
        "POLICY_BINDING_MISMATCH",
    }
)

#: The durable field-policy ledger actions (the ONE authoritative record of
#: what the capability matrix resolved for every non-system field).
_LEDGER_ACTIONS = frozenset(
    {"KEEP", "PSEUDONYMIZE_REVERSIBLE", "MASK_REVERSIBLE", "SHIFT_REVERSIBLE"}
)

#: Index artifacts that only a VFP/index backend (P6) could semantically
#: verify; their presence yields a truthful PARTIAL, never a fake PASS. DBC
#: companions are not indexes and are always output contamination.
_INDEX_ARTIFACT_SUFFIXES = frozenset({".cdx", ".idx"})

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

    The failure ``operation``/builder are supplied by the owning public
    service (the REQ-P5-001 verifier and the REQ-P5-002 recovery reader
    share this ONE read-only implementation).
    """

    def __init__(
        self,
        path: Path,
        *,
        operation: str = "verify_dataset",
        failure: Callable[[str], AnonymizerError] | None = None,
    ) -> None:
        self._operation = operation
        self._failure = failure if failure is not None else _verification_failure
        try:
            sidecars = dictionary_sidecars(path)
        except VaultError:
            # Uninspectable vault surroundings are a typed unreadable state
            # attributed to the owning service (never raw OS text).
            raise self._failure("VAULT_UNREADABLE") from None
        if sidecars:
            raise self._failure("VAULT_STATE_UNVERIFIABLE")
        try:
            self._connection = connect_dictionary_readonly(path)
            vault_id, schema_version, fingerprints = read_dictionary_identity(
                self._connection
            )
        except (sqlite3.DatabaseError, VaultError):
            raise self._failure("VAULT_UNREADABLE") from None
        self.vault_id = vault_id
        self.schema_version = schema_version
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
            raise self._failure("VAULT_UNREADABLE")
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
            raise self._failure("VAULT_UNREADABLE")
        return (str(row[0]), str(row[1]), str(row[2]))

    def table_rows(self) -> dict[str, str]:
        rows = self._connection.execute(
            "SELECT table_id, relative_path FROM tables ORDER BY relative_path"
        ).fetchall()
        tables: dict[str, str] = {}
        for row in rows:
            if not isinstance(row[0], str) or not isinstance(row[1], str):
                raise self._failure("VAULT_UNREADABLE")
            tables[str(row[1])] = str(row[0])
        return tables

    def field_rows(
        self, table_id: str
    ) -> tuple[tuple[str, str, str, int, str, str | None, str | None], ...]:
        rows = self._connection.execute(
            "SELECT field_id, name, dbf_type, width, encoding, transform_action, "
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
                or not isinstance(row[6], (str, type(None)))
            ):
                raise self._failure("VAULT_UNREADABLE")
        return tuple(
            (
                str(row[0]),
                str(row[1]),
                str(row[2]),
                int(row[3]),
                str(row[4]),
                row[5],
                row[6],
            )
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
            raise self._failure("VAULT_UNREADABLE")
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
            raise self._failure("VAULT_UNREADABLE")
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
            raise self._failure("VAULT_UNREADABLE")
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
            raise self._failure("VAULT_UNREADABLE")
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
            raise self._failure("VAULT_UNREADABLE")
        kind = str(row[1])
        if kind not in ("TEXT", "BINARY"):
            raise self._failure("VAULT_UNREADABLE")
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
            raise self._failure("VAULT_UNREADABLE")
        offset = int(row[1])
        if offset == 0:
            raise self._failure("VAULT_UNREADABLE")
        return offset

    def domains(self) -> tuple[tuple[str, str], ...]:
        rows = self._connection.execute(
            "SELECT domain_id, domain_kind FROM mapping_domains ORDER BY domain_id"
        ).fetchall()
        for row in rows:
            if not isinstance(row[0], str) or not isinstance(row[1], str):
                raise self._failure("VAULT_UNREADABLE")
        return tuple((str(row[0]), str(row[1])) for row in rows)


class _Findings:
    """Deterministic severity-aware aggregation of stable finding codes.

    FAIL findings (corruption, privacy/policy violation, missing or changed
    required data, mapping/receipt/identity mismatch) always win over
    PARTIAL findings (an unavailable verification dimension with every
    verified invariant intact); the authoritative status derivation is
    FAIL > PARTIAL > PASS, and a FAIL result reports every finding.
    """

    __slots__ = ("_failures", "_partials")

    def __init__(self) -> None:
        self._failures: set[str] = set()
        self._partials: set[str] = set()

    def fail(self, code: str) -> None:
        self._failures.add(code)

    def partial(self, code: str) -> None:
        self._partials.add(code)

    def codes(self) -> tuple[str, ...]:
        return tuple(sorted(self._failures | self._partials))

    def has_failure(self) -> bool:
        return bool(self._failures)

    def has_partial(self) -> bool:
        return bool(self._partials)

    def __bool__(self) -> bool:
        return self.has_failure() or self.has_partial()


def _output_table(
    output_root: Path,
    relative_path: str,
    *,
    owning_operation: str = "verify_dataset",
) -> DirectSourceTable:
    """Bind one OUTPUT table through the public Direct Read boundary.

    ``owning_operation`` is the OWNING public operation of the running
    verification (``verify_dataset`` for the standalone verifier,
    ``create_transfer_bundle`` when the REQ-P5-004 verified-dataset
    precondition reuses this internal core) — dependency errors keep the
    dbfbridge machine code and family but carry the true owner.
    """
    absolute = output_root / relative_path
    try:
        schema = dbfbridge.read_schema(absolute)  # type: ignore[attr-defined]
    except (CancellationError, CallbackError):
        raise
    except Exception as exc:
        raise DBFBridgeError.from_exception(
            exc,
            context=ErrorContext(
                operation=owning_operation,
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


def _verify_dataset_core(
    result: PseudonymizationResult,
    *,
    control: ProgressController,
    source_root: Path,
    output_root: Path,
    vault_path: Path,
    failure: Callable[[str], AnonymizerError] | None = None,
    owning_operation: str = "verify_dataset",
) -> VerificationResult:
    """The ONE P5-001 verification pipeline through a SUPPLIED controller.

    Drives every read-only verification stage through the caller's
    :class:`~dbf_anonymizer.progress.ProgressController` and returns the
    public verdict WITHOUT emitting any terminal completion: the public
    ``verify_dataset`` wrapper owns its single terminal event, and the
    internal REQ-P5-004 verified-dataset precondition of bundle creation
    reuses this core under the CREATE operation's controller and OWNING
    failure factory (every typed inability stays attributed to the
    create_transfer_bundle operation; cancellation and callback failures
    stay attributed to the owning public operation as well).
    """
    fail = failure if failure is not None else _verification_failure
    findings = _Findings()
    record_count = 0
    table_count = 0
    vault_reader = _VerifyVault(
        vault_path,
        operation=owning_operation,
        failure=fail,
    )
    try:
        record_count, table_count = _verify(
            result=result,
            control=control,
            findings=findings,
            source_root=source_root,
            output_root=output_root,
            vault_reader=vault_reader,
            failure=fail,
            owning_operation=owning_operation,
        )
    finally:
        vault_reader.close()

    # The authoritative PASS/PARTIAL/FAIL status (REQ-P5-001): FAIL always
    # wins over PARTIAL; PARTIAL is reserved for a genuinely unavailable
    # verification dimension while every verified invariant held; a clean
    # verified dataset is a truthful PASS.
    if findings.has_failure():
        status = VerificationStatus.FAIL
    elif findings.has_partial():
        status = VerificationStatus.PARTIAL
    else:
        status = VerificationStatus.PASS
    check_codes = findings.codes()

    verification_result = VerificationResult(
        status=status,
        dataset=result.dataset,
        operation_id=result.operation_id,
        table_count=table_count,
        record_count=record_count,
        check_codes=check_codes,
        assurance=result.assurance,
        output_data_state=result.output_data_state,
        index_artifacts=result.index_artifacts,
    )
    return verification_result


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
    versioned check codes. The evaluation itself is the shared internal
    core :func:`_verify_dataset_core` through this wrapper's controller.
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
    verification_result = _verify_dataset_core(
        result,
        control=control,
        source_root=source_root,
        output_root=output_root,
        vault_path=vault_path,
    )
    # The single terminal completion is emitted only now — after the public
    # result genuinely exists (never after cancellation).
    control.complete(completed=verification_result.table_count)
    return verification_result


def _iter_output_files(root: Path) -> Sequence[tuple[str, Path]]:
    """The canonical output inventory (the publication enumeration kernel)."""
    from dbf_anonymizer.engine.publication import _iter_dataset_files

    return tuple(_iter_dataset_files(root))


def _expected_output_inventory(
    table_paths: Sequence[str],
    *,
    source_root: Path,
    rebuilt_idx_paths: Sequence[str] = (),
) -> tuple[set[str], set[str], tuple[str, ...]]:
    """The exact expected output inventory from the SOURCE topology.

    One expected output DBF per planned table at the SAME normalized
    relative path (duplicate basenames in separate directories stay
    distinct — ownership is never inferred from the basename alone), plus
    one FPT companion per table whose SOURCE schema requires a memo
    companion (read-only public dbfbridge schema facts only).
    """
    expected: set[str] = set()
    memo_companions: set[str] = set()
    dbc_bound_tables: list[str] = []
    for relative_path in table_paths:
        expected.add(relative_path)
        table = read_source_table(source_root, relative_path)
        if table.schema.dbc_bound:
            dbc_bound_tables.append(relative_path)
        if table.has_memo_fields:
            memo_relative = Path(relative_path).with_suffix(".fpt").as_posix()
            expected.add(memo_relative)
            memo_companions.add(memo_relative)
    expected.update(rebuilt_idx_paths)
    return expected, memo_companions, tuple(dbc_bound_tables)


def _artifact_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _verify(
    *,
    result: PseudonymizationResult,
    control: ProgressController,
    findings: _Findings,
    source_root: Path,
    output_root: Path,
    vault_reader: _VerifyVault,
    failure: Callable[[str], AnonymizerError] | None = None,
    owning_operation: str = "verify_dataset",
) -> tuple[int, int]:
    """The bounded read-only verification pipeline (deterministic order)."""
    fail = failure if failure is not None else _verification_failure
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
        raise fail("SOURCE_UNREADABLE") from None
    if current_source != result.dataset.source_fingerprint:
        findings.fail("SOURCE_FINGERPRINT_MISMATCH")

    # --- TOPOLOGY: expected output inventory from the SOURCE topology --------
    rebuilt_idx_paths = tuple(
        item.artifact_path
        for item in result.index_artifacts
        if item.status == "REBUILT_VERIFIED"
    )
    rebuilt_idx_set = set(rebuilt_idx_paths)
    expected_output, expected_memo_companions, observed_dbc_bound_tables = (
        _expected_output_inventory(
            dataset.table_paths,
            source_root=source_root,
            rebuilt_idx_paths=rebuilt_idx_paths,
        )
    )
    if observed_dbc_bound_tables != dataset.dbc_bound_table_paths:
        findings.fail("SOURCE_DBC_INVENTORY_MISMATCH")
    try:
        output_inventory = _iter_output_files(output_root)
    except Exception:
        raise fail("OUTPUT_UNREADABLE") from None
    output_paths = {relative for relative, _path in output_inventory}
    for relative in sorted(expected_output - output_paths):
        if relative in expected_memo_companions:
            findings.fail("MEMO_COMPANION_MISSING")
        elif relative in rebuilt_idx_set:
            findings.fail("STANDALONE_IDX_EVIDENCE_MISMATCH")
        else:
            findings.fail("TABLE_MISSING")
    for relative in sorted(output_paths - expected_output):
        suffix = Path(relative).suffix.lower()
        if suffix == ".idx":
            findings.fail("STANDALONE_IDX_EVIDENCE_MISMATCH")
        elif suffix in _INDEX_ARTIFACT_SUFFIXES:
            findings.partial("INDEX_ARTIFACT_UNVERIFIED")
        else:
            findings.fail("UNEXPECTED_OUTPUT_ARTIFACT")

    # --- REQ-P6-004: durable per-IDX provenance and artifact binding ---------
    for item in result.index_artifacts:
        control.check_cancelled()
        source_idx = source_root / item.artifact_path
        try:
            if _artifact_sha256(source_idx) != item.source_sha256:
                findings.fail("STANDALONE_IDX_EVIDENCE_MISMATCH")
        except OSError:
            findings.fail("STANDALONE_IDX_EVIDENCE_MISMATCH")
        if item.status == "OMITTED_UNVERIFIED":
            findings.partial("STANDALONE_IDX_DEFINITION_UNAVAILABLE")
        elif item.status == "REBUILT_VERIFIED":
            output_idx = output_root / item.artifact_path
            try:
                if (
                    item.output_sha256 is None
                    or _artifact_sha256(output_idx) != item.output_sha256
                ):
                    findings.fail("STANDALONE_IDX_EVIDENCE_MISMATCH")
            except OSError:
                findings.fail("STANDALONE_IDX_EVIDENCE_MISMATCH")

    # --- VAULT VERIFICATION: identity, binding, receipt, mappings ------------
    control.start_phase(ProgressPhase.VAULT_VERIFICATION)
    _verify_vault(result, control, findings, vault_reader, output_root)

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
            failure=fail,
            owning_operation=owning_operation,
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
    except (CancellationError, CallbackError):
        raise
    except Exception:
        raise fail("OUTPUT_UNREADABLE") from None
    if current_output != result.output_fingerprint:
        findings.fail("OUTPUT_FINGERPRINT_MISMATCH")

    # Aggregated truthfulness: the scanned totals must match the public claim.
    if table_count != result.table_count or record_count != result.record_count:
        findings.fail("RECORD_COUNT_MISMATCH")
    return record_count, table_count


def _verify_vault(
    result: PseudonymizationResult,
    control: ProgressController,
    findings: _Findings,
    vault_reader: _VerifyVault,
    output_root: Path,
) -> None:
    """Read-only durable-state verification (identity, receipt, mappings).

    Enforces the COMPLETE identity consistency among the vault dataset row,
    the completed operation row, the receipt, the derived publication
    binding (recomputed read-only through the shared publication identity
    kernels) and the public result: source/policy/relationship fingerprints,
    vault fingerprint, destination identity, binding fingerprint and the
    output fingerprint must all agree for the SAME operation.
    """
    dataset_row = vault_reader.dataset_row()
    if dataset_row[0] != result.dataset.source_fingerprint:
        findings.fail("VAULT_IDENTITY_MISMATCH")
    if dataset_row[2] != result.assurance.relationship_fingerprint:
        findings.fail("VAULT_IDENTITY_MISMATCH")

    operation = vault_reader.completed_operation(result.operation_id)
    if operation is None or operation["state"] != VAULT_OPERATION_STATE_COMPLETED:
        findings.fail("OPERATION_NOT_COMPLETED")
        return
    # Every stored identity of the SAME operation must agree with the
    # dataset row and the public claim — policy included.
    identity_agreements = (
        (operation["source_fingerprint"], dataset_row[0]),
        (operation["policy_fingerprint"], dataset_row[1]),
        (operation["relationship_fingerprint"], dataset_row[2]),
        (operation["source_fingerprint"], result.dataset.source_fingerprint),
        (operation["relationship_fingerprint"], result.assurance.relationship_fingerprint),
        (operation["output_fingerprint"], result.output_fingerprint),
    )
    for stored, expected in identity_agreements:
        if stored is None or stored != expected:
            findings.fail("VAULT_IDENTITY_MISMATCH")

    # The full publication binding is recomputed READ-ONLY through the ONE
    # shared publication identity kernels (never duplicated hash recipes).
    destination_identity = derive_destination_identity(output_root)
    expected_vault_fingerprint = derive_vault_fingerprint(
        schema_version=vault_reader.schema_version,
        vault_id=vault_reader.vault_id,
        source_fingerprint=dataset_row[0],
        policy_fingerprint=dataset_row[1],
        relationship_fingerprint=dataset_row[2],
    )
    expected_binding = derive_binding_fingerprint(
        source_fingerprint=dataset_row[0],
        policy_fingerprint=dataset_row[1],
        relationship_fingerprint=dataset_row[2],
        vault_fingerprint=expected_vault_fingerprint,
        destination_identity=destination_identity,
    )
    if operation["vault_fingerprint"] != expected_vault_fingerprint:
        findings.fail("VAULT_IDENTITY_MISMATCH")
    if operation["destination_identity"] != destination_identity:
        findings.fail("VAULT_IDENTITY_MISMATCH")
    if operation["binding_fingerprint"] != expected_binding:
        findings.fail("VAULT_IDENTITY_MISMATCH")

    receipt_json = operation["result_json"]
    if receipt_json is None:
        findings.fail("RECEIPT_IDENTITY_MISMATCH")
        return
    try:
        receipt = result_from_receipt(receipt_json)
    except Exception:
        findings.fail("RECEIPT_IDENTITY_MISMATCH")
        return
    if receipt.operation_id != result.operation_id:
        findings.fail("RECEIPT_IDENTITY_MISMATCH")
    if receipt.output_fingerprint != result.output_fingerprint:
        findings.fail("RECEIPT_FINGERPRINT_MISMATCH")
    if receipt.index_artifacts != result.index_artifacts:
        findings.fail("RECEIPT_IDENTITY_MISMATCH")

    # The public relational assurance is cross-validated against the DURABLE
    # receipt evidence (never simply trusted).
    _verify_assurance(result.assurance, receipt.relations, findings)

    # Mapping-domain invariants per kind: bijection + NULL never mapped for
    # TEXT, bijection for NUMERIC_KEY, non-zero parameter existence for
    # TEMPORAL, and a fail-closed refusal for unknown/corrupt kinds.
    for domain_id, domain_kind in vault_reader.domains():
        control.check_cancelled()
        if domain_kind == VAULT_TABLE_DOMAIN_KIND_TEXT:
            count, distinct_originals, distinct_pseudonyms = (
                vault_reader.domain_bijection(domain_id, "text_mappings")
            )
            if count != distinct_originals or count != distinct_pseudonyms:
                findings.fail("VAULT_MAPPING_INVALID")
            if vault_reader.empty_text_originals(domain_id):
                # NULL/empty is a preserved identity and is never mapped.
                findings.fail("VAULT_MAPPING_INVALID")
        elif domain_kind == VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY:
            count, distinct_originals, distinct_pseudonyms = (
                vault_reader.domain_bijection(domain_id, "numeric_key_mappings")
            )
            if count != distinct_originals or count != distinct_pseudonyms:
                findings.fail("VAULT_MAPPING_INVALID")
        elif domain_kind == VAULT_TABLE_DOMAIN_KIND_TEMPORAL:
            # The persisted temporal parameter must be a genuine non-zero
            # reversible shift (typed corruption otherwise).
            vault_reader.temporal_offset(domain_id)
        else:
            # Unknown/corrupt domain kinds can never be silently treated as
            # numeric or text state.
            findings.fail("VAULT_MAPPING_INVALID")
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
        findings.fail("ASSURANCE_EVIDENCE_MISMATCH")
        return
    if declared == 0:
        if assurance.level is not RelationalAssuranceLevel.GLOBAL_EXACT_VALUE:
            findings.fail("ASSURANCE_EVIDENCE_MISMATCH")
    elif verified == declared and failed == 0:
        # Ordinary P3/P4 relation evidence establishes at most
        # DECLARED_RELATIONS_VERIFIED: VFP_METADATA_VERIFIED without the
        # authoritative P6 evidence input is an assurance overclaim that
        # the read-only verifier can never confirm (REQ-P3-007).
        if assurance.level is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED:
            pass
        else:
            findings.fail("ASSURANCE_EVIDENCE_MISMATCH")
    elif assurance.level is not RelationalAssuranceLevel.INCOMPLETE:
        findings.fail("ASSURANCE_EVIDENCE_MISMATCH")


def _verify_table(
    *,
    relative_path: str,
    source_root: Path,
    output_root: Path,
    vault_reader: _VerifyVault,
    findings: _Findings,
    checkpoint: Callable[[], None],
    failure: Callable[[str], AnonymizerError] | None = None,
    owning_operation: str = "verify_dataset",
) -> int:
    """One streamed source/output table comparison (O(1) memory).

    Compares logical schema facts and streams both sides in lockstep through
    the public dbfbridge boundary: physical order, deleted markers, record
    counts, NULL semantics and every transformed-field postcondition derived
    from the durable policy application (text/numeric/memo/temporal).
    """
    fail = failure if failure is not None else _verification_failure
    try:
        source_table = read_source_table(
            source_root, relative_path, cancel_check=checkpoint
        )
    except (CancellationError, CallbackError):
        raise
    except Exception:
        raise fail("SOURCE_UNREADABLE") from None
    output_table = _output_table(output_root, relative_path, owning_operation=owning_operation)
    if (
        output_table.schema.dbc_bound
        or output_table.schema.dbc_backlink_path is not None
        or output_table.schema.is_database_container
    ):
        findings.fail("OUTPUT_DBC_COUPLING_PRESENT")
        return 0
    if _schema_facts(source_table) != _schema_facts(output_table):
        findings.fail("SCHEMA_MISMATCH")
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
                operation=owning_operation,
                table_path=relative_path,
                detail_code="VERIFY_RECORD_STREAM_UNREADABLE",
            ),
        ) from None

    table_id = vault_reader.table_rows().get(relative_path)
    if table_id is None:
        # No durable table identity: the policy ledger for this table cannot
        # exist, so no per-field postcondition is verifiable (fail closed).
        findings.fail("POLICY_BINDING_MISSING")
        return 0
    fields = _verify_field_ledger(
        source_table,
        vault_reader.field_rows(table_id),
        vault_reader=vault_reader,
        findings=findings,
    )
    scanned = 0
    try:
        for source_record, output_record in zip(source_stream, output_stream):
            checkpoint()
            scanned += 1
            if source_record.physical_index != output_record.physical_index:
                findings.fail("RECORD_ORDER_MISMATCH")
                break
            if source_record.deleted != output_record.deleted:
                findings.fail("DELETED_MARKER_MISMATCH")
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
            findings.fail("RECORD_COUNT_MISMATCH")
    except (CancellationError, CallbackError):
        raise
    return scanned


def _verify_field_ledger(
    source_table: DirectSourceTable,
    rows: Sequence[tuple[str, str, str, int, str | None, str | None, str | None]],
    *,
    vault_reader: _VerifyVault,
    findings: _Findings,
) -> dict[str, tuple[str, str, str | None, str | None]]:
    """The complete durable field-policy ledger check (REQ-P5-001).

    Every non-system field of the source schema MUST carry exactly one
    explicit durable action — absence of evidence never means KEEP. The
    binding must be structurally consistent with the source schema facts
    (type, width, encoding), the action must be one of the bounded ledger
    actions, and the mapping-domain identity must be present and of the
    appropriate kind for the action (KEEP/MASK carry none). Violations are
    stable FAIL findings; no field values are ever exposed.
    """
    schema_facts: dict[str, tuple[str, int, str]] = {}
    for field in source_table.schema.fields:
        name = str(field.name)
        if str(field.dbf_type).upper() == "0":
            continue  # writer-managed system state (_NullFlags)
        schema_facts[name] = (
            str(field.dbf_type).upper(),
            int(field.length),
            str(source_table.schema.encoding),
        )
    bindings: dict[str, tuple[str, str, str | None, str | None]] = {}
    for field_id, name, dbf_type, width, encoding, action, domain_id in rows:
        if name in bindings:
            # Duplicate field bindings can never define one coherent policy.
            findings.fail("POLICY_BINDING_MISMATCH")
            continue
        bindings[name] = (field_id, dbf_type, action, domain_id)
        if name not in schema_facts:
            findings.fail("POLICY_BINDING_MISMATCH")
            continue
        expected_type, expected_width, expected_encoding = schema_facts[name]
        if dbf_type != expected_type or width != expected_width or (
            encoding != expected_encoding
        ):
            findings.fail("POLICY_BINDING_MISMATCH")
        if action not in _LEDGER_ACTIONS:
            findings.fail("POLICY_BINDING_MISMATCH")
            continue
        domain_kind = (
            vault_reader.domain_kind(domain_id) if domain_id is not None else None
        )
        if action == "KEEP" or action == "MASK_REVERSIBLE":
            if domain_id is not None:
                findings.fail("POLICY_BINDING_MISMATCH")
        elif action == "PSEUDONYMIZE_REVERSIBLE":
            if domain_id is None or domain_kind not in (
                VAULT_TABLE_DOMAIN_KIND_TEXT,
                VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
            ):
                findings.fail("POLICY_BINDING_MISMATCH")
        elif action == "SHIFT_REVERSIBLE":
            if domain_id is not None and domain_kind not in (
                VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
            ):
                findings.fail("POLICY_BINDING_MISMATCH")
    for name in schema_facts:
        if name not in bindings:
            # Absence of evidence is never an identity decision (REQ-P5-001).
            findings.fail("POLICY_BINDING_MISSING")
    return bindings


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
            # Absence of evidence is never an identity decision (REQ-P5-001):
            # the ledger check has already reported the missing binding, and
            # no original value can be accepted as a legitimate identity.
            findings.fail("POLICY_BINDING_MISSING")
            continue
        field_id, field_type, action, domain_id = binding
        source_value = source_values.get(name)
        output_value = output_values.get(name)
        if action == "KEEP":
            if source_values.get(name) != output_values.get(name):
                findings.fail("IDENTITY_VALUE_MISMATCH")
        elif action == "MASK_REVERSIBLE":
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
            if offset is None:
                # An EMPTY finalized temporal domain: logical identity is the
                # only legitimate state (every observed occurrence was NULL).
                if output_value != source_value:
                    findings.fail("TEMPORAL_VALUE_MISMATCH")
            elif output_value != temporal_shift(source_value, offset):
                findings.fail("TEMPORAL_VALUE_MISMATCH")
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
            findings.fail("POLICY_BINDING_MISMATCH")


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
            findings.fail("NULL_SEMANTICS_MISMATCH")
        return
    if output_value is None or not isinstance(output_value, str):
        findings.fail("NULL_SEMANTICS_MISMATCH")
        return
    if output_value == source_value:
        findings.fail("ORIGINAL_VALUE_SURVIVED")
        return
    if vault_reader.text_original(domain_id, output_value) != source_value:
        findings.fail("TEXT_MAPPING_MISMATCH")


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
            findings.fail("NULL_SEMANTICS_MISMATCH")
        return
    if output_value is None:
        findings.fail("NULL_SEMANTICS_MISMATCH")
        return
    if isinstance(output_value, bool) or not isinstance(output_value, int):
        findings.fail("NUMERIC_MAPPING_MISMATCH")
        return
    if output_value == source_value:
        findings.fail("ORIGINAL_VALUE_SURVIVED")
        return
    if vault_reader.numeric_original(
        domain_id, canonical_integer_text(output_value)
    ) != canonical_integer_text(source_value):
        findings.fail("NUMERIC_MAPPING_MISMATCH")


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
            findings.fail("NULL_SEMANTICS_MISMATCH")
        return
    if output_value is None:
        findings.fail("NULL_SEMANTICS_MISMATCH")
        return
    if table_id is None:
        findings.fail("MEMO_RECOVERY_ROW_MISSING")
        return
    recovery = vault_reader.memo_recovery_row(table_id, physical_index, field_id)
    if recovery is None:
        findings.fail("MEMO_RECOVERY_ROW_MISSING")
        return
    original, payload_kind = recovery
    if payload_kind == "TEXT" and not isinstance(output_value, str):
        findings.fail("MEMO_PAYLOAD_MISMATCH")
        return
    if payload_kind == "BINARY" and not isinstance(output_value, bytes):
        findings.fail("MEMO_PAYLOAD_MISMATCH")
        return
    original_logical: object = (
        original.decode("utf-8") if payload_kind == "TEXT" else original
    )
    if original_logical != source_value:
        findings.fail("MEMO_PAYLOAD_MISMATCH")
        return
    if output_value == original_logical:
        findings.fail("MEMO_PAYLOAD_MISMATCH")
        return
    if output_value != mask_memo_value(dbf_type, original_logical):
        findings.fail("MEMO_PAYLOAD_MISMATCH")
