"""Protected canonical dataset recovery (REQ-P5-002/REQ-P5-003).

``recover`` is the public REQ-P1-004/REQ-P1-008 service slice that
reconstructs the ORIGINAL logical DBF/FPT dataset from exactly two inputs —
the PSEUDONYMIZED working dataset plus the MATCHING protected SQLite vault.
The original source dataset is NEVER required, opened or inspected by
production recovery.

Authority is validated READ-ONLY and fail-closed BEFORE any byte is written:
the immutable ``mode=ro&immutable=1`` snapshot reader (shared with the
REQ-P5-001 verifier) proves the vault identity, the completed
pseudonymization operation binding (recomputed through the ONE shared
publication identity kernels), the pseudonymized dataset fingerprint, the
COMPLETE durable field-policy ledger, the mapping-domain bijections and the
temporal parameters. Ambiguous SQLite sidecar state makes recovery
impossible without mutating the protected store and fails closed.

Recovery then streams every pseudonymized table through the public dbfbridge
Direct Read boundary, reverses the durable policy application per field —
KEEP identity, text/numeric reverse mappings, protected memo recovery
payloads, reversible temporal shifts, NULL preservation, deleted markers and
physical order — writes fresh DBF/FPT staging through the public Direct
Write boundary, self-verifies the ENTIRE staged dataset against the same
authoritative recovery state (a successful DBF write alone is never
sufficient), and only then atomically promotes it with the existing P4
publication kernels under a real OS destination lock.

The recovery operation identity is clearly distinct from the pseudonymization
operation it recovers: the vault is never written, no operation row is
created and the invocation id is the controller's own bounded ``op-`` token,
shared by every progress event and the public result. Canonical success is
LOGICAL DATA + SCHEMA EQUIVALENCE (proven by the staged self-verification);
the separate raw DBF/FPT byte fact is truthfully ``NOT_EVALUATED`` in
production because no objective original-vs-recovered byte comparison oracle
exists without the source.

Original values, memo/binary payloads, reverse mappings, temporal offsets
and absolute private paths never appear in any public result, error,
progress event or log.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Iterator, Sequence

import dbfbridge
from dbfbridge import DirectRecord  # type: ignore[attr-defined]

from dbf_anonymizer.engine.direct_io import (
    DirectSourceTable,
    read_source_table,
    stream_table_records,
    write_fresh_table,
)
from dbf_anonymizer.engine.locking import DestinationLock
from dbf_anonymizer.engine.publication import (
    DatasetStaging,
    PublicationIdentity,
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
    PathError,
    RecoveryError,
)
from dbf_anonymizer.models import (
    PseudonymizationResult,
    RawByteEquivalence,
    RecoveryResult,
)
from dbf_anonymizer.preflight import _paths_overlap
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)
from dbf_anonymizer.transforms.numeric_keys import (
    canonical_integer_text,
    parse_canonical_integer_text,
)
from dbf_anonymizer.transforms.temporal import temporal_shift
from dbf_anonymizer.verification import _Findings, _VerifyVault, _verify_field_ledger
from dbf_anonymizer.vault.schema import (
    VAULT_OPERATION_STATE_COMPLETED,
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
)

__all__ = ["recover"]

_RECOVER_OPERATION = "recover"


def _recovery_failure(detail_code: str) -> RecoveryError:
    """Stable typed, value-free recovery inability (no protected values)."""
    return RecoveryError(
        ErrorCode.RECOVERY_FAILED,
        context=ErrorContext(operation=_RECOVER_OPERATION, detail_code=detail_code),
    )


def _recovery_target_conflict(detail_code: str) -> PathError:
    return PathError(
        ErrorCode.DESTINATION_CONFLICT,
        context=ErrorContext(operation=_RECOVER_OPERATION, detail_code=detail_code),
    )


def _ledger_failure(findings: _Findings) -> RecoveryError:
    """The typed refusal for an incomplete/incompatible policy ledger."""
    return _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")


def _recovery_identity(
    *,
    destination: Path,
    vault_reader: _VerifyVault,
    source_fingerprint: str,
    policy_fingerprint: str,
    relationship_fingerprint: str,
    operation_id: str,
) -> PublicationIdentity:
    """The recovery staging/lock identity (distinct from pseudonymization).

    The recovery destination, its canonical identity, the re-derived vault
    and binding fingerprints and the RECOVERY invocation id form a clearly
    distinct ownership identity: recovery never overloads the original
    pseudonymization operation row and never writes durable vault state.
    """
    destination_identity = derive_destination_identity(destination)
    vault_fingerprint = derive_vault_fingerprint(
        schema_version=vault_reader.schema_version,
        vault_id=vault_reader.vault_id,
        source_fingerprint=source_fingerprint,
        policy_fingerprint=policy_fingerprint,
        relationship_fingerprint=relationship_fingerprint,
    )
    binding_fingerprint = derive_binding_fingerprint(
        source_fingerprint=source_fingerprint,
        policy_fingerprint=policy_fingerprint,
        relationship_fingerprint=relationship_fingerprint,
        vault_fingerprint=vault_fingerprint,
        destination_identity=destination_identity,
    )
    sibling_token = hashlib.sha256(
        f"recovery-{destination_identity}".encode("ascii")
    ).hexdigest()[:24]
    parent = destination.resolve(strict=False).parent
    return PublicationIdentity(
        operation_id=operation_id,
        destination=destination.resolve(strict=False),
        destination_identity=destination_identity,
        vault_fingerprint=vault_fingerprint,
        binding_fingerprint=binding_fingerprint,
        lock_path=parent / f".dbf-anonymizer-{sibling_token}.lock",
        staging_root=parent / f".dbf-anonymizer-{sibling_token}.staging",
    )


def recover(
    pseudonymized: PseudonymizationResult,
    *,
    vault: str | Path,
    output: str | Path,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> RecoveryResult:
    """Reconstruct the original logical dataset (REQ-P5-002/REQ-P5-003).

    Production recovery requires ONLY the pseudonymized working dataset and
    the matching protected vault; the original source is never required,
    opened or inspected. The protected vault is validated READ-ONLY and
    fail-closed (schema, identity coherence, the matching completed
    pseudonymization operation, the pseudonymized dataset fingerprint, the
    complete durable field-policy ledger, mapping bijections and temporal
    parameters) before anything is written; ambiguous sidecar state fails
    closed because trustworthy recovery never mutates SQLite state.

    Every recovered DBF/FPT is written fresh through the public dbfbridge
    boundary into complete staging, the ENTIRE staged dataset is then
    self-verified against the authoritative recovery state (record streams,
    deleted markers, NULL semantics and every reverse postcondition), and
    only then is the recovery atomically promoted through the existing P4
    publication kernels. Cancellation before promotion leaves no final
    recovered tree and cleans owned staging; the pseudonymized input and the
    protected vault are never modified.

    REQ-P1-008: ONE :class:`ProgressController` (``operation="recover"``)
    with one bounded invocation id drives the bounded phases; the single
    terminal completion is emitted only after the genuine atomic promotion
    (never after a pre-publication cancellation, rejection or callback
    failure, and never with a post-promotion cancellation poll).

    The public verdict is CANONICAL LOGICAL + SCHEMA EQUIVALENCE; the raw
    DBF/FPT byte fact is truthfully ``NOT_EVALUATED`` because no
    original-source comparison oracle exists in production.
    """
    if not isinstance(pseudonymized, PseudonymizationResult):
        raise TypeError("recover requires a PseudonymizationResult")
    context = pseudonymized.execution_context
    if context is None:
        raise _recovery_failure("RECOVERY_PSEUDONYMIZED_CONTEXT_MISSING")
    pseudonymized_root = Path(context.output_root)
    vault_path = Path(vault)
    destination = Path(output)
    if destination.exists():
        raise _recovery_target_conflict("RECOVERY_TARGET_EXISTS")
    if _paths_overlap(pseudonymized_root, destination, vault_path.parent):
        raise _recovery_target_conflict("RECOVERY_TARGET_OVERLAP")

    control = ProgressController(
        operation=_RECOVER_OPERATION, progress=progress, cancel_check=cancel_check
    )
    control.start_phase(ProgressPhase.OPERATION)
    invocation_id = control.operation_id

    # --- 1. Read-only protected-state authority (fail closed) ---------------
    control.start_phase(ProgressPhase.VAULT_VERIFICATION)
    vault_reader = _VerifyVault(
        vault_path, operation=_RECOVER_OPERATION, failure=_recovery_failure
    )
    try:
        identity = _validate_recovery_authority(
            pseudonymized,
            control=control,
            pseudonymized_root=pseudonymized_root,
            vault_reader=vault_reader,
        )

        # --- 2..5. Staged streaming recovery, self-verification, publication
        recovery_identity = _recovery_identity(
            destination=destination,
            vault_reader=vault_reader,
            source_fingerprint=identity.source_fingerprint,
            policy_fingerprint=identity.policy_fingerprint,
            relationship_fingerprint=identity.relationship_fingerprint,
            operation_id=invocation_id,
        )
        staging = DatasetStaging(recovery_identity)
        try:
            with DestinationLock(recovery_identity.lock_path):
                control.check_cancelled()
                staging.create()
                try:
                    table_count, record_count = _recover_tables(
                        pseudonymized=pseudonymized,
                        control=control,
                        pseudonymized_root=pseudonymized_root,
                        staging=staging,
                        vault_reader=vault_reader,
                        ledger=identity.ledger,
                    )
                    _verify_staged_recovery(
                        control=control,
                        pseudonymized_root=pseudonymized_root,
                        staging=staging,
                        vault_reader=vault_reader,
                        ledger=identity.ledger,
                        expected_tables=table_count,
                        expected_records=record_count,
                    )
                    control.start_phase(ProgressPhase.PUBLICATION)
                    # The last cancellation checkpoint immediately before the
                    # atomic promotion (inside the publication phase); after
                    # that the committed publication is never reclassified by
                    # a late poll.
                    control.check_cancelled()
                    staging.promote()
                    staging.remove_metadata_after_promotion()
                except BaseException:
                    # Best-effort owned staging cleanup: a cleanup failure is
                    # never allowed to mask the primary failure
                    # classification (REQ-P5-002 failure contract).
                    try:
                        staging.cleanup_owned()
                    except Exception:
                        pass
                    raise
        except (CancellationError, CallbackError):
            raise
    finally:
        # The read-only immutable snapshot connection stays open across the
        # whole recovery and is ALWAYS closed afterwards (read-only close is
        # side-effect-free; no WAL/SHM state is created or changed).
        vault_reader.close()
    result = RecoveryResult(
        operation_id=invocation_id,
        dataset=pseudonymized.dataset,
        output_path=destination.name,
        table_count=table_count,
        record_count=record_count,
        canonical_verified=True,
        raw_byte_equivalence=RawByteEquivalence.NOT_EVALUATED,
    )
    # The single terminal completion is emitted only now — after the genuine
    # atomic promotion and the public result (never after cancellation, and
    # never with a post-promotion cancellation poll).
    control.complete(completed=record_count, check_cancel=False)
    return result


class _RecoveryAuthority:
    """The bounded read-only authority facts consumed by the recovery."""

    __slots__ = ("source_fingerprint", "policy_fingerprint", "relationship_fingerprint", "ledger")

    def __init__(
        self,
        *,
        source_fingerprint: str,
        policy_fingerprint: str,
        relationship_fingerprint: str,
        ledger: dict[str, dict[str, tuple[str, str, str | None, str | None]]],
    ) -> None:
        self.source_fingerprint = source_fingerprint
        self.policy_fingerprint = policy_fingerprint
        self.relationship_fingerprint = relationship_fingerprint
        self.ledger = ledger


def _validate_recovery_authority(
    pseudonymized: PseudonymizationResult,
    *,
    control: ProgressController,
    pseudonymized_root: Path,
    vault_reader: _VerifyVault,
) -> _RecoveryAuthority:
    """The read-only fail-closed recovery authority (REQ-P5-002 step 1).

    Proves, without any mutation: the completed pseudonymization operation
    binding (recomputed through the shared publication identity kernels),
    the pseudonymized dataset fingerprint, the COMPLETE durable field-policy
    ledger for every planned table, the mapping-domain bijections and the
    temporal parameters. Returns the bounded authority facts the streaming
    recovery consumes.
    """
    dataset_row = vault_reader.dataset_row()
    operation = vault_reader.completed_operation(pseudonymized.operation_id)
    if operation is None or operation["state"] != VAULT_OPERATION_STATE_COMPLETED:
        raise _recovery_failure("RECOVERY_OPERATION_NOT_COMPLETED")
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
        destination_identity=derive_destination_identity(pseudonymized_root),
    )
    agreements = (
        (operation["source_fingerprint"], dataset_row[0]),
        (operation["policy_fingerprint"], dataset_row[1]),
        (operation["relationship_fingerprint"], dataset_row[2]),
        (
            operation["source_fingerprint"],
            pseudonymized.dataset.source_fingerprint,
        ),
        (
            operation["relationship_fingerprint"],
            pseudonymized.assurance.relationship_fingerprint,
        ),
        (operation["vault_fingerprint"], expected_vault_fingerprint),
        (operation["binding_fingerprint"], expected_binding),
        (
            operation["destination_identity"],
            derive_destination_identity(pseudonymized_root),
        ),
        (operation["output_fingerprint"], pseudonymized.output_fingerprint),
    )
    for stored, expected in agreements:
        if stored is None or stored != expected:
            raise _recovery_failure("RECOVERY_IDENTITY_MISMATCH")
    receipt_json = operation["result_json"]
    if receipt_json is None:
        raise _recovery_failure("RECOVERY_OPERATION_NOT_COMPLETED")
    try:
        receipt = result_from_receipt(receipt_json)
    except Exception:
        raise _recovery_failure("RECOVERY_OPERATION_NOT_COMPLETED") from None
    if receipt.operation_id != pseudonymized.operation_id:
        raise _recovery_failure("RECOVERY_IDENTITY_MISMATCH")
    if receipt.output_fingerprint != pseudonymized.output_fingerprint:
        raise _recovery_failure("RECOVERY_RECEIPT_MISMATCH")

    # The pseudonymized dataset must still BE the durable publication state.
    control.check_cancelled()
    current_pseudonymized = fingerprint_dataset(
        pseudonymized_root, checkpoint=control.check_cancelled
    )
    if current_pseudonymized != pseudonymized.output_fingerprint:
        raise _recovery_failure("RECOVERY_PSEUDONYMIZED_MISMATCH")

    # Mapping-domain kinds must be coherent and reverse mappings unique.
    for domain_id, domain_kind in vault_reader.domains():
        control.check_cancelled()
        if domain_kind == VAULT_TABLE_DOMAIN_KIND_TEXT:
            count, distinct_originals, distinct_pseudonyms = (
                vault_reader.domain_bijection(domain_id, "text_mappings")
            )
            if count != distinct_originals or count != distinct_pseudonyms:
                raise _recovery_failure("RECOVERY_MAPPING_INVALID")
            if vault_reader.empty_text_originals(domain_id):
                raise _recovery_failure("RECOVERY_MAPPING_INVALID")
        elif domain_kind == VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY:
            count, distinct_originals, distinct_pseudonyms = (
                vault_reader.domain_bijection(domain_id, "numeric_key_mappings")
            )
            if count != distinct_originals or count != distinct_pseudonyms:
                raise _recovery_failure("RECOVERY_MAPPING_INVALID")
        elif domain_kind == VAULT_TABLE_DOMAIN_KIND_TEMPORAL:
            # The persisted temporal parameter must exist and be a genuine
            # non-zero reversible shift for the domain (typed corruption
            # otherwise; a missing parameter can never mean "no shift").
            if vault_reader.temporal_offset(domain_id) is None:
                raise _recovery_failure("RECOVERY_MAPPING_INVALID")
        else:
            raise _recovery_failure("RECOVERY_MAPPING_INVALID")

    # The COMPLETE durable field-policy ledger (shared with the verifier).
    vault_tables = vault_reader.table_rows()
    ledger: dict[str, dict[str, tuple[str, str, str | None, str | None]]] = {}
    for relative_path in pseudonymized.dataset.table_paths:
        control.check_cancelled()
        table_id = vault_tables.get(relative_path)
        if table_id is None:
            raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
        table = read_source_table(
            pseudonymized_root, relative_path, cancel_check=control.check_cancelled
        )
        findings = _Findings()
        ledger[relative_path] = _verify_field_ledger(
            table,
            vault_reader.field_rows(table_id),
            vault_reader=vault_reader,
            findings=findings,
        )
        if findings:
            raise _ledger_failure(findings)
    if len(vault_tables) != len(pseudonymized.dataset.table_paths):
        raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
    return _RecoveryAuthority(
        source_fingerprint=dataset_row[0],
        policy_fingerprint=dataset_row[1],
        relationship_fingerprint=dataset_row[2],
        ledger=ledger,
    )


def _reverse_value(
    *,
    action: str | None,
    domain_id: str | None,
    dbf_type: str,
    pseudonymized_value: object,
    physical_index: int,
    table_id: str,
    field_id: str,
    temporal_offset: int | None,
    vault_reader: _VerifyVault,
) -> object:
    """The typed reverse application of ONE durable field-policy action."""
    if action is None:
        raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
    if action == "KEEP":
        return pseudonymized_value
    if action == "MASK_REVERSIBLE":
        if pseudonymized_value is None:
            # NULL preserves NULL: the protected store holds no recovery row
            # for a NULL payload by design (REQ-P2-007 NULL semantics).
            return None
        recovery = vault_reader.memo_recovery_row(
            table_id, physical_index, field_id
        )
        if recovery is None:
            raise _recovery_failure("RECOVERY_RECOVERY_ROW_MISSING")
        original, payload_kind = recovery
        if payload_kind == "TEXT":
            return original.decode("utf-8")
        return original
    if action == "SHIFT_REVERSIBLE":
        if temporal_offset is None:
            # An EMPTY finalized temporal domain: the only legitimate state.
            return pseudonymized_value if pseudonymized_value is None else None
        return temporal_shift(pseudonymized_value, -temporal_offset)
    if action == "PSEUDONYMIZE_REVERSIBLE":
        if pseudonymized_value is None or pseudonymized_value == "":
            return pseudonymized_value
        if domain_id is None:
            raise _recovery_failure("RECOVERY_MAPPING_MISSING")
        if vault_reader.domain_kind(domain_id) == VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY:
            if isinstance(pseudonymized_value, bool) or not isinstance(
                pseudonymized_value, int
            ):
                raise _recovery_failure("RECOVERY_MAPPING_INVALID")
            original_text = vault_reader.numeric_original(
                domain_id, canonical_integer_text(pseudonymized_value)
            )
            if original_text is None:
                raise _recovery_failure("RECOVERY_MAPPING_MISSING")
            return parse_canonical_integer_text(original_text)
        if not isinstance(pseudonymized_value, str):
            raise _recovery_failure("RECOVERY_MAPPING_INVALID")
        original_text = vault_reader.text_original(domain_id, pseudonymized_value)
        if original_text is None:
            raise _recovery_failure("RECOVERY_MAPPING_MISSING")
        return original_text
    # Unknown durable action: fail closed, never guess.
    raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")


def _recover_tables(
    *,
    pseudonymized: PseudonymizationResult,
    control: ProgressController,
    pseudonymized_root: Path,
    staging: DatasetStaging,
    vault_reader: _VerifyVault,
    ledger: dict[str, dict[str, tuple[str, str, str | None, str | None]]],
) -> tuple[int, int]:
    """The streaming staged recovery of every planned table (REQ-P5-002).

    One pseudonymized table at a time: bounded-memory streaming generation
    of fresh original logical values through the public dbfbridge Direct
    Read/Write boundaries, complete FPT companions included, deleted
    markers and physical order preserved.
    """
    control.start_phase(ProgressPhase.RECOVERY_SCAN, total=len(pseudonymized.dataset.table_paths))
    table_count = 0
    record_count = 0
    for index, relative_path in enumerate(pseudonymized.dataset.table_paths):
        control.check_cancelled()
        table = read_source_table(
            pseudonymized_root, relative_path, cancel_check=control.check_cancelled
        )
        table_id = vault_reader.table_rows().get(relative_path)
        if table_id is None:
            raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
        bindings = ledger[relative_path]
        memo_policy = "inline" if table.has_memo_fields else "skip"
        destination = staging.table_destination(index, relative_path)
        records_written = 0
        try:
            result = write_fresh_table(
                destination,
                table.schema,
                _recovered_records(
                    table=table,
                    bindings=bindings,
                    vault_reader=vault_reader,
                    table_id=table_id,
                    checkpoint=control.check_cancelled,
                    memo_policy=memo_policy,
                ),
                cancel_check=control.check_cancelled,
            )
            records_written = int(result.records_written)
        except (CancellationError, CallbackError):
            raise
        except DBFBridgeError as write_failure:
            # The writer boundary wraps lazily consumed record-generation
            # failures; a typed project failure raised by the recovery
            # stream keeps its OWN classification (never reclassified as a
            # write artifact).
            cause = write_failure.__cause__
            while cause is not None:
                if isinstance(cause, AnonymizerError):
                    raise cause from None
                cause = cause.__cause__
            raise
        staging.assemble_table(index, relative_path)
        control.bump(ProgressPhase.RECOVERY_SCAN, table_path=relative_path)
        table_count += 1
        record_count += records_written
    if record_count != pseudonymized.record_count:
        raise _recovery_failure("RECOVERY_RECORD_COUNT_MISMATCH")
    return table_count, record_count


def _recovered_records(
    *,
    table: DirectSourceTable,
    bindings: dict[str, tuple[str, str, str | None, str | None]],
    vault_reader: _VerifyVault,
    table_id: str,
    checkpoint: Callable[[], None],
    memo_policy: str,
) -> Iterator[DirectRecord]:
    """The lazily consumed recovery stream (O(1) memory per record)."""
    for record in stream_table_records(
        table, include_deleted=True, memo_policy=memo_policy, cancel_check=checkpoint
    ):
        checkpoint()
        values: dict[str, object] = {}
        for field in table.schema.fields:
            name = str(field.name)
            if str(field.dbf_type).upper() == "0":
                continue  # writer-owned system state (_NullFlags bitmap)
            field_id, _field_type, action, domain_id = bindings[name]
            if action is None:
                raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
            pseudonymized_value = record.values.get(name)
            temporal_offset: int | None = None
            if action == "SHIFT_REVERSIBLE" and domain_id is not None:
                temporal_offset = vault_reader.temporal_offset(domain_id)
            values[name] = _reverse_value(
                action=action,
                domain_id=domain_id,
                dbf_type=str(field.dbf_type).upper(),
                pseudonymized_value=pseudonymized_value,
                physical_index=record.physical_index,
                table_id=table_id,
                field_id=field_id,
                temporal_offset=temporal_offset,
                vault_reader=vault_reader,
            )
        yield DirectRecord(physical_index=0, deleted=record.deleted, values=values)


def _verify_staged_recovery(
    *,
    control: ProgressController,
    pseudonymized_root: Path,
    staging: DatasetStaging,
    vault_reader: _VerifyVault,
    ledger: dict[str, dict[str, tuple[str, str, str | None, str | None]]],
    expected_tables: int,
    expected_records: int,
) -> None:
    """The complete staged self-verification BEFORE publication.

    The staged dataset is re-read through the public dbfbridge boundary and
    compared against the authoritative recovery state: topology, logical
    schema facts, record counts, physical order, deleted markers, NULL
    semantics and every reverse postcondition. A successful DBF write alone
    is never sufficient for canonical recovery success.
    """
    control.start_phase(ProgressPhase.VERIFICATION, total=expected_tables)
    staged_root = staging.dataset_root
    try:
        from dbf_anonymizer.engine.publication import _iter_dataset_files

        staged_inventory = {
            relative for relative, _path in _iter_dataset_files(staged_root)
        }
    except Exception:
        raise _recovery_failure("RECOVERY_STAGED_INVALID") from None
    expected_staged: set[str] = set()
    for relative_path in ledger:
        expected_staged.add(relative_path)
        table = read_source_table(
            pseudonymized_root, relative_path, cancel_check=control.check_cancelled
        )
        if table.has_memo_fields:
            expected_staged.add(
                Path(relative_path).with_suffix(".fpt").as_posix()
            )
    if staged_inventory != expected_staged:
        raise _recovery_failure("RECOVERY_STAGED_INVALID")
    record_total = 0
    for relative_path in sorted(ledger):
        control.check_cancelled()
        record_total += _verify_staged_table(
            relative_path=relative_path,
            pseudonymized_root=pseudonymized_root,
            staged_root=staged_root,
            vault_reader=vault_reader,
            bindings=ledger[relative_path],
        )
        control.bump(ProgressPhase.VERIFICATION, table_path=relative_path)
    if record_total != expected_records:
        raise _recovery_failure("RECOVERY_STAGED_INVALID")


def _verify_staged_table(
    *,
    relative_path: str,
    pseudonymized_root: Path,
    staged_root: Path,
    vault_reader: _VerifyVault,
    bindings: dict[str, tuple[str, str, str | None, str | None]],
) -> int:
    """One streamed staged-table comparison against the recovery state."""
    pseudonymized_table = read_source_table(pseudonymized_root, relative_path)
    staged_table = read_source_table(staged_root, relative_path)
    from dbf_anonymizer.verification import _schema_facts

    if _schema_facts(pseudonymized_table) != _schema_facts(staged_table):
        raise _recovery_failure("RECOVERY_STAGED_INVALID")
    memo_policy = "inline" if pseudonymized_table.has_memo_fields else "skip"
    table_id = vault_reader.table_rows().get(relative_path)
    assert table_id is not None
    scanned = 0
    try:
        pseudonymized_stream = stream_table_records(
            pseudonymized_table,
            include_deleted=True,
            memo_policy=memo_policy,
        )
        staged_stream = stream_table_records(
            staged_table,
            include_deleted=True,
            memo_policy=memo_policy,
        )
        for pseudonymized_record, staged_record in zip(
            pseudonymized_stream, staged_stream
        ):
            scanned += 1
            if (
                pseudonymized_record.physical_index != staged_record.physical_index
                or pseudonymized_record.deleted != staged_record.deleted
            ):
                raise _recovery_failure("RECOVERY_STAGED_INVALID")
            for field in pseudonymized_table.schema.fields:
                name = str(field.name)
                if str(field.dbf_type).upper() == "0":
                    continue
                field_id, _field_type, action, domain_id = bindings[name]
                pseudonymized_value = pseudonymized_record.values.get(name)
                staged_value = staged_record.values.get(name)
                if action == "KEEP":
                    if staged_value != pseudonymized_value:
                        raise _recovery_failure("RECOVERY_STAGED_INVALID")
                elif action == "MASK_REVERSIBLE":
                    if pseudonymized_value is None:
                        if staged_value is not None:
                            raise _recovery_failure("RECOVERY_STAGED_INVALID")
                        continue
                    recovery = vault_reader.memo_recovery_row(
                        table_id,
                        pseudonymized_record.physical_index,
                        field_id,
                    )
                    if recovery is None or staged_value != _staged_memo_payload(
                        recovery
                    ):
                        raise _recovery_failure("RECOVERY_STAGED_INVALID")
                elif action == "SHIFT_REVERSIBLE":
                    offset = (
                        vault_reader.temporal_offset(domain_id)
                        if domain_id is not None
                        else None
                    )
                    if offset is None:
                        if staged_value != pseudonymized_value:
                            raise _recovery_failure("RECOVERY_STAGED_INVALID")
                    elif staged_value != temporal_shift(
                        pseudonymized_value, -offset
                    ):
                        raise _recovery_failure("RECOVERY_STAGED_INVALID")
                elif action == "PSEUDONYMIZE_REVERSIBLE":
                    if not _reverse_agrees(
                        staged_value,
                        pseudonymized_value,
                        domain_id,
                        vault_reader,
                    ):
                        raise _recovery_failure("RECOVERY_STAGED_INVALID")
                else:
                    raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
        extra_pseudonymized = sum(1 for _record in pseudonymized_stream)
        extra_staged = sum(1 for _record in staged_stream)
        if extra_pseudonymized or extra_staged:
            raise _recovery_failure("RECOVERY_STAGED_INVALID")
    except (CancellationError, CallbackError):
        raise
    return scanned


def _reverse_agrees(
    staged_value: object,
    pseudonymized_value: object,
    domain_id: str | None,
    vault_reader: _VerifyVault,
) -> bool:
    """Whether the staged value is the exact authoritative reverse mapping.

    The staged value is the ORIGINAL and the pseudonymized value is the
    pseudonym, so the authoritative agreement is the durable mapping of the
    PSEUDONYM back to the staged original (the mapping tables map
    original -> pseudonym and are read through their indexed pseudonym
    lookup).
    """
    if pseudonymized_value is None or pseudonymized_value == "":
        return staged_value == pseudonymized_value
    if domain_id is None:
        return False
    if vault_reader.domain_kind(domain_id) == VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY:
        if isinstance(staged_value, bool) or not isinstance(staged_value, int):
            return False
        if isinstance(pseudonymized_value, bool) or not isinstance(
            pseudonymized_value, int
        ):
            return False
        return (
            vault_reader.numeric_original(
                domain_id, canonical_integer_text(pseudonymized_value)
            )
            == canonical_integer_text(staged_value)
        )
    if not isinstance(staged_value, str) or not isinstance(pseudonymized_value, str):
        return False
    return vault_reader.text_original(domain_id, pseudonymized_value) == staged_value


def _staged_memo_payload(
    recovery: tuple[bytes, str],
) -> object:
    payload, payload_kind = recovery
    if payload_kind == "TEXT":
        return payload.decode("utf-8")
    return payload


