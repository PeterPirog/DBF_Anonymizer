"""Protected canonical dataset recovery (REQ-P5-002/REQ-P5-003).

``recover`` is the public REQ-P1-004/REQ-P1-008 service slice that
reconstructs the ORIGINAL logical DBF/FPT dataset from exactly two inputs —
the PSEUDONYMIZED working dataset PATH plus the MATCHING protected SQLite
vault PATH. The original source dataset is NEVER required, opened or
inspected by production recovery, and NO in-process private state (no
``PseudonymizationResult``/private execution context) is required: a
separate privileged recovery action can run in a fresh process against just
the two paths.

All authority is derived deterministically from those two paths through the
ONE shared identity kernels — no in-process state and no scanning for "some
plausible operation":

1. the vault is opened read-only (immutable ``mode=ro&immutable=1`` snapshot
   shared with the REQ-P5-001 verifier) and its dataset row provides the
   authoritative source/policy/relationship fingerprints;
2. the canonical pseudonymization operation id is derived with the existing
   ``derive_operation_id`` kernel from those fingerprints plus the
   destination identity of the given pseudonymized path;
3. exactly that completed operation is loaded (zero or incompatible
   operations fail closed);
4. the pseudonymized dataset fingerprint is recomputed and must equal the
   stored operation AND receipt fingerprints;
5. the vault/binding fingerprints are re-derived and the complete durable
   field-policy ledger, mapping bijections and temporal parameters are
   validated — all fail-closed.

Recovery then streams every pseudonymized table through the public dbfbridge
Direct Read boundary, reverses the durable policy application per field —
KEEP identity, text/numeric reverse mappings, protected memo recovery
payloads, reversible temporal shifts, NULL preservation, deleted markers and
physical order — writes fresh DBF/FPT staging through the public Direct
Write boundary, self-verifies the ENTIRE staged dataset against the same
authoritative recovery state (a successful DBF write alone is never
sufficient; cancellation is polled at every record boundary during the
staged verification), and only then atomically promotes it with the
existing P4 publication kernels under a real OS destination lock.

The recovery operation identity is clearly distinct from the pseudonymization
operation it recovers: the vault is never written, no operation row is
created and the invocation id is the controller's own bounded ``op-`` token,
shared by every progress event and the public result. Canonical success is
LOGICAL DATA + SCHEMA EQUIVALENCE (proven by the staged self-verification);
the separate raw DBF/FPT byte fact is truthfully ``NOT_EVALUATED`` in
production because no objective original-vs-recovered byte comparison oracle
exists without the source.

Recovery staging contains ORIGINAL LOGICAL DATA: a cleanup failure is never
suppressed — the primary failure keeps its classification and the sensitive
residual-staging risk is machine-detectably surfaced as a typed secondary
cause, never through a staging path or any protected value.

Original values, memo/binary payloads, reverse mappings, temporal offsets
and absolute private paths never appear in any public result, error,
progress event or log.

REQ-P7-003: Recovery capability is controlled by an explicit host policy.
When ``recovery_policy`` is ``RecoveryPolicy.DISABLED``, the refusal occurs
BEFORE any vault access (no sqlite3.connect, no vault metadata read, no
staging, no locking).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Iterator, Sequence

import dbfbridge
from dbfbridge import DirectRecord  # type: ignore[attr-defined]

from dbf_anonymizer.discovery import derive_dataset_id
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
    derive_operation_id,
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
    DatasetIdentity,
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
from dbf_anonymizer.recovery_policy import RecoveryPolicy
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

__all__ = ["recover", "RecoveryPolicy"]

_RECOVER_OPERATION = "recover"


def _recovery_failure(detail_code: str) -> RecoveryError:
    """Stable typed, value-free recovery inability (no protected values)."""
    return RecoveryError(
        ErrorCode.RECOVERY_FAILED,
        context=ErrorContext(operation=_RECOVER_OPERATION, detail_code=detail_code),
    )


def _recovery_not_permitted() -> RecoveryError:
    """Stable typed refusal when recovery is disabled by host policy."""
    return RecoveryError(
        ErrorCode.RECOVERY_NOT_PERMITTED,
        context=ErrorContext(operation=_RECOVER_OPERATION, detail_code="POLICY_DISABLED"),
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
    pseudonymized: str | Path,
    *,
    vault: str | Path,
    output: str | Path,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
    recovery_policy: RecoveryPolicy = RecoveryPolicy.ENABLED,
) -> RecoveryResult:
    """Reconstruct the original logical dataset (REQ-P5-002/REQ-P5-003).

    Production recovery takes the PSEUDONYMIZED WORKING DATASET PATH and the
    MATCHING PROTECTED VAULT PATH — never an in-process result object and
    never the original source. All authority is derived deterministically
    from those two paths through the shared identity kernels (operation id,
    vault fingerprint, binding fingerprint and destination identity); zero
    or incompatible durable operations fail closed.

    The protected vault is validated READ-ONLY and fail-closed before any
    byte is written (schema, SQLite trustworthiness, the matching completed
    pseudonymization operation, the pseudonymized dataset fingerprint against
    the stored operation and receipt, the complete durable field-policy
    ledger, mapping bijections and temporal parameters); ambiguous sidecar
    state fails closed because trustworthy recovery never mutates SQLite
    state.

    Every recovered DBF/FPT is written fresh through the public dbfbridge
    boundary into complete staging, the ENTIRE staged dataset is then
    self-verified against the authoritative recovery state (record streams,
    deleted markers, NULL semantics and every reverse postcondition, with
    cancellation checkpoints at every record boundary), and only then is the
    recovery atomically promoted through the existing P4 publication kernels.
    Cancellation before promotion leaves no final recovered tree and cleans
    owned staging; the pseudonymized input and the protected vault are never
    modified. A staging cleanup failure over original-bearing residuals is
    never suppressed: the primary failure keeps its exact classification and
    the sensitive cleanup risk is machine-detectably surfaced as a typed
    secondary cause (``RECOVERY_SENSITIVE_STAGING_CLEANUP_FAILED``).

    REQ-P1-008: ONE :class:`ProgressController` (``operation="recover"``)
    with one bounded invocation id drives the bounded phases; the single
    terminal completion is emitted only after the genuine atomic promotion
    (never after a cancellation, rejection or callback failure, and never
    with a post-promotion cancellation poll).

    REQ-P7-003: The ``recovery_policy`` argument controls whether recovery
    is permitted. When ``RecoveryPolicy.DISABLED``, a stable typed refusal
    (``RECOVERY_NOT_PERMITTED``) is returned BEFORE any vault access — no
    sqlite3.connect, no vault metadata read, no staging creation, no
    destination locking, no DBF/FPT reads for recovery. The vault path is
    never disclosed in the error.

    The public verdict is CANONICAL LOGICAL + SCHEMA EQUIVALENCE; the raw
    DBF/FPT byte fact is truthfully ``NOT_EVALUATED`` because no
    original-source comparison oracle exists in production.
    """
    if not isinstance(recovery_policy, RecoveryPolicy):
        raise TypeError("recovery_policy must be a RecoveryPolicy enum value")
    if recovery_policy is RecoveryPolicy.DISABLED:
        raise _recovery_not_permitted()

    if isinstance(pseudonymized, (str, Path)) is False or isinstance(
        pseudonymized, (bytes, bytearray)
    ):
        raise TypeError("recover requires a pseudonymized dataset PATH")
    pseudonymized_root = Path(pseudonymized)
    if not pseudonymized_root.is_dir():
        raise _recovery_target_conflict("RECOVERY_PSEUDONYMIZED_MISSING")
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
            pseudonymized_root=pseudonymized_root,
            control=control,
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
                        control=control,
                        pseudonymized_root=pseudonymized_root,
                        staging=staging,
                        vault_reader=vault_reader,
                        authority=identity,
                    )
                    _verify_staged_recovery(
                        control=control,
                        pseudonymized_root=pseudonymized_root,
                        staging=staging,
                        vault_reader=vault_reader,
                        authority=identity,
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
                except BaseException as primary:
                    # Best-effort owned staging cleanup: recovery staging
                    # carries ORIGINAL LOGICAL DATA, so a cleanup failure is
                    # NEVER suppressed — the primary failure keeps its exact
                    # classification and the sensitive residual-staging risk
                    # is machine-detectably surfaced as the typed secondary
                    # cause (REQ-P2-009 cleanup contract).
                    if isinstance(primary, Exception):
                        try:
                            staging.cleanup_owned()
                        except Exception as cleanup_exc:
                            cleanup_failure = _recovery_failure(
                                "RECOVERY_SENSITIVE_STAGING_CLEANUP_FAILED"
                            )
                            raise primary from cleanup_failure
                    else:
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
        dataset=identity.dataset,
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

    __slots__ = (
        "source_fingerprint",
        "policy_fingerprint",
        "relationship_fingerprint",
        "dataset",
        "ledger",
        "expected_records",
    )

    def __init__(
        self,
        *,
        source_fingerprint: str,
        policy_fingerprint: str,
        relationship_fingerprint: str,
        dataset: DatasetIdentity,
        ledger: dict[str, dict[str, tuple[str, str, str | None, str | None]]],
        expected_records: int,
    ) -> None:
        self.source_fingerprint = source_fingerprint
        self.policy_fingerprint = policy_fingerprint
        self.relationship_fingerprint = relationship_fingerprint
        self.dataset = dataset
        self.ledger = ledger
        self.expected_records = expected_records


def _validate_recovery_authority(
    *,
    pseudonymized_root: Path,
    control: ProgressController,
    vault_reader: _VerifyVault,
) -> _RecoveryAuthority:
    """The read-only fail-closed recovery authority (REQ-P5-002 step 1).

    ALL identity is derived from the two given PATHS plus the protected
    durable metadata — never from in-process private state and never by
    scanning for a plausible operation: the canonical operation id comes
    from the shared ``derive_operation_id`` kernel over the vault's dataset
    fingerprints and the pseudonymized destination identity, and any zero or
    incompatible completed operation fails closed.

    Proves, without any mutation: the completed pseudonymization operation
    binding, the pseudonymized dataset fingerprint (against the stored
    operation AND receipt), the COMPLETE durable field-policy ledger for
    every durable table identity, the mapping-domain bijections and the
    temporal parameters.
    """
    dataset_row = vault_reader.dataset_row()
    destination_identity = derive_destination_identity(pseudonymized_root)
    operation_id = derive_operation_id(
        source_fingerprint=dataset_row[0],
        policy_fingerprint=dataset_row[1],
        relationship_fingerprint=dataset_row[2],
        destination_identity=destination_identity,
    )
    operation = vault_reader.completed_operation(operation_id)
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
        destination_identity=destination_identity,
    )
    agreements = (
        (operation["source_fingerprint"], dataset_row[0]),
        (operation["policy_fingerprint"], dataset_row[1]),
        (operation["relationship_fingerprint"], dataset_row[2]),
        (operation["vault_fingerprint"], expected_vault_fingerprint),
        (operation["binding_fingerprint"], expected_binding),
        (operation["destination_identity"], destination_identity),
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
    if receipt.operation_id != operation_id:
        raise _recovery_failure("RECOVERY_IDENTITY_MISMATCH")
    durable_output = operation["output_fingerprint"]
    if (
        durable_output is None
        or durable_output != receipt.output_fingerprint
    ):
        raise _recovery_failure("RECOVERY_PSEUDONYMIZED_MISMATCH")

    # The given pseudonymized dataset must still BE the durable publication.
    control.check_cancelled()
    current_pseudonymized = fingerprint_dataset(
        pseudonymized_root, checkpoint=control.check_cancelled
    )
    if current_pseudonymized != durable_output:
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

    # The COMPLETE durable field-policy ledger for EVERY durable table
    # identity (shared with the verifier — no second field-type switch).
    vault_tables = vault_reader.table_rows()
    ledger: dict[str, dict[str, tuple[str, str, str | None, str | None]]] = {}
    for relative_path in sorted(vault_tables):
        control.check_cancelled()
        table = read_source_table(
            pseudonymized_root, relative_path, cancel_check=control.check_cancelled
        )
        findings = _Findings()
        ledger[relative_path] = _verify_field_ledger(
            table,
            vault_reader.field_rows(vault_tables[relative_path]),
            vault_reader=vault_reader,
            findings=findings,
        )
        if findings:
            raise _ledger_failure(findings)
    return _RecoveryAuthority(
        source_fingerprint=dataset_row[0],
        policy_fingerprint=dataset_row[1],
        relationship_fingerprint=dataset_row[2],
        dataset=DatasetIdentity(
            dataset_id=derive_dataset_id(dataset_row[0]),
            source_fingerprint=dataset_row[0],
            table_paths=tuple(sorted(vault_tables)),
            standalone_idx_paths=tuple(
                item.artifact_path for item in receipt.index_artifacts
            ),
        ),
        ledger=ledger,
        expected_records=int(receipt.pass2_records_written),
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
    control: ProgressController,
    pseudonymized_root: Path,
    staging: DatasetStaging,
    vault_reader: _VerifyVault,
    authority: _RecoveryAuthority,
) -> tuple[int, int]:
    """The streaming staged recovery of every durable table (REQ-P5-002).

    One pseudonymized table at a time: bounded-memory streaming generation
    of fresh original logical values through the public dbfbridge Direct
    Read/Write boundaries, complete FPT companions included, deleted
    markers and physical order preserved.
    """
    table_paths = sorted(authority.ledger)
    control.start_phase(ProgressPhase.RECOVERY_SCAN, total=len(table_paths))
    table_count = 0
    record_count = 0
    for index, relative_path in enumerate(table_paths):
        control.check_cancelled()
        table = read_source_table(
            pseudonymized_root, relative_path, cancel_check=control.check_cancelled
        )
        table_id = vault_reader.table_rows().get(relative_path)
        if table_id is None:
            raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
        bindings = authority.ledger[relative_path]
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
    if record_count != authority.expected_records:
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
    authority: _RecoveryAuthority,
    expected_tables: int,
    expected_records: int,
) -> None:
    """The complete staged self-verification BEFORE publication.

    The staged dataset is re-read through the public dbfbridge boundary and
    compared against the authoritative recovery state: topology, logical
    schema facts, record counts, physical order, deleted markers, NULL
    semantics and every reverse postcondition — with cancellation
    checkpoints at every record boundary. A successful DBF write alone is
    never sufficient for canonical recovery success.
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
    for relative_path in sorted(authority.ledger):
        control.check_cancelled()
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
    for relative_path in sorted(authority.ledger):
        control.check_cancelled()
        record_total += _verify_staged_table(
            relative_path=relative_path,
            pseudonymized_root=pseudonymized_root,
            staged_root=staged_root,
            vault_reader=vault_reader,
            bindings=authority.ledger[relative_path],
            checkpoint=control.check_cancelled,
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
    checkpoint: Callable[[], None],
) -> int:
    """One streamed staged-table comparison against the recovery state.

    Cancellation is polled at every record boundary of BOTH streamed sides
    (a single large table can therefore never continue staged verification
    after cancellation; REQ-P1-008 bounded latency).
    """
    pseudonymized_table = read_source_table(
        pseudonymized_root, relative_path, cancel_check=checkpoint
    )
    staged_table = read_source_table(staged_root, relative_path, cancel_check=checkpoint)
    from dbf_anonymizer.verification import _schema_facts

    if _schema_facts(pseudonymized_table) != _schema_facts(staged_table):
        raise _recovery_failure("RECOVERY_STAGED_INVALID")
    memo_policy = "inline" if pseudonymized_table.has_memo_fields else "skip"
    table_id = vault_reader.table_rows().get(relative_path)
    if table_id is None:
        raise _recovery_failure("RECOVERY_LEDGER_INCOMPLETE")
    scanned = 0
    try:
        pseudonymized_stream = stream_table_records(
            pseudonymized_table,
            include_deleted=True,
            memo_policy=memo_policy,
            cancel_check=checkpoint,
        )
        staged_stream = stream_table_records(
            staged_table,
            include_deleted=True,
            memo_policy=memo_policy,
            cancel_check=checkpoint,
        )
        for pseudonymized_record, staged_record in zip(
            pseudonymized_stream, staged_stream
        ):
            checkpoint()
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


def _staged_memo_payload(recovery: tuple[bytes, str]) -> object:
    payload, payload_kind = recovery
    if payload_kind == "TEXT":
        return payload.decode("utf-8")
    return payload
