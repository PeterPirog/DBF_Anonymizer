"""Fingerprint-bound dataset staging and publication for REQ-P4-009."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable, Iterator

from dbf_anonymizer.durability import (
    PostRenameDurabilityError,
    atomic_replace,
    fsync_tree,
    write_durable_bytes,
)
from dbf_anonymizer.engine.directives import RelationPassSummary, TwoPassResult
from dbf_anonymizer.errors import ErrorCode, ErrorContext, PathError, PublicationError
from dbf_anonymizer.vault.store import VaultDatabase

__all__ = [
    "PublicationIdentity",
    "DatasetStaging",
    "build_publication_identity",
    "fingerprint_dataset",
    "result_receipt",
    "result_from_receipt",
]

FaultInjector = Callable[[str], None]

#: The INTERNAL operation-receipt schema. Any structural change bumps this
#: version; unknown versions are rejected fail-closed on read-back.
RECEIPT_SCHEMA_VERSION = "1.1"

#: Versioned identity of the PRIVATE publication crash-state record
#: (``transaction.json`` inside the staging root — never part of any
#: transferable final tree).
PUBLICATION_TXN_STATE_SCHEMA_VERSION = "1.1"
PUBLICATION_TXN_PHASE_RUNNING = "RUNNING"
PUBLICATION_TXN_PHASE_READY_TO_PROMOTE = "READY_TO_PROMOTE"
PUBLICATION_TXN_PHASE_PROMOTED = "PROMOTED"

__all__ = tuple(__all__) + (  # type: ignore[assignment]
    "PUBLICATION_TXN_STATE_SCHEMA_VERSION",
    "PUBLICATION_TXN_PHASE_RUNNING",
    "PUBLICATION_TXN_PHASE_READY_TO_PROMOTE",
    "PUBLICATION_TXN_PHASE_PROMOTED",
)


def _publication_failure(detail_code: str) -> PublicationError:
    return PublicationError(
        ErrorCode.PUBLICATION_INCOMPLETE,
        context=ErrorContext(operation="publication", detail_code=detail_code),
    )


def _target_conflict(detail_code: str) -> PathError:
    return PathError(
        ErrorCode.DESTINATION_CONFLICT,
        context=ErrorContext(operation="publication", detail_code=detail_code),
    )


def _digest(prefix: str, payload: object) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return prefix + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class PublicationIdentity:
    """Privacy-safe binding of one operation to vault, inputs and target."""

    operation_id: str
    destination: Path
    destination_identity: str
    vault_fingerprint: str
    binding_fingerprint: str
    lock_path: Path
    staging_root: Path


def derive_destination_identity(destination: Path) -> str:
    """The canonical normalized destination identity digest (``dst-...``).

    The ONE canonicalization of a destination root used by both the durable
    operation-id kernel and the publication identity (never duplicated).
    """
    resolved = destination.resolve(strict=False)
    normalized = os.path.normcase(os.path.normpath(str(resolved)))
    return _digest("dst-", {"path": normalized})


def derive_vault_fingerprint(
    *,
    schema_version: str,
    vault_id: str,
    source_fingerprint: str,
    policy_fingerprint: str,
    relationship_fingerprint: str,
) -> str:
    """The canonical protected-vault binding fingerprint (``vlt-...``).

    The ONE digest recipe shared by the publication identity builder and the
    REQ-P5-001 read-only verification (which re-derives the expected vault
    binding from the immutable snapshot identity without opening a writer).
    """
    return _digest(
        "vlt-",
        {
            "schema": schema_version,
            "vault_id": vault_id,
            "source": source_fingerprint,
            "policy": policy_fingerprint,
            "relationships": relationship_fingerprint,
        },
    )


def derive_binding_fingerprint(
    *,
    source_fingerprint: str,
    policy_fingerprint: str,
    relationship_fingerprint: str,
    vault_fingerprint: str,
    destination_identity: str,
) -> str:
    """The canonical full operation binding fingerprint (``opb-...``).

    The ONE digest recipe shared by the publication identity builder and the
    REQ-P5-001 read-only verification. The binding is the STRONGER engine
    check: it additionally binds the ACTUAL vault fingerprint.
    """
    return _digest(
        "opb-",
        {
            "source": source_fingerprint,
            "policy": policy_fingerprint,
            "relationships": relationship_fingerprint,
            "vault": vault_fingerprint,
            "destination": destination_identity,
        },
    )


def derive_operation_id(
    *,
    source_fingerprint: str,
    policy_fingerprint: str,
    relationship_fingerprint: str,
    destination_identity: str,
) -> str:
    """The deterministic durable operation id (stable ``vop-`` vocabulary).

    Derived ONLY from privacy-safe identity digests that are available
    BEFORE any execution — never from source values — and stable for an
    exact compatible retry of the same plan against the same destination.
    The full P4-009 operation binding (which additionally binds the ACTUAL
    vault fingerprint) remains the stronger engine-side fail-closed check.
    """
    payload = {
        "source": source_fingerprint,
        "policy": policy_fingerprint,
        "relationships": relationship_fingerprint,
        "destination": destination_identity,
    }
    return "vop-" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        .encode("ascii")
    ).hexdigest()[:32]


def build_publication_identity(
    *,
    destination: Path,
    vault: VaultDatabase,
    source_fingerprint: str,
    policy_fingerprint: str,
    relationship_fingerprint: str,
    operation_id: str | None,
) -> PublicationIdentity:
    destination_identity = derive_destination_identity(destination)
    vault_fingerprint = derive_vault_fingerprint(
        schema_version=vault.schema_version,
        vault_id=vault.vault_id,
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
    # ONE deterministic operation-id kernel: an explicit id wins, otherwise
    # the canonical pre-executable derivation applies (stable for retries).
    effective_operation_id = operation_id or derive_operation_id(
        source_fingerprint=source_fingerprint,
        policy_fingerprint=policy_fingerprint,
        relationship_fingerprint=relationship_fingerprint,
        destination_identity=destination_identity,
    )
    sibling_token = hashlib.sha256(destination_identity.encode("ascii")).hexdigest()[:24]
    parent = destination.resolve(strict=False).parent
    return PublicationIdentity(
        operation_id=effective_operation_id,
        destination=destination.resolve(strict=False),
        destination_identity=destination_identity,
        vault_fingerprint=vault_fingerprint,
        binding_fingerprint=binding_fingerprint,
        lock_path=parent / f".dbf-anonymizer-{sibling_token}.lock",
        staging_root=parent / f".dbf-anonymizer-{sibling_token}.staging",
    )


def _iter_dataset_files(root: Path) -> Iterator[tuple[str, Path]]:
    try:
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories.sort()
            files.sort()
            for name in tuple(directories):
                candidate = current_path / name
                if candidate.is_symlink():
                    raise _publication_failure("DATASET_SYMLINK_REFUSED")
            for name in files:
                candidate = current_path / name
                status = os.lstat(candidate)
                if not stat.S_ISREG(status.st_mode):
                    raise _publication_failure("DATASET_ARTIFACT_INVALID")
                yield candidate.relative_to(root).as_posix(), candidate
    except PublicationError:
        raise
    except OSError:
        raise _publication_failure("DATASET_INSPECTION_FAILED") from None


def fingerprint_dataset(
    root: Path,
    *,
    checkpoint: Callable[[], None] | None = None,
    progress_probe: Callable[[int, int, str], None] | None = None,
) -> str:
    """Hash a complete dataset tree incrementally in canonical path order.

    The optional private progress probe (REQ-P1-008, used by the REQ-P5-001
    dataset verification service) is called with ``done, total, relative``
    after each artifact digest — one bounded event per file, never per byte.
    With ``progress_probe=None`` the pre-existing deterministic behavior and
    the exact fingerprint bytes are unchanged.
    """
    if not root.is_dir():
        raise _publication_failure("DATASET_MISSING")
    digest = hashlib.sha256(b"DBF-ANONYMIZER-DATASET/v1\x00")
    inventory = list(_iter_dataset_files(root))
    count = 0
    for relative, path in inventory:
        if checkpoint is not None:
            checkpoint()
        count += 1
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        size = path.stat().st_size
        digest.update(size.to_bytes(8, "big"))
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                if checkpoint is not None:
                    checkpoint()
        if progress_probe is not None:
            progress_probe(count, len(inventory), relative)
    digest.update(count.to_bytes(8, "big"))
    return "out-" + digest.hexdigest()


class DatasetStaging:
    """Owner-scoped per-table and complete-dataset staging on one filesystem.

    REQ-P5-008: the staging root also carries the PRIVATE durable
    crash-recovery state (``transaction.json``) — the staged payload and the
    private crash state live in the same private namespace and are never
    part of any transferable final tree.

    The truthful publication transition is recorded on this object as
    separate, monotonic facts (never collapsed into one boolean):

    1. staging created (``_created``) + RUNNING crash state durably
       persisted;
    2. payload fully written, fsynced, verified + READY_TO_PROMOTE crash
       state durably persisted;
    3. atomic rename/replace HAS OCCURRED (:attr:`renamed`) — the
       destination now holds the moved payload (recorded BEFORE the
       parent-directory durability step completes, so a genuine post-rename
       durability failure is never classified as "nothing was promoted");
    4. the destination parent-directory durability step completed, or was
       truthfully classified as unsupported by the platform (Windows);
    5. PROMOTED crash state durably recorded (:attr:`promoted`);
    6. the durable completion receipt/authoritative completion state
       exists (the caller's vault operation row);
    7. only then may the private staging metadata be removed.
    """

    __slots__ = (
        "identity",
        "_created",
        "_renamed",
        "_promoted",
        "_recorded_fingerprint",
    )

    def __init__(self, identity: PublicationIdentity) -> None:
        self.identity = identity
        self._created = False
        self._renamed = False
        self._promoted = False
        self._recorded_fingerprint: str | None = None

    @property
    def dataset_root(self) -> Path:
        return self.identity.staging_root / "dataset"

    @property
    def renamed(self) -> bool:
        """Whether the atomic rename/replace HAS ALREADY occurred.

        The destination now holds the moved payload and the source staging
        dataset no longer exists. This fact is recorded the moment
        :func:`os.replace` succeeded — even when the destination parent
        directory durability step afterwards fails — and it must never be
        treated as "nothing was promoted".
        """
        return self._renamed

    @property
    def promoted(self) -> bool:
        return self._promoted

    def create(self) -> None:
        root = self.identity.staging_root
        if root.exists():
            raise _publication_failure("STALE_STAGING_DETECTED")
        try:
            root.mkdir(mode=0o700)
            self._created = True
            (root / "tables").mkdir(mode=0o700)
            self.dataset_root.mkdir(mode=0o700)
            marker = {
                "schema_version": PUBLICATION_TXN_STATE_SCHEMA_VERSION,
                "phase": PUBLICATION_TXN_PHASE_RUNNING,
                "operation_id": self.identity.operation_id,
                "binding_fingerprint": self.identity.binding_fingerprint,
                "destination_identity": self.identity.destination_identity,
            }
            # REQ-P5-008: the crash-recovery transaction state is persisted
            # durably and ATOMICALLY (same-directory temporary file →
            # fsync → os.replace; directory entry where the platform
            # supports it) BEFORE any payload byte is written.
            write_durable_bytes(
                root / "transaction.json",
                json.dumps(
                    marker, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode("ascii"),
            )
        except FileExistsError:
            raise _publication_failure("STALE_STAGING_DETECTED") from None
        except OSError:
            raise _publication_failure("STAGING_CREATE_FAILED") from None

    def table_destination(self, index: int, relative_path: str) -> Path:
        table_root = self.identity.staging_root / "tables" / f"{index:08d}"
        try:
            table_root.mkdir(mode=0o700)
        except FileExistsError:
            raise _publication_failure("TABLE_STAGING_CONFLICT") from None
        except OSError:
            raise _publication_failure("TABLE_STAGING_CREATE_FAILED") from None
        return table_root / Path(relative_path).name

    def assemble_table(self, index: int, relative_path: str) -> None:
        table_root = self.identity.staging_root / "tables" / f"{index:08d}"
        source = table_root / Path(relative_path).name
        if not source.is_file():
            raise _publication_failure("STAGED_TABLE_MISSING")
        destination = self.dataset_root / relative_path
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
            source_memo = source.with_suffix(".fpt")
            if source_memo.exists():
                os.replace(source_memo, destination.with_suffix(".fpt"))
            table_root.rmdir()
        except OSError:
            raise _publication_failure("TABLE_ASSEMBLY_FAILED") from None

    def record_staged_fingerprint(self, output_fingerprint: str) -> None:
        """Remember the verified staged fingerprint for later crash-state
        records (PROMOTED phase) and reconciliation."""
        self._recorded_fingerprint = output_fingerprint

    def persist_payload(self, *, checkpoint: Callable[[], None] | None = None) -> int:
        """Flush + fsync every staged regular file, then persist directory
        entries where the platform supports it (REQ-P5-008 step 5/6).

        REQ-P1-008: the optional cooperative checkpoint is polled at the
        bounded durability safe points (between regular files and between
        directories); callers driving a public long-running operation pass
        the SAME controller probe used everywhere else.

        Returns the number of files fsynced. Directory-entry persistence is
        truthful per platform (POSIX: synced; Windows: unsupported and
        reported as such — never claimed). A genuine durability failure is
        a typed durability failure (never silently downgraded).
        """
        if not self.dataset_root.is_dir():
            raise _publication_failure("STAGED_PAYLOAD_MISSING")
        return fsync_tree(self.dataset_root, checkpoint=checkpoint)

    def mark_ready_to_promote(
        self,
        *,
        payload_fingerprint: str,
    ) -> None:
        """Persist the durable READY_TO_PROMOTE crash state (step 8).

        The staged payload has been fully written, fsynced and verified; the
        crash-state record is atomically updated (fsync file + directory
        where supported) so an interruption can never leave the payload
        mistaken for an unverified partial artifact.
        """
        self._write_phase(
            PUBLICATION_TXN_PHASE_READY_TO_PROMOTE,
            output_fingerprint=payload_fingerprint,
        )

    def mark_promoted(self) -> None:
        """Persist the PROMOTED crash state after the atomic replace
        (the rename is already done; the private state records it)."""
        self._promoted = True
        self._write_phase(
            PUBLICATION_TXN_PHASE_PROMOTED,
            output_fingerprint=self._recorded_fingerprint,
        )

    def _write_phase(self, phase: str, *, output_fingerprint: str | None) -> None:
        """Atomically REPLACE one crash-state phase record.

        The complete new record is written to a same-directory temporary
        file, flushed, fsynced as a regular file, and only then atomically
        swapped in via :func:`~dbf_anonymizer.durability.write_durable_bytes`
        (temporary file → fsync → ``os.replace`` → parent directory entry
        where the platform supports it). The previous valid crash state
        therefore remains intact until the atomic replace, and no temporary
        file remains on normal success — an interrupted update can never
        truncate or empty the durable transaction state.
        """
        if self._recorded_fingerprint is None and output_fingerprint is not None:
            self._recorded_fingerprint = output_fingerprint
        payload: dict[str, object] = {
            "schema_version": PUBLICATION_TXN_STATE_SCHEMA_VERSION,
            "phase": phase,
            "operation_id": self.identity.operation_id,
            "binding_fingerprint": self.identity.binding_fingerprint,
            "destination_identity": self.identity.destination_identity,
        }
        if self._recorded_fingerprint is not None:
            payload["output_fingerprint"] = self._recorded_fingerprint
        write_durable_bytes(
            self.identity.staging_root / "transaction.json",
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii"),
        )

    def transaction_state(self) -> dict[str, object] | None:
        """Read the durable crash-recovery state of this staging root."""
        path = self.identity.staging_root / "transaction.json"
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def cleanup_durable_state(self) -> None:
        """Remove private crash-state metadata AFTER genuine completion
        (step 13). A failure here must never make a genuinely completed
        operation appear incomplete — callers treat cleanup failure as
        non-fatal for the committed result."""
        if not self._promoted:
            raise _publication_failure("PROMOTION_NOT_COMPLETE")
        try:
            tables = self.identity.staging_root / "tables"
            if tables.exists():
                tables.rmdir()
            (self.identity.staging_root / "transaction.json").unlink()
            self.identity.staging_root.rmdir()
        except FileNotFoundError:
            # Non-critical cleanup already done; the completed state stands.
            return
        except OSError:
            raise _publication_failure("STAGING_CLEANUP_FAILED") from None

    def promote(self) -> None:
        """Atomically promote the staged payload (REQ-P5-008 step 10).

        The objective rename fact (:attr:`renamed`) is recorded the moment
        ``os.replace`` has succeeded — BEFORE the destination parent
        directory durability step completes — so a genuine post-rename
        durability failure propagates with ``renamed is True`` and can
        never be classified as "nothing was promoted" by any caller. A
        failure of the rename itself (``OSError``) means nothing was
        renamed (the primitive is atomic) and keeps the pre-promotion
        classification.
        """
        if self.identity.destination.exists():
            raise _target_conflict("TARGET_ALREADY_EXISTS")
        try:
            # REQ-P5-008: same-filesystem atomic replace + destination
            # parent-directory persistence where the platform supports it.
            atomic_replace(self.dataset_root, self.identity.destination)
        except PostRenameDurabilityError:
            # The rename HAS occurred (the destination now holds the moved
            # payload); only the parent-directory durability step failed.
            # Record the objective rename fact BEFORE the typed failure
            # propagates: no caller may classify this as pre-promotion and
            # destroy the crash-state evidence.
            self._renamed = True
            raise
        except OSError:
            raise _publication_failure("STAGING_PROMOTION_FAILED") from None
        self._renamed = True
        self._promoted = True

    def remove_metadata_after_promotion(self) -> None:
        if not self._promoted:
            raise _publication_failure("PROMOTION_NOT_COMPLETE")
        try:
            tables = self.identity.staging_root / "tables"
            if tables.exists():
                tables.rmdir()
            (self.identity.staging_root / "transaction.json").unlink()
            self.identity.staging_root.rmdir()
        except OSError:
            raise _publication_failure("STAGING_CLEANUP_FAILED") from None

    def cleanup_owned(self) -> None:
        """Remove only staging created by this live owner BEFORE any atomic
        rename has occurred.

        After a successful rename (:attr:`renamed`) the final destination
        exists and the residual staging root carries the private crash-state
        evidence required to classify the interrupted publication
        deterministically — removing it would destroy that evidence, so this
        cleanup is a no-op from the rename fact on. (Deleting the renamed
        destination itself is NOT this object's decision; classification and
        any safe resolution stay with the reconciliation contract.)
        """
        if not self._created or self._renamed:
            return
        try:
            shutil.rmtree(self.identity.staging_root)
        except FileNotFoundError:
            return
        except OSError:
            raise _publication_failure("STAGING_CLEANUP_FAILED") from None


def _staging_residual_is_owned(root: Path) -> bool:
    """Whether a post-promotion staging root contains ONLY objectively owned
    residual metadata — the empty ``tables/`` directory, the crash-state
    record, the deterministic private temporary file of an interrupted
    crash-state update — and no payload (a PROMOTED dataset was MOVED to the
    destination, so any payload entry would contradict the proven state).
    """
    try:
        with os.scandir(root) as entries:
            names = sorted(entry.name for entry in entries)
    except OSError:
        return False
    for name in names:
        entry = root / name
        if name == "transaction.json":
            if not entry.is_file() or entry.is_symlink():
                return False
            continue
        if name == "tables":
            if not entry.is_dir() or entry.is_symlink():
                return False
            try:
                with os.scandir(entry) as residual:
                    if next(iter(residual), None) is not None:
                        return False
            except OSError:
                return False
            continue
        if name == ".transaction.json.tmp" and entry.is_file() and not entry.is_symlink():
            continue
        return False
    return True


def reconcile_completed_staging_residual(
    identity: PublicationIdentity,
    operation_id: str,
    destination_identity: str,
    *,
    output_fingerprint: str,
) -> None:
    """Reconcile a crash after the durable completion receipt but before
    private metadata cleanup (REQ-P5-008 case C).

    The caller must ALREADY have fully proven the completed operation
    (structurally valid COMPLETED vault state, a schema-valid durable
    receipt and a final destination whose complete dataset fingerprint
    matches the authoritative completed output fingerprint). Before any
    residual private metadata is removed, the private crash-state record
    itself must be objectively owned and coherent:

    * exact crash-state ``schema_version``;
    * ``phase == PROMOTED``;
    * matching operation id, destination identity and binding fingerprint;
    * a crash-state ``output_fingerprint`` that equals the authoritative
      completed output fingerprint;
    * only the expected post-promotion residual entries inside the staging
      root (empty ``tables/``, the crash-state record, the deterministic
      private temporary file of an interrupted crash-state update) and no
      payload.

    Any missing, malformed or mismatched element fails CLOSED with a stable
    typed detail code: the ambiguous crash state is NOT deleted and the
    completed output is NOT modified. Only after every element is proven is
    the objectively owned residual metadata removed so the idempotent
    completed retry can proceed.
    """
    state_path = identity.staging_root / "transaction.json"
    if not state_path.is_file():
        # The residual staging cannot prove which phase it reached: fail
        # closed rather than deleting an ambiguous state.
        raise _publication_failure("COMPLETED_STAGING_STATE_MISSING")
    try:
        payload = json.loads(state_path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise _publication_failure("COMPLETED_STAGING_STATE_INVALID") from None
    coherent = (
        isinstance(payload, dict)
        and payload.get("schema_version") == PUBLICATION_TXN_STATE_SCHEMA_VERSION
        and payload.get("phase") == PUBLICATION_TXN_PHASE_PROMOTED
        and payload.get("operation_id") == operation_id
        and payload.get("destination_identity") == destination_identity
        and payload.get("binding_fingerprint") == identity.binding_fingerprint
        and payload.get("output_fingerprint") == output_fingerprint
    )
    if not coherent:
        raise _publication_failure("COMPLETED_STAGING_STATE_INVALID")
    if not _staging_residual_is_owned(identity.staging_root):
        raise _publication_failure("COMPLETED_STAGING_UNRECOGNIZED")
    # The crash state proves the metadata cleanup was the ONLY step left;
    # remove the objectively owned, coherent residual metadata now.
    try:
        shutil.rmtree(identity.staging_root)
    except OSError:
        # Non-critical: the completed state stands regardless.
        pass


def result_receipt(result: TwoPassResult) -> str:
    payload = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tables_written": list(result.tables_written),
        "pass1_records_scanned": result.pass1_records_scanned,
        "pass1_deleted_scanned": result.pass1_deleted_scanned,
        "pass2_records_written": result.pass2_records_written,
        "text_allocated": result.text_allocated,
        "text_reused": result.text_reused,
        "numeric_allocated": dict(sorted(result.numeric_allocated.items())),
        "temporal_offset_allocated": result.temporal_offset_allocated,
        "relations": [asdict(summary) for summary in result.relations],
        "evidence_spool_bytes": result.evidence_spool_bytes,
        "read_streams": [list(item) for item in result.read_streams],
        "operation_id": result.operation_id,
        "output_fingerprint": result.output_fingerprint,
        "protected_state_created": result.protected_state_created,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def result_from_receipt(receipt: str) -> TwoPassResult:
    try:
        payload = json.loads(receipt)
        if payload.get("schema_version") != RECEIPT_SCHEMA_VERSION:
            raise ValueError
        relations = tuple(
            RelationPassSummary(**item) for item in payload["relations"]
        )
        result = TwoPassResult(
            tables_written=tuple(str(item) for item in payload["tables_written"]),
            pass1_records_scanned=int(payload["pass1_records_scanned"]),
            pass1_deleted_scanned=int(payload["pass1_deleted_scanned"]),
            pass2_records_written=int(payload["pass2_records_written"]),
            text_allocated=int(payload["text_allocated"]),
            text_reused=int(payload["text_reused"]),
            numeric_allocated={
                str(key): int(value)
                for key, value in payload["numeric_allocated"].items()
            },
            temporal_offset_allocated=bool(payload["temporal_offset_allocated"]),
            relations=relations,
            evidence_spool_bytes=int(payload["evidence_spool_bytes"]),
            read_streams=tuple(
                (str(item[0]), str(item[1])) for item in payload["read_streams"]
            ),
            operation_id=str(payload["operation_id"]),
            output_fingerprint=str(payload["output_fingerprint"]),
            reused_existing=True,
            protected_state_created=bool(payload["protected_state_created"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise _publication_failure("OPERATION_RECEIPT_INVALID") from None
    return replace(result, reused_existing=True)
