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
    vault_fingerprint = _digest(
        "vlt-",
        {
            "schema": vault.schema_version,
            "vault_id": vault.vault_id,
            "source": source_fingerprint,
            "policy": policy_fingerprint,
            "relationships": relationship_fingerprint,
        },
    )
    binding_fingerprint = _digest(
        "opb-",
        {
            "source": source_fingerprint,
            "policy": policy_fingerprint,
            "relationships": relationship_fingerprint,
            "vault": vault_fingerprint,
            "destination": destination_identity,
        },
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
    """Owner-scoped per-table and complete-dataset staging on one filesystem."""

    __slots__ = ("identity", "_created", "_promoted")

    def __init__(self, identity: PublicationIdentity) -> None:
        self.identity = identity
        self._created = False
        self._promoted = False

    @property
    def dataset_root(self) -> Path:
        return self.identity.staging_root / "dataset"

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
                "schema_version": "1.0",
                "operation_id": self.identity.operation_id,
                "binding_fingerprint": self.identity.binding_fingerprint,
                "destination_identity": self.identity.destination_identity,
            }
            with (root / "transaction.json").open("x", encoding="ascii") as stream:
                json.dump(marker, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
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

    def promote(self) -> None:
        if self.identity.destination.exists():
            raise _target_conflict("TARGET_ALREADY_EXISTS")
        try:
            os.replace(self.dataset_root, self.identity.destination)
        except OSError:
            raise _publication_failure("STAGING_PROMOTION_FAILED") from None
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
        """Remove only staging created by this live owner before promotion."""
        if not self._created or self._promoted:
            return
        try:
            shutil.rmtree(self.identity.staging_root)
        except FileNotFoundError:
            return
        except OSError:
            raise _publication_failure("STAGING_CLEANUP_FAILED") from None


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
