"""Safe standalone DATA_ONLY transfer bundles (REQ-P5-004..REQ-P5-007).

``create_transfer_bundle`` builds a BRAND-NEW allowlisted export tree from a
verified pseudonymized working dataset — never a broad copy of the working
directory — plus a sanitized, versioned public manifest with per-artifact
hashes. ``verify_transfer_bundle`` verifies a COPIED bundle directory
STANDALONE (no source, no vault, no recovery mappings, no in-process
execution context) and returns the typed public verdict.

The bundle is PSEUDONYMIZED DATA, never anonymous. For DATA_ONLY the
allowlisted payload is exactly: the expected pseudonymized DBF tables, their
required fresh FPT companions and the public manifest. Until authoritative
P6 index validation exists, CDX/IDX/DBC/DCT/DCX artifacts are never
transferable as valid and are omitted; DATA_ONLY remains standalone fresh
DBF/FPT data.

Creation proves the working dataset is the EXPECTED PUBLISHED dataset
before any transferable byte is copied: the complete working-tree
fingerprint (the accepted P4 publication kernel) must equal the supplied
pseudonymization result's durable output fingerprint — a modified, stale or
injected working tree fails closed. No vault, recovery mapping, temporal
offset or any other protected state is read into the bundle; no recovery
material is required by standalone verification.

The manifest schema is versioned (:data:`TRANSFER_MANIFEST_SCHEMA_VERSION`)
with an exact key-vocabulary snapshot; the manifest fingerprint is the
canonical digest of the finalized manifest bytes (no recursive ambiguity).
Normalized relative paths are deduplicated case-insensitively (Windows
collision safety), traversal/absolute paths are refused, and the
deterministic canonical ordering is authoritative — never directory
enumeration order. The denylist artifact CLASSIFICATION is defense in depth
(the allowlist stays authoritative), so hostile names, casing or nesting can
never smuggle vault/SQLite/journal/log/temp/lock/staging/index or unknown
executables into a transfer tree.

REQ-P1-008: both long-running operations share the bounded
:class:`~dbf_anonymizer.progress.ProgressController`; cancellation is
polled at hash/copy chunks, table boundaries and immediately before the
atomic publication, and a pre-publication cancellation leaves no completed
bundle claim, no partial final tree and cleaned owned staging. Callback
failures remain typed, contained and privacy-safe.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Sequence

import dbfbridge

from dbf_anonymizer.engine.direct_io import (
    DirectSourceTable,
    read_source_table,
    stream_table_records,
)
from dbf_anonymizer.engine.locking import DestinationLock
from dbf_anonymizer.engine.publication import (
    DatasetStaging,
    PublicationIdentity,
    derive_destination_identity,
    fingerprint_dataset,
)
from dbf_anonymizer.errors import (
    AnonymizerError,
    CallbackError,
    CancellationError,
    ErrorCode,
    ErrorContext,
    PathError,
    TransferError,
)
from dbf_anonymizer.models import (
    PseudonymizationResult,
    RelationalAssurance,
    TransferBundleResult,
    TransferProfile,
)
from dbf_anonymizer.preflight import _paths_overlap
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)
from dbf_anonymizer.verification import _schema_facts

__all__ = [
    "TRANSFER_MANIFEST_FILENAME",
    "TRANSFER_MANIFEST_SCHEMA_VERSION",
    "create_transfer_bundle",
    "verify_transfer_bundle",
]

#: Versioned identity of the sanitized public bundle manifest schema.
TRANSFER_MANIFEST_SCHEMA_VERSION = "1.0"

#: The manifest is the ONLY non-payload artifact inside a DATA_ONLY bundle.
TRANSFER_MANIFEST_FILENAME = "transfer-manifest.json"

#: The truthful index statement of a DATA_ONLY bundle: no index artifact is
#: transferable as valid until authoritative P6 validation exists.
_INDEX_STATE_DATA_ONLY = "DATA_ONLY_INDEX_OMITTED"

_CREATE_OPERATION = "create_transfer_bundle"
_VERIFY_OPERATION = "verify_transfer_bundle"

#: The denylist is DEFENSE IN DEPTH (the allowlist is authoritative):
#: artifact CLASSIFICATION by suffix/name pattern, case-insensitively, so
#: hostile names, casing or nesting can never smuggle protected state into a
#: transfer tree (vault databases/sidecars, foreign SQLite databases,
#: journals, logs, temporaries, locks, staging, unverified index artifacts,
#: foreign manifests and executables).
_FORBIDDEN_SUFFIXES = frozenset(
    {
        ".sqlite",
        ".sqlite3",
        ".sqlite-wal",
        ".sqlite3-wal",
        "-wal",
        "-shm",
        ".journal",
        ".jrn",
        ".log",
        ".tmp",
        ".temp",
        ".lock",
        ".staging",
        ".partial",
        ".bak",
        ".cdx",
        ".idx",
        ".dbc",
        ".dct",
        ".dcx",
        ".exe",
        ".dll",
        ".py",
        ".pyc",
        ".bat",
        ".cmd",
        ".ps1",
        ".sh",
        ".bin",
    }
)
_FORBIDDEN_BASENAME_MARKERS = (
    'temp-',
    "dictionary.sqlite",
    "recovery",
    "private-manifest",
    "source-manifest",
    "reverse-mapping",
    "mapping-table",
    "secret",
    "salt",
    "keyfile",
    "debug",
)


def _transfer_failure(detail_code: str) -> TransferError:
    """Stable typed, value-free transfer failure (no protected values)."""
    return TransferError(
        ErrorCode.TRANSFER_FAILED,
        context=ErrorContext(
            operation=_CREATE_OPERATION, detail_code=detail_code
        ),
    )


def _standalone_failure(detail_code: str) -> TransferError:
    return TransferError(
        ErrorCode.TRANSFER_FAILED,
        context=ErrorContext(
            operation=_VERIFY_OPERATION, detail_code=detail_code
        ),
    )


def _transfer_target_conflict(detail_code: str) -> PathError:
    return PathError(
        ErrorCode.DESTINATION_CONFLICT,
        context=ErrorContext(operation=_CREATE_OPERATION, detail_code=detail_code),
    )


def _normalized_artifact_path(
    relative_path: str,
    *,
    failure: Callable[[str], AnonymizerError] | None = None,
) -> str:
    """The canonical normalized relative artifact path (fail-closed)."""
    fail = failure if failure is not None else _transfer_failure
    if not relative_path or "\x00" in relative_path:
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    posix = PurePosixPath(relative_path.replace("\\", "/"))
    if posix.is_absolute() or posix.root or any(part == ".." for part in posix.parts):
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    if any(part in ("", ".", "..") for part in posix.parts):
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    return posix.as_posix()


def _forbidden_artifact_class(relative_path: str) -> str | None:
    """The forbidden artifact CLASS of a path, or ``None`` when transferable.

    Classification (not exact filenames) keeps hostile names, casing and
    nesting from bypassing the denylist; the allowlist remains the
    authoritative gate either way.
    """
    lowered = relative_path.lower()
    posix_name = PurePosixPath(lowered).name
    for suffix in _FORBIDDEN_SUFFIXES:
        if lowered.endswith(suffix):
            return "FORBIDDEN_ARTIFACT_CLASS"
    for marker in _FORBIDDEN_BASENAME_MARKERS:
        if marker in posix_name:
            return "FORBIDDEN_ARTIFACT_CLASS"
    if posix_name.startswith(".") or posix_name.startswith("~$"):
        return "FORBIDDEN_ARTIFACT_CLASS"
    return None


def _schema_digest(table: DirectSourceTable) -> str:
    """The non-sensitive logical schema fingerprint declared in the manifest."""
    fields, encoding, language_driver = _schema_facts(table)
    canonical = json.dumps(
        {
            "fields": [list(field) for field in fields],
            "encoding": encoding,
            "language_driver": language_driver,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sch-" + hashlib.sha256(canonical.encode("ascii")).hexdigest()[:32]


def _validated_profile(profile: object) -> TransferProfile:
    if profile is TransferProfile.DATA_ONLY or profile == "DATA_ONLY":
        return TransferProfile.DATA_ONLY
    raise _transfer_failure("TRANSFER_PROFILE_UNSUPPORTED")


def _copy_with_digest(
    source_path: Path,
    staged_path: Path,
    *,
    checkpoint: Callable[[], None],
) -> tuple[str, int]:
    """Copy one payload artifact with its bounded streaming SHA-256 digest.

    The public published DBF/FPT artifacts are transferred by exact byte
    copy (the same file-class semantics the P4 publication promotion uses);
    the digest is computed over the same streamed chunks with cooperative
    cancellation checkpoints.
    """
    digest = hashlib.sha256()
    size = 0
    staged_path.parent.mkdir(parents=True, exist_ok=True)
    with source_path.open("rb") as reader, staged_path.open("wb") as writer:
        while True:
            checkpoint()
            block = reader.read(1024 * 1024)
            if not block:
                break
            writer.write(block)
            digest.update(block)
            size += len(block)
            checkpoint()
    return digest.hexdigest(), size


def _build_manifest(
    *,
    result: PseudonymizationResult,
    artifacts: Sequence[dict[str, object]],
) -> dict[str, object]:
    """The sanitized public bundle manifest (REQ-P5-006).

    Only non-sensitive operational metadata: schema version, package and
    dbfbridge versions, the DATA_ONLY profile, the explicit PSEUDONYMIZED
    classification, normalized relative artifact paths/types/sizes/hashes,
    DBF record counts, logical schema fingerprints, the public relational
    assurance facts, the truthful DATA_ONLY index-omission state and the
    creation-verification status. No original values, no reverse mappings,
    no recovery parameters, no temporal offsets, no absolute paths.
    """
    assurance = result.assurance
    return {
        "schema_version": TRANSFER_MANIFEST_SCHEMA_VERSION,
        "package_version": _package_version(),
        "dbfbridge_version": _dbfbridge_version(),
        "profile": TransferProfile.DATA_ONLY.value,
        "classification": "PSEUDONYMIZED",
        "dataset_id": result.dataset.dataset_id,
        "index_state": _INDEX_STATE_DATA_ONLY,
        "verification_status": "CREATION_SELF_VERIFIED",
        "artifacts": [
            {
                "path": artifact["path"],
                "artifact_type": artifact["artifact_type"],
                "size_bytes": artifact["size_bytes"],
                "sha256": artifact["sha256"],
                "record_count": artifact.get("record_count"),
                "schema_fingerprint": artifact.get("schema_fingerprint"),
            }
            for artifact in artifacts
        ],
        "assurance": {
            "level": assurance.level.value,
            "declared_relations": assurance.declared_relations,
            "verified_relations": assurance.verified_relations,
            "failed_relations": assurance.failed_relations,
            "incomplete_relations": assurance.incomplete_relations,
            "evidence_fingerprint": assurance.evidence_fingerprint,
            "relationship_fingerprint": assurance.relationship_fingerprint,
            "evidence_schema_version": assurance.evidence_schema_version,
            "scope_note": assurance.scope_note,
        },
    }


def _package_version() -> str:
    import importlib.metadata as metadata

    try:
        return metadata.version("dbf_anonymizer")
    except metadata.PackageNotFoundError:  # pragma: no cover - defensive
        return "unknown"


def _dbfbridge_version() -> str:
    import importlib.metadata as metadata

    try:
        return metadata.version("dbfbridge")
    except metadata.PackageNotFoundError:  # pragma: no cover - defensive
        return "unknown"


def _bundle_identity(
    destination: Path, operation_id: str
) -> PublicationIdentity:
    """The transfer staging/lock identity (distinct per bundle destination)."""
    destination_identity = derive_destination_identity(destination)
    sibling_token = hashlib.sha256(
        f"transfer-{destination_identity}".encode("ascii")
    ).hexdigest()[:24]
    parent = destination.resolve(strict=False).parent
    return PublicationIdentity(
        operation_id=operation_id,
        destination=destination.resolve(strict=False),
        destination_identity=destination_identity,
        vault_fingerprint="bundle-vault-independent",
        binding_fingerprint=sibling_token,
        lock_path=parent / f".dbf-anonymizer-{sibling_token}.lock",
        staging_root=parent / f".dbf-anonymizer-{sibling_token}.staging",
    )


def create_transfer_bundle(
    result: PseudonymizationResult,
    *,
    destination: str | Path,
    profile: str | TransferProfile = "DATA_ONLY",
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> TransferBundleResult:
    """Create the safe standalone DATA_ONLY transfer bundle (REQ-P5-004).

    The bundle is built as a BRAND-NEW allowlisted tree — never a broad copy
    of the working directory: exactly the expected pseudonymized DBF tables,
    their required fresh FPT companions and the sanitized public manifest.
    Before any transferable byte is copied, the working dataset is proven to
    be the EXPECTED PUBLISHED dataset (the complete working-tree fingerprint
    must equal the supplied result's durable publication fingerprint — a
    modified or injected tree fails closed; extra working-tree artifacts
    therefore invalidate that identity contract and are handled truthfully,
    never silently rewritten). No vault, recovery mapping, temporal offset
    or any other protected state is read into the bundle.

    The sanitized manifest (versioned schema, bounded JSON-safe fields)
    carries only non-sensitive operational metadata: relative artifact
    paths/types/sizes/hashes, DBF record counts, logical schema
    fingerprints, the public relational assurance facts, the truthful
    DATA_ONLY index-omission state and the PSEUDONYMIZED classification
    (the bundle is never labelled anonymous).

    REQ-P1-008: ONE :class:`ProgressController`
    (``operation="create_transfer_bundle"``) drives the bounded phases
    (working-dataset proof, TRANSFER_SCAN copy/hash per artifact, manifest
    finalization and atomic publication); cancellation before the atomic
    promotion leaves no completed bundle and cleaned owned staging; the
    single terminal completion is emitted only after genuine publication.
    """
    if not isinstance(result, PseudonymizationResult):
        raise TypeError("create_transfer_bundle requires a PseudonymizationResult")
    profile_value = _validated_profile(profile)
    del profile_value
    context = result.execution_context
    if context is None:
        raise _transfer_failure("TRANSFER_RESULT_CONTEXT_MISSING")
    working_root = Path(context.output_root)
    destination = Path(destination)
    if destination.exists():
        raise _transfer_target_conflict("TRANSFER_TARGET_EXISTS")
    working_resolved = working_root.resolve(strict=False)
    destination_resolved = destination.resolve(strict=False)
    if (
        destination_resolved == working_resolved
        or working_resolved in destination_resolved.parents
        or destination_resolved in working_resolved.parents
    ):
        raise _transfer_target_conflict("TRANSFER_TARGET_OVERLAP")

    control = ProgressController(
        operation=_CREATE_OPERATION, progress=progress, cancel_check=cancel_check
    )
    control.start_phase(ProgressPhase.OPERATION)
    invocation_id = control.operation_id

    # --- 1. Working-dataset identity proof (fail closed) --------------------
    control.start_phase(ProgressPhase.SOURCE_VERIFICATION)
    current = fingerprint_dataset(
        working_root, checkpoint=control.check_cancelled
    )
    if current != result.output_fingerprint:
        raise _transfer_failure("TRANSFER_WORKING_DATASET_MISMATCH")

    # --- 2. The authoritative DATA_ONLY allowlist ---------------------------
    expected_payload: list[tuple[str, str]] = []
    for relative_path in result.dataset.table_paths:
        control.check_cancelled()
        table = read_source_table(
            working_root, relative_path, cancel_check=control.check_cancelled
        )
        expected_payload.append((relative_path, "DBF"))
        if table.has_memo_fields:
            companion = str(Path(relative_path).with_suffix(".fpt").as_posix())
            expected_payload.append((companion, "FPT"))
    allowlist: dict[str, tuple[str, str]] = {}
    for relative_path, artifact_type in expected_payload:
        normalized = _normalized_artifact_path(relative_path)
        if _forbidden_artifact_class(normalized) is not None:
            raise _transfer_failure("TRANSFER_FORBIDDEN_ARTIFACT")
        casefolded = normalized.casefold()
        if casefolded in allowlist:
            raise _transfer_failure("TRANSFER_MANIFEST_PATH_COLLISION")
        allowlist[casefolded] = (normalized, artifact_type)
    if len(allowlist) != len(expected_payload):
        raise _transfer_failure("TRANSFER_MANIFEST_PATH_COLLISION")

    # --- 3. Copy + hash the allowlisted payload into staging ----------------
    control.start_phase(ProgressPhase.TRANSFER_SCAN, total=len(allowlist))
    transfer_identity = _bundle_identity(destination, invocation_id)
    staging = DatasetStaging(transfer_identity)
    try:
        with DestinationLock(transfer_identity.lock_path):
            control.check_cancelled()
            staging.create()
            try:
                artifacts: list[dict[str, object]] = []
                for casefolded, (artifact_path, artifact_type) in sorted(
                    allowlist.items()
                ):
                    control.check_cancelled()
                    staged_path = staging.dataset_root / artifact_path
                    source_path = working_root / artifact_path
                    digest, size = _copy_with_digest(
                        source_path,
                        staged_path,
                        checkpoint=control.check_cancelled,
                    )
                    entry: dict[str, object] = {
                        "path": artifact_path,
                        "artifact_type": artifact_type,
                        "size_bytes": size,
                        "sha256": digest,
                    }
                    if artifact_type == "DBF":
                        table = read_source_table(
                            working_root,
                            artifact_path,
                            cancel_check=control.check_cancelled,
                        )
                        entry["record_count"] = _count_records(
                            table, checkpoint=control.check_cancelled
                        )
                        entry["schema_fingerprint"] = _schema_digest(table)
                    artifacts.append(entry)
                    control.bump(
                        ProgressPhase.TRANSFER_SCAN, table_path=artifact_path
                    )

                # --- 4. Sanitized manifest finalization ---------------------
                control.start_phase(ProgressPhase.PUBLICATION)
                manifest = _build_manifest(result=result, artifacts=artifacts)
                manifest_bytes = json.dumps(
                    manifest,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
                (staging.dataset_root / TRANSFER_MANIFEST_FILENAME).write_bytes(
                    manifest_bytes
                )
                manifest_fingerprint = "bundle-" + hashlib.sha256(
                    manifest_bytes
                ).hexdigest()
                # The last cancellation checkpoint immediately before the
                # atomic promotion; the committed publication is never
                # reclassified by a late poll.
                control.check_cancelled()
                staging.promote()
            except BaseException as primary:
                if isinstance(primary, Exception):
                    try:
                        staging.cleanup_owned()
                    except Exception as cleanup_exc:
                        cleanup_failure = _transfer_failure(
                            "TRANSFER_SENSITIVE_STAGING_CLEANUP_FAILED"
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
    bundle_result = TransferBundleResult(
        bundle_path=destination.name,
        profile=TransferProfile.DATA_ONLY,
        file_count=len(artifacts),
        manifest_fingerprint=manifest_fingerprint,
        verified=True,
        assurance=result.assurance,
    )
    # The single terminal completion is emitted only now — after the genuine
    # atomic promotion and the public result.
    control.complete(completed=len(artifacts), check_cancel=False)
    return bundle_result


def _count_records(
    table: DirectSourceTable, *, checkpoint: Callable[[], None]
) -> int:
    """The truthful DBF record count (bounded streaming, checkpointed)."""
    header_count = int(table.schema.record_count)
    streamed = 0
    for record in stream_table_records(
        table, include_deleted=True, memo_policy="skip", cancel_check=checkpoint
    ):
        checkpoint()
        streamed += 1
    if streamed != header_count:
        raise _transfer_failure("TRANSFER_RECORD_COUNT_MISMATCH")
    return streamed


def _digest_file(
    path: Path, *, checkpoint: Callable[[], None]
) -> tuple[str, int]:
    """The bounded streaming SHA-256 digest + size of one bundle artifact."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as reader:
        while True:
            checkpoint()
            block = reader.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def verify_transfer_bundle(
    bundle: str | Path,
    *,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> TransferBundleResult:
    """Standalone DATA_ONLY bundle verification (REQ-P5-007).

    Runs with ONLY the copied bundle directory — never the source dataset,
    the protected vault, any recovery mapping or any in-process execution
    context. Verifies the manifest schema/profile/classification, the strict
    allowlist (exact manifest/inventory equality, case-collision safety, no
    traversal/absolute paths), forbidden-artifact absence, every payload
    hash and size, DBF/FPT readability through the public dbfbridge
    boundary, record counts and logical schema facts, required FPT
    companions, and the truthful DATA_ONLY index-omission statement.
    Standalone verification never searches for or requests a vault.

    REQ-P1-008: ONE :class:`ProgressController`
    (``operation="verify_transfer_bundle"``) drives the bounded phases with
    cancellation checkpoints at every inventory/hash/record safe point; the
    single terminal completion is emitted only after the genuine verified
    result.
    """
    if isinstance(bundle, (str, Path)) is False or isinstance(
        bundle, (bytes, bytearray)
    ):
        raise TypeError("verify_transfer_bundle requires a bundle PATH")
    bundle_root = Path(bundle)
    if not bundle_root.is_dir():
        raise _standalone_failure("TRANSFER_BUNDLE_MISSING")

    control = ProgressController(
        operation=_VERIFY_OPERATION, progress=progress, cancel_check=cancel_check
    )
    control.start_phase(ProgressPhase.OPERATION)

    # --- 1. Inventory + manifest schema/profile/classification --------------
    control.start_phase(ProgressPhase.SOURCE_VERIFICATION, total=0)
    try:
        from dbf_anonymizer.engine.publication import _iter_dataset_files

        inventory = {
            relative: path for relative, path in _iter_dataset_files(bundle_root)
        }
    except Exception:
        raise _standalone_failure("TRANSFER_BUNDLE_UNREADABLE") from None
    manifest_relative = TRANSFER_MANIFEST_FILENAME
    if manifest_relative not in inventory:
        raise _standalone_failure("TRANSFER_MANIFEST_MISSING")
    for relative_path in inventory:
        if relative_path != manifest_relative and _forbidden_artifact_class(
            relative_path
        ):
            raise _standalone_failure("TRANSFER_FORBIDDEN_ARTIFACT")

    try:
        manifest_bytes = inventory[manifest_relative].read_bytes()
        manifest = json.loads(manifest_bytes.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE") from None
    if not isinstance(manifest, dict):
        raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
    if manifest.get("schema_version") != TRANSFER_MANIFEST_SCHEMA_VERSION:
        raise _standalone_failure("TRANSFER_MANIFEST_SCHEMA_UNSUPPORTED")
    if manifest.get("profile") != TransferProfile.DATA_ONLY.value:
        raise _standalone_failure("TRANSFER_PROFILE_UNSUPPORTED")
    if manifest.get("classification") != "PSEUDONYMIZED":
        raise _standalone_failure("TRANSFER_CLASSIFICATION_INVALID")
    if manifest.get("index_state") != _INDEX_STATE_DATA_ONLY:
        raise _standalone_failure("TRANSFER_INDEX_STATE_UNTRUTHFUL")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list):
        raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")

    # --- 2. Manifest inventory: path safety, allowlist equality, uniqueness -
    control.start_phase(ProgressPhase.TABLE_EVALUATION, total=len(entries))
    declared: dict[str, dict[str, object]] = {}
    for entry in entries:
        control.check_cancelled()
        if not isinstance(entry, dict):
            raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
        raw_path = entry.get("path")
        if not isinstance(raw_path, str):
            raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
        artifact_path = _normalized_artifact_path(raw_path, failure=_standalone_failure)
        if _forbidden_artifact_class(artifact_path):
            raise _standalone_failure("TRANSFER_FORBIDDEN_ARTIFACT")
        if artifact_path == TRANSFER_MANIFEST_FILENAME:
            raise _standalone_failure("TRANSFER_MANIFEST_PATH_COLLISION")
        casefolded = artifact_path.casefold()
        if casefolded in declared:
            raise _standalone_failure("TRANSFER_MANIFEST_PATH_COLLISION")
        artifact_type = entry.get("artifact_type")
        if artifact_type not in ("DBF", "FPT"):
            raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
        if artifact_path.casefold().endswith(".dbf") and artifact_type != "DBF":
            raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
        declared[casefolded] = {
            "path": artifact_path,
            "artifact_type": artifact_type,
            "size_bytes": entry.get("size_bytes"),
            "sha256": entry.get("sha256"),
            "record_count": entry.get("record_count"),
            "schema_fingerprint": entry.get("schema_fingerprint"),
        }
    expected_inventory = set(declared) | {manifest_relative.casefold()}
    actual_inventory = {relative.casefold() for relative in inventory}
    if actual_inventory != expected_inventory:
        raise _standalone_failure("TRANSFER_INVENTORY_MISMATCH")

    # --- 3. Payload hashes/sizes + DBF/FPT logical facts --------------------
    control.start_phase(ProgressPhase.VERIFICATION, total=len(declared))
    dbf_paths: list[str] = []
    fpt_paths: set[str] = set()
    for artifact_path, entry in sorted(declared.items()):
        control.check_cancelled()
        absolute = bundle_root / artifact_path
        size = entry["size_bytes"]
        digest = entry["sha256"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
        if not isinstance(digest, str) or not digest:
            raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
        computed_digest, computed_size = _digest_file(
            absolute, checkpoint=control.check_cancelled
        )
        if computed_size != size or computed_digest != digest:
            raise _standalone_failure("TRANSFER_HASH_MISMATCH")
        if entry["artifact_type"] == "DBF":
            table = read_source_table(
                bundle_root, artifact_path, cancel_check=control.check_cancelled
            )
            if int(table.schema.record_count) != entry.get("record_count"):
                raise _standalone_failure("TRANSFER_RECORD_COUNT_MISMATCH")
            if _schema_digest(table) != entry.get("schema_fingerprint"):
                raise _standalone_failure("TRANSFER_SCHEMA_MISMATCH")
            for field in table.schema.fields:
                if field.is_memo:
                    companion = str(
                        Path(artifact_path).with_suffix(".fpt").as_posix()
                    )
                    if companion.casefold() not in declared:
                        raise _standalone_failure("TRANSFER_FPT_COMPANION_MISSING")
        elif entry["artifact_type"] == "FPT":
            fpt_paths.add(artifact_path.casefold())
        control.bump(ProgressPhase.VERIFICATION, table_path=artifact_path)
    # No unexpected FPT: every declared FPT must belong to a memo DBF.
    for artifact_path, entry in declared.items():
        if entry["artifact_type"] == "DBF":
            table = read_source_table(
                bundle_root, artifact_path, cancel_check=control.check_cancelled
            )
            if table.has_memo_fields:
                companion = str(Path(artifact_path).with_suffix(".fpt").as_posix())
                fpt_paths.discard(companion.casefold())
    if fpt_paths:
        # Declared FPT companions without a memo DBF are unexpected artifacts.
        raise _standalone_failure("TRANSFER_UNEXPECTED_FPT")

    manifest_fingerprint = "bundle-" + hashlib.sha256(manifest_bytes).hexdigest()
    assurance = _manifest_assurance(manifest.get("assurance"))
    bundle_result = TransferBundleResult(
        bundle_path=bundle_root.name,
        profile=TransferProfile.DATA_ONLY,
        file_count=len(declared),
        manifest_fingerprint=manifest_fingerprint,
        verified=True,
        assurance=assurance,
    )
    # The single terminal completion is emitted only after the genuine
    # verified result (never after cancellation).
    control.complete(completed=len(declared))
    return bundle_result


def _manifest_assurance(payload: object) -> RelationalAssurance:
    """Reconstruct the public assurance from the sanitized manifest facts."""
    from dataclasses import fields as dataclass_fields

    if not isinstance(payload, dict):
        raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
    try:
        from dbf_anonymizer.models import RelationalAssuranceLevel

        level_value = payload["level"]
        declared = payload["declared_relations"]
        verified = payload["verified_relations"]
        failed = payload["failed_relations"]
        incomplete = payload["incomplete_relations"]
        evidence_fingerprint = payload["evidence_fingerprint"]
        relationship_fingerprint = payload["relationship_fingerprint"]
        evidence_schema_version = payload["evidence_schema_version"]
        scope_note = payload["scope_note"]
        level = RelationalAssuranceLevel(level_value)
        if not (
            isinstance(declared, int)
            and isinstance(verified, int)
            and isinstance(failed, int)
            and isinstance(incomplete, int)
            and verified + failed + incomplete == declared
            and isinstance(evidence_fingerprint, (str, type(None)))
            and isinstance(relationship_fingerprint, (str, type(None)))
            and isinstance(evidence_schema_version, (str, type(None)))
            and isinstance(scope_note, (str, type(None)))
        ):
            raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
        return RelationalAssurance(
            level=level,
            declared_relations=declared,
            verified_relations=verified,
            failed_relations=failed,
            incomplete_relations=incomplete,
            evidence_fingerprint=evidence_fingerprint,
            relationship_fingerprint=relationship_fingerprint,
            evidence_schema_version=evidence_schema_version,
            scope_note=scope_note,
        )
    except KeyError:
        raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE") from None
    del dataclass_fields