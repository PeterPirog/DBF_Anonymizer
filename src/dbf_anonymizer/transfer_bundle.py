"""Safe standalone DATA_ONLY transfer bundles (REQ-P5-004..REQ-P5-007).

``create_transfer_bundle`` builds a BRAND-NEW allowlisted export tree from a
VERIFIED pseudonymized working dataset — never a broad copy of the working
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

Creation enforces the authoritative REQ-P5-001 verified-dataset precondition
by reusing the ONE internal verification core under its OWN controller
before any transferable byte is copied: only an objectively verified dataset
(PASS, or the single narrowly defined PARTIAL whose unproven dimension is
exactly the index class DATA_ONLY omits) may be exported; a corrupted,
tampered or policy/mapping-violating working dataset always refuses export.
No vault, recovery mapping, temporal offset or any other protected state is
read into the bundle; no recovery material is required by standalone
verification.

Before the final atomic promotion the COMPLETE staged bundle is
self-verified through the SAME private standalone validation core (strict
closed manifest schema, exact inventory, forbidden artifacts, hashes/sizes,
DBF/FPT readability, record counts, schema fingerprints, FPT companion
semantics and index-omission truthfulness) — ``verified=True`` is returned
only after that staged verification has genuinely succeeded; a staged
failure publishes nothing.

The manifest schema is versioned (:data:`TRANSFER_MANIFEST_SCHEMA_VERSION`)
with an EXACT closed key vocabulary (unknown or missing keys at the
top level, inside artifact entries or inside the assurance object all fail
closed), bounded value validation (byte size, artifact count, path/token
lengths, no absolute-path syntax, no control characters, exact verification
status vocabulary) and the bidirectional artifact-type/extension binding
(``DBF`` ⇔ ``.dbf`` and ``FPT`` ⇔ ``.fpt`` — a renamed payload can never be
accepted merely because its bytes are parseable). The manifest fingerprint
is the canonical digest of the finalized manifest bytes; normalized relative
paths are deduplicated case-insensitively (Windows collision safety),
traversal/absolute paths are refused and the deterministic canonical
ordering is authoritative. The denylist artifact CLASSIFICATION is defense
in depth (the allowlist stays authoritative).

REQ-P1-008: both long-running operations share the bounded
:class:`~dbf_anonymizer.progress.ProgressController`; cancellation is
polled at hash/copy chunks, table boundaries, record boundaries and
immediately before the atomic publication, and a pre-publication
cancellation leaves no completed bundle claim, no partial final tree and
cleaned owned staging. Callback failures remain typed, contained and
privacy-safe.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Sequence

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
    DatasetIdentity,
    PseudonymizationResult,
    RelationalAssurance,
    RelationalAssuranceLevel,
    TransferBundleResult,
    TransferProfile,
    VerificationStatus,
)
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)
from dbf_anonymizer.verification import (
    _schema_facts,
    _verify_dataset_core,
)
from dbf_anonymizer.vault.schema import VAULT_OPERATION_STATE_COMPLETED
from dbf_anonymizer.engine.publication import (
    result_from_receipt,
)
from dbf_anonymizer.dictionary_identity import (
    connect_dictionary_readonly,
    dictionary_sidecars,
    read_dictionary_identity,
)

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

#: The exact creation-verification status vocabulary of schema 1.0: the
#: producing service self-verified the staged bundle before promotion, and
#: the dataset-level verified precondition (REQ-P5-001) was enforced.
_VERIFICATION_STATUS_CREATED = "CREATION_SELF_VERIFIED"

_CREATE_OPERATION = "create_transfer_bundle"
_VERIFY_OPERATION = "verify_transfer_bundle"

# ---------------------------------------------------------------------------
# Closed manifest schema (REQ-P5-005/REQ-P5-006): EXACT key vocabularies.
# ---------------------------------------------------------------------------
_MANIFEST_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "package_version",
        "dbfbridge_version",
        "profile",
        "classification",
        "dataset_id",
        "index_state",
        "verification_status",
        "artifacts",
        "assurance",
    }
)
_MANIFEST_DBF_ARTIFACT_KEYS = frozenset(
    {
        "path",
        "artifact_type",
        "size_bytes",
        "sha256",
        "record_count",
        "schema_fingerprint",
    }
)
_MANIFEST_FPT_ARTIFACT_KEYS = frozenset(
    {
        "path",
        "artifact_type",
        "size_bytes",
        "sha256",
        "record_count",
        "schema_fingerprint",
    }
)
_MANIFEST_ASSURANCE_KEYS = frozenset(
    {
        "level",
        "declared_relations",
        "verified_relations",
        "failed_relations",
        "incomplete_relations",
        "evidence_fingerprint",
        "relationship_fingerprint",
        "evidence_schema_version",
        "scope_note",
    }
)
_ALLOWED_VERIFICATION_STATUSES = frozenset({"CREATION_SELF_VERIFIED"})
_ALLOWED_INDEX_STATES = frozenset({_INDEX_STATE_DATA_ONLY})

# ---------------------------------------------------------------------------
# Bounded limits for the UNTRUSTED standalone manifest input boundary.
# ---------------------------------------------------------------------------
#: The transferred manifest file may not exceed this byte size before parsing.
_MAX_MANIFEST_BYTES = 1_000_000
#: The maximum number of declared artifact entries.
_MAX_MANIFEST_ARTIFACTS = 4096
#: The maximum normalized relative artifact path length.
_MAX_ARTIFACT_PATH_LENGTH = 512
#: The maximum bounded machine-token/string length for manifest scalars.
_MAX_TOKEN_LENGTH = 128
#: The maximum length of the manifest's bounded free-text scope note.
_MAX_SCOPE_NOTE_LENGTH = 256

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
    "temp-",
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
    """The canonical normalized relative artifact path (fail-closed).

    The path is interpreted under BOTH pure path grammars — POSIX and
    Windows — because the bundle is intended to move BETWEEN operating
    systems: a name that is drive-qualified, rooted, absolute or a UNC
    reference under either interpretation (including forms that become
    drive-qualified after slash normalization, e.g. ``C:/evil.dbf``) is
    refused, as is every traversal form. Valid ordinary relative paths are
    never rejected.
    """
    fail = failure if failure is not None else _transfer_failure
    if not relative_path or "\x00" in relative_path:
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    if len(relative_path) > _MAX_ARTIFACT_PATH_LENGTH:
        raise fail("TRANSFER_MANIFEST_PATH_TOO_LONG")
    slashed = relative_path.replace("\\", "/")
    posix = PurePosixPath(slashed)
    if posix.is_absolute() or posix.root or any(part == ".." for part in posix.parts):
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    if any(part in ("", ".", "..") for part in posix.parts):
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    windows = PureWindowsPath(relative_path)
    if (
        windows.drive
        or windows.root
        or windows.is_absolute()
        or any(part == ".." for part in windows.parts)
    ):
        # Drive-qualified, rooted, absolute or UNC under the WINDOWS
        # grammar (covers C:/evil.dbf, C:\\evil.dbf and \\\\host\\share\\x).
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    if PureWindowsPath(slashed).drive:
        # A name that becomes drive-qualified after slash normalization.
        raise fail("TRANSFER_MANIFEST_PATH_INVALID")
    return posix.as_posix()


def _casefold_inventory(relative_paths: Sequence[str]) -> dict[str, str]:
    """The casefold-keyed inventory with EXPLICIT collision detection.

    A plain ``set()`` would silently collapse two ACTUAL files that differ
    only by case on a case-sensitive filesystem, hiding them from the
    allowlist comparison (a material REQ-P5-007 defect). This pure helper
    refuses any duplicate casefold key with a stable typed detail code so
    the invariant is testable on every platform with synthetic name lists.
    """
    by_casefold: dict[str, str] = {}
    for relative_path in relative_paths:
        key = relative_path.casefold()
        if key in by_casefold:
            raise _standalone_failure("TRANSFER_INVENTORY_CASE_COLLISION")
        by_casefold[key] = relative_path
    return by_casefold


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
        "verification_status": _VERIFICATION_STATUS_CREATED,
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


_VERIFICATION_STATUS_CREATED = "CREATION_SELF_VERIFIED"


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


def _iter_bundle_inventory(
    bundle_root: Path,
    *,
    failure: Callable[[str], AnonymizerError] | None = None,
) -> dict[str, Path]:
    """The canonical bundle inventory (fail-closed on unreadable trees)."""
    from dbf_anonymizer.engine.publication import _iter_dataset_files

    fail = failure if failure is not None else _standalone_failure
    try:
        return {
            relative: path for relative, path in _iter_dataset_files(bundle_root)
        }
    except Exception:
        raise fail("TRANSFER_BUNDLE_UNREADABLE") from None


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


def _bounded_manifest_text(value: object, *, max_length: int) -> str:
    """Validate one hostile manifest scalar as a bounded safe string."""
    if not isinstance(value, str):
        raise _owning_failure("TRANSFER_MANIFEST_VALUE_INVALID")
    if len(value) > max_length or "\x00" in value:
        raise _owning_failure("TRANSFER_MANIFEST_VALUE_INVALID")
    if any(character.isprintable() is False for character in value):
        raise _owning_failure("TRANSFER_MANIFEST_VALUE_INVALID")
    if (
        "\\" in value
        or value.startswith("/")
        or PurePosixPath(value.lower()).is_absolute()
        or any(part == ".." for part in PurePosixPath(value.lower()).parts)
    ):
        # No absolute-path syntax may hide inside a manifest string.
        raise _owning_failure("TRANSFER_MANIFEST_VALUE_INVALID")
    return value


def _bounded_manifest_token(value: object) -> str:
    """A bounded machine token (no whitespace, no path syntax)."""
    token = _bounded_manifest_text(value, max_length=_MAX_TOKEN_LENGTH)
    if token != token.strip() or any(character.isspace() for character in token):
        raise _owning_failure("TRANSFER_MANIFEST_VALUE_INVALID")
    return token


def _validate_manifest_contract(
    manifest: object,
    *,
    failure: Callable[[str], AnonymizerError] | None = None,
) -> dict[str, dict[str, object]]:
    """The ONE authoritative strict closed-schema manifest validator.

    Schema 1.0 requires EXACTLY the allowed top-level keys, the exact
    per-entry artifact vocabularies and the exact assurance key set —
    unknown, missing or duplicated keys fail closed with stable
    privacy-safe detail codes (a hostile transferred manifest can never add
    private fields such as ``vault_path``, ``original_value``,
    ``date_offset`` or ``reverse_mapping`` and still verify). Every
    top-level value is validated (bounded strings, no absolute-path syntax,
    no control characters, exact token/verification vocabularies) and the
    bidirectional artifact-type/extension binding is enforced (``DBF`` ⇔
    ``.dbf`` and ``FPT`` ⇔ ``.fpt`` case-insensitively), so a valid table
    renamed to an arbitrary extension can never pass merely because its
    bytes are parseable.
    """
    fail = failure if failure is not None else _standalone_failure
    if not isinstance(manifest, dict):
        raise fail("TRANSFER_MANIFEST_UNREADABLE")
    manifest_keys = set(manifest)
    if manifest_keys != set(_MANIFEST_TOP_LEVEL_KEYS):
        raise fail("TRANSFER_MANIFEST_SCHEMA_INVALID")
    for scalar in (
        "schema_version",
        "package_version",
        "dbfbridge_version",
        "profile",
        "classification",
        "dataset_id",
        "index_state",
        "verification_status",
    ):
        _bounded_manifest_token(manifest[scalar])
    if manifest["schema_version"] != TRANSFER_MANIFEST_SCHEMA_VERSION:
        raise fail("TRANSFER_MANIFEST_SCHEMA_UNSUPPORTED")
    if manifest["profile"] != TransferProfile.DATA_ONLY.value:
        raise fail("TRANSFER_PROFILE_UNSUPPORTED")
    if manifest["classification"] != "PSEUDONYMIZED":
        raise fail("TRANSFER_CLASSIFICATION_INVALID")
    if manifest["index_state"] != _INDEX_STATE_DATA_ONLY:
        raise fail("TRANSFER_INDEX_STATE_UNTRUTHFUL")
    if manifest["verification_status"] not in _ALLOWED_VERIFICATION_STATUSES:
        raise fail("TRANSFER_VERIFICATION_STATUS_INVALID")
    if not manifest["dataset_id"].startswith("ds-") or len(
        manifest["dataset_id"]
    ) != len("ds-") + 16:
        raise fail("TRANSFER_MANIFEST_VALUE_INVALID")
    entries = manifest["artifacts"]
    if not isinstance(entries, list) or not entries:
        raise fail("TRANSFER_MANIFEST_UNREADABLE")
    if len(entries) > _MAX_MANIFEST_ARTIFACTS:
        raise fail("TRANSFER_MANIFEST_TOO_LARGE")
    declared: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise fail("TRANSFER_MANIFEST_UNREADABLE")
        artifact_type = entry.get("artifact_type")
        if artifact_type == "DBF":
            expected_keys = _MANIFEST_DBF_ARTIFACT_KEYS
        elif artifact_type == "FPT":
            expected_keys = _MANIFEST_FPT_ARTIFACT_KEYS
        else:
            raise fail("TRANSFER_MANIFEST_UNREADABLE")
        if artifact_type not in ("DBF", "FPT"):
            raise fail("TRANSFER_MANIFEST_UNREADABLE")
        if set(entry) != set(expected_keys):
            raise fail("TRANSFER_MANIFEST_SCHEMA_INVALID")
        raw_path = entry["path"]
        if not isinstance(raw_path, str):
            raise fail("TRANSFER_MANIFEST_UNREADABLE")
        artifact_path = _normalized_artifact_path(raw_path, failure=fail)
        if artifact_path == TRANSFER_MANIFEST_FILENAME:
            raise fail("TRANSFER_MANIFEST_PATH_COLLISION")
        forbidden = _forbidden_artifact_class(artifact_path)
        if forbidden is not None:
            raise fail("TRANSFER_FORBIDDEN_ARTIFACT")
        lowered = artifact_path.casefold()
        # The bidirectional artifact-type/extension binding (REQ-P5-005).
        if artifact_type == "DBF" and not lowered.endswith(".dbf"):
            raise fail("TRANSFER_ARTIFACT_TYPE_MISMATCH")
        if artifact_type == "FPT" and not lowered.endswith(".fpt"):
            raise fail("TRANSFER_ARTIFACT_TYPE_MISMATCH")
        if lowered.endswith(".dbf") and artifact_type != "DBF":
            raise fail("TRANSFER_ARTIFACT_TYPE_MISMATCH")
        if lowered.endswith(".fpt") and artifact_type != "FPT":
            raise fail("TRANSFER_ARTIFACT_TYPE_MISMATCH")
        if lowered in declared:
            raise fail("TRANSFER_MANIFEST_PATH_COLLISION")
        size = entry["size_bytes"]
        digest = entry["sha256"]
        record_count = entry["record_count"]
        schema_fingerprint = entry["schema_fingerprint"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise fail("TRANSFER_MANIFEST_VALUE_INVALID")
        if not isinstance(digest, str) or not digest or len(digest) > _MAX_TOKEN_LENGTH:
            raise fail("TRANSFER_MANIFEST_VALUE_INVALID")
        if artifact_type == "DBF":
            if (
                not isinstance(record_count, int)
                or isinstance(record_count, bool)
                or record_count < 0
            ):
                raise fail("TRANSFER_MANIFEST_VALUE_INVALID")
            if not isinstance(schema_fingerprint, str) or not schema_fingerprint:
                raise fail("TRANSFER_MANIFEST_VALUE_INVALID")
        else:
            # The FPT entry vocabulary: companion metadata is deliberately
            # null (the logical facts belong to the DBF entry).
            if record_count is not None or schema_fingerprint is not None:
                raise fail("TRANSFER_MANIFEST_VALUE_INVALID")
        declared[lowered] = {
            "path": artifact_path,
            "artifact_type": artifact_type,
            "size_bytes": size,
            "sha256": digest,
            "record_count": record_count,
            "schema_fingerprint": schema_fingerprint,
        }
    if len(declared) < 1:
        raise fail("TRANSFER_MANIFEST_UNREADABLE")
    return declared


_OWNING_OPERATION: str = "verify_transfer_bundle"


def _owning_failure(detail_code: str) -> AnonymizerError:
    """The owning-operation failure factory of the running core.

    The shared private bundle validator is used by TWO public operations;
    each supplies its own failure factory so every typed failure carries
    the OWNING operation context (never the other operation's identity).
    """
    if _OWNING_OPERATION == _CREATE_OPERATION:
        return _transfer_failure(detail_code)
    return _standalone_failure(detail_code)


def _manifest_assurance(
    payload: object,
    *,
    fail: Callable[[str], AnonymizerError],
) -> RelationalAssurance:
    """Reconstruct the public assurance from the sanitized manifest facts.

    Every hostile manifest/model validation failure (unknown level, negative
    or boolean counts, inconsistent totals, malformed fingerprints or scope
    note, missing keys) is converted into the typed privacy-safe transfer
    refusal — a raw ValueError/TypeError can never escape standalone
    verification.

    The sanitized-manifest VALUE contract is strict (REQ-P5-005/REQ-P5-006):
    ``scope_note`` must be the EXACT authoritative
    ``RELATIONAL_ASSURANCE_SCOPE_NOTE`` token of the relationship assurance
    layer (never arbitrary free text that could carry private strings),
    ``evidence_schema_version`` must be the EXACT currently supported
    ``EVIDENCE_SCHEMA_VERSION``, and both fingerprints must be ``None`` or
    exactly 64 lowercase hexadecimal SHA-256 characters.
    """
    if not isinstance(payload, dict):
        raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
    if set(payload) != set(_MANIFEST_ASSURANCE_KEYS):
        raise _standalone_failure("TRANSFER_MANIFEST_SCHEMA_INVALID")
    try:
        from dbf_anonymizer.models import RelationalAssuranceLevel
        from dbf_anonymizer.relationships.assurance import (
            RELATIONAL_ASSURANCE_SCOPE_NOTE,
        )
        from dbf_anonymizer.relationships.verification import (
            EVIDENCE_SCHEMA_VERSION,
        )

        level = RelationalAssuranceLevel(payload["level"])
        declared = payload["declared_relations"]
        verified = payload["verified_relations"]
        failed = payload["failed_relations"]
        incomplete = payload["incomplete_relations"]
        evidence_fingerprint = payload["evidence_fingerprint"]
        relationship_fingerprint = payload["relationship_fingerprint"]
        evidence_schema_version = payload["evidence_schema_version"]
        scope_note = payload["scope_note"]
        counts_ok = all(
            isinstance(count, int) and not isinstance(count, bool) and count >= 0
            for count in (declared, verified, failed, incomplete)
        )
        # Every declared relation is classified into EXACTLY one category —
        # none may disappear from the accounting.
        totals_complete = counts_ok and (
            verified + failed + incomplete == declared
        )
        fingerprint_ok = all(
            value is None
            or (
                isinstance(value, str)
                and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
            )
            for value in (evidence_fingerprint, relationship_fingerprint)
        )
        evidence_version_ok = evidence_schema_version in (None, EVIDENCE_SCHEMA_VERSION)
        scope_note_ok = scope_note in (None, RELATIONAL_ASSURANCE_SCOPE_NOTE)
        if not (totals_complete and fingerprint_ok and evidence_version_ok and scope_note_ok):
            raise _standalone_failure("TRANSFER_MANIFEST_VALUE_INVALID")
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
    except (KeyError, ValueError, TypeError):
        raise _standalone_failure("TRANSFER_MANIFEST_VALUE_INVALID") from None


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    global _OWNING_OPERATION
    """Reject DUPLICATE JSON object keys before json.loads collapses them.

    This is an UNTRUSTED transferable JSON boundary: a manifest carrying
    ``{"classification": "ANONYMOUS", "classification": "PSEUDONYMIZED"}``
    must never be interpreted according to "last value wins". Duplicates are
    detected recursively (top level, artifact entries, assurance object)
    and rejected with a typed, privacy-safe refusal.
    """
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            if _OWNING_OPERATION == _CREATE_OPERATION:
                raise _transfer_failure("TRANSFER_MANIFEST_DUPLICATE_KEY")
            raise _standalone_failure("TRANSFER_MANIFEST_DUPLICATE_KEY")
        result[key] = value
    return result


def _strict_json_loads(manifest_bytes: bytes) -> dict[str, object]:
    loaded = json.loads(
        manifest_bytes.decode("ascii"), object_pairs_hook=_reject_duplicate_keys
    )
    if not isinstance(loaded, dict):
        raise _standalone_failure("TRANSFER_MANIFEST_UNREADABLE")
    return loaded


def _verify_bundle_core(
    bundle_root: Path,
    *,
    control: ProgressController,
    failure: Callable[[str], AnonymizerError] | None = None,
) -> tuple[str, RelationalAssurance, int]:
    global _OWNING_OPERATION
    """The ONE standalone DATA_ONLY bundle validation core (REQ-P5-007).

    Runs with ONLY the bundle directory — never the source dataset, the
    protected vault, any recovery mapping or any in-process execution
    context — through the caller's controller and the caller's OWNING
    failure factory (the public standalone verifier attributes every typed
    failure to ``verify_transfer_bundle``; bundle creation reuses this core
    under its OWN controller and failure factory for the pre-promotion
    staged self-verification, so every internal stage is attributed to
    ``create_transfer_bundle``).

    Validates: the strict closed manifest schema (exact top-level /
    artifact-entry / assurance key vocabularies, bounded value validation
    and the bidirectional artifact-type/extension binding), the strict
    allowlist (exact manifest/inventory equality with EXPLICIT
    actual-filesystem case-collision detection), forbidden-artifact
    absence, every payload hash and size, TRUE DBF/FPT READABILITY through
    the public dbfbridge boundary (every physical record streamed with memo
    payloads read inline, deleted records included, record counts proven
    against the manifest AND the header), logical schema facts, required
    FPT companions, no unexpected FPT and the truthful DATA_ONLY
    index-omission statement. Cancellation is polled at every
    inventory/hash/record safe point.
    """
    global _OWNING_OPERATION
    _OWNING_OPERATION = (
        _CREATE_OPERATION if failure is _transfer_failure else _VERIFY_OPERATION
    )
    fail = failure if failure is not None else _standalone_failure
    control.start_phase(ProgressPhase.SOURCE_VERIFICATION)
    inventory = _iter_bundle_inventory(bundle_root, failure=fail)
    manifest_relative = TRANSFER_MANIFEST_FILENAME
    if manifest_relative.casefold() not in {key for key in inventory}:
        raise fail("TRANSFER_MANIFEST_MISSING")
    for relative_path in inventory:
        control.check_cancelled()
        if relative_path != manifest_relative and _forbidden_artifact_class(
            relative_path
        ):
            raise fail("TRANSFER_FORBIDDEN_ARTIFACT")
    manifest_path = inventory[manifest_relative]
    try:
        if manifest_path.stat().st_size > _MAX_MANIFEST_BYTES:
            raise fail("TRANSFER_MANIFEST_TOO_LARGE")
        manifest_bytes = manifest_path.read_bytes()
        manifest = _strict_json_loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise fail("TRANSFER_MANIFEST_UNREADABLE") from None
    except OSError:
        raise fail("TRANSFER_BUNDLE_UNREADABLE") from None
    declared = _validate_manifest_contract(manifest, failure=fail)

    # Strict allowlist: exact manifest/inventory equality with EXPLICIT
    # actual-filesystem case-collision detection (a plain set() would
    # collapse two real files differing only by case on a case-sensitive
    # filesystem — a material REQ-P5-007 allowlist defect).
    control.start_phase(ProgressPhase.TABLE_EVALUATION, total=len(declared))
    actual_by_casefold = _casefold_inventory(tuple(inventory))
    expected_inventory = set(declared) | {manifest_relative.casefold()}
    if set(actual_by_casefold) != expected_inventory:
        raise fail("TRANSFER_INVENTORY_MISMATCH")

    # Payload hashes/sizes + TRUE DBF/FPT logical readability (bounded,
    # checkpointed; every record and every memo payload is actually read).
    control.start_phase(ProgressPhase.VERIFICATION, total=len(declared))
    companion_expectations: set[str] = set()
    for artifact_path, entry in sorted(declared.items()):
        control.check_cancelled()
        absolute = bundle_root / artifact_path
        computed_digest, computed_size = _digest_file(
            absolute, checkpoint=control.check_cancelled
        )
        if (
            computed_size != entry["size_bytes"]
            or computed_digest != entry["sha256"]
        ):
            raise fail("TRANSFER_HASH_MISMATCH")
        if entry["artifact_type"] == "DBF":
            table = read_source_table(
                bundle_root, artifact_path, cancel_check=control.check_cancelled
            )
            if int(table.schema.record_count) != entry["record_count"]:
                raise fail("TRANSFER_RECORD_COUNT_MISMATCH")
            if _schema_digest(table) != entry["schema_fingerprint"]:
                raise fail("TRANSFER_SCHEMA_MISMATCH")
            streamed = 0
            memo_policy = "inline" if table.has_memo_fields else "skip"
            for record in stream_table_records(
                table,
                include_deleted=True,
                memo_policy=memo_policy,
                cancel_check=control.check_cancelled,
            ):
                # Every physical record (deleted included) and every memo
                # payload is actually READ through the public boundary; a
                # corrupted record body or FPT block fails even when the
                # attacker also updated the manifest hash/size.
                control.check_cancelled()
                streamed += 1
            if streamed != entry["record_count"]:
                raise fail("TRANSFER_RECORD_COUNT_MISMATCH")
            for field in table.schema.fields:
                if field.is_memo:
                    companion = str(
                        Path(artifact_path).with_suffix(".fpt").as_posix()
                    )
                    if companion.casefold() not in declared:
                        raise fail("TRANSFER_FPT_COMPANION_MISSING")
        control.bump(ProgressPhase.VERIFICATION, table_path=artifact_path)
    # No unexpected FPT: every declared FPT must belong to a memo DBF.
    for artifact_path, entry in declared.items():
        if entry["artifact_type"] == "DBF":
            table = read_source_table(
                bundle_root, artifact_path, cancel_check=control.check_cancelled
            )
            if table.has_memo_fields:
                companion = str(Path(artifact_path).with_suffix(".fpt").as_posix())
                companion_expectations.add(companion.casefold())
    declared_fpt_paths = {
        artifact_path
        for artifact_path, entry in declared.items()
        if entry["artifact_type"] == "FPT"
    }
    if declared_fpt_paths - companion_expectations:
        raise fail("TRANSFER_UNEXPECTED_FPT")

    manifest_fingerprint = "bundle-" + hashlib.sha256(manifest_bytes).hexdigest()
    assurance = _manifest_assurance(
        manifest.get("assurance"), fail=fail
    )
    return manifest_fingerprint, assurance, len(declared)


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
    Before any transferable byte is copied, the VERIFIED-dataset
    precondition (REQ-P5-004/P5-001) is enforced by reusing the ONE internal
    verification core under THIS operation's controller: only an objectively
    verified dataset (PASS, or the single narrowly defined PARTIAL whose
    unproven dimension is exactly the index class DATA_ONLY omits) may be
    exported; corruption, policy/mapping violations or a source change
    always refuse export with the typed transfer contract. The working
    dataset must ALSO still be the expected published dataset (the complete
    working-tree fingerprint must equal the supplied result's durable
    publication fingerprint — a modified or injected tree fails closed). No
    vault, recovery mapping, temporal offset or any other protected state is
    read into the bundle.

    The sanitized manifest (closed schema 1.0) carries only non-sensitive
    operational metadata and the explicit PSEUDONYMIZED classification
    (never anonymous). Before the final atomic promotion the ENTIRE staged
    bundle is self-verified through the SAME private standalone validation
    core (strict closed manifest schema, exact inventory, forbidden
    artifacts, hashes/sizes, DBF/FPT readability, record counts, schema
    fingerprints, FPT companion semantics and index-omission truthfulness) —
    ``verified=True`` is returned only after that staged verification has
    genuinely succeeded; a staged failure publishes nothing.

    REQ-P1-008: ONE :class:`ProgressController`
    (``operation="create_transfer_bundle"``) drives the bounded phases
    (verified-dataset precondition, working-dataset identity proof,
    TRANSFER_SCAN copy/hash per artifact, staged self-verification, manifest
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

    # --- 1. The REQ-P5-001 verified-dataset precondition --------------------
    # Reusing the ONE internal verification core under THIS controller: the
    # data/privacy invariants are the authoritative P5-001 ones (not a second
    # algorithm), and cancellation/callback failures stay attributed to the
    # create_transfer_bundle operation.
    control.start_phase(ProgressPhase.VAULT_VERIFICATION)
    verification_result = _verify_dataset_core(
        result,
        control=control,
        source_root=Path(context.source_root),
        output_root=working_root,
        vault_path=Path(context.vault_path),
        failure=_transfer_failure,
        owning_operation=_CREATE_OPERATION,
    )
    if verification_result.status is VerificationStatus.PASS:
        pass
    elif verification_result.status is VerificationStatus.PARTIAL and (
        verification_result.check_codes == ("INDEX_ARTIFACT_UNVERIFIED",)
    ):
        # The single narrowly defined exportable PARTIAL: the ONLY unproven
        # dimension is the index class that DATA_ONLY deliberately omits
        # (never a generic PARTIAL and never a FAIL).
        pass
    else:
        raise _transfer_failure("TRANSFER_DATASET_NOT_VERIFIED")

    # --- 2. Working-dataset identity proof (fail closed) --------------------
    control.start_phase(ProgressPhase.SOURCE_VERIFICATION)
    current = fingerprint_dataset(
        working_root, checkpoint=control.check_cancelled
    )
    if current != result.output_fingerprint:
        raise _transfer_failure("TRANSFER_WORKING_DATASET_MISMATCH")

    # --- 3. The authoritative DATA_ONLY allowlist ---------------------------
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

    # --- 4. Copy + hash the allowlisted payload into staging ----------------
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

                # --- 5. Sanitized manifest finalization ---------------------
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

                # --- 6. Staged bundle self-verification (BEFORE promotion) --
                # The SAME private standalone validation core proves the
                # complete staged bundle so the returned verified=True is
                # objectively supported by bundle evidence; every typed
                # failure is attributed to the create_transfer_bundle
                # operation through its own failure factory.
                control.start_phase(ProgressPhase.VERIFICATION)
                _verify_bundle_core(
                    staging.dataset_root,
                    control=control,
                    failure=_transfer_failure,
                )

                # --- 7. Atomic promotion ------------------------------------
                control.start_phase(ProgressPhase.PUBLICATION)
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


def verify_transfer_bundle(
    bundle: str | Path,
    *,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> TransferBundleResult:
    """Standalone DATA_ONLY bundle verification (REQ-P5-007).

    Runs with ONLY the copied bundle directory — never the source dataset,
    the protected vault, any recovery mapping or any in-process execution
    context — through the ONE private validation core: the strict closed
    manifest schema (unknown/missing keys fail closed), the strict
    allowlist (exact manifest/inventory equality, case-collision safety, no
    traversal/absolute paths), forbidden-artifact absence, every payload
    hash and size, DBF/FPT readability through the public dbfbridge
    boundary, record counts, logical schema facts, required FPT companions,
    no unexpected FPT, the bidirectional artifact-type/extension binding and
    the truthful DATA_ONLY index-omission statement. Standalone verification
    never searches for or requests a vault.

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
    manifest_fingerprint, assurance, artifact_count = _verify_bundle_core(
        bundle_root, control=control, failure=_standalone_failure
    )
    bundle_result = TransferBundleResult(
        bundle_path=bundle_root.name,
        profile=TransferProfile.DATA_ONLY,
        file_count=artifact_count,
        manifest_fingerprint=manifest_fingerprint,
        verified=True,
        assurance=assurance,
    )
    # The single terminal completion is emitted only after the genuine
    # verified result (never after cancellation).
    control.complete(completed=artifact_count)
    return bundle_result
