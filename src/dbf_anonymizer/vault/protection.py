"""Authoritative protected-vault path policy and artifact containment (REQ-P2-009).

ONE internal component that the future execution engine and transfer pipeline
MUST reuse; this module is deliberately NOT public API yet.

Responsibilities:

* **Protected-vault root policy** — a protected vault root must never overlap
  the source tree, the pseudonymized working-output tree or the (future)
  transfer-output tree: equality or containment in EITHER direction is
  refused, because sensitive vault artifacts could be swept into source or
  output publication through parent/child ambiguity.  Sibling trees are
  valid.  Comparison resolves aliases platform-safely: absolute
  normalization, ``.``/``..`` segments, symlinks and Windows
  junctions/reparse points where ``os.path.realpath`` supports them, plus
  Windows case-insensitive equivalence.  Failures are typed, fail closed and
  never expose absolute sensitive paths.

* **Sensitive-artifact containment** — the authoritative vocabulary of
  sensitive vault artifacts consists of DICTIONARY-DERIVED SQLite artifacts
  (the dictionary database plus its WAL/SHM/rollback-journal sidecars) plus
  FIXED reserved private-vault artifact names (future private recovery
  manifests and original-bearing spools).  Every such artifact stays rooted
  beside ``dictionary.sqlite3`` inside the protected vault tree.  There is
  NO recovery JSON sidecar, NO second SQLite recovery database and NO
  ordinary output copy of the vault.

* **Best-effort filesystem hardening** — POSIX: owner-only directory modes
  (``0700``) and owner read/write dictionary modes (``0600``) applied as
  early as practical, verified truthfully in tests; SQLite WAL/SHM stay
  protected by the protected directory boundary.  Windows: chmod-style POSIX
  bits do NOT create robust NTFS ACL isolation — the module makes no such
  claim, classifies Windows protection truthfully as limited/best-effort and
  the operator documentation requires ACL-restricted directories and
  protected volumes.  A REAL attempted-hardening failure is never silently
  swallowed: it surfaces as a typed, privacy-safe error.

* **Truthful security limits** — ordinary deletion is NOT secure deletion;
  filesystem journaling, snapshots, SSD wear leveling, copy-on-write and
  backups may retain old data; volume/full-disk encryption is recommended;
  vault backups are equally sensitive.  No forensic or cryptographic
  secure-deletion claim is made anywhere.
"""

from __future__ import annotations

import os
from pathlib import Path

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VaultError

__all__ = [
    "VAULT_PROTECTION_POLICY_VERSION",
    "SENSITIVE_VAULT_ARTIFACT_SUFFIXES",
    "RESERVED_PRIVATE_VAULT_VOCABULARY",
    "HARDENING_OWNER_MODES_APPLIED",
    "HARDENING_WINDOWS_LIMITED",
    "sensitive_artifact_names",
    "validate_protected_vault_root",
    "harden_vault_directory",
]

#: Versioned identity of the protected-vault path policy.
VAULT_PROTECTION_POLICY_VERSION = "1.0"

#: Sensitive sidecar suffixes SQLite derives from the dictionary filename.
#: All of them stay beside ``dictionary.sqlite3`` inside the vault root.
SENSITIVE_VAULT_ARTIFACT_SUFFIXES: tuple[str, ...] = (
    "-wal",
    "-shm",
    "-journal",
)

#: Fixed reserved private-vault artifact names (REQ-P2-009 vocabulary).  No
#: producer exists yet; the names are FIXED (NOT derived from the dictionary
#: filename) so a future private manifest or original-bearing spool can never
#: silently escape the vault root naming scheme.
RESERVED_PRIVATE_VAULT_VOCABULARY: tuple[str, ...] = (
    "recovery-manifest.private",
    "recovery-spool.private",
)

#: Truthful hardening classifications (bounded, privacy-safe).
HARDENING_OWNER_MODES_APPLIED = "OWNER_MODES_APPLIED"
HARDENING_WINDOWS_LIMITED = "WINDOWS_LIMITED_BEST_EFFORT"


def _vocabulary_invalid() -> VaultError:
    """Stable typed refusal for a non-basename dictionary filename."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code="SENSITIVE_VOCABULARY_INVALID"),
    )


def sensitive_artifact_names(dictionary_filename: str) -> tuple[str, ...]:
    """The COMPLETE authoritative sensitive-artifact vocabulary of one vault.

    The authoritative vocabulary consists of DICTIONARY-DERIVED SQLite
    artifacts (the dictionary database plus its ``-wal``/``-shm``/
    ``-journal`` sidecars, which only ever appear beside it) PLUS the fixed
    reserved private-vault artifact names (future private recovery manifests
    and original-bearing spools — fixed names, NOT derived from the
    dictionary filename).  No producer for the private artifacts exists yet.

    The helper is a basename vocabulary helper: a caller-supplied filename
    carrying path separators or absolute form is refused (fail closed,
    typed, privacy-safe) — every returned name is a plain basename, so the
    complete vocabulary stays rooted under whatever vault root it is joined
    with.
    """
    if (
        not isinstance(dictionary_filename, str)
        or not dictionary_filename
        or "/" in dictionary_filename
        or "\\" in dictionary_filename
        or Path(dictionary_filename).name != dictionary_filename
    ):
        raise _vocabulary_invalid()
    return (
        dictionary_filename,
        *(dictionary_filename + suffix for suffix in SENSITIVE_VAULT_ARTIFACT_SUFFIXES),
        *RESERVED_PRIVATE_VAULT_VOCABULARY,
    )


def _overlap_key(path: Path) -> str:
    """The platform-safe comparison key of one tree root.

    Absolute normalization, ``.``/``..`` resolution, symlink and (on Windows)
    junction/reparse resolution through ``os.path.realpath`` where supported,
    plus case-insensitive equivalence on Windows.
    """
    try:
        resolved = os.path.realpath(os.path.abspath(path))
    except OSError:
        resolved = os.path.abspath(path)
    if os.name == "nt":
        return resolved.casefold()
    return resolved


def _is_within(child_key: str, parent_key: str) -> bool:
    if child_key == parent_key:
        return True
    return child_key.startswith(parent_key.rstrip("/\\") + os.sep) or child_key.startswith(
        parent_key.rstrip("/") + "/"
    )


def _overlap_failure(detail_code: str) -> VaultError:
    """Stable typed refusal; never exposes absolute sensitive paths."""
    return VaultError(
        ErrorCode.VAULT_STATE_INVALID,
        context=ErrorContext(operation="vault", detail_code=detail_code),
    )


def validate_protected_vault_root(
    vault_root: Path,
    *,
    source_root: Path,
    working_output_root: Path | None = None,
    transfer_output_root: Path | None = None,
) -> None:
    """ONE authoritative protected-vault path policy (REQ-P2-009).

    The protected vault root must not be equal to, inside, or a parent of the
    source tree, the pseudonymized working-output tree, or — when supplied —
    the future transfer-output tree.  Sibling trees are valid.  Aliases are
    resolved as practically and platform-safely as possible (absolute
    normalization, ``.``/``..``, symlinks, Windows case-insensitive
    equivalence and junction/reparse equivalence where ``os.path.realpath``
    supports them).  Every refusal is typed, fail closed and free of absolute
    sensitive paths.
    """
    vault_key = _overlap_key(vault_root)
    candidates = (
        ("VAULT_ROOT_OVERLAP_SOURCE", source_root),
        ("VAULT_ROOT_OVERLAP_WORKING_OUTPUT", working_output_root),
        ("VAULT_ROOT_OVERLAP_TRANSFER_OUTPUT", transfer_output_root),
    )
    for detail_code, other_root in candidates:
        if other_root is None:
            continue
        other_key = _overlap_key(other_root)
        if vault_key == other_key or _is_within(vault_key, other_key) or _is_within(other_key, vault_key):
            raise _overlap_failure(detail_code)


def harden_vault_directory(directory: Path) -> str:
    """Best-effort filesystem hardening of the protected vault directory.

    POSIX: the vault directory receives owner-only modes (``0700``) and the
    dictionary file owner read/write modes (``0600``) as early as practical;
    a real attempted chmod failure surfaces as a typed, privacy-safe error
    (never silently swallowed).  SQLite WAL/SHM artifacts stay protected by
    the protected directory boundary.

    Windows: POSIX mode bits do not create robust NTFS ACL isolation and the
    module makes NO such claim — the truthful classification
    :data:`HARDENING_WINDOWS_LIMITED` is returned and operators must place
    the vault inside an ACL-restricted directory on an encrypted volume.
    """
    if os.name != "posix":
        # Truthful classification: no chmod-style claim is made on Windows.
        return HARDENING_WINDOWS_LIMITED
    try:
        os.chmod(directory, 0o700)
    except PermissionError:
        raise VaultError(
            ErrorCode.VAULT_ACCESS_DENIED,
            context=ErrorContext(operation="vault", detail_code="HARDENING_DENIED"),
        ) from None
    except OSError:
        raise VaultError(
            ErrorCode.VAULT_UNAVAILABLE,
            context=ErrorContext(operation="vault", detail_code="HARDENING_FAILED"),
        ) from None
    return HARDENING_OWNER_MODES_APPLIED
