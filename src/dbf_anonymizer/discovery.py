"""Source dataset discovery for REQ-P1-005 read-only planning.

Discovers DBF tables and their companion artifacts under a source root.
Uses only public ``dbfbridge`` read APIs for schema and companion facts.
IDX files are inventoried globally for fingerprinting but never associated
with a specific DBF by inference.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import dbfbridge

from dbf_anonymizer import progress as _progress
from dbf_anonymizer.errors import CancellationError, CallbackError

_DBF_EXTENSIONS = frozenset({".dbf"})
_FPT_EXTENSIONS = frozenset({".fpt"})
_CDX_EXTENSIONS = frozenset({".cdx"})
_IDX_EXTENSIONS = frozenset({".idx"})

IN_SCOPE_EXTENSIONS = _DBF_EXTENSIONS | _FPT_EXTENSIONS | _CDX_EXTENSIONS | _IDX_EXTENSIONS

# ---------------------------------------------------------------------------
# Internal stat-based path probe (shared by preflight security decisions)
# ---------------------------------------------------------------------------
# Pathlib's Path.exists()/is_file()/is_dir() predicates suppress OS-level
# errors on modern Python (3.12+): an inaccessible (e.g. permission-denied)
# path reports as missing. Security-relevant inspection must therefore use a
# raw stat probe where ONLY FileNotFoundError means "missing"; PermissionError
# and every other OSError propagate to the caller for deterministic fail-closed
# handling (PATH_INSPECTION_UNAVAILABLE / SOURCE_UNAVAILABLE /
# STORAGE_ESTIMATE_UNAVAILABLE).
_PATH_MISSING = "missing"
_PATH_FILE = "file"
_PATH_DIRECTORY = "directory"
_PATH_OTHER = "other"
#: A path component that is not a directory (NotADirectoryError): the
#: hierarchy is blocked/invalid, not innocent-empty.
_PATH_BLOCKED = "blocked"


def probe_path(path: Path) -> str:
    """Classify *path* with one raw stat probe (never pathlib predicates).

    Returns one of the ``_PATH_*`` kind constants. Raises ``OSError`` when the
    path cannot be inspected (e.g. ``PermissionError``): an inaccessible path
    is NEVER treated as missing.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return _PATH_MISSING
    except NotADirectoryError:
        # A component of *path* itself is not a directory: the hierarchy is
        # blocked/invalid. Callers treat it deterministically (an uncreatable
        # destination), never as a missing/empty path.
        return _PATH_BLOCKED
    if stat_module.S_ISDIR(st.st_mode):
        return _PATH_DIRECTORY
    if stat_module.S_ISREG(st.st_mode):
        return _PATH_FILE
    return _PATH_OTHER


@dataclass(frozen=True, slots=True)
class DiscoveredTable:
    """One discovered DBF table with its companion artifacts."""

    relative_path: str
    memo_relative_path: str | None
    record_count: int
    field_count: int
    structural_cdx: bool
    dbc_bound: bool
    companion_cdx_relative_path: str | None


@dataclass(frozen=True, slots=True)
class ArtifactFingerprintEntry:
    """One artifact included in the source fingerprint."""

    relative_path: str
    artifact_type: str
    size_bytes: int
    sha256: str


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _safe_relative(path: str | None, root: Path) -> str | None:
    """Normalize a companion path relative to source root, or return None."""
    if path is None:
        return None
    p = Path(path)
    if not p.is_absolute():
        p = (root.parent / p) if not p.exists() else Path.cwd() / p
    try:
        resolved = p.resolve()
        root_resolved = root.resolve()
        rel = resolved.relative_to(root_resolved)
        return rel.as_posix()
    except (ValueError, OSError):
        return None


def _file_sha256(
    path: Path,
    *,
    cancel_probe: Callable[[], None] | None = None,
) -> str:
    """Compute the SHA-256 of *path* in the existing 64 KiB-chunk streaming way.

    ``cancel_probe`` (a REQ-P1-008 private hook supplied by the progress
    controller) is invoked before the first chunk and at least every
    ``FINGERPRINT_CANCEL_CHUNK_QUANTUM`` chunks while hashing, so cooperative
    cancellation can be observed no later than the declared bound even for a
    very large artifact.  With ``cancel_probe=None`` the hashing is exactly
    the pre-existing behavior (same reads, same digest).
    """
    h = hashlib.sha256()
    cancel_quantum = _progress.FINGERPRINT_CANCEL_CHUNK_QUANTUM
    chunk_size = _progress.FINGERPRINT_HASH_CHUNK_SIZE
    chunks = 0
    with path.open("rb") as fh:
        while True:
            if cancel_probe is not None and chunks % cancel_quantum == 0:
                cancel_probe()
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            chunks += 1
    return h.hexdigest()


def discover_tables(
    source_root: Path,
    *,
    cancel_probe: Callable[[], None] | None = None,
    progress_probe: Callable[[str], None] | None = None,
) -> tuple[DiscoveredTable, ...]:
    """Discover all DBF tables under *source_root* deterministically.

    Returns a tuple sorted by normalized relative path.

    The optional private REQ-P1-008 hooks are supplied by the progress
    controller: ``cancel_probe`` is polled before every table's schema read
    (a scan safe point between discovered tables) and raises on cancellation;
    ``progress_probe`` is called with the table's normalized relative path
    after each table has been read.  With both hooks ``None`` the behavior is
    exactly the pre-existing deterministic discovery.
    """
    if not source_root.is_dir():
        from dbf_anonymizer.errors import PathError, ErrorCode, ErrorContext

        raise PathError(
            ErrorCode.PATH_NOT_FOUND,
            context=ErrorContext(operation="build_plan", detail_code="source_root_not_a_directory"),
        )

    dbf_files: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(source_root):
        for fname in filenames:
            if Path(fname).suffix.lower() in _DBF_EXTENSIONS:
                dbf_files.append(Path(dirpath) / fname)

    dbf_files.sort()

    tables: list[DiscoveredTable] = []
    for dbf_path in dbf_files:
        rel = _relative_posix(dbf_path, source_root)

        if cancel_probe is not None:
            cancel_probe()

        from dbf_anonymizer.errors import DBFBridgeError, ErrorContext

        try:
            schema = dbfbridge.read_schema(dbf_path)  # type: ignore[attr-defined]
        except (CancellationError, CallbackError):
            raise
        except Exception as exc:
            raise DBFBridgeError.from_exception(
                exc,
                context=ErrorContext(
                    operation="build_plan",
                    table_path=rel,
                    detail_code="read_schema_failed",
                ),
            ) from None

        memo_rel = _safe_relative(schema.memo_companion_path, source_root) if schema.memo_companion_present else None
        cdx_rel = _safe_relative(schema.companion_cdx_path, source_root) if schema.companion_cdx_present else None

        tables.append(
            DiscoveredTable(
                relative_path=rel,
                memo_relative_path=memo_rel,
                record_count=schema.record_count,
                field_count=len(schema.fields),
                structural_cdx=schema.has_structural_cdx,
                dbc_bound=schema.dbc_bound,
                companion_cdx_relative_path=cdx_rel,
            )
        )

        if progress_probe is not None:
            progress_probe(rel)

    tables.sort(key=lambda t: t.relative_path)
    return tuple(tables)


def enumerate_in_scope_paths(source_root: Path, *, strict: bool = False) -> dict[str, Path]:
    """Map relative posix path -> absolute path for in-scope source artifacts.

    Includes all DBF, FPT, CDX and IDX files found in the tree.  With
    ``strict=True`` (the preflight/verification setting) a traversal error
    (unreadable directory, disappeared entry) is raised as ``OSError`` so an
    incomplete enumeration can never silently degrade source completeness, and
    the root itself is checked with the raw stat probe: an absent, unreadable
    or non-directory source root raises instead of producing an innocent empty
    enumeration.  With ``strict=False`` the historical P1-005 planning
    behaviour is kept. The fingerprint payload format is unchanged.
    """
    def _on_error(error: OSError) -> None:
        if strict:
            raise error

    result: dict[str, Path] = {}
    if strict:
        # Raw stat semantics: only FileNotFoundError means "missing" here.
        # Path.is_dir() would swallow PermissionError on Python 3.12+ and
        # turn an unreadable source root into an innocent empty enumeration.
        # The raised error carries no path payload (privacy-safe).
        kind = probe_path(source_root)
        if kind == _PATH_MISSING:
            raise FileNotFoundError(2, "source root is missing")
        if kind != _PATH_DIRECTORY:
            raise NotADirectoryError(20, "source root is not a directory")
    elif not source_root.is_dir():
        return result
    for dirpath, _dirnames, filenames in os.walk(source_root, onerror=_on_error):
        for name in filenames:
            suffix = Path(name).suffix.lower()
            if suffix in IN_SCOPE_EXTENSIONS:
                full = Path(dirpath) / name
                result[full.relative_to(source_root).as_posix()] = full
    return result


def collect_fingerprint_entries(
    source_root: Path,
    *,
    strict: bool = False,
    cancel_probe: Callable[[], None] | None = None,
    progress_probe: Callable[[int, int, str], None] | None = None,
) -> tuple[ArtifactFingerprintEntry, ...]:
    """Compute fingerprint entries for all in-scope artifacts under *source_root*.

    Includes all DBF, FPT, CDX, IDX files found in the tree.
    IDX files are included in the global fingerprint but never associated
    with a specific DBF.  The fingerprint payload format is unchanged.
    ``strict=True`` raises ``OSError`` on traversal errors instead of silently
    skipping them (used by preflight so incomplete enumeration cannot masquerade
    as a complete fingerprint).

    The optional private REQ-P1-008 hooks are supplied by the progress
    controller: the in-scope artifacts are enumerated first, then hashed in
    deterministic sorted-relative-path order; ``cancel_probe`` is polled once
    before every artifact and inside the chunked hashing loop (bounded
    cancellation latency); ``progress_probe(done, total, relative_path)`` is
    called after each artifact digest, with ``total`` the defensible artifact
    count.  With both hooks ``None`` the results are exactly the pre-existing
    deterministic fingerprint entries.
    """
    def _on_error(error: OSError) -> None:
        if strict:
            raise error

    paths = enumerate_in_scope_paths(source_root, strict=strict)
    ordered = sorted(paths)
    total = len(ordered)

    entries: list[ArtifactFingerprintEntry] = []
    for done, rel in enumerate(ordered, start=1):
        p = paths[rel]
        if cancel_probe is not None:
            cancel_probe()
        size = p.stat().st_size
        if cancel_probe is None:
            digest = _file_sha256(p)
        else:
            digest = _file_sha256(p, cancel_probe=cancel_probe)
        artifact_type = Path(rel).suffix.lstrip(".").upper()
        entries.append(
            ArtifactFingerprintEntry(
                relative_path=rel,
                artifact_type=artifact_type,
                size_bytes=size,
                sha256=digest,
            )
        )
        if progress_probe is not None:
            progress_probe(done, total, rel)

    entries.sort(key=lambda e: e.relative_path)
    return tuple(entries)


def compute_source_fingerprint(
    entries: tuple[ArtifactFingerprintEntry, ...],
) -> str:
    """Compute a deterministic SHA-256 source fingerprint.

    Uses unambiguous canonical JSON encoding to avoid delimiter ambiguity
    in hostile filenames. No absolute paths, timestamps or user info.
    """
    import json

    canonical = json.dumps(
        [
            {"p": e.relative_path, "t": e.artifact_type, "s": e.size_bytes, "h": e.sha256}
            for e in entries
        ],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
