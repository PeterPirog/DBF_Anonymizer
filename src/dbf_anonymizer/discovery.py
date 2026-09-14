"""Source dataset discovery for REQ-P1-005 read-only planning.

Discovers DBF tables and their companion artifacts under a source root.
Uses only public ``dbfbridge`` read APIs for schema and companion facts.
IDX files are inventoried globally for fingerprinting but never associated
with a specific DBF by inference.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import dbfbridge

_DBF_EXTENSIONS = frozenset({".dbf"})
_FPT_EXTENSIONS = frozenset({".fpt"})
_CDX_EXTENSIONS = frozenset({".cdx"})
_IDX_EXTENSIONS = frozenset({".idx"})

IN_SCOPE_EXTENSIONS = _DBF_EXTENSIONS | _FPT_EXTENSIONS | _CDX_EXTENSIONS | _IDX_EXTENSIONS


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


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


def discover_tables(source_root: Path) -> tuple[DiscoveredTable, ...]:
    """Discover all DBF tables under *source_root* deterministically.

    Returns a tuple sorted by normalized relative path.
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

        from dbf_anonymizer.errors import DBFBridgeError, ErrorContext

        try:
            schema = dbfbridge.read_schema(dbf_path)  # type: ignore[attr-defined]
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

    tables.sort(key=lambda t: t.relative_path)
    return tuple(tables)


def enumerate_in_scope_paths(source_root: Path, *, strict: bool = False) -> dict[str, Path]:
    """Map relative posix path -> absolute path for in-scope source artifacts.

    Includes all DBF, FPT, CDX and IDX files found in the tree.  With
    ``strict=True`` (the preflight/verification setting) a traversal error
    (unreadable directory, disappeared entry) is raised as ``OSError`` so an
    incomplete enumeration can never silently degrade source completeness;
    with ``strict=False`` the historical P1-005 planning behaviour is kept.
    """
    def _on_error(error: OSError) -> None:
        if strict:
            raise error

    result: dict[str, Path] = {}
    if not source_root.is_dir():
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
) -> tuple[ArtifactFingerprintEntry, ...]:
    """Compute fingerprint entries for all in-scope artifacts under *source_root*.

    Includes all DBF, FPT, CDX, IDX files found in the tree.
    IDX files are included in the global fingerprint but never associated
    with a specific DBF.  The fingerprint payload format is unchanged.
    ``strict=True`` raises ``OSError`` on traversal errors instead of silently
    skipping them (used by preflight so incomplete enumeration cannot masquerade
    as a complete fingerprint).
    """
    def _on_error(error: OSError) -> None:
        if strict:
            raise error

    entries: list[ArtifactFingerprintEntry] = []

    for dirpath, _dirnames, filenames in os.walk(source_root, onerror=_on_error):
        for fname in sorted(filenames):
            p = Path(dirpath) / fname
            suffix = Path(fname).suffix.lower()
            if suffix not in IN_SCOPE_EXTENSIONS:
                continue
            rel = _relative_posix(p, source_root)
            size = p.stat().st_size
            digest = _file_sha256(p)
            artifact_type = suffix.lstrip(".").upper()
            entries.append(
                ArtifactFingerprintEntry(
                    relative_path=rel,
                    artifact_type=artifact_type,
                    size_bytes=size,
                    sha256=digest,
                )
            )

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
