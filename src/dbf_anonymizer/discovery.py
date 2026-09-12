"""Source dataset discovery for REQ-P1-005 read-only planning.

Discovers DBF tables, FPT companions, structural CDX and standalone IDX
artifacts under a source root. Uses only public ``dbfbridge`` read APIs.
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
    standalone_idx_relative_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArtifactFingerprintEntry:
    """One artifact included in the source fingerprint."""

    relative_path: str
    artifact_type: str
    size_bytes: int
    sha256: str


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


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

        schema = dbfbridge.read_schema(dbf_path)  # type: ignore[attr-defined]

        memo_rel: str | None = None
        if schema.has_memo:
            fpt_path = dbf_path.with_suffix(".fpt")
            if fpt_path.is_file():
                memo_rel = _relative_posix(fpt_path, source_root)

        cdx_rel: str | None = None
        cdx_path = dbf_path.with_suffix(".cdx")
        if cdx_path.is_file():
            cdx_rel = _relative_posix(cdx_path, source_root)

        idx_files: list[str] = []
        stem = dbf_path.stem
        for dirpath2, _dirs, fnames in os.walk(source_root):
            for fn in sorted(fnames):
                if Path(fn).suffix.lower() in _IDX_EXTENSIONS and Path(fn).stem == stem:
                    idx_files.append(_relative_posix(Path(dirpath2) / fn, source_root))

        tables.append(
            DiscoveredTable(
                relative_path=rel,
                memo_relative_path=memo_rel,
                record_count=schema.record_count,
                field_count=len(schema.fields),
                structural_cdx=schema.has_structural_cdx,
                dbc_bound=schema.dbc_bound,
                companion_cdx_relative_path=cdx_rel,
                standalone_idx_relative_paths=tuple(sorted(idx_files)),
            )
        )

    tables.sort(key=lambda t: t.relative_path)
    return tuple(tables)


def collect_fingerprint_entries(
    source_root: Path, tables: tuple[DiscoveredTable, ...]
) -> tuple[ArtifactFingerprintEntry, ...]:
    """Compute fingerprint entries for all in-scope artifacts under *source_root*.

    Includes all DBF, FPT, CDX, IDX files found in the tree.
    """
    entries: list[ArtifactFingerprintEntry] = []

    for dirpath, _dirnames, filenames in os.walk(source_root):
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

    The canonical sequence is the sorted tuple of (path, type, size, digest)
    tuples, joined and hashed. No absolute paths, timestamps or user info.
    """
    canonical = "\n".join(
        f"{e.relative_path}|{e.artifact_type}|{e.size_bytes}|{e.sha256}"
        for e in entries
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
