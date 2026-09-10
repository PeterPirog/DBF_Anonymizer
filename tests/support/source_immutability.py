"""Test-support source-immutability evidence helpers (REQ-P0-004).

TEST-ONLY infrastructure: nothing here belongs to the installable package,
the public API or any future P1 preflight/cancellation system.  It exists to
prove the P0 source-immutability invariant over representative operations on
synthetic P0 corpus copies.

Evidence contract:

- every in-scope source artifact (``*.dbf``/``*.fpt``/``*.cdx``/``*.idx``,
  matched case-insensitively) is discovered recursively and fingerprinted
  with its normalized relative POSIX path, byte size and complete-byte
  SHA-256 (raw hashing is not DBF parsing);
- a fingerprint is a frozen, deterministic tuple; equality proves both the
  same artifact path set AND the same SHA-256 for every artifact — any
  deleted, added, renamed or byte-changed in-scope artifact breaks equality;
- a write-target guard rejects any output root that equals the source root,
  lies inside it or reaches back into it through ``..`` segments, using
  resolved filesystem paths (case-normalized only in the platform's
  ``os.path.normcase`` sense);
- a representative operation harness exercises real public dbfbridge
  read/write work with deterministic injected-failure and test-only
  cancellation points.  It is NOT pseudonymization and NOT the future
  REQ-P1-008 cancellation contract.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from dbfbridge import DirectRecord, iter_records, read_schema, write_table

IN_SCOPE_SUFFIXES = frozenset({".dbf", ".fpt", ".cdx", ".idx"})

#: Committed synthetic P0 corpus families used as the evidence source
#: dataset.  They are COPIED into disposable temporary source trees; the
#: committed corpus itself is never operated on.
CORPUS_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "p0"
CORPUS_FAMILY: tuple[str, ...] = (
    "plain/plain_customers.dbf",
    "memos/memo_payloads.dbf",
    "memos/memo_payloads.fpt",
    "vfp/structural/indexed_table.dbf",
    "vfp/structural/indexed_table.cdx",
    "vfp/idx/standalone_idx_table.dbf",
    "vfp/idx/code_idx.idx",
)


class WriteTargetInsideSourceError(Exception):
    """A write target resolves inside the source tree (rejected before write)."""


class OperationFailedError(Exception):
    """TEST-ONLY injected failure for the P0-004 failure scenario."""


class OperationCancelled(Exception):
    """TEST-ONLY cancellation signal for the P0-004 cancellation scenario.

    This is P0 source-immutability cancellation evidence only; it is NOT
    acceptance evidence for the future REQ-P1-008 public cancellation
    semantics.
    """


@dataclass(frozen=True)
class SourceArtifact:
    """One in-scope source artifact's deterministic fingerprint record."""

    relative_path: str
    artifact_class: str
    size_bytes: int
    sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def fingerprint_source_tree(source_root: Path) -> tuple[SourceArtifact, ...]:
    """Recursively fingerprint every in-scope source artifact under *root*."""
    artifacts: list[SourceArtifact] = []
    for path in sorted(source_root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in IN_SCOPE_SUFFIXES:
            continue
        artifacts.append(
            SourceArtifact(
                relative_path=_relative_posix(path, source_root),
                artifact_class=suffix[1:],
                size_bytes=path.stat().st_size,
                sha256=_sha256(path),
            )
        )
    return tuple(artifacts)


def canonical_fingerprint_digest(fingerprint: tuple[SourceArtifact, ...]) -> str:
    """One deterministic digest over the whole source fingerprint.

    The digest is extra evidence; equality proofs always use the deep
    artifact comparison in :func:`assert_fingerprints_equal`.
    """
    canonical = "\n".join(
        f"{a.relative_path}|{a.artifact_class}|{a.size_bytes}|{a.sha256}"
        for a in fingerprint
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assert_fingerprints_equal(
    before: tuple[SourceArtifact, ...], after: tuple[SourceArtifact, ...]
) -> None:
    """Fail unless the two fingerprints are exactly identical.

    Any deleted, added, renamed or byte-changed in-scope artifact breaks the
    equality with a precise difference message.
    """
    before_map = {artifact.relative_path: artifact for artifact in before}
    after_map = {artifact.relative_path: artifact for artifact in after}
    removed = sorted(set(before_map) - set(after_map))
    added = sorted(set(after_map) - set(before_map))
    changed = sorted(
        path
        for path in set(before_map) & set(after_map)
        if before_map[path].sha256 != after_map[path].sha256
        or before_map[path].size_bytes != after_map[path].size_bytes
    )
    problems = []
    if removed:
        problems.append(f"removed in-scope artifacts: {removed}")
    if added:
        problems.append(f"added in-scope artifacts: {added}")
    if changed:
        problems.append(f"byte-changed in-scope artifacts: {changed}")
    if problems:
        raise AssertionError("source fingerprint changed: " + "; ".join(problems))


def full_tree_inventory(root: Path) -> tuple[tuple[str, str], ...]:
    """SHA-256 inventory of EVERY file under *root* (any suffix), sorted.

    Used to prove that the operation created no new files and removed none
    anywhere inside the source tree — stricter than the in-scope-artifact
    fingerprint, which remains the mandatory byte-hash comparison.
    """
    return tuple(
        (_relative_posix(path, root), _sha256(path))
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def resolve_outside_source(source_root: Path, write_target: Path) -> Path:
    """Resolve *write_target* and reject it if it is inside the source tree.

    Rejects (before any write occurs):
    - output root equal to the source root;
    - output root inside the source root;
    - normalized ``..`` forms that resolve back inside the source root.

    Path identity is compared through ``os.path.normcase`` of the resolved
    paths, which is the platform's own case normalization (identity on
    POSIX, lowercase + backslash normalization on Windows).
    """
    resolved_source = os.path.normcase(str(source_root.resolve()))
    resolved_target = os.path.normcase(str(write_target.resolve()))
    if resolved_target == resolved_source or resolved_target.startswith(
        resolved_source + os.sep
    ):
        raise WriteTargetInsideSourceError(
            f"write target {write_target} resolves inside the source tree "
            f"({resolved_source})"
        )
    return Path(write_target).resolve()


def build_synthetic_source_tree(dest_root: Path) -> None:
    """Assemble the disposable synthetic source tree from committed P0 fixtures.

    The committed corpus is read-only material: files are copied, never
    operated on in place.  The tree nests the four required artifact
    families in different directories (recursive discovery) plus one
    deliberately uppercase-suffixed copy (case-insensitive matching).
    """
    for relative in CORPUS_FAMILY:
        target = dest_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((CORPUS_ROOT / relative).read_bytes())
    uppercase_probe = dest_root / "extra" / "UPPERCASE.DBF"
    uppercase_probe.parent.mkdir(parents=True, exist_ok=True)
    uppercase_probe.write_bytes((CORPUS_ROOT / "plain/plain_customers.dbf").read_bytes())


# ---------------------------------------------------------------------------
# representative operation harness (public dbfbridge APIs only)
# ---------------------------------------------------------------------------


def representative_operation(
    source_root: Path,
    output_root: Path,
    *,
    fail_after_tables: int | None = None,
    cancel_after_tables: int | None = None,
) -> list[str]:
    """Perform representative read/write work and return created write targets.

    For every discovered source DBF table (deterministic sorted order) the
    harness reads the schema and all logical records through the public
    dbfbridge Direct Read API and freshly writes one output DBF (plus the
    FPT companion for memo tables) through the public ``write_table`` into
    *output_root*, mirroring the source-relative directory layout.

    The output is a fresh public-API copy of the source table.  It is NOT
    pseudonymization and NOT the transformation engine: it is merely the
    representative write workload required for P0-004 source-immutability
    evidence.

    ``fail_after_tables``/``cancel_after_tables`` inject the deterministic
    failure/cancellation AFTER that many tables have been fully processed
    (i.e. after meaningful read/write work has happened).
    """
    output_root = resolve_outside_source(source_root, output_root)
    created: list[str] = []
    tables = [
        artifact
        for artifact in fingerprint_source_tree(source_root)
        if artifact.artifact_class == "dbf"
    ]
    for index, table in enumerate(tables):
        source_table = source_root / table.relative_path
        schema = read_schema(source_table)
        records = list(iter_records(source_table, memo="inline", include_deleted=True))
        destination = output_root / table.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_table(
            destination,
            schema=schema,
            records=[
                DirectRecord(physical_index=out_index, deleted=record.deleted, values=dict(record.values))
                for out_index, record in enumerate(records)
            ],
            overwrite=True,
        )
        created.append(_relative_posix(destination, output_root))
        fpt = destination.with_suffix(".fpt")
        if fpt.exists():
            created.append(_relative_posix(fpt, output_root))
        if fail_after_tables is not None and index == fail_after_tables:
            raise OperationFailedError(
                f"test-injected failure after {fail_after_tables + 1} processed table(s)"
            )
        if cancel_after_tables is not None and index == cancel_after_tables:
            raise OperationCancelled(
                f"test-injected cancellation after {cancel_after_tables + 1} processed table(s)"
            )
    return created