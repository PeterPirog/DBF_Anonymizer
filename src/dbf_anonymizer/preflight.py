"""Deterministic, source-read-only, side-effect-free preflight (REQ-P1-006).

``preflight(plan)`` evaluates the already-planned :class:`~dbf_anonymizer.Plan`
against the preconditions that must hold *before* any transformation starts,
and returns an immutable :class:`~dbf_anonymizer.PreflightResult`.

Guarantees enforced by this module:

* source-read-only and side-effect-free: it creates no output, vault, SQLite
  file/sidecar, staging, lock, manifest, log, CDX/IDX/DBC or transformed data,
  and does not modify any source DBF/FPT/CDX/IDX/DBC artifact;
* it performs no network, subprocess, COM or VFP invocation;
* ordinary preflight findings are AGGREGATED into a single ``PreflightResult``
  with ``ready=False`` rather than throwing after the first finding;
* the public result carries only bounded machine codes and capability facts
  (no source values, memo payloads, absolute paths or dependency messages);
* filesystem inspection failures (permission errors, vanished entries) never
  leak raw ``OSError`` text or private absolute paths: they degrade to the
  deterministic ``PATH_INSPECTION_UNAVAILABLE`` / ``SOURCE_UNAVAILABLE`` /
  ``STORAGE_ESTIMATE_UNAVAILABLE`` findings and the caller fails closed.

Exceptions remain reserved for invalid object contracts, unexpected dependency
failures and impossible internal invariants (see :mod:`dbf_anonymizer.errors`).

Determinism
-----------
``check_codes`` / ``warning_codes`` / ``error_codes`` are each emitted in
ascending code-string order. No code is duplicated within a category. The
result depends only on the ``Plan``, the current source state and the
deterministic capability/storage inputs, so repeated calls over the same state
produce exactly equal ``to_dict()`` output.

Pseudonym capacity model (GLOBAL_TEXT C/V domain)
-------------------------------------------------
For every exact non-empty decoded original across the WHOLE dataset there is
ONE global strictest width: ``strictest_width(original)`` is the minimum
logical byte-width constraint encountered across every occurrence of that
original in any participating table/field. The same original is represented
exactly once in the global domain, no matter in how many fields, widths or
tables it occurs. Feasibility is Hall's condition over the nested token pools:
for each field width ``w`` (ascending), the number of distinct originals whose
strictest width is ``<= w`` must not exceed the token space
``base^1 + ... + base^w``.

The proof runs in two phases:

* PHASE A — cheap mathematical upper bounds: with ``schema.record_count`` and
  the participating C/V field lengths, the cumulative occurrence upper bound
  ``sum(record_count * participating fields with length <= w)`` bounds the
  distinct-original count from above. When that bound already fits the token
  space, the width constraint is proven WITHOUT storing any source value.
* PHASE B — exact tracking only for tight widths: widths whose occurrence
  bound exceeds the token space keep exact originals (exact-value equality,
  never digests) in a bounded in-memory tracker, each mapped to its strictest
  width. The tracker has a hard, enforced integer ceiling
  (``_MAX_EXACT_VALUES``): membership is tested BEFORE the ceiling so repeated
  duplicates never falsely exceed it, and a genuine new value beyond the
  ceiling fails closed with ``PSEUDONYM_CAPACITY_UNPROVEN`` instead of
  exhausting RAM or pretending mathematical insufficiency. An exact
  contradiction found within the ceiling fails closed with
  ``PSEUDONYM_CAPACITY_INSUFFICIENT``.

The public result contains no original values; the bounded scan retains at
most ``_MAX_EXACT_VALUES`` source strings in memory and never serializes them.
No SQLite database and no original-bearing temporary file is created.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable

import dbfbridge

from dbf_anonymizer import _capability
from dbf_anonymizer import discovery
from dbf_anonymizer.errors import DBFBridgeError, ErrorContext, ErrorCode
from dbf_anonymizer.models import (
    Capabilities,
    PreflightResult,
    Plan,
    TablePlan,
    TransferProfile,
    VaultStrategy,
)

__all__ = ["preflight", "PREFLIGHT_CODE_VERSION", "PreflightCode"]

#: Versioned identity of the preflight code vocabulary.
PREFLIGHT_CODE_VERSION = "1.1"


# ---------------------------------------------------------------------------
# Stable, deterministic, privacy-safe preflight code vocabulary
# ---------------------------------------------------------------------------
# Each token is a bounded machine code. They are unique within a category in a
# result and are never derived from source values, memo payloads, absolute
# paths or dependency messages.
class PreflightCode:
    """Stable preflight finding codes (read-only string constants)."""

    # --- rejection (error_codes, ready=False) ---
    PATH_OVERLAP = "PATH_OVERLAP"
    PATH_INSPECTION_UNAVAILABLE = "PATH_INSPECTION_UNAVAILABLE"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_FINGERPRINT_MISMATCH = "SOURCE_FINGERPRINT_MISMATCH"
    DESTINATION_CONFLICT = "DESTINATION_CONFLICT"
    MISSING_MEMO_COMPANION = "MISSING_MEMO_COMPANION"
    MISSING_STRUCTURAL_INDEX = "MISSING_STRUCTURAL_INDEX"
    UNSUPPORTED_FIELD = "UNSUPPORTED_FIELD"
    UNSAFE_FIELD = "UNSAFE_FIELD"
    POLICY_INCONSISTENT = "POLICY_INCONSISTENT"
    OUTPUT_PROFILE_UNSUPPORTED = "OUTPUT_PROFILE_UNSUPPORTED"
    CAPABILITY_MISSING = "CAPABILITY_MISSING"
    STORAGE_SPACE_INSUFFICIENT = "STORAGE_SPACE_INSUFFICIENT"
    STORAGE_ESTIMATE_UNAVAILABLE = "STORAGE_ESTIMATE_UNAVAILABLE"
    RELATIONSHIP_DOMAIN_UNVERIFIED = "RELATIONSHIP_DOMAIN_UNVERIFIED"
    PSEUDONYM_CAPACITY_INSUFFICIENT = "PSEUDONYM_CAPACITY_INSUFFICIENT"
    PSEUDONYM_CAPACITY_UNPROVEN = "PSEUDONYM_CAPACITY_UNPROVEN"

    # --- advisory (warning_codes) ---
    STRUCTURAL_CDX_DATA_ONLY = "STRUCTURAL_CDX_DATA_ONLY"
    STANDALONE_IDX_DATA_ONLY = "STANDALONE_IDX_DATA_ONLY"
    DBC_BOUND_REDUCED = "DBC_BOUND_REDUCED"

    # --- informational (check_codes) ---
    DATA_ONLY_STANDALONE = "DATA_ONLY_STANDALONE"
    PREFLIGHT_EVALUATED = "PREFLIGHT_EVALUATED"


_ERROR_CODES = frozenset(
    {
        PreflightCode.PATH_OVERLAP,
        PreflightCode.PATH_INSPECTION_UNAVAILABLE,
        PreflightCode.SOURCE_UNAVAILABLE,
        PreflightCode.SOURCE_FINGERPRINT_MISMATCH,
        PreflightCode.DESTINATION_CONFLICT,
        PreflightCode.MISSING_MEMO_COMPANION,
        PreflightCode.MISSING_STRUCTURAL_INDEX,
        PreflightCode.UNSUPPORTED_FIELD,
        PreflightCode.UNSAFE_FIELD,
        PreflightCode.POLICY_INCONSISTENT,
        PreflightCode.OUTPUT_PROFILE_UNSUPPORTED,
        PreflightCode.CAPABILITY_MISSING,
        PreflightCode.STORAGE_SPACE_INSUFFICIENT,
        PreflightCode.STORAGE_ESTIMATE_UNAVAILABLE,
        PreflightCode.RELATIONSHIP_DOMAIN_UNVERIFIED,
        PreflightCode.PSEUDONYM_CAPACITY_INSUFFICIENT,
        PreflightCode.PSEUDONYM_CAPACITY_UNPROVEN,
    }
)
_WARNING_CODES = frozenset(
    {
        PreflightCode.STRUCTURAL_CDX_DATA_ONLY,
        PreflightCode.STANDALONE_IDX_DATA_ONLY,
        PreflightCode.DBC_BOUND_REDUCED,
    }
)
_CHECK_CODES = frozenset(
    {
        PreflightCode.DATA_ONLY_STANDALONE,
        PreflightCode.PREFLIGHT_EVALUATED,
    }
)


# ---------------------------------------------------------------------------
# Private test seams (module-level callables; not part of the public API)
# ---------------------------------------------------------------------------
def _default_resolve_path(path: Path) -> Path:
    """Resolve symlinks/aliases using standard-library path resolution only."""
    return path.resolve()


def _default_disk_usage(path: Path) -> tuple[int, int, int]:
    """Return (total, used, free) bytes for the nearest existing ancestor."""
    usage = shutil.disk_usage(_nearest_existing_ancestor(path))
    return int(usage.total), int(usage.used), int(usage.free)


def _default_stat_dev(path: Path) -> int:
    """Return the st_dev of *path* (used to compare filesystems)."""
    return os.stat(path).st_dev


def _default_path_exists(path: Path) -> bool:
    return path.exists()


def _default_path_is_file(path: Path) -> bool:
    return path.is_file()


def _default_path_is_dir(path: Path) -> bool:
    return path.is_dir()


def _default_iterdir(path: Path) -> list[Path]:
    return list(path.iterdir())


_resolve_path: Callable[[Path], Path] = _default_resolve_path
_disk_usage: Callable[[Path], tuple[int, int, int]] = _default_disk_usage
_stat_dev: Callable[[Path], int] = _default_stat_dev
_path_exists: Callable[[Path], bool] = _default_path_exists
_path_is_file: Callable[[Path], bool] = _default_path_is_file
_path_is_dir: Callable[[Path], bool] = _default_path_is_dir
_iterdir: Callable[[Path], list[Path]] = _default_iterdir

# ---------------------------------------------------------------------------
# Conservative storage-risk constants (documented risk bounds, NOT benchmark
# figures and NOT exact future-size predictions)
# ---------------------------------------------------------------------------
#: Peak exposure of the fresh output footprint: the published output plus one
#: full staged/temporary copy of the same data that may coexist before commit.
#: The fresh DBF/FPT output never exceeds the in-scope source footprint, so the
#: source footprint bounds the published output; doubling it covers the
#: staged/temporary copy that coexists until the write commits.
_STAGING_FACTOR = 2

#: Conservative dbfbridge writer/spool reserve (bytes) for temporary/spill
#: state created while a table is written. Documented constant; not a
#: benchmark figure.
_WRITER_SPOOL_RESERVE_BYTES = 16 * 1024 * 1024

#: Conservative source-size multiplier for the recovery-vault risk reserve.
#: Rationale (risk bound, not an exact SQLite size prediction): when reversible
#: transforms are planned, the vault stores the global mapping domain (every
#: distinct original plus its pseudonym and per-occurrence references) and the
#: masked memo volumes; together these can approach the full in-scope source
#: text volume, and SQLite b-tree/overflow-page layout can roughly double the
#: raw stored content. A multiplier of 2 therefore over-covers the realistic
#: recovery material for any dataset instead of under-estimating it.
_VAULT_SOURCE_FACTOR = 2

#: Conservative fixed vault overhead floor (bytes). Rationale: SQLite main
#: database header/schema/page bookkeeping plus transient journal/WAL/rollback
#: exposure that does not scale with content on small datasets. Documented
#: constant; not a benchmark figure.
_VAULT_FIXED_RESERVE_BYTES = 32 * 1024 * 1024

#: Hard, enforced integer ceiling on exact source originals retained by the
#: capacity scan (PHASE B). Reaching the ceiling fails closed with
#: ``PSEUDONYM_CAPACITY_UNPROVEN``; it is never treated as capacity data.
_MAX_EXACT_VALUES = 65536

#: Bounded-state instrumentation of the last capacity scan. Counts and codes
#: only — never source values. Tests may inspect it to prove the memory
#: ceiling is actually enforced; it is not part of the public result.
_LAST_CAPACITY_SCAN_STATS: dict[str, int | str] | None = None

_CAPACITY_OK = "OK"
_CAPACITY_INSUFFICIENT = "INSUFFICIENT"
_CAPACITY_UNPROVEN = "UNPROVEN"


def _vault_reserve_bytes(source_footprint: int) -> int:
    """Conservative recovery-vault storage RISK RESERVE for a dataset.

    Scales with the source footprint (see ``_VAULT_SOURCE_FACTOR`` and
    ``_VAULT_FIXED_RESERVE_BYTES`` for the documented bound). This is an
    explicitly conservative provisional bound, not an exact prediction of the
    future SQLite vault size.
    """
    return _VAULT_SOURCE_FACTOR * max(0, source_footprint) + _VAULT_FIXED_RESERVE_BYTES


def _nearest_existing_ancestor(path: Path) -> Path:
    """Return the nearest existing ancestor of *path* (for disk usage)."""
    candidate = path
    while True:
        if _path_exists(candidate):
            return candidate
        parent = candidate.parent
        if parent == candidate:  # reached filesystem root
            return candidate
        candidate = parent


# ---------------------------------------------------------------------------
# Findings accumulator
# ---------------------------------------------------------------------------
class _Findings:
    """Accumulates deterministic, de-duplicated preflight codes."""

    def __init__(self) -> None:
        self.checks: set[str] = set()
        self.warnings: set[str] = set()
        self.errors: set[str] = set()

    def check(self, code: str) -> None:
        self.checks.add(code)

    def warn(self, code: str) -> None:
        self.warnings.add(code)

    def error(self, code: str) -> None:
        self.errors.add(code)

    def result(self, plan: Plan, caps: Capabilities) -> PreflightResult:
        self.check(PreflightCode.PREFLIGHT_EVALUATED)
        ready = not self.errors
        return PreflightResult(
            ready=ready,
            plan_id=plan.plan_id,
            capabilities=caps,
            check_codes=tuple(sorted(self.checks)),
            warning_codes=tuple(sorted(self.warnings)),
            error_codes=tuple(sorted(self.errors)),
        )


# ---------------------------------------------------------------------------
# Source artifact enumeration (read-only, STRICT traversal)
# ---------------------------------------------------------------------------
def _enumerate_in_scope_strict(source_root: Path) -> dict[str, Path]:
    """Strict in-scope enumeration: traversal errors raise ``OSError``.

    Source verification in preflight must never treat an incomplete traversal
    as complete: an unreadable directory or disappeared entry fails closed
    (``SOURCE_UNAVAILABLE``) instead of being silently skipped.
    """
    return discovery.enumerate_in_scope_paths(source_root, strict=True)


def _source_footprint_bytes(source_files: dict[str, Path] | None) -> int | None:
    """In-scope source DBF/FPT byte footprint, or None if not defensible.

    Any stat failure makes the footprint unknown; the storage risk model then
    fails closed rather than under-estimate.
    """
    if source_files is None:
        return None
    total = 0
    for rel, full in sorted(source_files.items()):
        if rel.lower().endswith((".dbf", ".fpt")):
            try:
                total += full.stat().st_size
            except OSError:
                return None
    return total


def _recompute_source_fingerprint(source_root: Path) -> str | None:
    """Recompute the current source fingerprint using the P1-005/P0-004 logic.

    STRICT traversal: an incomplete enumeration (unreadable directory, racing
    deletion) raises ``OSError`` and the caller reports ``SOURCE_UNAVAILABLE``
    instead of treating a partial fingerprint as complete. The fingerprint
    payload format itself is unchanged.
    """
    try:
        entries = discovery.collect_fingerprint_entries(source_root, strict=True)
    except OSError:
        return None
    return discovery.compute_source_fingerprint(entries)


# ---------------------------------------------------------------------------
# Path overlap / alias safety
# ---------------------------------------------------------------------------
def _canonical(path: Path) -> str:
    resolved = _resolve_path(path)
    return os.path.normcase(resolved).replace(os.sep, "/")


def _within(inner: Path, outer: Path) -> bool:
    """True when *inner* is the same as or located inside *outer*."""
    ci = _canonical(inner)
    co = _canonical(outer)
    if ci == co:
        return True
    prefix = co if co.endswith("/") else co + "/"
    return ci.startswith(prefix)


def _paths_overlap(source: Path, output: Path, vault: Path) -> bool:
    pairs = (
        (source, output),
        (source, vault),
        (output, vault),
    )
    for a, b in pairs:
        if _within(a, b) or _within(b, a):
            return True
    return False


# ---------------------------------------------------------------------------
# Destination conflicts
# ---------------------------------------------------------------------------
def _ancestor_is_file(path: Path) -> bool:
    """True when ANY ancestor of *path* is a file.

    A directory cannot be nested under a file anywhere in the chain, so the
    whole hierarchy must be checked, not only the immediate parent.
    """
    ancestor = path.parent
    while True:
        if _path_is_file(ancestor):
            return True
        parent = ancestor.parent
        if parent == ancestor:  # reached filesystem root
            return False
        ancestor = parent


def _destination_conflict(output: Path, vault: Path) -> bool:
    """Detect path-type conflicts and unsafe existing destination state.

    Vault reuse is intentionally NOT implemented here (future REQ-P2-010); an
    existing vault file therefore fails closed as a conflict. The ancestor
    chains of BOTH targets are checked: a file anywhere in the hierarchy
    makes the destination uncreatable. Raises ``OSError`` when existing state
    cannot be inspected; the caller converts that into the deterministic
    ``PATH_INSPECTION_UNAVAILABLE`` finding (never a raw OS error/path).
    """
    # Output is a directory target.
    if _path_exists(output):
        if _path_is_file(output):
            return True  # type conflict: cannot publish a directory over a file
        if _path_is_dir(output) and any(_iterdir(output)):
            return True  # non-empty directory would overwrite existing state

    # Vault is a file target.
    if _path_exists(vault):
        if _path_is_dir(vault):
            return True  # type conflict: cannot place a file where a dir is
        return True  # existing vault file: reuse unimplemented -> fail closed

    # Any file in either ancestor chain blocks directory creation.
    return _ancestor_is_file(output) or _ancestor_is_file(vault)


# ---------------------------------------------------------------------------
# Table-level and policy-level findings
# ---------------------------------------------------------------------------
_SUPPORTED_POLICY_SCHEMA_VERSIONS = frozenset({"1"})
_SUPPORTED_TRANSFORMATION_CLASSES = frozenset(
    {"PSEUDONYMIZE_REVERSIBLE", "MASK_REVERSIBLE", "SHIFT_REVERSIBLE"}
)
_SUPPORTED_INDEX_STRATEGIES = frozenset({"DATA_ONLY", "VFP_INDEXED"})


def _check_fields(tables: tuple[TablePlan, ...], findings: _Findings) -> None:
    for table in tables:
        if table.unsupported_field_count > 0:
            findings.error(PreflightCode.UNSUPPORTED_FIELD)
        if table.unsafe_field_count > 0:
            findings.error(PreflightCode.UNSAFE_FIELD)
        # Known _NullFlags is writer-managed system state and must NOT reject.
        # ``system_field_count`` is therefore intentionally not a rejection.
        if table.memo_required and not table.memo_companion_present:
            findings.error(PreflightCode.MISSING_MEMO_COMPANION)
        if table.structural_cdx and not table.structural_cdx_companion_present:
            findings.error(PreflightCode.MISSING_STRUCTURAL_INDEX)


def _check_policy_consistency(plan: Plan, findings: _Findings) -> None:
    policy = plan.policy
    if policy.policy_schema_version not in _SUPPORTED_POLICY_SCHEMA_VERSIONS:
        findings.error(PreflightCode.POLICY_INCONSISTENT)
    for cls in policy.transformation_classes:
        if cls not in _SUPPORTED_TRANSFORMATION_CLASSES:
            findings.error(PreflightCode.POLICY_INCONSISTENT)
    if policy.recovery_enabled != (len(policy.transformation_classes) > 0):
        findings.error(PreflightCode.POLICY_INCONSISTENT)
    expected_vault = (
        VaultStrategy.SINGLE_DATASET_SQLITE
        if policy.recovery_enabled
        else VaultStrategy.NONE
    )
    if policy.vault_strategy is not expected_vault:
        findings.error(PreflightCode.POLICY_INCONSISTENT)
    if policy.relationship_count != plan.relationships.relation_count:
        findings.error(PreflightCode.POLICY_INCONSISTENT)
    for table in plan.tables:
        if table.index_strategy not in _SUPPORTED_INDEX_STRATEGIES:
            findings.error(PreflightCode.POLICY_INCONSISTENT)
        if (
            plan.output_profile is TransferProfile.DATA_ONLY
            and table.index_strategy == "VFP_INDEXED"
        ):
            findings.error(PreflightCode.POLICY_INCONSISTENT)


def _check_output_profile_and_capabilities(
    plan: Plan, caps: Capabilities, findings: _Findings
) -> None:
    # A valid preflight plan always needs direct read and direct write.
    if not caps.direct_read or not caps.direct_write:
        findings.error(PreflightCode.CAPABILITY_MISSING)

    if plan.output_profile is TransferProfile.DATA_ONLY:
        findings.check(PreflightCode.DATA_ONLY_STANDALONE)
        return

    # VFP_INDEXED requires an authoritative VFP index backend (future REQ-P6).
    # No such backend exists in this standalone implementation -> fail closed.
    findings.error(PreflightCode.OUTPUT_PROFILE_UNSUPPORTED)
    if not caps.vfp_index_backend:
        findings.error(PreflightCode.CAPABILITY_MISSING)


def _check_relationships(plan: Plan, findings: _Findings) -> None:
    # REQ-P3-001 member/role semantics are not implemented in this iteration.
    # relation_count == 0: ordinary P1 preflight may continue.
    # relation_count > 0: member-domain compatibility cannot be proven from the
    # summary metadata, so we fail closed (no DECLARED_RELATIONS_VERIFIED claim).
    if plan.relationships.relation_count > 0:
        findings.error(PreflightCode.RELATIONSHIP_DOMAIN_UNVERIFIED)


def _check_index_conditions(plan: Plan, findings: _Findings) -> None:
    if plan.output_profile is not TransferProfile.DATA_ONLY:
        return
    for table in plan.tables:
        if table.structural_cdx and table.structural_cdx_companion_present:
            # Source structural index state does not constitute valid output
            # index assurance for DATA_ONLY; truthfully warn, do not claim it.
            findings.warn(PreflightCode.STRUCTURAL_CDX_DATA_ONLY)
        if table.dbc_bound:
            findings.warn(PreflightCode.DBC_BOUND_REDUCED)


def _check_standalone_idx(
    source_files: dict[str, Path] | None, plan: Plan, findings: _Findings
) -> None:
    if plan.output_profile is not TransferProfile.DATA_ONLY:
        return
    if source_files and any(rel.lower().endswith(".idx") for rel in source_files):
        findings.warn(PreflightCode.STANDALONE_IDX_DATA_ONLY)


# ---------------------------------------------------------------------------
# Pseudonym capacity feasibility (GLOBAL_TEXT C/V domain) — read-only
# ---------------------------------------------------------------------------
_CANDIDATE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _candidate_alphabet(participating_encodings: frozenset[str]) -> str:
    """Intersect the conservative alphabet with single-byte codepoints.

    Keeps only characters that encode to exactly one byte under every
    participating source encoding. A single case form is used so that
    case-insensitive collision ambiguity is not introduced.
    """
    keep: list[str] = []
    for ch in _CANDIDATE_ALPHABET:
        accepted = True
        for encoding in participating_encodings:
            try:
                if len(ch.encode(encoding, "strict")) != 1:
                    accepted = False
                    break
            except (LookupError, UnicodeEncodeError, ValueError):
                accepted = False
                break
        if accepted:
            keep.append(ch)
    return "".join(keep)


def _token_space_at_least(max_width: int, base: int, needed: int) -> bool:
    """True when base^1 + ... + base^max_width >= needed.

    Streams the geometric terms and stops as soon as *needed* is reached, so
    wide field lengths never build astronomically large integers.
    """
    if max_width < 1 or base < 1:
        return needed <= 0
    total = 0
    term = 1
    for _ in range(1, max_width + 1):
        term *= base
        total += term
        if total >= needed:
            return True
    return False


def _capacity_sufficient(source_files: dict[str, Path], plan: Plan) -> str:
    """Conservative, deterministic GLOBAL_TEXT C/V capacity feasibility check.

    Reads only the C/V character fields that participate in the global text
    domain (deleted records included, because they are transformed later).
    NULL and empty values are preserved and therefore do not consume capacity.
    Varchar significant trailing spaces are part of the exact value, so
    ``"AB"`` and ``"AB "`` are distinct originals.

    The GLOBAL domain holds ONE representation per exact non-empty decoded
    original, mapped to its ONE strictest width: the minimum logical
    byte-width constraint encountered across every occurrence of that original
    in any participating table/field. The same original is never counted twice
    (cross-width or cross-table).

    Feasibility is Hall's condition over the nested token pools: for every
    field width ``w`` (ascending), the number of distinct originals whose
    strictest width is ``<= w`` must not exceed the token space
    ``base^1 + ... + base^w`` (exact-value equality, never digests;
    self-exclusion is only infeasible in the single-token edge case).

    PHASE A proves width constraints mathematically from
    ``schema.record_count`` and the participating field lengths without
    retaining any source value. PHASE B tracks exact originals only for tight
    widths, under the hard enforced ceiling ``_MAX_EXACT_VALUES``; exceeding
    it fails closed with ``_CAPACITY_UNPROVEN``.

    Returns ``_CAPACITY_OK``, ``_CAPACITY_INSUFFICIENT`` or
    ``_CAPACITY_UNPROVEN``. No source value is ever logged or serialized.
    """
    global _LAST_CAPACITY_SCAN_STATS
    _LAST_CAPACITY_SCAN_STATS = {
        "retained_distinct": 0,
        "exact_ceiling": _MAX_EXACT_VALUES,
        "phase_a_proven_widths": 0,
        "tight_widths": 0,
        "outcome": _CAPACITY_OK,
    }

    if "PSEUDONYMIZE_REVERSIBLE" not in plan.policy.transformation_classes:
        return _CAPACITY_OK

    dbf_rels = sorted(rel for rel in source_files if rel.lower().endswith(".dbf"))
    if not dbf_rels:
        return _CAPACITY_OK

    participating: set[str] = set()
    sensitive: list[tuple[str, Path, int, list[tuple[str, int]]]] = []
    for rel in dbf_rels:
        full = source_files[rel]
        try:
            schema = dbfbridge.read_schema(full)  # type: ignore[attr-defined]
        except Exception as exc:  # unexpected dependency failure
            raise DBFBridgeError.from_exception(
                exc,
                context=ErrorContext(
                    operation="preflight",
                    table_path=rel,
                    detail_code="capacity_read_schema_failed",
                ),
            ) from None
        fields: list[tuple[str, int]] = []
        for field in schema.fields:
            if (
                field.dbf_type.upper() in {"C", "V"}
                and field.supported
                and not field.is_binary
                and not field.nocptrans
            ):
                fields.append((field.name, field.length))
        if fields:
            if schema.encoding:
                participating.add(schema.encoding)
            sensitive.append((rel, full, schema.record_count, fields))

    if not sensitive:
        return _CAPACITY_OK

    alphabet = _candidate_alphabet(frozenset(participating))
    if not alphabet:
        _LAST_CAPACITY_SCAN_STATS["outcome"] = _CAPACITY_INSUFFICIENT
        return _CAPACITY_INSUFFICIENT  # no safe common alphabet -> fail closed

    base = len(alphabet)
    widths = sorted({length for _rel, _full, _rc, fields in sensitive for _n, length in fields})

    # PHASE A — cheap mathematical upper bounds per width constraint.
    tight: list[int] = []
    proven = 0
    for width in widths:
        occurrence_upper_bound = 0
        for _rel, _full, record_count, table_fields in sensitive:
            participating_narrow = sum(1 for _n, length in table_fields if length <= width)
            occurrence_upper_bound += record_count * participating_narrow
        if _token_space_at_least(width, base, occurrence_upper_bound):
            proven += 1
        else:
            tight.append(width)
    if base == 1 and widths and 1 not in tight:
        # With a one-token space the self-exclusion rule can genuinely fail,
        # so width 1 always requires the exact value proof.
        tight = [1] + tight
    _LAST_CAPACITY_SCAN_STATS["phase_a_proven_widths"] = proven
    _LAST_CAPACITY_SCAN_STATS["tight_widths"] = len(tight)

    if not tight:
        return _CAPACITY_OK  # every width constraint proven without exact values

    # PHASE B — exact tracking only for tight widths (strictest width per
    # original, one global entry per original, hard enforced ceiling).
    max_tight = tight[-1]
    tracker: dict[str, int] = {}
    counts: dict[int, int] = {width: 0 for width in tight}
    outcome = _CAPACITY_OK

    def _note_strictest(previous: int | None, strictest: int) -> bool:
        """Update per-width distinct counts for one original; True when a
        Hall condition is violated.

        ``previous=None`` marks a newly tracked original (it must count toward
        every tight width >= its strictest width); otherwise the original's
        strictest width decreased from *previous* to *strictest* and it gains
        the tight widths in ``[strictest, previous)``.
        """
        for width in tight:
            if width >= strictest and (previous is None or width < previous):
                counts[width] += 1
                if not _token_space_at_least(width, base, counts[width]):
                    return True
        return False

    for rel, full, _record_count, table_fields in sensitive:
        selected = [(name, length) for name, length in table_fields if length <= max_tight]
        if not selected:
            continue
        names = [name for name, _length in selected]
        try:
            for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
                full, include_deleted=True, fields=names, memo="lazy"
            ):
                for name, length in selected:
                    value = record.values.get(name)
                    if value is None or value == "":
                        continue
                    if not isinstance(value, str):
                        continue
                    strictest = tracker.get(value)
                    if strictest is None:
                        if len(tracker) >= _MAX_EXACT_VALUES:
                            # Hard memory ceiling: the exact proof cannot be
                            # completed within the bounded state -> fail
                            # closed without claiming mathematical
                            # insufficiency. Membership was already tested.
                            outcome = _CAPACITY_UNPROVEN
                            break
                        tracker[value] = length
                        if _note_strictest(None, length):
                            outcome = _CAPACITY_INSUFFICIENT
                            break
                    elif length < strictest:
                        tracker[value] = length
                        if _note_strictest(strictest, length):
                            outcome = _CAPACITY_INSUFFICIENT
                            break
                if outcome is not _CAPACITY_OK:
                    break
            if outcome is not _CAPACITY_OK:
                break
        except Exception as exc:  # unexpected dependency failure
            raise DBFBridgeError.from_exception(
                exc,
                context=ErrorContext(
                    operation="preflight",
                    table_path=rel,
                    detail_code="capacity_iter_records_failed",
                ),
            ) from None

    _LAST_CAPACITY_SCAN_STATS["retained_distinct"] = len(tracker)
    _LAST_CAPACITY_SCAN_STATS["outcome"] = outcome

    if outcome is not _CAPACITY_OK:
        return outcome

    # Single-token edge case: with a one-character alphabet the only token is
    # that character itself; a single original equal to it could not receive a
    # different pseudonym.
    if base == 1 and counts.get(1, 0) == 1:
        only_value = next(value for value, strictest in tracker.items() if strictest == 1)
        if only_value == alphabet:
            _LAST_CAPACITY_SCAN_STATS["outcome"] = _CAPACITY_INSUFFICIENT
            return _CAPACITY_INSUFFICIENT
    return _CAPACITY_OK


# ---------------------------------------------------------------------------
# Storage-space risk
# ---------------------------------------------------------------------------
def _storage_ok(
    source_files: dict[str, Path] | None,
    output: Path,
    vault: Path,
    recovery_enabled: bool,
) -> bool | None:
    """Return True (ok), False (insufficient) or None (estimate unavailable).

    The risk model accounts for the fresh output footprint, the peak staged
    exposure (output plus one full temporary copy), the dbfbridge
    writer/spool reserve and, when reversible transforms are planned, the
    source-scaled recovery-vault reserve (:func:`_vault_reserve_bytes`). If
    any input needed for a defensible estimate is unknown, None is returned
    and the caller fails closed.
    """
    footprint = _source_footprint_bytes(source_files)
    if footprint is None:
        return None
    required_output = footprint * _STAGING_FACTOR + _WRITER_SPOOL_RESERVE_BYTES
    required_vault = _vault_reserve_bytes(footprint) if recovery_enabled else 0

    try:
        out_total, _out_used, out_free = _disk_usage(output)
    except (OSError, ValueError):
        return None
    try:
        vault_total, _vault_used, vault_free = _disk_usage(vault)
    except (OSError, ValueError):
        return None

    try:
        out_dev = _stat_dev(_nearest_existing_ancestor(output))
        vault_dev = _stat_dev(_nearest_existing_ancestor(vault))
    except OSError:
        return None

    if out_dev == vault_dev:
        return out_free >= required_output + required_vault
    return out_free >= required_output and vault_free >= required_vault


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def preflight(plan: Plan) -> PreflightResult:
    """Evaluate a planned dataset for preconditions before transformation.

    ``preflight`` is source-read-only and side-effect-free. It aggregates all
    preconditions into a single immutable :class:`PreflightResult`. Ordinary
    findings never raise; only invalid object contracts, unexpected dependency
    failures and impossible invariants do.
    """
    if not isinstance(plan, Plan):
        raise TypeError("preflight requires a Plan")

    findings = _Findings()
    caps = _capability.capabilities_provider()

    context = plan.execution_context
    if context is None:
        # Impossible for a real build_plan result; fail closed rather than guess.
        findings.error(PreflightCode.SOURCE_FINGERPRINT_MISMATCH)
        return findings.result(plan, caps)

    source_root = Path(context.source_root)
    output_root = Path(context.output_root)
    vault_path = Path(context.vault_path)

    # 1. Source/output/vault overlap (resolved aliases where practical).
    #    Unresolvable/unsafe path inspection fails closed deterministically.
    try:
        overlap = _paths_overlap(source_root, output_root, vault_path)
    except OSError:
        overlap = False
        findings.error(PreflightCode.PATH_INSPECTION_UNAVAILABLE)
    if overlap:
        findings.error(PreflightCode.PATH_OVERLAP)

    # 2. Source availability + freshness, under STRICT traversal: a missing or
    #    unreadable source fails closed as SOURCE_UNAVAILABLE (an incomplete
    #    enumeration is never treated as complete); a changed source is a
    #    fingerprint mismatch. Downstream source-consuming checks (standalone
    #    IDX inventory, capacity scan) only run on verified source state.
    source_files: dict[str, Path] | None = None
    source_verified = False
    try:
        root_available = _path_is_dir(source_root)
    except OSError:
        root_available = False
    if not root_available:
        findings.error(PreflightCode.SOURCE_UNAVAILABLE)
    else:
        try:
            source_files = _enumerate_in_scope_strict(source_root)
        except OSError:
            source_files = None
            findings.error(PreflightCode.SOURCE_UNAVAILABLE)
        if source_files is not None:
            current_fp = _recompute_source_fingerprint(source_root)
            if current_fp is None:
                findings.error(PreflightCode.SOURCE_UNAVAILABLE)
            elif current_fp != plan.dataset.source_fingerprint:
                findings.error(PreflightCode.SOURCE_FINGERPRINT_MISMATCH)
            else:
                source_verified = True

    # 3. Destination conflicts (type conflicts / unsafe existing state).
    #    Uninspectable existing state fails closed deterministically.
    try:
        conflict = _destination_conflict(output_root, vault_path)
    except OSError:
        conflict = False
        findings.error(PreflightCode.PATH_INSPECTION_UNAVAILABLE)
    if conflict:
        findings.error(PreflightCode.DESTINATION_CONFLICT)

    # 4. Table-level field/companion findings (unsupported/unsafe/memo/cdx).
    _check_fields(plan.tables, findings)

    # 5. Policy/plan consistency (tamper-resistant).
    _check_policy_consistency(plan, findings)

    # 6. Output profile safety + runtime capabilities.
    _check_output_profile_and_capabilities(plan, caps, findings)

    # 7. Relationship-domain safety (fail closed when unprovable).
    _check_relationships(plan, findings)

    # 8. Structural-index and DBC semantic conditions.
    _check_index_conditions(plan, findings)

    # 9. Standalone IDX presence (dataset-level, no ownership inference).
    if source_files is not None:
        _check_standalone_idx(source_files, plan, findings)

    # 10. Pseudonym capacity feasibility (read-only, GLOBAL_TEXT C/V only).
    #     Requires verified source state AND the direct-read capability
    #     (schema + record streaming): a missing capability is reported as
    #     CAPABILITY_MISSING and the capacity scan is not entered at all.
    if (
        source_verified
        and source_files is not None
        and caps.direct_read
        and "PSEUDONYMIZE_REVERSIBLE" in plan.policy.transformation_classes
    ):
        outcome = _capacity_sufficient(source_files, plan)
        if outcome == _CAPACITY_INSUFFICIENT:
            findings.error(PreflightCode.PSEUDONYM_CAPACITY_INSUFFICIENT)
        elif outcome == _CAPACITY_UNPROVEN:
            findings.error(PreflightCode.PSEUDONYM_CAPACITY_UNPROVEN)

    # 11. Storage-space risk (side-effect-free; fail closed if the estimate
    #     cannot be made defensibly).
    storage = _storage_ok(source_files, output_root, vault_path, plan.policy.recovery_enabled)
    if storage is None:
        findings.error(PreflightCode.STORAGE_ESTIMATE_UNAVAILABLE)
    elif not storage:
        findings.error(PreflightCode.STORAGE_SPACE_INSUFFICIENT)

    return findings.result(plan, caps)