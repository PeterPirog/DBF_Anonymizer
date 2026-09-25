"""Deterministic, source-read-only, side-effect-free preflight (REQ-P1-006).

``preflight(plan)`` evaluates the already-planned :class:`~dbf_anonymizer.Plan`
against the preconditions that must hold *before* any transformation starts,
and returns an immutable :class:`~dbf_anonymizer.PreflightResult`.

Guarantees enforced by this module:

* source-read-only and side-effect-free: it creates no output, vault, SQLite
  file/sidecar, staging, lock, manifest, log, CDX/IDX/DBC or transformed data,
  and does not modify any source DBF/FPT/CDX/IDX/DBC artifact;
* it performs no network, subprocess, COM, VFP rebuild or verification itself;
  an explicitly supplied backend is queried only for its typed capability
  statement and is never discovered or retained globally;
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
The text-domain mathematical model (safe alphabet, encoded byte
feasibility, finite token space, strictest-width reduction) is owned by the
pure shared module :mod:`dbf_anonymizer.transforms.text`; this read-only
proof and the vault allocation service (REQ-P2-004/005/006) are two
consumers of that ONE authoritative model.

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
from typing import Callable, Mapping

import dbfbridge

from dbf_anonymizer import _capability
from dbf_anonymizer import discovery
from dbf_anonymizer import progress as progress_layer
from dbf_anonymizer.dictionary_identity import validate_dictionary_identity_readonly
from dbf_anonymizer.discovery import (
    _PATH_BLOCKED,
    _PATH_DIRECTORY,
    _PATH_FILE,
    _PATH_MISSING,
    _PATH_OTHER,
    probe_path,
)
from dbf_anonymizer.errors import (
    CancellationError,
    CallbackError,
    DBFBridgeError,
    ErrorContext,
    ErrorCode,
    VaultError,
)
from dbf_anonymizer.index_backend import IndexBackend, validate_backend_capabilities
from dbf_anonymizer.models import (
    Capabilities,
    IndexBackendCapability,
    PreflightResult,
    Plan,
    TablePlan,
    TransferProfile,
    VaultStrategy,
)
from dbf_anonymizer.policy import classify_field_capability
from dbf_anonymizer.progress import (
    CancelCheck,
    ProgressCallback,
    ProgressController,
    ProgressPhase,
)
from dbf_anonymizer.transforms.text import (
    SAFE_TEXT_ALPHABET,
    candidate_alphabet,
    reduced_strictest,
    token_space_at_least,
)

__all__ = ["preflight", "PREFLIGHT_CODE_VERSION", "PreflightCode"]

#: Versioned identity of the preflight code vocabulary.
PREFLIGHT_CODE_VERSION = "1.2"


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
    VAULT_REUSE_INCOMPATIBLE = "VAULT_REUSE_INCOMPATIBLE"
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
    NUMERIC_KEY_RECOVERY_UNWRITABLE = "NUMERIC_KEY_RECOVERY_UNWRITABLE"

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
        PreflightCode.VAULT_REUSE_INCOMPATIBLE,
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
        PreflightCode.NUMERIC_KEY_RECOVERY_UNWRITABLE,
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


def _default_iterdir(path: Path) -> list[Path]:
    return list(path.iterdir())


_resolve_path: Callable[[Path], Path] = _default_resolve_path
_disk_usage: Callable[[Path], tuple[int, int, int]] = _default_disk_usage
_stat_dev: Callable[[Path], int] = _default_stat_dev
_iterdir: Callable[[Path], list[Path]] = _default_iterdir
#: Stat-based path-probe seam (see :mod:`dbf_anonymizer.discovery.probe_path`).
#: Security-relevant inspection NEVER uses pathlib's exists/is_file/is_dir:
#: on Python 3.12+ they suppress OSError/PermissionError and would report an
#: inaccessible path as missing (fail-open). Only FileNotFoundError means
#: "missing"; other OSError propagates for deterministic fail-closed codes.
_probe: Callable[[Path], str] = probe_path

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
    """Return the nearest existing ancestor of *path* (for disk usage).

    Uses the raw stat probe: an inaccessible component raises ``OSError``
    (the caller degrades the storage estimate); it is never walked past as if
    it did not exist.
    """
    candidate = path
    while True:
        if _probe(candidate) != _PATH_MISSING:
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
def _enumerate_in_scope_strict(
    source_root: Path,
    *,
    cancel_probe: Callable[[], None] | None = None,
) -> dict[str, Path]:
    """Strict in-scope enumeration: traversal errors raise ``OSError``.

    Source verification in preflight must never treat an incomplete traversal
    as complete: an unreadable directory or disappeared entry fails closed
    (``SOURCE_UNAVAILABLE``) instead of being silently skipped.

    ``cancel_probe`` (a REQ-P1-008 private hook supplied by the progress
    controller) is forwarded into the traversal so cancellation is observed
    once per visited directory — the strict enumeration itself can never run
    to exhaustion unobserved.  The probe's typed cancellation/control
    exceptions propagate; they are never converted into findings.
    """
    return discovery.enumerate_in_scope_paths(
        source_root, strict=True, cancel_probe=cancel_probe
    )


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


def _recompute_source_fingerprint(
    source_root: Path,
    *,
    cancel_probe: Callable[[], None] | None = None,
    progress_probe: Callable[[int, int, str], None] | None = None,
) -> str | None:
    """Recompute the current source fingerprint using the P1-005/P0-004 logic.

    STRICT traversal: an incomplete enumeration (unreadable directory, racing
    deletion) raises ``OSError`` and the caller reports ``SOURCE_UNAVAILABLE``
    instead of treating a partial fingerprint as complete. The fingerprint
    payload format itself is unchanged.

    The optional private REQ-P1-008 hooks thread the shared progress
    controller into the strict fingerprinting: cancellation is polled per
    artifact and at bounded chunk intervals; one progress event is emitted
    per hashed artifact.
    """
    try:
        entries = discovery.collect_fingerprint_entries(
            source_root,
            strict=True,
            cancel_probe=cancel_probe,
            progress_probe=progress_probe,
        )
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
def _ancestor_conflict(path: Path) -> bool:
    """True when ANY ancestor of *path* makes the hierarchy uncreatable.

    A directory cannot be nested under a file anywhere in the chain, so the
    whole hierarchy is walked with the raw stat probe: missing components are
    walked past (they must be created), while an existing FILE/OTHER — or a
    BLOCKED component (NotADirectoryError: some part of the chain is not a
    directory) — is a deterministic destination conflict. ``OSError`` (e.g.
    ``PermissionError``) propagates; the caller converts it into
    ``PATH_INSPECTION_UNAVAILABLE``. An inaccessible component is never
    treated as nonexistent (Python 3.12+ pathlib predicates would).
    """
    ancestor = path.parent
    while True:
        kind = _probe(ancestor)
        if kind in (_PATH_FILE, _PATH_OTHER, _PATH_BLOCKED):
            return True
        parent = ancestor.parent
        if parent == ancestor:  # reached filesystem root
            return False
        ancestor = parent


def _destination_conflict(output: Path, vault: Path) -> bool:
    """Detect path-type conflicts and unsafe existing destination state.

    An existing regular vault file is a structurally valid reuse CANDIDATE
    only: its schema, integrity and complete dataset/policy/relationship
    identity are validated read-only and fail-closed by the dedicated
    vault-reuse step (see :func:`preflight`), which emits the
    ``VAULT_REUSE_INCOMPATIBLE`` finding without ever mutating anything. A
    directory or other non-file at the vault target remains a conflict. The
    ancestor chains of BOTH targets are also checked: a file (or otherwise
    non-directory component) in the hierarchy makes a missing target
    uncreatable.

    All decisions use the raw stat probe (never pathlib predicates):
    MISSING is the only innocent state; an uninspectable path raises
    ``OSError`` which the caller converts into the deterministic
    ``PATH_INSPECTION_UNAVAILABLE`` finding (never a raw OS error/path).
    """
    # Output is a directory target.
    output_kind = _probe(output)
    if output_kind in (_PATH_FILE, _PATH_OTHER):
        return True  # type conflict: cannot publish a directory over it
    if output_kind == _PATH_BLOCKED:
        return True  # blocked hierarchy: the target cannot be created
    if output_kind == _PATH_DIRECTORY and any(_iterdir(output)):
        return True  # non-empty directory would overwrite existing state

    # Vault is a file target: a missing target or existing regular file is
    # structurally valid; compatibility is validated read-only below.
    vault_kind = _probe(vault)
    if vault_kind not in (_PATH_MISSING, _PATH_FILE):
        return True

    # Any non-directory in either ancestor chain blocks directory creation.
    return _ancestor_conflict(output) or _ancestor_conflict(vault)


def _existing_vault_reusable(
    vault_path: Path,
    *,
    expected_source_fingerprint: str,
    expected_policy_fingerprint: str,
    expected_relationship_fingerprint: str,
) -> bool:
    """Read-only compatibility check of an existing regular vault file.

    Delegates to the shared dictionary-identity kernel (ONE authoritative
    schema/fingerprint parsing): integrity, exact schema version, identifier
    shape, dataset identity and unambiguous sidecar state — all without any
    mutation, sidecar creation, journal change or recovery. ``True`` means
    the file is a compatible reuse candidate; every incompatible or
    unverifiable state (including an unreadable file) fails closed.
    """
    try:
        validate_dictionary_identity_readonly(
            vault_path,
            expected_source_fingerprint=expected_source_fingerprint,
            expected_policy_fingerprint=expected_policy_fingerprint,
            expected_relationship_fingerprint=expected_relationship_fingerprint,
        )
    except (VaultError, OSError):
        return False
    return True


# ---------------------------------------------------------------------------
# Table-level and policy-level findings
# ---------------------------------------------------------------------------
_SUPPORTED_POLICY_SCHEMA_VERSIONS = frozenset({"1"})
_SUPPORTED_TRANSFORMATION_CLASSES = frozenset(
    {"PSEUDONYMIZE_REVERSIBLE", "MASK_REVERSIBLE", "SHIFT_REVERSIBLE"}
)
_SUPPORTED_INDEX_STRATEGIES = frozenset({"DATA_ONLY", "VFP_INDEXED"})


def _check_fields(
    tables: tuple[TablePlan, ...],
    findings: _Findings,
    on_table: Callable[[int, str], None] | None = None,
) -> None:
    for index, table in enumerate(tables, start=1):
        if on_table is not None:
            on_table(index, table.table_path)
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
    plan: Plan,
    caps: Capabilities,
    findings: _Findings,
    *,
    index_backend_capability: IndexBackendCapability | None = None,
) -> None:
    # A valid preflight plan always needs direct read and direct write.
    if not caps.direct_read or not caps.direct_write:
        findings.error(PreflightCode.CAPABILITY_MISSING)

    if plan.output_profile is TransferProfile.DATA_ONLY:
        findings.check(PreflightCode.DATA_ONLY_STANDALONE)
        return

    # Standalone discovery remains truthful (vfp_index_backend=False). A
    # public pseudonymize call may provide one already-validated, operation-
    # scoped backend capability without mutating that global discovery fact.
    if plan.output_profile is TransferProfile.VFP_INDEXED:
        if (
            index_backend_capability is None
            or not index_backend_capability.supports_structural_cdx_rebuild
            or not index_backend_capability.supports_verification
            or not index_backend_capability.vfp_runtime_available
        ):
            findings.error(PreflightCode.CAPABILITY_MISSING)
        return

    # Unknown profile -> fail closed.
    findings.error(PreflightCode.OUTPUT_PROFILE_UNSUPPORTED)


def _check_relationships(plan: Plan, findings: _Findings) -> None:
    """REQ-P3-001/003/005 relationship-domain validation.

    When the plan carries a parsed typed relationship document (from the
    real ``build_plan`` ingestion), the authoritative P3 compatibility
    validation runs against the retained document and the source-schema
    binding facts.  A VALID declared C/V or numeric-key relationship is
    accepted.

    A plan whose relationship metadata is only a SUMMARY (relation_count > 0)
    with no member semantics available CANNOT be verified from the count
    alone and still fails closed as ``RELATIONSHIP_DOMAIN_UNVERIFIED`` —
    verification is never faked from relation_count.
    """
    relationships = (
        getattr(plan.execution_context, "relationship_document", None)
        if plan.execution_context is not None
        else None
    )
    if relationships is None:
        if plan.relationships.relation_count > 0:
            findings.error(PreflightCode.RELATIONSHIP_DOMAIN_UNVERIFIED)
        return
    from dbf_anonymizer.relationships.compatibility import (
        validate_document_compatibility,
    )

    # The REAL P3 compatibility validation (typed, fail closed, privacy-safe):
    # a compatible document produces NO finding here; an incompatible one
    # FAILS CLOSED.  The typed PolicyError propagates as a preflight failure.
    from dbf_anonymizer.errors import PolicyError as _PolicyError

    try:
        validate_document_compatibility(relationships)
    except _PolicyError:
        findings.error(PreflightCode.RELATIONSHIP_DOMAIN_UNVERIFIED)
        return
    bindings = (
        getattr(plan.execution_context, "relationship_bindings", None)
        if plan.execution_context is not None
        else None
    )
    if bindings is not None:
        # Re-verify every declared member against the retained source-schema
        # binding facts (defence in depth; the build_plan binding already
        # refused mismatches before any plan existed).  Numeric key members
        # are re-verified against their FULL representation facts, including
        # the integral Numeric domain and the autoincrement refusal for
        # explicit reversible pseudonymization.
        from dbf_anonymizer.relationships.models import (
            NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
        )

        for group in relationships.groups:
            for member in group.members:
                fact = bindings.get((member.table_path, member.field_name))
                if (
                    fact is None
                    or member.dbf_type != fact[0]
                    or member.byte_width != fact[1]
                ):
                    findings.error(PreflightCode.RELATIONSHIP_DOMAIN_UNVERIFIED)
                    return
                if member.is_numeric_member and (
                    group.numeric_strategy == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE
                ):
                    if (member.dbf_type == "N" and fact[3] != 0) or fact[4]:
                        findings.error(PreflightCode.RELATIONSHIP_DOMAIN_UNVERIFIED)
                        return


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
# The text-domain mathematical model is OWNED by the pure shared module
# ``dbf_anonymizer.transforms.text`` (REQ-P2-004/005/006); the preflight
# capacity proof and the vault allocation service are two consumers of that
# ONE authoritative model (safe alphabet, encoded byte feasibility, token
# space, strictest-width reduction). The aliases below keep the historical
# private names of this module pointing at the shared kernels.
_CANDIDATE_ALPHABET = SAFE_TEXT_ALPHABET

_candidate_alphabet = candidate_alphabet

_token_space_at_least = token_space_at_least


def _capacity_sufficient(
    source_files: dict[str, Path],
    plan: Plan,
    control: ProgressController | None = None,
) -> str:
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

    REQ-P1-008: when a progress controller is supplied, the scan emits
    bounded structured progress (one ``CAPACITY_SCAN`` progress event per
    ``CAPACITY_PROGRESS_RECORD_QUANTUM`` streamed records) and polls
    cooperative cancellation at every streamed record boundary and at every
    table boundary.  Cancellation raises the typed
    ``CancellationError``; the result is never computed after cancellation.
    """
    global _LAST_CAPACITY_SCAN_STATS
    if control is None:
        control = ProgressController(operation="preflight")
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

    execution_context = plan.execution_context
    merged_policy = (
        execution_context.resolved_policy
        if execution_context is not None
        else None
    )
    if not isinstance(merged_policy, Mapping):
        _LAST_CAPACITY_SCAN_STATS["outcome"] = _CAPACITY_UNPROVEN
        return _CAPACITY_UNPROVEN

    participating: set[str] = set()
    sensitive: list[tuple[str, Path, int, list[tuple[str, int]]]] = []
    for rel in dbf_rels:
        control.check_cancelled()
        full = source_files[rel]
        try:
            schema = dbfbridge.read_schema(full)  # type: ignore[attr-defined]
        except (CancellationError, CallbackError):
            raise
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
            action, _unsafe, _system = classify_field_capability(
                str(field.dbf_type),
                str(field.name),
                bool(field.supported),
                bool(field.is_binary),
                bool(field.system),
                bool(field.nocptrans),
                merged_policy,
            )
            if action == "PSEUDONYMIZE_REVERSIBLE":
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

    streaming_tables: list[tuple[str, Path, list[tuple[str, int]]]] = []
    total_stream_records = 0
    for rel, full, record_count, table_fields in sensitive:
        selected = [(name, length) for name, length in table_fields if length <= max_tight]
        if selected:
            streaming_tables.append((rel, full, selected))
            total_stream_records += record_count

    # The capacity scan is a real long-running safe point: cancellation is
    # polled at EVERY streamed record boundary (quantum 1 record, minimal
    # deterministic latency) and at every table boundary; progress events are
    # bounded to one per CAPACITY_PROGRESS_RECORD_QUANTUM streamed records.
    control.start_phase(ProgressPhase.CAPACITY_SCAN, total=total_stream_records)
    record_quantum = progress_layer.CAPACITY_PROGRESS_RECORD_QUANTUM
    streamed = 0
    for rel, full, selected in streaming_tables:
        names = [name for name, _length in selected]
        try:
            for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
                full, include_deleted=True, fields=names, memo="lazy"
            ):
                streamed += 1
                control.check_cancelled()
                if control.has_progress and streamed % record_quantum == 0:
                    control.progress(
                        ProgressPhase.CAPACITY_SCAN,
                        completed=streamed,
                        total=total_stream_records,
                        table_path=rel,
                    )
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
                        tracker[value] = reduced_strictest(None, length)
                        if _note_strictest(None, length):
                            outcome = _CAPACITY_INSUFFICIENT
                            break
                    elif length < strictest:
                        tracker[value] = reduced_strictest(strictest, length)
                        if _note_strictest(strictest, length):
                            outcome = _CAPACITY_INSUFFICIENT
                            break
                if outcome is not _CAPACITY_OK:
                    break
            if outcome is not _CAPACITY_OK:
                break
        except (CancellationError, CallbackError):
            raise
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
# Numeric key-domain capacity feasibility (REQ-P3-005) — read-only
# ---------------------------------------------------------------------------
#: Hard, enforced integer ceiling on the exact distinct numeric originals
#: retained by the numeric capacity scan.  Reaching the ceiling fails closed
#: with ``PSEUDONYM_CAPACITY_UNPROVEN``; it is never treated as capacity data.
_MAX_NUMERIC_EXACT_VALUES = 65536

_NUMERIC_CAPACITY_UNWRITABLE = "NUMERIC_KEY_RECOVERY_UNWRITABLE"


def _numeric_relation_capacity(
    source_files: dict[str, Path],
    plan: Plan,
    control: ProgressController | None = None,
) -> tuple[str, bool]:
    """Side-effect-free numeric key-domain capacity preflight (REQ-P3-005).

    For EVERY explicitly declared ``REVERSIBLE_BIJECTIVE`` numeric key
    relationship the scan proves, BEFORE any transformation and with ZERO
    created output/vault state, that the shared numeric mapping domain can
    allocate a bijection for all distinct observed originals:

    * the already-parsed relationship document and the REAL source-schema
      bindings resolve each relation's member representations through the
      authoritative numeric domain kernel (no vault, no second database);
    * public dbfbridge record streaming covers ACTIVE AND DELETED records
      (both are transformed later);
    * NULL consumes no mapping token (it stays a preserved identity);
    * exact distinct originals are collected only as required for the proof,
      under the hard enforced ceiling ``_MAX_NUMERIC_EXACT_VALUES``; exceeding
      it fails closed with ``_CAPACITY_UNPROVEN`` instead of guessing;
    * a readable Integer original that the pinned public Direct Write
      boundary could never reconstruct during recovery (the int32 extremes)
      is reported as ``NUMERIC_KEY_RECOVERY_UNWRITABLE``;
    * a non-integral observed numeric value can never be represented
      faithfully by the integral domain -> ``_CAPACITY_INSUFFICIENT``.

    Returns ``(capacity_outcome, unwritable_original_found)``; the capacity
    outcome is one of ``_CAPACITY_OK`` / ``_CAPACITY_INSUFFICIENT`` /
    ``_CAPACITY_UNPROVEN``.  No source value is ever logged or serialized.

    REQ-P1-008: the scan polls cooperative cancellation at every streamed
    record boundary and emits bounded structured progress through the shared
    ``CAPACITY_SCAN`` phase.
    """
    if control is None:
        control = ProgressController(operation="preflight")
    context = plan.execution_context
    document = context.relationship_document if context is not None else None
    if document is None:
        return (_CAPACITY_OK, False)
    from dbf_anonymizer.relationships.models import (
        NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
    )

    reversible_groups = [
        group
        for group in document.groups
        if group.numeric_strategy == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE
    ]
    if not reversible_groups:
        return (_CAPACITY_OK, False)
    bindings = context.relationship_bindings if context is not None else None
    if bindings is None:
        bindings = {}
    from dbf_anonymizer.transforms.numeric_keys import (
        MEMBER_ORIGINAL_OUT_OF_MEMBER_RANGE,
        MEMBER_ORIGINAL_RECOVERY_UNWRITABLE,
        MEMBER_ORIGINAL_REVERSIBLE,
        NumericKeyDomain,
        NumericKeyMemberRange,
        classify_member_original,
        integral_numeric_member,
        integer_member,
        numeric_key_domain_for,
        plan_numeric_bijection,
    )

    tasks: list[
        tuple[str, NumericKeyDomain, list[tuple[str, str, NumericKeyMemberRange]]]
    ] = []
    for group in reversible_groups:
        members: list[tuple[str, str, NumericKeyMemberRange]] = []
        domain_members = []
        for member in group.members:
            if not member.is_numeric_member:
                continue
            fact = bindings.get((member.table_path, member.field_name))
            if fact is None:
                # A reversible numeric member without a REAL source-schema
                # binding cannot be proven: fail closed without guessing.
                return (_CAPACITY_UNPROVEN, False)
            dbf_type, _length, _encoding, _decimals, _autoincrement, _nullable = fact
            if dbf_type == "I":
                kernel_member = integer_member()
            else:
                kernel_member = integral_numeric_member(int(member.byte_width))
            domain_members.append(kernel_member)
            members.append((member.table_path, member.field_name, kernel_member))
        if not members:
            return (_CAPACITY_UNPROVEN, False)
        try:
            domain = numeric_key_domain_for(domain_members)
        except ValueError:
            # An empty shared representable range is an impossible constraint.
            return (_CAPACITY_INSUFFICIENT, False)
        tasks.append((group.relation_id, domain, members))
    if not tasks:
        return (_CAPACITY_OK, False)

    unwritable = False
    for _relation_id, domain, members in tasks:
        control.start_phase(ProgressPhase.CAPACITY_SCAN, total=len(members))
        distinct: set[int] = set()
        for table_path, field_name, kernel_member in members:
            rel = table_path
            full = source_files.get(rel)
            if full is None:
                return (_CAPACITY_UNPROVEN, unwritable)
            control.check_cancelled()
            names = [field_name]
            try:
                for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
                    full, include_deleted=True, fields=names, memo="skip"
                ):
                    control.check_cancelled()
                    value = record.values.get(field_name)
                    if value is None:
                        continue  # NULL consumes no mapping token
                    if isinstance(value, bool) or not isinstance(value, int):
                        # A non-integral observed numeric value cannot be
                        # represented faithfully by the integral domain.
                        return (_CAPACITY_INSUFFICIENT, unwritable)
                    # THE SAME authoritative origin-member reversible rule the
                    # allocator enforces: the verdict depends ONLY on the
                    # originating member, never on the union of members.
                    verdict = classify_member_original(kernel_member, value)
                    if verdict == MEMBER_ORIGINAL_OUT_OF_MEMBER_RANGE:
                        return (_CAPACITY_INSUFFICIENT, unwritable)
                    if verdict == MEMBER_ORIGINAL_RECOVERY_UNWRITABLE:
                        # Readable but NOT reconstructable through the pinned
                        # public Direct Write boundary for this member.
                        unwritable = True
                        continue
                    if len(distinct) >= _MAX_NUMERIC_EXACT_VALUES and value not in distinct:
                        return (_CAPACITY_UNPROVEN, unwritable)
                    distinct.add(value)
            except (CancellationError, CallbackError):
                raise
            except Exception as exc:
                raise DBFBridgeError.from_exception(
                    exc,
                    context=ErrorContext(
                        operation="preflight",
                        table_path=rel,
                        detail_code="numeric_capacity_iter_records_failed",
                    ),
                ) from None
            control.bump(ProgressPhase.CAPACITY_SCAN, table_path=rel)
        if not plan_numeric_bijection(domain, sorted(distinct), []):
            return (_CAPACITY_INSUFFICIENT, unwritable)
    return (_CAPACITY_OK, unwritable)


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
# Public entry point + shared internal evaluation core
# ---------------------------------------------------------------------------
def _evaluate_plan_readonly(
    plan: Plan,
    control: ProgressController,
    injected_backend_capability: IndexBackendCapability | None = None,
) -> PreflightResult:
    """The ONE read-only preflight evaluation core (internal).

    Drives every side-effect-free evaluation step through the SUPPLIED
    :class:`~dbf_anonymizer.progress.ProgressController`: cancellation is
    polled at the declared scan safe points and bounded structured progress
    events are emitted with the controller's ONE operation id. The core
    NEVER emits a terminal completion event:

    * the public :func:`preflight` wrapper owns its single terminal
      ``COMPLETED`` event for the standalone operation;
    * the public ``pseudonymize`` service reuses this core under its OWN
      controller, so one public invocation has exactly one controller, one
      operation id and exactly one terminal completion emitted only after
      the whole operation genuinely succeeds (no second logical operation
      and no intermediate preflight completion).

    ``injected_backend_capability`` augments only the operation-scoped
    VFP_INDEXED check. Canonical direct-read/write facts always come from the
    side-effect-free standalone provider and are never replaced or mutated.
    """
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
    control.check_cancelled()
    try:
        overlap = _paths_overlap(source_root, output_root, vault_path)
    except OSError:
        overlap = False
        findings.error(PreflightCode.PATH_INSPECTION_UNAVAILABLE)
    if overlap:
        findings.error(PreflightCode.PATH_OVERLAP)

    # 2. Source availability + freshness, under STRICT traversal: a missing,
    #    unreadable or non-directory source fails closed as
    #    SOURCE_UNAVAILABLE (an incomplete enumeration is never treated as
    #    complete, and Python 3.12+ pathlib predicate suppression is never
    #    trusted); a changed source is a fingerprint mismatch. Downstream
    #    source-consuming checks (standalone IDX inventory, capacity scan)
    #    only run on verified source state.
    control.start_phase(ProgressPhase.SOURCE_VERIFICATION)
    source_files: dict[str, Path] | None = None
    source_verified = False
    try:
        root_kind = _probe(source_root)
    except OSError:
        root_kind = None
    if root_kind != _PATH_DIRECTORY:
        findings.error(PreflightCode.SOURCE_UNAVAILABLE)
    else:
        try:
            source_files = _enumerate_in_scope_strict(
                source_root, cancel_probe=control.check_cancelled
            )
        except OSError:
            source_files = None
            findings.error(PreflightCode.SOURCE_UNAVAILABLE)
        if source_files is not None:
            current_fp = _recompute_source_fingerprint(
                source_root,
                cancel_probe=control.check_cancelled,
                progress_probe=lambda done, total, rel: control.progress(
                    ProgressPhase.SOURCE_VERIFICATION,
                    completed=done,
                    total=total,
                    table_path=rel,
                ),
            )
            if current_fp is None:
                findings.error(PreflightCode.SOURCE_UNAVAILABLE)
            elif current_fp != plan.dataset.source_fingerprint:
                findings.error(PreflightCode.SOURCE_FINGERPRINT_MISMATCH)
            else:
                source_verified = True

    # 3. Destination conflicts (type conflicts / unsafe existing state).
    #    Uninspectable existing state fails closed deterministically.
    control.check_cancelled()
    try:
        conflict = _destination_conflict(output_root, vault_path)
    except OSError:
        conflict = False
        findings.error(PreflightCode.PATH_INSPECTION_UNAVAILABLE)
    if conflict:
        findings.error(PreflightCode.DESTINATION_CONFLICT)

    # 3b. Existing regular vault file: read-only reuse validation
    #     (REQ-P1-006 destination-state detection + REQ-P2-010 identity
    #     checking). ONE shared dictionary-identity kernel decides integrity,
    #     schema version, identifier shape, dataset identity and sidecar
    #     ambiguity with ZERO mutation, sidecar creation, journal change or
    #     recovery. An incompatible or unverifiable file fails closed with
    #     the dedicated privacy-safe code — never with a SQLite message.
    #     This runs for EVERY existing vault file, independently of any other
    #     destination conflict, so an incompatible vault can never hide
    #     behind an unrelated destination finding.
    control.check_cancelled()
    try:
        vault_kind = _probe(vault_path)
    except OSError:
        vault_kind = None
    if vault_kind == _PATH_FILE and not _existing_vault_reusable(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
    ):
        findings.error(PreflightCode.VAULT_REUSE_INCOMPATIBLE)

    # 4. Table-level field/companion findings (unsupported/unsafe/memo/cdx),
    #    with a per-table cancellation safe point and a progress event per
    #    table: at every table evaluation boundary cancellation is polled
    #    first, then the progress event is reported (deterministic order),
    #    then the table's findings are evaluated.  The bound is one table.
    control.start_phase(ProgressPhase.TABLE_EVALUATION, total=len(plan.tables))

    def _on_table(_index: int, table_path: str) -> None:
        control.check_cancelled()
        control.bump(ProgressPhase.TABLE_EVALUATION, table_path=table_path)

    _check_fields(plan.tables, findings, on_table=_on_table)

    # 5. Policy/plan consistency (tamper-resistant).
    control.check_cancelled()
    _check_policy_consistency(plan, findings)

    # 6. Output profile safety + runtime capabilities.
    control.check_cancelled()
    _check_output_profile_and_capabilities(
        plan,
        caps,
        findings,
        index_backend_capability=injected_backend_capability,
    )

    # 7. Relationship-domain safety (fail closed when unprovable).
    control.check_cancelled()
    _check_relationships(plan, findings)

    # 8. Structural-index and DBC semantic conditions.
    control.check_cancelled()
    _check_index_conditions(plan, findings)

    # 9. Standalone IDX presence (dataset-level, no ownership inference).
    control.check_cancelled()
    if source_files is not None:
        _check_standalone_idx(source_files, plan, findings)

    # 10. Pseudonym capacity feasibility (read-only, GLOBAL_TEXT C/V and
    #     REQ-P3-005 numeric key domains).  Requires verified source state AND
    #     the direct-read capability (schema + record streaming): a missing
    #     capability is reported as CAPABILITY_MISSING and the capacity scans
    #     are not entered at all.  Both scans are side-effect-free: they
    #     create no output, no vault and no SQLite artifact.
    control.check_cancelled()
    if (
        source_verified
        and source_files is not None
        and caps.direct_read
        and "PSEUDONYMIZE_REVERSIBLE" in plan.policy.transformation_classes
    ):
        outcome = _capacity_sufficient(source_files, plan, control)
        if outcome == _CAPACITY_INSUFFICIENT:
            findings.error(PreflightCode.PSEUDONYM_CAPACITY_INSUFFICIENT)
        elif outcome == _CAPACITY_UNPROVEN:
            findings.error(PreflightCode.PSEUDONYM_CAPACITY_UNPROVEN)
        numeric_outcome, unwritable = _numeric_relation_capacity(
            source_files, plan, control
        )
        if unwritable:
            findings.error(PreflightCode.NUMERIC_KEY_RECOVERY_UNWRITABLE)
        if numeric_outcome == _CAPACITY_INSUFFICIENT:
            findings.error(PreflightCode.PSEUDONYM_CAPACITY_INSUFFICIENT)
        elif numeric_outcome == _CAPACITY_UNPROVEN:
            findings.error(PreflightCode.PSEUDONYM_CAPACITY_UNPROVEN)

    # 11. Storage-space risk (side-effect-free; fail closed if the estimate
    #     cannot be made defensibly).
    control.check_cancelled()
    storage = _storage_ok(source_files, output_root, vault_path, plan.policy.recovery_enabled)
    if storage is None:
        findings.error(PreflightCode.STORAGE_ESTIMATE_UNAVAILABLE)
    elif not storage:
        findings.error(PreflightCode.STORAGE_SPACE_INSUFFICIENT)

    return findings.result(plan, caps)


def preflight(
    plan: Plan,
    *,
    index_backend: IndexBackend | None = None,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> PreflightResult:
    """Evaluate a planned dataset for preconditions before transformation.

    ``preflight`` is source-read-only and side-effect-free. It aggregates all
    preconditions into a single immutable :class:`PreflightResult`. The
    optional ``index_backend`` is an explicit operation-scoped capability
    input: its typed capability statement is validated fail-closed and used
    only for this evaluation. No backend is discovered, imported, initialized
    or stored globally, and no rebuild or verification method is called.
    Ordinary findings never raise; only invalid object contracts, unexpected
    dependency failures and impossible invariants do.

    REQ-P1-008: the optional keyword-only ``progress`` callback receives
    bounded structured :class:`~dbf_anonymizer.models.ProgressEvent` updates
    and ``cancel_check`` is polled at scan safe points (before every major
    stage, once per visited directory during the strict source enumeration,
    per checked table, per revalidated artifact, at bounded chunk intervals
    while hashing and at every streamed capacity-scan record).
    Cancellation raises the typed
    :class:`~dbf_anonymizer.errors.CancellationError` — it is never turned
    into an ordinary preflight finding and no result is produced after it.
    Callback failures are contained into the classified
    :class:`~dbf_anonymizer.errors.CallbackError`.  With both callbacks
    omitted the deterministic result is unchanged.

    The evaluation itself is the shared internal core
    :func:`_evaluate_plan_readonly`; this wrapper owns the standalone
    operation's single terminal completion event.
    """
    if not isinstance(plan, Plan):
        raise TypeError("preflight requires a Plan")
    if index_backend is not None and not isinstance(index_backend, IndexBackend):
        raise TypeError("index_backend must implement the IndexBackend protocol")

    backend_capability = (
        validate_backend_capabilities(index_backend)
        if index_backend is not None
        else None
    )

    control = ProgressController(
        operation="preflight", progress=progress, cancel_check=cancel_check
    )
    control.start_phase(ProgressPhase.OPERATION)
    result = _evaluate_plan_readonly(
        plan,
        control,
        injected_backend_capability=(
            backend_capability
            if plan.output_profile is TransferProfile.VFP_INDEXED
            else None
        ),
    )
    # The single terminal completion event is emitted only now — after the
    # public result genuinely exists (never after cancellation).
    control.complete(completed=len(plan.tables))
    return result
