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
  (no source values, memo payloads, absolute paths or dependency messages).

Exceptions remain reserved for invalid object contracts, unexpected dependency
failures and impossible internal invariants (see :mod:`dbf_anonymizer.errors`).

Determinism
-----------
``check_codes`` / ``warning_codes`` / ``error_codes`` are each emitted in
ascending code-string order. No code is duplicated within a category. The
result depends only on the ``Plan``, the current source state and the
deterministic capability/storage inputs, so repeated calls over the same state
produce exactly equal ``to_dict()`` output.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable, cast

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
PREFLIGHT_CODE_VERSION = "1.0"


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


_resolve_path: Callable[[Path], Path] = _default_resolve_path
_disk_usage: Callable[[Path], tuple[int, int, int]] = _default_disk_usage

#: Conservative protected-vault reserve (bytes) used when reversible transforms
#: are planned. Documented constant; not a benchmark figure.
_VAULT_RESERVE_BYTES = 1024 * 1024

#: Conservative dbfbridge writer/spool reserve (bytes) for temporary/spill
#: state created while a table is written. Documented constant; not a
#: benchmark figure.
_WRITER_SPOOL_RESERVE_BYTES = 16 * 1024 * 1024

#: Peak exposure of the fresh output footprint: the published output plus one
#: full staged/temporary copy of the same data that may coexist before commit.
_STAGING_FACTOR = 2

#: Upper bound on exact distinct values retained per width class during the
#: capacity scan. Tight classes keep at most ``tokens(width) + 1`` values;
#: reaching a bound fails closed instead of growing unbounded.
_MAX_TRACKED_DISTINCT = 65536


def _nearest_existing_ancestor(path: Path) -> Path:
    """Return the nearest existing ancestor of *path* (for disk usage)."""
    candidate = path
    while True:
        if candidate.exists():
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
# Source artifact enumeration (read-only)
# ---------------------------------------------------------------------------
def _enumerate_in_scope(source_root: Path) -> dict[str, Path]:
    """Map relative posix path -> absolute path for in-scope source artifacts."""
    result: dict[str, Path] = {}
    if not source_root.is_dir():
        return result
    for dirpath, _dirnames, filenames in os.walk(source_root):
        for name in filenames:
            suffix = Path(name).suffix.lower()
            if suffix not in discovery.IN_SCOPE_EXTENSIONS:
                continue
            full = Path(dirpath) / name
            result[full.relative_to(source_root).as_posix()] = full
    return result


def _source_footprint_bytes(source_root: Path) -> int | None:
    """In-scope source DBF/FPT byte footprint, or None if not defensible.

    A missing source root or any stat failure makes the footprint unknown;
    the storage risk model then fails closed rather than under-estimate.
    """
    if not source_root.is_dir():
        return None
    total = 0
    for rel, full in _enumerate_in_scope(source_root).items():
        if rel.lower().endswith((".dbf", ".fpt")):
            try:
                total += full.stat().st_size
            except OSError:
                return None
    return total


def _standalone_idx_present(source_root: Path) -> bool:
    return any(rel.lower().endswith(".idx") for rel in _enumerate_in_scope(source_root))


def _recompute_source_fingerprint(source_root: Path) -> str | None:
    """Recompute the current source fingerprint using the P1-005/P0-004 logic."""
    try:
        entries = discovery.collect_fingerprint_entries(source_root)
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
        if ancestor.is_file():
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
    makes the destination uncreatable.
    """
    # Output is a directory target.
    if output.exists():
        if output.is_file():
            return True  # type conflict: cannot publish a directory over a file
        if output.is_dir() and any(output.iterdir()):
            return True  # non-empty directory would overwrite existing state

    # Vault is a file target.
    if vault.exists():
        if vault.is_dir():
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


def _check_standalone_idx(source_root: Path, plan: Plan, findings: _Findings) -> None:
    if plan.output_profile is not TransferProfile.DATA_ONLY:
        return
    if _standalone_idx_present(source_root):
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


def _tokens_up_to_width(max_width: int, base: int, limit: int | None = None) -> int:
    """Sum base^1..base^max_width, optionally stopping once *limit* is reached."""
    if max_width < 1 or base < 1:
        return 0
    total = 0
    term = 1
    for _ in range(1, max_width + 1):
        term *= base
        total += term
        if limit is not None and total >= limit:
            return total
    return total


def _capacity_sufficient(source_root: Path, plan: Plan) -> bool:
    """Conservative, deterministic GLOBAL_TEXT C/V capacity feasibility check.

    Reads only the C/V character fields that participate in the global text
    domain (deleted records included, because they are transformed later).
    NULL and empty values are preserved and therefore do not consume capacity.

    Feasibility is decided on EXACT distinct values (never on digests) against
    the mathematical token-space upper bound per width class: the number of
    distinct values of width <= w must not exceed base^1 + ... + base^w.
    Self-exclusion (a value must never map to itself) is only infeasible in
    the single-token edge case; it never removes a token per value.

    Memory is bounded: each width class retains at most
    ``min(tokens(width), _MAX_TRACKED_DISTINCT) + 1`` exact values; reaching a
    bound fails closed instead of tracking the whole dataset.
    No source value is ever logged or serialized.
    """
    if "PSEUDONYMIZE_REVERSIBLE" not in plan.policy.transformation_classes:
        return True

    tables = _enumerate_in_scope(source_root)
    dbf_paths = sorted(
        rel for rel in tables if rel.lower().endswith(".dbf")
    )
    if not dbf_paths:
        return True

    participating: set[str] = set()
    sensitive: list[tuple[str, Path, list[tuple[str, int]]]] = []
    for rel in dbf_paths:
        full = tables[rel]
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
            sensitive.append((rel, full, fields))

    if not sensitive:
        return True

    alphabet = _candidate_alphabet(frozenset(participating))
    if not alphabet:
        return False  # no safe common alphabet -> fail closed

    base = len(alphabet)
    widths = sorted({length for _rel, _full, fields in sensitive for _n, length in fields})
    class_cap = {
        width: _tokens_up_to_width(width, base, _MAX_TRACKED_DISTINCT) + 1
        for width in widths
    }
    class_sets: dict[int, set[str]] = {width: set() for width in widths}

    for rel, full, fields in sensitive:
        names = [name for name, _length in fields]
        length_by_name = dict(fields)
        try:
            for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
                full, include_deleted=True, fields=names, memo="lazy"
            ):
                for name in names:
                    value = record.values.get(name)
                    if value is None or value == "":
                        continue
                    if not isinstance(value, str):
                        continue
                    width = length_by_name[name]
                    members = class_sets[width]
                    if len(members) < class_cap[width]:
                        members.add(value)
                    else:
                        # Distinct count exceeded the class bound: either the
                        # token budget is exhausted (infeasible) or the width
                        # class is pathological (huge token space). Both fail
                        # closed; never an unbounded in-memory scan.
                        return False
        except Exception as exc:  # unexpected dependency failure
            raise DBFBridgeError.from_exception(
                exc,
                context=ErrorContext(
                    operation="preflight",
                    table_path=rel,
                    detail_code="capacity_iter_records_failed",
                ),
            ) from None

    # Feasibility: exact distinct counts vs the token-space upper bound, in
    # ascending width order (narrow classes bind first).
    smaller = 0
    total_distinct = 0
    for width in widths:
        count = len(class_sets[width])
        total_distinct += count
        if count + smaller > _tokens_up_to_width(width, base):
            return False
        smaller += count
    if total_distinct == 0:
        return True

    # Single-token edge case: with one value and a one-token space, that value
    # must not be the only token (it could not receive a different pseudonym).
    if total_distinct == 1 and base == 1:
        only_width = next(width for width in widths if class_sets[width])
        only_value = next(iter(class_sets[only_width]))
        if only_width == 1 and only_value == alphabet[0]:
            return False
    return True


# ---------------------------------------------------------------------------
# Storage-space risk
# ---------------------------------------------------------------------------
def _storage_ok(
    source_root: Path,
    output: Path,
    vault: Path,
    recovery_enabled: bool,
) -> bool | None:
    """Return True (ok), False (insufficient) or None (estimate unavailable).

    The risk model accounts for the fresh output footprint, the peak staged
    exposure (output plus one full temporary copy), the dbfbridge
    writer/spool reserve and, when reversible transforms are planned, the
    protected recovery-state reserve. If any input needed for a defensible
    estimate is unknown, None is returned and the caller fails closed.
    """
    footprint = _source_footprint_bytes(source_root)
    if footprint is None:
        return None
    required_output = footprint * _STAGING_FACTOR + _WRITER_SPOOL_RESERVE_BYTES
    required_vault = _VAULT_RESERVE_BYTES if recovery_enabled else 0

    try:
        out_total, _out_used, out_free = _disk_usage(output)
    except (OSError, ValueError):
        return None
    try:
        vault_total, _vault_used, vault_free = _disk_usage(vault)
    except (OSError, ValueError):
        return None

    try:
        out_dev = os.stat(_nearest_existing_ancestor(output)).st_dev
        vault_dev = os.stat(_nearest_existing_ancestor(vault)).st_dev
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
    if _paths_overlap(source_root, output_root, vault_path):
        findings.error(PreflightCode.PATH_OVERLAP)

    # 2. Source availability + freshness: a missing or unreadable source
    #    fails closed; a changed source is a fingerprint mismatch.
    if not source_root.is_dir():
        findings.error(PreflightCode.SOURCE_UNAVAILABLE)
    else:
        current_fp = _recompute_source_fingerprint(source_root)
        if current_fp is None:
            findings.error(PreflightCode.SOURCE_UNAVAILABLE)
        elif current_fp != plan.dataset.source_fingerprint:
            findings.error(PreflightCode.SOURCE_FINGERPRINT_MISMATCH)

    # 3. Destination conflicts (type conflicts / unsafe existing state).
    if _destination_conflict(output_root, vault_path):
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
    if source_root.is_dir():
        _check_standalone_idx(source_root, plan, findings)

    # 10. Pseudonym capacity feasibility (read-only, GLOBAL_TEXT C/V only).
    if source_root.is_dir() and "PSEUDONYMIZE_REVERSIBLE" in plan.policy.transformation_classes:
        if not _capacity_sufficient(source_root, plan):
            findings.error(PreflightCode.PSEUDONYM_CAPACITY_INSUFFICIENT)

    # 11. Storage-space risk (side-effect-free; fail closed if the estimate
    #     cannot be made defensibly).
    storage = _storage_ok(
        source_root, output_root, vault_path, plan.policy.recovery_enabled
    )
    if storage is None:
        findings.error(PreflightCode.STORAGE_ESTIMATE_UNAVAILABLE)
    elif not storage:
        findings.error(PreflightCode.STORAGE_SPACE_INSUFFICIENT)

    return findings.result(plan, caps)
