"""REQ-P1-006 — deterministic read-only, side-effect-free preflight evidence.

This suite proves the stable negative-fixture matrix (aggregated ``ready=False``
findings), the truthful positive/warning cases, deterministic repeatability,
privacy/redaction, the global-strictest-width pseudonym capacity proof with a
hard enforced memory ceiling, source-scaled storage risk reserves, strict
source traversal, privacy-safe filesystem-error degradation, and — for every
rejection — zero created output/vault state and byte-identical source.

Only approved synthetic fixtures (``tests/fixtures/p0/**``) and disposable
synthetic data created under ``tmp_path`` via the public ``dbfbridge`` API are
used. No production data is accessed. No raw/manual DBF writer exists in this
suite: every synthetic table is produced through the public ``dbfbridge``
``write_table`` boundary (the repository-wide no-raw-DBF-writer regression
lives in ``tests/test_architecture_boundary.py``).

Unsupported-field and NOCPTRANS acceptance evidence is deliberately split:

* the P0 fixture corpus proves the dependency's negative/opaque classification
  through the public API (``test_opaque_field_write_refusal``: the public
  writer refuses Q/W, so no on-disk unsupported-type fixture can exist) and
  the P1-005 planning tests prove NOCPTRANS/binary classification
  (``test_nocptrans_*`` in ``tests/test_p1_build_plan.py``);
* THIS suite proves the preflight decision logic with immutable public
  ``TablePlan``/``Plan`` models — no byte-level fixture fabrication.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

import dbfbridge

import dbf_anonymizer._capability as _capabilities_mod
from dbf_anonymizer import build_plan, preflight
from dbf_anonymizer.errors import DBFBridgeError, ErrorCode
from dbf_anonymizer.models import (
    Capabilities,
    Plan,
    PreflightResult,
    RelationshipMetadata,
)

import dbf_anonymizer.preflight  # ensure module loaded
from dbf_anonymizer import preflight as _preflight_mod  # noqa: F401

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "p0"

#: The conservative single-case pseudonym alphabet mirrored from the product.
_BASE36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _pf_module():
    """Return the preflight module object (reliably, despite name shadowing)."""
    return sys.modules["dbf_anonymizer.preflight"]


# ---------------------------------------------------------------------------
# Synthetic data helpers (public dbfbridge only)
# ---------------------------------------------------------------------------
def _field(
    name: str, dbf_type: str, length: int, *, flags: int = 0
) -> dbfbridge.FieldInfo:
    return dbfbridge.FieldInfo(
        ordinal=0, name=name, dbf_type=dbf_type, length=length,
        decimal_count=0, address=0, flags=flags, index_field_flag=0,
        autoincrement_next_value=0, autoincrement_step=1,
        is_memo=dbf_type in {"M", "G", "P"}, is_binary=False, supported=True,
        dbversion_byte=0x30,
    )


def _schema(fields: tuple[dbfbridge.FieldInfo, ...]) -> dbfbridge.TableSchema:
    return dbfbridge.TableSchema(
        path=Path("memory:test"), record_count=0,
        header_length=32 + 32 * len(fields) + 1,
        record_length=sum(f.length for f in fields) + 1,
        language_driver=0xC8, encoding="cp1250",
        has_memo=False, has_memo_flag=False, has_structural_cdx=False,
        is_database_container=False, dbc_bound=False, dbc_backlink_path=None,
        table_flags=0, fields=fields, warnings=(),
        dbversion_byte=0x30, dbversion_name="Visual FoxPro",
        last_update=None, incomplete_transaction=False, encryption_flag=False,
        memo_companion_format=None, memo_companion_present=False,
        memo_companion_path=None, memo_companion_size_bytes=None,
        memo_block_size=None, memo_next_free_block=None,
        companion_cdx_present=False, companion_cdx_path=None,
    )


def _write_table(path: Path, fields: list[tuple[str, str, int]], records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fdefs = tuple(_field(n, t, l) for n, t, l in fields)
    dbfbridge.write_table(path, schema=_schema(fdefs), records=records)


def _nullflags_field() -> dbfbridge.FieldInfo:
    """The trusted VFP NULL bitmap system column required beside V fields."""
    return _field("_NULLFLAGS", "0", 1, flags=0x01)


def _write_varchar_table(path: Path, values: list[str | None]) -> None:
    """Write a Varchar table through public dbfbridge (V values keep their
    significant trailing spaces; NULL/empty are preserved as-is)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fdefs = (_field("VC", "V", 2), _nullflags_field())
    dbfbridge.write_table(
        path,
        schema=_schema(fdefs),
        records=[{"VC": value, "_NULLFLAGS": 0} for value in values],
    )


def _copy_fixture(dest_root: Path, rel: str) -> None:
    dst = dest_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(FIXTURES / rel, dst)


def _make_source(tmp: Path) -> Path:
    src = tmp / "src"
    _write_table(src / "customers" / "customers.dbf",
                 [("CODE", "C", 20), ("QTY", "N", 10)],
                 [{"CODE": "ALPHA", "QTY": 1}, {"CODE": "BETA", "QTY": 2},
                  {"CODE": "GAMMA", "QTY": 3}])
    return src


def _build_plan(tmp: Path, **kwargs: Any) -> Plan:
    src = _make_source(tmp)
    return build_plan(source=src, output=tmp / "out", vault=tmp / "vault" / "dict.sqlite3", **kwargs)


def _source_dbf_footprint(src: Path) -> int:
    """The in-scope (DBF/FPT) source byte footprint, mirroring the product."""
    return sum(
        p.stat().st_size
        for p in src.rglob("*")
        if p.is_file() and p.suffix.lower() in {".dbf", ".fpt"}
    )


# ---------------------------------------------------------------------------
# Deterministic storage seam: ample free space by default
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _ample_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _pf_module(), "_disk_usage",
        lambda _p: (10**15, 10**12, 10**15 - 10**12),
    )


def _caps(**overrides: bool) -> Capabilities:
    base: dict[str, Any] = {
        "direct_read": True, "direct_write": True, "recovery": False,
        "transfer_bundle": False, "vfp_index_backend": False,
        "dbfbridge_version": "1.1.0",
    }
    base.update(overrides)
    return Capabilities(**base)  # type: ignore[arg-type]


def _set_caps(monkeypatch: pytest.MonkeyPatch, caps: Capabilities) -> None:
    monkeypatch.setattr(_capabilities_mod, "capabilities_provider", lambda: caps)


# ---------------------------------------------------------------------------
# Side-effect-free harness: prove zero created state + byte-identical source
# ---------------------------------------------------------------------------
def _tree_snapshot(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            h = hashlib.sha256()
            with p.open("rb") as fh:
                while chunk := fh.read(65536):
                    h.update(chunk)
            out[rel] = h.hexdigest()
    return out


def _preflight_no_side_effects(
    plan: Plan, tmp: Path, *, preexisting: tuple[str, ...] = (),
) -> PreflightResult:
    """Run preflight and prove zero created/modified state.

    Paths named in *preexisting* may already exist (they are part of the
    tested filesystem state) but must gain no new files either.
    """
    before = _tree_snapshot(tmp)
    result = preflight(plan)
    after = _tree_snapshot(tmp)
    created = set(after) - set(before)
    modified = {r for r in before if before[r] != after.get(r)}
    assert not created, f"preflight created files: {sorted(created)}"
    assert not modified, f"preflight modified files: {sorted(modified)}"
    for absent in ("out", "vault"):
        if absent not in preexisting:
            assert not (tmp / absent).exists(), f"{absent} directory was created"
    sqlite_sidecars = [n for n in (*created, *after) if "sqlite" in n.lower() or n.lower().endswith(("-wal", "-shm", ".lock", ".log"))]
    assert not sqlite_sidecars, f"sqlite/sidecar created: {sqlite_sidecars}"
    return result


# ---------------------------------------------------------------------------
# 1-6. Source/output/vault overlap (including nesting)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "output_suffix,vault_suffix",
    [
        ("src", "v"),          # 1. source == output
        ("o", "src"),          # 2. source == vault
        ("o", "o"),            # 3. output == vault
    ],
    ids=["source==output", "source==vault", "output==vault"],
)
def test_identity_overlap_rejected(
    tmp_path: Path, output_suffix: str, vault_suffix: str
) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / output_suffix, vault=tmp_path / vault_suffix)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PATH_OVERLAP" in result.error_codes


@pytest.mark.parametrize(
    "output_suffix,vault_suffix",
    [
        ("src/nested_out", "v"),                # 4. output nested under source
        ("o", "src/nested_v"),                  # 5. vault nested under source
        ("src/out/x", "src/vault/v"),           # 6. both nested under source
    ],
    ids=["output-in-source", "vault-in-source", "both-nested"],
)
def test_nested_overlap_rejected(
    tmp_path: Path, output_suffix: str, vault_suffix: str
) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / output_suffix, vault=tmp_path / vault_suffix)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PATH_OVERLAP" in result.error_codes


# ---------------------------------------------------------------------------
# 7. Resolved alias overlap (portable test seam; no symlink required)
# ---------------------------------------------------------------------------
def test_alias_overlap_detected_via_resolver_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "elsewhere", vault=tmp_path / "v")
    # Distinct literal paths that the resolver maps to the same canonical target.
    shared = src.resolve()

    def _fake_resolve(p: Path) -> Path:
        if p.as_posix().endswith("elsewhere"):
            return shared
        return p.resolve()

    monkeypatch.setattr(_pf_module(), "_resolve_path", _fake_resolve)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PATH_OVERLAP" in result.error_codes


# ---------------------------------------------------------------------------
# 8. Source fingerprint changed after build_plan
# ---------------------------------------------------------------------------
def test_source_fingerprint_mismatch_rejected(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    # Mutate the source after planning (add a record -> different bytes).
    table = src / "customers" / "customers.dbf"
    dbfbridge.write_table(
        table,
        schema=dbfbridge.read_schema(table),
        records=[{"CODE": "ALPHA", "QTY": 1}, {"CODE": "BETA", "QTY": 2},
                 {"CODE": "GAMMA", "QTY": 3}, {"CODE": "DELTA", "QTY": 4}],
        overwrite=True,
    )
    result = preflight(plan)
    assert result.ready is False
    assert "SOURCE_FINGERPRINT_MISMATCH" in result.error_codes


def test_source_unavailable_rejected(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    # The source disappears after planning: preflight must fail closed.
    shutil.rmtree(src)
    result = preflight(plan)
    assert result.ready is False
    assert "SOURCE_UNAVAILABLE" in result.error_codes
    # Without a defensible footprint the storage estimate fails closed too.
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes


# ---------------------------------------------------------------------------
# 9. Missing memo companion (approved synthetic fixture)
# ---------------------------------------------------------------------------
def test_missing_memo_companion_rejected(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _copy_fixture(src, "malformed/missing_memo_companion.dbf")
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "MISSING_MEMO_COMPANION" in result.error_codes


# ---------------------------------------------------------------------------
# 10-11. Unsupported / unsafe (NOCPTRANS) user fields
# ---------------------------------------------------------------------------
# The public dbfbridge writer refuses unsupported (Q/W) and binary/NOCPTRANS
# user fields, so no on-disk fixture with those conditions can be produced
# through the approved boundary (see the P0 corpus negative evidence
# ``test_opaque_field_write_refusal`` and P1-005 ``test_nocptrans_*``).
# The preflight DECISION logic is therefore proven here with immutable public
# models: a real synthetic plan whose TablePlan counts objectively carry the
# condition. No byte-level fixture is fabricated.
def _plan_with_field_counts(tmp_path: Path, **count_overrides: int) -> Plan:
    plan = _build_plan(tmp_path)
    table = plan.tables[0]
    mutated = dataclasses.replace(table, **count_overrides)
    return dataclasses.replace(plan, tables=(mutated, *plan.tables[1:]))


def test_unsupported_field_rejected(tmp_path: Path) -> None:
    # A reader-unsupported (e.g. Q Varbinary) user field is rejected by the
    # preflight decision, mirroring the TablePlan facts build_plan computes.
    plan = _plan_with_field_counts(tmp_path, unsupported_field_count=1, unsafe_field_count=1)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "UNSUPPORTED_FIELD" in result.error_codes
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes


def test_unsafe_nocptrans_binary_field_rejected(tmp_path: Path) -> None:
    # A Character field carrying the binary/NOCPTRANS descriptor condition is
    # unsafe for the global-text domain and must reject.
    plan = _plan_with_field_counts(tmp_path, unsafe_field_count=1)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "UNSAFE_FIELD" in result.error_codes


def test_unsafe_only_text_field_is_not_capacity_participating(tmp_path: Path) -> None:
    # A binary/NOCPTRANS C field is excluded from the GLOBAL_TEXT domain: a
    # table whose only text field is unsafe contributes no capacity constraint,
    # so the sole rejection is UNSAFE_FIELD (mirroring the P1-005 planning
    # classification that makes such fields non-participating).
    src = tmp_path / "src"
    _write_table(src / "only" / "only.dbf", [("NOTE", "C", 8)], [{"NOTE": "keep-me"}])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    table = dataclasses.replace(
        plan.tables[0], transform_field_count=0, unsafe_field_count=1
    )
    plan = dataclasses.replace(plan, tables=(table,))
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "UNSAFE_FIELD" in result.error_codes


# ---------------------------------------------------------------------------
# 12-14. Destination conflicts
# ---------------------------------------------------------------------------
def test_output_already_exists_as_file_rejected(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    (tmp_path / "out").write_bytes(b"preexisting-state")
    result = preflight(plan)
    assert result.ready is False
    assert "DESTINATION_CONFLICT" in result.error_codes


def test_output_parent_is_a_file_rejected(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "parentfile" / "out", vault=tmp_path / "v")
    (tmp_path / "parentfile").write_bytes(b"file-where-a-dir-is-expected")
    result = preflight(plan)
    assert result.ready is False
    assert "DESTINATION_CONFLICT" in result.error_codes


def test_deep_ancestor_is_file_rejected(tmp_path: Path) -> None:
    # A file anywhere in the output ancestor chain (not just the immediate
    # parent) makes the destination hierarchy uncreatable.
    src = _make_source(tmp_path)
    blocker = tmp_path / "block" / "file"
    blocker.parent.mkdir(parents=True)
    blocker.write_bytes(b"file-blocking-deeper-hierarchy")
    plan = build_plan(
        source=src,
        output=tmp_path / "block" / "file" / "sub" / "out",
        vault=tmp_path / "v",
    )
    result = preflight(plan)
    assert result.ready is False
    assert "DESTINATION_CONFLICT" in result.error_codes


def test_vault_ancestor_is_file_rejected(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    blocker = tmp_path / "vblocker"
    blocker.write_bytes(b"file-where-vault-hierarchy-expected")
    plan = build_plan(
        source=src,
        output=tmp_path / "out",
        vault=tmp_path / "vblocker" / "deep" / "dict.sqlite3",
    )
    result = preflight(plan)
    assert result.ready is False
    assert "DESTINATION_CONFLICT" in result.error_codes


def test_existing_vault_file_rejected_reuse_unimplemented(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    vault = tmp_path / "vault" / "dict.sqlite3"
    vault.parent.mkdir(parents=True, exist_ok=True)
    vault.write_bytes(b"opaque-preexisting-vault")
    result = preflight(plan)
    assert result.ready is False
    assert "DESTINATION_CONFLICT" in result.error_codes


def test_vault_target_is_directory_rejected(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vdir" / "dict.sqlite3")
    (tmp_path / "vdir" / "dict.sqlite3").mkdir(parents=True)
    result = preflight(plan)
    assert result.ready is False
    assert "DESTINATION_CONFLICT" in result.error_codes


# ---------------------------------------------------------------------------
# 15. Invalid / tampered policy summary
# ---------------------------------------------------------------------------
def test_tampered_transformation_class_rejected(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    policy = dataclasses.replace(plan.policy, transformation_classes=("BOGUS_ACTION",))
    plan = dataclasses.replace(plan, policy=policy)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "POLICY_INCONSISTENT" in result.error_codes


def test_recovery_enabled_inconsistency_rejected(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    policy = dataclasses.replace(
        plan.policy, transformation_classes=(), recovery_enabled=True,
        vault_strategy=dataclasses.replace(plan.policy, transformation_classes=()).vault_strategy,
    )
    plan = dataclasses.replace(plan, policy=policy)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "POLICY_INCONSISTENT" in result.error_codes


# ---------------------------------------------------------------------------
# 16-17. Unsupported output profile / VFP_INDEXED without backend
# ---------------------------------------------------------------------------
def test_vfp_indexed_without_backend_rejected(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path, policy={"indexes": {"profile": "VFP_INDEXED"}})
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "OUTPUT_PROFILE_UNSUPPORTED" in result.error_codes
    assert "CAPABILITY_MISSING" in result.error_codes


# ---------------------------------------------------------------------------
# 18. Structural CDX flag + missing companion
# ---------------------------------------------------------------------------
def test_structural_cdx_missing_companion_rejected(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _copy_fixture(src, "vfp/structural/indexed_table.dbf")  # DBF without its CDX
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    table = plan.tables[0]
    # The fixture objectively carries the structural-CDX flag without its
    # companion file; fail the test (not the product) if that ever changes.
    assert table.structural_cdx
    assert not table.structural_cdx_companion_present
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "MISSING_STRUCTURAL_INDEX" in result.error_codes


# ---------------------------------------------------------------------------
# 23. Declared relationships whose domain cannot be proven compatible
# ---------------------------------------------------------------------------
def test_relationship_domain_unverifiable_rejected(tmp_path: Path) -> None:
    rel = RelationshipMetadata(
        metadata_schema_version="1.0", provenance="declared",
        relationship_fingerprint="f" * 64, relation_count=3, authoritative=True,
    )
    plan = _build_plan(tmp_path, relationships=rel)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "RELATIONSHIP_DOMAIN_UNVERIFIED" in result.error_codes


# ---------------------------------------------------------------------------
# 24. GLOBAL_TEXT pseudonym capacity — global original, strictest width
# ---------------------------------------------------------------------------
def _tight_c_source(tmp: Path, rel: str, width: int, values: list[str]) -> Path:
    src = tmp / "src"
    _write_table(src / rel / f"{rel}.dbf", [("CODE", "C", width)],
                 [{"CODE": v} for v in values])
    return src


def test_pseudonym_capacity_insufficient_rejected(tmp_path: Path) -> None:
    src = tmp_path / "src"
    values = [chr(ord("A") + i) for i in range(26)] + [str(i) for i in range(10)] + ["\u017b"]
    assert len(set(values)) == 37
    _write_table(src / "tight" / "tight.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in values])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" in result.error_codes


def test_pseudonym_capacity_feasible_at_exact_bound(tmp_path: Path) -> None:
    # Exactly 36 distinct values in a C(1) field: the 36-token width-1 space
    # suffices (a permutation with no self-mapping exists). A per-value token
    # reservation would wrongly report infeasibility here.
    src = tmp_path / "src"
    values = [chr(ord("A") + i) for i in range(26)] + [str(i) for i in range(10)]
    assert len(values) == 36
    _write_table(src / "tight" / "tight.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in values])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes


def test_pseudonym_capacity_35_values_feasible(tmp_path: Path) -> None:
    # 35 distinct C(1) originals: below the exact 36-token bound -> feasible;
    # the occurrence upper bound alone already proves the constraint.
    src = tmp_path / "src"
    values = [chr(ord("A") + i) for i in range(26)] + [str(i) for i in range(9)]
    assert len(set(values)) == 35
    _write_table(src / "tight" / "tight.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in values])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    assert _pf_module()._LAST_CAPACITY_SCAN_STATS is not None
    assert _pf_module()._LAST_CAPACITY_SCAN_STATS["retained_distinct"] == 0


def test_pseudonym_capacity_single_value_c1_feasible(tmp_path: Path) -> None:
    # One original in C(1): feasible — it receives one of the OTHER 35 tokens.
    src = tmp_path / "src"
    _write_table(src / "single" / "single.dbf", [("CODE", "C", 1)], [{"CODE": "A"}])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes


def test_pseudonym_capacity_distinctness_is_exact(tmp_path: Path) -> None:
    # 37 records but only 36 EXACTLY distinct values -> feasible. Distinctness
    # is exact value equality, not positional or digest identity.
    src = tmp_path / "src"
    values = [chr(ord("A") + i) for i in range(26)] + [str(i) for i in range(10)]
    _write_table(src / "tight" / "tight.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in values] + [{"CODE": "A"}])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes


def test_capacity_strictest_width_same_original_c1_c2(tmp_path: Path) -> None:
    # The same 36 originals occur in C(1) AND in C(2). The global domain holds
    # each original ONCE with its ONE strictest width (1), so the exact
    # narrow-domain count is 36 — not 72 — and the domain stays feasible.
    src = tmp_path / "src"
    values = list(_BASE36)
    assert len(values) == 36
    records = [{"CODE": values[i % 36], "WIDE": values[i % 36]} for i in range(40)]
    _write_table(src / "mixed" / "mixed.dbf",
                 [("CODE", "C", 1), ("WIDE", "C", 10)], records)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    stats = _pf_module()._LAST_CAPACITY_SCAN_STATS
    assert stats is not None
    assert stats["retained_distinct"] == 36  # one global original each


def test_capacity_36_narrow_plus_1296_wide_only_is_feasible(tmp_path: Path) -> None:
    # THE strictest-width regression: 36 distinct originals occur in C(1); the
    # same 36 also occur in C(2); 1296 additional originals occur only in C(2).
    # Global distinct originals = 1332. Available tokens up to width 2 =
    # 36 + 36^2 = 1332. The domain is feasible and the 36 narrow originals
    # MUST NOT be counted twice.
    src = tmp_path / "src"
    singles = list(_BASE36)
    pairs = [a + b for a in _BASE36 for b in _BASE36]
    assert len(pairs) == 1296
    _write_table(src / "narrow" / "narrow.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in singles])
    _write_table(src / "wide" / "wide.dbf", [("CODE", "C", 2)],
                 [{"CODE": v} for v in singles] + [{"CODE": p} for p in pairs])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    stats = _pf_module()._LAST_CAPACITY_SCAN_STATS
    assert stats is not None
    # Width 1 was proven by the cheap occurrence bound; width 2 (tight) needed
    # the exact 1332-value proof at the exact token-space boundary.
    assert stats["phase_a_proven_widths"] == 1
    assert stats["tight_widths"] == 1
    assert stats["retained_distinct"] == 1332
    assert stats["outcome"] == "OK"


def test_capacity_same_original_across_tables_counted_once(tmp_path: Path) -> None:
    # The same 36 originals occur in TWO tables (both C(1)): the global domain
    # counts each original exactly once -> feasible. A per-table double count
    # would wrongly report 72 distinct originals.
    src = tmp_path / "src"
    values = list(_BASE36)
    _write_table(src / "alpha" / "alpha.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in values])
    _write_table(src / "beta" / "beta.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in values])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    stats = _pf_module()._LAST_CAPACITY_SCAN_STATS
    assert stats is not None
    assert stats["retained_distinct"] == 36  # not 72


def test_capacity_varchar_trailing_space_values_remain_distinct(tmp_path: Path) -> None:
    # Significant Varchar trailing spaces are part of the exact original:
    # "A" and "A " are DIFFERENT originals. NULL and empty remain excluded.
    src = tmp_path / "src"
    values: list[str | None] = []
    for i in range(1500):
        values.extend(("A", "A "))
    values.extend((None, "", "B"))  # NULL/empty excluded; B is a third original
    _write_varchar_table(src / "vchar" / "vchar.dbf", values)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    stats = _pf_module()._LAST_CAPACITY_SCAN_STATS
    assert stats is not None
    # Exactly 3 distinct originals survived: "A", "A " (trailing space exact)
    # and "B" — the 1500 duplicates and the NULL/empty values did not.
    assert stats["retained_distinct"] == 3


def test_capacity_duplicate_after_tracker_saturation_not_false_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With a small exact-tracker ceiling, repeated duplicates of already-known
    # originals must NOT falsely report the ceiling as exceeded.
    mod = _pf_module()
    monkeypatch.setattr(mod, "_MAX_EXACT_VALUES", 8)
    src = tmp_path / "src"
    values = ["A", "B", "C", "D", "E"]
    records = [{"CODE": values[i % 5]} for i in range(40)]
    _write_table(src / "dup" / "dup.dbf", [("CODE", "C", 1)], records)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "PSEUDONYM_CAPACITY_UNPROVEN" not in result.error_codes
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    stats = mod._LAST_CAPACITY_SCAN_STATS
    assert stats is not None
    assert stats["retained_distinct"] == 5
    assert stats["exact_ceiling"] == 8


def test_capacity_analysis_memory_ceiling_fails_closed_unproven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the exact proof would need more than the configured ceiling, the
    # analysis fails closed with PSEUDONYM_CAPACITY_UNPROVEN — it must NOT
    # pretend mathematical insufficiency and must NOT exceed the ceiling.
    mod = _pf_module()
    monkeypatch.setattr(mod, "_MAX_EXACT_VALUES", 8)
    src = tmp_path / "src"
    values = [chr(33 + i) for i in range(40)]
    assert len(set(values)) == 40
    _write_table(src / "wide_tight" / "wide_tight.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in values])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PSEUDONYM_CAPACITY_UNPROVEN" in result.error_codes
    # Never claim insufficiency without the exact proof.
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    stats = mod._LAST_CAPACITY_SCAN_STATS
    assert stats is not None
    assert stats["retained_distinct"] == 8  # the ceiling was actually enforced
    assert stats["outcome"] == "UNPROVEN"


def test_capacity_scan_records_failure_is_wrapped_privately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A raw dependency failure mid-record-scan must surface as the structured
    # DBFBRIDGE_FAILURE (never as the raw exception) and must not leak the
    # dependency message, paths or values. The source is deliberately tight so
    # the exact-tracking scan actually consumes the dependency generator.
    src = tmp_path / "src"
    _write_table(src / "tight" / "tight.dbf", [("CODE", "C", 1)],
                 [{"CODE": v} for v in list(_BASE36) + ["\u017b"]])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")

    class _RawBoom(Exception):
        code = "DBF_RAW_INTERNAL"

        def __init__(self) -> None:
            super().__init__("CANARY_SECRET /abs/path/value ALPHA BETA GAMMA")

    def _boom(*_args: Any, **_kwargs: Any):
        raise _RawBoom()
        yield  # pragma: no cover - generator marker

    monkeypatch.setattr(dbfbridge, "iter_records", _boom)
    with pytest.raises(DBFBridgeError) as excinfo:
        preflight(plan)
    error = excinfo.value
    assert error.code is ErrorCode.DBFBRIDGE_FAILURE
    assert error.dependency_code == "DBF_RAW_INTERNAL"  # machine code preserved
    assert error.context.detail_code == "capacity_iter_records_failed"
    blob = json.dumps(error.to_dict(), ensure_ascii=False)
    assert "CANARY_SECRET" not in blob
    assert "ALPHA" not in blob
    assert "/abs/path" not in blob


def test_capacity_scan_read_schema_failure_is_wrapped_privately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A raw dependency failure during the capacity schema collection must
    # surface as the structured DBFBRIDGE_FAILURE with its machine code
    # preserved and no message/path/value leakage.
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")

    class _SchemaBoom(Exception):
        code = "SCHEMA_RAW_INTERNAL"

        def __init__(self) -> None:
            super().__init__("SCHEMA_CANARY /abs/schema/path")

    def _boom(*_args: Any, **_kwargs: Any):
        raise _SchemaBoom()

    monkeypatch.setattr(dbfbridge, "read_schema", _boom)
    with pytest.raises(DBFBridgeError) as excinfo:
        preflight(plan)
    error = excinfo.value
    assert error.code is ErrorCode.DBFBRIDGE_FAILURE
    assert error.dependency_code == "SCHEMA_RAW_INTERNAL"
    assert error.context.detail_code == "capacity_read_schema_failed"
    blob = json.dumps(error.to_dict(), ensure_ascii=False)
    assert "SCHEMA_CANARY" not in blob
    assert "/abs/schema" not in blob


# ---------------------------------------------------------------------------
# 25-26. Missing direct read/write capability (symbol and dependency truth)
# ---------------------------------------------------------------------------
def test_missing_direct_read_capability_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_caps(monkeypatch, _caps(direct_read=False))
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "CAPABILITY_MISSING" in result.error_codes


def test_missing_direct_write_capability_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_caps(monkeypatch, _caps(direct_write=False))
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "CAPABILITY_MISSING" in result.error_codes


def test_write_dependency_missing_detected_by_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Truthful capability: the write_table symbol alone is not enough; the
    # dbfbridge[write] runtime dependency (dbf) must be discoverable.
    monkeypatch.setattr(_capabilities_mod, "_write_dependency_available", lambda: False)
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.capabilities.direct_write is False
    assert result.ready is False
    assert "CAPABILITY_MISSING" in result.error_codes


def test_read_dependency_missing_detected_by_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_capabilities_mod, "_read_dependency_available", lambda: False)
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.capabilities.direct_read is False
    assert result.ready is False
    assert "CAPABILITY_MISSING" in result.error_codes


def test_missing_iter_records_symbol_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # iter_records is REQUIRED for the GLOBAL_TEXT capacity scan: without it,
    # direct read is unavailable, preflight reports CAPABILITY_MISSING and the
    # capacity scan is never entered.
    mod = _pf_module()
    plan = _build_plan(tmp_path)
    monkeypatch.setattr(mod, "_LAST_CAPACITY_SCAN_STATS", None)
    monkeypatch.setattr(dbfbridge, "iter_records", None)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.capabilities.direct_read is False
    assert result.ready is False
    assert "CAPABILITY_MISSING" in result.error_codes
    assert mod._LAST_CAPACITY_SCAN_STATS is None  # scan never entered


def test_missing_read_schema_symbol_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # read_schema is REQUIRED for schema/companion facts and the capacity
    # domain: without it, direct read is unavailable.
    mod = _pf_module()
    plan = _build_plan(tmp_path)
    monkeypatch.setattr(mod, "_LAST_CAPACITY_SCAN_STATS", None)
    monkeypatch.setattr(dbfbridge, "read_schema", None)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.capabilities.direct_read is False
    assert result.ready is False
    assert "CAPABILITY_MISSING" in result.error_codes
    assert mod._LAST_CAPACITY_SCAN_STATS is None  # scan never entered


def test_missing_direct_read_symbol_does_not_enter_capacity_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Even with every other precondition satisfied, a missing iter_records
    # capability yields CAPABILITY_MISSING rather than any capacity finding.
    mod = _pf_module()
    plan = _build_plan(tmp_path)
    monkeypatch.setattr(mod, "_LAST_CAPACITY_SCAN_STATS", None)
    monkeypatch.setattr(dbfbridge, "iter_records", None)
    result = preflight(plan)
    assert result.ready is False
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    assert "PSEUDONYM_CAPACITY_UNPROVEN" not in result.error_codes
    assert "CAPABILITY_MISSING" in result.error_codes
    assert mod._LAST_CAPACITY_SCAN_STATS is None


# ---------------------------------------------------------------------------
# 27-28. Storage-space risk (source-scaled reserves, boundary-exact)
# ---------------------------------------------------------------------------
def test_vault_reserve_grows_with_source_footprint() -> None:
    mod = _pf_module()
    assert mod._vault_reserve_bytes(0) == mod._VAULT_FIXED_RESERVE_BYTES
    assert mod._vault_reserve_bytes(1) > mod._vault_reserve_bytes(0)
    assert mod._vault_reserve_bytes(10**6) < mod._vault_reserve_bytes(10**9)
    assert (
        mod._vault_reserve_bytes(5)
        == mod._VAULT_SOURCE_FACTOR * 5 + mod._VAULT_FIXED_RESERVE_BYTES
    )


def test_insufficient_disk_space_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_pf_module(), "_disk_usage", lambda _p: (1000, 900, 0))
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "STORAGE_SPACE_INSUFFICIENT" in result.error_codes


def test_unavailable_storage_estimate_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(_p: Path) -> tuple[int, int, int]:
        raise OSError("storage information unavailable")

    monkeypatch.setattr(_pf_module(), "_disk_usage", _boom)
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes


def test_storage_model_counts_staging_and_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Free space that covers a naive single-copy estimate (footprint plus one
    # writer/spool reserve) but NOT the real peak (fresh output + staged copy
    # + the source-scaled vault reserve) must be rejected.
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    footprint = _source_dbf_footprint(src)
    required_output = footprint * mod._STAGING_FACTOR + mod._WRITER_SPOOL_RESERVE_BYTES
    required_vault = mod._vault_reserve_bytes(footprint)
    required = required_output + required_vault
    free = footprint + mod._WRITER_SPOOL_RESERVE_BYTES + 1
    assert required > free
    monkeypatch.setattr(
        mod, "_disk_usage", lambda _p: (10**15, 10**15 - free, free)
    )
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "STORAGE_SPACE_INSUFFICIENT" in result.error_codes


def test_same_filesystem_combined_reserve_exact_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Output and vault share one filesystem: the peak reserve is the combined
    # output + vault exposure; the exact boundary must be ACCEPTED.
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    footprint = _source_dbf_footprint(src)
    required_output = footprint * mod._STAGING_FACTOR + mod._WRITER_SPOOL_RESERVE_BYTES
    required_vault = mod._vault_reserve_bytes(footprint)
    free = required_output + required_vault
    monkeypatch.setattr(mod, "_disk_usage", lambda _p: (10**15, 0, free))
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert result.error_codes == ()


def test_same_filesystem_combined_reserve_one_byte_below_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    footprint = _source_dbf_footprint(src)
    free = (
        footprint * mod._STAGING_FACTOR
        + mod._WRITER_SPOOL_RESERVE_BYTES
        + mod._vault_reserve_bytes(footprint)
        - 1
    )
    monkeypatch.setattr(mod, "_disk_usage", lambda _p: (10**15, 0, free))
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "STORAGE_SPACE_INSUFFICIENT" in result.error_codes


def test_separate_filesystem_vault_reserve_scales(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On a DIFFERENT filesystem the vault must independently require the
    # source-scaled reserve: a multi-megabyte dataset cannot pass merely
    # because the vault filesystem has slightly more than 1 MiB free.
    mod = _pf_module()
    src = tmp_path / "src"
    # A realistically large (multi-record) synthetic table ~2.4 MB.
    wide = "W" * 40
    _write_table(src / "bulk" / "bulk.dbf", [("CODE", "C", 40)],
                 [{"CODE": wide} for _i in range(60000)])
    footprint = _source_dbf_footprint(src)
    required_vault = mod._vault_reserve_bytes(footprint)
    # The pre-repair 1 MiB constant reserve would have (wrongly) accepted this.
    assert required_vault > 2 * 1024 * 1024
    vault_dir = tmp_path / "vdir"
    vault_dir.mkdir()  # separate-filesystem ancestor for the dev seam
    plan = build_plan(source=src, output=tmp_path / "out", vault=vault_dir / "dict.sqlite3")

    def _fake_dev(path: Path) -> int:
        return 2 if path == vault_dir else 1

    def _usage(path: Path) -> tuple[int, int, int]:
        if path.name.startswith("out"):
            return (10**15, 0, 10**15)
        return (10**7, 0, 2 * 1024 * 1024)

    monkeypatch.setattr(mod, "_stat_dev", _fake_dev)
    monkeypatch.setattr(mod, "_disk_usage", _usage)
    result = _preflight_no_side_effects(plan, tmp_path, preexisting=("vdir",))
    assert result.ready is False
    assert "STORAGE_SPACE_INSUFFICIENT" in result.error_codes


def test_separate_filesystem_vault_boundary_exact_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _pf_module()
    src = _make_source(tmp_path)
    footprint = _source_dbf_footprint(src)
    required_vault = mod._vault_reserve_bytes(footprint)
    vault_dir = tmp_path / "vdir"
    vault_dir.mkdir()
    plan = build_plan(source=src, output=tmp_path / "out", vault=vault_dir / "dict.sqlite3")

    monkeypatch.setattr(mod, "_stat_dev", lambda path: 2 if path == vault_dir else 1)
    monkeypatch.setattr(
        mod, "_disk_usage",
        lambda path: (10**7, 0, required_vault)
        if not path.name.startswith("out")
        else (10**15, 0, 10**15),
    )
    result = _preflight_no_side_effects(plan, tmp_path, preexisting=("vdir",))
    assert result.ready is True
    assert result.error_codes == ()


def test_separate_filesystem_vault_boundary_one_byte_below_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _pf_module()
    src = _make_source(tmp_path)
    footprint = _source_dbf_footprint(src)
    required_vault = mod._vault_reserve_bytes(footprint) - 1
    vault_dir = tmp_path / "vdir"
    vault_dir.mkdir()
    plan = build_plan(source=src, output=tmp_path / "out", vault=vault_dir / "dict.sqlite3")

    monkeypatch.setattr(mod, "_stat_dev", lambda path: 2 if path == vault_dir else 1)
    monkeypatch.setattr(
        mod, "_disk_usage",
        lambda path: (10**7, 0, required_vault)
        if not path.name.startswith("out")
        else (10**15, 0, 10**15),
    )
    result = _preflight_no_side_effects(plan, tmp_path, preexisting=("vdir",))
    assert result.ready is False
    assert "STORAGE_SPACE_INSUFFICIENT" in result.error_codes


def test_storage_ancestor_stat_failure_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _pf_module()

    def _boom(_p: Path) -> int:
        raise PermissionError(13, "filesystem identity unavailable")

    monkeypatch.setattr(mod, "_stat_dev", _boom)
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes


# ---------------------------------------------------------------------------
# 29. Filesystem inspection errors: fail closed, privacy-safe, no side effects
# ---------------------------------------------------------------------------
def _assert_no_private_paths(result: PreflightResult, tmp_path: Path) -> None:
    blob = json.dumps(result.to_dict(), ensure_ascii=False)
    assert str(tmp_path) not in blob
    assert "C:\\" not in blob
    assert "D:\\" not in blob
    assert "denied" not in blob.lower()


def test_output_iterdir_error_fails_closed_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "stale.txt").write_bytes(b"stale")

    def _denied(_p: Path) -> list[Path]:
        raise PermissionError(13, f"secrets under {tmp_path}")

    monkeypatch.setattr(mod, "_iterdir", _denied)
    result = _preflight_no_side_effects(plan, tmp_path, preexisting=("out",))
    assert result.ready is False
    assert "PATH_INSPECTION_UNAVAILABLE" in result.error_codes
    assert "DESTINATION_CONFLICT" not in result.error_codes
    _assert_no_private_paths(result, tmp_path)


def test_ancestor_inspection_error_fails_closed_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(
        source=src, output=tmp_path / "block" / "out", vault=tmp_path / "v"
    )
    real_probe = mod._probe

    def _denied(p: Path) -> str:
        if p == tmp_path / "block":  # first (missing) output ancestor
            raise PermissionError(13, f"ancestor secrets under {tmp_path}")
        return real_probe(p)

    monkeypatch.setattr(mod, "_probe", _denied)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PATH_INSPECTION_UNAVAILABLE" in result.error_codes
    assert "DESTINATION_CONFLICT" not in result.error_codes
    _assert_no_private_paths(result, tmp_path)


def test_alias_resolver_error_fails_closed_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")

    def _denied(_p: Path) -> Path:
        raise OSError(13, f"resolver secrets under {tmp_path}")

    monkeypatch.setattr(mod, "_resolve_path", _denied)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PATH_INSPECTION_UNAVAILABLE" in result.error_codes
    assert "PATH_OVERLAP" not in result.error_codes
    _assert_no_private_paths(result, tmp_path)


# ---------------------------------------------------------------------------
# 29b. Python 3.12+/3.14-safe stat probing: an inaccessible path is NEVER
#      treated as missing (pathlib predicates suppress OSError there)
# ---------------------------------------------------------------------------
def test_probe_path_classifies_raw_stat_kinds(tmp_path: Path) -> None:
    import dbf_anonymizer.discovery as discovery

    directory = tmp_path / "d"
    directory.mkdir()
    plain_file = tmp_path / "f"
    plain_file.write_bytes(b"synthetic")
    assert discovery.probe_path(directory) == discovery._PATH_DIRECTORY
    assert discovery.probe_path(plain_file) == discovery._PATH_FILE
    assert discovery.probe_path(tmp_path / "gone") == discovery._PATH_MISSING
    # A component that is not a directory blocks the hierarchy: on POSIX this
    # is NotADirectoryError (BLOCKED); on Windows os.stat reports FileNotFoundError
    # (MISSING) — never DIRECTORY in either case.
    assert discovery.probe_path(plain_file / "sub") != discovery._PATH_DIRECTORY


def _patch_probe_denied_for(
    monkeypatch: pytest.MonkeyPatch, mod: Any, denied_path: Path
) -> None:
    real_probe = mod._probe

    def _denied(p: Path) -> str:
        if p == denied_path:
            raise PermissionError(13, f"probe secrets under {denied_path}")
        return real_probe(p)

    monkeypatch.setattr(mod, "_probe", _denied)


def test_output_stat_permission_error_fails_closed_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An inaccessible output target is NEVER an innocent missing target:
    # the stat probe propagates the failure and preflight fails closed.
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    _patch_probe_denied_for(monkeypatch, mod, tmp_path / "out")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PATH_INSPECTION_UNAVAILABLE" in result.error_codes
    assert "DESTINATION_CONFLICT" not in result.error_codes
    _assert_no_private_paths(result, tmp_path)


def test_vault_stat_permission_error_fails_closed_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An inaccessible vault target cannot be proven acceptable: fail closed.
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "vault" / "dict.sqlite3")
    _patch_probe_denied_for(monkeypatch, mod, tmp_path / "vault" / "dict.sqlite3")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "PATH_INSPECTION_UNAVAILABLE" in result.error_codes
    assert "DESTINATION_CONFLICT" not in result.error_codes
    _assert_no_private_paths(result, tmp_path)


def test_storage_ancestor_stat_permission_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The nearest-existing-ancestor walk for the storage estimate uses the
    # same stat probe: an inaccessible ancestor must NOT be walked past as if
    # it did not exist; the estimate degrades to STORAGE_ESTIMATE_UNAVAILABLE.
    mod = _pf_module()
    src = _make_source(tmp_path)
    vault_dir = tmp_path / "vdir"
    vault_dir.mkdir()  # pre-existing (blocked) vault ancestor
    plan = build_plan(source=src, output=tmp_path / "out", vault=vault_dir / "dict.sqlite3")
    _patch_probe_denied_for(monkeypatch, mod, vault_dir)
    result = _preflight_no_side_effects(plan, tmp_path, preexisting=("vdir",))
    assert result.ready is False
    # The device comparison cannot be made defensibly without the ancestor.
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes
    _assert_no_private_paths(result, tmp_path)


def test_deep_missing_ancestor_chain_is_not_a_false_conflict(tmp_path: Path) -> None:
    # Deeply missing ancestor chains must still be created-able: missing
    # components are walked past, never misread as conflicts.
    src = _make_source(tmp_path)
    plan = build_plan(
        source=src,
        output=tmp_path / "deep" / "l1" / "l2" / "out",
        vault=tmp_path / "v" / "d" / "dict.sqlite3",
    )
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "DESTINATION_CONFLICT" not in result.error_codes
    assert "PATH_INSPECTION_UNAVAILABLE" not in result.error_codes


def test_source_root_stat_permission_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An inaccessible source root is not an innocent absence: the stat probe
    # reports SOURCE_UNAVAILABLE (and the storage estimate degrades).
    mod = _pf_module()
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    monkeypatch.setattr(mod, "_LAST_CAPACITY_SCAN_STATS", None)
    _patch_probe_denied_for(monkeypatch, mod, src)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "SOURCE_UNAVAILABLE" in result.error_codes
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes
    _assert_no_private_paths(result, tmp_path)
    assert mod._LAST_CAPACITY_SCAN_STATS is None  # scan never entered


def test_strict_discovery_root_inspection_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Strict discovery itself must not trust Python 3.12+/3.14 predicate
    # suppression: an unreadable source root surfaces as a failure.
    import dbf_anonymizer.discovery as discovery

    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")

    def _denied(_p: Path) -> str:
        raise PermissionError(13, f"root secrets under {tmp_path}")

    monkeypatch.setattr(discovery, "probe_path", _denied)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "SOURCE_UNAVAILABLE" in result.error_codes
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes
    _assert_no_private_paths(result, tmp_path)


def test_strict_enumeration_rejects_missing_and_non_directory_roots(
    tmp_path: Path,
) -> None:
    # Real-filesystem proof (no monkeypatching): strict enumeration must
    # never turn a missing or non-directory source root into an innocent
    # empty enumeration.
    import dbf_anonymizer.discovery as discovery

    plain_file = tmp_path / "not_a_dir"
    plain_file.write_bytes(b"synthetic")

    with pytest.raises(OSError):
        discovery.enumerate_in_scope_paths(tmp_path / "gone", strict=True)
    assert discovery.enumerate_in_scope_paths(tmp_path / "gone") == {}
    with pytest.raises(OSError):
        discovery.enumerate_in_scope_paths(plain_file, strict=True)
    assert discovery.enumerate_in_scope_paths(plain_file) == {}


def test_preflight_never_uses_314_suppressing_pathlib_predicates(
    tmp_path: Path,
) -> None:
    # REGRESSION GUARD: production preflight security decisions must not call
    # Path.exists()/is_file()/is_dir() at all — on Python 3.12+ those
    # predicates suppress OSError/PermissionError and would report an
    # inaccessible path as missing (fail-open). A normal preflight must still
    # complete successfully with every pathlib predicate poisoned.
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    before = _tree_snapshot(tmp_path)

    real_predicates = (Path.exists, Path.is_file, Path.is_dir)

    def _forbidden(name: str) -> Any:
        def _poison(_self: Any, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError(f"Path.{name} used inside production preflight")

        return _forbidden

    Path.exists = _forbidden("exists")  # type: ignore[method-assign]
    Path.is_file = _forbidden("is_file")  # type: ignore[method-assign]
    Path.is_dir = _forbidden("is_dir")  # type: ignore[method-assign]
    try:
        result = preflight(plan)
        assert result.ready is True
        assert result.error_codes == ()
        assert "PREFLIGHT_EVALUATED" in result.check_codes
    finally:
        (Path.exists, Path.is_file, Path.is_dir) = real_predicates

    after = _tree_snapshot(tmp_path)
    created = set(after) - set(before)
    modified = {r for r in before if before[r] != after.get(r)}
    assert not created, f"preflight created files: {sorted(created)}"
    assert not modified, f"preflight modified files: {sorted(modified)}"
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "v").exists()


def test_source_traversal_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # STRICT preflight traversal: an unreadable source directory must never be
    # treated as a complete enumeration; it fails closed as SOURCE_UNAVAILABLE
    # (and the storage estimate becomes unavailable without a footprint).
    import dbf_anonymizer.discovery as discovery

    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    real_walk = os.walk

    def _broken_walk(top: Any, onerror: Any = None, followlinks: bool = False) -> Any:
        if str(top) == str(src):
            if onerror is not None:
                onerror(OSError(13, f"traversal secrets under {src}"))
            return iter(())
        return real_walk(top, onerror=onerror, followlinks=followlinks)

    monkeypatch.setattr(discovery.os, "walk", _broken_walk)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "SOURCE_UNAVAILABLE" in result.error_codes
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes
    _assert_no_private_paths(result, tmp_path)


def test_source_stat_failure_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A source DBF that cannot be statted/read makes the fingerprint (and the
    # footprint) indefensible: fail closed as SOURCE_UNAVAILABLE plus
    # STORAGE_ESTIMATE_UNAVAILABLE, with no capacity scan on unverified state.
    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    mod = _pf_module()
    monkeypatch.setattr(mod, "_LAST_CAPACITY_SCAN_STATS", None)
    real_stat = Path.stat

    def _denied_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.suffix.lower() == ".dbf" and str(self).startswith(str(src)):
            raise PermissionError(13, f"stat secrets under {src}")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _denied_stat)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "SOURCE_UNAVAILABLE" in result.error_codes
    assert "STORAGE_ESTIMATE_UNAVAILABLE" in result.error_codes
    _assert_no_private_paths(result, tmp_path)
    assert mod._LAST_CAPACITY_SCAN_STATS is None  # scan never entered


def test_source_read_failure_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A source file that cannot be READ during strict fingerprinting fails
    # closed (an incomplete fingerprint is never treated as complete).
    import dbf_anonymizer.discovery as discovery

    src = _make_source(tmp_path)
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    mod = _pf_module()
    monkeypatch.setattr(mod, "_LAST_CAPACITY_SCAN_STATS", None)

    def _denied_hash(_p: Path) -> str:
        raise OSError(13, f"read secrets under {src}")

    monkeypatch.setattr(discovery, "_file_sha256", _denied_hash)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "SOURCE_UNAVAILABLE" in result.error_codes
    _assert_no_private_paths(result, tmp_path)
    assert mod._LAST_CAPACITY_SCAN_STATS is None  # scan never entered


def test_strict_discovery_enumeration_raises_on_traversal_error(
    tmp_path: Path,
) -> None:
    # Direct unit proof of the strict flag contract in discovery.
    import dbf_anonymizer.discovery as discovery

    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "table.dbf").write_bytes(b"placeholder")

    def _broken_walk(top: Any, onerror: Any = None, followlinks: bool = False) -> Any:
        if onerror is not None:
            onerror(OSError(13, "denied"))
        return iter(())

    real_walk = discovery.os.walk
    try:
        discovery.os.walk = _broken_walk  # type: ignore[assignment]
        with pytest.raises(OSError):
            discovery.enumerate_in_scope_paths(tmp_path, strict=True)
        # Non-strict planning behaviour is unchanged (errors are skipped).
        assert discovery.enumerate_in_scope_paths(tmp_path) == {}
        with pytest.raises(OSError):
            discovery.collect_fingerprint_entries(tmp_path, strict=True)
        assert discovery.collect_fingerprint_entries(tmp_path) == ()
    finally:
        discovery.os.walk = real_walk  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# 30. Multiple simultaneous findings aggregate deterministically
# ---------------------------------------------------------------------------
def test_multiple_findings_aggregate_deterministically(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _copy_fixture(src, "malformed/missing_memo_companion.dbf")
    plan = build_plan(source=src, output=tmp_path / "src", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    # Both a path overlap and a missing memo companion are present and unique.
    assert "PATH_OVERLAP" in result.error_codes
    assert "MISSING_MEMO_COMPANION" in result.error_codes
    assert len(result.error_codes) == len(set(result.error_codes))
    assert result.error_codes == tuple(sorted(result.error_codes))


# ---------------------------------------------------------------------------
# 31. Repeatability / determinism
# ---------------------------------------------------------------------------
def test_repeated_preflight_is_exactly_equal(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    first = preflight(plan)
    second = preflight(plan)
    assert first.to_dict() == second.to_dict()
    assert first == second


# ---------------------------------------------------------------------------
# Positive / warning cases
# ---------------------------------------------------------------------------
def test_clean_data_only_plan_is_ready(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert result.error_codes == ()
    assert "DATA_ONLY_STANDALONE" in result.check_codes
    assert "PREFLIGHT_EVALUATED" in result.check_codes
    assert result.capabilities.direct_read is True
    assert result.capabilities.direct_write is True
    assert result.capabilities.vfp_index_backend is False


def test_structural_cdx_data_only_warns_not_rejects(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _copy_fixture(src, "vfp/structural/indexed_table.dbf")
    _copy_fixture(src, "vfp/structural/indexed_table.cdx")
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "STRUCTURAL_CDX_DATA_ONLY" in result.warning_codes
    assert result.error_codes == ()


def test_standalone_idx_data_only_warns_without_ownership(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _copy_fixture(src, "vfp/idx/standalone_idx_table.dbf")
    _copy_fixture(src, "vfp/idx/code_idx.idx")
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "STANDALONE_IDX_DATA_ONLY" in result.warning_codes
    serialized = json.dumps(plan.to_dict(), ensure_ascii=False)
    # No TablePlan carries an inferred standalone-IDX ownership relation.
    assert "code_idx" not in serialized
    assert result.error_codes == ()


def test_dbc_bound_data_only_warns_not_rejects(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _copy_fixture(src, "vfp/dbc/dbc_bound_table.dbf")
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "DBC_BOUND_REDUCED" in result.warning_codes
    assert result.error_codes == ()


def test_nullflags_system_field_does_not_reject(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _copy_fixture(src, "nullable/nullable_varchar.dbf")
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert plan.tables[0].system_field_count == 1
    assert plan.tables[0].unsafe_field_count == 0
    assert plan.tables[0].unsupported_field_count == 0
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is True
    assert "UNSAFE_FIELD" not in result.error_codes
    assert "UNSUPPORTED_FIELD" not in result.error_codes


# ---------------------------------------------------------------------------
# Privacy / redaction (canary) and no absolute paths
# ---------------------------------------------------------------------------
def test_result_contains_no_source_values_or_paths(tmp_path: Path) -> None:
    src = tmp_path / "src"
    canary = "CANARY_XYZZY_DO_NOT_LEAK_9F8E7D"
    _write_table(src / "canary" / "canary.dbf", [("SECRET", "C", 40)],
                 [{"SECRET": canary}])
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = preflight(plan)
    blob = json.dumps(result.to_dict(), ensure_ascii=False)
    assert canary not in blob
    assert str(tmp_path) not in blob
    assert "C:\\" not in blob
    assert "D:\\" not in blob
    assert not str(src).lower().replace("\\", "/") in blob


def test_preflight_requires_a_plan() -> None:
    with pytest.raises(TypeError):
        preflight(object())  # type: ignore[arg-type]


def test_preflight_exposed_at_root() -> None:
    import dbf_anonymizer

    assert hasattr(dbf_anonymizer, "preflight")
    assert "preflight" in dbf_anonymizer.__all__
    assert callable(dbf_anonymizer.preflight)