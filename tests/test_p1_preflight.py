"""REQ-P1-006 — deterministic read-only, side-effect-free preflight evidence.

This suite proves the stable negative-fixture matrix (aggregated ``ready=False``
findings), the truthful positive/warning cases, deterministic repeatability,
privacy/redaction, and — for every rejection — zero created output/vault state
and byte-identical source.

Only approved synthetic fixtures (``tests/fixtures/p0/**``) and disposable
synthetic data created under ``tmp_path`` via the public ``dbfbridge`` API are
used. No production data is accessed.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import struct
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

import dbfbridge

import dbf_anonymizer._capability as _capabilities_mod
from dbf_anonymizer import build_plan, preflight
from dbf_anonymizer.errors import DBFBridgeError, ErrorCode
from dbf_anonymizer.models import Capabilities, Plan, PreflightResult, RelationshipMetadata

import dbf_anonymizer.preflight  # ensure module loaded
from dbf_anonymizer import preflight as _preflight_mod  # noqa: F401

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "p0"


def _pf_module():
    """Return the preflight module object (reliably, despite name shadowing)."""
    return sys.modules["dbf_anonymizer.preflight"]


# ---------------------------------------------------------------------------
# Synthetic data helpers (public dbfbridge only)
# ---------------------------------------------------------------------------
def _field(name: str, dbf_type: str, length: int) -> dbfbridge.FieldInfo:
    return dbfbridge.FieldInfo(
        ordinal=0, name=name, dbf_type=dbf_type, length=length,
        decimal_count=0, address=0, flags=0, index_field_flag=0,
        autoincrement_next_value=0, autoincrement_step=1,
        is_memo=False, is_binary=False, supported=True, dbversion_byte=0x30,
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
    plan: Plan, tmp: Path,
) -> PreflightResult:
    before = _tree_snapshot(tmp)
    result = preflight(plan)
    after = _tree_snapshot(tmp)
    created = set(after) - set(before)
    modified = {r for r in before if before[r] != after.get(r)}
    assert not created, f"preflight created files: {sorted(created)}"
    assert not modified, f"preflight modified files: {sorted(modified)}"
    assert not (tmp / "out").exists(), "output directory was created"
    assert not (tmp / "vault").exists(), "vault directory was created"
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
# 10-11. Unsupported / unsafe (binary/NOCPTRANS) user fields
# ---------------------------------------------------------------------------
# The public dbfbridge writer intentionally refuses Q (Varbinary), W (Blob)
# and binary/NOCPTRANS C/V fields, so these conditions cannot be produced via
# ``write_table``. They are produced by deterministic synthetic DBF byte
# layouts (disposable, under tmp_path) whose field descriptors objectively
# carry the condition — no Plan tampering, no fixture modification.
def _raw_dbf(
    path: Path,
    fields: list[tuple[str, str, int, int]],
    records: list[bytes],
) -> None:
    """Deterministically build a synthetic VFP (0x30) DBF file.

    *fields* are (name, type, length, flags) where flags is the descriptor
    flag byte (0x01 system, 0x02 nullable, 0x04 binary/NOCPTRANS).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    header_len = 32 + 32 * len(fields) + 1 + 263  # + VFP backlink extension
    rec_len = 1 + sum(length for _n, _t, length, _f in fields)
    header = bytearray(32)
    header[0] = 0x03
    header[1] = 0x30
    header[2] = 0x26  # 2026, BCD
    header[3] = 0x09
    header[4] = 0x12
    struct.pack_into("<I", header, 4, len(records))
    struct.pack_into("<H", header, 8, header_len)
    struct.pack_into("<H", header, 10, rec_len)
    header[29] = 0xC8  # cp1250
    descriptors = bytearray()
    for name, ftype, length, flags in fields:
        d = bytearray(32)
        name_bytes = name.encode("ascii")
        d[0:11] = name_bytes + b"\x00" * (11 - len(name_bytes))
        d[11] = ord(ftype)
        d[16] = length
        d[18] = flags
        descriptors += d
    body = bytes(header) + bytes(descriptors) + b"\x0d" + bytes(263)
    record_bytes = b"".join(b" " + data for data in records)
    path.write_bytes(body + record_bytes + b"\x1a")


def test_unsupported_field_rejected(tmp_path: Path) -> None:
    src = tmp_path / "src"
    # A Q (Varbinary) field is reader-unsupported; the table must also carry
    # the VFP _NullFlags bitmap column the format requires for V/Q fields.
    _raw_dbf(
        src / "varbin" / "varbin.dbf",
        [("NAME", "C", 10, 0), ("VARBIN", "Q", 16, 0), ("_NULLFLAGS", "0", 1, 0x01)],
        [b"alpha" + b" " * 5 + bytes(range(16)) + b"\x00"],
    )
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert plan.tables[0].unsupported_field_count >= 1
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "UNSUPPORTED_FIELD" in result.error_codes


def test_unsafe_nocptrans_binary_field_rejected(tmp_path: Path) -> None:
    src = tmp_path / "src"
    # A Character field carrying the 0x04 (binary/NOCPTRANS) descriptor bit
    # is unsafe for the global-text domain.
    _raw_dbf(
        src / "binchar" / "binchar.dbf",
        [("BCHAR", "C", 8, 0x04)],
        [bytes(range(8))],
    )
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    assert plan.tables[0].unsafe_field_count >= 1
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
# 24. Deliberately insufficient GLOBAL_TEXT pseudonym capacity
# ---------------------------------------------------------------------------
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


def test_capacity_scan_records_failure_is_wrapped_privately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A raw dependency failure mid-record-scan must surface as the structured
    # DBFBRIDGE_FAILURE (never as the raw exception) and must not leak the
    # dependency message, paths or values.
    src = _make_source(tmp_path)
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
    assert error.context.detail_code == "capacity_iter_records_failed"
    blob = json.dumps(error.to_dict(), ensure_ascii=False)
    assert "CANARY_SECRET" not in blob
    assert "ALPHA" not in blob
    assert "/abs/path" not in blob


# ---------------------------------------------------------------------------
# 25-26. Missing direct read/write capability
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


# ---------------------------------------------------------------------------
# 27-28. Storage-space risk
# ---------------------------------------------------------------------------
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
    # Free space that covers the bare footprint (plus the vault reserve) but
    # NOT the fresh output + one staged copy + writer/spool reserve must be
    # rejected: the model is not allowed to under-count peak exposure.
    mod = _pf_module()
    src = _make_source(tmp_path)
    footprint = sum(p.stat().st_size for p in src.rglob("*") if p.is_file())
    free = footprint + mod._VAULT_RESERVE_BYTES + 1
    required = (
        footprint * mod._STAGING_FACTOR
        + mod._WRITER_SPOOL_RESERVE_BYTES
        + mod._VAULT_RESERVE_BYTES
    )
    assert required > free
    monkeypatch.setattr(
        mod, "_disk_usage", lambda _p: (10**15, 10**15 - free, free)
    )
    plan = build_plan(source=src, output=tmp_path / "out", vault=tmp_path / "v")
    result = _preflight_no_side_effects(plan, tmp_path)
    assert result.ready is False
    assert "STORAGE_SPACE_INSUFFICIENT" in result.error_codes


# ---------------------------------------------------------------------------
# 29. Multiple simultaneous findings aggregate deterministically
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
# 30. Repeatability / determinism
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
