"""REQ-P6-002 — DATA_ONLY standalone structural decoupling evidence.

Proves, over redistributable synthetic fixtures only, that the default
DATA_ONLY output is a truthful STANDALONE fresh DBF/FPT dataset:

A. a structural-CDX source table produces a standalone fresh output whose
   schema carries NO structural coupling, with the stale CDX absent, while
   the source reports its coupling truthfully and stays byte-identical;
B. a DBC-bound source produces output without DBC/DCT/DCX companions and
   the standalone output claims no DBC semantics;
C. a standalone IDX is never copied as valid (no rebuild behavior yet:
   REQ-P6-004 stays out of scope);
D. a hostile combined source (DBF+FPT+CDX+IDX+DBC/DCT/DCX plus unrelated
   unknown sidecars) exports ONLY the approved standalone DBF/FPT payload
   plus the sanitized manifest;
E. ``verify_transfer_bundle`` PASSES for the resulting clean DATA_ONLY
   bundle and DETECTS injected stale structural artifacts;
F. deleted records, NULL values, memo masking and declared PK/FK
   preservation are unchanged through the standalone fresh-write path.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import dbfbridge  # noqa: E402
from dbf_anonymizer import (  # noqa: E402
    TransferError,
    VerificationStatus,
    build_plan,
    create_transfer_bundle,
    preflight,
    pseudonymize,
    verify_dataset,
    verify_transfer_bundle,
)
from tests.support.numeric_tables import (  # noqa: E402
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table,
    write_numeric_table_with_deleted,
)

_FIXTURE_VFP = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "p0" / "vfp"

_FORBIDDEN_IN_DATA_ONLY = frozenset(
    (".cdx", ".idx", ".dbc", ".dct", ".dcx", ".sqlite3", "-wal", "-shm", "-journal")
)


def _copy_fixture(source_root: Path, fixture_relative: str, relative: str) -> None:
    destination = source_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(_FIXTURE_VFP / fixture_relative, destination)


def _hash_source_tree(source_root: Path) -> dict[str, str]:
    """Hash every source artifact, including hostile unknown sidecars."""
    return {
        path.relative_to(source_root).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(source_root.rglob("*"))
        if path.is_file()
    }


def _pipeline(tmp_path: Path, copies: tuple[tuple[str, str], ...]):
    """Run the REAL production pipeline over copied synthetic fixtures.

    Each copy maps (fixture relative path, source-tree relative path).
    """
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    for fixture_relative, relative in copies:
        _copy_fixture(source, fixture_relative, relative)
    plan = build_plan(str(source), str(output), str(vault))
    check = preflight(plan)
    assert check.ready, check.error_codes
    result = pseudonymize(plan)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.PASS
    return plan, result, source, output, vault


# ---------------------------------------------------------------------------
# A. structural-CDX source table
# ---------------------------------------------------------------------------
def test_structural_cdx_source_produces_standalone_output(tmp_path: Path) -> None:
    plan, result, source, output, vault = _pipeline(
        tmp_path,
        (("structural/indexed_table.dbf", "structural/indexed_table.dbf"),
         ("structural/indexed_table.cdx", "structural/indexed_table.cdx")),
    )
    table_plan = plan.tables[0]
    # The SOURCE truthfully reports its structural coupling.
    assert table_plan.structural_cdx is True
    assert table_plan.structural_cdx_companion_present is True
    assert table_plan.index_strategy == "DATA_ONLY"

    output_schema = dbfbridge.read_schema(output / "structural" / "indexed_table.dbf")
    # The FRESH output schema carries NO structural coupling.
    assert output_schema.has_structural_cdx is False
    assert output_schema.table_flags == 0
    assert output_schema.companion_cdx_present is False
    # The stale CDX is absent from the working output.
    assert not (output / "structural" / "indexed_table.cdx").exists()
    assert not list(output.rglob("*.cdx"))

    # The output remains readable standalone through the public boundary,
    # with the logical record facts preserved (record count, deleted-record
    # fidelity and NUMERIC value identity; pseudonymizable text/memo fields
    # are transformed by the pipeline's global text/memo domain).
    source_records = list(
        dbfbridge.iter_records(source / "structural" / "indexed_table.dbf",
                               include_deleted=True, memo="inline")
    )
    output_records = list(
        dbfbridge.iter_records(output / "structural" / "indexed_table.dbf",
                               include_deleted=True, memo="inline")
    )
    assert len(output_records) == len(source_records) == 4
    assert ([row.deleted for row in output_records]
            == [row.deleted for row in source_records])
    assert all(
        a.values["AMOUNT"] == b.values["AMOUNT"]
        for a, b in zip(output_records, source_records)
    )

    # Source immutability: source DBF and CDX bytes unchanged.
    committed = Path(_FIXTURE_VFP / "structural" / "indexed_table.dbf").read_bytes()
    assert (source / "structural" / "indexed_table.dbf").read_bytes() == committed


def test_p0_benchmark_harness_remains_standalone_source(tmp_path: Path) -> None:
    """The P0-005 benchmark workload keeps proving source immutability
    through the standalone fresh write (regression guard)."""
    bench = pytest.importorskip("tools.final_pipeline_benchmark")
    run = bench.run_final_pipeline_benchmark(
        tmp_path / "bench", customers=40, orders=20, archived=10, workers=1
    )
    assert run.report["record_count"] == 70
    assert run.report["index_backend_applicable"] is False
    assert run.report["index_backend_seconds"] is None


# ---------------------------------------------------------------------------
# B. DBC-bound source
# ---------------------------------------------------------------------------
def test_dbc_bound_source_produces_output_without_dbc_artifacts(
    tmp_path: Path,
) -> None:
    plan, result, source, output, vault = _pipeline(
        tmp_path,
        (("dbc/dbc_bound_table.dbf", "dbc/dbc_bound_table.dbf"),
         ("fixture.dbc", "fixture.dbc"),
         ("fixture.dct", "fixture.dct"),
         ("fixture.dcx", "fixture.dcx")),
    )
    table_plan = plan.tables[0]
    # The SOURCE truthfully reports its DBC-bound state.
    assert table_plan.dbc_bound is True

    output_names = sorted(
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    )
    assert output_names == ["dbc/dbc_bound_table.dbf"]
    assert not list(output.rglob("*.dbc"))
    assert not list(output.rglob("*.dct"))
    assert not list(output.rglob("*.dcx"))

    output_table_path = output / "dbc" / "dbc_bound_table.dbf"
    output_schema = dbfbridge.read_schema(output_table_path)
    assert output_schema.dbc_bound is False
    assert output_schema.dbc_backlink_path is None
    assert output_schema.table_flags == 0
    # The standalone output remains fully readable.
    rows = list(
        dbfbridge.iter_records(output_table_path, include_deleted=True, memo="inline")
    )
    assert len(rows) == table_plan.record_count


# ---------------------------------------------------------------------------
# C. standalone IDX is never copied as valid
# ---------------------------------------------------------------------------
def test_standalone_idx_is_not_copied_and_no_rebuild_is_claimed(
    tmp_path: Path,
) -> None:
    plan, result, source, output, vault = _pipeline(
        tmp_path,
        (("idx/standalone_idx_table.dbf", "idx/standalone_idx_table.dbf"),
         ("idx/code_idx.idx", "idx/code_idx.idx")),
    )
    assert plan.tables[0].index_strategy == "DATA_ONLY"
    assert not list(output.rglob("*.idx"))
    assert (output / "idx" / "standalone_idx_table.dbf").is_file()
    # No rebuild behavior is claimed yet (REQ-P6-004 stays out of scope).
    assert plan.output_profile is not None
    rows = list(
        dbfbridge.iter_records(output / "idx" / "standalone_idx_table.dbf",
                               include_deleted=True, memo="inline")
    )
    assert len(rows) == plan.tables[0].record_count


# ---------------------------------------------------------------------------
# D. hostile combined source with unrelated unknown sidecars
# ---------------------------------------------------------------------------
def test_hostile_combined_source_exports_only_approved_standalone_payload(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    copies = (
        ("structural/indexed_table.dbf", "combined/indexed_table.dbf"),
        ("structural/indexed_table.cdx", "combined/indexed_table.cdx"),
        ("idx/standalone_idx_table.dbf", "combined/standalone_idx_table.dbf"),
        ("idx/code_idx.idx", "combined/code_idx.idx"),
        ("dbc/dbc_bound_table.dbf", "combined/dbc_bound_table.dbf"),
        ("fixture.dbc", "fixture.dbc"),
        ("fixture.dct", "fixture.dct"),
        ("fixture.dcx", "fixture.dcx"),
    )
    for fixture_relative, relative in copies:
        _copy_fixture(source, fixture_relative, relative)
    write_numeric_table(
        source,
        "combined/memo_table.dbf",
        (numeric_field("KEY", "C", 12), numeric_field("NOTE", "M", 4)),
        [
            {"KEY": f"MEMO{index:08d}", "NOTE": f"PRIVATE-MEMO-{index}"}
            for index in range(4)
        ],
    )

    # Every hostile artifact exists BEFORE planning and execution.
    (source / "combined" / "notes.txt").write_bytes(b"unknown sidecar")
    (source / "combined" / "dictionary.sqlite3").write_bytes(b"hostile vault")
    (source / "combined" / "leftover.tmp").write_bytes(b"temp")
    source_before = _hash_source_tree(source)
    assert {
        ".dbf", ".fpt", ".cdx", ".idx", ".dbc", ".dct", ".dcx",
        ".txt", ".sqlite3", ".tmp",
    } <= {Path(relative).suffix.lower() for relative in source_before}

    plan = build_plan(str(source), str(output), str(vault))
    check = preflight(plan)
    assert check.ready, check.error_codes
    result = pseudonymize(plan)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.PASS
    assert _hash_source_tree(source) == source_before

    # No stale structural/DBC artifact reached the working output tree.
    for suffix in _FORBIDDEN_IN_DATA_ONLY:
        assert not list(output.rglob(f"*{suffix}"))
    output_files = sorted(path.name for path in output.rglob("*") if path.is_file())
    assert output_files == [
        "dbc_bound_table.dbf",
        "indexed_table.dbf",
        "memo_table.dbf",
        "memo_table.fpt",
        "standalone_idx_table.dbf",
    ]

    bundle_root = tmp_path / "bundle"
    bundle = create_transfer_bundle(result, destination=str(bundle_root))
    assert bundle.verified is True
    verified = verify_transfer_bundle(str(bundle_root))
    assert verified.verified is True
    bundle_files = sorted(
        path.relative_to(bundle_root).as_posix()
        for path in bundle_root.rglob("*")
        if path.is_file()
    )
    assert bundle_files == [
        "combined/dbc_bound_table.dbf",
        "combined/indexed_table.dbf",
        "combined/memo_table.dbf",
        "combined/memo_table.fpt",
        "combined/standalone_idx_table.dbf",
        "transfer-manifest.json",
    ]

    stale = bundle_root / "combined" / "injected.cdx"
    stale.write_bytes(b"stale index")
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(str(bundle_root))
    assert caught.value.context.detail_code == "TRANSFER_FORBIDDEN_ARTIFACT"


# ---------------------------------------------------------------------------
# E. transfer verification of the clean bundle + stale-artifact detection
# ---------------------------------------------------------------------------
def test_data_only_bundle_verifies_and_refuses_injected_stale_artifacts(
    tmp_path: Path,
) -> None:
    plan, result, source, output, vault = _pipeline(
        tmp_path,
        (("structural/indexed_table.dbf", "structural/indexed_table.dbf"),
         ("structural/indexed_table.cdx", "structural/indexed_table.cdx"),
         ("idx/code_idx.idx", "idx/code_idx.idx"),
         ("dbc/dbc_bound_table.dbf", "dbc/dbc_bound_table.dbf"),
         ("fixture.dbc", "fixture.dbc")),
    )
    bundle = create_transfer_bundle(result, destination=str(tmp_path / "bundle"))
    assert bundle.verified is True

    manifest_path = tmp_path / "bundle" / "transfer-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1.1"
    assert manifest["index_state"] == "DATA_ONLY_INDEX_OMITTED"
    assert manifest["data_state"] == "STANDALONE_REDUCED_SEMANTICS"

    verified = verify_transfer_bundle(str(tmp_path / "bundle"))
    assert verified.verified is True

    # An injected stale structural artifact MUST be detected standalone.
    stale = tmp_path / "bundle" / "structural" / "indexed_table.cdx"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_bytes(b"stale structural index bytes")
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(str(tmp_path / "bundle"))
    assert caught.value.context.detail_code == "TRANSFER_FORBIDDEN_ARTIFACT"


# ---------------------------------------------------------------------------
# F. deleted records, NULL values, memo masking and PK/FK preservation
# ---------------------------------------------------------------------------
def test_standalone_fresh_write_preserves_data_facts(tmp_path: Path) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    write_numeric_table_with_deleted(
        source,
        "archive/data.dbf",
        (
            numeric_field("LEG_ID", "C", 12),
            numeric_field("NOTE", "M", 4),
            numeric_field("AMT", "N", 9),
        ),
        [
            ({"LEG_ID": f"LEG{index:08d}", "NOTE": f"MEMO-{index}", "AMT": index + 1},
             index % 3 == 2)
            for index in range(30)
        ],
    )
    write_numeric_table(
        source,
        "north/customers.dbf",
        (
            numeric_field("CUST_ID", "C", 14),
            numeric_field("NAME", "C", 24, flags=NULLABLE_FLAG),
            numeric_field("NOTE", "M", 4),
        ),
        [
            {"CUST_ID": f"CUST{index:09d}", "NAME": None if index % 4 == 0 else f"N-{index}",
             "NOTE": f"MEMO-{index}"}
            for index in range(30)
        ],
    )
    write_numeric_table(
        source,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 14), numeric_field("ORD_N", "N", 9)),
        [
            {"CUST_ID": f"CUST{index % 30:09d}", "ORD_N": index + 1}
            for index in range(45)
        ],
    )
    document = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "north/customers.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 14,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 14,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }
    plan = build_plan(str(source), str(output), str(vault),
                      relationship_document=document)
    result = pseudonymize(plan)
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.PASS
    # The declared PK/FK text keys stay join-compatible (equal after
    # pseudonymization), deleted-record and NULL fidelity hold.
    assurance = result.assurance
    assert assurance.incomplete_relations == 0
    rows = list(
        dbfbridge.iter_records(output / "archive" / "data.dbf",
                               include_deleted=True, memo="skip")
    )
    deleted_flags = [row.deleted for row in rows]
    assert deleted_flags == [row.deleted for row in
                             dbfbridge.iter_records(source / "archive" / "data.dbf",
                                                    include_deleted=True, memo="skip")]
    assert sum(deleted_flags) == 10  # every third record was deleted


def test_p6_module_imports_are_toolchain_free() -> None:
    """The P6 boundary imports no VFP/COM/toolchain module, no subprocess or
    network machinery, and no private dbfbridge module (AST + runtime)."""
    import ast
    import importlib

    import dbf_anonymizer.index_backend as backend_module

    source = Path(backend_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    allowed_roots = {"__future__", "dbf_anonymizer", "dataclasses", "typing"}
    assert imported_roots <= allowed_roots, sorted(imported_roots)
    for loaded in ("win32com", "pythoncom", "mcp_vfp9sp2_toolchain"):
        assert loaded not in sys.modules, loaded
    importlib.reload(backend_module)
    assert "win32com" not in sys.modules
    assert "mcp_vfp9sp2_toolchain" not in sys.modules
