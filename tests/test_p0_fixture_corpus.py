"""REQ-P0-003 — deterministic verification of the synthetic fixture corpus.

Every committed fixture artifact is verified through the public ``dbfbridge``
Direct Read / Direct Write contract only.  The tests re-derive every manifest
claim independently (existence, SHA-256, schema facts, typed values, deleted
state, NULL semantics, shared keys, malformed behavior) and guard privacy
policy (synthetic-only artifacts, no private paths, narrow Git allowlist).
No test compares the manifest only with itself: every claim is cross-checked
against the public dbfbridge API or the actual file tree.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile
from decimal import Decimal
from pathlib import Path

import pytest
from dbfbridge import (
    ErrorCode,
    WriteFieldUnsupportedError,
    inspect_table,
    iter_records,
    read_schema,
)

import dbfbridge

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "p0"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"
PROVENANCE_PATH = FIXTURE_ROOT / "PROVENANCE.md"
GENERATOR_PATH = REPO_ROOT / "tools" / "generate_p0_fixtures.py"

#: Every REQ-P0-003 coverage dimension that must be represented either by a
#: fixture artifact or by an explicitly declared, justified gap.
REQUIRED_DIMENSIONS = frozenset(
    {
        "plain_dbf",
        "dbf_fpt",
        "cp1250",
        "cp852",
        "mazovia_piast_text",
        "deleted_records",
        "null_values_and_nullflags",
        "duplicate_basenames",
        "shared_cross_table_keys",
        "character",
        "varchar_significant_trailing_spaces",
        "integer",
        "numeric",
        "float",
        "currency",
        "double",
        "logical",
        "date",
        "datetime",
        "memo",
        "general_picture_payloads",
        "structural_cdx_metadata",
        "dbc_bound_metadata",
        "standalone_idx_inventory",
        "malformed_inputs",
        "negative_opaque_field_cases",
    }
)

#: Dimensions that may only be declared as gaps (no fabricated artifacts).
GAP_DIMENSIONS = frozenset(
    {"structural_cdx_metadata", "dbc_bound_metadata", "standalone_idx_inventory"}
)

PRIVACY_TOKENS = (
    "C:\\",
    "C:/",
    "\\Users\\",
    "/Users/",
    "Downloads",
    "Desktop",
    "Documents",
    "dictionary.sqlite3",
    "-wal",
    "-shm",
)


def _load_manifest() -> dict:
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    return json.loads(text)


def _fixture_entry(manifest: dict, fixture_id: str) -> dict:
    return next(entry for entry in manifest["fixtures"] if entry["id"] == fixture_id)


def _fixture_path(manifest: dict, fixture_id: str) -> Path:
    return FIXTURE_ROOT / _fixture_entry(manifest, fixture_id)["path"]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _committed_artifact_paths(manifest: dict) -> set[str]:
    return {entry["path"] for entry in manifest["fixtures"]}


def capability_test_exists(reference: str) -> bool:
    """Whether a ``module::test_name`` capability reference names a real test."""
    if "::" not in reference:
        return False
    test_name = reference.split("::", 1)[1]
    module_text = Path(__file__).read_text(encoding="utf-8")
    return re.search(rf"^def {re.escape(test_name)}\(", module_text, re.MULTILINE) is not None


# ---------------------------------------------------------------------------
# manifest / provenance / privacy policy
# ---------------------------------------------------------------------------


def test_manifest_is_valid_and_contains_no_private_information() -> None:
    manifest = _load_manifest()
    assert manifest["manifest_schema"] == "req-p0-003/1"
    assert manifest["generator"]["dbfbridge"] == "1.1.0"
    assert manifest["generator"]["dbfbridge_import_namespace"] == "dbfbridge"
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert "\\" not in text, "manifest must use posix relative paths only"
    assert not re.search(r"[A-Za-z]:[\\/]", text), "absolute paths are forbidden"
    for forbidden in ("Users", "peter", "AppData", "Temp", "Desktop", "Downloads"):
        assert forbidden not in text, f"private marker {forbidden!r} in manifest"
    for entry in manifest["fixtures"]:
        relative = entry["path"]
        assert not relative.startswith("/") and ":" not in relative
        assert entry["synthetic"] is True
        assert (FIXTURE_ROOT / relative).is_file()


def test_declared_artifacts_exist_with_matching_sha256() -> None:
    manifest = _load_manifest()
    for entry in manifest["fixtures"]:
        artifact = FIXTURE_ROOT / entry["path"]
        assert artifact.is_file(), f"missing artifact: {entry['path']}"
        assert _sha256(artifact) == entry["sha256"], f"sha256 mismatch: {entry['path']}"


def test_no_undeclared_committed_artifacts() -> None:
    manifest = _load_manifest()
    allowed = {"manifest.json", "PROVENANCE.md"} | _committed_artifact_paths(manifest)
    present = {
        path.relative_to(FIXTURE_ROOT).as_posix()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file()
    }
    undeclared = present - allowed
    assert not undeclared, f"undeclared committed artifacts: {sorted(undeclared)}"


def test_provenance_document_states_synthetic_origin() -> None:
    text = PROVENANCE_PATH.read_text(encoding="utf-8")
    for required in (
        "synthetic",
        "no production, customer or organizational",
        "dbfbridge",
        "1.1.0",
        "write_table",
        "malformed",
        "regeneration",
        "MIT",
    ):
        assert re.search(re.escape(required), text, re.IGNORECASE), (
            f"provenance statement missing: {required!r}"
        )


def test_fixture_tree_has_no_sensitive_artifacts_or_paths() -> None:
    sensitive_names = (
        "dictionary.sqlite3",
        "*.sqlite3-wal",
        "*.sqlite3-shm",
        "*.sqlite3-journal",
        "*-wal",
        "*-shm",
    )
    for pattern in sensitive_names:
        assert not list(FIXTURE_ROOT.glob(f"**/{pattern}")), pattern
    for artifact in FIXTURE_ROOT.rglob("*"):
        if not artifact.is_file():
            continue
        data = artifact.read_bytes()
        for token in (b"dictionary.sqlite3", b"Users", b"AppData", b"Desktop"):
            assert token not in data, f"{artifact.name} contains {token!r}"


def test_gitignore_allowlist_is_narrow() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("*.dbf", "*.fpt", "*.cdx"):
        assert re.search(rf"^{re.escape(pattern)}\s*$", gitignore, re.MULTILINE), (
            f"global exclusion missing: {pattern}"
        )
    assert re.search(r"^!tests/fixtures/p0/\*\*/\*\.dbf\s*$", gitignore, re.MULTILINE)
    assert re.search(r"^!tests/fixtures/p0/\*\*/\*\.fpt\s*$", gitignore, re.MULTILINE)
    assert "!*.dbf" not in gitignore.replace("!tests/fixtures/p0/**/*.dbf", "")
    if (REPO_ROOT / ".git").is_dir():
        # Behavioral check (path-based; the file need not exist): a DBF in the
        # production source tree must stay ignored while the committed
        # synthetic fixture subtree is re-included.
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", "src/canary_ignored.dbf"],
            cwd=REPO_ROOT,
            check=False,
        ).returncode
        assert ignored == 0, "DBF files outside the fixture subtree must stay ignored"
        fixture_rel = "tests/fixtures/p0/plain/plain_customers.dbf"
        not_ignored = subprocess.run(
            ["git", "check-ignore", "-q", fixture_rel], cwd=REPO_ROOT, check=False
        ).returncode
        assert not_ignored != 0, "committed synthetic fixtures must not be ignored"


# ---------------------------------------------------------------------------
# coverage matrix
# ---------------------------------------------------------------------------


def test_required_dimensions_are_represented() -> None:
    manifest = _load_manifest()
    coverage = manifest["coverage"]
    gaps = {gap["dimension"] for gap in manifest["gaps"]}
    covered = set(coverage)
    assert covered | gaps == REQUIRED_DIMENSIONS, (
        f"missing dimensions: {sorted(REQUIRED_DIMENSIONS - (covered | gaps))}"
    )
    for dimension, references in coverage.items():
        assert dimension in REQUIRED_DIMENSIONS, f"unknown dimension: {dimension}"
        assert reference_is_resolvable(dimension, references), dimension


def test_declared_gaps_are_not_claimed() -> None:
    manifest = _load_manifest()
    gaps = {gap["dimension"]: gap for gap in manifest["gaps"]}
    assert set(gaps) == GAP_DIMENSIONS
    for dimension, gap in gaps.items():
        assert gap["blocker"].strip(), f"gap without blocker: {dimension}"
        for reference in gap["capability_evidence"]:
            assert capability_test_exists(reference), reference
    for entry in manifest["fixtures"]:
        for dimension in entry["coverage"]:
            assert dimension not in GAP_DIMENSIONS, (
                f"gap dimension {dimension} claimed by fixture {entry['id']}"
            )


def reference_is_resolvable(dimension: str, references: list[str]) -> bool:
    if not references:
        return False
    module_text = Path(__file__).read_text(encoding="utf-8")
    for reference in references:
        if reference.startswith("tests.test_p0_fixture_corpus::"):
            if not re.search(
                rf"^def {re.escape(reference.split('::')[1])}\(", module_text, re.MULTILINE
            ):
                return False
        else:
            fixture_ids = {entry["id"] for entry in _load_manifest()["fixtures"]}
            if reference not in fixture_ids:
                return False
    return True


# ---------------------------------------------------------------------------
# public-API verification of the valid fixtures
# ---------------------------------------------------------------------------


def test_plain_fixture_schema_records_and_deleted_state() -> None:
    manifest = _load_manifest()
    entry = _fixture_entry(manifest, "plain.plain_customers")
    schema = read_schema(FIXTURE_ROOT / entry["path"])
    assert schema.dbversion_byte == 0x30
    assert schema.encoding == "cp1250"
    assert schema.record_count == entry["dbf"]["record_count"] == 6
    assert [f.dbf_type for f in schema.fields] == entry["dbf"]["field_classes"]
    records = list(iter_records(schema.path, include_deleted=True))
    assert [record.deleted for record in records] == [False, False, False, True, False, True]
    row0 = records[0].values
    assert row0["CODE"] == "SYNTH-01"
    assert row0["CNT"] == -42
    assert row0["AMOUNT"] == 123.45
    assert row0["RATIO"] == 2.5
    assert row0["PRICE"] == Decimal("1234.5678")
    assert row0["MEASURE"] == 3.14159
    assert row0["FLAG"] is True
    assert row0["WHEN"] == datetime.date(2028, 2, 29)
    assert row0["MOMENT"] == datetime.datetime(2028, 2, 29, 23, 59, 58)


def test_codepage_fixtures_round_trip_through_public_api() -> None:
    manifest = _load_manifest()
    texts = {
        "cp1250": "Zażółć gęślą jaźń ĄĆĘŁŃÓŚŹŻ ąćęłńóśźż SYNTH-P1250",
        "cp852": "Zażółć gęślą jaźń ĄĆĘŁŃÓŚŹŻ ąćęłńóśźż SYNTH-P852",
        "mazovia": "Zażółć gęślą jaźń ĄĆĘŁŃÓŚŹŻ ąćęłńóśźż SYNTH-MAZOVIA",
    }
    for fixture_id, encoding in (
        ("text.cp1250", "cp1250"),
        ("text.cp852", "cp852"),
        ("text.mazovia", "mazovia"),
    ):
        entry = _fixture_entry(manifest, fixture_id)
        path = FIXTURE_ROOT / entry["path"]
        schema = read_schema(path)
        assert schema.encoding == entry["dbf"]["encoding"] == encoding
        records = list(iter_records(path))
        assert records[0].values["TEXT"] == texts[encoding], fixture_id
        assert records[1].values["TEXT"] == "ASCII-ONLY-SYNTH-ROW"
    # PIAST is the public codec alias of the same Mazovia OEM table; reading
    # the committed Mazovia fixture through it must decode identically.
    mazovia = _fixture_path(manifest, "text.mazovia")
    assert list(iter_records(mazovia, encoding="piast"))[0].values["TEXT"] == texts["mazovia"]


def test_nullable_fixture_null_empty_zero_distinction() -> None:
    manifest = _load_manifest()
    entry = _fixture_entry(manifest, "nullable.nullable_varchar")
    path = FIXTURE_ROOT / entry["path"]
    schema = read_schema(path)
    assert schema.dbversion_byte == 0x32
    assert any(f.dbf_type == "0" and f.name == "_NULLFLAGS" for f in schema.fields)
    records = list(iter_records(path, include_deleted=True))
    values = [record.values for record in records]
    assert values[0]["QTY"] == 1.5 and values[0]["CNT"] == 10
    assert values[1]["QTY"] is None and values[1]["CNT"] is None  # explicit NULLs
    assert values[2]["QTY"] == 0.0 and values[2]["CNT"] == 0  # zero, not NULL
    assert values[1]["WHEN"] is None
    assert values[0]["WHEN"] == datetime.date(2026, 1, 2)
    # The system column is exposed as writer metadata, not as a user value.
    assert all("_NULLFLAGS" in record.values for record in records)
    assert entry["expectations"]["system_column"] == "_NULLFLAGS"


def test_varchar_trailing_spaces_are_significant() -> None:
    manifest = _load_manifest()
    path = _fixture_path(manifest, "nullable.nullable_varchar")
    records = list(iter_records(path))
    assert records[0].values["VC"] == "padded   "  # trailing spaces preserved
    assert records[1].values["VC"] == "  lead"  # leading spaces preserved
    assert records[0].values["NOTE"] == "x"  # Character value is not padded on read
    assert records[3].values["NOTE"] == ""  # trailing-space-only C value trims to empty


def test_duplicate_basenames_and_shared_keys() -> None:
    manifest = _load_manifest()
    north_path = FIXTURE_ROOT / _fixture_entry(manifest, "topology.north_registry")["path"]
    south_path = FIXTURE_ROOT / _fixture_entry(manifest, "topology.south_registry")["path"]
    assert north_path.name == south_path.name == "registry.dbf"
    assert north_path.parent != south_path.parent
    north_keys = [r.values["KEY"] for r in iter_records(north_path) if not r.deleted]
    south_rows = [(r.values["KEY"], r.deleted) for r in iter_records(south_path, include_deleted=True)]
    active_south_keys = [key for key, deleted in south_rows if not deleted]
    assert sorted(set(north_keys)) == ["KEY0001", "KEY0002", "KEY0003", "KEY0004"]
    assert active_south_keys.count("KEY0002") == 2  # duplicate FK multiplicity
    assert "" in active_south_keys  # empty (non-key) row preserved
    shared = set(active_south_keys) - {""}
    assert shared <= set(north_keys)
    assert shared == {"KEY0001", "KEY0002", "KEY0004"}


def test_memo_general_picture_round_trip() -> None:
    manifest = _load_manifest()
    entry = _fixture_entry(manifest, "memos.memo_payloads")
    path = FIXTURE_ROOT / entry["path"]
    fpt_path = _fixture_path(manifest, "memos.memo_payloads.fpt")
    assert fpt_path.is_file()
    schema = read_schema(path)
    assert schema.has_memo is True
    assert schema.memo_companion_present is True
    records = list(iter_records(path, memo="inline", include_deleted=True))
    row0 = records[0].values
    assert row0["TXT"] == entry["expectations"]["row0"]["TXT"]
    assert row0["BIN"].hex() == entry["expectations"]["row0"]["BIN_hex"]
    assert row0["GEN"].hex() == entry["expectations"]["row0"]["GEN_hex"]
    assert row0["PIC"].hex() == entry["expectations"]["row0"]["PIC_hex"]
    assert records[1].values["TXT"] is None
    assert records[1].values["GEN"] is None
    assert records[1].values["BIN"] is None
    assert records[1].values["PIC"] is None
    assert records[2].deleted is True
    assert records[2].values["TXT"] == "DELETED-MEMO-SYNTH"


# ---------------------------------------------------------------------------
# malformed / negative / capability evidence
# ---------------------------------------------------------------------------


def test_malformed_fixtures_fail_with_typed_dependency_errors() -> None:
    manifest = _load_manifest()
    for fixture_id in (
        "malformed.truncated_records",
        "malformed.unknown_version",
        "malformed.corrupt_header_length",
    ):
        entry = _fixture_entry(manifest, fixture_id)
        path = FIXTURE_ROOT / entry["path"]
        expected = entry["malformed"]["expected"]
        if expected["operation"] == "read_schema":
            with pytest.raises(Exception) as excinfo:
                read_schema(path)
        else:
            with pytest.raises(Exception) as excinfo:
                list(iter_records(path))
        error = excinfo.value
        assert getattr(error, "code", None) == ErrorCode[expected["error_code"]], (
            f"{fixture_id}: unexpected failure {error!r}"
        )


def test_missing_memo_companion_behavior() -> None:
    manifest = _load_manifest()
    path = _fixture_path(manifest, "malformed.missing_memo_companion")
    assert not path.with_suffix(".fpt").exists()
    info = inspect_table(path)
    assert info.warnings and "companion" in info.warnings[0]
    with pytest.raises(Exception) as excinfo:
        list(iter_records(path, memo="inline"))
    assert excinfo.value.code == ErrorCode.FPT_REQUIRED_MISSING
    lazy_records = list(iter_records(path))  # default memo='lazy' never fails
    assert all(
        type(record.values["TXT"]).__name__ == "LazyMemoValue" for record in lazy_records
    )


def test_opaque_field_write_refusal() -> None:
    for dbf_type in ("Q", "W"):
        fields = (dbfbridge.FieldInfo(
            ordinal=0, name="OPAQUE", dbf_type=dbf_type, length=8, decimal_count=0,
            address=0, flags=0, index_field_flag=0, autoincrement_next_value=0,
            autoincrement_step=1, is_memo=False, is_binary=True, supported=True,
            dbversion_byte=0x30,
        ),)
        schema = dbfbridge.TableSchema(
            path=Path("memory:negative"), record_count=0, header_length=65,
            record_length=9, language_driver=0xC8, encoding="cp1250", has_memo=False,
            has_memo_flag=False, has_structural_cdx=False, is_database_container=False,
            dbc_bound=False, dbc_backlink_path=None, table_flags=0, fields=fields,
            warnings=(), dbversion_byte=0x30, dbversion_name="Visual FoxPro",
            last_update=None, incomplete_transaction=False, encryption_flag=False,
            memo_companion_format=None, memo_companion_present=False,
            memo_companion_path=None, memo_companion_size_bytes=None,
            memo_block_size=None, memo_next_free_block=None,
            companion_cdx_present=False, companion_cdx_path=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(WriteFieldUnsupportedError):
                dbfbridge.write_table(
                    Path(tmp) / f"opaque_{dbf_type}.dbf", schema=schema, records=[]
                )


def test_unknown_projection_negative() -> None:
    manifest = _load_manifest()
    path = _fixture_path(manifest, "plain.plain_customers")
    with pytest.raises(Exception) as excinfo:
        list(iter_records(path, fields=["NO_SUCH_FIELD"]))
    assert excinfo.value.code == ErrorCode.FIELD_PROJECTION_INVALID


def test_structural_cdx_capability_fact(tmp_path: object) -> None:
    """Truthful structural-CDX evidence: the flag is accepted but not persisted."""
    fields = (
        dbfbridge.FieldInfo(
            ordinal=0, name="CODE", dbf_type="C", length=8, decimal_count=0, address=0,
            flags=0, index_field_flag=0, autoincrement_next_value=0, autoincrement_step=1,
            is_memo=False, is_binary=False, supported=True, dbversion_byte=0x30,
        ),
    )
    schema = dbfbridge.TableSchema(
        path=Path("memory:cdx"), record_count=0, header_length=65, record_length=9,
        language_driver=0xC8, encoding="cp1250", has_memo=False, has_memo_flag=False,
        has_structural_cdx=True, is_database_container=False, dbc_bound=False,
        dbc_backlink_path=None, table_flags=0, fields=fields, warnings=(),
        dbversion_byte=0x30, dbversion_name="Visual FoxPro", last_update=None,
        incomplete_transaction=False, encryption_flag=False,
        memo_companion_format=None, memo_companion_present=False,
        memo_companion_path=None, memo_companion_size_bytes=None,
        memo_block_size=None, memo_next_free_block=None,
        companion_cdx_present=False, companion_cdx_path=None,
    )
    destination = Path(str(tmp_path)) / "structural_cdx.dbf"
    result = dbfbridge.write_table(
        destination, schema=schema, records=[dbfbridge.DirectRecord(0, False, {"CODE": "SYNTH"})],
        overwrite=True,
    )
    assert result.structural_cdx is True
    assert result.index_rebuild_required is True
    assert any("structural CDX" in warning for warning in result.warnings)
    persisted = read_schema(destination)
    assert persisted.has_structural_cdx is False
    assert persisted.companion_cdx_present is False


def test_written_fixtures_are_standalone() -> None:
    manifest = _load_manifest()
    for entry in manifest["fixtures"]:
        if entry["artifact_class"] not in {"dbf", "dbf-missing-companion"}:
            continue
        schema = read_schema(FIXTURE_ROOT / entry["path"])
        assert schema.dbc_bound is False, entry["id"]
        assert schema.is_database_container is False, entry["id"]
        assert schema.companion_cdx_present is False, entry["id"]


# ---------------------------------------------------------------------------
# deterministic regeneration
# ---------------------------------------------------------------------------


def test_regeneration_is_byte_deterministic() -> None:
    manifest = _load_manifest()
    spec = importlib.util.spec_from_file_location("generate_p0_fixtures", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="p0-corpus-regen-") as tmp:
        regenerated_root = Path(tmp) / "p0"
        module.generate(regenerated_root)
        regenerated = json.loads(
            (regenerated_root / "manifest.json").read_text(encoding="utf-8")
        )
        assert regenerated == manifest, "regenerated corpus differs from the committed corpus"
        for entry in regenerated["fixtures"]:
            artifact = regenerated_root / entry["path"]
            assert _sha256(artifact) == entry["sha256"], entry["id"]