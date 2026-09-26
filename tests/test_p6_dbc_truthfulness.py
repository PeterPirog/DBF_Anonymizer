"""Focused REQ-P6-005 DBC source/output truthfulness evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import dbfbridge
import pytest

from dbf_anonymizer import (
    OutputDataState,
    PolicyError,
    RelationalAssuranceLevel,
    RelationshipMetadata,
    TransferError,
    VerificationStatus,
    build_plan,
    create_transfer_bundle,
    preflight,
    pseudonymize,
    verify_dataset,
    verify_transfer_bundle,
)
from dbf_anonymizer.relationships import (
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    authoritative_vfp_metadata_from_document,
    parse_relationship_document,
    relationship_fingerprint,
    verify_relationships,
)
from dbf_anonymizer.relationships.assurance import derive_relational_assurance
from tests.test_p3_relationship_verification import _counts


_FIXTURE_VFP = Path(__file__).resolve().parent / "fixtures" / "p0" / "vfp"
_FORBIDDEN_OUTPUT_SUFFIXES = frozenset({".cdx", ".idx", ".dbc", ".dct", ".dcx"})
_RECOVERY_MARKERS = ("dictionary.sqlite", "-wal", "-shm", "recovery", "vault")
_DBC_SENTINELS = (
    "TRIGGER_SENTINEL_P6005",
    "RULE_SENTINEL_P6005",
    "STORED_PROCEDURE_SENTINEL_P6005",
    "PERSISTENT_RELATION_SENTINEL_P6005",
    "VIEW_SENTINEL_P6005",
)


def _copy_fixture(source: Path, fixture_relative: str, relative: str) -> None:
    destination = source / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_FIXTURE_VFP / fixture_relative, destination)


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _files(root: Path) -> tuple[Path, ...]:
    return tuple(path for path in sorted(root.rglob("*")) if path.is_file())


def _prepare_hostile_source(source: Path) -> None:
    _copy_fixture(source, "dbc/dbc_bound_table.dbf", "dbc/dbc_bound_table.dbf")
    _copy_fixture(source, "../memos/memo_payloads.dbf", "memo/memo_payloads.dbf")
    _copy_fixture(source, "../memos/memo_payloads.fpt", "memo/memo_payloads.fpt")
    _copy_fixture(source, "structural/indexed_table.cdx", "stale/orphan.cdx")
    _copy_fixture(source, "idx/code_idx.idx", "stale/orphan.idx")
    source.mkdir(parents=True, exist_ok=True)
    for suffix in (".dbc", ".dct", ".dcx"):
        payload = "|".join(_DBC_SENTINELS).encode("ascii") + suffix.encode("ascii")
        (source / f"fixture{suffix}").write_bytes(payload)


def _authoritative_document(provenance: str) -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-authoritative-p6005",
                "provenance": provenance,
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "parent.dbf",
                        "field": "KEY",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "child.dbf",
                        "field": "FK",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }


def test_dbc_bound_source_and_standalone_output_are_reported_truthfully(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "protected" / "dictionary.sqlite3"
    bundle_root = tmp_path / "bundle"
    _prepare_hostile_source(source)
    source_before = _tree_hashes(source)
    assert {Path(path).suffix.lower() for path in source_before} >= {
        ".dbf",
        ".fpt",
        ".cdx",
        ".idx",
        ".dbc",
        ".dct",
        ".dcx",
    }

    original_rows = list(
        dbfbridge.iter_records(
            source / "dbc" / "dbc_bound_table.dbf",
            include_deleted=True,
            memo="inline",
        )
    )
    original_text = next(
        value
        for row in original_rows
        for value in row.values.values()
        if isinstance(value, str) and len(value) >= 4
    )
    events = []
    plan = build_plan(source, output, vault, progress=events.append)
    table = next(item for item in plan.tables if item.table_path.endswith("dbc_bound_table.dbf"))
    assert table.dbc_bound is True
    assert plan.dataset.dbc_bound_table_paths == ("dbc/dbc_bound_table.dbf",)
    assert plan.output_data_state is OutputDataState.STANDALONE_REDUCED_SEMANTICS

    check = preflight(plan, progress=events.append)
    assert check.ready is True
    assert "DBC_BOUND_REDUCED" in check.warning_codes
    assert "DATA_ONLY_STANDALONE" in check.check_codes

    result = pseudonymize(plan, progress=events.append)
    verification = verify_dataset(
        result, source=source, vault=vault, progress=events.append
    )
    assert verification.status is VerificationStatus.PASS
    assert result.dataset.dbc_bound_table_paths == ("dbc/dbc_bound_table.dbf",)
    assert verification.dataset.dbc_bound_table_paths == (
        "dbc/dbc_bound_table.dbf",
    )
    assert result.output_data_state is OutputDataState.STANDALONE_REDUCED_SEMANTICS
    assert (
        verification.output_data_state
        is OutputDataState.STANDALONE_REDUCED_SEMANTICS
    )
    assert result.assurance.level is not RelationalAssuranceLevel.VFP_METADATA_VERIFIED

    hidden_source_fact = replace(
        result,
        dataset=replace(result.dataset, dbc_bound_table_paths=()),
    )
    hidden_verification = verify_dataset(
        hidden_source_fact, source=source, vault=vault
    )
    assert hidden_verification.status is VerificationStatus.FAIL
    assert "SOURCE_DBC_INVENTORY_MISMATCH" in hidden_verification.check_codes

    output_table = output / "dbc" / "dbc_bound_table.dbf"
    output_schema = dbfbridge.read_schema(output_table)
    assert output_schema.dbc_bound is False
    assert output_schema.dbc_backlink_path is None
    assert output_schema.is_database_container is False
    assert len(
        list(dbfbridge.iter_records(output_table, include_deleted=True, memo="inline"))
    ) == len(original_rows)
    output_files = _files(output)
    assert {path.suffix.lower() for path in output_files}.isdisjoint(
        _FORBIDDEN_OUTPUT_SUFFIXES
    )
    assert any(path.suffix.lower() == ".fpt" for path in output_files)

    bundle = create_transfer_bundle(
        result, destination=bundle_root, progress=events.append
    )
    bundle_verification = verify_transfer_bundle(bundle_root, progress=events.append)
    assert bundle.verified is True
    assert bundle_verification.verified is True
    bundle_files = _files(bundle_root)
    assert {path.suffix.lower() for path in bundle_files}.isdisjoint(
        _FORBIDDEN_OUTPUT_SUFFIXES
    )
    assert all(
        marker not in path.name.casefold()
        for path in bundle_files
        for marker in _RECOVERY_MARKERS
    )
    manifest = json.loads(
        (bundle_root / "transfer-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["data_state"] == "STANDALONE_REDUCED_SEMANTICS"

    public_payloads = [
        plan.to_dict(),
        check.to_dict(),
        result.to_dict(),
        verification.to_dict(),
        bundle.to_dict(),
        bundle_verification.to_dict(),
        *(event.to_dict() for event in events),
    ]
    public_text = json.dumps(public_payloads, sort_keys=True, ensure_ascii=True)
    artifact_bytes = b"".join(path.read_bytes() for path in (*output_files, *bundle_files))
    for sentinel in _DBC_SENTINELS:
        assert sentinel not in public_text
        assert sentinel.encode("ascii") not in artifact_bytes
    assert original_text not in public_text
    normalized_public = public_text.replace("\\\\", "/").replace("\\", "/")
    assert source.resolve().as_posix() not in normalized_public

    forbidden = bundle_root / "hostile.dbc"
    forbidden.write_text(_DBC_SENTINELS[0], encoding="ascii")
    with pytest.raises(TransferError) as caught:
        verify_transfer_bundle(bundle_root)
    error_text = json.dumps(caught.value.to_dict(), sort_keys=True)
    assert caught.value.context.detail_code == "TRANSFER_FORBIDDEN_ARTIFACT"
    assert _DBC_SENTINELS[0] not in error_text
    assert source.resolve().as_posix() not in error_text.replace("\\", "/")

    assert _tree_hashes(source) == source_before


def test_verifier_rejects_a_retained_source_dbc_claim(tmp_path: Path) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "protected" / "dictionary.sqlite3"
    _prepare_hostile_source(source)
    source_before = _tree_hashes(source)
    plan = build_plan(source, output, vault)
    result = pseudonymize(plan)

    shutil.copyfile(
        source / "dbc" / "dbc_bound_table.dbf",
        output / "dbc" / "dbc_bound_table.dbf",
    )
    verification = verify_dataset(result, source=source, vault=vault)
    assert verification.status is VerificationStatus.FAIL
    assert "OUTPUT_DBC_COUPLING_PRESENT" in verification.check_codes
    assert _tree_hashes(source) == source_before


def test_higher_assurance_requires_the_existing_validated_authority_binding() -> None:
    payload = _authoritative_document(PROVENANCE_MCP_VFP9SP2_TOOLCHAIN)
    document = parse_relationship_document(payload)
    report = verify_relationships(
        document,
        before={"rel-authoritative-p6005": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-authoritative-p6005": _counts([("A",)], [("A",), ("B",)])},
    )
    authoritative = authoritative_vfp_metadata_from_document(document)
    verified = derive_relational_assurance(
        authoritative.metadata,
        report,
        authority_binding=authoritative.binding,
    )
    assert verified.level is RelationalAssuranceLevel.VFP_METADATA_VERIFIED

    forged = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
        relationship_fingerprint=relationship_fingerprint(document),
        relation_count=1,
        authoritative=True,
    )
    assert (
        derive_relational_assurance(forged, report).level
        is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    )

    invalid = _authoritative_document("POLICY_FILE")
    with pytest.raises(PolicyError):
        authoritative_vfp_metadata_from_document(parse_relationship_document(invalid))
    unknown = _authoritative_document("UNKNOWN_PROVENANCE")
    with pytest.raises(PolicyError):
        parse_relationship_document(unknown)
