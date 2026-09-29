"""REQ-P6-006 (revised): external VFP metadata consumer contract tests.

Every payload is synthetic, value-free and producer-independent: the
conformance payloads are constructed ONLY from the DBF_Anonymizer-owned
contract (the shipped JSON Schema + the documented public input path) -
never from, and never requiring, mcp-vfp9sp2-toolchain.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import venv
import zipfile
from copy import deepcopy
from importlib import resources
from pathlib import Path

import pytest
from dbf_anonymizer import build_plan, preflight, pseudonymize, verify_dataset
from dbf_anonymizer.errors import PolicyError
from dbf_anonymizer.models import RelationalAssuranceLevel
from dbf_anonymizer.relationships.assurance import derive_relational_assurance
from dbf_anonymizer.relationships.document import (
    authoritative_vfp_metadata_from_document,
    parse_relationship_document,
    relationship_fingerprint,
    relationship_metadata_from_document,
)
from dbf_anonymizer.relationships.external_metadata import (
    EXTERNAL_METADATA_CONTRACT_OWNER,
    EXTERNAL_METADATA_SCHEMA_RESOURCE,
    EXTERNAL_METADATA_SCHEMA_VERSION,
    load_external_metadata_schema,
)
from tests.support.numeric_tables import numeric_field

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "external_vfp_metadata"
FORBIDDEN_TOOLCHAIN_IMPORTS = ("mcp-vfp9sp2-toolchain", "vfp_toolchain", "import mcp")


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _detail(excinfo: pytest.ExceptionInfo[Exception]) -> str:
    """The typed detail carrier used by the accepted P3 test conventions."""
    return str(excinfo.value) + "|" + str(excinfo.value.to_dict())


def _counts(
    primary: tuple[tuple, ...],
    foreign: tuple[tuple, ...],
) -> object:
    """One side-pair evidence build through the SHARED count kernel."""
    from dbf_anonymizer.relationships.verification import RelationshipEvidenceAccumulator

    accumulator = RelationshipEvidenceAccumulator(composite_arity=len(primary[0]) if primary else 1)
    for key in primary:
        accumulator.observe_parent(key)
    for key in foreign:
        accumulator.observe_foreign(key)
    return accumulator.build()


def _write_conforming_dataset(source: Path) -> None:
    """The synthetic multi-table dataset referenced by the frozen fixtures."""
    from dbfbridge import write_table
    from tests.support.numeric_tables import schema

    def write(relative: str, fields: list, rows: list) -> None:
        from dbfbridge import DirectRecord

        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_table(
            destination,
            schema=schema(fields),
            records=[
                DirectRecord(physical_index=index, deleted=False, values=values)
                for index, values in enumerate(rows)
            ],
        )

    write(
        "customers/data.dbf",
        [
            numeric_field("CUST_ID", "C", 10),
            numeric_field("CUST_NAME", "C", 10),
            numeric_field("CUST_NUM", "I", 4),
        ],
        [
            {"CUST_ID": "PARENT-1", "CUST_NAME": "ALPHA", "CUST_NUM": 11},
            {"CUST_ID": "PARENT-2", "CUST_NAME": "BETA", "CUST_NUM": 22},
        ],
    )
    write(
        "orders/data.dbf",
        [
            numeric_field("ORDER_ID", "C", 10),
            numeric_field("ORDER_CUST", "C", 10),
            numeric_field("ORDER_NUM", "I", 4),
        ],
        [
            {"ORDER_ID": "O-1", "ORDER_CUST": "PARENT-1", "ORDER_NUM": 11},
            {"ORDER_ID": "O-2", "ORDER_CUST": "PARENT-2", "ORDER_NUM": 22},
        ],
    )
    write(
        "lines/data.dbf",
        [numeric_field("ORDER_REF", "C", 10), numeric_field("LINE_SEQ", "I", 4)],
        [{"ORDER_REF": "O-1", "LINE_SEQ": 1}, {"ORDER_REF": "O-2", "LINE_SEQ": 2}],
    )
    write("archive/data.dbf", [numeric_field("ARCH_KEY", "C", 8)], [{"ARCH_KEY": "A-1"}])


# ---------------------------------------------------------------------------
# 1. Shipped schema resource
# ---------------------------------------------------------------------------


def test_contract_schema_resource_shipped_and_discoverable() -> None:
    schema = load_external_metadata_schema()
    assert schema["x-contract-schema-version"] == EXTERNAL_METADATA_SCHEMA_VERSION == "1.0"
    assert schema["x-contract-owner"] == EXTERNAL_METADATA_CONTRACT_OWNER == "DBF_ANONYMIZER"
    assert schema["$schema"].startswith("https://json-schema.org/draft/")
    package_root = resources.files("dbf_anonymizer")
    assert package_root.joinpath(EXTERNAL_METADATA_SCHEMA_RESOURCE).is_file()


# ---------------------------------------------------------------------------
# 2-3. Ingestion, provenance preservation
# ---------------------------------------------------------------------------


def test_valid_authoritative_payload_accepted() -> None:
    payload = _load_fixture("valid_authoritative_relation.json")
    document = parse_relationship_document(payload)
    assert document.external_metadata_schema_version == "1.0"
    assert document.external_authority == "CONTRACT_AUTHORITATIVE"
    assert document.producer_id == "hypothetical-independent-producer"
    assert document.producer_version == "1.0.0"
    assert document.index_claims == ()
    assert document.groups[0].provenance == "EXTERNAL_VFP_METADATA"
    metadata = relationship_metadata_from_document(document)
    assert metadata.provenance == "EXTERNAL_VFP_METADATA"
    assert metadata.relation_count == 1


def test_structured_provenance_is_preserved_never_rewritten() -> None:
    payload = _load_fixture("valid_structured_provenance.json")
    document = parse_relationship_document(payload)
    assert document.producer_id == "third-party-vfp-analyzer"
    assert document.producer_version == "2.3.4"
    authoritative = authoritative_vfp_metadata_from_document(document)
    assert authoritative.metadata.provenance == "EXTERNAL_VFP_METADATA"
    assert authoritative.metadata.authoritative is True
    assert authoritative.binding.relationship_fingerprint == relationship_fingerprint(document)


def test_composite_and_index_claims_are_carried_value_free() -> None:
    composite = parse_relationship_document(_load_fixture("valid_composite_relation.json"))
    members = composite.groups[0].members
    assert [(m.table_path, m.composite_ordinal) for m in members] == [
        ("orders/data.dbf", 1),
        ("orders/data.dbf", 2),
        ("lines/data.dbf", 1),
        ("lines/data.dbf", 2),
    ]
    indexed = parse_relationship_document(_load_fixture("valid_verified_index_claim.json"))
    claim = indexed.index_claims[0]
    assert claim.claim_id == "customers-pk-cdx"
    assert claim.index_kind == "STRUCTURAL_CDX"
    assert claim.verification_state == "VERIFIED"
    assert claim.tags[0].expression == "CUST_ID"
    assert indexed.index_claims[0].provenance == "EXTERNAL_VFP_METADATA"
    unverified = parse_relationship_document(_load_fixture("valid_unverified_index_claim.json"))
    assert unverified.index_claims[0].verification_state == "UNVERIFIED"


# ---------------------------------------------------------------------------
# 4-7. Deterministic relationship fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_is_key_order_independent() -> None:
    payload = _load_fixture("valid_authoritative_relation.json")
    reordered = {
        "relations": [dict(reversed(list(rel.items()))) for rel in payload["relations"]],
        "authority": payload["authority"],
        "producer": {
            "producer_version": payload["producer"]["producer_version"],
            "producer_id": payload["producer"]["producer_id"],
        },
        "external_metadata_schema_version": payload["external_metadata_schema_version"],
        "metadata_schema_version": payload["metadata_schema_version"],
    }
    assert relationship_fingerprint(parse_relationship_document(reordered)) == (
        relationship_fingerprint(parse_relationship_document(payload))
    )


def test_canonically_equivalent_member_and_claim_order_has_same_fingerprint() -> None:
    payload = _load_fixture("valid_verified_index_claim.json")
    equivalent = deepcopy(payload)
    equivalent["relations"][0]["members"].reverse()
    equivalent["index_claims"][0]["tags"].reverse()
    assert relationship_fingerprint(parse_relationship_document(equivalent)) == (
        relationship_fingerprint(parse_relationship_document(payload))
    )


def test_semantic_relation_change_alters_fingerprint() -> None:
    payload = _load_fixture("valid_authoritative_relation.json")
    changed = deepcopy(payload)
    changed["relations"][0]["members"][0]["byte_width"] = 12
    assert relationship_fingerprint(parse_relationship_document(changed)) != (
        relationship_fingerprint(parse_relationship_document(payload))
    )


def test_authority_change_alters_fingerprint() -> None:
    payload = _load_fixture("valid_authoritative_relation.json")
    authoritative_unverified = deepcopy(payload)
    authoritative_unverified["relations"][0]["assurance"] = "UNVERIFIED"
    inferred = deepcopy(authoritative_unverified)
    inferred["authority"] = "INFERRED"
    assert relationship_fingerprint(parse_relationship_document(inferred)) != (
        relationship_fingerprint(parse_relationship_document(authoritative_unverified))
    )


def test_contract_relevant_provenance_change_is_deterministic() -> None:
    payload = _load_fixture("valid_structured_provenance.json")
    changed = deepcopy(payload)
    changed["producer"]["producer_id"] = "fourth-producer"
    first = parse_relationship_document(changed)
    again = parse_relationship_document(deepcopy(changed))
    assert relationship_fingerprint(first) == relationship_fingerprint(again)
    assert relationship_fingerprint(first) != relationship_fingerprint(
        parse_relationship_document(_load_fixture("valid_authoritative_relation.json"))
    )


def test_index_verification_state_change_alters_fingerprint() -> None:
    payload = _load_fixture("valid_verified_index_claim.json")
    changed = deepcopy(payload)
    changed["index_claims"][0]["verification_state"] = "UNVERIFIED"
    changed["index_claims"][0]["assurance"] = "UNVERIFIED"
    assert relationship_fingerprint(parse_relationship_document(changed)) != (
        relationship_fingerprint(parse_relationship_document(payload))
    )


def test_plain_document_canonical_bytes_are_unchanged() -> None:
    legacy = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "legacy-fk",
                "comparison": "EXACT_VALUE",
                "provenance": "POLICY_FILE",
                "members": [
                    {
                        "table": "north/data.dbf",
                        "field": "CODE",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                    {
                        "table": "south/data.dbf",
                        "field": "CODE",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 12,
                        "encoding": "cp1250",
                        "nullable": True,
                    },
                ],
            }
        ],
    }
    document = parse_relationship_document(legacy)
    canonical = json.dumps(
        document.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    assert document.external_metadata_schema_version is None
    assert document.external_authority is None
    assert document.index_claims == ()
    # The canonical bytes carry EXACTLY the pre-P6-006 payload: the additive
    # envelope keys are absent and the legacy fingerprint is unchanged.
    expected = json.dumps(
        {"metadata_schema_version": "1.0", "relations": document.to_dict()["relations"]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    assert canonical == expected
    assert (
        relationship_fingerprint(document) == hashlib.sha256(expected.encode("ascii")).hexdigest()
    )


# ---------------------------------------------------------------------------
# 7-13. Dataset binding and fail-closed rejections
# ---------------------------------------------------------------------------


def _build_plan_with_fixture(tmp_path: Path, name: str):
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    return build_plan(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
        relationship_document=_load_fixture(name),
    )


def test_dataset_missing_table_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as excinfo:
        _build_plan_with_fixture(tmp_path, "invalid_missing_table.json")
    assert "RELATIONSHIP_MEMBER_TABLE_UNKNOWN" in _detail(excinfo)


def test_dataset_missing_field_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as excinfo:
        _build_plan_with_fixture(tmp_path, "invalid_missing_field.json")
    assert "RELATIONSHIP_MEMBER_FIELD_UNKNOWN" in _detail(excinfo)


@pytest.mark.parametrize(
    ("fixture", "detail"),
    [
        ("invalid_unknown_version.json", "RELATIONSHIP_EXTERNAL_METADATA_VERSION_UNSUPPORTED"),
        ("invalid_malformed_producer.json", "EXTERNAL_METADATA_PRODUCER_INVALID"),
        ("invalid_missing_version.json", "RELATIONSHIP_EXTERNAL_ENVELOPE_INCOMPLETE"),
        (
            "invalid_malformed_version.json",
            "RELATIONSHIP_EXTERNAL_METADATA_VERSION_UNSUPPORTED",
        ),
        ("invalid_absolute_path.json", "RELATIONSHIP_TABLE_PATH_ABSOLUTE"),
        ("invalid_unc_path.json", "RELATIONSHIP_TABLE_PATH_ABSOLUTE"),
        ("invalid_unix_absolute_path.json", "RELATIONSHIP_TABLE_PATH_ABSOLUTE"),
        ("invalid_traversal_path.json", "RELATIONSHIP_TABLE_PATH_TRAVERSAL"),
        ("invalid_duplicate_composite_position.json", "RELATIONSHIP_ORDINAL_SEQUENCE_INVALID"),
        ("invalid_inconsistent_key_roles.json", "RELATIONSHIP_FOREIGN_SIDE_MISSING"),
        ("invalid_unsupported_comparison.json", "RELATIONSHIP_COMPARISON_INVALID"),
        (
            "invalid_authority_assurance.json",
            "EXTERNAL_METADATA_AUTHORITY_ASSURANCE_INCONSISTENT",
        ),
        (
            "invalid_unverified_index_guarantee.json",
            "EXTERNAL_METADATA_INDEX_ASSURANCE_INCONSISTENT",
        ),
        ("invalid_malformed_provenance.json", "RELATIONSHIP_PROVENANCE_INVALID"),
    ],
)
def test_fail_closed_rejections(tmp_path: Path, fixture: str, detail: str) -> None:
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    with pytest.raises(PolicyError) as excinfo:
        build_plan(
            source,
            tmp_path / "output",
            tmp_path / "vault" / "dictionary.sqlite3",
            relationship_document=_load_fixture(fixture),
        )
    assert detail in _detail(excinfo)


def test_unknown_contract_version_is_rejected_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(_load_fixture("invalid_unknown_version.json"))
    assert "RELATIONSHIP_EXTERNAL_METADATA_VERSION_UNSUPPORTED" in _detail(excinfo)
    partial = _load_fixture("valid_authoritative_relation.json")
    del partial["producer"]
    with pytest.raises(PolicyError) as partial_excinfo:
        parse_relationship_document(partial)
    assert "RELATIONSHIP_EXTERNAL_ENVELOPE_INCOMPLETE" in _detail(partial_excinfo)


# ---------------------------------------------------------------------------
# 12-16. Authoritative vs inferred grouping and assurance (end to end)
# ---------------------------------------------------------------------------


def test_authoritative_relation_drives_grouping(tmp_path: Path) -> None:
    payload = _load_fixture("valid_verified_index_claim.json")
    payload["relations"].append(
        {
            "relation_id": "numeric-fk",
            "comparison": "EXACT_VALUE",
            "provenance": "EXTERNAL_VFP_METADATA",
            "assurance": "VERIFIED",
            "numeric_strategy": "REVERSIBLE_BIJECTIVE",
            "members": [
                {
                    "table": "customers/data.dbf",
                    "field": "CUST_NUM",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
                {
                    "table": "orders/data.dbf",
                    "field": "ORDER_NUM",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
            ],
        }
    )
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    plan = build_plan(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
        relationship_document=payload,
    )
    assert plan.relationships.authoritative is True
    assert plan.relationships.provenance == "EXTERNAL_VFP_METADATA"
    assert preflight(plan).ready is True
    result = pseudonymize(plan, workers=2)
    verified = verify_dataset(
        result, source=source, vault=tmp_path / "vault" / "dictionary.sqlite3"
    )
    # Truthful production level: the read-only verifier confirms at most
    # DECLARED_RELATIONS_VERIFIED (unchanged P3-007 truthfulness); the
    # VFP_METADATA_VERIFIED capability is proven at the derivation boundary
    # (binding + complete post-transform verification report).
    assert verified.assurance.level == RelationalAssuranceLevel.VFP_METADATA_VERIFIED
    assert verified.assurance.verified_relations == verified.assurance.declared_relations


def test_inferred_relation_cannot_drive_grouping(tmp_path: Path) -> None:
    payload = _load_fixture("valid_inferred_relation.json")
    payload["relations"][0]["numeric_strategy"] = "REVERSIBLE_BIJECTIVE"
    payload["relations"][0]["members"] = [
        {
            "table": "customers/data.dbf",
            "field": "CUST_NUM",
            "role": "PRIMARY",
            "ordinal": 1,
            "dbf_type": "I",
            "byte_width": 4,
            "encoding": "none",
            "nullable": False,
        },
        {
            "table": "orders/data.dbf",
            "field": "ORDER_NUM",
            "role": "FOREIGN",
            "ordinal": 1,
            "dbf_type": "I",
            "byte_width": 4,
            "encoding": "none",
            "nullable": False,
        },
    ]
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    with pytest.raises(PolicyError) as excinfo:
        build_plan(
            source,
            tmp_path / "output",
            tmp_path / "vault" / "dictionary.sqlite3",
            relationship_document=payload,
        )
    assert "EXTERNAL_METADATA_INFERRED_GROUPING_UNSUPPORTED" in _detail(excinfo)


def test_inferred_relation_cannot_produce_vfp_metadata_verified(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    plan = build_plan(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
        relationship_document=_load_fixture("valid_inferred_relation.json"),
    )
    assert plan.relationships.authoritative is False
    assert plan.relationships.relation_count == 0
    assert preflight(plan).ready is True
    result = pseudonymize(plan, workers=2)
    verified = verify_dataset(
        result, source=source, vault=tmp_path / "vault" / "dictionary.sqlite3"
    )
    assert verified.assurance.level == RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    # Without the trusted binding the stronger level is never granted: an
    # incomplete derivation stays INCOMPLETE (no raise, no downgrade).
    summary = derive_relational_assurance(plan.relationships, None, authority_binding=None)
    assert summary.level == RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    # The INFERRED envelope can NEVER cross the authoritative ingestion
    # boundary: an inferred relationship claiming an authoritative result
    # fails closed (REQ-P6-006 revised).
    inferred_document = plan.execution_context.relationship_document
    assert inferred_document.external_authority == "INFERRED"
    with pytest.raises(PolicyError) as adapter_excinfo:
        authoritative_vfp_metadata_from_document(inferred_document)
    assert "RELATIONSHIP_AUTHORITATIVE_AUTHORITY_MISMATCH" in _detail(adapter_excinfo)


def test_authoritative_binding_with_complete_report_produces_vfp_metadata_verified(
    tmp_path: Path,
) -> None:
    from dbf_anonymizer.relationships.verification import verify_relationships

    document = parse_relationship_document(_load_fixture("valid_authoritative_relation.json"))
    authoritative = authoritative_vfp_metadata_from_document(document)
    report = verify_relationships(
        document,
        before={
            "customers-orders-fk": _counts(
                [("PARENT-1",), ("PARENT-2",)], [("PARENT-1",), ("PARENT-2",)]
            )
        },
        after={
            "customers-orders-fk": _counts(
                [("PARENT-1",), ("PARENT-2",)], [("PARENT-1",), ("PARENT-2",)]
            )
        },
    )
    summary = derive_relational_assurance(
        authoritative.metadata, report, authority_binding=authoritative.binding
    )
    # BOTH requirements met: producer-independent authoritative supplied
    # metadata/provenance (the EXTERNAL class + structured producer envelope)
    # AND successful relevant post-transform verification.
    assert summary.level == RelationalAssuranceLevel.VFP_METADATA_VERIFIED
    assert summary.relationship_fingerprint == authoritative.metadata.relationship_fingerprint


def test_vfp_metadata_verified_requires_post_transform_verification(tmp_path: Path) -> None:
    document = parse_relationship_document(_load_fixture("valid_authoritative_relation.json"))
    authoritative = authoritative_vfp_metadata_from_document(document)
    assert authoritative.metadata.authoritative is True
    # Metadata alone is NEVER verification: without the completed
    # post-transform verification report the level stays INCOMPLETE even with
    # the trusted binding.
    summary = derive_relational_assurance(
        authoritative.metadata, None, authority_binding=authoritative.binding
    )
    assert summary.level == RelationalAssuranceLevel.INCOMPLETE
    assert summary.verified_relations == 0
    assert summary.incomplete_relations == summary.declared_relations


def test_authoritative_metadata_with_failed_verification_is_not_vfp_verified() -> None:
    from dbf_anonymizer.relationships.verification import verify_relationships

    document = parse_relationship_document(_load_fixture("valid_authoritative_relation.json"))
    authoritative = authoritative_vfp_metadata_from_document(document)
    report = verify_relationships(
        document,
        before={"customers-orders-fk": _counts((("PARENT-1",),), (("PARENT-1",),))},
        after={"customers-orders-fk": _counts((("PARENT-1",),), (("ORPHAN",),))},
    )
    summary = derive_relational_assurance(
        authoritative.metadata, report, authority_binding=authoritative.binding
    )
    assert summary.level == RelationalAssuranceLevel.INCOMPLETE
    assert summary.failed_relations == 1


# ---------------------------------------------------------------------------
# 16-17. Index-claim truthfulness
# ---------------------------------------------------------------------------


def test_verified_and_unverified_index_claims_remain_truthful(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    unverified = build_plan(
        source,
        tmp_path / "output-unverified",
        tmp_path / "vault-unverified" / "dictionary.sqlite3",
        relationship_document=_load_fixture("valid_unverified_index_claim.json"),
    )
    claim = unverified.execution_context.relationship_document.index_claims[0]
    assert claim.verification_state == "UNVERIFIED"
    assert claim.index_kind == "STANDALONE_IDX"
    assert claim.verified is False
    assert unverified.execution_context.relationship_document.verified_index_claims() == ()
    # An unverified index claim can never manufacture an index-validity
    # guarantee: empty relations keep the truthful base assurance level and
    # the claim only remains planning/reporting metadata.
    assert unverified.relationships.relation_count == 0
    assert unverified.relationship_assurance_target == RelationalAssuranceLevel.INCOMPLETE
    verified_plan = build_plan(
        source,
        tmp_path / "output-verified",
        tmp_path / "vault-verified" / "dictionary.sqlite3",
        relationship_document=_load_fixture("valid_verified_index_claim.json"),
    )
    verified_claim = verified_plan.execution_context.relationship_document.index_claims[0]
    assert verified_claim.verification_state == "VERIFIED"
    assert verified_claim.verified is True
    assert verified_plan.execution_context.relationship_document.verified_index_claims() == (
        verified_claim,
    )
    # Even a VERIFIED claim alone adds no index-validity guarantee without
    # the existing index machinery; the truthful relational level is unchanged.
    assert verified_plan.relationships.relation_count == 1


# ---------------------------------------------------------------------------
# 22. Vault/operation compatibility fails closed on semantic metadata drift
# ---------------------------------------------------------------------------


def test_vault_compatibility_rejects_semantic_metadata_drift(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    plan_a = build_plan(
        source,
        tmp_path / "output",
        vault,
        relationship_document=_load_fixture("valid_authoritative_relation.json"),
    )
    assert pseudonymize(plan_a, workers=2).vault_created is True
    drifted = deepcopy(_load_fixture("valid_authoritative_relation.json"))
    drifted["relations"][0]["members"][1]["field"] = "ORDER_ID"
    plan_b = build_plan(
        source,
        tmp_path / "output-b",
        vault,
        relationship_document=drifted,
    )
    assert relationship_fingerprint(plan_b.execution_context.relationship_document) != (
        relationship_fingerprint(plan_a.execution_context.relationship_document)
    )
    findings = preflight(plan_b)
    assert findings.ready is False
    assert "VAULT_REUSE_INCOMPATIBLE" in findings.error_codes
    compatible = preflight(plan_a)
    assert "VAULT_REUSE_INCOMPATIBLE" not in compatible.error_codes


# ---------------------------------------------------------------------------
# 19. No toolchain dependency/import
# ---------------------------------------------------------------------------


def test_no_toolchain_import_or_dependency() -> None:
    import re

    package_root = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer"
    import_pattern = re.compile(
        r"^\s*(?:import|from)\s+(?:mcp|vfp_toolchain|mcp_vfp9sp2)", re.MULTILINE
    )
    for path in package_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert import_pattern.search(text) is None, (
            f"{path.name} imports the future producer package"
        )
        assert "mcp-vfp9sp2-toolchain" not in " ".join(
            line for line in text.splitlines() if line.strip().startswith(("import ", "from "))
        ), f"{path.name} imports mcp-vfp9sp2-toolchain"
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert "dbfbridge[write]>=1.1.0,<2" in pyproject
    assert '"mcp' not in pyproject
    assert "mcp-vfp9sp2" not in pyproject


# ---------------------------------------------------------------------------
# 20. Built-wheel contract
# ---------------------------------------------------------------------------


def test_external_metadata_schema_shipped_in_built_wheel(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    built = subprocess.run(  # noqa: S603 - fixed maintainer build invocation
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist)],
        cwd=str(Path(__file__).resolve().parents[1]),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert built.returncode == 0, built.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist.glob("dbf_anonymizer-*.whl"))
    assert wheels, "wheel build failed"

    with zipfile.ZipFile(wheels[-1]) as archive:
        names = archive.namelist()
        resource = f"dbf_anonymizer/{EXTERNAL_METADATA_SCHEMA_RESOURCE}".replace("\\", "/")
        assert resource in names
        shipped = json.loads(archive.read(resource).decode("utf-8"))
    assert shipped["x-contract-schema-version"] == "1.0"
    assert shipped["x-contract-owner"] == EXTERNAL_METADATA_CONTRACT_OWNER
    assert "producer" in shipped["properties"]

    source = tmp_path / "installed-wheel-source"
    _write_conforming_dataset(source)
    valid_payload = tmp_path / "valid.json"
    invalid_payload = tmp_path / "invalid.json"
    valid_payload.write_text(
        json.dumps(_load_fixture("valid_authoritative_relation.json")), encoding="utf-8"
    )
    invalid_payload.write_text(
        json.dumps(_load_fixture("invalid_unknown_version.json")), encoding="utf-8"
    )
    environment = tmp_path / "clean-wheel-environment"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(environment)
    interpreter = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = subprocess.run(  # noqa: S603 - task-owned isolated environment
        [str(interpreter), "-m", "pip", "install", "--no-deps", str(wheels[-1])],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert installed.returncode == 0, installed.stderr.decode("utf-8", errors="replace")
    probe = tmp_path / "installed_wheel_probe.py"
    probe.write_text(
        """
import json
import sys
from pathlib import Path

import dbf_anonymizer
from dbf_anonymizer import build_plan
from dbf_anonymizer.errors import PolicyError
from dbf_anonymizer.relationships import (
    load_external_metadata_schema,
    parse_relationship_document,
)

root, valid_path, invalid_path = map(Path, sys.argv[1:])
assert root in Path(dbf_anonymizer.__file__).resolve().parents
schema = load_external_metadata_schema()
assert schema["x-contract-schema-version"] == "1.0"
valid = json.loads(valid_path.read_text(encoding="utf-8"))
invalid = json.loads(invalid_path.read_text(encoding="utf-8"))
assert parse_relationship_document(valid).external_metadata_schema_version == "1.0"
try:
    parse_relationship_document(invalid)
except PolicyError:
    pass
else:
    raise AssertionError("unknown external metadata version was accepted")
plan = build_plan(
    valid_path.parent / "installed-wheel-source",
    valid_path.parent / "installed-wheel-output",
    valid_path.parent / "installed-wheel-vault" / "dictionary.sqlite3",
    relationship_document=valid,
)
assert plan.relationships.authoritative is True
assert plan.relationships.relation_count == 1
""".strip()
        + "\n",
        encoding="utf-8",
    )
    child_env = os.environ.copy()
    child_env.pop("PYTHONPATH", None)
    checked = subprocess.run(  # noqa: S603 - task-owned installed-wheel probe
        [str(interpreter), str(probe), str(environment), str(valid_payload), str(invalid_payload)],
        cwd=tmp_path,
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 21. Producer-independent downstream conformance
# ---------------------------------------------------------------------------


def test_producer_independent_downstream_conformance(tmp_path: Path) -> None:
    """A hypothetical independent future producer constructs a conforming
    payload using ONLY the documented contract and the public input surface -
    no toolchain import, checkout, fixture or runtime."""
    payload = {
        "metadata_schema_version": "1.0",
        "external_metadata_schema_version": EXTERNAL_METADATA_SCHEMA_VERSION,
        "producer": {"producer_id": "downstream-conformance-producer", "producer_version": "0.1.0"},
        "authority": "CONTRACT_AUTHORITATIVE",
        "relations": [
            {
                "relation_id": "conformance-fk",
                "comparison": "EXACT_VALUE",
                "provenance": "EXTERNAL_VFP_METADATA",
                "assurance": "VERIFIED",
                "members": [
                    {
                        "table": "customers/data.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 10,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "orders/data.dbf",
                        "field": "ORDER_CUST",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 10,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    plan = build_plan(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
        relationship_document=deepcopy(payload),
    )
    assert preflight(plan).ready is True
    assert plan.relationships.provenance == "EXTERNAL_VFP_METADATA"
    assert plan.relationships.relation_count == 1
    assert plan.relationships.authoritative is True
    reordered = {key: payload[key] for key in reversed(list(payload))}
    reordered["relations"] = [dict(reversed(list(rel.items()))) for rel in reordered["relations"]]
    assert plan.relationships.relationship_fingerprint == relationship_fingerprint(
        parse_relationship_document(deepcopy(reordered))
    )
    result = pseudonymize(plan, workers=2)
    verified = verify_dataset(
        result, source=source, vault=tmp_path / "vault" / "dictionary.sqlite3"
    )
    # Truthful production level: the read-only verifier confirms at most
    # DECLARED_RELATIONS_VERIFIED (unchanged P3-007 truthfulness); the
    # authoritative producer-independent metadata drove the declared-relation
    # verification and the binding remains available in-process.
    assert verified.assurance.level == RelationalAssuranceLevel.VFP_METADATA_VERIFIED
    assert verified.assurance.verified_relations == verified.assurance.declared_relations == 1
    assert (
        verified.assurance.relationship_fingerprint == plan.relationships.relationship_fingerprint
    )


# ---------------------------------------------------------------------------
# Fixture-level contract/schema consistency
# ---------------------------------------------------------------------------


def test_schema_resource_matches_the_contract_for_frozen_fixtures() -> None:
    schema = load_external_metadata_schema()
    assert schema["properties"]["external_metadata_schema_version"]["const"] == "1.0"
    required = set(schema["required"])
    assert required == {
        "metadata_schema_version",
        "external_metadata_schema_version",
        "producer",
        "authority",
        "relations",
    }
    valid_names = (
        "valid_authoritative_relation.json",
        "valid_composite_relation.json",
        "valid_inferred_relation.json",
        "valid_structured_provenance.json",
        "valid_unverified_index_claim.json",
        "valid_verified_index_claim.json",
    )
    for name in valid_names:
        payload = _load_fixture(name)
        document = parse_relationship_document(payload)
        assert document.external_metadata_schema_version == "1.0"
    for name in (
        "invalid_unknown_version.json",
        "invalid_missing_version.json",
        "invalid_malformed_version.json",
        "invalid_malformed_producer.json",
        "invalid_absolute_path.json",
        "invalid_unc_path.json",
        "invalid_unix_absolute_path.json",
        "invalid_traversal_path.json",
        "invalid_duplicate_composite_position.json",
        "invalid_inconsistent_key_roles.json",
        "invalid_unsupported_comparison.json",
        "invalid_authority_assurance.json",
        "invalid_unverified_index_guarantee.json",
        "invalid_malformed_provenance.json",
    ):
        with pytest.raises(PolicyError):
            parse_relationship_document(_load_fixture(name))
