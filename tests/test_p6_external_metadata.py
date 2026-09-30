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


def test_index_only_payload_accepted_and_preserves_provenance(tmp_path: Path) -> None:
    """Index-only payload (relations=[]) is valid and preserves provenance."""
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    plan = build_plan(
        source,
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
        relationship_document=_load_fixture("valid_index_only.json"),
    )
    # Schema valid and runtime accepted
    assert preflight(plan).ready is True
    # External schema version preserved
    assert plan.relationships.external_metadata_schema_version == "1.0"
    # Producer provenance preserved
    assert plan.relationships.producer_id == "index-only-producer"
    assert plan.relationships.producer_version == "1.0.0"
    # No relations, so relation_count is 0 but NOT because of MIXED provenance
    assert plan.relationships.relation_count == 0
    assert plan.relationships.provenance != "MIXED"
    # Relational assurance not upgraded
    assert plan.relationship_assurance_target == RelationalAssuranceLevel.INCOMPLETE
    # Index claims truthfulness preserved
    assert len(plan.execution_context.relationship_document.index_claims) == 2
    verified_claims = plan.execution_context.relationship_document.verified_index_claims()
    assert len(verified_claims) == 1
    assert verified_claims[0].claim_id == "customers-pk-cdx"
    unverified_claims = [
        c for c in plan.execution_context.relationship_document.index_claims if not c.verified
    ]
    assert len(unverified_claims) == 1
    assert unverified_claims[0].claim_id == "orders-idx"


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
            "authority": "CONTRACT_AUTHORITATIVE",
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
    assert "RELATIONSHIP_AUTHORITATIVE_EMPTY" in _detail(adapter_excinfo)


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
    invalid_authority_payload = tmp_path / "invalid-authority.json"
    valid_payload.write_text(
        json.dumps(_load_fixture("valid_authoritative_relation.json")), encoding="utf-8"
    )
    invalid_payload.write_text(
        json.dumps(_load_fixture("invalid_unknown_version.json")), encoding="utf-8"
    )
    inferred_verified = _load_fixture("valid_authoritative_relation.json")
    inferred_verified["relations"][0]["authority"] = "INFERRED"
    invalid_authority_payload.write_text(json.dumps(inferred_verified), encoding="utf-8")
    acceptance_pin = (
        (Path(__file__).resolve().parents[1] / "requirements" / "p0-dbfbridge-tested.txt")
        .read_text(encoding="utf-8")
        .strip()
        .splitlines()[-1]
        .strip()
    )
    assert acceptance_pin.startswith("dbfbridge[write]==")
    environment = tmp_path / "clean-wheel-environment"
    # GENUINELY isolated child venv: NO system-site-packages inheritance, so
    # neither the parent's dbfbridge nor the repository source can leak in.
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
    interpreter = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    child_pip = [str(interpreter), "-m", "pip", "install", "--no-cache-dir"]
    for command in (
        [*child_pip, acceptance_pin],
        [*child_pip, "jsonschema>=4.21"],
        [*child_pip, "--no-deps", str(wheels[-1])],
    ):
        installed = subprocess.run(  # noqa: S603 - task-owned isolated environment
            command,
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
import dbfbridge
from dbf_anonymizer import build_plan
from dbf_anonymizer.errors import PolicyError
from dbf_anonymizer.relationships import (
    load_external_metadata_schema,
    parse_relationship_document,
)
from jsonschema import Draft202012Validator

root, valid_path, invalid_path, invalid_authority_path = map(Path, sys.argv[1:])

# Import-origin proof: BOTH packages resolve from the child venv
# site-packages (never the repository checkout, never the parent env).
for module in (dbf_anonymizer, dbfbridge):
    origin = Path(module.__file__).resolve()
    lowered = {part.lower() for part in origin.parts}
    assert lowered & {"site-packages", "dist-packages"}, origin
    assert root.resolve() in origin.parents, origin
assert dbfbridge.__version__ == "1.1.1", dbfbridge.__version__
assert not any(
    entry and "DBF_Anonymizer" in str(Path(entry).resolve())
    for entry in sys.path
    if entry
), sys.path

# The schema loads from the INSTALLED wheel and is a valid Draft 2020-12
# schema usable as a real validation oracle.
schema = load_external_metadata_schema()
assert schema["x-contract-schema-version"] == "1.0"
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)

valid = json.loads(valid_path.read_text(encoding="utf-8"))
invalid = json.loads(invalid_path.read_text(encoding="utf-8"))
invalid_authority = json.loads(invalid_authority_path.read_text(encoding="utf-8"))

# Schema-oracle decisions on the installed artifact.
assert validator.is_valid(valid) is True
assert validator.is_valid(invalid) is False
assert validator.is_valid(invalid_authority) is False

# Runtime decisions agree with the schema (producer-independent contract).
assert parse_relationship_document(valid).external_metadata_schema_version == "1.0"
for hostile in (invalid, invalid_authority):
    try:
        parse_relationship_document(hostile)
    except PolicyError:
        pass
    else:
        raise AssertionError("hostile external metadata was accepted")

plan = build_plan(
    valid_path.parent / "installed-wheel-source",
    valid_path.parent / "installed-wheel-output",
    valid_path.parent / "installed-wheel-vault" / "dictionary.sqlite3",
    relationship_document=valid,
)
assert plan.relationships.authoritative is True
assert plan.relationships.relation_count == 1
assert plan.relationships.external_metadata_schema_version == "1.0"
serialized = plan.to_dict()["relationships"]
assert serialized["external_metadata_schema_version"] == "1.0"
assert serialized["producer"]["producer_id"] == "hypothetical-independent-producer"
assert serialized["producer"]["producer_version"] == "1.0.0"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    child_env = os.environ.copy()
    child_env.pop("PYTHONPATH", None)
    checked = subprocess.run(  # noqa: S603 - task-owned installed-wheel probe
        [
            str(interpreter),
            str(probe),
            str(environment),
            str(valid_payload),
            str(invalid_payload),
            str(invalid_authority_payload),
        ],
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
                "authority": "CONTRACT_AUTHORITATIVE",
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


# ---------------------------------------------------------------------------
# REAL Draft 2020-12 schema validation (the shipped schema is the oracle)
# ---------------------------------------------------------------------------


def _draft_validator():
    from jsonschema import Draft202012Validator

    schema = load_external_metadata_schema()
    # Meta-validation: the shipped schema must be a valid Draft 2020-12
    # schema BEFORE it is used as an oracle (not merely loadable JSON).
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_shipped_schema_is_a_valid_draft_2020_12_schema() -> None:
    """Meta-validation, $ref resolvability and pattern compilability."""
    schema = load_external_metadata_schema()
    _draft_validator()  # check_schema must pass (raises otherwise)
    # Every $ref must resolve against the ROOT document ($defs at root scope).
    definitions = schema.get("$defs") or {}
    assert definitions, "$defs must exist at the schema root scope"
    refs: list[str] = []

    def _collect(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str):
                    refs.append(value)
                _collect(value)
        elif isinstance(node, list):
            for item in node:
                _collect(item)

    _collect(schema)
    assert refs, "the contract schema must use $defs references"
    for ref in refs:
        assert ref.startswith("#/$defs/"), f"non-local reference: {ref}"
        assert ref.rsplit("/", 1)[-1] in definitions, f"unresolvable reference: {ref}"
    # Every pattern must be a usable regular expression for the validator.
    patterns: list[str] = []

    def _collect_patterns(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "pattern" and isinstance(value, str):
                    patterns.append(value)
                _collect_patterns(value)
        elif isinstance(node, list):
            for item in node:
                _collect_patterns(item)

    _collect_patterns(schema)
    assert patterns, "the contract schema constrains tokens with patterns"
    import re

    for pattern in patterns:
        re.compile(pattern)


# ---------------------------------------------------------------------------
# Schema/runtime parity matrix over the frozen fixtures
# ---------------------------------------------------------------------------
#
# Canonical semantics (documented in docs/external-vfp-metadata-contract.md):
# TIER 1 - every single-claim syntactic constraint must accept EXACTLY the
#          same payloads on both sides (schema ACCEPT <=> runtime ACCEPT).
# TIER 2 - cross-claim structural rules (identity/ordinal/arity consistency)
#          and dataset-reference validation are runtime-only (JSON Schema
#          cannot express them); the runtime is a fail-closed superset: it
#          never accepts a payload the schema rejects.

_TIER1_REJECTED: dict[str, str] = {
    "invalid_unknown_version.json": "RELATIONSHIP_EXTERNAL_METADATA_VERSION_UNSUPPORTED",
    "invalid_malformed_version.json": "RELATIONSHIP_EXTERNAL_METADATA_VERSION_UNSUPPORTED",
    "invalid_missing_version.json": "RELATIONSHIP_EXTERNAL_ENVELOPE_INCOMPLETE",
    "invalid_malformed_producer.json": "EXTERNAL_METADATA_PRODUCER_INVALID",
    "invalid_malformed_provenance.json": "RELATIONSHIP_PROVENANCE_INVALID",
    "invalid_unsupported_comparison.json": "RELATIONSHIP_COMPARISON_INVALID",
    "invalid_absolute_path.json": "RELATIONSHIP_TABLE_PATH_ABSOLUTE",
    "invalid_unc_path.json": "RELATIONSHIP_TABLE_PATH_ABSOLUTE",
    "invalid_unix_absolute_path.json": "RELATIONSHIP_TABLE_PATH_ABSOLUTE",
    "invalid_traversal_path.json": "RELATIONSHIP_TABLE_PATH_TRAVERSAL",
    "invalid_authority_assurance.json": "EXTERNAL_METADATA_AUTHORITY_ASSURANCE_INCONSISTENT",
    "invalid_unverified_index_guarantee.json": "EXTERNAL_METADATA_INDEX_ASSURANCE_INCONSISTENT",
    "invalid_policy_file_authoritative.json": (
        "EXTERNAL_METADATA_RELATION_PROVENANCE_INAUTHORITATIVE"
    ),
    "invalid_policy_file_index_authoritative.json": (
        "EXTERNAL_METADATA_INDEX_PROVENANCE_INAUTHORITATIVE"
    ),
}
_TIER2_PARSE_REJECTED: dict[str, str] = {
    "invalid_duplicate_composite_position.json": "RELATIONSHIP_ORDINAL_SEQUENCE_INVALID",
    "invalid_inconsistent_key_roles.json": "RELATIONSHIP_FOREIGN_SIDE_MISSING",
}
_TIER2_DATASET_REJECTED: dict[str, str] = {
    "invalid_missing_table.json": "RELATIONSHIP_MEMBER_TABLE_UNKNOWN",
    "invalid_missing_field.json": "RELATIONSHIP_MEMBER_FIELD_UNKNOWN",
}
_VALID_FIXTURES: tuple[str, ...] = (
    "valid_authoritative_relation.json",
    "valid_composite_relation.json",
    "valid_index_only.json",
    "valid_inferred_relation.json",
    "valid_policy_file_planning.json",
    "valid_structured_provenance.json",
    "valid_unverified_index_claim.json",
    "valid_verified_index_claim.json",
)
#: The documented RUNTIME-ONLY rule codes (Tier 2): genuinely cross-claim or
#: inspected-dataset-dependent rules that JSON Schema cannot express.  A Tier-2
#: classification may only use these codes, so Tier 2 can never silently
#: absorb a schema-expressible single-claim constraint (Tier 1).
_RUNTIME_ONLY_RULE_CODES = frozenset(
    {
        "RELATIONSHIP_ORDINAL_SEQUENCE_INVALID",
        "RELATIONSHIP_FOREIGN_SIDE_MISSING",
        "RELATIONSHIP_MEMBER_TABLE_UNKNOWN",
        "RELATIONSHIP_MEMBER_FIELD_UNKNOWN",
    }
)


def test_tier2_classification_cannot_absorb_schema_expressible_constraints() -> None:
    """Every Tier-2 rejection must be a documented runtime-only rule."""
    for code in (*_TIER2_PARSE_REJECTED.values(), *_TIER2_DATASET_REJECTED.values()):
        assert code in _RUNTIME_ONLY_RULE_CODES, code
    # No Tier-1 (schema-expressible) refusal may be reclassified as Tier 2.
    for code in _TIER1_REJECTED.values():
        assert code not in _RUNTIME_ONLY_RULE_CODES, code


# ---------------------------------------------------------------------------
# PUBLIC-INGESTION parity: schema, parser AND public build_plan must decide
# every provenance-eligibility case identically (three independent oracles)
# ---------------------------------------------------------------------------


def test_public_ingestion_provenance_eligibility_parity(tmp_path: Path) -> None:
    """POLICY_FILE provenance can never claim authoritative VFP strength.

    The complete public ingestion path (not only the parser) must agree with
    the shipped schema: a POLICY_FILE claim claiming CONTRACT_AUTHORITATIVE +
    VERIFIED strength is schema-REJECTED, parser-REJECTED and rejected by the
    PUBLIC build_plan ingestion; a NON-authoritative POLICY_FILE claim
    (CONTRACT_AUTHORITATIVE + UNVERIFIED) remains schema-valid and is accepted
    as planning/reporting information without any authoritative binding.
    """
    validator = _draft_validator()
    authoritative_claiming = deepcopy(_load_fixture("invalid_policy_file_authoritative.json"))

    # 1. Draft 2020-12 schema oracle: REJECT.
    assert validator.is_valid(deepcopy(authoritative_claiming)) is False

    # 2. Runtime parser oracle: typed fail-closed rejection.
    with pytest.raises(PolicyError) as parse_excinfo:
        parse_relationship_document(deepcopy(authoritative_claiming))
    assert "EXTERNAL_METADATA_RELATION_PROVENANCE_INAUTHORITATIVE" in _detail(parse_excinfo)

    # 3. PUBLIC ingestion oracle (build_plan): REJECT — the parser refusal
    #    propagates fail closed before any binding is minted.
    source = tmp_path / "source"
    _write_conforming_dataset(source)
    with pytest.raises(PolicyError) as plan_excinfo:
        build_plan(
            source,
            tmp_path / "output",
            tmp_path / "vault" / "dictionary.sqlite3",
            relationship_document=deepcopy(authoritative_claiming),
        )
    assert "EXTERNAL_METADATA_RELATION_PROVENANCE_INAUTHORITATIVE" in _detail(plan_excinfo)

    # 4. RETAINED: a NON-authoritative POLICY_FILE claim stays schema-valid
    #    and is accepted as planning/reporting information (no binding, no
    #    authoritative metadata, index claims remain the only carriers).
    retained = deepcopy(_load_fixture("valid_policy_file_planning.json"))
    assert validator.is_valid(deepcopy(retained)) is True
    document = parse_relationship_document(deepcopy(retained))
    assert document.groups[0].claim_authority == "CONTRACT_AUTHORITATIVE"
    assert document.groups[0].claim_assurance == "UNVERIFIED"
    assert document.groups[0].provenance == "POLICY_FILE"
    # The claim is NOT effective: no authoritative grouping, no binding.
    assert document.effective_groups() == ()
    retained_plan = build_plan(
        source,
        tmp_path / "retained-output",
        tmp_path / "retained-vault" / "dictionary.sqlite3",
        relationship_document=deepcopy(retained),
    )
    assert preflight(retained_plan).ready is True
    assert retained_plan.relationships.authoritative is False
    assert retained_plan.relationships.relation_count == 0
    assert retained_plan.relationships.external_metadata_schema_version == "1.0"


def test_frozen_fixture_schema_runtime_parity_matrix(tmp_path: Path) -> None:
    """SCHEMA decision == RUNTIME decision for every expressible constraint."""
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    validator = _draft_validator()
    all_fixtures = sorted(path.name for path in FIXTURES.glob("*.json"))
    classified = (
        set(_TIER1_REJECTED)
        | set(_TIER2_PARSE_REJECTED)
        | set(_TIER2_DATASET_REJECTED)
        | set(_VALID_FIXTURES)
    )
    assert set(all_fixtures) == classified, "every frozen fixture must stay classified"
    for name in all_fixtures:
        payload = _load_fixture(name)
        schema_accepts = validator.is_valid(deepcopy(payload))
        if name in _VALID_FIXTURES:
            assert schema_accepts is True, f"{name}: fixture must be schema-VALID"
            document = parse_relationship_document(deepcopy(payload))
            assert document.external_metadata_schema_version == "1.0"
        elif name in _TIER1_REJECTED:
            assert schema_accepts is False, f"{name}: fixture must be schema-INVALID"
            with pytest.raises(PolicyError) as excinfo:
                parse_relationship_document(deepcopy(payload))
            assert _TIER1_REJECTED[name] in _detail(excinfo)
        elif name in _TIER2_PARSE_REJECTED:
            # Runtime-only structural rule (cross-claim; not expressible in
            # JSON Schema): schema accepts, runtime fails closed.
            assert schema_accepts is True, f"{name}: Tier-2 fixture is schema-valid"
            with pytest.raises(PolicyError) as excinfo:
                parse_relationship_document(deepcopy(payload))
            assert _TIER2_PARSE_REJECTED[name] in _detail(excinfo)
        else:
            # Dataset-dependent semantic validation after schema validation.
            assert schema_accepts is True, f"{name}: Tier-2 fixture is schema-valid"
            _write_conforming_dataset(tmp_path / name / "source")
            with pytest.raises(PolicyError) as excinfo:
                build_plan(
                    tmp_path / name / "source",
                    tmp_path / name / "output",
                    tmp_path / name / "vault" / "dictionary.sqlite3",
                    relationship_document=deepcopy(payload),
                )
            assert _TIER2_DATASET_REJECTED[name] in _detail(excinfo)


# ---------------------------------------------------------------------------
# Adversarial schema/runtime parity cases
# ---------------------------------------------------------------------------


def _adversarial_base() -> dict:
    return deepcopy(_load_fixture("valid_authoritative_relation.json"))


_ADVERSARIAL_CASES: tuple[tuple[str, dict, bool, str | None], ...] = (
    # (name, payload, schema_accepts, runtime_detail_code_or_None)
    (
        "per_claim_authority_overrides_inferred_envelope",
        {**_adversarial_base(), "authority": "INFERRED"},
        True,
        None,
    ),
    (
        "claim_inferred_but_verified",
        {
            **_adversarial_base(),
            "relations": [{**_adversarial_base()["relations"][0], "authority": "INFERRED"}],
        },
        False,
        "EXTERNAL_METADATA_AUTHORITY_ASSURANCE_INCONSISTENT",
    ),
    (
        "inferred_index_claim_claiming_verified",
        {
            **deepcopy(_load_fixture("valid_verified_index_claim.json")),
            "index_claims": [
                {
                    **_load_fixture("valid_verified_index_claim.json")["index_claims"][0],
                    "authority": "INFERRED",
                }
            ],
        },
        False,
        "EXTERNAL_METADATA_AUTHORITY_ASSURANCE_INCONSISTENT",
    ),
    (
        "future_contract_version",
        {**_adversarial_base(), "external_metadata_schema_version": "1.1"},
        False,
        "RELATIONSHIP_EXTERNAL_METADATA_VERSION_UNSUPPORTED",
    ),
    (
        "producer_token_overlong",
        {
            **_adversarial_base(),
            "producer": {"producer_id": "x" * 65, "producer_version": "1"},
        },
        False,
        "EXTERNAL_METADATA_PRODUCER_ID_INVALID",
    ),
    (
        "expression_drive_path",
        {
            **deepcopy(_load_fixture("valid_verified_index_claim.json")),
            "index_claims": [
                {
                    **_load_fixture("valid_verified_index_claim.json")["index_claims"][0],
                    "tags": [
                        {"name": "CUST_ID", "sort_order": "ASCENDING", "expression": "C:/private"}
                    ],
                }
            ],
        },
        False,
        "EXTERNAL_METADATA_INDEX_EXPRESSION_INVALID",
    ),
    (
        "expression_parent_traversal",
        {
            **deepcopy(_load_fixture("valid_verified_index_claim.json")),
            "index_claims": [
                {
                    **_load_fixture("valid_verified_index_claim.json")["index_claims"][0],
                    "tags": [
                        {"name": "CUST_ID", "sort_order": "ASCENDING", "expression": "a/../b"}
                    ],
                }
            ],
        },
        False,
        "EXTERNAL_METADATA_INDEX_EXPRESSION_INVALID",
    ),
    (
        "backslash_relative_table_identity",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "table": "data\\customers.dbf",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_TABLE_PATH_INVALID",
    ),
    (
        "overlong_table_identity",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "table": "d/" + "x" * 252 + ".dbf",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_TABLE_PATH_INVALID",
    ),
    (
        "illegal_table_identity_characters",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "table": "data$/x.dbf",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_TABLE_PATH_INVALID",
    ),
    (
        "empty_path_segment",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "table": "data//x.dbf",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_TABLE_PATH_INVALID",
    ),
    (
        "dot_path_segment",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "table": "data/./x.dbf",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_TABLE_PATH_TRAVERSAL",
    ),
    (
        "table_identity_without_dbf_suffix",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "table": "customers/data.dat",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_TABLE_PATH_INVALID",
    ),
    (
        "index_policy_file_authoritative_claim",
        {
            **deepcopy(_load_fixture("valid_verified_index_claim.json")),
            "index_claims": [
                {
                    **_load_fixture("valid_verified_index_claim.json")["index_claims"][0],
                    "provenance": "POLICY_FILE",
                }
            ],
        },
        False,
        "EXTERNAL_METADATA_INDEX_PROVENANCE_INAUTHORITATIVE",
    ),
    (
        "index_file_suffix_kind_mismatch",
        {
            **deepcopy(_load_fixture("valid_unverified_index_claim.json")),
            "index_claims": [
                {
                    **_load_fixture("valid_unverified_index_claim.json")["index_claims"][0],
                    "index_file": "archive/data.txt",
                }
            ],
        },
        False,
        "EXTERNAL_METADATA_INDEX_PATH_KIND_MISMATCH",
    ),
    (
        "integer_member_wrong_width",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "dbf_type": "I",
                            "byte_width": 5,
                            "encoding": "none",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_INTEGER_WIDTH_INVALID",
    ),
    (
        "numeric_member_overlong_width",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "dbf_type": "N",
                            "byte_width": 21,
                            "encoding": "none",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_NUMERIC_WIDTH_INVALID",
    ),
    (
        "numeric_member_text_encoding",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "dbf_type": "I",
                            "encoding": "cp1250",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_NUMERIC_ENCODING_INVALID",
    ),
    (
        "uppercase_member_encoding_accepted",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            **_adversarial_base()["relations"][0]["members"][0],
                            "encoding": "CP1250",
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        True,
        None,
    ),
    (
        "extra_top_level_key",
        {**_adversarial_base(), "extra": "x"},
        False,
        "RELATIONSHIP_DOCUMENT_KEY_UNKNOWN",
    ),
    (
        "extra_producer_key",
        {
            **_adversarial_base(),
            "producer": {"producer_id": "p", "producer_version": "1", "note": "x"},
        },
        False,
        "EXTERNAL_METADATA_PRODUCER_KEY_UNKNOWN",
    ),
    (
        "extra_relation_key",
        {
            **_adversarial_base(),
            "relations": [{**_adversarial_base()["relations"][0], "weight": 1}],
        },
        False,
        "RELATIONSHIP_GROUP_KEY_UNKNOWN",
    ),
    (
        "extra_member_key",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {**_adversarial_base()["relations"][0]["members"][0], "weight": 1},
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_MEMBER_KEY_UNKNOWN",
    ),
    (
        "extra_index_claim_key",
        {
            **deepcopy(_load_fixture("valid_index_only.json")),
            "index_claims": [
                {**_load_fixture("valid_index_only.json")["index_claims"][0], "weight": 1}
            ],
        },
        False,
        "EXTERNAL_METADATA_INDEX_CLAIM_KEY_INVALID",
    ),
    (
        "missing_required_member_key",
        {
            **_adversarial_base(),
            "relations": [
                {
                    **_adversarial_base()["relations"][0],
                    "members": [
                        {
                            key: value
                            for key, value in _adversarial_base()["relations"][0]["members"][
                                0
                            ].items()
                            if key != "field"
                        },
                        *_adversarial_base()["relations"][0]["members"][1:],
                    ],
                }
            ],
        },
        False,
        "RELATIONSHIP_MEMBER_KEY_MISSING",
    ),
)


@pytest.mark.parametrize(
    ("name", "payload", "schema_accepts", "runtime_code"),
    list(_ADVERSARIAL_CASES),
    ids=[case[0] for case in _ADVERSARIAL_CASES],
)
def test_schema_runtime_adversarial_parity(
    name: str, payload: dict, schema_accepts: bool, runtime_code: str | None
) -> None:
    """The shipped schema and the runtime decide EVERY case identically."""
    validator = _draft_validator()
    assert validator.is_valid(deepcopy(payload)) is schema_accepts, name
    if runtime_code is None:
        parse_relationship_document(deepcopy(payload))  # must ACCEPT
    else:
        with pytest.raises(PolicyError) as excinfo:
            parse_relationship_document(deepcopy(payload))
        assert runtime_code in _detail(excinfo)
