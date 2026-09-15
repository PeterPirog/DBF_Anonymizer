"""Typed relationship documents, canonicalization and provenance (REQ-P3-001).

Evidence for the relationship document boundary: valid single and composite
relations, deterministic canonical bytes, stable semantic fingerprints,
provenance serialization, and every fail-closed invalid-document case.
"""

from __future__ import annotations

import json

import pytest

from dbf_anonymizer import PolicyError
from dbf_anonymizer.relationships import (
    COMPARISON_EXACT_VALUE,
    COMPARISON_UNSPECIFIED,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    PROVENANCE_POLICY_FILE,
    RELATIONSHIP_METADATA_SCHEMA_VERSION,
    RelationGroup,
    RelationMember,
    canonical_relationship_bytes,
    normalize_relative_table_path,
    parse_relationship_document,
    relationship_fingerprint,
    relationship_metadata_from_document,
)

SINGLE_DOCUMENT = {
    "metadata_schema_version": "1.0",
    "relations": [
        {
            "relation_id": "rel-customer-key",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "members": [
                {
                    "table": "customers.dbf",
                    "field": "customer_id",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "C",
                    "byte_width": 8,
                    "encoding": "cp1250",
                    "nullable": False,
                },
                {
                    "table": "orders.dbf",
                    "field": "customer_id",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "C",
                    "byte_width": 8,
                    "encoding": "cp1250",
                    "nullable": True,
                },
            ],
        }
    ],
}


def _detail(excinfo: pytest.ExceptionInfo[PolicyError]) -> str:
    return str(excinfo.value) + "|" + str(excinfo.value.to_dict())


def test_valid_single_relation_document_parses() -> None:
    document = parse_relationship_document(SINGLE_DOCUMENT)
    assert document.to_dict()["metadata_schema_version"] == "1.0"
    group = document.groups[0]
    assert group.relation_id == "rel-customer-key"
    assert group.comparison == COMPARISON_EXACT_VALUE
    assert group.provenance == PROVENANCE_POLICY_FILE
    primary = group.members_for_role("PRIMARY")
    foreign = group.members_for_role("FOREIGN")
    assert primary[0].table_path == "customers.dbf"
    assert foreign[0].table_path == "orders.dbf"


def test_valid_composite_relation_document_parses() -> None:
    composite = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-device",
                "provenance": "MCP_VFP9SP2_TOOLCHAIN",
                "comparison": "EXACT_VALUE",
                "source_digest": "digest01",
                "members": [
                    {"table": "site/devices.dbf", "field": "site_code", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                    {"table": "site/devices.dbf", "field": "device_code", "role": "PRIMARY", "ordinal": 2, "dbf_type": "C", "byte_width": 6, "encoding": "cp1250", "nullable": False},
                    {"table": "logs/jobs.dbf", "field": "parent_site_code", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 8, "encoding": "cp1250", "nullable": False},
                    {"table": "logs/jobs.dbf", "field": "parent_device_code", "role": "FOREIGN", "ordinal": 2, "dbf_type": "V", "byte_width": 8, "encoding": "cp1250", "nullable": True},
                ],
            }
        ],
    }
    document = parse_relationship_document(composite)
    group = document.groups[0]
    assert len(group.members) == 4
    primary = group.members_for_role("PRIMARY")
    foreign = group.members_for_role("FOREIGN")
    assert [m.composite_ordinal for m in primary] == [1, 2]
    assert [m.composite_ordinal for m in foreign] == [1, 2]
    assert foreign[1].dbf_type == "V"


def test_document_roundtrip_and_canonicalization_is_deterministic() -> None:
    document = parse_relationship_document(SINGLE_DOCUMENT)
    # JSON roundtrip with different key order and whitespace stays identical.
    reloaded = parse_relationship_document(
        json.loads(json.dumps(SINGLE_DOCUMENT, indent=3))
    )
    assert canonical_relationship_bytes(document) == canonical_relationship_bytes(reloaded)
    # Member-list input order is irrelevant; (role, ordinal, identity) is not.
    reordered = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer-key",
                "comparison": "EXACT_VALUE",
                "provenance": "POLICY_FILE",
                "members": list(reversed(SINGLE_DOCUMENT["relations"][0]["members"])),
            }
        ],
    }
    assert canonical_relationship_bytes(
        parse_relationship_document(reordered)
    ) == canonical_relationship_bytes(document)
    # Whitespace and key order do not matter, and no whitespace leaks into
    # the canonical bytes.
    assert b" " not in canonical_relationship_bytes(document)
    assert b"\n" not in canonical_relationship_bytes(document)


def test_changed_semantic_metadata_changes_the_fingerprint() -> None:
    document = parse_relationship_document(SINGLE_DOCUMENT)
    baseline = relationship_fingerprint(document)
    altered = json.loads(json.dumps(SINGLE_DOCUMENT))
    altered["relations"][0]["members"][0]["byte_width"] = 12
    assert relationship_fingerprint(parse_relationship_document(altered)) != baseline
    swapped = json.loads(json.dumps(SINGLE_DOCUMENT))
    # Composite order is semantically significant: swapping roles/ordinals
    # must change the fingerprint.
    swapped["relations"][0]["members"][0]["table"] = "clients.dbf"
    assert relationship_fingerprint(parse_relationship_document(swapped)) != baseline
    # The (A,B) vs (B,A) composite distinction is preserved.
    composite_a = parse_relationship_document(
        json.loads(json.dumps(SINGLE_DOCUMENT))
    )
    composite_b = json.loads(json.dumps(SINGLE_DOCUMENT))
    composite_b["relations"][0]["relation_id"] = "rel-swapped"
    assert relationship_fingerprint(parse_relationship_document(composite_b)) != baseline


def test_policy_file_and_toolchain_provenance() -> None:
    policy_document = json.loads(json.dumps(SINGLE_DOCUMENT))
    policy_document["relations"][0]["provenance"] = PROVENANCE_POLICY_FILE
    document = parse_relationship_document(policy_document)
    metadata = relationship_metadata_from_document(document)
    assert metadata.provenance == "POLICY_FILE"
    toolchain_document = json.loads(json.dumps(SINGLE_DOCUMENT))
    toolchain_document["relations"][0]["provenance"] = PROVENANCE_MCP_VFP9SP2_TOOLCHAIN
    toolchain = parse_relationship_document(toolchain_document)
    metadata = relationship_metadata_from_document(toolchain)
    assert metadata.provenance == "MCP_VFP9SP2_TOOLCHAIN"
    # Provenance serialization is bounded: only normalized relative table
    # paths, field names and bounded tokens — never absolute paths.
    payload = document.groups[0].to_dict()
    assert "C:\\" not in json.dumps(payload) and "C:/" not in json.dumps(payload)
    assert metadata.relation_count == 1


def test_unsupported_document_version_fails_closed() -> None:
    for version in ("0.9", "1.1", 1.0, None):
        payload = json.loads(json.dumps(SINGLE_DOCUMENT))
        payload["metadata_schema_version"] = version
        with pytest.raises(PolicyError) as excinfo:
            parse_relationship_document(payload)
        assert "RELATIONSHIP_METADATA_VERSION_UNSUPPORTED" in _detail(excinfo)


def test_absolute_and_traversal_table_paths_rejected() -> None:
    for hostile in ("C:/abs/customers.dbf", "../customers.dbf", "C:\\abs\\customers.dbf"):
        payload = json.loads(json.dumps(SINGLE_DOCUMENT))
        payload["relations"][0]["members"][0]["table"] = hostile
        with pytest.raises(PolicyError) as excinfo:
            parse_relationship_document(payload)
        detail = _detail(excinfo)
        assert "RELATIONSHIP_TABLE_PATH_ABSOLUTE" in detail or (
            "RELATIONSHIP_TABLE_PATH_TRAVERSAL" in detail
        )
        assert hostile not in str(excinfo.value)


def test_duplicate_relation_id_rejected() -> None:
    payload = json.loads(json.dumps(SINGLE_DOCUMENT))
    payload["relations"].append(payload["relations"][0])
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_ID_DUPLICATE" in _detail(excinfo)


def test_duplicate_member_rejected() -> None:
    payload = json.loads(json.dumps(SINGLE_DOCUMENT))
    payload["relations"][0]["members"].append(payload["relations"][0]["members"][0])
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_MEMBER_DUPLICATE" in _detail(excinfo)


def test_invalid_key_role_rejected() -> None:
    payload = json.loads(json.dumps(SINGLE_DOCUMENT))
    payload["relations"][0]["members"][0]["role"] = "OWNER"
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_KEY_ROLE_INVALID" in _detail(excinfo)


@pytest.mark.parametrize(
    "ordinals",
    ([2, 2], [1, 1], [1, 3], [2], [3, 4]),
)
def test_duplicate_and_gapped_composite_ordinals_rejected(ordinals: list[int]) -> None:
    payload = json.loads(json.dumps(SINGLE_DOCUMENT))
    members = payload["relations"][0]["members"]
    members[0]["ordinal"] = ordinals[0]
    members[1]["role"] = "PRIMARY" if len(ordinals) > 1 else "FOREIGN"
    if len(ordinals) > 1:
        members[1]["ordinal"] = ordinals[1]
        # Two primary members with broken sequences are refused directly.
        payload["relations"][0]["members"][1]["role"] = "PRIMARY"
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    detail = _detail(excinfo)
    assert "RELATIONSHIP_ORDINAL_SEQUENCE_INVALID" in detail or (
        "RELATIONSHIP_MEMBER_DUPLICATE" in detail
    )


def test_arity_mismatch_rejected() -> None:
    payload = json.loads(json.dumps(SINGLE_DOCUMENT))
    payload["relations"][0]["members"].append(
        {
            "table": "extra.dbf",
            "field": "customer_id",
            "role": "PRIMARY",
            "ordinal": 2,
            "dbf_type": "C",
            "byte_width": 8,
            "encoding": "cp1250",
            "nullable": False,
        }
    )
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_ARITY_MISMATCH" in _detail(excinfo)


def test_unsupported_member_type_and_unknown_keys_rejected() -> None:
    payload = json.loads(json.dumps(SINGLE_DOCUMENT))
    payload["relations"][0]["members"][0]["dbf_type"] = "N"
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_DBF_TYPE_UNSUPPORTED" in _detail(excinfo)
    payload = json.loads(json.dumps(SINGLE_DOCUMENT))
    payload["relations"][0]["mystery"] = 1
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_GROUP_KEY_UNKNOWN" in _detail(excinfo)


def test_provenance_serialization_is_bounded() -> None:
    document = parse_relationship_document(SINGLE_DOCUMENT)
    group = document.groups[0]
    payload = json.dumps(group.to_dict())
    # Bounded serialization: only table paths, field names, roles, ordinals,
    # types, widths, encodings and provenance tokens — never absolute paths,
    # key values, vault material or secrets.
    assert "C:\\" not in payload and "C:/" not in payload
    assert "KUND" not in payload
    metadata = relationship_metadata_from_document(document)
    metadata_payload = json.dumps(metadata.to_dict())
    assert "C:\\" not in metadata_payload


def test_normalized_relative_paths() -> None:
    assert normalize_relative_table_path("data/north/customers.dbf") == "data/north/customers.dbf"
    assert normalize_relative_table_path("data\\north\\customers.dbf") == "data/north/customers.dbf"
    with pytest.raises(PolicyError):
        normalize_relative_table_path("/abs/customers.dbf")
    with pytest.raises(PolicyError):
        normalize_relative_table_path("data/../secrets.dbf")


def test_comparison_semantics_vocabulary() -> None:
    # EXACT_VALUE is the honored semantics; UNSPECIFIED is the bounded
    # representation of richer/unknown semantics (never honored as a claim).
    document = parse_relationship_document(SINGLE_DOCUMENT)
    assert document.groups[0].comparison == "EXACT_VALUE"
    assert COMPARISON_UNSPECIFIED == "UNSPECIFIED"
    unknown = json.loads(json.dumps(SINGLE_DOCUMENT))
    unknown["relations"][0]["comparison"] = "VFP_NOCASE"
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(unknown)
    assert "RELATIONSHIP_COMPARISON_INVALID" in _detail(excinfo)


def test_member_metadata_carries_declared_information() -> None:
    document = parse_relationship_document(SINGLE_DOCUMENT)
    group: RelationGroup = document.groups[0]
    member: RelationMember = group.members_for_role("PRIMARY")[0]
    assert member.byte_width == 8
    assert member.encoding == "cp1250"
    assert member.nullable is False
    assert member.dbf_type == "C"
    assert "KUND" not in json.dumps(group.to_dict())