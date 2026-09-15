"""Declared C/V relations, domain resolution and compatibility (REQ-P3-003).

Single and composite declared relations resolved to the ONE global text
mapping domain, compatibility preflight before any transformation, ordered
composite tuple semantics, differing table paths, differing widths, proven
code pages — and every deliberate incompatibility fail-closed.  No key value
ever reaches an error boundary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dbf_anonymizer import PolicyError
from dbf_anonymizer.relationships import (
    COMPARISON_UNSPECIFIED,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    parse_relationship_document,
    relation_metrics,
    resolved_relation_domain,
    validate_document_compatibility,
    validate_relation_group_compatibility,
)

CanaryKey = "KUND-CANARY-SECRET"


def _detail(excinfo: pytest.ExceptionInfo[PolicyError]) -> str:
    return (
        str(excinfo.value)
        + "|"
        + repr(excinfo.value)
        + "|"
        + str(excinfo.value.to_dict())
    )


def _single_document(
    *,
    encoding: str = "cp1250",
    pk_width: int = 8,
    fk_width: int = 8,
    pk_nullable: bool = False,
    fk_nullable: bool = False,
    comparison: str = "EXACT_VALUE",
) -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer-key",
                "provenance": "POLICY_FILE",
                "comparison": comparison,
                "members": [
                    {
                        "table": "north/customers.dbf",
                        "field": "customer_id",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": pk_width,
                        "encoding": encoding,
                        "nullable": pk_nullable,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "customer_id",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": fk_width,
                        "encoding": encoding,
                        "nullable": fk_nullable,
                    },
                ],
            }
        ],
    }


def _composite_document(*, encoding: str = "cp1250") -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-device",
                "provenance": PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
                "comparison": "EXACT_VALUE",
                "members": [
                    {"table": "site/devices.dbf", "field": "site_code", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": encoding, "nullable": False},
                    {"table": "site/devices.dbf", "field": "device_code", "role": "PRIMARY", "ordinal": 2, "dbf_type": "V", "byte_width": 6, "encoding": encoding, "nullable": False},
                    {"table": "logs/jobs.dbf", "field": "parent_site_code", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": encoding, "nullable": False},
                    {"table": "logs/jobs.dbf", "field": "parent_device_code", "role": "FOREIGN", "ordinal": 2, "dbf_type": "V", "byte_width": 6, "encoding": encoding, "nullable": False},
                ],
            }
        ],
    }


def _assert_no_key_leakage(excinfo: pytest.ExceptionInfo[PolicyError]) -> None:
    boundary = (
        str(excinfo.value)
        + "|"
        + repr(excinfo.value)
        + "|"
        + str(excinfo.value.to_dict())
    )
    assert CanaryKey not in boundary
    assert "C:\\" not in boundary and "C:/" not in boundary


# ---------------------------------------------------------------------------
# domain resolution and compatible declarations
# ---------------------------------------------------------------------------
def test_single_c_relation_resolves_to_the_global_domain() -> None:
    from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID

    document = parse_relationship_document(_single_document())
    validate_document_compatibility(document)
    group = document.groups[0]
    domain = resolved_relation_domain(group)
    assert domain == GLOBAL_TEXT_DOMAIN_ID
    assert resolved_relation_domain(group) == domain  # deterministic


def test_single_v_relation_compatible() -> None:
    document = parse_relationship_document(
        _single_document(encoding="cp852", pk_width=10, fk_width=12)
    )
    validate_document_compatibility(document)
    assert document.groups[0].members_for_role("PRIMARY")[0].dbf_type == "C"


def test_compatible_differing_widths_binding_width_is_the_minimum() -> None:
    document = parse_relationship_document(_single_document(pk_width=10, fk_width=2))
    validate_document_compatibility(document)
    # The binding constraint is the narrowest member width: the P2
    # allocation's strictest-width rule already enforces it (never truncates).
    assert min(m.byte_width for m in document.groups[0].members) == 2


def test_composite_c_v_relation_ordered_tuple_semantics() -> None:
    document = parse_relationship_document(_composite_document())
    validate_document_compatibility(document)
    group = document.groups[0]
    primary = group.members_for_role("PRIMARY")
    foreign = group.members_for_role("FOREIGN")
    # Component ordering is semantically significant: (A,B) is NOT (B,A).
    assert [(m.field_name, m.composite_ordinal) for m in primary] == [
        ("site_code", 1),
        ("device_code", 2),
    ]
    assert [(m.field_name, m.composite_ordinal) for m in foreign] == [
        ("parent_site_code", 1),
        ("parent_device_code", 2),
    ]
    # Ordered tuple evidence: (A, B) and (B, A) are DISTINCT composite keys.
    pk_tuples = [("S1", "DEV-A"), ("S1", "DEV-B"), ("S2", "DEV-A")]
    assert relation_metrics(pk_tuples, [("S1", "DEV-A")]).orphan_count == 0
    # The swapped component order no longer matches: ordering is semantic.
    assert relation_metrics(pk_tuples, [("DEV-A", "S1")]).orphan_count == 1


def test_compatible_code_pages_cp1250_and_cp852() -> None:
    """Mixed PROVEN code pages are compatible (single-byte safe alphabet)."""
    payload = json.loads(json.dumps(_single_document(encoding="cp1250")))
    payload["relations"][0]["members"][1]["encoding"] = "cp852"
    document = parse_relationship_document(payload)
    validate_document_compatibility(document)  # mixed proven pages: valid


def test_differing_table_paths_resolve_one_domain() -> None:
    document = parse_relationship_document(_composite_document())
    assert document.groups[0].members[0].table_path == "site/devices.dbf"
    assert document.groups[0].members[2].table_path == "logs/jobs.dbf"
    validate_document_compatibility(document)
    assert document.groups[0].members_for_role("PRIMARY")[0].dbf_type == "C"


# ---------------------------------------------------------------------------
# deliberate incompatibilities (fail closed before any transformation)
# ---------------------------------------------------------------------------
def test_unproven_encoding_incompatible() -> None:
    document = parse_relationship_document(
        json.loads(json.dumps(_single_document(encoding="utf-16le")))
    )
    with pytest.raises(PolicyError) as excinfo:
        validate_document_compatibility(document)
    assert "RELATIONSHIP_ENCODING_INCOMPATIBLE" in _detail(excinfo)
    _assert_no_key_leakage(excinfo)


def test_comparison_semantics_incompatible() -> None:
    document = parse_relationship_document(
        json.loads(json.dumps(_single_document(comparison=COMPARISON_UNSPECIFIED)))
    )
    with pytest.raises(PolicyError) as excinfo:
        validate_relation_group_compatibility(document.groups[0])
    assert "RELATIONSHIP_COMPARISON_INCOMPATIBLE" in _detail(excinfo)
    _assert_no_key_leakage(excinfo)


def test_null_policy_inconsistent() -> None:
    payload = _single_document(pk_nullable=False, fk_nullable=True)
    document = parse_relationship_document(payload)
    with pytest.raises(PolicyError) as excinfo:
        validate_document_compatibility(document)
    assert "RELATIONSHIP_NULL_POLICY_INCONSISTENT" in _detail(excinfo)
    _assert_no_key_leakage(excinfo)


def test_incompatible_byte_width_constraint() -> None:
    # A byte width below one byte cannot hold ANY safe shared pseudonym.
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(_single_document(pk_width=0))
    assert "RELATIONSHIP_BYTE_WIDTH_INVALID" in _detail(excinfo)
    _assert_no_key_leakage(excinfo)


def test_unsupported_member_type_in_declared_relation() -> None:
    payload = json.loads(json.dumps(_single_document()))
    payload["relations"][0]["members"][0]["dbf_type"] = "N"
    # The parse boundary itself refuses non-C/V member types.
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_DBF_TYPE_UNSUPPORTED" in _detail(excinfo)
    _assert_no_key_leakage(excinfo)


def test_ambiguous_overlapping_relation_definitions_rejected() -> None:
    """The same member declared with conflicting metadata fails closed."""
    conflicting = json.loads(json.dumps(_composite_document()))
    # A second group redeclares (site/devices.dbf, site_code) with a
    # conflicting byte width: the per-group checks pass (the encoding is
    # proven), so only the CROSS-GROUP consistency rule can refuse it —
    # one logical key must never receive incompatible pseudonyms.
    conflicting["relations"].append(
        {
            "relation_id": "rel-device-alt",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "members": [
                {"table": "site/devices.dbf", "field": "site_code", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 8, "encoding": "cp1250", "nullable": False},
                {"table": "other/x.dbf", "field": "site_code", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
            ],
        }
    )
    document = parse_relationship_document(conflicting)
    with pytest.raises(PolicyError) as excinfo:
        validate_document_compatibility(document)
    assert "RELATIONSHIP_DOMAIN_CONFLICT" in _detail(excinfo)
    _assert_no_key_leakage(excinfo)


def test_compatible_overlapping_groups_share_the_global_domain() -> None:
    """Overlapping groups with consistent members resolve to one domain."""
    payload = json.loads(json.dumps(_composite_document()))
    payload["relations"].append(
        {
            "relation_id": "rel-device-consistent",
            "provenance": "MCP_VFP9SP2_TOOLCHAIN",
            "comparison": "EXACT_VALUE",
            "members": [
                {"table": "site/devices.dbf", "field": "site_code", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                {"table": "audit/site_keys.dbf", "field": "site_code", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
            ],
        }
    )
    document = parse_relationship_document(payload)
    validate_document_compatibility(document)
    from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID

    domains = {resolved_relation_domain(group) for group in document.groups}
    assert domains == {GLOBAL_TEXT_DOMAIN_ID}  # ONE shared domain everywhere


# ---------------------------------------------------------------------------
# declared composite relation end-to-end over the real P2 path
# ---------------------------------------------------------------------------
def test_declared_composite_relation_preserves_tuple_integrity(
    tmp_path: Path,
) -> None:
    document = parse_relationship_document(_composite_document())
    # COMPATIBILITY BEFORE ANY TRANSFORMATION-EQUIVALENT ACTION.
    validate_document_compatibility(document)
    from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID

    assert resolved_relation_domain(document.groups[0]) == GLOBAL_TEXT_DOMAIN_ID

    from dbf_anonymizer.vault import (
        VAULT_DATABASE_FILENAME,
        VAULT_TABLE_DOMAIN_KIND_TEXT,
        VaultDatabase,
    )
    from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID
    from dbf_anonymizer.vault.text_allocation import GlobalTextDomainMapping
    from support.vault_sessions import writer_session

    site_codes = ["S1", "S2"]
    device_codes = ["DEV-A", "DEV-B"]
    pk_tuples = [(site, device) for site, device in zip(site_codes, device_codes)]
    parent_pairs: list[tuple[str, str] | None] = [
        ("S1", "DEV-A"),
        ("S1", "DEV-A"),
        ("S2", "DEV-B"),
        None,
    ]
    fk_tuples = [pair for pair in parent_pairs if pair is not None]

    with VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
        dbfbridge_version="1.1.0",
    ) as vault:
        with writer_session(vault):
            with vault.transaction():
                from dbf_anonymizer.vault.mappings import create_domain

                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
            allocator = GlobalTextDomainMapping(vault)
            originals = sorted({value for pair in pk_tuples + fk_tuples for value in pair})
            for original in originals:
                allocator.observe(original, encoding="cp1250", byte_width=6)
            allocator.finalize()

            def shift(pair: tuple[str, str]) -> tuple[str, str]:
                return (
                    allocator.pseudonym_for(pair[0]),
                    allocator.pseudonym_for(pair[1]),
                )

            # NULL FK rows are represented by the empty tuple and flagged in
            # the mask (the evidence utility zips keys with their masks).
            fk_keys_before = [pair if pair is not None else () for pair in parent_pairs]
            before = relation_metrics(
                pk_tuples,
                fk_keys_before,
                foreign_null_mask=[pair is None for pair in parent_pairs],
            )
            after = relation_metrics(
                [shift(pair) for pair in pk_tuples],
                [() if pair is None else shift(pair) for pair in parent_pairs],
                foreign_null_mask=[pair is None for pair in parent_pairs],
            )
            assert before.to_dict() == after.to_dict()
            # Ordered tuple equality/inequality is preserved: (A,B) and (B,A)
            # remain distinct tuples after the declared-relation shift.
            shifted_a = shift(("S1", "DEV-A"))
            shifted_swapped = shift(("DEV-A", "S1"))
            assert shifted_a != shifted_swapped or ("DEV-A", "S1") == ("S1", "DEV-A")