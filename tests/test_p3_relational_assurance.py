"""Relational assurance levels derived from verification evidence (P3-007).

The exact four-level vocabulary, the evidence-based derivation rules, the
explicit VFP-metadata scope limitation (no full database relational
correctness claim) and the privacy guards of the public assurance boundary.
"""

from __future__ import annotations

import json
from dataclasses import fields as dataclass_fields
from pathlib import Path

import pytest

from dbf_anonymizer import VerificationError
from dbf_anonymizer.models import (
    MODEL_SCHEMA_VERSION,
    PUBLIC_MODEL_TYPES,
    RelationalAssuranceLevel,
    RelationshipMetadata,
)
from dbf_anonymizer.relationships import (
    NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    PROVENANCE_POLICY_FILE,
    RELATIONAL_ASSURANCE_SCOPE_NOTE,
    EVIDENCE_SCHEMA_VERSION,
    RelationalAssuranceSummary,
    parse_relationship_document,
    relationship_fingerprint,
    verify_relationships,
)
from dbf_anonymizer.relationships.assurance import derive_relational_assurance
from dbf_anonymizer.relationships.verification import (
    RelationEvidenceCounts,
    RelationSideMetrics,
)
from dataclasses import fields as dataclass_fields

from tests.test_p3_relationship_verification import (
    _counts,
    _numeric_document,
    CANARY_NUMERIC,
    CANARY_TEXT,
)


def _metadata(
    payload: object, *, authoritative: bool, provenance: str | None = None
) -> RelationshipMetadata:
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    return RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=provenance or PROVENANCE_POLICY_FILE,
        relationship_fingerprint=relationship_fingerprint(document),
        relation_count=len(document.groups),
        authoritative=authoritative,
    )


def _verified_report(payload: object) -> object:
    """A complete verified report for every relation of the document."""
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    before: dict[str, RelationEvidenceCounts] = {}
    after: dict[str, RelationEvidenceCounts] = {}
    for group in document.canonical_groups():
        evidence = _counts([("A",), ("B",)], [("A",), ("B",), ("B",)])
        before[group.relation_id] = evidence
        after[group.relation_id] = evidence
    return verify_relationships(document, before=before, after=after)


def test_assurance_levels_are_the_exact_architecture_values() -> None:
    assert {level.value for level in RelationalAssuranceLevel} == {
        "GLOBAL_EXACT_VALUE",
        "DECLARED_RELATIONS_VERIFIED",
        "VFP_METADATA_VERIFIED",
        "INCOMPLETE",
    }
    assert len(RelationalAssuranceLevel) == 4


# ---------------------------------------------------------------------------
# 18. no declared metadata + global mapping semantics => GLOBAL_EXACT_VALUE
# ---------------------------------------------------------------------------
def test_no_declared_metadata_is_global_exact_value() -> None:
    relationships = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint="sha256:no-relationships",
        relation_count=0,
        authoritative=False,
    )
    summary = derive_relational_assurance(relationships, None)
    assert summary.level is RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    assert summary.relation_count == 0
    assert summary.verified_relation_count == 0
    assert summary.failed_relation_count == 0
    assert summary.incomplete_relation_count == 0
    assert summary.scope_note == RELATIONAL_ASSURANCE_SCOPE_NOTE
    # An empty report for the same empty dataset stays in the same state.
    empty_document = parse_relationship_document(
        {"metadata_schema_version": "1.0", "relations": []}
    )
    empty_report = verify_relationships(empty_document, before={}, after={})
    assert derive_relational_assurance(relationships, empty_report) == summary


def test_global_exact_value_rests_on_the_real_global_mapping_semantics(
    tmp_path: Path,
) -> None:
    """The no-metadata claim is backed by the REAL global text domain."""
    from dbf_anonymizer.vault import (
        VAULT_DATABASE_FILENAME,
        VAULT_TABLE_DOMAIN_KIND_TEXT,
        VaultDatabase,
    )
    from dbf_anonymizer.vault.mappings import create_domain
    from dbf_anonymizer.vault.text_allocation import (
        GLOBAL_TEXT_DOMAIN_ID,
        GlobalTextDomainMapping,
    )
    from support.vault_sessions import writer_session

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
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                vault.register_table("customers.dbf")
                vault.register_table("orders.dbf")
            allocator = GlobalTextDomainMapping(vault)
            for original in (CANARY_TEXT, "OTHER"):
                allocator.observe(original, encoding="cp1250", byte_width=8)
            allocator.finalize()
            first = allocator.pseudonym_for(CANARY_TEXT)
            second = allocator.pseudonym_for(CANARY_TEXT)
            assert first == second and first != CANARY_TEXT
    # Without declared relationship metadata only the global exact-value
    # preservation is truthfully claimed.
    relationships = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint="sha256:no-relationships",
        relation_count=0,
        authoritative=False,
    )
    assert (
        derive_relational_assurance(relationships, None).level
        is RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    )


# ---------------------------------------------------------------------------
# 19. declared document + all relations verified => DECLARED_RELATIONS_VERIFIED
# ---------------------------------------------------------------------------
def test_declared_relations_verified() -> None:
    payload = _numeric_document()
    relationships = _metadata(payload, authoritative=False)
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    summary = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert summary.level is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    assert summary.relation_count == 1
    assert summary.verified_relation_count == 1
    assert summary.failed_relation_count == 0
    assert summary.incomplete_relation_count == 0


# ---------------------------------------------------------------------------
# 20. declared document + one failed relation => INCOMPLETE
# ---------------------------------------------------------------------------
def test_declared_one_failed_relation_is_incomplete() -> None:
    payload = _numeric_document()
    relationships = _metadata(payload, authoritative=False)
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        # A broken after side (an extra orphan) FAILS the relation.
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("Z",), ("W",)])},
    )
    assert report.relations[0].status.value == "FAILED"
    summary = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert summary.level is RelationalAssuranceLevel.INCOMPLETE
    assert summary.failed_relation_count == 1
    assert summary.verified_relation_count == 0


# ---------------------------------------------------------------------------
# 21. declared document + one missing relation => INCOMPLETE
# ---------------------------------------------------------------------------
def test_declared_one_missing_relation_is_incomplete() -> None:
    payload = _numeric_document()
    relationships = _metadata(payload, authoritative=False)
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": evidence},
        after={},
    )
    assert report.relations[0].status.value == "INCOMPLETE"
    summary = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert summary.level is RelationalAssuranceLevel.INCOMPLETE
    assert summary.incomplete_relation_count == 1


def test_declared_relations_without_any_report_is_incomplete() -> None:
    payload = _numeric_document()
    relationships = _metadata(payload, authoritative=True)
    summary = derive_relational_assurance(relationships, None)
    assert summary.level is RelationalAssuranceLevel.INCOMPLETE
    assert summary.incomplete_relation_count == 1
    assert summary.verified_relation_count == 0


# ---------------------------------------------------------------------------
# 22. VFP provenance label alone is NEVER evidence
# ---------------------------------------------------------------------------
def test_vfp_provenance_label_alone_never_grants_vfp_metadata_verified() -> None:
    payload = _numeric_document()
    # The MCP provenance token with an UNVERIFIED (missing) report: the label
    # alone grants nothing — the truthful level is INCOMPLETE.
    summary = derive_relational_assurance(
        _metadata(payload, authoritative=False, provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN),
        None,
    )
    assert summary.level is RelationalAssuranceLevel.INCOMPLETE
    # Provenance + complete verified evidence but NON-authoritative metadata:
    # still only the declared level (the label alone is not coverage proof).
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        document,
        before={"rel-numeric-key": evidence},
        after={"rel-numeric-key": evidence},
    )
    non_authoritative = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
        relationship_fingerprint=relationship_fingerprint(document),
        relation_count=1,
        authoritative=False,
    )
    assert (
        derive_relational_assurance(non_authoritative, report).level
        is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    )
    # Authoritative + complete evidence but a POLICY_FILE provenance: the
    # VFP toolchain boundary was not the source of the metadata.
    policy_authoritative = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_POLICY_FILE,
        relationship_fingerprint=relationship_fingerprint(document),
        relation_count=1,
        authoritative=True,
    )
    assert (
        derive_relational_assurance(policy_authoritative, report).level
        is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    )


# ---------------------------------------------------------------------------
# 23. authoritative VFP metadata + proven complete scope => VFP_METADATA_VERIFIED
# ---------------------------------------------------------------------------
def test_authoritative_vfp_metadata_with_complete_scope_is_verified() -> None:
    payload = _numeric_document()
    relationships = _metadata(
        payload, authoritative=True, provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN
    )
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    summary = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert summary.level is RelationalAssuranceLevel.VFP_METADATA_VERIFIED
    assert summary.verified_relation_count == 1
    # Even this stronger level never claims full database correctness.
    assert summary.scope_note == RELATIONAL_ASSURANCE_SCOPE_NOTE


def test_authoritative_vfp_metadata_with_incomplete_coverage_is_not_upgraded() -> None:
    """Authoritative VFP metadata + a failed relation stays INCOMPLETE."""
    payload = _numeric_document()
    relationships = _metadata(
        payload, authoritative=True, provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN
    )
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",), ("W",)])},
    )
    assert report.relations[0].status.value == "FAILED"
    summary = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert summary.level is RelationalAssuranceLevel.INCOMPLETE


def test_vfp_metadata_requires_at_least_one_verified_relation() -> None:
    """Authoritative metadata with ZERO relations never upgrades."""
    relationships = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
        relationship_fingerprint="sha256:authoritative-empty",
        relation_count=0,
        authoritative=True,
    )
    assert (
        derive_relational_assurance(relationships, None).level
        is RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    )


# ---------------------------------------------------------------------------
# fail closed: inconsistent evidence bindings
# ---------------------------------------------------------------------------
def test_evidence_fingerprint_mismatch_fails_closed() -> None:
    payload = _numeric_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    other_payload = _numeric_document()
    other_payload["relations"][0]["relation_id"] = "rel-other"  # type: ignore[index,union-attr]
    other_document = parse_relationship_document(other_payload)  # type: ignore[arg-type]
    other_fingerprint = relationship_fingerprint(other_document)
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        document,
        before={"rel-numeric-key": evidence},
        after={"rel-numeric-key": evidence},
    )
    mismatched = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_POLICY_FILE,
        relationship_fingerprint=other_fingerprint,
        relation_count=1,
        authoritative=False,
    )
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(mismatched, report)
    assert "RELATIONSHIP_EVIDENCE_FINGERPRINT_MISMATCH" in str(excinfo.value.to_dict())
    # An empty report against declared relations is also refused.
    empty_document = parse_relationship_document(
        {"metadata_schema_version": "1.0", "relations": []}
    )
    empty_report = verify_relationships(empty_document, before={}, after={})
    with pytest.raises(VerificationError):
        derive_relational_assurance(mismatched, empty_report)


# ---------------------------------------------------------------------------
# 24. explicit assurance-level serialization
# ---------------------------------------------------------------------------
def test_assurance_summary_serialization_is_stable() -> None:
    payload = _numeric_document()
    relationships = _metadata(payload, authoritative=False)
    summary = derive_relational_assurance(relationships, None)
    payload_dict = summary.to_dict()
    assert payload_dict["model_type"] == "RelationalAssuranceSummary"
    assert payload_dict["schema_version"] == MODEL_SCHEMA_VERSION
    assert tuple(payload_dict) == (
        "schema_version",
        "model_type",
        "level",
        "relation_count",
        "verified_relation_count",
        "failed_relation_count",
        "incomplete_relation_count",
        "relationship_fingerprint",
        "evidence_schema_version",
        "scope_note",
    )
    assert payload_dict["level"] == "INCOMPLETE"
    assert payload_dict["evidence_schema_version"] == EVIDENCE_SCHEMA_VERSION
    # Deterministic JSON round trip.
    assert json.loads(json.dumps(payload_dict, sort_keys=True)) == payload_dict


def test_assurance_summary_model_is_guarded() -> None:
    # The P1 public model registry stays untouched (REQ-P1-002 evidence);
    # the P3-007 summary is the standalone model embedded by P4/P5 later.
    assert RelationalAssuranceSummary not in PUBLIC_MODEL_TYPES
    forbidden = {
        "key",
        "keys",
        "sample",
        "samples",
        "original",
        "originals",
        "original_value",
        "original_values",
        "pseudonym",
        "pseudonyms",
        "value",
        "values",
        "payload",
        "memo_payload",
        "reverse_mapping",
        "vault_path",
        "vault_contents",
        "source_absolute_path",
        "secret",
        "secrets",
    }
    from dbf_anonymizer.relationships import (
        RelationInvariantResult,
        RelationSideMetrics as SideMetrics,
        RelationEvidenceCounts as Counts,
        RelationVerificationEvidence,
        RelationshipVerificationReport,
    )

    for model_type in (
        RelationalAssuranceSummary,
        RelationshipVerificationReport,
        RelationInvariantResult,
        RelationVerificationEvidence,
        Counts,
        SideMetrics,
    ):
        assert forbidden.isdisjoint(
            field.name for field in dataclass_fields(model_type)
        )


# ---------------------------------------------------------------------------
# 25. no overclaim of full database correctness
# ---------------------------------------------------------------------------
def test_no_full_database_correctness_overclaim() -> None:
    """No level, token or summary field claims full database correctness."""
    # The vocabulary is EXACTLY the four architecture levels (no synonyms).
    assert {level.value for level in RelationalAssuranceLevel} == {
        "GLOBAL_EXACT_VALUE",
        "DECLARED_RELATIONS_VERIFIED",
        "VFP_METADATA_VERIFIED",
        "INCOMPLETE",
    }
    # Precise overclaim tokens (word-safe: INCOMPLETE must not false-match).
    overclaims = (
        "FULL",
        "COMPLETE_DATABASE_INTEGRITY",
        "GUARANTEED",
        "COMPLETE_DATABASE",
        "FULL_DATABASE",
        "RELATIONAL_CORRECTNESS",
    )
    for level in RelationalAssuranceLevel:
        for token in overclaims:
            assert token not in level.value
    assert RELATIONAL_ASSURANCE_SCOPE_NOTE == "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"
    # The scope note is machine-carried by EVERY assurance payload.
    relationships = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint="sha256:no-relationships",
        relation_count=0,
        authoritative=False,
    )
    for summary in (
        derive_relational_assurance(relationships, None),
        RelationalAssuranceSummary(
            level=RelationalAssuranceLevel.INCOMPLETE,
            relation_count=1,
            verified_relation_count=0,
            failed_relation_count=0,
            incomplete_relation_count=1,
            relationship_fingerprint="sha256:rel",
            evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
            scope_note=RELATIONAL_ASSURANCE_SCOPE_NOTE,
        ),
    ):
        assert summary.to_dict()["scope_note"] == "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"
        boundary = str(summary) + "|" + repr(summary) + json.dumps(summary.to_dict())
        for token in overclaims:
            assert token not in boundary
        assert "DBC" not in boundary  # no invented coverage claims


def test_assurance_boundary_never_leaks_sensitive_material() -> None:
    payload = _numeric_document()
    relationships = _metadata(payload, authoritative=True)
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    summary = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    boundary = (
        str(summary)
        + "|"
        + repr(summary)
        + "|"
        + json.dumps(summary.to_dict(), sort_keys=True)
        + "|"
        + str(report)
        + "|"
        + repr(report)
        + "|"
        + json.dumps(report.to_dict(), sort_keys=True)
    )
    assert CANARY_TEXT not in boundary
    assert str(CANARY_NUMERIC) not in boundary
    assert "C:\\" not in boundary and "C:/" not in boundary
    assert "dictionary.sqlite3" not in boundary
    assert "vault" not in boundary.lower()


def test_new_modules_are_pure_and_value_free() -> None:
    """The verification/assurance layer performs no IO, no DBF, no network."""
    import dbf_anonymizer.relationships.assurance as assurance_module
    import dbf_anonymizer.relationships.verification as verification_module

    for module in (assurance_module, verification_module):
        module_file = module.__file__
        assert module_file is not None
        source = Path(module_file).read_text(encoding="utf-8")
        for forbidden in (
            "dbfbridge",
            "socket",
            "urllib",
            "requests",
            "http.client",
            "subprocess",
            "sqlite3",
            "win32com",
            "open(",
            "Path(",
        ):
            assert forbidden not in source, f"{module.__name__} uses {forbidden}"