"""Relational assurance levels derived from verification evidence (P3-007).

The exact four-level vocabulary, the evidence-based derivation rules, the ONE
tested authoritative VFP metadata ingestion adapter, the explicit scope
limitation (no full database relational correctness claim) and the privacy
guards of the canonical public ``RelationalAssurance`` boundary.
"""

from __future__ import annotations

import json
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from dbf_anonymizer import PolicyError, VerificationError
from dbf_anonymizer.models import (
    MODEL_SCHEMA_VERSION,
    PUBLIC_MODEL_TYPES,
    RelationalAssurance,
    RelationalAssuranceLevel,
    RelationshipMetadata,
)
from dbf_anonymizer.relationships import (
    EVIDENCE_SCHEMA_VERSION,
    NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    PROVENANCE_POLICY_FILE,
    RELATIONAL_ASSURANCE_SCOPE_NOTE,
    authoritative_vfp_metadata_from_document,
    parse_relationship_document,
    relationship_fingerprint,
    verify_relationships,
)
from dbf_anonymizer.relationships.assurance import derive_relational_assurance
from dbf_anonymizer.relationships.verification import (
    RelationEvidenceCounts,
)

from tests.test_p3_relationship_verification import (
    _counts,
    _numeric_document,
    CANARY_NUMERIC,
    CANARY_TEXT,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from dbf_anonymizer.relationships.document import _AuthoritativeVFPBinding


def _toolchain_document() -> dict[str, object]:
    """The authoritative toolchain document (single relation, MCP provenance)."""
    payload = _numeric_document()
    payload["relations"][0]["provenance"] = PROVENANCE_MCP_VFP9SP2_TOOLCHAIN  # type: ignore[index,union-attr]
    return payload


def _multi_toolchain_document() -> dict[str, object]:
    """A two-relation toolchain document (for missing/failed coverage)."""
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-a",
                "provenance": PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
                "comparison": "EXACT_VALUE",
                "members": [
                    {"table": "p/x.dbf", "field": "A", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                    {"table": "c/y.dbf", "field": "A", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                ],
            },
            {
                "relation_id": "rel-b",
                "provenance": PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
                "comparison": "EXACT_VALUE",
                "members": [
                    {"table": "p/x.dbf", "field": "B", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                    {"table": "c/y.dbf", "field": "B", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                ],
            },
        ],
    }


def _ordinary_metadata(payload: object) -> RelationshipMetadata:
    """The ORDINARY (non-authoritative) adapter output for one document."""
    from dbf_anonymizer.relationships import relationship_metadata_from_document

    return relationship_metadata_from_document(
        parse_relationship_document(payload)  # type: ignore[arg-type]
    )


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
    assurance = derive_relational_assurance(relationships, None)
    assert assurance.level is RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    assert assurance.declared_relations == 0
    assert assurance.verified_relations == 0
    assert assurance.failed_relations == 0
    assert assurance.incomplete_relations == 0
    assert assurance.scope_note == RELATIONAL_ASSURANCE_SCOPE_NOTE
    assert assurance.evidence_fingerprint is None
    assert assurance.evidence_schema_version == EVIDENCE_SCHEMA_VERSION
    # An empty report for the same empty dataset stays in the same state.
    empty_document = parse_relationship_document(
        {"metadata_schema_version": "1.0", "relations": []}
    )
    empty_report = verify_relationships(empty_document, before={}, after={})
    assert derive_relational_assurance(relationships, empty_report) == assurance


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
    relationships = _ordinary_metadata(payload)
    assert relationships.authoritative is False
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    assurance = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert assurance.level is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    assert assurance.declared_relations == 1
    assert assurance.verified_relations == 1
    assert assurance.failed_relations == 0
    assert assurance.incomplete_relations == 0


# ---------------------------------------------------------------------------
# 20. declared document + one failed relation => INCOMPLETE
# ---------------------------------------------------------------------------
def test_declared_one_failed_relation_is_incomplete() -> None:
    payload = _numeric_document()
    relationships = _ordinary_metadata(payload)
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        # A broken after side (extra orphans) FAILS the relation.
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("Z",), ("W",)])},
    )
    assert report.relations[0].status.value == "FAILED"
    assurance = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert assurance.level is RelationalAssuranceLevel.INCOMPLETE
    assert assurance.failed_relations == 1
    assert assurance.verified_relations == 0


# ---------------------------------------------------------------------------
# 21. declared document + one missing relation => INCOMPLETE
# ---------------------------------------------------------------------------
def test_declared_one_missing_relation_is_incomplete() -> None:
    payload = _numeric_document()
    relationships = _ordinary_metadata(payload)
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={},
    )
    assert report.relations[0].status.value == "INCOMPLETE"
    assurance = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert assurance.level is RelationalAssuranceLevel.INCOMPLETE
    assert assurance.incomplete_relations == 1


def test_declared_relations_without_any_report_is_incomplete() -> None:
    payload = _numeric_document()
    relationships = _ordinary_metadata(payload)
    assurance = derive_relational_assurance(relationships, None)
    assert assurance.level is RelationalAssuranceLevel.INCOMPLETE
    assert assurance.incomplete_relations == 1
    assert assurance.verified_relations == 0
    assert assurance.evidence_fingerprint is None


# ---------------------------------------------------------------------------
# 22. VFP provenance label alone is NEVER evidence
# ---------------------------------------------------------------------------
def test_vfp_provenance_label_alone_never_grants_vfp_metadata_verified() -> None:
    payload = _toolchain_document()
    # The MCP provenance token with an UNVERIFIED (missing) report: the label
    # alone grants nothing — the truthful level is INCOMPLETE.
    assurance = derive_relational_assurance(
        _ordinary_metadata(payload),
        None,
    )
    assert assurance.level is RelationalAssuranceLevel.INCOMPLETE
    # Provenance + complete verified evidence but NON-authoritative metadata
    # (the ORDINARY adapter): still only the declared level.
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        document,
        before={"rel-numeric-key": evidence},
        after={"rel-numeric-key": evidence},
    )
    assert (
        derive_relational_assurance(_ordinary_metadata(payload), report).level
        is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    )


# ---------------------------------------------------------------------------
# the authoritative VFP metadata adapter (THE tested injection boundary)
# ---------------------------------------------------------------------------
def test_authoritative_adapter_marks_a_qualifying_toolchain_document() -> None:
    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    result = authoritative_vfp_metadata_from_document(document)
    metadata = result.metadata
    binding = result.binding
    assert metadata.authoritative is True
    assert metadata.provenance == PROVENANCE_MCP_VFP9SP2_TOOLCHAIN
    assert metadata.relationship_fingerprint == relationship_fingerprint(document)
    assert metadata.relation_count == 1
    assert metadata.metadata_schema_version == "1.0"
    # The binding is the internal authority proof minted by THIS call: it
    # binds the SAME canonical fingerprint and declared relation count.
    assert binding.relationship_fingerprint == metadata.relationship_fingerprint
    assert binding.relation_count == metadata.relation_count
    assert binding.metadata_schema_version == "1.0"


# ---------------------------------------------------------------------------
# THE TRUST BOUNDARY: the public authoritative boolean is NOT the credential
# ---------------------------------------------------------------------------
def test_forged_public_authoritative_metadata_cannot_reach_vfp_metadata_verified() -> None:
    """MANDATORY adversarial regression (final trust-boundary repair).

    ``public authoritative=True + toolchain provenance + matching fingerprint
    + matching relation count + a COMPLETE verified report`` is STILL
    insufficient: without the internal trust binding minted ONLY by the
    validated authoritative ingestion adapter the maximum level is
    ``DECLARED_RELATIONS_VERIFIED``.
    """
    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    report = verify_relationships(
        document,
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    forged = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
        relationship_fingerprint=relationship_fingerprint(document),
        relation_count=len(document.groups),
        authoritative=True,
    )
    assurance = derive_relational_assurance(forged, report)  # type: ignore[arg-type]
    # NO trusted authority binding was supplied: the stronger level is
    # unreachable no matter how complete the public facts are.
    assert assurance.level is not RelationalAssuranceLevel.VFP_METADATA_VERIFIED
    assert assurance.level is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    assert assurance.verified_relations == 1
    assert assurance.scope_note == RELATIONAL_ASSURANCE_SCOPE_NOTE


def test_valid_binding_with_tampered_metadata_schema_fails_closed() -> None:
    """MANDATORY adversarial regression (final schema-version binding gap).

    A VALID binding minted for the supported metadata schema 1.0 paired with
    a manually reconstructed descriptive metadata object that claims the
    SAME toolchain provenance, fingerprint, relation count and
    ``authoritative=True`` but a TAMPERED metadata schema version is a
    structural trust-boundary error: a typed, value-free refusal — never
    ``VFP_METADATA_VERIFIED``/``DECLARED_RELATIONS_VERIFIED``/``INCOMPLETE``.
    """
    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    authoritative = authoritative_vfp_metadata_from_document(document)
    report = verify_relationships(
        document,
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    tampered_metadata = RelationshipMetadata(
        metadata_schema_version="2.0",
        provenance=authoritative.metadata.provenance,
        relationship_fingerprint=authoritative.metadata.relationship_fingerprint,
        relation_count=authoritative.metadata.relation_count,
        authoritative=True,
    )
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(
            tampered_metadata,
            report,  # type: ignore[arg-type]
            authority_binding=authoritative.binding,
        )
    assert excinfo.value.context.detail_code == "RELATIONSHIP_AUTHORITY_BINDING_MISMATCH"
    # The tampered version value is never exposed in the failure boundary;
    # the typed refusal carries only the stable machine detail code.
    boundary = (
        str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
    )
    assert "2.0" not in boundary
    assert "2.0" not in str(excinfo.value.context.to_dict())


def test_valid_binding_with_incomplete_and_failed_evidence_stays_incomplete() -> None:
    """Binding negatives 10/11: a VALID binding never repairs bad evidence."""
    payload = _multi_toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    authoritative = authoritative_vfp_metadata_from_document(document)
    evidence = _counts([("A",)], [("A",), ("B",)])
    broken = _counts([("A",)], [("A",), ("W",), ("Z",)])
    # Incomplete evidence (rel-b AFTER missing) + valid binding.
    incomplete_report = verify_relationships(
        document,
        before={"rel-a": evidence, "rel-b": evidence},
        after={"rel-a": evidence},
    )
    assert (
        derive_relational_assurance(
            authoritative.metadata,
            incomplete_report,  # type: ignore[arg-type]
            authority_binding=authoritative.binding,
        ).level
        is RelationalAssuranceLevel.INCOMPLETE
    )
    # Failed evidence (rel-b broken) + valid binding.
    failed_report = verify_relationships(
        document,
        before={"rel-a": evidence, "rel-b": evidence},
        after={"rel-a": evidence, "rel-b": broken},
    )
    assert (
        derive_relational_assurance(
            authoritative.metadata,
            failed_report,  # type: ignore[arg-type]
            authority_binding=authoritative.binding,
        ).level
        is RelationalAssuranceLevel.INCOMPLETE
    )


def _forged_binding(
    *,
    fingerprint: str,
    relation_count: int = 1,
    schema_version: str = "1.0",
) -> "_AuthoritativeVFPBinding":
    """A hostile binding construction for NEGATIVE tests only."""
    from dbf_anonymizer.relationships.document import _AuthoritativeVFPBinding

    return _AuthoritativeVFPBinding(
        relationship_fingerprint=fingerprint,
        relation_count=relation_count,
        metadata_schema_version=schema_version,
    )


def test_binding_fingerprint_mismatch_fails_closed() -> None:
    """Binding negatives 1/2: a SUPPLIED binding with a different canonical
    relationship fingerprint (versus the metadata or the report) is a typed
    structural refusal."""
    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    other_payload = _toolchain_document()
    other_payload["relations"][0]["relation_id"] = "rel-other"  # type: ignore[index,union-attr]
    other_fingerprint = relationship_fingerprint(
        parse_relationship_document(other_payload)  # type: ignore[arg-type]
    )
    metadata = authoritative_vfp_metadata_from_document(document).metadata
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        document,
        before={"rel-numeric-key": evidence},
        after={"rel-numeric-key": evidence},
    )
    hostile_binding = _forged_binding(fingerprint=other_fingerprint)
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(
            metadata,
            report,  # type: ignore[arg-type]
            authority_binding=hostile_binding,  # type: ignore[arg-type]
        )
    assert "RELATIONSHIP_AUTHORITY_BINDING_MISMATCH" in str(excinfo.value.to_dict())
    # The same mismatch fails even WITHOUT a report (binding vs metadata).
    with pytest.raises(VerificationError) as metadata_only:
        derive_relational_assurance(
            metadata,
            None,
            authority_binding=hostile_binding,
        )
    assert "RELATIONSHIP_AUTHORITY_BINDING_MISMATCH" in str(
        metadata_only.value.to_dict()
    )


def test_binding_relation_count_mismatch_fails_closed() -> None:
    """Binding negative 3: a different declared relation count refuses."""
    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    metadata = authoritative_vfp_metadata_from_document(document).metadata
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        document,
        before={"rel-numeric-key": evidence},
        after={"rel-numeric-key": evidence},
    )
    hostile_binding = _forged_binding(
        fingerprint=metadata.relationship_fingerprint, relation_count=2
    )
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(
            metadata,
            report,  # type: ignore[arg-type]
            authority_binding=hostile_binding,
        )
    assert "RELATIONSHIP_AUTHORITY_BINDING_MISMATCH" in str(excinfo.value.to_dict())


def test_binding_from_document_a_with_report_from_document_b_fails_closed() -> None:
    """Binding negative 4: cross-document binding/report pairing refuses."""
    payload_a = _toolchain_document()
    document_a = parse_relationship_document(payload_a)  # type: ignore[arg-type]
    binding_a = authoritative_vfp_metadata_from_document(document_a).binding
    payload_b = _toolchain_document()
    payload_b["relations"][0]["relation_id"] = "rel-other"  # type: ignore[index,union-attr]
    document_b = parse_relationship_document(payload_b)  # type: ignore[arg-type]
    evidence = _counts([("A",)], [("A",), ("B",)])
    report_b = verify_relationships(
        document_b,
        before={"rel-other": evidence},
        after={"rel-other": evidence},
    )
    # The metadata claims document B; the binding was minted for document A.
    metadata_b = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
        relationship_fingerprint=relationship_fingerprint(document_b),
        relation_count=len(document_b.groups),
        authoritative=True,
    )
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(
            metadata_b,
            report_b,  # type: ignore[arg-type]
            authority_binding=binding_a,
        )
    assert "RELATIONSHIP_AUTHORITY_BINDING_MISMATCH" in str(excinfo.value.to_dict())


def test_binding_with_unsupported_schema_version_fails_closed() -> None:
    """A binding for an unsupported metadata schema version refuses."""
    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    metadata = authoritative_vfp_metadata_from_document(document).metadata
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        document,
        before={"rel-numeric-key": evidence},
        after={"rel-numeric-key": evidence},
    )
    hostile_binding = _forged_binding(
        fingerprint=metadata.relationship_fingerprint, schema_version="2.0"
    )
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(
            metadata,
            report,  # type: ignore[arg-type]
            authority_binding=hostile_binding,
        )
    assert "RELATIONSHIP_AUTHORITY_BINDING_MISMATCH" in str(excinfo.value.to_dict())


def test_binding_is_the_internal_trust_boundary_not_public_api() -> None:
    """The binding is internal: not public, not serialized, values-free."""
    import dbf_anonymizer
    import dbf_anonymizer.relationships as relationships_package
    from dbf_anonymizer.models import PublicModel, PUBLIC_MODEL_TYPES

    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    binding = authoritative_vfp_metadata_from_document(document).binding
    # NOT a public model, never in the P1-002 registry, never root-exported,
    # never part of the public relationships API surface.
    assert not isinstance(binding, PublicModel)
    assert type(binding) not in PUBLIC_MODEL_TYPES
    assert type(binding).__name__ not in relationships_package.__all__
    assert type(binding).__name__ not in dbf_anonymizer.__all__
    assert not hasattr(binding, "to_dict")
    # ONLY bounded structural facts; no values, paths or secrets.
    assert tuple(vars(binding).keys()) == (
        "relationship_fingerprint",
        "relation_count",
        "metadata_schema_version",
    )


def test_authority_error_boundaries_never_leak_structural_values() -> None:
    """The typed binding refusal carries no values beyond bounded tokens."""
    payload = _toolchain_document()
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    metadata = authoritative_vfp_metadata_from_document(document).metadata
    hostile_binding = _forged_binding(fingerprint="0" * 64, relation_count=7)
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(
            metadata,
            None,
            authority_binding=hostile_binding,
        )
    boundary = str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(
        excinfo.value.to_dict()
    )
    assert CANARY_TEXT not in boundary
    assert str(CANARY_NUMERIC) not in boundary
    assert "C:\\" not in boundary and "C:/" not in boundary
    assert "0" * 64 not in boundary  # the hostile fingerprint is not echoed
    assert "7" not in boundary


def test_authoritative_adapter_refuses_policy_file_provenance() -> None:
    payload = _numeric_document()  # provenance POLICY_FILE
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    with pytest.raises(PolicyError) as excinfo:
        authoritative_vfp_metadata_from_document(document)
    assert "RELATIONSHIP_AUTHORITATIVE_PROVENANCE_INVALID" in str(
        excinfo.value.to_dict()
    )


def test_authoritative_adapter_refuses_mixed_provenance() -> None:
    payload = _multi_toolchain_document()
    payload["relations"][1]["provenance"] = PROVENANCE_POLICY_FILE  # type: ignore[index,union-attr]
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    with pytest.raises(PolicyError) as excinfo:
        authoritative_vfp_metadata_from_document(document)
    assert "RELATIONSHIP_AUTHORITATIVE_PROVENANCE_INVALID" in str(
        excinfo.value.to_dict()
    )
    # The ordinary adapter truthfully reports the ambiguity, non-authoritative.
    assert _ordinary_metadata(payload).provenance == "MIXED"  # type: ignore[arg-type]


def test_authoritative_adapter_refuses_zero_relations() -> None:
    empty_document = parse_relationship_document(
        {"metadata_schema_version": "1.0", "relations": []}
    )
    with pytest.raises(PolicyError) as excinfo:
        authoritative_vfp_metadata_from_document(empty_document)
    assert "RELATIONSHIP_AUTHORITATIVE_EMPTY" in str(excinfo.value.to_dict())


# ---------------------------------------------------------------------------
# A. authoritative toolchain document + complete verified report
#    => VFP_METADATA_VERIFIED (metadata obtained through THE adapter)
# ---------------------------------------------------------------------------
def test_authoritative_vfp_metadata_with_complete_scope_is_verified() -> None:
    payload = _toolchain_document()
    authoritative = authoritative_vfp_metadata_from_document(
        parse_relationship_document(payload)  # type: ignore[arg-type]
    )
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    assurance = derive_relational_assurance(
        authoritative.metadata,
        report,  # type: ignore[arg-type]
        authority_binding=authoritative.binding,
    )
    assert assurance.level is RelationalAssuranceLevel.VFP_METADATA_VERIFIED
    assert assurance.verified_relations == 1
    assert assurance.evidence_fingerprint == report.evidence_fingerprint  # type: ignore[attr-defined]
    assert (
        assurance.relationship_fingerprint
        == authoritative.metadata.relationship_fingerprint
    )
    # Even this stronger level never claims full database correctness.
    assert assurance.scope_note == RELATIONAL_ASSURANCE_SCOPE_NOTE


# ---------------------------------------------------------------------------
# B. toolchain provenance through the ORDINARY adapter => DECLARED_RELATIONS_VERIFIED
# ---------------------------------------------------------------------------
def test_toolchain_provenance_via_ordinary_adapter_stays_declared() -> None:
    payload = _toolchain_document()
    relationships = _ordinary_metadata(payload)
    assert relationships.authoritative is False
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    assurance = derive_relational_assurance(relationships, report)  # type: ignore[arg-type]
    assert assurance.level is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED


# ---------------------------------------------------------------------------
# C. authoritative adapter + one missing relation => INCOMPLETE
# ---------------------------------------------------------------------------
def test_authoritative_with_one_missing_relation_is_incomplete() -> None:
    payload = _multi_toolchain_document()
    authoritative = authoritative_vfp_metadata_from_document(
        parse_relationship_document(payload)  # type: ignore[arg-type]
    )
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-a": evidence, "rel-b": evidence},
        after={"rel-a": evidence},  # rel-b AFTER side never evaluated
    )
    statuses = [entry.status.value for entry in report.relations]
    assert statuses == ["VERIFIED", "INCOMPLETE"]
    assurance = derive_relational_assurance(
        authoritative.metadata,
        report,  # type: ignore[arg-type]
        authority_binding=authoritative.binding,
    )
    assert assurance.level is RelationalAssuranceLevel.INCOMPLETE
    assert assurance.verified_relations == 1
    assert assurance.incomplete_relations == 1


# ---------------------------------------------------------------------------
# D. authoritative adapter + one failed relation => INCOMPLETE
# ---------------------------------------------------------------------------
def test_authoritative_with_one_failed_relation_is_incomplete() -> None:
    payload = _multi_toolchain_document()
    authoritative = authoritative_vfp_metadata_from_document(
        parse_relationship_document(payload)  # type: ignore[arg-type]
    )
    evidence = _counts([("A",)], [("A",), ("B",)])
    broken = _counts([("A",)], [("A",), ("W",), ("Z",)])
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-a": evidence, "rel-b": evidence},
        after={"rel-a": evidence, "rel-b": broken},
    )
    statuses = [entry.status.value for entry in report.relations]
    assert statuses == ["VERIFIED", "FAILED"]
    assurance = derive_relational_assurance(
        authoritative.metadata,
        report,  # type: ignore[arg-type]
        authority_binding=authoritative.binding,
    )
    assert assurance.level is RelationalAssuranceLevel.INCOMPLETE
    assert assurance.failed_relations == 1


# ---------------------------------------------------------------------------
# E. authoritative adapter + fingerprint mismatch => typed VerificationError
# ---------------------------------------------------------------------------
def test_authoritative_fingerprint_mismatch_fails_closed() -> None:
    payload = _toolchain_document()
    authoritative = authoritative_vfp_metadata_from_document(
        parse_relationship_document(payload)  # type: ignore[arg-type]
    )
    other_payload = _toolchain_document()
    other_payload["relations"][0]["relation_id"] = "rel-other"  # type: ignore[index,union-attr]
    other_document = parse_relationship_document(other_payload)  # type: ignore[arg-type]
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        other_document,
        before={"rel-other": evidence},
        after={"rel-other": evidence},
    )
    with pytest.raises(VerificationError) as excinfo:
        derive_relational_assurance(authoritative.metadata, report)  # type: ignore[arg-type]
    assert "RELATIONSHIP_EVIDENCE_FINGERPRINT_MISMATCH" in str(
        excinfo.value.to_dict()
    )


# ---------------------------------------------------------------------------
# G/H. mixed provenance and zero relations can never reach VFP_METADATA_VERIFIED
# ---------------------------------------------------------------------------
def test_mixed_provenance_cannot_become_vfp_metadata_verified() -> None:
    """Mixed provenance: the adapter refuses, and even hostile truthiness
    (manually authoritative) can never reach VFP_METADATA_VERIFIED because
    the provenance is not the toolchain token."""
    payload = _multi_toolchain_document()
    payload["relations"][1]["provenance"] = PROVENANCE_POLICY_FILE  # type: ignore[index,union-attr]
    document = parse_relationship_document(payload)  # type: ignore[arg-type]
    with pytest.raises(PolicyError):
        authoritative_vfp_metadata_from_document(document)
    # Hostile manual construction (negative test only): the ordinary
    # semantics still refuse the upgrade on the provenance check.
    evidence = _counts([("A",)], [("A",), ("B",)])
    report = verify_relationships(
        document,
        before={"rel-a": evidence, "rel-b": evidence},
        after={"rel-a": evidence, "rel-b": evidence},
    )
    hostile = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance="MIXED",
        relationship_fingerprint=relationship_fingerprint(document),
        relation_count=2,
        authoritative=True,
    )
    assert (
        derive_relational_assurance(hostile, report).level
        is RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    )


def test_zero_relation_authoritative_metadata_never_upgrades() -> None:
    """H: a zero-relation document can never reach VFP_METADATA_VERIFIED."""
    empty_document = parse_relationship_document(
        {"metadata_schema_version": "1.0", "relations": []}
    )
    with pytest.raises(PolicyError):
        authoritative_vfp_metadata_from_document(empty_document)
    # Hostile manual construction (authoritative + toolchain provenance with
    # ZERO relations): the derivation still refuses the stronger level.
    hostile = RelationshipMetadata(
        metadata_schema_version="1.0",
        provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
        relationship_fingerprint="sha256:authoritative-empty",
        relation_count=0,
        authoritative=True,
    )
    assert (
        derive_relational_assurance(hostile, None).level
        is RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
    )


# ---------------------------------------------------------------------------
# 24. explicit assurance-level serialization (canonical public model)
# ---------------------------------------------------------------------------
def test_derived_assurance_serialization_is_stable() -> None:
    payload = _numeric_document()
    relationships = _ordinary_metadata(payload)
    assurance = derive_relational_assurance(relationships, None)
    payload_dict = assurance.to_dict()
    assert payload_dict["model_type"] == "RelationalAssurance"
    assert payload_dict["schema_version"] == MODEL_SCHEMA_VERSION
    assert tuple(payload_dict) == (
        "schema_version",
        "model_type",
        "level",
        "declared_relations",
        "verified_relations",
        "failed_relations",
        "incomplete_relations",
        "evidence_fingerprint",
        "relationship_fingerprint",
        "evidence_schema_version",
        "scope_note",
    )
    assert payload_dict["level"] == "INCOMPLETE"
    assert payload_dict["evidence_schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert payload_dict["scope_note"] == "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"
    # Deterministic JSON round trip.
    assert json.loads(json.dumps(payload_dict, sort_keys=True)) == payload_dict


def test_canonical_assurance_model_is_registered_and_guarded() -> None:
    """THE ONE canonical public assurance model is the P1-registered model."""
    assert RelationalAssurance in PUBLIC_MODEL_TYPES
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
    assert forbidden.isdisjoint(
        field.name for field in dataclass_fields(RelationalAssurance)
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
    # The scope note is machine-carried by EVERY derived assurance payload.
    relationships = RelationshipMetadata(
        metadata_schema_version="1.1",
        provenance="none",
        relationship_fingerprint="sha256:no-relationships",
        relation_count=0,
        authoritative=False,
    )
    for assurance in (
        derive_relational_assurance(relationships, None),
        RelationalAssurance(
            level=RelationalAssuranceLevel.INCOMPLETE,
            declared_relations=1,
            verified_relations=0,
            failed_relations=0,
            incomplete_relations=1,
            relationship_fingerprint="sha256:rel",
            evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
            scope_note=RELATIONAL_ASSURANCE_SCOPE_NOTE,
        ),
    ):
        assert assurance.to_dict()["scope_note"] == "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"
        boundary = str(assurance) + "|" + repr(assurance) + json.dumps(assurance.to_dict())
        for token in overclaims:
            assert token not in boundary
        assert "DBC" not in boundary  # no invented coverage claims


def test_assurance_boundary_never_leaks_sensitive_material() -> None:
    payload = _toolchain_document()
    authoritative = authoritative_vfp_metadata_from_document(
        parse_relationship_document(payload)  # type: ignore[arg-type]
    )
    report = verify_relationships(
        parse_relationship_document(payload),  # type: ignore[arg-type]
        before={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
        after={"rel-numeric-key": _counts([("A",)], [("A",), ("B",)])},
    )
    assurance = derive_relational_assurance(
        authoritative.metadata,
        report,  # type: ignore[arg-type]
        authority_binding=authoritative.binding,
    )
    boundary = (
        str(assurance)
        + "|"
        + repr(assurance)
        + "|"
        + json.dumps(assurance.to_dict(), sort_keys=True)
        + "|"
        + str(report)
        + "|"
        + repr(report)
        + "|"
        + json.dumps(report.to_dict(), sort_keys=True)
        + "|"
        + json.dumps(authoritative.metadata.to_dict(), sort_keys=True)
        + "|"
        + repr(authoritative.binding)
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