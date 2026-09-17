"""Relational assurance levels derived from verification evidence (P3-007).

The evidence-based derivation of the FOUR exact architecture levels —
``GLOBAL_EXACT_VALUE``, ``DECLARED_RELATIONS_VERIFIED``, ``VFP_METADATA_VERIFIED``
and ``INCOMPLETE`` — into the ONE canonical public
:class:`~dbf_anonymizer.models.RelationalAssurance` model.  The level is
derived from evidence, never from user preference, and a provenance label
alone is never evidence.

Truthful scope: NO level claims full database relational correctness.  Even
``VFP_METADATA_VERIFIED`` covers ONLY the scope that was actually validated —
the declared relations verified from complete before/after evidence plus the
explicitly injected authoritative metadata coverage (obtained through the ONE
tested adapter :func:`~dbf_anonymizer.relationships.document.authoritative_vfp_metadata_from_document`).
It never means:

* arbitrary application-level business rules are verified;
* DBC persistent-relation expressions are evaluated (unless actually
  available, supplied and checked);
* arbitrary CDX index expressions are understood;
* trigger/stored-procedure/application semantics are verified.

The scope statement is machine-encoded in the stable
:data:`RELATIONAL_ASSURANCE_SCOPE_NOTE` token carried by every derived
payload, so no consumer can mistake the level for full database relational
correctness.
"""

from __future__ import annotations

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VerificationError
from dbf_anonymizer.models import (
    RelationalAssurance,
    RelationalAssuranceLevel,
    RelationshipMetadata,
)
from dbf_anonymizer.relationships.models import (
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
)
from dbf_anonymizer.relationships.verification import (
    EVIDENCE_SCHEMA_VERSION,
    RelationshipVerificationReport,
    VerificationStatus,
)

__all__ = [
    "RELATIONAL_ASSURANCE_SCOPE_NOTE",
    "derive_relational_assurance",
]

#: The stable machine token carried by every derived assurance payload: the
#: level describes ONLY the declared/injected metadata scope that was
#: actually verified — never full database relational correctness (DBC
#: expressions, CDX expressions, application-level key semantics, triggers or
#: stored procedures stay out of scope).
RELATIONAL_ASSURANCE_SCOPE_NOTE = "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"


def derive_relational_assurance(
    relationships: RelationshipMetadata,
    report: RelationshipVerificationReport | None,
) -> RelationalAssurance:
    """Derive the assurance level from evidence — never from preference.

    The result is the ONE canonical public
    :class:`~dbf_anonymizer.models.RelationalAssurance` model (REQ-P1-002),
    extended by REQ-P3-007 to carry the truthful evidence binding and scope.

    Exact derivation rules (evidence-based, no user preference):

    * ``relation_count == 0`` — no richer authoritative relationship metadata
      is available: only the global exact-value preservation established by
      the global mapping semantics can truthfully be claimed
      (``GLOBAL_EXACT_VALUE``); no statement about full DB-level relational
      correctness is made or implied.
    * ``report is None`` with declared relations — verification was not
      completed: ``INCOMPLETE`` with every declared relation incomplete.
    * a supplied report must bind EXACTLY the declared relations of the
      relationship fingerprint (the SAME document the authority metadata is
      bound to); any mismatch is a typed fail-closed refusal.
    * every declared relation ``VERIFIED`` (at least one declared relation):

      * ``VFP_METADATA_VERIFIED`` only when authoritative VFP metadata was
        explicitly injected through the tested authoritative adapter (the
        metadata model's ``authoritative`` flag) AND its provenance is the
        ``MCP_VFP9SP2_TOOLCHAIN`` token AND every declared relation carries
        complete verified evidence — the provenance LABEL alone is never
        sufficient and an incomplete coverage is never upgraded;
      * otherwise ``DECLARED_RELATIONS_VERIFIED``.
    * any failed or incomplete relation — ``INCOMPLETE``.

    The payload never claims full database relational correctness; the
    machine-readable scope note is carried by every derivation.
    """
    relation_count = relationships.relation_count
    if report is None or not report.relations:
        verified = 0
        failed = 0
        if relation_count == 0:
            level = RelationalAssuranceLevel.GLOBAL_EXACT_VALUE
        else:
            level = RelationalAssuranceLevel.INCOMPLETE
            if report is not None:
                # An empty report against declared relations is a structural
                # inconsistency: fail closed instead of a partial truth.
                raise VerificationError(
                    ErrorCode.VERIFICATION_FAILED,
                    context=ErrorContext(
                        operation="derive_relational_assurance",
                        detail_code="RELATIONSHIP_EVIDENCE_RELATION_COUNT_MISMATCH",
                    ),
                )
        evidence_fingerprint = None
    else:
        if report.relationship_fingerprint != relationships.relationship_fingerprint:
            raise VerificationError(
                ErrorCode.VERIFICATION_FAILED,
                context=ErrorContext(
                    operation="derive_relational_assurance",
                    detail_code="RELATIONSHIP_EVIDENCE_FINGERPRINT_MISMATCH",
                ),
            )
        if len(report.relations) != relation_count:
            raise VerificationError(
                ErrorCode.VERIFICATION_FAILED,
                context=ErrorContext(
                    operation="derive_relational_assurance",
                    detail_code="RELATIONSHIP_EVIDENCE_RELATION_COUNT_MISMATCH",
                ),
            )
        verified = sum(
            1
            for entry in report.relations
            if entry.status is VerificationStatus.VERIFIED
        )
        failed = sum(
            1
            for entry in report.relations
            if entry.status is VerificationStatus.FAILED
        )
        if verified + failed > relation_count:
            raise VerificationError(
                ErrorCode.VERIFICATION_FAILED,
                context=ErrorContext(
                    operation="derive_relational_assurance",
                    detail_code="RELATIONSHIP_EVIDENCE_RELATION_COUNT_MISMATCH",
                ),
            )
        if verified == relation_count and relation_count > 0:
            if (
                relationships.authoritative
                and relationships.provenance == PROVENANCE_MCP_VFP9SP2_TOOLCHAIN
            ):
                level = RelationalAssuranceLevel.VFP_METADATA_VERIFIED
            else:
                level = RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
        else:
            level = RelationalAssuranceLevel.INCOMPLETE
        evidence_fingerprint = report.evidence_fingerprint
    return RelationalAssurance(
        level=level,
        declared_relations=relation_count,
        verified_relations=verified,
        failed_relations=failed,
        incomplete_relations=relation_count - verified - failed,
        evidence_fingerprint=evidence_fingerprint,
        relationship_fingerprint=relationships.relationship_fingerprint,
        evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
        scope_note=RELATIONAL_ASSURANCE_SCOPE_NOTE,
    )