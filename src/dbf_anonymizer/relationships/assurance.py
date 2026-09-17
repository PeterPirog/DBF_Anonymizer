"""Relational assurance levels derived from verification evidence (P3-007).

The evidence-based derivation of the FOUR exact architecture levels —
``GLOBAL_EXACT_VALUE``, ``DECLARED_RELATIONS_VERIFIED``, ``VFP_METADATA_VERIFIED``
and ``INCOMPLETE`` — into the ONE canonical public
:class:`~dbf_anonymizer.models.RelationalAssurance` model.  The level is
derived from evidence, never from user preference; a provenance label alone
is never evidence, and the public ``RelationshipMetadata.authoritative``
boolean alone is never the credential.

Truthful scope: NO level claims full database relational correctness.  Even
``VFP_METADATA_VERIFIED`` covers ONLY the scope that was actually validated —
the declared relations verified from complete before/after evidence plus the
explicitly injected authoritative metadata coverage (ingested through the ONE
tested adapter
:func:`~dbf_anonymizer.relationships.document.authoritative_vfp_metadata_from_document`,
whose internal ``_AuthoritativeVFPBinding`` is the required trust proof).
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
from dbf_anonymizer.relationships.document import _AuthoritativeVFPBinding
from dbf_anonymizer.relationships.models import (
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    RELATIONSHIP_METADATA_SCHEMA_VERSION,
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

#: The bounded detail code of a SUPPLIED-but-inconsistent authority binding.
_BINDING_MISMATCH = "RELATIONSHIP_AUTHORITY_BINDING_MISMATCH"


def _validated_authority_binding(
    relationships: RelationshipMetadata,
    report: RelationshipVerificationReport | None,
    binding: _AuthoritativeVFPBinding | None,
) -> bool:
    """Whether the trusted adapter binding authorizes the stronger level.

    The binding is the NON-PUBLIC authority proof minted ONLY by
    :func:`~dbf_anonymizer.relationships.document.authoritative_vfp_metadata_from_document`.

    * ``binding is None`` — the caller supplied no trusted binding: the
      stronger level is simply never granted (the public
      ``RelationshipMetadata.authoritative`` boolean and the toolchain
      provenance label are DESCRIPTIVE facts, never credentials), and the
      maximum level stays ``DECLARED_RELATIONS_VERIFIED``.
    * a SUPPLIED binding that is structurally inconsistent with the metadata
      or the report (different canonical relationship fingerprint, different
      declared relation count, unsupported metadata schema version) is a
      structural error: a stable typed, value-free ``VerificationError``.
    """
    if binding is None:
        return False
    if (
        binding.metadata_schema_version != RELATIONSHIP_METADATA_SCHEMA_VERSION
        or binding.relationship_fingerprint != relationships.relationship_fingerprint
        or binding.relation_count != relationships.relation_count
        or (
            report is not None
            and binding.relationship_fingerprint != report.relationship_fingerprint
        )
    ):
        raise VerificationError(
            ErrorCode.VERIFICATION_FAILED,
            context=ErrorContext(
                operation="derive_relational_assurance",
                detail_code=_BINDING_MISMATCH,
            ),
        )
    return True


def derive_relational_assurance(
    relationships: RelationshipMetadata,
    report: RelationshipVerificationReport | None,
    *,
    authority_binding: _AuthoritativeVFPBinding | None = None,
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
      relationship fingerprint; any mismatch is a typed fail-closed refusal.
    * every declared relation ``VERIFIED`` (at least one declared relation):

      * ``VFP_METADATA_VERIFIED`` requires the COMPLETE trust boundary: the
        descriptive public ``authoritative`` flag AND the
        ``MCP_VFP9SP2_TOOLCHAIN`` provenance AND complete verified evidence
        AND a VALID internal ``_AuthoritativeVFPBinding`` minted ONLY by the
        tested authoritative ingestion adapter for the SAME relationship
        fingerprint and relation count.  The public boolean and the
        provenance label alone are NEVER sufficient: without a binding the
        maximum level is ``DECLARED_RELATIONS_VERIFIED``; a SUPPLIED but
        inconsistent binding fails closed with a typed
        ``RELATIONSHIP_AUTHORITY_BINDING_MISMATCH`` refusal;
      * otherwise ``DECLARED_RELATIONS_VERIFIED``.
    * any failed or incomplete relation — ``INCOMPLETE``.

    The payload never claims full database relational correctness; the
    machine-readable scope note is carried by every derivation.
    """
    if authority_binding is not None:
        # Fail closed loudly on a SUPPLIED-but-inconsistent binding,
        # regardless of the evidence state (a missing binding is simply
        # never granted — see _validated_authority_binding).
        _validated_authority_binding(relationships, report, authority_binding)
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
                # The trust credential: a valid internal binding minted ONLY
                # by the tested authoritative ingestion adapter.  The public
                # boolean and provenance label alone are descriptive facts.
                and _validated_authority_binding(
                    relationships, report, authority_binding
                )
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