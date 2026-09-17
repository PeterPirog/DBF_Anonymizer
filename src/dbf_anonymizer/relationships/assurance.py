"""Relational assurance levels derived from verification evidence (P3-007).

The evidence-based derivation of the FOUR exact architecture levels —
``GLOBAL_EXACT_VALUE``, ``DECLARED_RELATIONS_VERIFIED``, ``VFP_METADATA_VERIFIED``
and ``INCOMPLETE`` — plus the compact public summary model.  The level is
derived from evidence, never from user preference, and a provenance label
alone is never evidence.

Truthful scope: NO level claims full database relational correctness.  Even
``VFP_METADATA_VERIFIED`` covers ONLY the scope that was actually validated —
the declared relations verified from complete before/after evidence plus the
explicitly injected authoritative metadata coverage.  It never means:

* arbitrary application-level business rules are verified;
* DBC persistent-relation expressions are evaluated (unless actually
  available, supplied and checked);
* arbitrary CDX index expressions are understood;
* trigger/stored-procedure/application semantics are verified.

The scope statement is machine-encoded in the
:attr:`RelationalAssuranceSummary.scope_note` stable token, so no consumer
can mistake the level for full database relational correctness.
"""

from __future__ import annotations

from dataclasses import dataclass

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VerificationError
from dbf_anonymizer.models import (
    JsonDict,
    PublicModel,
    RelationalAssuranceLevel,
    RelationshipMetadata,
    _payload,
    _validated_code,
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
    "RelationalAssuranceSummary",
    "derive_relational_assurance",
]

#: The stable machine token carried by every assurance summary: the level
#: describes ONLY the declared/injected metadata scope that was actually
#: verified — never full database relational correctness (DBC expressions,
#: CDX expressions, application-level key semantics, triggers or stored
#: procedures stay out of scope).
RELATIONAL_ASSURANCE_SCOPE_NOTE = "DECLARED_AND_INJECTED_METADATA_SCOPE_ONLY"


@dataclass(frozen=True, slots=True)
class RelationalAssuranceSummary(PublicModel):
    """The compact public relationship-assurance summary (REQ-P3-007).

    Count-only, value-free and deterministic: the derived level plus the
    declared/verified/failed/incomplete relation counts, the canonical
    relationship-document fingerprint the evidence is bound to and the stable
    evidence schema version.  The counts always satisfy
    ``verified + failed + incomplete == relation_count``.
    """

    level: RelationalAssuranceLevel
    relation_count: int
    verified_relation_count: int
    failed_relation_count: int
    incomplete_relation_count: int
    relationship_fingerprint: str
    evidence_schema_version: str
    scope_note: str

    def __post_init__(self) -> None:
        if not isinstance(self.level, RelationalAssuranceLevel):
            raise TypeError("level must be a RelationalAssuranceLevel")
        for field_name, value in (
            ("relation_count", self.relation_count),
            ("verified_relation_count", self.verified_relation_count),
            ("failed_relation_count", self.failed_relation_count),
            ("incomplete_relation_count", self.incomplete_relation_count),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an exact integer")
            if value < 0:
                raise ValueError(f"{field_name} must be non-negative")
        if (
            self.verified_relation_count
            + self.failed_relation_count
            + self.incomplete_relation_count
            != self.relation_count
        ):
            raise ValueError(
                "verified + failed + incomplete relations must equal the declared relations"
            )
        _validated_code(
            self.relationship_fingerprint, field_name="relationship_fingerprint"
        )
        if self.evidence_schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError(
                "unsupported relationship-evidence schema version (fail closed)"
            )
        if self.scope_note != RELATIONAL_ASSURANCE_SCOPE_NOTE:
            raise ValueError("the assurance scope note is a stable constant")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationalAssuranceSummary",
            level=self.level,
            relation_count=self.relation_count,
            verified_relation_count=self.verified_relation_count,
            failed_relation_count=self.failed_relation_count,
            incomplete_relation_count=self.incomplete_relation_count,
            relationship_fingerprint=self.relationship_fingerprint,
            evidence_schema_version=self.evidence_schema_version,
            scope_note=self.scope_note,
        )


def derive_relational_assurance(
    relationships: RelationshipMetadata,
    report: RelationshipVerificationReport | None,
) -> RelationalAssuranceSummary:
    """Derive the assurance level from evidence — never from preference.

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

      * ``VFP_METADATA_VERIFIED`` only when authoritative VFP metadata was
        explicitly supplied through the accepted adapter boundary (the
        metadata model's ``authoritative`` flag) AND its provenance is the
        ``MCP_VFP9SP2_TOOLCHAIN`` token AND every declared relation carries
        complete verified evidence — the provenance LABEL alone is never
        sufficient and an incomplete coverage is never upgraded;
      * otherwise ``DECLARED_RELATIONS_VERIFIED``.
    * any failed or incomplete relation — ``INCOMPLETE``.

    The summary never claims full database relational correctness; the
    machine-readable scope note is carried by every payload.
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
    return RelationalAssuranceSummary(
        level=level,
        relation_count=relation_count,
        verified_relation_count=verified,
        failed_relation_count=failed,
        incomplete_relation_count=relation_count - verified - failed,
        relationship_fingerprint=relationships.relationship_fingerprint,
        evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
        scope_note=RELATIONAL_ASSURANCE_SCOPE_NOTE,
    )