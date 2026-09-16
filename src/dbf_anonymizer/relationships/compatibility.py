"""Declared C/V relation compatibility preflight (REQ-P3-003).

The ONE authoritative compatibility boundary for declared Character/Varchar
relationship groups, evaluated BEFORE any transformation-equivalent action:

* every member must be a supported ``C``/``V`` logical type (the global text
  domain resolution of REQ-P3-003 applies only to this cluster);
* the group's comparison semantics must be the one semantics this release can
  truthfully honor (``EXACT_VALUE``); richer/unknown semantics
  (``UNSPECIFIED``) can never back a join-preservation claim and fail closed;
* every member encoding must admit the PROVEN safe shared alphabet (the
  single-byte proof of the P1/P2 text policy, judged against the live codec
  registry) — mixed proven code pages are compatible; any encoding for which
  the safe alphabet cannot be proven is refused;
* the NULL policy must be consistent across the group's members;
* domain resolution maps every C/V member to the ONE global text mapping
  domain (never a second or relation-local domain); overlapping relation
  groups must agree on every member's metadata or fail closed.

Byte-width truthfulness: differing byte widths across members are COMPATIBLE
(the binding constraint is the narrowest member width, which the P2
allocation path already enforces via its strictest-width rule); a member
cannot declare a width below one byte.  No pseudonym is ever truncated to
make a relationship fit.

Collation truthfulness: only exact decoded-value equality is honored; the
package never claims full VFP collation or application-level relationship
equivalence (future REQ-P3-007 scope).
"""

from __future__ import annotations

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PolicyError
from dbf_anonymizer.relationships.models import (
    COMPARISON_EXACT_VALUE,
    KEY_ROLE_CANDIDATE,
    KEY_ROLE_FOREIGN,
    KEY_ROLE_PRIMARY,
    RelationGroup,
    RelationMember,
    RelationshipDocument,
)

__all__ = [
    "validate_relation_group_compatibility",
    "validate_document_compatibility",
    "resolved_relation_domain",
]


def _incompatible(detail_code: str) -> PolicyError:
    return PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="preflight", detail_code=detail_code),
    )


def validate_relation_group_compatibility(group: RelationGroup) -> None:
    """The declared-relation compatibility preflight for one group."""
    for member in group.members:
        if member.dbf_type not in ("C", "V"):
            # Non-character members resolve to their own later P3 requirements.
            raise _incompatible("RELATIONSHIP_DBF_TYPE_UNSUPPORTED")
    if group.comparison != "EXACT_VALUE":
        # Only exact decoded C/V value equality is proven in this release.
        raise _incompatible("RELATIONSHIP_COMPARISON_INCOMPATIBLE")
    nullity: set[bool] = {member.nullable for member in group.members}
    if len(nullity) > 1:
        raise _incompatible("RELATIONSHIP_NULL_POLICY_INCONSISTENT")
    encodings = sorted({member.encoding for member in group.members})
    from dbf_anonymizer.transforms.text import candidate_alphabet

    if not candidate_alphabet(encodings):
        # No PROVEN safe shared representation across the member code pages:
        # fail closed instead of guessing (no truncation, no case games).
        raise _incompatible("RELATIONSHIP_ENCODING_INCOMPATIBLE")


def validate_document_compatibility(document: RelationshipDocument) -> None:
    """Compatibility for the WHOLE document, including cross-group overlap.

    Every group is validated on its own; in addition, a member
    (table, field) shared by multiple relation groups must declare
    IDENTICAL metadata everywhere — ambiguous overlapping definitions fail
    closed so one logical key can never receive incompatible pseudonyms.
    """
    seen: dict[tuple[str, str], RelationMember] = {}
    for group in document.groups:
        validate_relation_group_compatibility(group)
        for member in group.members:
            identity = (member.table_path, member.field_name)
            previous = seen.get(identity)
            if previous is not None and (
                previous.dbf_type != member.dbf_type
                or previous.byte_width != member.byte_width
                or previous.encoding != member.encoding
                or previous.nullable != member.nullable
            ):
                raise _incompatible("RELATIONSHIP_DOMAIN_CONFLICT")
            seen.setdefault(identity, member)


def resolved_relation_domain(group: RelationGroup) -> str:
    """The ONE compatible mapping domain of a declared C/V relation group.

    Architecture-consistent resolution: every supported C/V member shares
    the existing global text mapping domain — no relation-local domains are
    introduced.  A group containing any unsupported type fails closed.
    """
    for member in group.members:
        if member.dbf_type not in ("C", "V"):
            raise _incompatible("RELATIONSHIP_DBF_TYPE_UNSUPPORTED")
    from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID

    return GLOBAL_TEXT_DOMAIN_ID