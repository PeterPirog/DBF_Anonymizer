"""Declared relation compatibility preflight (REQ-P3-003/REQ-P3-005).

The ONE authoritative compatibility boundary for declared relationship
groups, evaluated BEFORE any transformation-equivalent action:

* every member must be a supported logical type: ``C``/``V`` text members
  (the global text domain) or, explicitly declared, ``I``/``N`` numeric key
  members (REQ-P3-005); floating/currency/logical numeric runtime types
  (``F``/``Y``/``B``/``L``) are never reinterpreted as integer key domains;
* the group's comparison semantics must be the one semantics this release can
  truthfully honor (``EXACT_VALUE``); richer/unknown semantics
  (``UNSPECIFIED``) can never back a join-preservation claim and fail closed;
* every text member encoding must admit the PROVEN safe shared alphabet (the
  single-byte proof of the P1/P2 text policy, judged against the live codec
  registry) — mixed proven code pages are compatible; any encoding for which
  the safe alphabet cannot be proven is refused.  Numeric key members carry
  no text code-page semantics and never enter the alphabet proof;
* the NULL policy must be consistent across the group's members;
* the numeric key strategy (REQ-P3-005) must be EXPLICIT: reversible
  bijective numeric pseudonymization is never inferred from the member type
  and a declaration without a numeric member is refused; unknown strategies
  fail closed at the typed model boundary;
* text domain resolution maps every ``C``/``V`` member to the ONE global text
  mapping domain (never a second or relation-local domain); numeric key
  domain resolution (REQ-P3-005) maps each ``REVERSIBLE_BIJECTIVE`` group to
  ONE deterministic shared candidate domain for its parent and all foreign
  members; overlapping relation groups must agree on every member's metadata
  or fail closed (ambiguous or conflicting numeric domains fail closed).

Byte-width truthfulness: differing text member byte widths across members are
COMPATIBLE (the binding constraint is the narrowest member width, which the
P2 allocation path already enforces via its strictest-width rule); numeric
member widths are format-defined facts (Integer ``I`` = 4 bytes; Numeric
``N`` = the declared width) and are schema-bound in planning.  A member
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
    NUMERIC_STRATEGY_IDENTITY,
    NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
    SUPPORTED_RELATIONSHIP_DBF_TYPES,
    RelationGroup,
    RelationMember,
    RelationshipDocument,
)

__all__ = [
    "validate_relation_group_compatibility",
    "validate_document_compatibility",
    "resolved_relation_domain",
    "resolved_numeric_domain",
]


def _incompatible(detail_code: str) -> PolicyError:
    return PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="preflight", detail_code=detail_code),
    )


def validate_relation_group_compatibility(group: RelationGroup) -> None:
    """The declared-relation compatibility preflight for one group."""
    for member in group.members:
        if member.dbf_type not in SUPPORTED_RELATIONSHIP_DBF_TYPES:
            # Only the bounded C/V (text) and I/N (declared numeric key)
            # vocabularies are supported members in this release.
            raise _incompatible("RELATIONSHIP_DBF_TYPE_UNSUPPORTED")
    if group.comparison != COMPARISON_EXACT_VALUE:
        # Only exact decoded value equality is proven in this release.
        raise _incompatible("RELATIONSHIP_COMPARISON_INCOMPATIBLE")
    nullity: set[bool] = {member.nullable for member in group.members}
    if len(nullity) > 1:
        raise _incompatible("RELATIONSHIP_NULL_POLICY_INCONSISTENT")
    text_members = [m for m in group.members if m.dbf_type in ("C", "V")]
    if text_members:
        encodings = sorted({member.encoding for member in text_members})
        from dbf_anonymizer.transforms.text import candidate_alphabet

        if not candidate_alphabet(encodings):
            # No PROVEN safe shared representation across the member code
            # pages: fail closed instead of guessing (no truncation, no case
            # games).
            raise _incompatible("RELATIONSHIP_ENCODING_INCOMPATIBLE")
    numeric_members = [m for m in group.members if m.is_numeric_member]
    if group.numeric_strategy == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE:
        if not numeric_members:
            # The explicit reversible numeric strategy is meaningless without
            # a numeric key member: fail closed (never silently inferred).
            raise _incompatible("RELATIONSHIP_NUMERIC_STRATEGY_MEMBER_REQUIRED")
    elif group.numeric_strategy == NUMERIC_STRATEGY_IDENTITY:
        pass  # the truthful default: numeric key members stay value-identical


def validate_document_compatibility(document: RelationshipDocument) -> None:
    """Compatibility for the WHOLE document, including cross-group overlap.

    Every group is validated on its own; in addition, a member
    (table, field) shared by multiple relation groups must declare
    IDENTICAL metadata everywhere — ambiguous overlapping definitions fail
    closed so one logical key can never receive incompatible pseudonyms.
    A numeric key member shared by multiple groups must additionally never
    receive conflicting numeric treatment: one logical numeric key can never
    be value-identical in one declared relation and pseudonymized in
    another, and two reversible declarations would map it through two
    different numeric domains — both fail closed.
    """
    seen: dict[tuple[str, str], RelationMember] = {}
    numeric_strategy_by_member: dict[tuple[str, str], str] = {}
    numeric_reversible: set[tuple[str, str]] = set()
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
            if member.is_numeric_member:
                if group.numeric_strategy == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE:
                    numeric_reversible.add(identity)
                else:
                    numeric_strategy_by_member.setdefault(
                        identity, NUMERIC_STRATEGY_IDENTITY
                    )
    # Any numeric member whose declarations do not agree on exactly one
    # numeric strategy is an ambiguous/incompatible overlap.
    conflicts = numeric_reversible.intersection(set(numeric_strategy_by_member))
    if conflicts:
        raise _incompatible("RELATIONSHIP_NUMERIC_DOMAIN_CONFLICT")
    reversible_conflicts: list[tuple[str, str]] = []
    reversible_by_identity: dict[tuple[str, str], str] = {}
    for group in document.groups:
        if group.numeric_strategy != NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE:
            continue
        for member in group.members:
            if not member.is_numeric_member:
                continue
            identity = (member.table_path, member.field_name)
            domain = resolved_numeric_domain(document, group)
            previous_domain = reversible_by_identity.get(identity)
            if previous_domain is None:
                reversible_by_identity[identity] = domain
            elif previous_domain != domain:
                # Two reversible relations would map one logical numeric key
                # through two different numeric domains.
                reversible_conflicts.append(identity)
    if reversible_conflicts:
        raise _incompatible("RELATIONSHIP_NUMERIC_DOMAIN_CONFLICT")


def resolved_relation_domain(group: RelationGroup) -> str:
    """The ONE compatible TEXT mapping domain of a declared relation group.

    Architecture-consistent resolution: every supported ``C``/``V`` member
    shares the existing global text mapping domain — no relation-local text
    domains are introduced.  A group containing any unsupported type fails
    closed.  Declared numeric key members resolve through
    :func:`resolved_numeric_domain` (REQ-P3-005), never through this text
    resolution.
    """
    for member in group.members:
        if member.dbf_type not in ("C", "V"):
            raise _incompatible("RELATIONSHIP_DBF_TYPE_UNSUPPORTED")
    from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID

    return GLOBAL_TEXT_DOMAIN_ID


def resolved_numeric_domain(document: RelationshipDocument, group: RelationGroup) -> str:
    """The ONE shared numeric key mapping domain of a declared relation.

    The domain identity is derived deterministically from the canonical
    relationship fingerprint of the WHOLE document and the stable relation
    id — never from process randomness, Python hash randomization, member
    order or key values — so the parent and ALL foreign members of the
    relation resolve to the same domain across processes and runs.  A group
    without the explicit reversible numeric strategy has no numeric mapping
    domain and fails closed here.
    """
    if group.numeric_strategy != NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE:
        raise _incompatible("RELATIONSHIP_NUMERIC_STRATEGY_IDENTITY_HAS_NO_DOMAIN")
    if not any(member.is_numeric_member for member in group.members):
        raise _incompatible("RELATIONSHIP_NUMERIC_STRATEGY_MEMBER_REQUIRED")
    from dbf_anonymizer.relationships.document import relationship_fingerprint
    from dbf_anonymizer.vault.numeric_allocation import numeric_key_domain_id

    if group not in document.groups:
        raise _incompatible("RELATIONSHIP_GROUP_NOT_IN_DOCUMENT")
    return numeric_key_domain_id(relationship_fingerprint(document), group.relation_id)