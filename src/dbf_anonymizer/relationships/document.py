"""Versioned relationship document: parsing, canonicalization, fingerprint.

REQ-P3-001 boundary.  One deterministic versioned JSON document shape is
accepted (schema ``1.0``); every other version or shape FAILS CLOSED —
malformed semantic structures are never silently normalized into valid ones.

Canonicalization: the canonical bytes are independent of JSON key order,
whitespace and input member-list order, while preserving the SEMANTICALLY
SIGNIFICANT ordering (key role + composite ordinal + member identity).  The
relationship fingerprint is the SHA-256 of the canonical bytes; different
semantic metadata always changes it, and actual key values never enter the
material (there are none in the model).

The adapter :func:`relationship_metadata_from_document` integrates with the
existing P1/P2 ``RelationshipMetadata`` planning model without duplicating it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PolicyError
from dbf_anonymizer.models import RelationshipMetadata
from dbf_anonymizer.relationships.models import (
    COMPARISON_SEMANTICS,
    KEY_ROLES,
    RELATIONSHIP_METADATA_SCHEMA_VERSION,
    RELATIONSHIP_PROVENANCES,
    SUPPORTED_RELATIONSHIP_DBF_TYPES,
    RelationGroup,
    RelationMember,
    RelationshipDocument,
    _validate_bounded_token,
)

__all__ = [
    "parse_relationship_document",
    "canonical_relationship_bytes",
    "relationship_fingerprint",
    "relationship_metadata_from_document",
]

_MEMBER_KEYS = frozenset(
    {"table", "field", "role", "ordinal", "dbf_type", "byte_width", "encoding", "nullable"}
)


def _document_invalid(detail_code: str) -> PolicyError:
    return PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


def _require_mapping(value: object, detail: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _document_invalid(detail)
    return value


def _parse_member(payload: object) -> RelationMember:
    if not isinstance(payload, Mapping):
        raise _document_invalid("RELATIONSHIP_MEMBER_INVALID")
    unknown = set(payload) - _MEMBER_KEYS
    if unknown:
        raise _document_invalid("RELATIONSHIP_MEMBER_KEY_UNKNOWN")
    missing = _MEMBER_KEYS - set(payload)
    if missing:
        raise _document_invalid("RELATIONSHIP_MEMBER_KEY_MISSING")
    role = payload.get("role")
    if role not in KEY_ROLES:
        raise _document_invalid("RELATIONSHIP_KEY_ROLE_INVALID")
    dbf_type = payload.get("dbf_type")
    if dbf_type not in SUPPORTED_RELATIONSHIP_DBF_TYPES:
        raise _document_invalid("RELATIONSHIP_DBF_TYPE_UNSUPPORTED")
    # The typed model validates every raw value fail-closed in __post_init__;
    # the local Any aliases only satisfy the static contract of that check.
    raw_table: Any = payload.get("table")
    raw_field: Any = payload.get("field")
    raw_ordinal: Any = payload.get("ordinal")
    raw_width: Any = payload.get("byte_width")
    raw_encoding: Any = payload.get("encoding")
    raw_nullable: Any = payload.get("nullable")
    return RelationMember(
        table_path=raw_table,
        field_name=raw_field,
        key_role=str(role),
        composite_ordinal=raw_ordinal,
        dbf_type=str(dbf_type),
        byte_width=raw_width,
        encoding=raw_encoding,
        nullable=raw_nullable,
    )


def _parse_group(payload: object) -> RelationGroup:
    group_payload = _require_mapping(payload, "RELATIONSHIP_GROUP_INVALID")
    unknown = set(group_payload) - {
        "relation_id", "provenance", "comparison", "source_digest", "members"
    }
    if unknown:
        raise _document_invalid("RELATIONSHIP_GROUP_KEY_UNKNOWN")
    missing = {"relation_id", "provenance", "comparison", "members"} - set(group_payload)
    if missing:
        raise _document_invalid("RELATIONSHIP_GROUP_KEY_MISSING")
    comparison = group_payload.get("comparison")
    if comparison not in COMPARISON_SEMANTICS:
        raise _document_invalid("RELATIONSHIP_COMPARISON_INVALID")
    provenance = group_payload.get("provenance")
    if provenance not in RELATIONSHIP_PROVENANCES:
        raise _document_invalid("RELATIONSHIP_PROVENANCE_INVALID")
    raw_members = group_payload.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise _document_invalid("RELATIONSHIP_MEMBERS_EMPTY")
    members = tuple(_parse_member(member) for member in raw_members)
    source_digest = group_payload.get("source_digest")
    if source_digest is not None:
        _validate_bounded_token(source_digest, "RELATIONSHIP_SOURCE_DIGEST_INVALID")
    # The required scalar values are validated WITHOUT coercion: the raw
    # values pass through the typed model, which refuses nulls and wrong
    # types (no str(None)-style conversion as validation).
    raw_relation_id: Any = group_payload.get("relation_id")
    raw_comparison: Any = comparison
    raw_provenance: Any = provenance
    return RelationGroup(
        relation_id=raw_relation_id,
        members=members,
        comparison=raw_comparison,
        provenance=raw_provenance,
        source_digest=None if source_digest is None else str(source_digest),
    )


def parse_relationship_document(payload: Mapping[str, Any]) -> RelationshipDocument:
    """Parse and validate one versioned relationship metadata document.

    Supported schema: exactly ``metadata_schema_version == "1.0"``.  Any
    other version, shape, role, semantics, provenance, type, ordinal
    sequence or path form fails closed; malformed semantic structures are
    never normalized into valid ones.  REQUIRED keys (document:
    ``metadata_schema_version``/``relations``; group:
    ``relation_id``/``provenance``/``comparison``/``members``; member: all
    eight member keys) must be PRESENT — a missing required key is a typed
    refusal, never a silent ``None`` coercion; ``source_digest`` remains
    the one optional bounded non-secret source identifier.
    """
    document = _require_mapping(payload, "RELATIONSHIP_DOCUMENT_INVALID")
    unknown_top = set(document) - {"metadata_schema_version", "relations"}
    if unknown_top:
        raise _document_invalid("RELATIONSHIP_DOCUMENT_KEY_UNKNOWN")
    missing_top = {"metadata_schema_version", "relations"} - set(document)
    if missing_top:
        raise _document_invalid("RELATIONSHIP_DOCUMENT_KEY_MISSING")
    if document.get("metadata_schema_version") != RELATIONSHIP_METADATA_SCHEMA_VERSION:
        raise _document_invalid("RELATIONSHIP_METADATA_VERSION_UNSUPPORTED")
    raw_relations = document.get("relations")
    if not isinstance(raw_relations, list):
        raise _document_invalid("RELATIONSHIP_RELATIONS_INVALID")
    groups = tuple(_parse_group(relation) for relation in raw_relations)
    return RelationshipDocument(groups=groups)


def canonical_relationship_bytes(document: RelationshipDocument) -> bytes:
    """The deterministic canonical bytes of one relationship document.

    Independent of JSON key order, whitespace, input member-list order AND
    input relation-group order (groups are canonicalized by their stable
    ``relation_id`` — document order carries no semantics); the semantically
    significant (role, composite ordinal, member identity) ordering is
    preserved, so composite keys keep (A,B) != (B,A).
    """
    canonical = json.dumps(
        document.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return canonical.encode("ascii")


def relationship_fingerprint(document: RelationshipDocument) -> str:
    """The stable SHA-256 fingerprint of the canonical relationship bytes."""
    return hashlib.sha256(canonical_relationship_bytes(document)).hexdigest()


def relationship_metadata_from_document(
    document: RelationshipDocument,
    *,
    metadata_path: str | None = None,
) -> RelationshipMetadata:
    """The existing planning-facing metadata for one parsed document.

    The adapter keeps the P1/P2 fingerprint mechanism intact: the canonical
    fingerprint becomes the dataset's ``relationship_fingerprint`` and the
    provenance becomes the bounded metadata token.
    """
    provenances = {group.provenance for group in document.groups}
    provenance = next(iter(provenances)) if len(provenances) == 1 else "MIXED"
    return RelationshipMetadata(
        metadata_schema_version=RELATIONSHIP_METADATA_SCHEMA_VERSION,
        provenance=provenance,
        relationship_fingerprint=relationship_fingerprint(document),
        relation_count=len(document.groups),
        authoritative=False,
        metadata_path=metadata_path,
    )