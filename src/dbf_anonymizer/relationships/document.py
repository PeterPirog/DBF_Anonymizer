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
from dataclasses import dataclass
from typing import Any, Mapping

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PolicyError
from dbf_anonymizer.models import RelationshipMetadata
from dbf_anonymizer.relationships.models import (
    COMPARISON_SEMANTICS,
    KEY_ROLES,
    NUMERIC_STRATEGIES,
    NUMERIC_STRATEGY_IDENTITY,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
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
    "authoritative_vfp_metadata_from_document",
]

_MEMBER_KEYS = frozenset(
    {"table", "field", "role", "ordinal", "dbf_type", "byte_width", "encoding", "nullable"}
)
_GROUP_KEYS = frozenset(
    {
        "relation_id",
        "provenance",
        "comparison",
        "source_digest",
        "members",
        "numeric_strategy",
    }
)


def _document_invalid(detail_code: str) -> PolicyError:
    return PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


@dataclass(frozen=True)
class _AuthoritativeVFPBinding:
    """The INTERNAL, non-public authority proof of the validated adapter.

    Created ONLY by
    :func:`authoritative_vfp_metadata_from_document` after its typed
    validation, this is the in-process trust boundary object that
    :func:`~dbf_anonymizer.relationships.assurance.derive_relational_assurance`
    requires before it may report ``VFP_METADATA_VERIFIED``.  It carries
    ONLY bounded structural facts — the canonical relationship fingerprint,
    the declared relation count and the metadata schema version — and it is
    deliberately:

    * NOT a :class:`~dbf_anonymizer.models.PublicModel` and never serialized
      into any public/transfer payload;
    * NOT exported from ``dbf_anonymizer`` or the public relationships API;
    * free of key values, pseudonyms, paths, secrets or reverse mappings.

    This is an architectural trust boundary, not a cryptographic secret: the
    public ``RelationshipMetadata.authoritative`` boolean stays DESCRIPTIVE
    metadata and is never by itself sufficient to cross this boundary.
    """

    relationship_fingerprint: str
    relation_count: int
    metadata_schema_version: str


@dataclass(frozen=True)
class _AuthoritativeVFPMetadata:
    """The internal result of the validated authoritative ingestion adapter.

    Pairs the canonical descriptive public
    :class:`~dbf_anonymizer.models.RelationshipMetadata` with the internal
    ``_AuthoritativeVFPBinding`` minted by the SAME validated adapter call,
    so callers pass a single coherent authority object onward.
    """

    metadata: RelationshipMetadata
    binding: _AuthoritativeVFPBinding


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
    unknown = set(group_payload) - _GROUP_KEYS
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
    raw_strategy = group_payload.get("numeric_strategy")
    if raw_strategy is not None and raw_strategy not in NUMERIC_STRATEGIES:
        # Unknown numeric strategies fail closed (no silent normalization).
        raise _document_invalid("RELATIONSHIP_NUMERIC_STRATEGY_INVALID")
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
        numeric_strategy=(
            NUMERIC_STRATEGY_IDENTITY if raw_strategy is None else str(raw_strategy)
        ),
    )


def parse_relationship_document(payload: Mapping[str, Any]) -> RelationshipDocument:
    """Parse and validate one versioned relationship metadata document.

    Supported schema: exactly ``metadata_schema_version == "1.0"``.  Any
    other version, shape, role, semantics, provenance, type, numeric
    strategy, ordinal sequence or path form fails closed; malformed semantic
    structures are never normalized into valid ones.  REQUIRED keys
    (document: ``metadata_schema_version``/``relations``; group:
    ``relation_id``/``provenance``/``comparison``/``members``; member: all
    eight member keys) must be PRESENT — a missing required key is a typed
    refusal, never a silent ``None`` coercion; ``source_digest`` and
    ``numeric_strategy`` (REQ-P3-005, default ``IDENTITY``) remain the two
    optional bounded group keys.
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
    provenance becomes the bounded metadata token.  The result is ALWAYS
    NON-authoritative: declared planning metadata never masquerades as
    injected authoritative VFP metadata (see
    :func:`authoritative_vfp_metadata_from_document`).
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


def authoritative_vfp_metadata_from_document(
    document: RelationshipDocument,
    *,
    metadata_path: str | None = None,
) -> _AuthoritativeVFPMetadata:
    """The typed adapter for ALREADY-INJECTED authoritative VFP metadata.

    This is the ONE tested authoritative ingestion boundary of REQ-P3-007:
    it accepts metadata that a host has ALREADY injected (source-neutral,
    in-memory) and validates that it genuinely qualifies BEFORE minting the
    internal trust binding:

    * the document declares at least one relation;
    * EVERY group provenance is exactly ``MCP_VFP9SP2_TOOLCHAIN`` — a
      POLICY_FILE document or a MIXED-provenance document never qualifies;
    * the canonical relationship fingerprint of THIS document becomes the
      metadata fingerprint (authority is bound to the same document the
      verification report must bind to);
    * the metadata version is the supported schema (the typed parser already
      refuses every other version);
    * paths stay normalized-relative and no key value or absolute path is
      added.

    The adapter performs NO network, NO MCP transport, NO COM and NO VFP
    process automation: the injection already happened; this boundary only
    certifies the injected facts.  A document that does not qualify fails
    closed with the stable typed ``RELATIONSHIP_AUTHORITATIVE_*`` refusals.

    The result carries the canonical descriptive public
    :class:`~dbf_anonymizer.models.RelationshipMetadata` plus the INTERNAL
    ``_AuthoritativeVFPBinding`` — the non-public authority proof that
    :func:`~dbf_anonymizer.relationships.assurance.derive_relational_assurance`
    requires for the ``VFP_METADATA_VERIFIED`` level.  The public
    ``authoritative`` boolean on ``RelationshipMetadata`` is DESCRIPTIVE
    metadata; it is never by itself sufficient to cross the authoritative
    assurance boundary.
    """
    if not document.groups:
        raise _document_invalid("RELATIONSHIP_AUTHORITATIVE_EMPTY")
    provenances = {group.provenance for group in document.groups}
    if provenances != {PROVENANCE_MCP_VFP9SP2_TOOLCHAIN}:
        # A POLICY_FILE or MIXED-provenance document is never authoritative
        # VFP metadata — the provenance label alone is never evidence, and
        # mixed provenance is ambiguous by definition.
        raise _document_invalid("RELATIONSHIP_AUTHORITATIVE_PROVENANCE_INVALID")
    fingerprint = relationship_fingerprint(document)
    metadata = RelationshipMetadata(
        metadata_schema_version=RELATIONSHIP_METADATA_SCHEMA_VERSION,
        provenance=PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
        relationship_fingerprint=fingerprint,
        relation_count=len(document.groups),
        authoritative=True,
        metadata_path=metadata_path,
    )
    # The binding is minted ONLY here, after the typed validation above: it
    # is the in-process authority proof, not a cryptographic secret and not a
    # public credential.
    binding = _AuthoritativeVFPBinding(
        relationship_fingerprint=fingerprint,
        relation_count=len(document.groups),
        metadata_schema_version=RELATIONSHIP_METADATA_SCHEMA_VERSION,
    )
    return _AuthoritativeVFPMetadata(metadata=metadata, binding=binding)