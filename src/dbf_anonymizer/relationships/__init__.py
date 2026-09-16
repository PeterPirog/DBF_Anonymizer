"""Typed relationship metadata, documents, compatibility and evidence.

The ONE authoritative internal boundary for declared primary/foreign-key
relationship metadata (REQ-P3-001..003).  It is independent from DBF
parsing, imports no ``dbfbridge`` namespace and never carries actual key
values.  The document boundary accepts metadata from policy files or
``mcp-vfp9sp2-toolchain``-produced material (adapter boundary only — no MCP
transport exists in this package).
"""

from __future__ import annotations

from dbf_anonymizer.relationships.compatibility import (
    resolved_relation_domain,
    validate_document_compatibility,
    validate_relation_group_compatibility,
)
from dbf_anonymizer.relationships.document import (
    canonical_relationship_bytes,
    parse_relationship_document,
    relationship_fingerprint,
    relationship_metadata_from_document,
)
from dbf_anonymizer.relationships.evidence import (
    RelationalMetrics,
    relation_metrics,
)
from dbf_anonymizer.relationships.models import (
    COMPARISON_EXACT_VALUE,
    COMPARISON_UNSPECIFIED,
    KEY_ROLES,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    PROVENANCE_POLICY_FILE,
    RELATIONSHIP_METADATA_SCHEMA_VERSION,
    RELATIONSHIP_PROVENANCES,
    SUPPORTED_RELATIONSHIP_DBF_TYPES,
    RelationGroup,
    RelationMember,
    RelationshipDocument,
    normalize_relative_table_path,
)

__all__ = [
    "RELATIONSHIP_METADATA_SCHEMA_VERSION",
    "KEY_ROLES",
    "COMPARISON_EXACT_VALUE",
    "COMPARISON_UNSPECIFIED",
    "RELATIONSHIP_PROVENANCES",
    "SUPPORTED_RELATIONSHIP_DBF_TYPES",
    "PROVENANCE_POLICY_FILE",
    "PROVENANCE_MCP_VFP9SP2_TOOLCHAIN",
    "RelationGroup",
    "RelationMember",
    "RelationshipDocument",
    "normalize_relative_table_path",
    "parse_relationship_document",
    "canonical_relationship_bytes",
    "relationship_fingerprint",
    "relationship_metadata_from_document",
    "validate_relation_group_compatibility",
    "validate_document_compatibility",
    "resolved_relation_domain",
    "RelationalMetrics",
    "relation_metrics",
]