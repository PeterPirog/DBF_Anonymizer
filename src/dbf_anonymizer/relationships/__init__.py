"""Typed relationship metadata, documents, compatibility and evidence.

The ONE authoritative internal boundary for declared primary/foreign-key
relationship metadata (REQ-P3-001..003) plus the deterministic value-free
verification evidence (REQ-P3-006) and the evidence-based assurance
derivation (REQ-P3-007, delivered through the canonical public
``dbf_anonymizer.RelationalAssurance`` model).  It is independent from DBF
parsing, imports no ``dbfbridge`` namespace and never carries actual key
values.  The document boundary accepts metadata from policy files or
``mcp-vfp9sp2-toolchain``-produced material (adapter boundary only — no MCP
transport exists in this package); the tested
``authoritative_vfp_metadata_from_document`` adapter certifies ALREADY
INJECTED authoritative VFP metadata.
"""

from __future__ import annotations

from dbf_anonymizer.relationships.assurance import (
    RELATIONAL_ASSURANCE_SCOPE_NOTE,
    derive_relational_assurance,
)
from dbf_anonymizer.relationships.compatibility import (
    resolved_numeric_domain,
    resolved_relation_domain,
    validate_document_compatibility,
    validate_relation_group_compatibility,
)
from dbf_anonymizer.relationships.document import (
    authoritative_vfp_metadata_from_document,
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
    INTEGER_MEMBER_BYTE_WIDTH,
    KEY_ROLES,
    NUMERIC_MEMBER_ENCODING,
    NUMERIC_STRATEGIES,
    NUMERIC_STRATEGY_IDENTITY,
    NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
    PROVENANCE_POLICY_FILE,
    RELATIONSHIP_METADATA_SCHEMA_VERSION,
    RELATIONSHIP_PROVENANCES,
    SUPPORTED_NUMERIC_RELATIONSHIP_DBF_TYPES,
    SUPPORTED_RELATIONSHIP_DBF_TYPES,
    SUPPORTED_TEXT_RELATIONSHIP_DBF_TYPES,
    RelationGroup,
    RelationMember,
    RelationshipDocument,
    normalize_relative_table_path,
)
from dbf_anonymizer.relationships.verification import (
    EVIDENCE_SCHEMA_VERSION,
    INVARIANT_FOREIGN_MULTIPLICITY,
    INVARIANT_MATCHED_ROWS,
    INVARIANT_NULL_COUNTS,
    INVARIANT_ORPHAN_COUNT,
    INVARIANT_PARENT_UNIQUENESS,
    RELATIONSHIP_INVARIANTS,
    RelationEvidenceCounts,
    RelationInvariantResult,
    RelationSideMetrics,
    RelationVerificationEvidence,
    RelationshipEvidenceAccumulator,
    RelationshipVerificationReport,
    VerificationStatus,
    compare_relation_metrics,
    verify_relationships,
)

__all__ = [
    "RELATIONSHIP_METADATA_SCHEMA_VERSION",
    "KEY_ROLES",
    "COMPARISON_EXACT_VALUE",
    "COMPARISON_UNSPECIFIED",
    "RELATIONSHIP_PROVENANCES",
    "SUPPORTED_RELATIONSHIP_DBF_TYPES",
    "SUPPORTED_TEXT_RELATIONSHIP_DBF_TYPES",
    "SUPPORTED_NUMERIC_RELATIONSHIP_DBF_TYPES",
    "NUMERIC_STRATEGIES",
    "NUMERIC_STRATEGY_IDENTITY",
    "NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE",
    "NUMERIC_MEMBER_ENCODING",
    "INTEGER_MEMBER_BYTE_WIDTH",
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
    "authoritative_vfp_metadata_from_document",
    "validate_relation_group_compatibility",
    "validate_document_compatibility",
    "resolved_relation_domain",
    "resolved_numeric_domain",
    "RelationalMetrics",
    "relation_metrics",
    "EVIDENCE_SCHEMA_VERSION",
    "RELATIONSHIP_INVARIANTS",
    "INVARIANT_PARENT_UNIQUENESS",
    "INVARIANT_ORPHAN_COUNT",
    "INVARIANT_MATCHED_ROWS",
    "INVARIANT_NULL_COUNTS",
    "INVARIANT_FOREIGN_MULTIPLICITY",
    "VerificationStatus",
    "RelationSideMetrics",
    "RelationEvidenceCounts",
    "RelationInvariantResult",
    "RelationVerificationEvidence",
    "RelationshipVerificationReport",
    "RelationshipEvidenceAccumulator",
    "compare_relation_metrics",
    "verify_relationships",
    "RELATIONAL_ASSURANCE_SCOPE_NOTE",
    "derive_relational_assurance",
]