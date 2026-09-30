"""External VFP relationship/index metadata consumer contract (REQ-P6-006).

The ONE DBF_Anonymizer-owned, versioned, transport-neutral,
producer-independent contract for external VFP relationship/index metadata.
A future higher-level analyzer - including ``mcp-vfp9sp2-toolchain`` - can
IMPLEMENT this contract (emit conforming JSON) without DBF_Anonymizer
importing, executing or depending on any producer, without MCP libraries,
without a VFP runtime and without network access.

ONE relationship semantic model: an accepted external envelope is normalized
through the EXISTING P3 relationship-document parser
(:func:`~dbf_anonymizer.relationships.document.parse_relationship_document`);
no parallel "MCP relationship model" or "external VFP relationship model" is
created.  Index claims are the additive typed extension of the existing
index-assurance truthfulness: they are carried, value-free, inside the SAME
relationship document, so they participate deterministically in the EXISTING
relationship fingerprint (planning, vault compatibility, operation binding).

Producer independence: the envelope's ``producer`` provenance is structured
and bounded - ``id``/``version`` are free bounded tokens, never one
hardcoded producer.  The supplied provenance is PRESERVED (it participates
in the deterministic relationship identity and is retained on the parsed
document); it is never rewritten to a specific producer name.

Authority model (fail closed):

* ``CONTRACT_AUTHORITATIVE`` - claims may drive authoritative behavior
  (eligible for the existing authoritative ingestion boundary, therefore
  for ``VFP_METADATA_VERIFIED`` together with post-transform verification,
  and for authoritative grouping);
* ``INFERRED`` - claims are retained only as non-authoritative
  planning/reporting information; they can never drive authoritative
  grouping, strengthen relational/index assurance, or produce
  ``VFP_METADATA_VERIFIED`` (an inferred envelope that declares an
  authoritative grouping action fails closed - no silent downgrade).

Index claims carry an explicit ``verification_state``: only ``VERIFIED``
claims may ever support an index-validity guarantee; ``UNVERIFIED`` claims
are retained for planning/reporting and can never claim a valid rebuilt
CDX/IDX nor strengthen index assurance.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import PurePosixPath
from typing import Any, Mapping

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PolicyError
from dbf_anonymizer.relationships.models import (
    RELATIONSHIP_PROVENANCES,
    _validate_bounded_token,
)

__all__ = [
    "EXTERNAL_METADATA_SCHEMA_VERSION",
    "EXTERNAL_METADATA_SCHEMA_RESOURCE",
    "EXTERNAL_METADATA_CONTRACT_OWNER",
    "EXTERNAL_METADATA_AUTHORITIES",
    "AUTHORITY_CONTRACT_AUTHORITATIVE",
    "AUTHORITY_INFERRED",
    "AUTHORITATIVE_PROVENANCES",
    "CLAIM_ASSURANCES",
    "CLAIM_ASSURANCE_VERIFIED",
    "CLAIM_ASSURANCE_UNVERIFIED",
    "INDEX_CLAIM_KINDS",
    "INDEX_KIND_STRUCTURAL_CDX",
    "INDEX_KIND_STANDALONE_IDX",
    "INDEX_VERIFICATION_STATES",
    "INDEX_STATE_VERIFIED",
    "INDEX_STATE_UNVERIFIED",
    "TAG_SORT_ORDERS",
    "ExternalIndexTag",
    "ExternalIndexClaim",
    "ExternalProducerProvenance",
    "load_external_metadata_schema",
    "parse_index_claims",
    "validate_external_metadata_path",
]

#: The single supported external-metadata CONTRACT schema version.  Any other
#: version FAILS CLOSED - unknown, missing, malformed and legacy versions are
#: never normalized (no silent fallback, no downgrade).
EXTERNAL_METADATA_SCHEMA_VERSION = "1.0"

#: The stable package-resource path of the shipped JSON Schema (the wheel
#: carries it; consumers discover it through ``importlib.resources``).
EXTERNAL_METADATA_SCHEMA_RESOURCE = "schemas/external-vfp-metadata-1.0.schema.json"

#: The owner of the contract: DBF_Anonymizer itself.  The schema is
#: producer-INDEPENDENT - any bounded producer token may implement it.
EXTERNAL_METADATA_CONTRACT_OWNER = "DBF_ANONYMIZER"

AUTHORITY_CONTRACT_AUTHORITATIVE = "CONTRACT_AUTHORITATIVE"
AUTHORITY_INFERRED = "INFERRED"
EXTERNAL_METADATA_AUTHORITIES: tuple[str, ...] = (
    AUTHORITY_CONTRACT_AUTHORITATIVE,
    AUTHORITY_INFERRED,
)

#: Provenance classes eligible for AUTHORITATIVE VFP metadata strength.  The
#: shipped JSON Schema encodes the SAME eligibility for every claim that
#: claims authoritative strength (CONTRACT_AUTHORITATIVE + VERIFIED, index
#: claims additionally VERIFIED verification state): ``POLICY_FILE`` is a
#: policy-side declaration class and can NEVER cross the authoritative
#: boundary (REQ-P6-006 revised).
AUTHORITATIVE_PROVENANCES: tuple[str, ...] = (
    "MCP_VFP9SP2_TOOLCHAIN",
    "EXTERNAL_VFP_METADATA",
)

INDEX_KIND_STRUCTURAL_CDX = "STRUCTURAL_CDX"
INDEX_KIND_STANDALONE_IDX = "STANDALONE_IDX"
INDEX_CLAIM_KINDS: tuple[str, ...] = (INDEX_KIND_STRUCTURAL_CDX, INDEX_KIND_STANDALONE_IDX)

INDEX_STATE_VERIFIED = "VERIFIED"
INDEX_STATE_UNVERIFIED = "UNVERIFIED"
INDEX_VERIFICATION_STATES: tuple[str, ...] = (INDEX_STATE_VERIFIED, INDEX_STATE_UNVERIFIED)

TAG_SORT_ORDERS: tuple[str, ...] = ("ASCENDING", "DESCENDING")

CLAIM_ASSURANCE_VERIFIED = "VERIFIED"
CLAIM_ASSURANCE_UNVERIFIED = "UNVERIFIED"
CLAIM_ASSURANCES: tuple[str, ...] = (
    CLAIM_ASSURANCE_VERIFIED,
    CLAIM_ASSURANCE_UNVERIFIED,
)

_MAX_INDEX_CLAIMS = 256
_MAX_INDEX_TAGS = 256
_MAX_EXTERNAL_PATH_LENGTH = 256
_PRIVATE_PATH = re.compile(r"(?:^[A-Za-z]:[\\/]|^[/\\]{1,2}|(?:^|[/\\])\.\.(?:[/\\]|$))")
_BACKSLASH_PATH = re.compile(r"\\")
#: The EXACT segment character class of the shipped JSON Schema
#: ``$defs.relativePath``/``relativeTablePath`` (single parity source).
_EXTERNAL_PATH_SEGMENT = re.compile(r"[A-Za-z0-9_. -]+\Z")


def validate_external_metadata_path(
    value: object, detail: str, *, require_table_suffix: bool = False
) -> str:
    """Validate one EXTERNAL metadata path against the shipped JSON Schema.

    The external contract requires canonical forward-slash relative paths and
    REJECTS backslash forms (fail closed, no silent normalization).  The
    acceptance rules are the EXACT runtime mirror of the shipped schema's
    ``$defs.relativePath``/``relativeTablePath`` patterns: verbatim identity
    (no whitespace stripping), bounded length 1..256, forward-slash separated
    segments of ``[A-Za-z0-9_. -]`` with no empty segment, no absolute/drive/
    UNC form and no ``.``/``..`` segments.  Table identities additionally
    require the ``.dbf`` suffix (case-insensitive) when
    ``require_table_suffix`` is set.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_EXTERNAL_PATH_LENGTH:
        raise _external_invalid("RELATIONSHIP_TABLE_PATH_INVALID")
    if value.startswith("/"):
        raise _external_invalid("RELATIONSHIP_TABLE_PATH_ABSOLUTE")
    if re.match(r"[A-Za-z]:", value):
        raise _external_invalid("RELATIONSHIP_TABLE_PATH_ABSOLUTE")
    if value.startswith("\\\\") or value.startswith("//"):
        raise _external_invalid("RELATIONSHIP_TABLE_PATH_ABSOLUTE")
    if _BACKSLASH_PATH.search(value):
        raise _external_invalid("RELATIONSHIP_TABLE_PATH_INVALID")
    for part in value.split("/"):
        if part in {".", ".."}:
            raise _external_invalid("RELATIONSHIP_TABLE_PATH_TRAVERSAL")
        if ":" in part:
            raise _external_invalid("RELATIONSHIP_TABLE_PATH_ABSOLUTE")
        if _EXTERNAL_PATH_SEGMENT.fullmatch(part) is None:
            # Covers empty segments ("//" or a trailing "/") and every
            # character outside the schema's segment class - both sides of
            # the contract reject them, with no silent normalization.
            raise _external_invalid("RELATIONSHIP_TABLE_PATH_INVALID")
    if require_table_suffix and not value.lower().endswith(".dbf"):
        raise _external_invalid("RELATIONSHIP_TABLE_PATH_INVALID")
    return value


def _external_invalid(detail_code: str) -> PolicyError:
    """Stable typed, value-free refusal for external metadata (REQ-P6-006)."""
    return PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


@dataclass(frozen=True, slots=True)
class ExternalProducerProvenance:
    """Structured, bounded, producer-independent provenance envelope.

    ``producer_id``/``producer_version`` are free bounded tokens: the
    contract is producer-independent and NO producer is hardcoded.  The
    structured provenance is preserved verbatim on the parsed document and
    participates deterministically in the relationship fingerprint.
    """

    producer_id: str
    producer_version: str

    def to_dict(self) -> dict[str, str]:
        return {
            "producer_id": self.producer_id,
            "producer_version": self.producer_version,
        }


@dataclass(frozen=True, slots=True)
class ExternalIndexTag:
    """One value-free index tag claim (name, order, optional expression)."""

    name: str
    sort_order: str
    expression: str | None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "sort_order": self.sort_order}
        if self.expression is not None:
            payload["expression"] = self.expression
        return payload


@dataclass(frozen=True, slots=True)
class ExternalIndexClaim:
    """One value-free external index claim (REQ-P6-006).

    ``verification_state`` is the explicit truthfulness carrier: only
    ``VERIFIED`` claims may ever support an index-validity guarantee;
    ``UNVERIFIED`` claims are retained purely for planning/reporting.

    ``authority`` is the per-claim authority classification (REQ-P6-006 revised):
    only CONTRACT_AUTHORITATIVE claims may support index-validity guarantees.
    """

    claim_id: str
    table_path: str
    index_file_path: str
    index_kind: str
    tags: tuple[ExternalIndexTag, ...]
    verification_state: str
    assurance: str
    provenance: str
    authority: str

    @property
    def verified(self) -> bool:
        """Whether this claim may support, but never manufacture, index assurance."""
        return (
            self.authority == AUTHORITY_CONTRACT_AUTHORITATIVE
            and self.verification_state == INDEX_STATE_VERIFIED
            and self.assurance == CLAIM_ASSURANCE_VERIFIED
            and external_provenance_class_allowed(self.provenance)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "table": self.table_path,
            "index_file": self.index_file_path,
            "index_kind": self.index_kind,
            "tags": [
                tag.to_dict()
                for tag in sorted(
                    self.tags,
                    key=lambda item: (item.name.upper(), item.sort_order, item.expression or ""),
                )
            ],
            "verification_state": self.verification_state,
            "assurance": self.assurance,
            "provenance": self.provenance,
            "authority": self.authority,
        }


def load_external_metadata_schema() -> dict[str, Any]:
    """Load the shipped JSON Schema through the documented package resource.

    The stable discovery mechanism is ``importlib.resources`` over the
    package path :data:`EXTERNAL_METADATA_SCHEMA_RESOURCE`; the schema ships
    inside the built wheel.  The loader validates the schema's own identity:
    it must declare the matching contract version, or the boundary fails
    closed (a mismatching shipped schema is a packaging defect, never a
    silent acceptance).
    """
    text = (
        resources.files("dbf_anonymizer")
        .joinpath(EXTERNAL_METADATA_SCHEMA_RESOURCE)
        .read_text(encoding="utf-8")
    )
    schema = json.loads(text)
    if not isinstance(schema, Mapping):
        raise _external_invalid("EXTERNAL_METADATA_SCHEMA_INVALID")
    declared = schema.get("x-contract-schema-version")
    if declared != EXTERNAL_METADATA_SCHEMA_VERSION:
        raise _external_invalid("EXTERNAL_METADATA_SCHEMA_IDENTITY_MISMATCH")
    return dict(schema)


def parse_producer(payload: object) -> ExternalProducerProvenance:
    """Parse and validate the structured producer provenance envelope."""
    if not isinstance(payload, Mapping):
        raise _external_invalid("EXTERNAL_METADATA_PRODUCER_INVALID")
    unknown = set(payload) - {"producer_id", "producer_version"}
    if unknown:
        raise _external_invalid("EXTERNAL_METADATA_PRODUCER_KEY_UNKNOWN")
    producer_id = payload.get("producer_id")
    producer_version = payload.get("producer_version")
    _validate_bounded_token(producer_id, "EXTERNAL_METADATA_PRODUCER_ID_INVALID")
    _validate_bounded_token(producer_version, "EXTERNAL_METADATA_PRODUCER_VERSION_INVALID")
    assert isinstance(producer_id, str) and isinstance(producer_version, str)
    return ExternalProducerProvenance(producer_id, producer_version)


def parse_index_tags(payload: object, detail: str) -> tuple[ExternalIndexTag, ...]:
    """Parse bounded, value-free index tag claims."""
    if not isinstance(payload, list) or not payload or len(payload) > _MAX_INDEX_TAGS:
        raise _external_invalid(detail)
    tags: list[ExternalIndexTag] = []
    for item in payload:
        if not isinstance(item, Mapping):
            raise _external_invalid("EXTERNAL_METADATA_INDEX_TAG_INVALID")
        unknown = set(item) - {"name", "sort_order", "expression"}
        if unknown or not {"name", "sort_order"} <= set(item):
            raise _external_invalid("EXTERNAL_METADATA_INDEX_TAG_KEY_INVALID")
        name = item["name"]
        _validate_bounded_token(name, "EXTERNAL_METADATA_INDEX_TAG_NAME_INVALID")
        sort_order = item["sort_order"]
        if sort_order not in TAG_SORT_ORDERS:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_TAG_ORDER_INVALID")
        expression = item.get("expression")
        if expression is not None:
            if (
                not isinstance(expression, str)
                or not (1 <= len(expression) <= 256)
                # The EXACT runtime mirror of the shipped schema's
                # ``[ -~]+`` expression pattern: printable ASCII only.
                or any(not 32 <= ord(character) <= 126 for character in expression)
                or _PRIVATE_PATH.search(expression)
            ):
                raise _external_invalid("EXTERNAL_METADATA_INDEX_EXPRESSION_INVALID")
        tags.append(ExternalIndexTag(str(name), str(sort_order), expression))
    if len({tag.name.upper() for tag in tags}) != len(tags):
        raise _external_invalid("EXTERNAL_METADATA_INDEX_TAG_DUPLICATE")
    return tuple(tags)


def parse_index_claims(payload: object) -> tuple[ExternalIndexClaim, ...]:
    """Parse the ``index_claims`` list of one external metadata envelope."""
    if not isinstance(payload, list) or len(payload) > _MAX_INDEX_CLAIMS:
        raise _external_invalid("EXTERNAL_METADATA_INDEX_CLAIMS_INVALID")
    claims: list[ExternalIndexClaim] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, Mapping):
            raise _external_invalid("EXTERNAL_METADATA_INDEX_CLAIM_INVALID")
        required = {
            "claim_id",
            "table",
            "index_file",
            "index_kind",
            "tags",
            "verification_state",
            "assurance",
            "provenance",
            "authority",
        }
        unknown = set(item) - required
        if unknown or not required <= set(item):
            raise _external_invalid("EXTERNAL_METADATA_INDEX_CLAIM_KEY_INVALID")
        claim_id = item["claim_id"]
        _validate_bounded_token(claim_id, "EXTERNAL_METADATA_INDEX_CLAIM_ID_INVALID")
        if claim_id in seen:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_CLAIM_DUPLICATE")
        seen.add(claim_id)

        try:
            table_path = validate_external_metadata_path(
                item["table"],
                "EXTERNAL_METADATA_INDEX_PATH_INVALID",
                require_table_suffix=True,
            )
            index_file_path = validate_external_metadata_path(
                item["index_file"], "EXTERNAL_METADATA_INDEX_PATH_INVALID"
            )
        except PolicyError:
            raise
        except Exception:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_PATH_INVALID")
        index_kind = item["index_kind"]
        if index_kind not in INDEX_CLAIM_KINDS:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_KIND_INVALID")
        tags = parse_index_tags(item["tags"], "EXTERNAL_METADATA_INDEX_TAGS_INVALID")
        verification_state = item["verification_state"]
        if verification_state not in INDEX_VERIFICATION_STATES:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_VERIFICATION_INVALID")
        assurance = item["assurance"]
        if assurance not in CLAIM_ASSURANCES:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_ASSURANCE_INVALID")
        if assurance != verification_state:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_ASSURANCE_INCONSISTENT")
        authority = item["authority"]
        if authority not in EXTERNAL_METADATA_AUTHORITIES:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_AUTHORITY_INVALID")
        index_suffix = PurePosixPath(index_file_path).suffix.lower()
        if (index_kind == INDEX_KIND_STRUCTURAL_CDX and index_suffix != ".cdx") or (
            index_kind == INDEX_KIND_STANDALONE_IDX and index_suffix != ".idx"
        ):
            raise _external_invalid("EXTERNAL_METADATA_INDEX_PATH_KIND_MISMATCH")
        provenance = item["provenance"]
        if provenance not in RELATIONSHIP_PROVENANCES:
            raise _external_invalid("EXTERNAL_METADATA_INDEX_PROVENANCE_INVALID")
        if (
            authority == AUTHORITY_CONTRACT_AUTHORITATIVE
            and assurance == CLAIM_ASSURANCE_VERIFIED
            and verification_state == INDEX_STATE_VERIFIED
            and not external_provenance_class_allowed(str(provenance))
        ):
            # REQ-P6-006 (revised): a claim that claims authoritative index
            # strength must carry an authoritative VFP-metadata-class
            # provenance; POLICY_FILE provenance is retained only as
            # non-authoritative planning/reporting information and can never
            # cross the authoritative boundary (the shipped JSON Schema
            # encodes the same eligibility).
            raise _external_invalid("EXTERNAL_METADATA_INDEX_PROVENANCE_INAUTHORITATIVE")
        claims.append(
            ExternalIndexClaim(
                claim_id=str(claim_id),
                table_path=table_path,
                index_file_path=index_file_path,
                index_kind=str(index_kind),
                tags=tags,
                verification_state=str(verification_state),
                assurance=str(assurance),
                provenance=str(provenance),
                authority=str(authority),
            )
        )
    return tuple(claims)


def parse_external_authority(payload: object) -> str:
    """Parse the envelope-level authority classification."""
    if payload not in EXTERNAL_METADATA_AUTHORITIES:
        raise _external_invalid("EXTERNAL_METADATA_AUTHORITY_INVALID")
    return str(payload)


def parse_claim_assurance(payload: object) -> str:
    """Parse one relationship claim's explicit assurance classification."""
    if payload not in CLAIM_ASSURANCES:
        raise _external_invalid("EXTERNAL_METADATA_RELATION_ASSURANCE_INVALID")
    return str(payload)


def validate_authority_assurance(authority: str, assurance: str) -> None:
    """Reject a verified claim whose producer classifies it as inferred."""
    if authority == AUTHORITY_INFERRED and assurance == CLAIM_ASSURANCE_VERIFIED:
        raise _external_invalid("EXTERNAL_METADATA_AUTHORITY_ASSURANCE_INCONSISTENT")


def external_provenance_class_allowed(provenance: str) -> bool:
    """Whether one provenance token is an authoritative VFP-metadata class.

    ``POLICY_FILE`` provenance is a policy-side declaration and can NEVER be
    authoritative VFP metadata; both the toolchain-class provenance and the
    producer-independent external-contract provenance are VFP-metadata
    classes.  The bounded vocabulary remains fail-closed.
    """
    return provenance in AUTHORITATIVE_PROVENANCES
