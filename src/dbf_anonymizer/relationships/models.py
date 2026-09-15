"""Typed relationship metadata independent from DBF parsing (REQ-P3-001).

The ONE authoritative internal model of declared primary/foreign-key
relationship metadata.  It never depends on ``dbfbridge`` record or parser
objects: a relationship is described by NORMALIZED RELATIVE table paths,
field names, bounded key roles, composite-key ordinals, logical comparison
semantics and provenance — never by actual key values.

Vocabularies (all bounded, fail-closed against anything else):

* key roles: ``PRIMARY`` / ``CANDIDATE`` / ``FOREIGN``;
* comparison semantics: ``EXACT_VALUE`` (the only semantics this release can
  truthfully honor — exact decoded C/V value equality) and ``UNSPECIFIED``
  (a bounded representation of richer/unknown semantics; it can never back a
  join-preservation claim);
* provenance: ``POLICY_FILE`` / ``MCP_VFP9SP2_TOOLCHAIN`` (the document
  boundary only — no MCP transport exists or is implemented here);
* logical types of this cluster: ``C`` / ``V`` only.

Provenance serialization stays bounded: relation IDs, bounded tokens and an
optional normalized relative/digest identifier — never absolute local paths,
key values, source values or vault material.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from dbf_anonymizer.errors import ErrorCode, ErrorContext, PolicyError

__all__ = [
    "RELATIONSHIP_METADATA_SCHEMA_VERSION",
    "KEY_ROLES",
    "COMPARISON_SEMANTICS",
    "RELATIONSHIP_PROVENANCES",
    "SUPPORTED_RELATIONSHIP_DBF_TYPES",
    "KEY_ROLE_PRIMARY",
    "KEY_ROLE_CANDIDATE",
    "KEY_ROLE_FOREIGN",
    "COMPARISON_EXACT_VALUE",
    "COMPARISON_UNSPECIFIED",
    "PROVENANCE_POLICY_FILE",
    "PROVENANCE_MCP_VFP9SP2_TOOLCHAIN",
    "RelationMember",
    "RelationGroup",
    "RelationshipDocument",
]

#: The single supported relationship-metadata schema version.  Any other
#: version FAILS CLOSED (no silent normalization of other shapes).
RELATIONSHIP_METADATA_SCHEMA_VERSION = "1.0"

KEY_ROLE_PRIMARY = "PRIMARY"
KEY_ROLE_CANDIDATE = "CANDIDATE"
KEY_ROLE_FOREIGN = "FOREIGN"
KEY_ROLES: tuple[str, ...] = (KEY_ROLE_PRIMARY, KEY_ROLE_CANDIDATE, KEY_ROLE_FOREIGN)

COMPARISON_EXACT_VALUE = "EXACT_VALUE"
COMPARISON_UNSPECIFIED = "UNSPECIFIED"
COMPARISON_SEMANTICS: tuple[str, ...] = (COMPARISON_EXACT_VALUE, COMPARISON_UNSPECIFIED)

PROVENANCE_POLICY_FILE = "POLICY_FILE"
PROVENANCE_MCP_VFP9SP2_TOOLCHAIN = "MCP_VFP9SP2_TOOLCHAIN"
RELATIONSHIP_PROVENANCES: tuple[str, ...] = (
    PROVENANCE_POLICY_FILE,
    PROVENANCE_MCP_VFP9SP2_TOOLCHAIN,
)

SUPPORTED_RELATIONSHIP_DBF_TYPES: tuple[str, ...] = ("C", "V")

_BOUNDED_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _invalid(detail_code: str) -> PolicyError:
    """Stable typed refusal for invalid relationship metadata (no values)."""
    return PolicyError(
        ErrorCode.POLICY_INVALID,
        context=ErrorContext(operation="build_plan", detail_code=detail_code),
    )


def _validate_bounded_token(value: object, detail: str) -> str:
    if not isinstance(value, str) or not _BOUNDED_TOKEN.match(value):
        raise _invalid(detail)
    return value


def normalize_relative_table_path(value: object) -> str:
    """Normalize one member table path to a relative forward-slash path.

    Absolute paths (leading separator or drive prefix), ``..`` traversal,
    ``.`` segments and backslash-forms are refused (fail closed); the
    normalized form is the vault-stable relative identity used by every P2
    table registration.
    """
    if not isinstance(value, str) or not value.strip():
        raise _invalid("RELATIONSHIP_TABLE_PATH_INVALID")
    segments = re.split(r"[\\/]+", value.strip())
    if segments and segments[0] == "":
        # A leading separator is an absolute path — never silently
        # normalized into a relative identity.
        raise _invalid("RELATIONSHIP_TABLE_PATH_ABSOLUTE")
    parts = [part for part in segments if part != ""]
    if not parts:
        raise _invalid("RELATIONSHIP_TABLE_PATH_INVALID")
    for part in parts:
        if part in {".", ".."}:
            raise _invalid("RELATIONSHIP_TABLE_PATH_TRAVERSAL")
        if ":" in part:
            raise _invalid("RELATIONSHIP_TABLE_PATH_ABSOLUTE")
    return "/".join(parts)


def _validate_member_encoding(value: object) -> str:
    if not isinstance(value, str) or not _BOUNDED_TOKEN.match(value):
        raise _invalid("RELATIONSHIP_ENCODING_INVALID")
    return value.lower()


@dataclass(frozen=True)
class RelationMember:
    """One ordered member of a declared relation group (no key values)."""

    table_path: str
    field_name: str
    key_role: str
    composite_ordinal: int
    dbf_type: str
    byte_width: int
    encoding: str
    nullable: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "table_path", normalize_relative_table_path(self.table_path)
        )
        _validate_bounded_token(self.field_name, "RELATIONSHIP_FIELD_INVALID")
        if self.key_role not in KEY_ROLES:
            raise _invalid("RELATIONSHIP_KEY_ROLE_INVALID")
        if isinstance(self.composite_ordinal, bool) or not isinstance(
            self.composite_ordinal, int
        ) or self.composite_ordinal < 1:
            raise _invalid("RELATIONSHIP_ORDINAL_INVALID")
        if self.dbf_type not in SUPPORTED_RELATIONSHIP_DBF_TYPES:
            raise _invalid("RELATIONSHIP_DBF_TYPE_UNSUPPORTED")
        if isinstance(self.byte_width, bool) or not isinstance(self.byte_width, int) or self.byte_width < 1:
            raise _invalid("RELATIONSHIP_BYTE_WIDTH_INVALID")
        object.__setattr__(self, "encoding", _validate_member_encoding(self.encoding))
        if not isinstance(self.nullable, bool):
            raise _invalid("RELATIONSHIP_NULL_POLICY_INVALID")

    @property
    def identity(self) -> tuple[str, str, str]:
        """The unique member identity within one document (table, field, role)."""
        return (self.table_path, self.field_name, self.key_role)


@dataclass(frozen=True)
class RelationGroup:
    """One declared relation group: ordered members plus semantics."""

    relation_id: str
    members: tuple[RelationMember, ...]
    comparison: str
    provenance: str
    source_digest: str | None = None

    def __post_init__(self) -> None:
        _validate_bounded_token(self.relation_id, "RELATIONSHIP_ID_INVALID")
        if not self.members:
            raise _invalid("RELATIONSHIP_MEMBERS_EMPTY")
        if self.comparison not in COMPARISON_SEMANTICS:
            raise _invalid("RELATIONSHIP_COMPARISON_INVALID")
        if self.provenance not in RELATIONSHIP_PROVENANCES:
            raise _invalid("RELATIONSHIP_PROVENANCE_INVALID")
        if self.source_digest is not None:
            _validate_bounded_token(self.source_digest, "RELATIONSHIP_SOURCE_DIGEST_INVALID")
        seen: set[tuple[str, str, str]] = set()
        for member in self.members:
            if member.identity in seen:
                raise _invalid("RELATIONSHIP_MEMBER_DUPLICATE")
            seen.add(member.identity)
        # Composite ordering: per key role, ordinals must be exactly 1..N
        # without duplicates or gaps (consistent arity per side).
        roles = {member.key_role for member in self.members}
        for role in sorted(roles):
            ordinals = sorted(
                m.composite_ordinal for m in self.members if m.key_role == role
            )
            if ordinals != list(range(1, len(ordinals) + 1)):
                raise _invalid("RELATIONSHIP_ORDINAL_SEQUENCE_INVALID")
        # A PRIMARY side and a FOREIGN side must carry equal arity so the
        # composite tuple semantics are defined.
        primary_count = sum(1 for m in self.members if m.key_role == KEY_ROLE_PRIMARY)
        foreign_count = sum(1 for m in self.members if m.key_role == KEY_ROLE_FOREIGN)
        if {KEY_ROLE_PRIMARY, KEY_ROLE_FOREIGN} <= roles and primary_count != foreign_count:
            raise _invalid("RELATIONSHIP_ARITY_MISMATCH")

    def members_for_role(self, role: str) -> tuple[RelationMember, ...]:
        """The ordered members of one key role (composite ordinal order)."""
        return tuple(
            sorted(
                (m for m in self.members if m.key_role == role),
                key=lambda m: (m.composite_ordinal, m.table_path, m.field_name),
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Bounded provenance serialization (never any key/source values)."""
        return {
            "relation_id": self.relation_id,
            "comparison": self.comparison,
            "provenance": self.provenance,
            "source_digest": self.source_digest,
            "members": [
                {
                    "table": member.table_path,
                    "field": member.field_name,
                    "role": member.key_role,
                    "ordinal": member.composite_ordinal,
                    "dbf_type": member.dbf_type,
                    "byte_width": member.byte_width,
                    "encoding": member.encoding,
                    "nullable": member.nullable,
                }
                for member in sorted(
                    self.members,
                    key=lambda m: (m.key_role, m.composite_ordinal, m.table_path, m.field_name),
                )
            ],
        }


@dataclass(frozen=True)
class RelationshipDocument:
    """The ONE deterministic versioned relationship metadata document."""

    groups: tuple[RelationGroup, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.groups, tuple):
            raise _invalid("RELATIONSHIP_DOCUMENT_INVALID")
        identifiers = [group.relation_id for group in self.groups]
        if len(set(identifiers)) != len(identifiers):
            raise _invalid("RELATIONSHIP_ID_DUPLICATE")

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata_schema_version": RELATIONSHIP_METADATA_SCHEMA_VERSION,
            "relations": [group.to_dict() for group in self.groups],
        }