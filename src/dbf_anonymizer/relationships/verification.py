"""Deterministic relationship-verification evidence (REQ-P3-006).

The ONE typed, deterministic, VALUE-FREE relationship-verification model.  For
every declared relation it compares BEFORE (source-side) and AFTER
(transformed-side) evidence as counts only — PK uniqueness, FK orphan count,
matched-row count, NULL counts and composite-key tuple multiplicity — and
never serializes an actual key value, sample tuple, pseudonym, reverse
mapping, absolute path or secret.

Scope (truthful, matching the immutable architecture "verification compares
structure, not sensitive values"):

* the evidence is the prescribed COUNT family; a value-level change that
  preserves every count is NOT distinguished — the assurance model never
  overclaims value-level integrity;
* composite tuples are ORDERED: ``(A, B)`` and ``(B, A)`` are distinct keys
  unless the tuple values themselves are equal, so an ordinal change of a
  real foreign key becomes a match/orphan-count change and FAILS;
* NULL tuples participate exactly like the established
  :func:`~dbf_anonymizer.relationships.relation_metrics` semantics: a
  NULL-containing tuple (the empty tuple is the canonical NULL marker) is
  excluded from uniqueness, join matching and multiplicity profiles and is
  COUNTED per side; BEFORE and AFTER use the SAME rule;
* DELETED records are in scope: the caller streams every physical record the
  production pipeline will transform (active AND deleted) into the
  accumulator; the evidence counts rows and never deletion state, so a
  deleted key row cannot silently disappear from the model.

The model is designed for the future P4 production engine: the
:class:`RelationshipEvidenceAccumulator` consumes one key tuple per
observation (bounded by DISTINCT key tuples, never by dataset size), so P4
can stream before/after evidence during its passes without materializing a
dataset.  No production engine, public ``pseudonymize``/``verify_dataset``
operation, private DBF/FPT IO, second database or persistence is introduced
here.

Every public payload serializes deterministically (canonical relation order,
canonical invariant order, sorted count profiles) and carries the stable
``evidence_schema_version``; counts are the only evidence material.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Hashable, Mapping

from dbf_anonymizer.errors import ErrorCode, ErrorContext, VerificationError
from dbf_anonymizer.models import (
    MODEL_SCHEMA_VERSION,
    JsonDict,
    PublicModel,
    _payload,
    _validated_code,
)
from dbf_anonymizer.relationships.document import relationship_fingerprint
from dbf_anonymizer.relationships.models import (
    KEY_ROLE_CANDIDATE,
    KEY_ROLE_PRIMARY,
    RelationGroup,
    RelationshipDocument,
    _validate_bounded_token,
)

__all__ = [
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
]

#: The stable version of the relationship-verification evidence payload.
#: Unknown future versions must fail closed when parsing persisted evidence
#: (no persistence exists in this phase; the version is carried by every
#: payload so later consumers can bind their expectations).
EVIDENCE_SCHEMA_VERSION = "1.0"

#: The canonical ordered invariant vocabulary of :func:`compare_relation_metrics`.
INVARIANT_PARENT_UNIQUENESS = "PARENT_UNIQUENESS_PRESERVED"
INVARIANT_ORPHAN_COUNT = "ORPHAN_COUNT_PRESERVED"
INVARIANT_MATCHED_ROWS = "MATCHED_ROWS_PRESERVED"
INVARIANT_NULL_COUNTS = "NULL_COUNTS_PRESERVED"
INVARIANT_FOREIGN_MULTIPLICITY = "FOREIGN_MULTIPLICITY_PRESERVED"

RELATIONSHIP_INVARIANTS: tuple[str, ...] = (
    INVARIANT_PARENT_UNIQUENESS,
    INVARIANT_ORPHAN_COUNT,
    INVARIANT_MATCHED_ROWS,
    INVARIANT_NULL_COUNTS,
    INVARIANT_FOREIGN_MULTIPLICITY,
)


class VerificationStatus(str, Enum):
    """The per-relation verification verdict of one declared relation.

    ``INCOMPLETE`` is the FAIL-CLOSED state for missing evidence: a declared
    relation whose before- or after-side was never evaluated is never
    silently treated as a zero-count relation that would compare equal.
    """

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"


def _verification_failure(
    detail_code: str, relationship_id: str | None = None
) -> VerificationError:
    """Stable typed, value-free verification refusal."""
    return VerificationError(
        ErrorCode.VERIFICATION_FAILED,
        context=ErrorContext(
            operation="verify_relationships",
            relationship_id=relationship_id,
            detail_code=detail_code,
        ),
    )


def _checked_count(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an exact integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return value


@dataclass(frozen=True, slots=True)
class RelationSideMetrics(PublicModel):
    """The count-only evidence of ONE side (parent or foreign) of a relation.

    A NULL-containing tuple is excluded from uniqueness and multiplicity and
    is counted by ``null_tuple_count``; the multiplicity profile is the
    deterministic sorted (descending) multiset of the multiplicities of the
    DISTINCT non-NULL tuples — the actual key values are consumed and never
    serialized.  ``rows_considered`` covers every observed physical row of
    the side (active AND deleted records).
    """

    rows_considered: int
    null_tuple_count: int
    unique_tuple_count: int
    duplicate_row_count: int
    multiplicity_profile: tuple[int, ...]

    def __post_init__(self) -> None:
        _checked_count(self.rows_considered, "rows_considered")
        _checked_count(self.null_tuple_count, "null_tuple_count")
        _checked_count(self.unique_tuple_count, "unique_tuple_count")
        _checked_count(self.duplicate_row_count, "duplicate_row_count")
        profile: list[int] = []
        for multiplicity in self.multiplicity_profile:
            if isinstance(multiplicity, bool) or not isinstance(multiplicity, int):
                raise TypeError("multiplicity profile entries must be exact integers")
            if multiplicity < 1:
                raise ValueError("multiplicity profile entries must be positive")
            profile.append(multiplicity)
        if tuple(sorted(profile, reverse=True)) != tuple(profile):
            raise ValueError("the multiplicity profile must be sorted descending")
        if self.unique_tuple_count != len(profile):
            raise ValueError("unique_tuple_count must equal the profile length")
        if self.duplicate_row_count != sum(profile) - len(profile):
            raise ValueError(
                "duplicate_row_count must equal rows beyond the distinct tuples"
            )
        if self.rows_considered != self.null_tuple_count + sum(profile):
            raise ValueError("rows_considered must equal NULL tuples plus non-NULL rows")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationSideMetrics",
            rows_considered=self.rows_considered,
            null_tuple_count=self.null_tuple_count,
            unique_tuple_count=self.unique_tuple_count,
            duplicate_row_count=self.duplicate_row_count,
            multiplicity_profile=self.multiplicity_profile,
        )


@dataclass(frozen=True, slots=True)
class RelationEvidenceCounts(PublicModel):
    """The complete count-only evidence of ONE side-pair evaluation.

    One accumulator build: the parent and foreign side metrics plus the
    join-level counts.  ``composite_arity`` binds the evidence to the
    declared relation arity (a mismatch is a typed fail-closed refusal,
    never a silent reinterpretation).
    """

    composite_arity: int
    parent: RelationSideMetrics
    foreign: RelationSideMetrics
    matched_row_count: int
    orphan_count: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.composite_arity, bool)
            or not isinstance(self.composite_arity, int)
            or self.composite_arity < 1
        ):
            raise ValueError("composite_arity must be a positive integer")
        if not isinstance(self.parent, RelationSideMetrics) or not isinstance(
            self.foreign, RelationSideMetrics
        ):
            raise TypeError("relation evidence sides must be RelationSideMetrics")
        _checked_count(self.matched_row_count, "matched_row_count")
        _checked_count(self.orphan_count, "orphan_count")
        foreign_non_null = self.foreign.rows_considered - self.foreign.null_tuple_count
        if self.matched_row_count + self.orphan_count != foreign_non_null:
            raise ValueError("matched + orphan must cover every non-NULL foreign row")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationEvidenceCounts",
            composite_arity=self.composite_arity,
            parent=self.parent,
            foreign=self.foreign,
            matched_row_count=self.matched_row_count,
            orphan_count=self.orphan_count,
        )


@dataclass(frozen=True, slots=True)
class RelationInvariantResult(PublicModel):
    """One named before/after invariant of :data:`RELATIONSHIP_INVARIANTS`."""

    invariant: str
    preserved: bool

    def __post_init__(self) -> None:
        _validated_code(self.invariant, field_name="invariant")
        if self.invariant not in RELATIONSHIP_INVARIANTS:
            raise ValueError("the invariant token is not part of the evidence vocabulary")
        if not isinstance(self.preserved, bool):
            raise TypeError("preserved must be a genuine boolean")

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationInvariantResult",
            invariant=self.invariant,
            preserved=self.preserved,
        )


@dataclass(frozen=True, slots=True)
class RelationVerificationEvidence(PublicModel):
    """The deterministic value-free verification evidence of ONE relation.

    ``status`` is ``VERIFIED`` only when BOTH sides supplied complete
    evidence and EVERY canonical invariant is preserved; ``FAILED`` when
    complete evidence shows a broken invariant; ``INCOMPLETE`` when a side is
    missing (fail closed — never a zero-count accidental PASS).
    """

    relation_id: str
    composite_arity: int
    status: VerificationStatus
    before: RelationEvidenceCounts | None
    after: RelationEvidenceCounts | None
    invariants: tuple[RelationInvariantResult, ...]

    def __post_init__(self) -> None:
        _validated_code(self.relation_id, field_name="relation_id")
        if (
            isinstance(self.composite_arity, bool)
            or not isinstance(self.composite_arity, int)
            or self.composite_arity < 1
        ):
            raise ValueError("composite_arity must be a positive integer")
        for side_name, side in (("before", self.before), ("after", self.after)):
            if side is not None and side.composite_arity != self.composite_arity:
                raise ValueError(
                    f"the {side_name} evidence arity must match the declared relation arity"
                )
        if not isinstance(self.status, VerificationStatus):
            raise TypeError("status must be a VerificationStatus")
        if not isinstance(self.invariants, tuple) or not all(
            isinstance(result, RelationInvariantResult) for result in self.invariants
        ):
            raise TypeError("invariants must be a tuple of RelationInvariantResult")
        if self.status is VerificationStatus.INCOMPLETE:
            if self.before is None and self.after is None:
                raise ValueError(
                    "an INCOMPLETE relation is missing at least one complete side"
                )
            if self.invariants:
                raise ValueError("an INCOMPLETE relation carries no invariant results")
        else:
            if self.before is None or self.after is None:
                raise ValueError(
                    "a VERIFIED/FAILED relation requires complete before and after evidence"
                )
            if tuple(result.invariant for result in self.invariants) != tuple(
                RELATIONSHIP_INVARIANTS
            ):
                raise ValueError(
                    "a VERIFIED/FAILED relation carries the full canonical invariant set"
                )
            preserved = all(result.preserved for result in self.invariants)
            expected = (
                VerificationStatus.VERIFIED if preserved else VerificationStatus.FAILED
            )
            if self.status is not expected:
                raise ValueError(
                    "the relation status must agree with the invariant results"
                )

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationVerificationEvidence",
            relation_id=self.relation_id,
            composite_arity=self.composite_arity,
            status=self.status,
            before=self.before,
            after=self.after,
            invariants=self.invariants,
        )


@dataclass(frozen=True, slots=True)
class RelationshipVerificationReport(PublicModel):
    """The deterministic, value-free relationship-verification report.

    Relations are stored in CANONICAL order (ascending stable ``relation_id``)
    and the payload serializes identically regardless of input ordering,
    dictionary iteration or process ``PYTHONHASHSEED``.  The report binds the
    verified relations to the canonical relationship-document fingerprint —
    it never carries actual key values, sample tuples, reverse mappings,
    vault paths or absolute paths.  ``evidence_fingerprint`` is the stable
    SHA-256 of the canonical report content (computed at construction).
    """

    evidence_schema_version: str
    relationship_fingerprint: str
    relations: tuple[RelationVerificationEvidence, ...]
    complete: bool
    evidence_fingerprint: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if self.evidence_schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError(
                "unsupported relationship-evidence schema version (fail closed)"
            )
        _validated_code(
            self.relationship_fingerprint, field_name="relationship_fingerprint"
        )
        if not isinstance(self.relations, tuple) or not all(
            isinstance(entry, RelationVerificationEvidence) for entry in self.relations
        ):
            raise TypeError("relations must be a tuple of RelationVerificationEvidence")
        identifiers = [entry.relation_id for entry in self.relations]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("relation evidence ids must be unique")
        if identifiers != sorted(identifiers):
            raise ValueError("relation evidence must be in canonical (relation_id) order")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be a genuine boolean")
        if self.complete is not all(
            entry.status is not VerificationStatus.INCOMPLETE
            for entry in self.relations
        ):
            raise ValueError(
                "complete must reflect the absence of INCOMPLETE relations"
            )
        canonical = json.dumps(
            {
                "complete": self.complete,
                "evidence_schema_version": self.evidence_schema_version,
                "model_type": "RelationshipVerificationReport",
                "relationship_fingerprint": self.relationship_fingerprint,
                "relations": [entry.to_dict() for entry in self.relations],
                "schema_version": MODEL_SCHEMA_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        object.__setattr__(
            self,
            "evidence_fingerprint",
            hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        )

    def to_dict(self) -> JsonDict:
        return _payload(
            "RelationshipVerificationReport",
            evidence_schema_version=self.evidence_schema_version,
            relationship_fingerprint=self.relationship_fingerprint,
            relations=self.relations,
            complete=self.complete,
            evidence_fingerprint=self.evidence_fingerprint,
        )


class RelationshipEvidenceAccumulator:
    """The bounded streaming evidence kernel for ONE relation side pair.

    One instance collects the before (source) side or the after (transformed)
    side of one declared relation.  Callers feed ONE key tuple per physical
    row (active AND deleted records); internal state is bounded by the number
    of DISTINCT key tuples, never by dataset size.  A NULL-containing tuple
    is observed as the EMPTY tuple with ``null=True`` — the same canonical
    marker the established relation evidence uses — and participates in
    neither uniqueness, nor join matching, nor the multiplicity profiles; it
    is counted per side.  A non-NULL key must have EXACTLY the declared
    composite arity; component order is semantically significant.
    """

    def __init__(self, *, composite_arity: int) -> None:
        if (
            isinstance(composite_arity, bool)
            or not isinstance(composite_arity, int)
            or composite_arity < 1
        ):
            raise ValueError("composite_arity must be a positive integer")
        self._arity = composite_arity
        self._parent_counts: dict[tuple[Hashable, ...], int] = {}
        self._parent_nulls = 0
        self._foreign_counts: dict[tuple[Hashable, ...], int] = {}
        self._foreign_nulls = 0

    @property
    def composite_arity(self) -> int:
        return self._arity

    def observe_parent(
        self, key: tuple[Hashable, ...], *, null: bool = False
    ) -> None:
        """Observe one parent-side row (active or deleted; never a value)."""
        self._observe(self._parent_counts, self._bump_parent_null, key, null)

    def observe_foreign(
        self, key: tuple[Hashable, ...], *, null: bool = False
    ) -> None:
        """Observe one foreign-side row (active or deleted; value-free)."""
        self._observe(self._foreign_counts, self._bump_foreign_null, key, null)

    def build(self) -> RelationEvidenceCounts:
        """The frozen count-only evidence of everything observed so far."""
        parent = _side_metrics(self._parent_counts, self._parent_nulls)
        foreign = _side_metrics(self._foreign_counts, self._foreign_nulls)
        matched = sum(
            count
            for key, count in self._foreign_counts.items()
            if key in self._parent_counts
        )
        orphan = sum(self._foreign_counts.values()) - matched
        return RelationEvidenceCounts(
            composite_arity=self._arity,
            parent=parent,
            foreign=foreign,
            matched_row_count=matched,
            orphan_count=orphan,
        )

    def _bump_parent_null(self) -> None:
        self._parent_nulls += 1

    def _bump_foreign_null(self) -> None:
        self._foreign_nulls += 1

    def _observe(
        self,
        counts: dict[tuple[Hashable, ...], int],
        bump_null: Callable[[], None],
        key: tuple[Hashable, ...],
        null: bool,
    ) -> None:
        if not isinstance(null, bool):
            raise TypeError("the null marker must be a genuine boolean")
        if not isinstance(key, tuple):
            raise TypeError("a relation evidence key must be a plain tuple")
        if null:
            if key != ():
                raise ValueError("a NULL evidence key must be the empty tuple")
            bump_null()
            return
        if len(key) != self._arity:
            raise ValueError("the evidence key arity must match the relation arity")
        try:
            counts[key] = counts.get(key, 0) + 1
        except TypeError:
            raise TypeError(
                "a relation evidence key must contain only hashable components"
            ) from None


def _side_metrics(
    counts: Mapping[tuple[Hashable, ...], int], nulls: int
) -> RelationSideMetrics:
    """The frozen side metrics of one histogram (sorted profile, no keys)."""
    profile = tuple(sorted(counts.values(), reverse=True))
    return RelationSideMetrics(
        rows_considered=nulls + sum(profile),
        null_tuple_count=nulls,
        unique_tuple_count=len(profile),
        duplicate_row_count=sum(profile) - len(profile),
        multiplicity_profile=profile,
    )


def compare_relation_metrics(
    before: RelationEvidenceCounts, after: RelationEvidenceCounts
) -> tuple[RelationInvariantResult, ...]:
    """The canonical before/after invariant comparison (counts only).

    THE ONE invariant rule of REQ-P3-006, shared by every caller:

    * parent key uniqueness is preserved (the full parent multiplicity
      profile is equal — unique tuple count, duplicate row count and every
      parent multiplicity are implied);
    * the FK orphan count is preserved;
    * the matched-row count is preserved;
    * both NULL counts are preserved;
    * the composite foreign tuple multiplicity profile is preserved.

    A before/after composite-arity mismatch is a typed fail-closed refusal —
    evidence with a different arity can never be compared truthfully.
    """
    if before.composite_arity != after.composite_arity:
        raise _verification_failure("RELATIONSHIP_VERIFICATION_ARITY_MISMATCH")
    return (
        RelationInvariantResult(
            invariant=INVARIANT_PARENT_UNIQUENESS,
            preserved=before.parent.multiplicity_profile
            == after.parent.multiplicity_profile,
        ),
        RelationInvariantResult(
            invariant=INVARIANT_ORPHAN_COUNT,
            preserved=before.orphan_count == after.orphan_count,
        ),
        RelationInvariantResult(
            invariant=INVARIANT_MATCHED_ROWS,
            preserved=before.matched_row_count == after.matched_row_count,
        ),
        RelationInvariantResult(
            invariant=INVARIANT_NULL_COUNTS,
            preserved=(
                before.parent.null_tuple_count,
                before.foreign.null_tuple_count,
            )
            == (after.parent.null_tuple_count, after.foreign.null_tuple_count),
        ),
        RelationInvariantResult(
            invariant=INVARIANT_FOREIGN_MULTIPLICITY,
            preserved=before.foreign.multiplicity_profile
            == after.foreign.multiplicity_profile,
        ),
    )


def _group_arity(group: RelationGroup) -> int:
    """The declared composite arity of one relation group (parent side)."""
    members = group.members_for_role(KEY_ROLE_PRIMARY)
    if not members:
        members = group.members_for_role(KEY_ROLE_CANDIDATE)
    return len(members)


def verify_relationships(
    document: RelationshipDocument,
    *,
    before: Mapping[str, RelationEvidenceCounts],
    after: Mapping[str, RelationEvidenceCounts],
) -> RelationshipVerificationReport:
    """Verify EVERY declared relation of one relationship document.

    The declared relations come from the authoritative typed document; the
    report is bound to the document's canonical fingerprint.  Fail-closed
    structural contract:

    * evidence for a relation that the document does not declare is a typed
      refusal (``RELATIONSHIP_VERIFICATION_UNKNOWN_RELATION``);
    * a composite-arity mismatch between a side and its declared relation —
      or between the two sides — is a typed refusal
      (``RELATIONSHIP_VERIFICATION_ARITY_MISMATCH``);
    * a declared relation WITHOUT before or after evidence becomes an
      ``INCOMPLETE`` entry (never a synthesized zero-count relation), and the
      report is not ``complete``;
    * relations are verified in canonical (relation_id) order so the report
      is deterministic regardless of declaration order.
    """
    fingerprint = relationship_fingerprint(document)
    declared = {group.relation_id: group for group in document.canonical_groups()}
    for side_name, side in (("before", before), ("after", after)):
        for relation_id, counts in side.items():
            if not isinstance(relation_id, str) or relation_id not in declared:
                raise _verification_failure(
                    "RELATIONSHIP_VERIFICATION_UNKNOWN_RELATION"
                )
            _validate_bounded_token(
                relation_id, "RELATIONSHIP_VERIFICATION_UNKNOWN_RELATION"
            )
            if not isinstance(counts, RelationEvidenceCounts):
                raise TypeError(
                    f"the {side_name} evidence must be RelationEvidenceCounts"
                )
    entries: list[RelationVerificationEvidence] = []
    for relation_id, group in declared.items():
        before_counts = before.get(relation_id)
        after_counts = after.get(relation_id)
        if before_counts is None or after_counts is None:
            entries.append(
                RelationVerificationEvidence(
                    relation_id=relation_id,
                    composite_arity=_group_arity(group),
                    status=VerificationStatus.INCOMPLETE,
                    before=before_counts,
                    after=after_counts,
                    invariants=(),
                )
            )
            continue
        arity = _group_arity(group)
        if (
            before_counts.composite_arity != arity
            or after_counts.composite_arity != arity
        ):
            raise _verification_failure(
                "RELATIONSHIP_VERIFICATION_ARITY_MISMATCH", relation_id
            )
        invariants = compare_relation_metrics(before_counts, after_counts)
        status = (
            VerificationStatus.VERIFIED
            if all(result.preserved for result in invariants)
            else VerificationStatus.FAILED
        )
        entries.append(
            RelationVerificationEvidence(
                relation_id=relation_id,
                composite_arity=arity,
                status=status,
                before=before_counts,
                after=after_counts,
                invariants=invariants,
            )
        )
    return RelationshipVerificationReport(
        evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
        relationship_fingerprint=fingerprint,
        relations=tuple(entries),
        complete=all(
            entry.status is not VerificationStatus.INCOMPLETE for entry in entries
        ),
    )