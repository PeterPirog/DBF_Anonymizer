"""Bounded relational evidence for declared C/V relations (P3-002/P3-003).

The minimal internal evidence utility for this PR's acceptance tests.  It
computes COUNTS ONLY — unique key count, duplicate multiplicity profiles,
orphan count, matched-row count and NULL counts — from caller-supplied key
tuples.  It never serializes, logs or exposes any actual key value: the
inputs are consumed and the outputs are integers and count profiles.

The counting itself is the ONE shared evidence kernel of REQ-P3-006
(:class:`~dbf_anonymizer.relationships.verification.RelationshipEvidenceAccumulator`),
so the established metric semantics and the verification evidence can never
drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable, Sequence

from dbf_anonymizer.relationships.verification import RelationshipEvidenceAccumulator

__all__ = ["RelationalMetrics", "relation_metrics"]


@dataclass(frozen=True)
class RelationalMetrics:
    """Bounded before/after relational evidence (counts, never values)."""

    key_unique_count: int
    key_null_count: int
    max_duplicate_multiplicity: int
    matched_row_count: int
    orphan_count: int
    foreign_null_count: int
    primary_multiplicity_profile: tuple[int, ...] = ()
    foreign_multiplicity_profile: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Counts-only serialization: no key value can ever appear."""
        return {
            "key_unique_count": self.key_unique_count,
            "key_null_count": self.key_null_count,
            "max_duplicate_multiplicity": self.max_duplicate_multiplicity,
            "matched_row_count": self.matched_row_count,
            "orphan_count": self.orphan_count,
            "foreign_null_count": self.foreign_null_count,
            "primary_multiplicity_profile": list(self.primary_multiplicity_profile),
            "foreign_multiplicity_profile": list(self.foreign_multiplicity_profile),
        }


def relation_metrics(
    primary_keys: Sequence[tuple[Hashable, ...]],
    foreign_keys: Sequence[tuple[Hashable, ...]],
    *,
    primary_null_mask: Sequence[bool] | None = None,
    foreign_null_mask: Sequence[bool] | None = None,
) -> RelationalMetrics:
    """Relational evidence for one primary/foreign side pair.

    NULL rows (marked ``True`` in the masks — represented by the empty tuple
    so the key sequence and the mask stay aligned) are excluded from
    uniqueness and join matching exactly like SQL NULL semantics; a composite
    key is one ordered tuple, so component ordering is semantically
    significant.  An omitted mask treats every row as non-NULL.

    Fail-closed input contract (deterministic, no misleading metrics): a
    supplied mask must have EXACTLY one entry per key, every mask entry must
    be a genuine ``bool``, every non-NULL key tuple of one side must share
    the same arity, and the parent arity must equal the foreign arity.
    """
    primary_mask = (
        primary_null_mask if primary_null_mask is not None else [False] * len(primary_keys)
    )
    foreign_mask = (
        foreign_null_mask if foreign_null_mask is not None else [False] * len(foreign_keys)
    )
    if len(primary_mask) != len(primary_keys) or len(foreign_mask) != len(foreign_keys):
        raise ValueError("relational evidence mask length must match the key count")
    if any(not isinstance(flagged, bool) for flagged in primary_mask) or any(
        not isinstance(flagged, bool) for flagged in foreign_mask
    ):
        raise TypeError("null mask entries must be genuine booleans")
    primary_arities = {
        len(key) for key, flagged in zip(primary_keys, primary_mask) if not flagged
    }
    if len(primary_arities) > 1:
        raise ValueError("primary key arity must be uniform")
    foreign_arities = {
        len(key) for key, flagged in zip(foreign_keys, foreign_mask) if not flagged
    }
    if len(foreign_arities) > 1:
        raise ValueError("foreign key arity must be uniform")
    if primary_arities and foreign_arities and primary_arities != foreign_arities:
        raise ValueError("parent and foreign key arity must match")
    if primary_arities:
        arity = next(iter(primary_arities))
    elif foreign_arities:
        arity = next(iter(foreign_arities))
    else:
        arity = 1
    accumulator = RelationshipEvidenceAccumulator(composite_arity=arity)
    for key, flagged in zip(primary_keys, primary_mask):
        if flagged:
            # A NULL-containing tuple: the actual key value is consumed and
            # never stored; the empty tuple is the canonical NULL marker.
            accumulator.observe_parent((), null=True)
        else:
            accumulator.observe_parent(key)
    for key, flagged in zip(foreign_keys, foreign_mask):
        if flagged:
            accumulator.observe_foreign((), null=True)
        else:
            accumulator.observe_foreign(key)
    counts = accumulator.build()
    return RelationalMetrics(
        key_unique_count=counts.parent.unique_tuple_count,
        key_null_count=counts.parent.null_tuple_count,
        max_duplicate_multiplicity=(
            counts.parent.multiplicity_profile[0]
            if counts.parent.multiplicity_profile
            else 0
        ),
        matched_row_count=counts.matched_row_count,
        orphan_count=counts.orphan_count,
        foreign_null_count=counts.foreign.null_tuple_count,
        primary_multiplicity_profile=counts.parent.multiplicity_profile,
        foreign_multiplicity_profile=counts.foreign.multiplicity_profile,
    )