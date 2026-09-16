"""Bounded relational evidence for declared C/V relations (P3-002/P3-003).

The minimal internal evidence utility for this PR's acceptance tests.  It
computes COUNTS ONLY — unique key count, duplicate multiplicity profiles,
orphan count, matched-row count and NULL counts — from caller-supplied key
tuples.  It never serializes, logs or exposes any actual key value: the
inputs are consumed and the outputs are integers and count profiles.

The full REQ-P3-006 reporting subsystem is deliberately NOT implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable, Sequence

__all__ = ["RelationalMetrics", "relation_metrics"]


def _multiplicity_profile(keys: Sequence[tuple[Hashable, ...]]) -> tuple[int, ...]:
    """The sorted (descending) multiplicities of DISTINCT non-NULL keys.

    A counts-only representation: the actual key values are consumed and
    never serialized.
    """
    histogram: dict[tuple[Hashable, ...], int] = {}
    for key in keys:
        histogram[key] = histogram.get(key, 0) + 1
    return tuple(sorted(histogram.values(), reverse=True))


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
    primary_nulls = sum(1 for flagged in primary_mask if flagged)
    foreign_nulls = len([flagged for flagged in foreign_mask if flagged])
    primary_set = {
        key for key, flagged in zip(primary_keys, primary_mask) if not flagged
    }
    primary_material = [
        key for key, flagged in zip(primary_keys, primary_mask) if not flagged
    ]
    multiplicity: dict[tuple[Hashable, ...], int] = {}
    for key in primary_material:
        multiplicity[key] = multiplicity.get(key, 0) + 1
    primary_profile = tuple(sorted(multiplicity.values(), reverse=True))
    foreign_histogram: dict[tuple[Hashable, ...], int] = {}
    for key, flagged in zip(foreign_keys, foreign_mask):
        if flagged:
            continue
        foreign_histogram[key] = foreign_histogram.get(key, 0) + 1
    matched = 0
    orphan = 0
    for key, flagged in zip(foreign_keys, foreign_mask):
        if flagged:
            continue
        if key in primary_set:
            matched += 1
        else:
            orphan += 1
    foreign_profile = tuple(sorted(foreign_histogram.values(), reverse=True))
    unique_count = len(multiplicity)
    max_multiplicity = max(multiplicity.values(), default=0)
    return RelationalMetrics(
        key_unique_count=unique_count,
        key_null_count=primary_nulls,
        max_duplicate_multiplicity=max_multiplicity,
        matched_row_count=matched,
        orphan_count=orphan,
        foreign_null_count=foreign_nulls,
        primary_multiplicity_profile=primary_profile,
        foreign_multiplicity_profile=foreign_profile,
    )