"""Pass 1 of the bounded two-pass engine (REQ-P4-002).

PASS 1 direct-reads the source dataset in deterministic table/physical-record
order through the ONE public Direct Read boundary and owns ONLY the global
facts that must be known before writing:

* text mapping observations and their storage-backed allocation state;
* explicit numeric key domain observations and allocation state;
* temporal-domain calendar extrema (O(1) bounded state, vault-persisted);
* declared relationship BEFORE evidence (SQLite histograms);
* bounded structural counters for pass 2.

Every dataset-sized or distinct-value-sized state lives in the protected
ephemeral SQLite spool (:mod:`dbf_anonymizer.engine.state`); the Python-side
state of this pass is O(1) plus bounded SQL batch buffers.

Finalization allocates the vault mappings through ONE semantic definition
per domain kind:

* TEXT — the fungible CSPRNG streaming allocation: originals are processed
  in deterministic (strictest width, canonical identity) order and each one
  receives a CSPRNG-chosen free token of the SHORTEST feasible length class
  that is neither occupied nor the still-unpersisted self-value of another
  original (EDF ordering; SQL-backed occupancy and self-value checks).  The
  documented near-exhaustion regime (NO fungible capacity left in any
  reachable class) delegates the remaining problem to the ONE authoritative
  exact planner — the existing P2 :class:`GlobalTextDomainMapping` — which
  is the same semantic definition as the P2 evidence; its O(remaining
  distinct) memory in that regime is truthful and never presented as the
  general bounded path.
* NUMERIC — every candidate is committed ONLY after the residual
  feasibility kernel (the authoritative P2/P3 Hall conditions, re-evaluated
  with O(1) SQL aggregates and cross-checked against
  :func:`dbf_anonymizer.transforms.numeric_keys.plan_numeric_bijection`)
  proves the residual problem stays feasible.

No original value, pseudonym, path or SQL text ever reaches a public
boundary; the spool is classified as sensitive Zone B material while it
exists.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Sequence

from dbf_anonymizer.engine import direct_io
from dbf_anonymizer.engine.directives import (
    ACTION_TEMPORAL,
    EnginePlan,
    FieldDirective,
    RelationDirective,
    TableDirective,
)
from dbf_anonymizer.engine.direct_io import stream_table_records
from dbf_anonymizer.engine.state import PassOneSpool
from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError
from dbf_anonymizer.progress import ProgressController, ProgressPhase
from dbf_anonymizer.transforms.numeric_keys import (
    NumericKeyDomain,
    NumericKeyMemberRange,
    canonical_integer_text,
    classify_member_original,
    parse_canonical_integer_text,
    plan_numeric_bijection,
)
from dbf_anonymizer.transforms.text import (
    candidate_alphabet,
    is_safe_token,
    token_at,
    token_index,
    token_space,
)
from dbf_anonymizer.vault.mappings import (
    add_numeric_key_mapping,
    add_text_mapping,
    create_domain,
    get_numeric_pseudonym,
    get_text_pseudonym,
    mapping_domains,
)
from dbf_anonymizer.vault.numeric_allocation import NUMERIC_KEY_PROBE_BUDGET
from dbf_anonymizer.vault.schema import (
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
)
from dbf_anonymizer.vault.store import VaultDatabase
from dbf_anonymizer.vault.text_allocation import (
    GLOBAL_TEXT_DOMAIN_ID,
    GLOBAL_TEXT_PROBE_BUDGET,
    GlobalTextDomainMapping,
)
from dbf_anonymizer.vault.temporal_allocation import TemporalShiftDomain

__all__ = ["PassOneOutcome", "run_pass_one", "run_pass_one_finalize"]

_TEXT_PROBE_BUDGET = GLOBAL_TEXT_PROBE_BUDGET
_TEXT_COMPLETION_WALK_LIMIT = 4096
_NUMERIC_COMPLETION_WALK_LIMIT = 4096


@dataclass
class PassOneOutcome:
    """The bounded pass-1 result (identities and counts only)."""

    text_domain_id: str | None = None
    text_allocated: int = 0
    text_reused: int = 0
    numeric_domains: tuple[str, ...] = ()
    numeric_allocated: dict[str, int] = field(default_factory=dict)
    temporal_offset: int | None = None
    temporal_domain_id: str | None = None
    tables_scanned: int = 0
    records_scanned: int = 0
    deleted_scanned: int = 0


def _mapping_failure(detail_code: str) -> MappingError:
    return MappingError(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        context=ErrorContext(operation="engine", detail_code=detail_code),
    )


def _capacity_failure(detail_code: str) -> MappingError:
    return MappingError(
        ErrorCode.MAPPING_CAPACITY_EXHAUSTED,
        context=ErrorContext(operation="engine", detail_code=detail_code),
    )


def _has_domain(vault: VaultDatabase, domain_id: str) -> bool:
    return any(row["domain_id"] == domain_id for row in mapping_domains(vault))


# ---------------------------------------------------------------------------
# PASS 1 SCAN
# ---------------------------------------------------------------------------
def run_pass_one(
    engine_plan: EnginePlan,
    *,
    source_root: Path,
    vault: VaultDatabase,
    spool: PassOneSpool,
    control: ProgressController,
    outcome: PassOneOutcome,
    temporal_domain: TemporalShiftDomain | None,
) -> None:
    """One deterministic Direct Read scan of the whole planned dataset."""


    assert isinstance(engine_plan, EnginePlan)
    control.start_phase(ProgressPhase.PASS1_SCAN, total=len(engine_plan.tables))
    for directive in engine_plan.tables:
        assert isinstance(directive, TableDirective)
        control.check_cancelled()
        table = direct_io.read_source_table(
            Path(source_root),
            directive.relative_path,
            cancel_check=control.check_cancelled,
        )
        spool.flush()
        projected = _projection_fields(directive)
        memo_policy = "inline" if table.has_memo_fields else "skip"
        records = stream_table_records(
            table,
            fields=projected,
            include_deleted=True,
            memo_policy=memo_policy,
            cancel_check=control.check_cancelled,
        )
        for record in records:
            control.check_cancelled()
            _observe_record(
                engine_plan, directive, record, spool, outcome, temporal_domain
            )
            outcome.records_scanned += 1
            if record.deleted:
                outcome.deleted_scanned += 1
        control.bump(ProgressPhase.PASS1_SCAN, table_path=directive.relative_path)
        outcome.tables_scanned += 1
        spool.flush()



def _projection_fields(directive: "TableDirective") -> Sequence[str] | None:
    """Pass 1 reads only the transformed/relation fields (bounded reads).

    Memo fields are NEVER read in pass 1 (their payloads are never copied
    into relationship evidence); the full field set is read in pass 2.
    """
    names: set[str] = set()
    for field_directive in directive.transformed:
        names.add(field_directive.field_name)
    return tuple(sorted(names)) if names else None


def _observe_record(
    engine_plan: "EnginePlan",
    directive: "TableDirective",
    record: object,
    spool: PassOneSpool,
    outcome: PassOneOutcome,
    temporal_domain: TemporalShiftDomain | None,
) -> None:
    values = record.values  # type: ignore[attr-defined]
    for field_directive in directive.transformed:
        name = field_directive.field_name
        value = values.get(name)
        if field_directive.numeric_domain_id is not None:
            _observe_numeric(field_directive, value, spool)
        elif field_directive.action == "PSEUDONYMIZE_REVERSIBLE":
            _observe_text(field_directive, value, spool)
        elif field_directive.action == "SHIFT_REVERSIBLE":
            if temporal_domain is not None:
                temporal_domain.observe(value)
        # MASK_REVERSIBLE: memo payloads are never collected into evidence.
    for relation in engine_plan.relations:
        assert isinstance(relation, RelationDirective)
        if relation.parent_table == directive.relative_path:
            _observe_relation_side(
                relation, "before", "parent", relation.parent_fields, record, spool
            )
        if relation.foreign_table == directive.relative_path:
            _observe_relation_side(
                relation, "before", "foreign", relation.foreign_fields, record, spool
            )


def _observe_relation_side(
    relation: "RelationDirective",
    side: str,
    role: str,
    fields: Sequence[str],
    record: object,
    spool: PassOneSpool,
) -> None:
    """The P3 NULL semantics: a NULL-containing tuple is counted, not keyed."""
    values = record.values  # type: ignore[attr-defined]
    components: list[object] = []
    null_tuple = False
    for field_name in fields:
        value = values.get(field_name)
        if value is None:
            null_tuple = True
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise _mapping_failure("ENGINE_RELATION_MEMBER_UNSUPPORTED")
        components.append(int(value) if isinstance(value, int) else str(value))
    spool.observe_relation_side(
        side, relation.relation_id, role, rows=1, nulls=1 if null_tuple else 0
    )
    if not null_tuple:
        from dbf_anonymizer.engine.state import canonical_composite_identity

        spool.observe_relation_key(
            side,
            relation.relation_id,
            role,
            canonical_composite_identity(tuple(components)),
        )


def _observe_text(
    field_directive: "FieldDirective", value: object, spool: PassOneSpool
) -> None:


    assert isinstance(field_directive, FieldDirective)
    if value is None or value == "":
        return  # NULL and empty stay preserved identities, never mapped
    if not isinstance(value, str):
        raise _mapping_failure("ENGINE_TEXT_VALUE_UNSUPPORTED")
    spool.observe_text(value, byte_width=field_directive.byte_width)
    spool.observe_text_encoding(field_directive.encoding)


def _observe_numeric(
    field_directive: "FieldDirective", value: object, spool: PassOneSpool
) -> None:


    assert isinstance(field_directive, FieldDirective)
    if value is None:
        return  # NULL is never observed (preserved identity)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _mapping_failure("ENGINE_NUMERIC_VALUE_UNSUPPORTED")
    domain_id = field_directive.numeric_domain_id
    assert domain_id is not None
    member = field_directive.numeric_member_range
    assert member is not None
    verdict = classify_member_original(member, value)
    if verdict == "OUT_OF_MEMBER_RANGE":
        raise _mapping_failure("ENGINE_NUMERIC_OUT_OF_MEMBER_RANGE")
    if verdict == "RECOVERY_UNWRITABLE":
        raise _mapping_failure("NUMERIC_KEY_RECOVERY_UNWRITABLE")
    spool.observe_numeric(domain_id, canonical_integer_text(value))


# ---------------------------------------------------------------------------
# PASS 1 FINALIZE
# ---------------------------------------------------------------------------
def run_pass_one_finalize(
    engine_plan: EnginePlan,
    *,
    vault: VaultDatabase,
    spool: PassOneSpool,
    control: ProgressController,
    outcome: PassOneOutcome,
    temporal_domain: TemporalShiftDomain | None,
) -> None:
    """Allocate every finalized mapping and persist the vault truth."""


    assert isinstance(engine_plan, EnginePlan)
    control.start_phase(ProgressPhase.PASS1_FINALIZE)
    if engine_plan.text_present:
        domain_id, allocated, reused = _finalize_text(vault, spool, control)
        outcome.text_domain_id = domain_id
        outcome.text_allocated = allocated
        outcome.text_reused = reused
    control.check_cancelled()
    for relation in engine_plan.relations:
        if relation.numeric_domain_id is None or relation.numeric_domain is None:
            continue
        allocated = _finalize_numeric(
            vault, spool, relation.numeric_domain_id, relation.numeric_domain, control
        )
        outcome.numeric_domains = outcome.numeric_domains + (relation.numeric_domain_id,)
        outcome.numeric_allocated[relation.numeric_domain_id] = allocated
        control.check_cancelled()
    if temporal_domain is not None:
        offset = temporal_domain.finalize()
        outcome.temporal_offset = offset
        outcome.temporal_domain_id = temporal_domain.domain_id



# ---------------------------------------------------------------------------
# TEXT finalization (storage-backed streaming allocation + exact oracle)
# ---------------------------------------------------------------------------
def _finalize_text(
    vault: VaultDatabase, spool: PassOneSpool, control: ProgressController
) -> tuple[str | None, int, int]:
    encodings = spool.text_encoding_union()
    if not encodings:
        return (None, 0, 0)
    alphabet = candidate_alphabet(encodings)
    if not alphabet:
        raise _mapping_failure("ENGINE_TEXT_NO_SAFE_ALPHABET")
    domain_id = GLOBAL_TEXT_DOMAIN_ID
    if not _has_domain(vault, domain_id):
        with vault.transaction():
            if not _has_domain(vault, domain_id):
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=domain_id,
                )
    base = len(alphabet)
    occupied = _occupied_text_lengths(vault, domain_id)
    reserved = _reserved_text_lengths(vault, spool, domain_id, alphabet)
    allocated = 0
    reused = 0
    for value, width in spool.text_observations():
        control.check_cancelled()
        existing = get_text_pseudonym(vault, domain_id, value)
        if existing is not None:
            if len(existing) > width:
                raise _mapping_failure("ENGINE_TEXT_PERSISTED_INCOMPATIBLE")
            spool.drop_text_observation(value)
            if is_safe_token(value, alphabet) and not _token_occupied(
                vault, domain_id, value
            ):
                _counter_down(reserved, len(value))
            reused += 1
            continue
        if width <= 0:
            raise _mapping_failure("ENGINE_TEXT_WIDTH_INFEASIBLE")
        candidate = _select_text_candidate(
            value,
            width,
            alphabet=alphabet,
            base=base,
            occupied=occupied,
            reserved=reserved,
            vault=vault,
            spool=spool,
            domain_id=domain_id,
        )
        with vault.transaction():
            fresh = get_text_pseudonym(vault, domain_id, value)
            if fresh is None:
                add_text_mapping(
                    vault,
                    domain_id,
                    value,
                    candidate,
                    logical_byte_length=len(candidate),
                )
            else:  # pragma: no cover - single writer, defensive only
                candidate = fresh
        spool.drop_text_observation(value)
        _after_text_commit(
            value, candidate, alphabet, vault, domain_id, spool, occupied, reserved
        )
        allocated += 1
    return (domain_id, allocated, reused)


def _occupied_text_lengths(
    vault: VaultDatabase, domain_id: str
) -> dict[int, int]:
    """O(max_width) occupied-token counters (one SQL aggregate)."""
    rows = vault._internal_connection().execute(
        "SELECT logical_byte_length, COUNT(*) FROM text_mappings "
        "WHERE domain_id = ? GROUP BY logical_byte_length",
        (domain_id,),
    ).fetchall()
    return {int(length): int(count) for length, count in rows}


def _reserved_text_lengths(
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
    alphabet: str,
) -> dict[int, int]:
    """O(max_width) reserved-token counters (one streamed SQL pass).

    A reserved token is the still-unpersisted self-value of one original: a
    safe token whose value equals some remaining observation and which is
    not occupied.  The pass streams the spool (O(1) RAM) and checks vault
    occupancy through the indexed mapping table.
    """
    reserved: dict[int, int] = {}
    cursor = spool.internal_connection().execute(
        "SELECT value_length, canonical FROM text_observation ORDER BY value_length"
    )
    while True:
        rows = cursor.fetchmany(512)
        if not rows:
            break
        for length, canonical in rows:
            value = bytes(canonical).decode("utf-8")
            if not is_safe_token(value, alphabet):
                continue
            if _token_occupied(vault, domain_id, value):
                continue
            reserved[int(length)] = reserved.get(int(length), 0) + 1
    return reserved


def _token_occupied(vault: VaultDatabase, domain_id: str, token: str) -> bool:
    row = vault._internal_connection().execute(
        "SELECT 1 FROM text_mappings WHERE domain_id = ? AND pseudonym_value = ?",
        (domain_id, token),
    ).fetchone()
    return row is not None


def _counter_down(counters: dict[int, int], length: int) -> None:
    current = counters.get(length, 0)
    if current > 0:
        counters[length] = current - 1


def _class_size(base: int, length: int) -> int:
    """The exact token count of one length class (bounded arithmetic)."""
    size: int = base**length
    return size


def _supply_of(
    length: int, base: int, occupied: dict[int, int], reserved: dict[int, int]
) -> int:
    return _class_size(base, length) - occupied.get(length, 0) - reserved.get(length, 0)


def _shortest_fungible_class(
    width: int, base: int, occupied: dict[int, int], reserved: dict[int, int]
) -> tuple[int, int] | None:
    """The shortest feasible length class and its fungible free supply."""
    for length in range(1, width + 1):
        supply = _supply_of(length, base, occupied, reserved)
        if supply > 0:
            return (length, supply)
    return None


def _select_text_candidate(
    value: str,
    width: int,
    *,
    alphabet: str,
    base: int,
    occupied: dict[int, int],
    reserved: dict[int, int],
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
) -> str:
    """One CSPRNG free fungible token (probe phase, then exact completion)."""
    selection = _shortest_fungible_class(width, base, occupied, reserved)
    if selection is None:
        return _text_oracle_complete(
            value,
            vault=vault,
            spool=spool,
            domain_id=domain_id,
        )
    length, _supply = selection
    class_low = token_space(length - 1, base)
    class_size = base**length
    for _ in range(_TEXT_PROBE_BUDGET):
        candidate = token_at(
            class_low + secrets.randbelow(class_size), length, alphabet
        )
        if candidate == value:
            continue
        if _token_occupied(vault, domain_id, candidate):
            continue
        if spool.text_is_observed(candidate):
            continue
        return candidate
    return _text_exact_completion(
        value,
        width,
        alphabet=alphabet,
        base=base,
        vault=vault,
        spool=spool,
        domain_id=domain_id,
    )


def _occupied_tokens_of_length(
    vault: VaultDatabase, domain_id: str, length: int
) -> Iterator[str]:
    cursor = vault._internal_connection().execute(
        "SELECT pseudonym_value FROM text_mappings "
        "WHERE domain_id = ? AND logical_byte_length = ?",
        (domain_id, length),
    )
    while True:
        rows = cursor.fetchmany(512)
        if not rows:
            return
        for (token,) in rows:
            yield str(token)


def _text_exact_completion(
    value: str,
    width: int,
    *,
    alphabet: str,
    base: int,
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
) -> str:
    """The exact deterministic completion of one fungible class slot.

    The j-th free fungible token of the SHORTEST feasible class is selected
    by an ascending gap walk over the blocked index stream; ``j`` comes from
    the OS CSPRNG exactly like the probe phase, so nothing is
    sequence-derived and nothing is derived from the original value.  The
    blocked indices are materialized into a sorted SQLite temp table so the
    walk runs with O(1) Python RAM.
    """
    counters = _counters_for(vault, spool, domain_id, alphabet)
    selection = _shortest_fungible_class(width, base, counters[0], counters[1])
    if selection is None:  # pragma: no cover - the caller checked supply
        return _text_oracle_complete(
            value, vault=vault, spool=spool, domain_id=domain_id
        )
    length, supply = selection
    class_low = token_space(length - 1, base)
    connection = spool.internal_connection()
    connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS blocked_index (idx INTEGER PRIMARY KEY)"
    )
    connection.execute("DELETE FROM blocked_index")
    for token in _occupied_tokens_of_length(vault, domain_id, length):
        connection.execute(
            "INSERT OR IGNORE INTO blocked_index (idx) VALUES (?)",
            (token_index(token, alphabet),),
        )
    for reserved_value in spool.text_values_of_length(length):
        if is_safe_token(reserved_value, alphabet):
            connection.execute(
                "INSERT OR IGNORE INTO blocked_index (idx) VALUES (?)",
                (token_index(reserved_value, alphabet),),
            )
    connection.commit()

    def sorted_indices() -> Iterator[int]:
        cursor = connection.execute("SELECT idx FROM blocked_index ORDER BY idx")
        while True:
            rows = cursor.fetchmany(512)
            if not rows:
                return
            for (index,) in rows:
                yield int(index)

    chosen = _streaming_jth_free_text(
        class_low=class_low, blocked_sorted=sorted_indices(), j=secrets.randbelow(supply)
    )
    connection.execute("DELETE FROM blocked_index")
    connection.commit()
    return token_at(chosen, length, alphabet)


def _streaming_jth_free_text(
    *,
    class_low: int,
    blocked_sorted: Iterator[int],
    j: int,
) -> int:
    """The j-th free index of one class over a SORTED blocked index stream.

    The same gap-walk rule as the authoritative P2
    :func:`dbf_anonymizer.transforms.text._jth_free_in_class` kernel
    (equivalence is cross-checked by the randomized test suite), evaluated
    with O(1) Python RAM over a SQL-ordered index stream.
    """
    previous = class_low - 1
    remaining = j
    for index in blocked_sorted:
        gap = index - previous - 1
        if remaining < gap:
            return previous + 1 + remaining
        remaining -= gap
        previous = index
    return previous + 1 + remaining


def _counters_for(
    vault: VaultDatabase, spool: PassOneSpool, domain_id: str, alphabet: str
) -> tuple[dict[int, int], dict[int, int]]:
    occupied = _occupied_text_lengths(vault, domain_id)
    reserved = _reserved_text_lengths(vault, spool, domain_id, alphabet)
    return (occupied, reserved)


def _text_oracle_complete(
    value: str,
    *,
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
) -> str:
    """The documented near-exhaustion regime: the ONE exact P2 planner.

    The remaining unpersisted observation set is loaded into the existing
    P2 :class:`GlobalTextDomainMapping` (the SAME semantic definition as the
    P2 evidence) which plans and allocates the complete residual problem
    EXACTLY (derangements included).  Its O(remaining distinct) memory in
    this regime is truthful, documented and exercised only by small
    adversarial fixtures.
    """
    planner = GlobalTextDomainMapping(vault, domain_id=domain_id)
    encodings = sorted(spool.text_encoding_union())
    if not encodings:  # pragma: no cover - the streaming phase required one
        raise _mapping_failure("ENGINE_TEXT_ORACLE_EMPTY")
    for observed, observed_width in spool.text_observations():
        for encoding in encodings:
            planner.observe(observed, encoding=encoding, byte_width=observed_width)
    planner.finalize()
    mapped = planner.pseudonym_for(value)
    spool.drop_text_observation(value)
    return mapped


def _after_text_commit(
    value: str,
    candidate: str,
    alphabet: str,
    vault: VaultDatabase,
    domain_id: str,
    spool: PassOneSpool,
    occupied: dict[int, int],
    reserved: dict[int, int],
) -> None:
    """O(1) counter maintenance after one committed allocation."""
    occupied[len(candidate)] = occupied.get(len(candidate), 0) + 1
    if is_safe_token(value, alphabet) and not _token_occupied(vault, domain_id, value):
        _counter_down(reserved, len(value))
    if is_safe_token(candidate, alphabet) and spool.text_is_observed(candidate):
        # The committed token was a remaining original's own value; it is
        # occupied now and leaves the reserved pool.
        _counter_down(reserved, len(candidate))


# ---------------------------------------------------------------------------
# NUMERIC finalization (storage-backed streaming allocation, P3 kernel rules)
# ---------------------------------------------------------------------------
def _finalize_numeric(
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
    domain: NumericKeyDomain,
    control: ProgressController,
) -> int:
    from dbf_anonymizer.vault.mappings import numeric_mapping_rows

    if not _has_domain(vault, domain_id):
        with vault.transaction():
            if not _has_domain(vault, domain_id):
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
                    domain_id=domain_id,
                )
    occupied = sum(1 for _row in numeric_mapping_rows(vault, domain_id))
    remaining = spool.numeric_unpersisted_count(domain_id)
    if not _numeric_residual_feasible(
        domain=domain,
        occupied_after=occupied,
        remaining_after=remaining,
        vault=vault,
        spool=spool,
        domain_id=domain_id,
    ):
        raise _capacity_failure("ENGINE_NUMERIC_DOMAIN_EXHAUSTED")
    allocated = 0
    for canonical in spool.numeric_observation_stream(domain_id):
        control.check_cancelled()
        existing = get_numeric_pseudonym(vault, domain_id, canonical)
        if existing is not None:
            spool.drop_numeric_observation(domain_id, canonical)
            continue
        value = parse_canonical_integer_text(canonical)
        candidate = _select_numeric_candidate(
            value,
            domain=domain,
            vault=vault,
            spool=spool,
            domain_id=domain_id,
            occupied=occupied,
            remaining=remaining,
        )
        with vault.transaction():
            fresh = get_numeric_pseudonym(vault, domain_id, canonical)
            if fresh is None:
                add_numeric_key_mapping(
                    vault,
                    domain_id,
                    canonical_integer_text(value),
                    canonical_integer_text(candidate),
                )
            else:  # pragma: no cover - single writer, defensive only
                candidate = parse_canonical_integer_text(fresh)
        spool.drop_numeric_observation(domain_id, canonical)
        occupied += 1
        remaining -= 1
        allocated += 1
    return allocated


def _numeric_residual_feasible(
    *,
    domain: NumericKeyDomain,
    occupied_after: int,
    remaining_after: int,
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
) -> bool:
    """The authoritative P2/P3 Hall conditions with O(1) SQL aggregates.

    Identical semantics to
    :func:`dbf_anonymizer.transforms.numeric_keys.plan_numeric_bijection`
    (cross-checked by randomized equivalence tests): the free token count
    must cover every still-unpersisted original and every original whose own
    value is a still-free domain token must retain a second free token.
    """
    free_after = domain.size - occupied_after
    if free_after < remaining_after:
        return False
    if free_after < 1:
        return False
    if remaining_after > 0 and _spool_value_free_in_domain(
        vault, spool, domain_id, domain
    ):
        if free_after < 2:
            return False
    return True


def _spool_value_free_in_domain(
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
    domain: NumericKeyDomain,
) -> bool:
    """Whether ANY remaining original's own value is a free domain token.

    Bounded streaming: the in-range remaining observations are streamed from
    the spool (SQLite-ordered) and each one is checked against the vault's
    indexed occupancy — no in-RAM set of remaining values is ever built.
    """
    cursor = spool.internal_connection().execute(
        "SELECT CAST(canonical AS INTEGER) FROM numeric_observation "
        "WHERE domain_id = ? AND CAST(canonical AS INTEGER) BETWEEN ? AND ?",
        (domain_id, domain.pseudonym_low, domain.pseudonym_high),
    )
    while True:
        rows = cursor.fetchmany(512)
        if not rows:
            return False
        for (candidate,) in rows:
            if not _numeric_token_occupied(vault, domain_id, int(candidate)):
                return True


def _numeric_token_occupied(
    vault: VaultDatabase, domain_id: str, token: int
) -> bool:
    row = vault._internal_connection().execute(
        "SELECT 1 FROM numeric_key_mappings WHERE domain_id = ? "
        "AND pseudonym_value = ?",
        (domain_id, canonical_integer_text(token)),
    ).fetchone()
    return row is not None


def _numeric_candidate_blocked(
    candidate: int, spool: PassOneSpool, domain_id: str
) -> bool:
    """Whether the candidate is a still-unpersisted original's own value."""
    row = spool.internal_connection().execute(  # noqa: SLF001 - engine SQL
        "SELECT 1 FROM numeric_observation WHERE domain_id = ? AND canonical = ?",
        (domain_id, canonical_integer_text(candidate)),
    ).fetchone()
    return row is not None


def _numeric_occupied_stream(
    vault: VaultDatabase, domain_id: str
) -> Iterator[int]:
    """The occupied pseudonyms of one numeric domain (ascending stream)."""
    cursor = vault._internal_connection().execute(
        "SELECT pseudonym_value FROM numeric_key_mappings WHERE domain_id = ? "
        "ORDER BY CAST(pseudonym_value AS INTEGER)",
        (domain_id,),
    )
    while True:
        rows = cursor.fetchmany(512)
        if not rows:
            return
        for (token,) in rows:
            yield parse_canonical_integer_text(str(token))


def _streaming_jth_free_numeric(
    domain: NumericKeyDomain,
    occupied_stream: Iterator[int],
    j: int,
) -> int:
    """The j-th free token over a SORTED occupied stream (O(1) RAM).

    The same gap-walk rule as
    :func:`dbf_anonymizer.transforms.numeric_keys.jth_free_token`
    (equivalence is cross-checked by randomized tests); values outside the
    domain never consume capacity.
    """
    previous = domain.pseudonym_low - 1
    remaining = j
    for value in occupied_stream:
        if value < domain.pseudonym_low or value > domain.pseudonym_high:
            continue
        gap = value - previous - 1
        if remaining < gap:
            return previous + 1 + remaining
        remaining -= gap
        previous = value
    return previous + 1 + remaining


def _select_numeric_candidate(
    original: int,
    *,
    domain: NumericKeyDomain,
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
    occupied: int,
    remaining: int,
) -> int:
    """One residual-feasibility-proven free numeric token (P3 kernel rules).

    Invariants enforced on EVERY candidate (probe and exact walk alike):
    ``candidate != original``, never an occupied token, never the
    still-unpersisted self-value of another original, and the residual
    problem stays feasible after the commitment (the authoritative kernel,
    re-evaluated with O(1) SQL aggregates).
    """
    free = domain.size - occupied
    if free < 1:
        raise _capacity_failure("ENGINE_NUMERIC_DOMAIN_EXHAUSTED")
    def occupied_stream() -> Iterator[int]:
        return _numeric_occupied_stream(vault, domain_id)

    def _accept(candidate: int) -> bool:
        if candidate == original:
            return False
        if _numeric_candidate_blocked(candidate, spool, domain_id):
            return False
        if not _numeric_residual_feasible(
            domain=domain,
            occupied_after=occupied + 1,
            remaining_after=remaining - 1,
            vault=vault,
            spool=spool,
            domain_id=domain_id,
        ):
            return False
        return True

    for _ in range(NUMERIC_KEY_PROBE_BUDGET):
        candidate = _streaming_jth_free_numeric(
            domain, occupied_stream(), secrets.randbelow(free)
        )
        if _accept(candidate):
            return candidate
    walk_limit = min(free, remaining + 2)
    for index in range(walk_limit):
        candidate = _streaming_jth_free_numeric(
            domain, occupied_stream(), index
        )
        if _accept(candidate):
            return candidate
    raise _capacity_failure("ENGINE_NUMERIC_NO_COMPLETION")




