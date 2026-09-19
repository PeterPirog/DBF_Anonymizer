"""The exact bounded text residual assignment solver (REQ-P4-002).

THE production replacement for the pre-P4 in-memory planner fallback: an
EXACT residual assignment computed with disk-backed augmenting paths whose
entire traversal state lives in the protected SQLite spool.  Python holds
NO structure that grows with the number of distinct originals, reserved
tokens or persisted mappings, in ANY reachable branch (near exhaustion,
tight width classes, derangements, reserved self-value chains, mixed
widths, mixed encodings included) — not even the unwind chain of one
augmentation, which is STREAMED from the SQLite DFS stack.

Problem (exactly the P2 planner's model): every remaining original i with
strictest width w(i) must receive a DISTINCT pseudonym token that is

* a free FUNGIBLE token of some length class ``l <= w(i)`` (a class
  capacity: every token of that length that is neither occupied nor a
  reserved self-value), or
* a RESERVED self-value token ``t`` of ANOTHER original (``t != own(i)``,
  ``len(t) <= w(i)``) — an exclusive capacity-1 resource,

while persisted vault mappings stay FIXED and the own-value self-exclusion
holds for every original.  This is a bipartite b-matching; the exact
solution is computed with augmenting paths (the same maximum-matching
theory as the P2 flow planner — the P2
:class:`~dbf_anonymizer.vault.text_allocation.GlobalTextDomainMapping`
remains the authoritative SMALL-CASE TEST ORACLE and equivalence is
cross-checked by the randomized suite).

Exactness: every augmenting path either finds a free resource or reroutes
a displaced original through a visited-guarded alternating chain, so the
solver finds a valid assignment whenever one exists (no false exhausted)
and only commits assignments that satisfy every constraint (no false
feasible).  All traversal state (stack, visited set, assignments,
capacities, the original/token tables) lives in SQLite tables; the
Python-side working set is O(1).  Time may reach O(N^2) SQLite work —
acceptable per the Phase 4 contract; correctness dominates speed.
"""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from typing import Callable, Iterator

from dbf_anonymizer.engine.state import MAX_SQL_BATCH, PassOneSpool
from dbf_anonymizer.errors import ErrorCode, ErrorContext, MappingError
from dbf_anonymizer.transforms.text import (
    is_safe_token,
    token_at,
    token_index,
    token_space,
)
from dbf_anonymizer.vault.store import VaultDatabase

__all__ = ["TextResidualPlan", "solve_text_residual"]


def _mapping_failure(detail_code: str) -> MappingError:
    return MappingError(
        ErrorCode.MAPPING_CAPACITY_EXHAUSTED,
        context=ErrorContext(operation="engine", detail_code=detail_code),
    )


def _class_size(base: int, length: int) -> int:
    size: int = base**length
    return size


#: SQLite INTEGER upper bound: stored fungible capacities are clamped to it.
_SQLITE_INT64_MAX = (1 << 63) - 1


def _stored_capacity(size: int) -> int:
    """Clamp an exact class capacity to the SQLite INTEGER domain.

    A stored capacity only ever competes with ORIGINAL counts (bounded by
    the dataset size, far below 2**63): clamping an astronomically large
    class size (e.g. 36**48 for a wide C field) preserves the matching
    semantics exactly while keeping the value storable in the spool's
    INTEGER column.  The token-selection code paths use the unclamped
    :func:`_class_size` so CSPRNG uniformity is untouched.
    """
    return min(size, _SQLITE_INT64_MAX)


@dataclass(frozen=True)
class TextResidualPlan:
    """The bounded outcome of the exact residual solve (counts only)."""

    originals: int
    reserved_tokens: int
    class_assignments: int
    token_assignments: int


# ---------------------------------------------------------------------------
# residual graph construction (bounded streaming)
# ---------------------------------------------------------------------------
def _build_residual_graph(
    vault: VaultDatabase,
    spool: PassOneSpool,
    *,
    domain_id: str,
    alphabet: str,
    base: int,
) -> tuple[int, int]:
    """Stream the remaining observations into the disk-backed residual graph.

    O(1) Python RAM: the originals, their own reserved tokens and the per
    class fungible capacities are materialized as SQLite rows, never as
    Python containers.
    """
    connection = spool.internal_connection()
    for table in (
        "res_original",
        "res_token",
        "res_cap",
        "res_assign",
        "res_visited",
        "res_dfs",
    ):
        connection.execute(f"DELETE FROM {table}")
    occupied_by_length: dict[int, int] = {}
    for length, count in vault._internal_connection().execute(
        "SELECT logical_byte_length, COUNT(*) FROM text_mappings "
        "WHERE domain_id = ? GROUP BY logical_byte_length",
        (domain_id,),
    ).fetchall():
        occupied_by_length[int(length)] = int(count)

    originals = 0
    tokens = 0
    max_width = 0
    cursor = connection.execute(
        "SELECT canonical, min_width FROM text_observation "
        "ORDER BY min_width ASC, canonical ASC"
    )
    while True:
        rows = cursor.fetchmany(MAX_SQL_BATCH)
        if not rows:
            break
        batch: list[tuple[int, int, bytes, str | None]] = []
        for canonical, width in rows:
            value = bytes(canonical).decode("utf-8")
            if int(width) <= 0:
                raise _mapping_failure("ENGINE_TEXT_WIDTH_INFEASIBLE")
            own_token: str | None = None
            if is_safe_token(value, alphabet):
                length = len(value)
                if length <= int(width) and not _token_occupied(
                    vault, domain_id, value
                ):
                    own_token = value
            batch.append((originals, int(width), canonical, own_token))
            if own_token is not None:
                tokens += 1
            if int(width) > max_width:
                max_width = int(width)
            originals += 1
        connection.executemany(
            "INSERT INTO res_original (idx, width, canonical, own_token) "
            "VALUES (?, ?, ?, ?)",
            batch,
        )
    connection.execute(
        "INSERT INTO res_token (tid, value, length, owner_idx) "
        "SELECT ROW_NUMBER() OVER (ORDER BY idx) - 1, own_token, "
        " length(own_token), idx FROM res_original WHERE own_token IS NOT NULL"
    )
    reserved_by_length: dict[int, int] = {}
    for length, count in connection.execute(
        "SELECT length, COUNT(*) FROM res_token GROUP BY length"
    ).fetchall():
        reserved_by_length[int(length)] = int(count)
    cap_batch: list[tuple[int, int]] = []
    for length in range(1, max_width + 1):
        fungible = _stored_capacity(
            _class_size(base, length)
            - occupied_by_length.get(length, 0)
            - reserved_by_length.get(length, 0)
        )
        cap_batch.append((length, fungible))
    connection.executemany(
        "INSERT INTO res_cap (length, fungible) VALUES (?, ?)", cap_batch
    )
    connection.commit()
    return originals, sum(reserved_by_length.values())


def _token_occupied(vault: VaultDatabase, domain_id: str, token: str) -> bool:
    row = vault._internal_connection().execute(
        "SELECT 1 FROM text_mappings WHERE domain_id = ? AND pseudonym_value = ?",
        (domain_id, token),
    ).fetchone()
    return row is not None


def _cap_of(connection: sqlite3.Connection, length: int) -> int:
    row = connection.execute(
        "SELECT fungible FROM res_cap WHERE length = ?", (length,)
    ).fetchone()
    if row is None:
        return 0
    return int(row[0])


def _assigned_to_class(
    connection: sqlite3.Connection, length: int, after_idx: int
) -> int | None:
    row = connection.execute(
        "SELECT orig_idx FROM res_assign WHERE kind = 'class' AND length = ? "
        "AND orig_idx > ? AND orig_idx NOT IN (SELECT orig_idx FROM res_visited) "
        "ORDER BY orig_idx LIMIT 1",
        (length, after_idx),
    ).fetchone()
    if row is None:
        return None
    return int(row[0])


def _assigned_to_token(connection: sqlite3.Connection, token_idx: int) -> int | None:
    """The current occupant of one reserved token, or ``None``."""
    row = connection.execute(
        "SELECT orig_idx FROM res_assign WHERE kind = 'token' AND token_idx = ?",
        (token_idx,),
    ).fetchone()
    if row is None:
        return None
    return int(row[0])


def _first_free_token_edge(
    connection: sqlite3.Connection,
    orig_idx: int,
    width: int,
    own_token: str | None,
    after_tid: int,
) -> int | None:
    """The FIRST FREE reserved-token edge of *orig_idx* (one indexed probe).

    Same edge filters as :func:`_next_token_edge` plus the assignment
    condition: the token must have NO occupant yet.  A single indexed
    probe instead of walking assigned tokens one query at a time.
    """
    if own_token is None:
        row = connection.execute(
            "SELECT t.tid FROM res_token t WHERE t.length <= ? AND t.tid > ? "
            "AND t.owner_idx != ? AND NOT EXISTS ("
            " SELECT 1 FROM res_assign a WHERE a.kind = 'token'"
            " AND a.token_idx = t.tid) ORDER BY t.tid LIMIT 1",
            (width, after_tid, orig_idx),
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT t.tid FROM res_token t WHERE t.length <= ? AND t.tid > ? "
            "AND t.owner_idx != ? AND t.value != ? AND NOT EXISTS ("
            " SELECT 1 FROM res_assign a WHERE a.kind = 'token'"
            " AND a.token_idx = t.tid) ORDER BY t.tid LIMIT 1",
            (width, after_tid, orig_idx, own_token),
        ).fetchone()
    if row is None:
        return None
    return int(row[0])


def _next_displaceable_token_edge(
    connection: sqlite3.Connection,
    orig_idx: int,
    width: int,
    own_token: str | None,
    after_tid: int,
) -> tuple[int, int] | None:
    """The next ASSIGNED reserved-token edge whose occupant is visitable.

    One indexed probe finds the next token (deterministic tid order,
    same edge filters as :func:`_next_token_edge`) that currently HAS an
    occupant not yet visited in this augmentation — the exact set of
    displacement candidates.  The visited guard lives in the probe, so a
    fully visited augmentation region is skipped in O(log N).
    """
    if own_token is None:
        row = connection.execute(
            "SELECT t.tid, a.orig_idx FROM res_token t JOIN res_assign a "
            "ON a.kind = 'token' AND a.token_idx = t.tid "
            "WHERE t.length <= ? AND t.tid > ? AND t.owner_idx != ? "
            "AND NOT EXISTS (SELECT 1 FROM res_visited v "
            " WHERE v.orig_idx = a.orig_idx) ORDER BY t.tid LIMIT 1",
            (width, after_tid, orig_idx),
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT t.tid, a.orig_idx FROM res_token t JOIN res_assign a "
            "ON a.kind = 'token' AND a.token_idx = t.tid "
            "WHERE t.length <= ? AND t.tid > ? AND t.owner_idx != ? "
            "AND t.value != ? AND NOT EXISTS (SELECT 1 FROM res_visited v "
            " WHERE v.orig_idx = a.orig_idx) ORDER BY t.tid LIMIT 1",
            (width, after_tid, orig_idx, own_token),
        ).fetchone()
    if row is None:
        return None
    return int(row[0]), int(row[1])


def _assign(
    connection: sqlite3.Connection,
    orig_idx: int,
    kind: str,
    length: int | None,
    token_idx: int | None,
) -> None:
    connection.execute(
        "INSERT INTO res_assign (orig_idx, kind, length, token_idx) "
        "VALUES (?, ?, ?, ?) ON CONFLICT(orig_idx) DO UPDATE SET "
        "kind = excluded.kind, length = excluded.length, "
        "token_idx = excluded.token_idx",
        (orig_idx, kind, length, token_idx),
    )


def _unwind(
    connection: sqlite3.Connection,
    found: tuple[str, int | None, int | None],
) -> None:
    """Apply the augmenting chain: the found resource for the head, then
    every displaced original takes the resource its child vacated.

    The chain is STREAMED from the SQLite DFS stack (deepest first) with
    O(1) Python state — the chain length may scale with the visited set,
    so it is never materialized as a Python container.  Capacity
    bookkeeping: every resource along the chain stays occupied (only the
    occupant changes), so the only capacity change is the head's FOUND
    fungible class slot being consumed.
    """
    kind, length, token_idx = found
    if kind == "class":
        assert length is not None
        connection.execute(
            "UPDATE res_cap SET fungible = fungible - 1 WHERE length = ?",
            (int(length),),
        )
    cursor = connection.execute(
        "SELECT orig_idx, vacate_kind, vacate_length, vacate_token_idx "
        "FROM res_dfs ORDER BY depth DESC"
    )
    carrying: tuple[str, int | None, int | None] = (kind, length, token_idx)
    while True:
        row = cursor.fetchone()
        if row is None:
            break
        _assign(connection, int(row[0]), carrying[0], carrying[1], carrying[2])
        carrying = (
            str(row[1]),
            None if row[2] is None else int(row[2]),
            None if row[3] is None else int(row[3]),
        )


def solve_text_residual(
    vault: VaultDatabase,
    spool: PassOneSpool,
    *,
    domain_id: str,
    alphabet: str,
    base: int,
    cancel_probe: Callable[[], None] | None = None,
) -> TextResidualPlan:
    """The EXACT bounded residual assignment (disk-backed augmenting paths).

    Semantically equivalent to the authoritative P2 exact planner (the
    randomized oracle-equivalence suite cross-checks feasibility verdicts
    and constraint satisfaction).  Python memory is O(1) in every reachable
    branch: the originals, the reserved tokens, the capacities, the visited
    set, the DFS stack and the assignment all live in the spool's SQLite
    tables.  Before returning, the solved assignment is VALIDATED
    structurally with bounded SQL aggregates (the matching invariants are
    enforced by the database too — see ``res_assign_token_once``); any
    corruption fails closed with a stable, value-free detail code.
    """
    connection = spool.internal_connection()
    originals, _tokens = _build_residual_graph(
        vault, spool, domain_id=domain_id, alphabet=alphabet, base=base
    )
    try:
        for original_idx in range(originals):
            if cancel_probe is not None:
                cancel_probe()
            if _augment(connection, original_idx):
                continue
            raise _mapping_failure("ENGINE_TEXT_RESIDUAL_INFEASIBLE")
    except sqlite3.IntegrityError as exc:
        # The database-enforced matching invariant fired (e.g. a reserved
        # token assigned twice): the solved state is corrupt — fail closed.
        raise _mapping_failure("ENGINE_TEXT_RESIDUAL_CORRUPT") from exc
    connection.execute("DELETE FROM res_visited")
    connection.execute("DELETE FROM res_dfs")
    connection.commit()
    _validate_residual_assignment(
        connection, vault=vault, domain_id=domain_id, originals=originals, base=base
    )
    class_assignments = int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign WHERE kind = 'class'"
        ).fetchone()[0]
    )
    token_assignments = int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign WHERE kind = 'token'"
        ).fetchone()[0]
    )
    return TextResidualPlan(
        originals=originals,
        reserved_tokens=int(
            connection.execute("SELECT COUNT(*) FROM res_token").fetchone()[0]
        ),
        class_assignments=class_assignments,
        token_assignments=token_assignments,
    )


def _validate_residual_assignment(
    connection: sqlite3.Connection,
    *,
    vault: VaultDatabase,
    domain_id: str,
    originals: int,
    base: int,
) -> None:
    """The post-solve matching-invariant validator (bounded SQL aggregates).

    Proven structurally, before any materialization, over the SOLVED
    assignment tables:

    * one assignment per original, every original assigned exactly once;
    * every reserved-token resource assigned at most once (the partial
      UNIQUE index enforces it at write time; the validator re-proves it);
    * class assignments never exceed the class capacity the solver
      consumed (the remaining fungible bookkeeping must reconcile exactly);
    * a named token assignment is never the original's own reserved value;
    * every assigned resource fits the original's strictest width;
    * no dangling token id and no unknown assignment kind.

    Only per-length aggregate rows (bounded by the maximum field width) and
    scalar counts are materialized — never assignments, tokens or values.
    Any violation is a stable, privacy-safe typed refusal.
    """
    _corrupt = _mapping_failure("ENGINE_TEXT_RESIDUAL_CORRUPT")
    total = int(
        connection.execute("SELECT COUNT(*) FROM res_assign").fetchone()[0]
    )
    if total != originals:
        raise _corrupt
    distinct_originals = int(
        connection.execute(
            "SELECT COUNT(DISTINCT orig_idx) FROM res_assign"
        ).fetchone()[0]
    )
    if distinct_originals != originals:
        raise _corrupt
    if int(
        connection.execute(
            "SELECT COUNT(*) FROM res_original WHERE idx >= ?", (originals,)
        ).fetchone()[0]
    ) or int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign WHERE orig_idx >= ?",
            (originals,),
        ).fetchone()[0]
    ):
        raise _corrupt
    unknown_kinds = int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign "
            "WHERE kind NOT IN ('class','token')"
        ).fetchone()[0]
    )
    if unknown_kinds:
        raise _corrupt
    malformed = int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign WHERE "
            "(kind = 'class' AND (length IS NULL OR token_idx IS NOT NULL))"
            " OR (kind = 'token' AND (token_idx IS NULL OR length IS NOT NULL))"
        ).fetchone()[0]
    )
    if malformed:
        raise _corrupt
    dangling = int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign a WHERE a.kind = 'token' "
            "AND NOT EXISTS ("
            " SELECT 1 FROM res_token t WHERE t.tid = a.token_idx)"
        ).fetchone()[0]
    )
    if dangling:
        raise _corrupt
    duplicate_tokens = int(
        connection.execute(
            "SELECT COUNT(*) FROM (SELECT token_idx FROM res_assign "
            "WHERE kind = 'token' GROUP BY token_idx "
            "HAVING COUNT(*) > 1)"
        ).fetchone()[0]
    )
    if duplicate_tokens:
        raise _corrupt
    self_assigned = int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign a JOIN res_token t "
            "ON t.tid = a.token_idx JOIN res_original o ON o.idx = a.orig_idx "
            "WHERE a.kind = 'token' AND (t.owner_idx = a.orig_idx "
            "OR t.value = o.own_token)"
        ).fetchone()[0]
    )
    if self_assigned:
        raise _corrupt
    too_long = int(
        connection.execute(
            "SELECT COUNT(*) FROM res_assign a JOIN res_original o "
            "ON o.idx = a.orig_idx WHERE "
            "(a.kind = 'token' AND EXISTS ("
            "  SELECT 1 FROM res_token t WHERE t.tid = a.token_idx "
            "  AND t.length > o.width))"
            " OR (a.kind = 'class' AND a.length > o.width)"
        ).fetchone()[0]
    )
    if too_long:
        raise _corrupt
    occupied_by_length = dict(
        (int(row[0]), int(row[1]))
        for row in vault._internal_connection().execute(
            "SELECT logical_byte_length, COUNT(*) FROM text_mappings "
            "WHERE domain_id = ? GROUP BY logical_byte_length",
            (domain_id,),
        ).fetchall()
    )
    capacity_by_length = {
        int(row[0]): int(row[1])
        for row in connection.execute(
            "SELECT length, fungible FROM res_cap"
        ).fetchall()
    }
    for length, fungible_remaining in capacity_by_length.items():
        reserved = int(
            connection.execute(
                "SELECT COUNT(*) FROM res_token WHERE length = ?",
                (int(length),),
            ).fetchone()[0]
        )
        class_taken = int(
            connection.execute(
                "SELECT COUNT(*) FROM res_assign WHERE kind = 'class' "
                "AND length = ?",
                (int(length),),
            ).fetchone()[0]
        )
        expected_remaining = _stored_capacity(
            _class_size(base, int(length))
            - occupied_by_length.get(int(length), 0)
            - reserved
        ) - class_taken
        if int(fungible_remaining) != expected_remaining or expected_remaining < 0:
            raise _corrupt


# ---------------------------------------------------------------------------
# the iterative augmenting-path DFS (all state in SQLite)
# ---------------------------------------------------------------------------
def _augment(connection: sqlite3.Connection, v0: int) -> bool:
    """One exact augmenting path for *v0* (O(1) Python RAM, SQLite state).

    The DFS stack (``res_dfs``) holds, per depth, the displaced original,
    the resource it vacates for its parent, its class-edge cursor, its
    token-edge cursor and the displacement watermark of the class edge
    under exploration.  The visited table guards every original to at most
    one stack appearance per augmentation, so the search is finite.
    """
    connection.execute("DELETE FROM res_visited")
    connection.execute("DELETE FROM res_dfs")
    connection.execute(
        "INSERT INTO res_dfs (depth, orig_idx, vacate_kind, vacate_length, "
        "vacate_token_idx, class_pos, token_pos, displace_from) "
        "VALUES (0, ?, NULL, NULL, NULL, 1, -1, -1)",
        (v0,),
    )
    connection.execute("INSERT INTO res_visited (orig_idx) VALUES (?)", (v0,))
    while True:
        head = connection.execute(
            "SELECT depth, orig_idx, class_pos, token_pos, displace_from "
            "FROM res_dfs ORDER BY depth DESC LIMIT 1"
        ).fetchone()
        if head is None:  # pragma: no cover - the stack never empties first
            return False
        depth, orig_idx, class_pos, token_pos, displace_from = (
            int(head[0]),
            int(head[1]),
            int(head[2]),
            int(head[3]),
            int(head[4]),
        )
        width_row = connection.execute(
            "SELECT width, own_token FROM res_original WHERE idx = ?",
            (orig_idx,),
        ).fetchone()
        if width_row is None:
            # A frame whose orig_idx is not a real original id (e.g. a
            # resource id used where an original id is required) is a
            # structural corruption of the search — fail closed.
            raise _mapping_failure("ENGINE_TEXT_RESIDUAL_CORRUPT")
        width = int(width_row[0])
        own_token = width_row[1]

        advanced = False
        # -- fungible class edges (1..width) --------------------------------
        while class_pos <= width:
            fungible = _cap_of(connection, class_pos)
            if fungible > 0:
                _unwind(connection, ("class", class_pos, None))
                connection.commit()
                return True
            displaced = _assigned_to_class(connection, class_pos, displace_from)
            if displaced is not None:
                connection.execute(
                    "UPDATE res_dfs SET displace_from = ? WHERE depth = ?",
                    (displaced, depth),
                )
                connection.execute(
                    "INSERT INTO res_dfs (depth, orig_idx, vacate_kind, "
                    "vacate_length, vacate_token_idx, class_pos, token_pos, "
                    "displace_from) VALUES (?, ?, 'class', ?, NULL, 1, -1, -1)",
                    (depth + 1, displaced, class_pos),
                )
                connection.execute(
                    "INSERT OR IGNORE INTO res_visited (orig_idx) VALUES (?)",
                    (displaced,),
                )
                advanced = True
                break
            class_pos += 1
            displace_from = -1
            connection.execute(
                "UPDATE res_dfs SET class_pos = ?, displace_from = -1 "
                "WHERE depth = ?",
                (class_pos, depth),
            )
        if advanced:
            continue
        # -- reserved-token edges (deterministic tid order) -------------------
        while True:
            # FAST PATH: the first FREE reserved token edge is found by ONE
            # indexed probe — the common case that keeps the whole solve
            # near-linear even when every original holds a reserved token.
            free_tid = _first_free_token_edge(
                connection, orig_idx, width, own_token, token_pos
            )
            if free_tid is not None:
                _unwind(connection, ("token", None, free_tid))
                connection.commit()
                return True
            # DISPLACEMENT PATH: the next assigned token whose occupant was
            # not visited in this augmentation — ONE indexed probe.
            candidate = _next_displaceable_token_edge(
                connection, orig_idx, width, own_token, token_pos
            )
            if candidate is None:
                break  # token edges exhausted
            token_idx, occupant = candidate
            token_pos = token_idx
            connection.execute(
                "UPDATE res_dfs SET token_pos = ? WHERE depth = ?",
                (token_idx, depth),
            )
            # The child frame represents the displaced OCCUPANT ORIGINAL —
            # NEVER the resource id.  ``res_token.tid`` and
            # ``res_original.idx`` are DIFFERENT namespaces: the occupant
            # currently holding ``token_idx`` must find a new resource, so
            # the frame's ``orig_idx`` is the occupant and the frame's
            # ``vacate_token_idx`` is the resource it will vacate for its
            # parent.  Using token_idx as orig_idx here would search for a
            # resource of a NONEXISTENT/WRONG original (resource ids are
            # not original ids).
            connection.execute(
                "INSERT INTO res_visited (orig_idx) VALUES (?)", (occupant,)
            )
            connection.execute(
                "INSERT INTO res_dfs (depth, orig_idx, vacate_kind, "
                "vacate_length, vacate_token_idx, class_pos, token_pos, "
                "displace_from) VALUES (?, ?, 'token', NULL, ?, 1, -1, -1)",
                (depth + 1, occupant, token_idx),
            )
            advanced = True
            break
        if advanced:
            continue
        # -- exhausted: pop the head, the parent continues its enumeration ----
        connection.execute("DELETE FROM res_dfs WHERE depth = ?", (depth,))
        connection.commit()


# ---------------------------------------------------------------------------
# CSPRNG materialization of the exact assignment
# ---------------------------------------------------------------------------
_TEXT_PROBE_BUDGET = 64
_TEXT_COMPLETION_WALK_LIMIT = 4096


def _randbelow(bound: int) -> int:
    """The OS CSPRNG (the ONLY production randomness source).

    A private seam so behavioral tests can inject deterministic sequences
    where exact choices matter; production always uses the OS CSPRNG.
    """
    return secrets.randbelow(bound)


def materialize_text_assignment(
    vault: VaultDatabase,
    spool: PassOneSpool,
    *,
    domain_id: str,
    alphabet: str,
    base: int,
) -> Iterator[tuple[str, str, int]]:
    """Stream (original, token, encoded length) from the solved assignment.

    The assignment table is streamed in deterministic original order; a
    fungible class slot receives a CSPRNG-chosen free token of that class
    (bounded probe phase, then the exact j-th-free walk over a SQL-ordered
    blocked index stream); a named reserved assignment receives its exact
    token.  Nothing is sequence-derived and nothing is derived from the
    original value.

    RESOURCE-PARTITION INVARIANCE: the free fungible universe during
    materialization is EXACTLY the partition ``solve_text_residual`` solved
    with — the token universe minus the persisted occupied tokens minus
    EVERY ``res_token`` value.  The solved residual tables are immutable
    for the whole materialization (they are dropped only afterwards), so a
    named reserved resource can never be stolen by a later class
    allocation, even though the corresponding observations are dropped
    from the mutable ``text_observation`` table as their mappings commit.
    """
    connection = spool.internal_connection()
    cursor = connection.execute(
        "SELECT o.canonical, o.width, a.kind, a.length, a.token_idx "
        "FROM res_original o JOIN res_assign a ON a.orig_idx = o.idx "
        "ORDER BY o.idx ASC"
    )
    while True:
        rows = cursor.fetchmany(MAX_SQL_BATCH)
        if not rows:
            return
        for canonical, _width, kind, length, token_idx in rows:
            value = bytes(canonical).decode("utf-8")
            if kind == "token":
                token_row = connection.execute(
                    "SELECT value FROM res_token WHERE tid = ?", (int(token_idx),)
                ).fetchone()
                if token_row is None:  # pragma: no cover - solver invariant
                    raise _mapping_failure("ENGINE_TEXT_RESIDUAL_BROKEN")
                yield value, str(token_row[0]), len(str(token_row[0]))
                continue
            length_int = int(length)
            candidate = _select_fungible_token(
                value,
                length_int,
                alphabet=alphabet,
                base=base,
                vault=vault,
                spool=spool,
                domain_id=domain_id,
            )
            yield value, candidate, len(candidate)


def _reserved_token_blocked(connection: sqlite3.Connection, candidate: str) -> bool:
    """Whether *candidate* is a RESERVED resource of the solved graph.

    The check reads the IMMUTABLE solved residual graph (``res_token``),
    never the mutable observation table: an original's self-value stays
    excluded from the fungible pool from the moment the assignment is
    solved until every assignment is materialized, regardless of when its
    own observation is dropped.
    """
    row = connection.execute(
        "SELECT 1 FROM res_token WHERE value = ?", (candidate,)
    ).fetchone()
    return row is not None


def _select_fungible_token(
    value: str,
    length: int,
    *,
    alphabet: str,
    base: int,
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
) -> str:
    """One CSPRNG free fungible token of *length* (probe, then exact walk).

    Both the probe and the exact walk exclude exactly the solved resource
    partition: persisted occupied tokens plus EVERY ``res_token`` value.
    """
    class_low = token_space(length - 1, base)
    class_size = _class_size(base, length)
    connection = spool.internal_connection()
    for _ in range(_TEXT_PROBE_BUDGET):
        candidate = token_at(
            class_low + _randbelow(class_size), length, alphabet
        )
        if candidate == value:
            continue
        if _token_occupied(vault, domain_id, candidate):
            continue
        if _reserved_token_blocked(connection, candidate):
            continue
        return candidate
    return _exact_fungible_walk(
        value,
        length,
        alphabet=alphabet,
        base=base,
        vault=vault,
        spool=spool,
        domain_id=domain_id,
    )


def _exact_fungible_walk(
    value: str,
    length: int,
    *,
    alphabet: str,
    base: int,
    vault: VaultDatabase,
    spool: PassOneSpool,
    domain_id: str,
) -> str:
    """The exact j-th free fungible token of the class (O(1) Python RAM).

    The blocked indices — persisted occupied tokens PLUS every ``res_token``
    value of the class (the immutable solved reserved partition) — are
    materialized into a sorted SQLite temp table and the gap walk runs over
    a SQL-ordered stream.  ``j`` comes from the OS CSPRNG exactly like the
    probe phase, so nothing is sequence-derived and nothing is derived from
    the original value.
    """
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
    reserved_cursor = connection.execute(
        "SELECT value FROM res_token WHERE length = ?", (int(length),)
    )
    while True:
        reserved_rows = reserved_cursor.fetchmany(MAX_SQL_BATCH)
        if not reserved_rows:
            break
        for (reserved_value,) in reserved_rows:
            connection.execute(
                "INSERT OR IGNORE INTO blocked_index (idx) VALUES (?)",
                (token_index(str(reserved_value), alphabet),),
            )
    connection.commit()

    def sorted_indices() -> Iterator[int]:
        index_cursor = connection.execute(
            "SELECT idx FROM blocked_index ORDER BY idx"
        )
        while True:
            index_rows = index_cursor.fetchmany(MAX_SQL_BATCH)
            if not index_rows:
                return
            for (index,) in index_rows:
                yield int(index)

    blocked_count = int(
        connection.execute("SELECT COUNT(*) FROM blocked_index").fetchone()[0]
    )
    free_count = _class_size(base, length) - blocked_count
    previous = class_low - 1
    remaining = _randbelow(free_count)
    for index in sorted_indices():
        gap = index - previous - 1
        if remaining < gap:
            chosen = previous + 1 + remaining
            break
        remaining -= gap
        previous = index
    else:
        chosen = previous + 1 + remaining
    connection.execute("DELETE FROM blocked_index")
    connection.commit()
    return token_at(chosen, length, alphabet)


def _supply_of_class(base: int, length: int) -> int:
    size: int = base**length
    return size


def _occupied_tokens_of_length(
    vault: VaultDatabase, domain_id: str, length: int
) -> Iterator[str]:
    cursor = vault._internal_connection().execute(
        "SELECT pseudonym_value FROM text_mappings "
        "WHERE domain_id = ? AND logical_byte_length = ?",
        (domain_id, length),
    )
    while True:
        rows = cursor.fetchmany(MAX_SQL_BATCH)
        if not rows:
            return
        for (token,) in rows:
            yield str(token)
