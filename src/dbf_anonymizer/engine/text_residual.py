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
        fungible = (
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
    tables.
    """
    connection = spool.internal_connection()
    originals, _tokens = _build_residual_graph(
        vault, spool, domain_id=domain_id, alphabet=alphabet, base=base
    )
    for original_idx in range(originals):
        if cancel_probe is not None:
            cancel_probe()
        if _augment(connection, original_idx):
            continue
        raise _mapping_failure("ENGINE_TEXT_RESIDUAL_INFEASIBLE")
    connection.execute("DELETE FROM res_visited")
    connection.execute("DELETE FROM res_dfs")
    connection.commit()
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
            connection.execute(
                "INSERT INTO res_visited (orig_idx) VALUES (?)", (occupant,)
            )
            connection.execute(
                "INSERT INTO res_dfs (depth, orig_idx, vacate_kind, "
                "vacate_length, vacate_token_idx, class_pos, token_pos, "
                "displace_from) VALUES (?, ?, 'token', NULL, ?, 1, ?, -1)",
                (depth + 1, token_idx, token_idx, occupant),
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
    """One CSPRNG free fungible token of *length* (probe, then exact walk)."""
    class_low = token_space(length - 1, base)
    class_size = _class_size(base, length)
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
    return _exact_fungible_walk(
        value, length, alphabet=alphabet, base=base, vault=vault, spool=spool, domain_id=domain_id
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

    The blocked indices (occupied vault tokens plus remaining spool values,
    which include the original's own value) are materialized into a sorted
    SQLite temp table and the gap walk runs over a SQL-ordered stream.
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
    for reserved_value in spool.text_values_of_length(length):
        if is_safe_token(reserved_value, alphabet):
            connection.execute(
                "INSERT OR IGNORE INTO blocked_index (idx) VALUES (?)",
                (token_index(reserved_value, alphabet),),
            )
    connection.commit()

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
    remaining = secrets.randbelow(free_count)
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
