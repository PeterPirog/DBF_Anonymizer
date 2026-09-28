"""REQ-P7-007 — deterministic property and adversarial evidence.

This module closes the specific adversarial/property gaps that the
existing P1/P2/P4/P5 suites do not objectively cover (see the delivery
gap matrix).  It does NOT duplicate evidence that is already objectively
sufficient (mapping-allocation unit properties, publication fault points,
transfer-bundle smuggling corpora) and does NOT duplicate dbfbridge
parser fuzzing: DBF/FPT parsing stays owned by the public ``dbfbridge``
boundary — the delegated-error tests use ONE representative synthetic
corruption plus controlled dependency fault injection at the public
``dbfbridge.iter_records``/``dbfbridge.write_table`` attributes only.

Property strategy (no new dependency): every randomized scenario is
driven by a test-local deterministic LCG generator (the same test-side
pattern as ``test_p2_global_adversarial.py``), so every failure is a
usable reproducer: the printed seed plus scenario fully reconstruct the
case.  No wall-clock, no network, no test-order or cross-test state,
no persistent databases outside the task-owned ``tmp_path`` trees.

Categories covered here (REQ-P7-007):
1. mapping collisions / capacity — seeded end-to-end bijectivity,
   transformed-never-equals-original, exact capacity completion and
   typed fail-closed exhaustion;
2. malformed policies — seeded mutation matrix: every mutation is
   either merged into a still-valid policy (deterministic fingerprints)
   or typed-rejected with a source/vault/staging-residue-free refusal;
3. hostile paths — resolved-alias/normalization/case behavior, hostile
   source names and strict synthetic-root containment;
4. corrupt SQLite — deterministic single-byte corruption sweep: every
   flip is either typed ``VaultError`` or leaves a fully
   integrity-verified vault; raw/untyped failures and canary leakage
   are forbidden;
5. malformed DBF/FPT delegated errors — execution-stage delegation
   through the public dbfbridge boundary (a real corrupt-FPT fixture and
   injected structured failures), machine codes preserved, no output;
6. cancellation — deterministic PASS1 scan cancellation with bounded
   response, no completed claim and a safe immediate retry;
8. crash residue — an injected Direct Write boundary fault never
   publishes and the same-vault retry stays idempotent.

Concurrency (category 7) is exercised end-to-end by the seeded
multi-worker property (the category-1 evidence runs with ``workers=3``);
transfer-bundle smuggling (category 9) keeps its authoritative existing
evidence in ``tests/test_p5_transfer_bundle.py`` (no duplication).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import dbfbridge
import pytest

import dbf_anonymizer as public
from dbf_anonymizer.transforms.text import SAFE_TEXT_ALPHABET, is_safe_token
from dbf_anonymizer.vault.store import VaultDatabase
from tests.support.memo_tables import field as memo_field
from tests.support.memo_tables import write_memo_table
from tests.support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table_with_deleted,
)

CANARY_ORIGINAL = "P7-007-CANARY-ORIGINAL-3F2A"
CANARY_PAYLOAD = "P7-007-CANARY-PAYLOAD"
STAGING_PATTERN = ".dbf-anonymizer-*"

#: The width-1 token space: every single-character safe token.
WIDTH_ONE_TOKEN_CAPACITY = len(SAFE_TEXT_ALPHABET)
#: One char beyond the width-1 token space, none of them a safe token.
NON_TOKEN_CHARACTERS = tuple("abcdefghijklmnopqrstuvwxyz?!.,+~=&%;$")

DBFBRIDGE_MACHINE_CODES = frozenset(error_code.value for error_code in dbfbridge.ErrorCode)


# ---------------------------------------------------------------------------
# Deterministic test-side randomness (never production code)
# ---------------------------------------------------------------------------


class _Lcg:
    """Tiny deterministic test-side generator (global-adversarial family)."""

    def __init__(self, seed: int) -> None:
        self._state = (seed & ((1 << 64) - 1)) or 0x9E3779B97F4A7C15

    def next(self) -> int:
        self._state = (self._state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        return self._state

    def below(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        return self.next() % bound


# ---------------------------------------------------------------------------
# Deterministic synthetic datasets (public dbfbridge writer only)
# ---------------------------------------------------------------------------


def _seeded_source_values(seed: int) -> tuple[tuple[str, ...], ...]:
    """Deterministic overlapping C-field vocabularies per table."""
    lcg = _Lcg(seed)
    bases = (
        "ALPHA-VALUE",
        "beta-value",
        "Gamma VALUE",
        "TRAILING ",
        "Zazolc gesla",
        "dup-VALUE",
        "MiXeD CaSe",
        "same-token",
    )
    tables: list[tuple[str, ...]] = []
    for table in range(2):
        records: list[str] = []
        for record in range(5 + lcg.below(4)):
            variant = lcg.below(5)
            base = bases[(record + seed + table) % len(bases)]
            if variant == 0:
                records.append("")  # empty: never creates a mapping row
            elif variant == 1:
                records.append("  ")  # whitespace-only stays distinct
            else:
                records.append(base)
        # The same original deliberately appears in BOTH tables.
        records[0] = "ALPHA-VALUE"
        tables.append(tuple(records))
    return tuple(tables)


def _write_seeded_dataset(
    source: Path,
    text_tables: tuple[tuple[str, ...], ...],
) -> None:
    fields = (
        numeric_field("CODE", "C", 12, flags=NULLABLE_FLAG),
        numeric_field("NOTE", "M", 4, flags=NULLABLE_FLAG),
        numeric_field("AMOUNT", "I", 4, flags=NULLABLE_FLAG),
    )
    for relative, codes in zip(("alpha/data.dbf", "beta/data.dbf"), text_tables):
        write_numeric_table_with_deleted(
            source,
            relative,
            fields,
            [
                (
                    {
                        "CODE": code,
                        "NOTE": "" if code == "" else f"MEMO-{relative}-{index}",
                        "AMOUNT": index,
                    },
                    False,
                )
                for index, code in enumerate(codes)
            ],
        )


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _logical_tree(root: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    result: dict[str, tuple[tuple[object, ...], ...]] = {}
    for path in sorted(root.rglob("*.dbf")):
        result[path.relative_to(root).as_posix()] = tuple(
            (
                record.physical_index,
                record.deleted,
                tuple(sorted(record.values.items())),
            )
            for record in dbfbridge.iter_records(path, include_deleted=True, memo="inline")
        )
    return result


def _text_mapping_rows(plan: Any, vault_path: Path) -> tuple[tuple[str, str], ...]:
    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
    ) as vault:
        connection = vault._internal_connection()
        return tuple(
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                "SELECT original_value, pseudonym_value FROM text_mappings ORDER BY original_value"
            )
        )


def _mapping_row_count(plan: Any, vault_path: Path) -> int:
    with VaultDatabase.open(
        vault_path,
        expected_source_fingerprint=plan.dataset.source_fingerprint,
        expected_policy_fingerprint=plan.policy.policy_fingerprint,
        expected_relationship_fingerprint=plan.relationships.relationship_fingerprint,
    ) as vault:
        connection = vault._internal_connection()
        return int(connection.execute("SELECT COUNT(*) FROM text_mappings").fetchone()[0])


def _assert_no_publication_residue(tmp_path: Path, output: Path, vault: Path) -> None:
    """No output dataset and no staging residue.

    ``.dbf-anonymizer-*.lock`` siblings are the documented stable
    destination-lock files whose mere existence is NOT ownership evidence;
    they are bounded machine-named, value-free artifacts and are never
    treated here as publication residue.
    """
    assert not output.exists()
    assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging*"))


def _error_payload_is_privacy_safe(error: BaseException, *forbidden: str) -> None:
    to_dict = getattr(error, "to_dict", None)
    payload = json.dumps(to_dict() if callable(to_dict) else {"repr": repr(error)}, sort_keys=True)
    for secret in forbidden:
        assert secret not in payload
    assert "C:\\" not in payload
    assert "D:\\" not in payload


def _assert_contained(root: Path, *declared_roots: Path) -> None:
    """Every created file stays inside the declared synthetic roots.

    The bounded value-free ``.dbf-anonymizer-*.lock`` destination-lock
    siblings are owned artifacts (documented contract) and are allowed.
    """
    resolved_roots = [os.path.realpath(declared) for declared in declared_roots]
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name.startswith(".dbf-anonymizer-") and path.name.endswith(".lock"):
            continue
        resolved = os.path.realpath(path)
        assert any(
            resolved == boundary or resolved.startswith(boundary + os.sep)
            for boundary in resolved_roots
        ), f"artifact escaped the synthetic roots: {path}"


def _assert_platform_safe_error(error: BaseException) -> None:
    """A typed public refusal: registry-controlled code, no raw details."""
    assert isinstance(error, public.AnonymizerError)
    _error_payload_is_privacy_safe(error)


# ---------------------------------------------------------------------------
# Category 1 + 7 — seeded end-to-end mapping/capacity properties
# ---------------------------------------------------------------------------


def test_seeded_mapping_bijectivity_self_exclusion_and_recovery_roundtrip(
    tmp_path: Path,
) -> None:
    """For every seed the full pipeline keeps the global mapping bijective,
    never aliases an original onto itself and round-trips recovery exactly
    (multi-worker execution over overlapping randomized vocabularies)."""
    for seed in range(6):
        text_tables = _seeded_source_values(seed)
        root = tmp_path / f"seed-{seed}"
        source = root / "source"
        output = root / "output"
        vault = root / "vault" / "dictionary.sqlite3"
        _write_seeded_dataset(source, text_tables)
        source_before = _hash_tree(source)

        plan = public.build_plan(source, output, vault)
        assert public.preflight(plan).ready is True
        result = public.pseudonymize(plan, workers=3)
        assert public.verify_dataset(result, source=source, vault=vault).status is (
            public.VerificationStatus.PASS
        )

        rows = _text_mapping_rows(plan, vault)
        assert rows, f"seed {seed}: no global text mappings were persisted"
        originals = tuple(original for original, _pseudonym in rows)
        pseudonyms = tuple(pseudonym for _original, pseudonym in rows)
        assert len(set(originals)) == len(originals)
        assert len(set(pseudonyms)) == len(pseudonyms)
        assert len(set(pseudonyms)) == len(set(originals))
        for original, pseudonym in rows:
            assert original != pseudonym, f"seed {seed}: silently unchanged original"
            assert is_safe_token(pseudonym, SAFE_TEXT_ALPHABET), pseudonym
            assert len(pseudonym.encode("cp1250")) <= 12, pseudonym

        # End-to-end per-record property: a transformed non-empty sensitive
        # value (text or memo payload) is never silently its own original.
        source_records = _logical_tree(source)
        output_records = _logical_tree(output)
        assert tuple(sorted(source_records)) == tuple(sorted(output_records))
        for relative in source_records:
            for source_record, output_record in zip(
                source_records[relative], output_records[relative]
            ):
                original_values = dict(source_record[2])
                output_values = dict(output_record[2])
                original_code = original_values["CODE"]
                output_code = output_values["CODE"]
                if original_code:
                    assert output_code != original_code
                original_note = original_values["NOTE"]
                output_note = output_values["NOTE"]
                if original_note:
                    assert output_note != original_note
        assert _hash_tree(source) == source_before

        # Protected recovery restores the canonical dataset exactly.
        recovery = public.recover(pseudonymized=output, vault=vault, output=root / "recovered")
        assert recovery.canonical_verified is True
        assert _logical_tree(root / "recovered") == _logical_tree(source)


def test_capacity_boundary_exact_completion_and_typed_exhaustion(tmp_path: Path) -> None:
    """With width 1 the exact token capacity (36 distinct originals)
    completes end to end, while one value beyond the exact boundary fails
    closed with the typed capacity refusal and creates neither output nor
    vault nor staging residue."""
    non_token_characters = tuple("abcdefghijklmnopqrstuvwxyz?!.,+~=&%;$")
    assert WIDTH_ONE_TOKEN_CAPACITY == 36
    assert len(non_token_characters) == 37
    assert all(
        len(character.encode("cp1250")) == 1 and not is_safe_token(character, SAFE_TEXT_ALPHABET)
        for character in non_token_characters
    )

    for size, feasible in ((36, True), (37, False)):
        root = tmp_path / f"capacity-{size}"
        source = root / "source"
        output = root / "output"
        vault = root / "vault" / "dictionary.sqlite3"
        fields = (
            numeric_field("CODE", "C", 1, flags=NULLABLE_FLAG),
            numeric_field("AMOUNT", "I", 4),
        )
        write_numeric_table_with_deleted(
            source,
            "one/data.dbf",
            fields,
            [
                ({"CODE": non_token_characters[index], "AMOUNT": index}, False)
                for index in range(size)
            ],
        )
        source_before = _hash_tree(source)
        plan = public.build_plan(source, output, vault)

        if feasible:
            assert public.preflight(plan).ready is True
            result = public.pseudonymize(plan)
            assert public.verify_dataset(result, source=source, vault=vault).status is (
                public.VerificationStatus.PASS
            )
            rows = _text_mapping_rows(plan, vault)
            assert len(rows) == size
            assert len({pseudonym for _original, pseudonym in rows}) == size
            for original, pseudonym in rows:
                assert original != pseudonym
                assert is_safe_token(pseudonym, SAFE_TEXT_ALPHABET)
                assert len(pseudonym) == 1
            output_codes = [
                dict(record[2])["CODE"] for record in _logical_tree(output)["one/data.dbf"]
            ]
            for original, transformed in zip(non_token_characters[:size], output_codes):
                assert transformed != original
        else:
            check = public.preflight(plan)
            assert check.ready is False
            assert any(str(code) == "PSEUDONYM_CAPACITY_INSUFFICIENT" for code in check.error_codes)
            with pytest.raises(public.PublicationError) as caught:
                public.pseudonymize(plan)
            assert caught.value.context.detail_code == "PREFLIGHT_REJECTED"
            _error_payload_is_privacy_safe(caught.value)
            assert not output.exists()
            assert not vault.exists()
            assert not tuple(root.glob(".dbf-anonymizer-*.staging*"))
            assert _hash_tree(source) == source_before


# ---------------------------------------------------------------------------
# Category 2 — malformed policy mutation matrix
# ---------------------------------------------------------------------------


def _base_policy() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "profile": "SAFE_TRANSFER",
        "text": {"default_action": "PSEUDONYMIZE_REVERSIBLE", "domain": "GLOBAL_TEXT"},
        "memo": {"text": "MASK_REVERSIBLE", "binary": "MASK_REVERSIBLE"},
        "temporal": {"date": "SHIFT_REVERSIBLE", "datetime": "SHIFT_REVERSIBLE"},
        "numeric": {"default_action": "KEEP"},
        "relationships": {"metadata_file": None},
        "indexes": {"profile": "DATA_ONLY"},
    }


def _policy_paths(policy: dict[str, Any]) -> list[list[str]]:
    """Every key path of the policy (nodes and leaves)."""
    paths: list[list[str]] = []
    stack: list[tuple[dict[str, Any], list[str]]] = [(policy, [])]
    while stack:
        node, prefix = stack.pop()
        for key, value in node.items():
            path = [*prefix, key]
            paths.append(path)
            if isinstance(value, dict):
                stack.append((value, path))
    return paths


def _mutated_policy(seed: int) -> tuple[dict[str, Any], str]:
    """One deterministic policy mutation (delete/type/enum/unknown)."""
    lcg = _Lcg(0xC0FFEE + seed)
    policy = _base_policy()
    paths = _policy_paths(policy)
    path = paths[lcg.below(len(paths))]
    mutation = lcg.below(4)
    canary = f"CANARY-{seed:02d}"
    node: dict[str, Any] = policy
    for key in path[:-1]:
        value = node[key]
        if not isinstance(value, dict):
            break
        node = value
    key = path[-1]
    if mutation == 0:
        node.pop(key, None)
    elif mutation == 1:
        node[key] = (2, ["junk"], "junk", True)[lcg.below(4)]
    elif mutation == 2:
        node[key] = f"MUTATED_{canary}"
    else:
        node[f"unknown_{canary}"] = 1
    return policy, canary


def test_seeded_policy_mutation_matrix_is_typed_and_residue_free(
    tmp_path: Path,
) -> None:
    """Every deterministic policy mutation is either merged into a still
    valid policy (deterministic fingerprints) or typed-rejected; a typed
    rejection leaves the source untouched and creates no output, vault,
    staging or lock residue — and never echoes the hostile value."""
    source = tmp_path / "source"
    _write_seeded_dataset(source, _seeded_source_values(0))
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    source_before = _hash_tree(source)

    for seed in range(16):
        policy, canary = _mutated_policy(seed)
        try:
            plan = public.build_plan(source, output, vault, policy=policy)
        except public.PolicyError as error:
            assert error.code.value in {"POLICY_INVALID", "POLICY_UNSUPPORTED"}
            payload = json.dumps(error.to_dict(), sort_keys=True)
            assert canary not in payload
            assert "C:\\" not in payload and "D:\\" not in payload
        except (TypeError, ValueError, KeyError, AttributeError) as unexpected:
            pytest.fail(
                f"seed {seed}: malformed policy produced an untyped failure: "
                f"{type(unexpected).__name__}"
            )
        else:
            # Still-valid merges keep deterministic fingerprints.
            rebuilt = public.build_plan(source, output, vault, policy=policy)
            assert rebuilt.policy.policy_fingerprint == plan.policy.policy_fingerprint
        assert _hash_tree(source) == source_before
        assert not output.exists()
        assert not vault.exists()
        assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging*"))


# ---------------------------------------------------------------------------
# Category 3 — hostile path properties
# ---------------------------------------------------------------------------


def test_vault_nested_inside_output_is_typed_refused_and_residue_free(
    tmp_path: Path,
) -> None:
    """A vault nested inside the output root is refused as containment with
    the typed PATH_OVERLAP finding and creates nothing."""
    source = tmp_path / "source"
    output = tmp_path / "output"
    nested_vault = output / "vault" / "dictionary.sqlite3"
    _write_seeded_dataset(source, _seeded_source_values(0))
    source_before = _hash_tree(source)
    plan = public.build_plan(source, output, nested_vault)
    check = public.preflight(plan)
    assert check.ready is False
    assert "PATH_OVERLAP" in check.error_codes
    assert not output.exists()
    assert not nested_vault.exists()
    assert _hash_tree(source) == source_before


def test_redundant_alias_segments_behave_like_canonical_paths(tmp_path: Path) -> None:
    """Output and vault arguments written with redundant dot and traversal
    segments resolve onto the same canonical targets: the pipeline treats
    them identically, publishes once and keeps every artifact contained."""
    source = tmp_path / "source"
    _write_seeded_dataset(source, _seeded_source_values(0))
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    alias_output = tmp_path / "." / "output" / ".." / "output"
    alias_vault = tmp_path / "vault" / "." / "sub" / ".." / "dictionary.sqlite3"

    plan = public.build_plan(source, alias_output, alias_vault)
    assert public.preflight(plan).ready is True
    public.pseudonymize(plan)
    assert (output / "alpha" / "data.dbf").is_file()
    assert (vault).is_file()
    _assert_contained(tmp_path, source, output, vault.parent)


def test_case_variant_output_target_follows_platform_resolution(
    tmp_path: Path,
) -> None:
    """Case-variant spellings follow the objective platform resolution: a
    vault nested under a case variant of the output root is refused on
    case-insensitive platforms (the two spellings denote one directory);
    on case-sensitive platforms both roots are distinct and valid."""
    source = tmp_path / "source"
    output = tmp_path / "OUTput"
    output.mkdir()
    canonical_output = tmp_path / "output"
    # The vault is spelled as nested inside the CASE VARIANT of the output:
    # on case-insensitive roots this is containment of the output root.
    case_vault = tmp_path / "OUTPUT" / "vault" / "dictionary.sqlite3"
    _write_seeded_dataset(source, _seeded_source_values(0))
    source_before = _hash_tree(source)
    plan = public.build_plan(source, output, case_vault)
    if os.path.realpath(output) == os.path.realpath(canonical_output):
        check = public.preflight(plan)
        assert check.ready is False
        assert "PATH_OVERLAP" in check.error_codes
        assert not case_vault.exists()
    else:
        assert public.preflight(plan).ready is True
    assert _hash_tree(source) == source_before


def test_hostile_source_file_names_complete_with_containment(tmp_path: Path) -> None:
    """Hostile but creatable source file names (dot runs, unicode, long
    names, mixed case) are planned and executed; every produced artifact
    stays inside the declared synthetic roots."""
    hostile_names = (
        "a..b.dbf",
        "..leading.dbf",
        "...sneaky.dbf",
        "źreć ą.dbf",
        "UPPER.DATA.dbf",
        "dot.in.name.dbf",
        "x" * 60 + ".dbf",
    )
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    fields = (
        numeric_field("CODE", "C", 8, flags=NULLABLE_FLAG),
        numeric_field("AMOUNT", "I", 4),
    )
    for index, name in enumerate(hostile_names):
        write_numeric_table_with_deleted(
            source,
            f"deep/nest/{name}",
            fields,
            [({"CODE": f"V{index}", "AMOUNT": index}, False)],
        )
    plan = public.build_plan(source, output, vault)
    assert public.preflight(plan).ready is True
    result = public.pseudonymize(plan)
    assert result.table_count == len(hostile_names)
    _assert_contained(tmp_path, source, output, vault.parent)


# ---------------------------------------------------------------------------
# Category 4 — corrupt SQLite single-byte corruption sweep
# ---------------------------------------------------------------------------


def test_vault_byte_corruption_sweep_is_typed_or_integrity_verified(
    tmp_path: Path,
) -> None:
    """Every deterministic single-byte corruption of a completed vault is
    either a typed ``VaultError`` or leaves a fully integrity-verified
    vault; raw/untyped failures and canary leakage are forbidden and a
    refused vault stays byte-identical (never repaired)."""
    root = tmp_path / "sweep"
    source = root / "source"
    output = root / "output"
    vault_path = root / "vault" / "dictionary.sqlite3"
    _write_seeded_dataset(source, _seeded_source_values(0))
    plan = public.build_plan(source, output, vault_path)
    public.pseudonymize(plan)
    reference = vault_path.read_bytes()
    size = len(reference)
    assert size >= 4096

    lcg = _Lcg(0xC0B07)
    offsets = sorted(
        {
            offset
            for offset in (
                0,
                12,
                16,
                18,
                20,
                24,
                28,
                44,
                92,
                96,
                512,
                1024,
                2048,
                3072,
                4095,
                *(lcg.below(size) for _ in range(8)),
            )
            if offset < size
        }
    )
    for index, offset in enumerate(offsets):
        flip_dir = tmp_path / f"flip-{index:02d}-offset-{offset:05d}"
        flip_dir.mkdir()
        corrupted = flip_dir / "dictionary.sqlite3"
        raw = bytearray(reference)
        raw[offset] ^= 0x40
        corrupted.write_bytes(bytes(raw))
        corrupted_hash = hashlib.sha256(corrupted.read_bytes()).hexdigest()
        try:
            with VaultDatabase.open(corrupted) as vault:
                vault.verify(full=True)
        except public.VaultError as typed:
            _error_payload_is_privacy_safe(typed, CANARY_ORIGINAL)
            # A refused vault is never repaired or rewritten.
            assert hashlib.sha256(corrupted.read_bytes()).hexdigest() == corrupted_hash
        except Exception as untyped:  # pragma: no cover - the property itself
            pytest.fail(f"offset {offset}: untyped failure {type(untyped).__name__}")
        # Otherwise the flip landed outside verified structure: the vault is
        # still fully integrity-verified (no false corruption claim).


# ---------------------------------------------------------------------------
# Category 5 + 8 — delegated DBF/FPT errors and write-boundary residue
# ---------------------------------------------------------------------------


def _memo_scenario(tmp_path: Path, seed: int) -> tuple[Path, Path, Path, Path]:
    """One valid DBF/FPT memo pair (no NULLs, no bitmap column needed)."""
    root = tmp_path / f"memo-{seed}"
    source = root / "source"
    output = root / "output"
    vault = root / "vault" / "dictionary.sqlite3"
    fields = (
        memo_field("CODE", "C", 12),
        memo_field("NOTE", "M", 4),
    )
    write_memo_table(
        source,
        "alpha/data.dbf",
        fields,
        [
            {"CODE": f"KEY-{index}", "NOTE": f"{CANARY_PAYLOAD}-{seed}-{index}"}
            for index in range(3)
        ],
    )
    return root, source, output, vault


def test_corrupt_fpt_fails_closed_during_execution_with_delegated_machine_code(
    tmp_path: Path,
) -> None:
    """A valid DBF with a corrupt FPT companion passes planning and the
    read-only preflight scan (memo payloads are not parsed there) and then
    fails closed at the delegated dbfbridge execution boundary with the
    dependency machine code preserved, the source untouched and no output,
    vault rows or staging residue."""
    root, source, output, vault = _memo_scenario(tmp_path, 0)
    dbf_path = source / "alpha" / "data.dbf"
    fpt_path = dbf_path.with_suffix(".fpt")
    uncorrupted = _hash_tree(source)
    # ONE representative deterministic corruption: truncate the FPT to its
    # 128-byte header block so every memo block link points beyond EOF.
    # The DBF header stays valid; dbfbridge owns all parsing and its typed
    # machine error is the expected delegated outcome (no internal fuzzing).
    raw = fpt_path.read_bytes()
    assert len(raw) > 128
    fpt_path.write_bytes(raw[:128])
    corrupted_state = _hash_tree(source)
    assert corrupted_state != uncorrupted

    plan = public.build_plan(source, output, vault)
    assert public.preflight(plan).ready is True
    with pytest.raises(public.DBFBridgeError) as caught:
        public.pseudonymize(plan)
    error = caught.value
    assert error.code.value == "DBFBRIDGE_FAILURE"
    dependency_code = error.dependency_code
    assert dependency_code is not None
    assert dependency_code in DBFBRIDGE_MACHINE_CODES
    assert error.context.detail_code == "ENGINE_DIRECT_READ_FAILED"
    assert error.context.table_path == "alpha/data.dbf"
    _error_payload_is_privacy_safe(error, CANARY_PAYLOAD, CANARY_ORIGINAL)
    assert _hash_tree(source) == corrupted_state
    assert not output.exists()
    assert not vault.exists() or _mapping_row_count(plan, vault) == 0
    assert not tuple(tmp_path.glob("memo-0/.dbf-anonymizer-*.staging*"))


def test_injected_dependency_read_failure_is_typed_delegated_and_residue_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A controlled dependency fault injected at the PUBLIC
    ``dbfbridge.iter_records`` attribute (representative malformed-input
    machine code) becomes the typed privacy-safe delegation failure with
    the machine code preserved — never a raw dbfbridge exception, never
    output, never residue.  The preflight scan (``memo="skip"``) still
    passes, proving the delegation boundary is the execution path."""
    root, source, output, vault = _memo_scenario(tmp_path, 1)
    plan = public.build_plan(source, output, vault)
    source_before = _hash_tree(source)

    real_iter_records = dbfbridge.iter_records

    def fake_iter_records(path: Path, **kwargs: Any) -> Any:
        if kwargs.get("memo") == "inline":
            raise dbfbridge.DbfRecordInvalidError("deterministic injected malformed record")
        return real_iter_records(path, **kwargs)

    monkeypatch.setattr(dbfbridge, "iter_records", fake_iter_records)
    with pytest.raises(public.DBFBridgeError) as caught:
        public.pseudonymize(plan)
    monkeypatch.undo()
    error = caught.value
    assert error.code.value == "DBFBRIDGE_FAILURE"
    assert error.dependency_code == "DBF_RECORD_INVALID"
    assert error.context.detail_code == "ENGINE_DIRECT_READ_FAILED"
    _error_payload_is_privacy_safe(error, CANARY_PAYLOAD)
    assert not output.exists()
    assert _hash_tree(source) == source_before
    if vault.exists():
        assert _mapping_row_count(plan, vault) == 0
    assert not tuple(tmp_path.glob("memo-1/.dbf-anonymizer-*.staging*"))


def test_injected_write_boundary_fault_never_publishes_and_retry_is_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deterministic fault at the public Direct Write boundary never
    publishes a partial dataset, leaves no owned residue, keeps the source
    unchanged, and the same-vault retry completes idempotently with a
    verified dataset (completed output is never re-anonymized)."""
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    _write_seeded_dataset(source, _seeded_source_values(2))
    plan = public.build_plan(source, output, vault)
    source_before = _hash_tree(source)
    events: list[public.ProgressEvent] = []

    def fake_write_table(*args: Any, **kwargs: Any) -> Any:
        raise dbfbridge.DestinationIoError("deterministic injected write fault")

    monkeypatch.setattr(dbfbridge, "write_table", fake_write_table)
    with pytest.raises(public.DBFBridgeError) as caught:
        public.pseudonymize(plan, workers=2, progress=events.append)
    monkeypatch.undo()
    error = caught.value
    assert error.code.value == "DBFBRIDGE_FAILURE"
    assert error.dependency_code == "DESTINATION_IO_ERROR"
    assert error.context.detail_code == "ENGINE_DIRECT_WRITE_FAILED"
    _error_payload_is_privacy_safe(error)
    assert not output.exists()
    assert not tuple(tmp_path.glob(".dbf-anonymizer-*.staging*"))
    assert _hash_tree(source) == source_before
    assert not any(event.event_code == "COMPLETED" for event in events)

    # The same-vault retry is safe and idempotent: the mappings persisted by
    # the failed run are reused (never duplicated), the output is published
    # exactly once and the verification passes.
    result = public.pseudonymize(plan, workers=2)
    assert result.output_fingerprint is not None
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS
    source_records = _logical_tree(source)
    for relative, records in _logical_tree(output).items():
        for source_record, output_record in zip(source_records[relative], records):
            original = dict(source_record[2])["CODE"]
            transformed = dict(output_record[2])["CODE"]
            if original:
                assert transformed != original


# ---------------------------------------------------------------------------
# Category 6 — deterministic PASS1 cancellation
# ---------------------------------------------------------------------------


def test_deterministic_pass1_scan_cancellation_is_bounded_and_retry_safe(
    tmp_path: Path,
) -> None:
    """Cancellation raised deterministically inside the PASS1 mapping scan
    is typed, free of any completed claim or output, truthful about the
    vault state and safe for an immediate retry."""
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    _write_seeded_dataset(source, _seeded_source_values(2))
    plan = public.build_plan(source, output, vault)
    source_before = _hash_tree(source)
    events: list[public.ProgressEvent] = []
    state = {"cancel": False}

    def progress(event: public.ProgressEvent) -> None:
        events.append(event)
        if event.phase_code == "PASS1_SCAN" and event.event_code == "STARTED":
            state["cancel"] = True

    with pytest.raises(public.CancellationError) as caught:
        public.pseudonymize(
            plan,
            workers=2,
            progress=progress,
            cancel_check=lambda: state["cancel"],
        )
    assert caught.value.code.value == "OPERATION_CANCELLED"
    assert caught.value.context.operation == "pseudonymize"
    _error_payload_is_privacy_safe(caught.value, CANARY_PAYLOAD)
    assert not output.exists()
    assert _hash_tree(source) == source_before
    assert not any(event.event_code == "COMPLETED" for event in events)
    if vault.exists():
        assert _mapping_row_count(plan, vault) == 0

    # The immediate retry without cancellation completes and verifies.
    result = public.pseudonymize(plan, workers=2)
    assert public.verify_dataset(result, source=source, vault=vault).status is (
        public.VerificationStatus.PASS
    )
