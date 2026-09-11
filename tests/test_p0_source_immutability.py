"""REQ-P0-004 — deterministic source-immutability evidence tests.

These tests prove, over representative public dbfbridge read/write operations
on disposable synthetic P0 corpus copies, that:

- every in-scope source DBF/FPT/CDX/IDX artifact is discovered recursively
  and fingerprinted (relative POSIX path, class, size, complete-byte
  SHA-256);
- source fingerprints are byte-identical before/after successful, failed
  and cancelled operation scenarios;
- every write target is outside the source tree and overlapping targets are
  rejected before any write occurs;
- the complete source tree inventory is unchanged (no new files inside the
  source tree).

The tests use only synthetic P0 corpus copies; committed fixtures are never
mutated.  The cancellation/failure scenarios are P0 source-immutability
evidence only, not the future REQ-P1-008 public cancellation semantics.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import pytest
from dbfbridge import read_schema

from support.source_immutability import (
    CORPUS_FAMILY,
    IN_SCOPE_SUFFIXES,
    OperationCancelled,
    OperationFailedError,
    SourceArtifact,
    WriteTargetInsideSourceError,
    assert_fingerprints_equal,
    build_synthetic_source_tree,
    canonical_fingerprint_digest,
    fingerprint_source_tree,
    full_tree_inventory,
    representative_operation,
    resolve_outside_source,
)

#: The eight in-scope artifacts of the evidence source matrix: plain DBF,
#: DBF+FPT pair, DBF+structural-CDX pair, DBF+standalone-IDX pair, in nested
#: directories, plus the uppercase-suffix probe copy.
EXPECTED_SOURCE_ARTIFACTS = frozenset(
    {
        "extra/UPPERCASE.DBF",
        "memos/memo_payloads.dbf",
        "memos/memo_payloads.fpt",
        "plain/plain_customers.dbf",
        "vfp/idx/code_idx.idx",
        "vfp/idx/standalone_idx_table.dbf",
        "vfp/structural/indexed_table.cdx",
        "vfp/structural/indexed_table.dbf",
    }
)

COMMITTED_CORPUS_HASHES = frozenset(
    {
        "3076275e4bcd174500a9e1954596b5fd62f826e957fd9e3136b7bfe45e6054aa",
        "b5ab7ee37138971be4c565dcb2871879b700b416d8861ae2f5203a9e695a3fe7",
        "e3af637ee9b9ab5a0fa8b5a31ab9a8a0f2ac3979c1110b05ecc8b25a31b27f6e",
        "66154a52129ddd4941ef300bf7dafa9bf4cc1394379248df91876f2535626fe5",
        "5a8f2864f65b65679b7f32371267b439c0a9371a865babf7cc68e8179b04bcc2",
        "682997f44cf5319a4dfb7d2df5c1294b8b8f5d6c354c1c0ab4fb65af395212a7",
        "4fccc6046832befc79452efd2669975a08635d3dc91749fafd5d1773d3728ee8",
        "2fbafb9e4d019480e028be193aac95680476755f994535445775e1dca8ac41f1",
        "2d0d7ef653eaea54bbf3ada0242e3bcbe69369decc83e31ab7c10fdb1aa5b3cd",
        "f6840f1a6015e926cb7b7db1a03c4dedac607f200534d5aa4c73a20cb020fe9f",
        "a814b2a4e57899dfbbefd88ab0044b4c74103ef692e9ec8a6ff8be86d8f97027",
    }
)


@pytest.fixture()
def synthetic_source_tree(tmp_path: Path) -> Path:
    source_root = tmp_path / "dataset"
    build_synthetic_source_tree(source_root)
    return source_root


def _output_root(tmp_path: Path) -> Path:
    """A sibling output root outside the source tree."""
    return tmp_path / "operation-output"


def _assert_targets_outside_source(source_root: Path, targets: list[str], output_root: Path) -> None:
    for relative in targets:
        absolute = output_root / relative
        assert absolute.is_file()
        resolved_source = os.path.normcase(str(source_root.resolve()))
        resolved_target = os.path.normcase(str(absolute.resolve()))
        assert resolved_target != resolved_source
        assert not resolved_target.startswith(resolved_source + os.sep)


# ---------------------------------------------------------------------------
# fingerprint helper evidence
# ---------------------------------------------------------------------------


def test_fingerprint_discovers_every_expected_artifact_recursively(synthetic_source_tree: Path) -> None:
    fingerprint = fingerprint_source_tree(synthetic_source_tree)
    assert {artifact.relative_path for artifact in fingerprint} == EXPECTED_SOURCE_ARTIFACTS
    assert {artifact.artifact_class for artifact in fingerprint} == {"dbf", "fpt", "cdx", "idx"}
    # The corpus hashes are preserved by the copy (synthetic-only source).
    assert {artifact.sha256 for artifact in fingerprint} <= COMMITTED_CORPUS_HASHES


def test_fingerprint_paths_are_normalized_relative_posix(synthetic_source_tree: Path) -> None:
    for artifact in fingerprint_source_tree(synthetic_source_tree):
        assert "\\" not in artifact.relative_path
        assert not artifact.relative_path.startswith("/")
        assert os.path.isabs(artifact.relative_path) is False
        assert artifact.artifact_class == artifact.relative_path.rsplit(".", 1)[1].lower()


def test_fingerprint_uses_complete_bytes_sha256_and_detects_change(
    synthetic_source_tree: Path,
) -> None:
    before = fingerprint_source_tree(synthetic_source_tree)
    # Negative self-test: deliberately mutate ONE byte of a DISPOSABLE copied
    # fixture (never a committed corpus file) and prove detection.
    victim = synthetic_source_tree / "plain" / "plain_customers.dbf"
    data = bytearray(victim.read_bytes())
    data[-1] ^= 0xFF
    victim.write_bytes(bytes(data))
    after = fingerprint_source_tree(synthetic_source_tree)
    with pytest.raises(AssertionError, match="byte-changed"):
        assert_fingerprints_equal(before, after)


def test_fingerprint_detects_added_artifact(synthetic_source_tree: Path) -> None:
    before = fingerprint_source_tree(synthetic_source_tree)
    added = synthetic_source_tree / "plain" / "added_companion.dbf"
    added.write_bytes((synthetic_source_tree / "plain" / "plain_customers.dbf").read_bytes())
    after = fingerprint_source_tree(synthetic_source_tree)
    with pytest.raises(AssertionError, match="added in-scope artifacts"):
        assert_fingerprints_equal(before, after)


def test_fingerprint_detects_deleted_artifact(synthetic_source_tree: Path) -> None:
    before = fingerprint_source_tree(synthetic_source_tree)
    (synthetic_source_tree / "vfp" / "idx" / "code_idx.idx").unlink()
    after = fingerprint_source_tree(synthetic_source_tree)
    with pytest.raises(AssertionError, match="removed in-scope artifacts"):
        assert_fingerprints_equal(before, after)
    # A rename is an add+delete pair for the path set: it breaks equality too.
    with pytest.raises(AssertionError):
        assert_fingerprints_equal(before, fingerprint_source_tree(synthetic_source_tree))


def test_fingerprint_digest_is_deterministic(synthetic_source_tree: Path) -> None:
    first = fingerprint_source_tree(synthetic_source_tree)
    second = fingerprint_source_tree(synthetic_source_tree)
    assert canonical_fingerprint_digest(first) == canonical_fingerprint_digest(second)


def test_committed_corpus_families_exist() -> None:
    for relative in CORPUS_FAMILY:
        assert (Path(__file__).parent / "fixtures" / "p0" / relative).is_file()
    assert IN_SCOPE_SUFFIXES == frozenset({".dbf", ".fpt", ".cdx", ".idx"})


# ---------------------------------------------------------------------------
# write-target separation evidence
# ---------------------------------------------------------------------------


def test_output_equal_to_source_root_is_rejected_before_write(synthetic_source_tree: Path) -> None:
    inventory_before = full_tree_inventory(synthetic_source_tree)
    with pytest.raises(WriteTargetInsideSourceError):
        resolve_outside_source(synthetic_source_tree, synthetic_source_tree)
    assert full_tree_inventory(synthetic_source_tree) == inventory_before


def test_output_inside_source_root_is_rejected_before_write(synthetic_source_tree: Path) -> None:
    inventory_before = full_tree_inventory(synthetic_source_tree)
    overlapping = synthetic_source_tree / "output"
    with pytest.raises(WriteTargetInsideSourceError):
        resolve_outside_source(synthetic_source_tree, overlapping)
    assert not (synthetic_source_tree / "output").exists()
    assert full_tree_inventory(synthetic_source_tree) == inventory_before


def test_nested_dotdot_target_resolving_inside_source_is_rejected(
    synthetic_source_tree: Path,
) -> None:
    inventory_before = full_tree_inventory(synthetic_source_tree)
    sneaky = synthetic_source_tree / "plain" / ".." / "output"
    with pytest.raises(WriteTargetInsideSourceError):
        resolve_outside_source(synthetic_source_tree, sneaky)
    assert not (synthetic_source_tree / "plain" / "output").exists()
    assert not (synthetic_source_tree / "output").exists()
    assert full_tree_inventory(synthetic_source_tree) == inventory_before


def test_dot_self_alias_target_is_rejected(synthetic_source_tree: Path) -> None:
    with pytest.raises(WriteTargetInsideSourceError):
        resolve_outside_source(synthetic_source_tree, synthetic_source_tree / ".")
    # A redundant-path sibling stays allowed (resolve-based, no flakiness).
    sibling = synthetic_source_tree.parent / "output-alias" / "."
    resolved = resolve_outside_source(synthetic_source_tree, sibling)
    assert resolved == (synthetic_source_tree.parent / "output-alias").resolve()


# ---------------------------------------------------------------------------
# operation scenarios
# ---------------------------------------------------------------------------


def test_success_scenario_leaves_source_byte_identical(
    synthetic_source_tree: Path, tmp_path: Path
) -> None:
    source_root = synthetic_source_tree
    output_root = _output_root(tmp_path)
    before = fingerprint_source_tree(source_root)
    source_inventory_before = full_tree_inventory(source_root)

    created = representative_operation(source_root, output_root)

    after = fingerprint_source_tree(source_root)
    assert_fingerprints_equal(before, after)
    assert full_tree_inventory(source_root) == source_inventory_before
    # Every write target was created outside the source tree, and DBF+FPT
    # output was produced externally (the memo table has memo fields).
    assert len(created) == 6  # 5 DBFs (incl. the uppercase probe) + 1 FPT
    assert any(target.endswith(".fpt") for target in created)
    _assert_targets_outside_source(source_root, created, output_root)
    # The outputs are readable fresh public-API copies of the sources.
    output_schema = read_schema(output_root / "memos" / "memo_payloads.dbf")
    source_schema = read_schema(source_root / "memos" / "memo_payloads.dbf")
    assert output_schema.record_count == source_schema.record_count
    assert output_schema.has_memo is True


def test_failure_scenario_leaves_source_byte_identical(
    synthetic_source_tree: Path, tmp_path: Path
) -> None:
    source_root = synthetic_source_tree
    output_root = _output_root(tmp_path)
    before = fingerprint_source_tree(source_root)
    source_inventory_before = full_tree_inventory(source_root)
    with pytest.raises(OperationFailedError):
        created = representative_operation(source_root, output_root, fail_after_tables=0)
    # Failure happened AFTER the first table (deterministic sorted order:
    # extra/UPPERCASE.DBF) was fully processed and externally written.
    assert (output_root / "extra" / "UPPERCASE.DBF").is_file()
    after = fingerprint_source_tree(source_root)
    assert_fingerprints_equal(before, after)
    assert full_tree_inventory(source_root) == source_inventory_before
    # Partial TEST output outside the source tree is acceptable P0 evidence
    # (no REQ-P4 atomic-publication semantics are claimed here).
    _assert_targets_outside_source(
        source_root,
        [path.relative_to(output_root).as_posix() for path in output_root.rglob("*") if path.is_file()],
        output_root,
    )


def test_cancellation_scenario_leaves_source_byte_identical(
    synthetic_source_tree: Path, tmp_path: Path
) -> None:
    source_root = synthetic_source_tree
    output_root = _output_root(tmp_path)
    before = fingerprint_source_tree(source_root)
    source_inventory_before = full_tree_inventory(source_root)
    with pytest.raises(OperationCancelled):
        representative_operation(source_root, output_root, cancel_after_tables=0)
    assert (output_root / "extra" / "UPPERCASE.DBF").is_file()
    after = fingerprint_source_tree(source_root)
    assert_fingerprints_equal(before, after)
    assert full_tree_inventory(source_root) == source_inventory_before
    _assert_targets_outside_source(
        source_root,
        [path.relative_to(output_root).as_posix() for path in output_root.rglob("*") if path.is_file()],
        output_root,
    )


def test_source_tree_receives_no_new_operation_files(
    synthetic_source_tree: Path, tmp_path: Path
) -> None:
    """Full-inventory proof: no operation target lands inside the source tree."""
    source_root = synthetic_source_tree
    output_root = _output_root(tmp_path)
    inventory_before = full_tree_inventory(source_root)
    representative_operation(source_root, output_root)
    inventory_after = full_tree_inventory(source_root)
    assert inventory_after == inventory_before
