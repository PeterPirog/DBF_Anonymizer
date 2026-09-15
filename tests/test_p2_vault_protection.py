"""Protected-vault path policy, containment and hardening (REQ-P2-009).

Proves the ONE authoritative internal path-policy component: overlap
refusals in both directions for source/working-output/transfer-output
roots, alias resolution (`.`, `..`, symlinks, Windows case-insensitive
equivalence), valid sibling layouts, typed privacy-safe failures, the
bounded sensitive-artifact vocabulary rooted in the vault directory,
POSIX owner-mode hardening verified against REAL effective modes and the
truthful Windows classification, close-time cleanup failures and the
WAL/SHM/journal lifecycle boundary.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from dbf_anonymizer import ErrorCode, ErrorContext, VaultError
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
)
from dbf_anonymizer.vault.protection import (
    HARDENING_OWNER_MODES_APPLIED,
    HARDENING_WINDOWS_LIMITED,
    RESERVED_PRIVATE_VAULT_VOCABULARY,
    SENSITIVE_VAULT_ARTIFACT_SUFFIXES,
    harden_vault_directory,
    sensitive_artifact_names,
    validate_protected_vault_root,
)

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60

POSIX = os.name == "posix"


def _create(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
        dbfbridge_version="1.1.0",
    )


def _error_detail(excinfo: pytest.ExceptionInfo[VaultError]) -> str:
    value = excinfo.value
    return str(value) + "|" + repr(value) + "|" + str(value.to_dict())


# ---------------------------------------------------------------------------
# path policy
# ---------------------------------------------------------------------------
def test_equal_roots_are_refused_per_target(tmp_path: Path) -> None:
    vault = tmp_path / "shared"
    for kwargs in (
        {"source_root": vault},
        {"source_root": tmp_path / "x", "working_output_root": vault},
        {
            "source_root": tmp_path / "x",
            "working_output_root": tmp_path / "y",
            "transfer_output_root": vault,
        },
    ):
        with pytest.raises(VaultError) as excinfo:
            validate_protected_vault_root(vault, **kwargs)  # type: ignore[arg-type]
        assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID


def test_containment_is_refused_in_both_directions(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    inside_source = source / "vault"
    outside = tmp_path / "outside"
    # Vault INSIDE source and source INSIDE vault are both ambiguous layouts
    # that could sweep sensitive artifacts into publication.
    validate_protected_vault_root(outside, source_root=source)  # sibling: valid
    with pytest.raises(VaultError) as excinfo:
        validate_protected_vault_root(inside_source, source_root=source)
    assert "VAULT_ROOT_OVERLAP_SOURCE" in _error_detail(excinfo)
    with pytest.raises(VaultError):
        validate_protected_vault_root(source, source_root=inside_source)
    # Working-output and transfer-output containment likewise.
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(VaultError):
        validate_protected_vault_root(output / "vault", source_root=outside, working_output_root=output)
    with pytest.raises(VaultError):
        validate_protected_vault_root(output, source_root=outside, working_output_root=output / "vault")


def test_sibling_trees_are_valid(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    source = tmp_path / "src"
    working = tmp_path / "work"
    transfer = tmp_path / "transfer"
    for directory in (vault, source, working, transfer):
        directory.mkdir()
    validate_protected_vault_root(
        vault, source_root=source, working_output_root=working, transfer_output_root=transfer
    )  # no refusal


def test_alias_resolution_dots_and_case(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    # `.` / `..` aliasing and Windows case-insensitive equivalence must not
    # smuggle an overlapping root past the policy.
    alias = vault / "." / ".." / "vault"
    with pytest.raises(VaultError):
        validate_protected_vault_root(alias, source_root=vault)
    if os.name == "nt":
        # A sibling with a different name stays a valid sibling on Windows...
        validate_protected_vault_root(
            vault, source_root=vault.parent / "S-IBLING"
        )
        # ...while a case-variant of the SAME overlapping root is refused
        # (case-insensitive filesystem equivalence).
        with pytest.raises(VaultError):
            validate_protected_vault_root(
                vault, source_root=vault.parent / vault.name.upper()
            )


def test_symlinked_source_root_is_resolved(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation requires privileges on Windows CI runners")
    real = tmp_path / "real" / "data"
    real.mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(VaultError):
        # The alias resolves INTO the real source tree: refused.
        validate_protected_vault_root(real / "vault", source_root=link)


def test_refusals_expose_no_absolute_paths(tmp_path: Path) -> None:
    canary_directory = tmp_path / "secret-vault-location"
    canary_directory.mkdir()
    with pytest.raises(VaultError) as excinfo:
        validate_protected_vault_root(
            canary_directory / "vault", source_root=canary_directory
        )
    boundary = str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
    assert str(canary_directory) not in boundary
    assert "secret-vault" not in boundary


# ---------------------------------------------------------------------------
# sensitive artifact containment
# ---------------------------------------------------------------------------
def test_artifact_vocabulary_is_bounded_and_dictionary_derived() -> None:
    # The SQLite SIDEcars are dictionary-derived; the authoritative
    # vocabulary additionally carries the fixed reserved private names
    # (see the complete-set evidence in the repair regressions below).
    names = sensitive_artifact_names(VAULT_DATABASE_FILENAME)
    assert names[:4] == (
        VAULT_DATABASE_FILENAME,
        VAULT_DATABASE_FILENAME + "-wal",
        VAULT_DATABASE_FILENAME + "-shm",
        VAULT_DATABASE_FILENAME + "-journal",
    )
    assert set(SENSITIVE_VAULT_ARTIFACT_SUFFIXES) == {"-wal", "-shm", "-journal"}
    # All dictionary-derived artifacts stay beside the dictionary (name
    # derivation only); the reserved private names are fixed basenames.
    for name in names[:4]:
        assert name.startswith(VAULT_DATABASE_FILENAME)
    for name in names[4:]:
        assert name in RESERVED_PRIVATE_VAULT_VOCABULARY


def test_vault_artifacts_stay_inside_the_vault_root(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    with _create(tmp_path) as vault:
        assert vault.path.parent == vault_root
        # A second raw connection forces real WAL/SHM sidecars into existence.
        import sqlite3

        held = sqlite3.connect(vault.path)
        try:
            held.execute("SELECT 1").fetchone()
            names = {p.name for p in vault_root.iterdir()}
            # Every artifact lives in the vault root, beside the dictionary.
            assert {n for n in names if n.startswith(VAULT_DATABASE_FILENAME)} <= set(
                sensitive_artifact_names(VAULT_DATABASE_FILENAME)
            )
        finally:
            held.close()
        vault.close()
    # A clean close leaves exactly the dictionary in the vault root.
    assert [p.name for p in sorted(vault_root.iterdir())] == [VAULT_DATABASE_FILENAME]


def test_journal_and_sidecars_cannot_escape_the_vault_root(tmp_path: Path) -> None:
    # The journal/naming derivation is anchored at the dictionary path: a
    # vault created under a nested vault root keeps every artifact there.
    nested = tmp_path / "deep" / "nest" / "vault"
    with VaultDatabase.open(
        nested / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
        dbfbridge_version="1.1.0",
    ) as vault:
        vault.verify()
    artifacts = [p.name for p in nested.iterdir()]
    assert artifacts == [VAULT_DATABASE_FILENAME]
    assert not any(p.name.endswith(".json") for p in nested.rglob("*"))


# ---------------------------------------------------------------------------
# filesystem permissions
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not NTFS ACLs")
def test_posix_owner_modes_are_applied_and_real(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        directory_mode = stat.S_IMODE(vault.path.parent.stat().st_mode)
        file_mode = stat.S_IMODE(vault.path.stat().st_mode)
        assert directory_mode == 0o700
        assert file_mode == 0o600
        classification = harden_vault_directory(vault.path.parent)
        assert classification == HARDENING_OWNER_MODES_APPLIED


@pytest.mark.skipif(os.name == "posix", reason="Windows-truthful classification only")
def test_windows_protection_is_truthfully_limited(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        classification = harden_vault_directory(vault.path.parent)
        assert classification == HARDENING_WINDOWS_LIMITED
        # No POSIX owner-mode claim is made on Windows.
        assert classification != HARDENING_OWNER_MODES_APPLIED


def test_hardening_failure_is_typed_not_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object) -> None:
        raise PermissionError(13, "operation not permitted")

    if os.name == "posix":
        monkeypatch.setattr("dbf_anonymizer.vault.protection.os.chmod", refuse)
        with pytest.raises(VaultError) as excinfo:
            harden_vault_directory(tmp_path)
        assert excinfo.value.code is ErrorCode.VAULT_ACCESS_DENIED
        assert "HARDENING_DENIED" in (
            str(excinfo.value) + "|" + str(excinfo.value.to_dict())
        )
        assert str(tmp_path) not in str(excinfo.value)
    else:
        # Windows truthfully makes no POSIX chmod claim at all.
        assert harden_vault_directory(tmp_path) == HARDENING_WINDOWS_LIMITED


def test_creation_with_failing_hardening_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix":
        pytest.skip("hardening refusal injection applies to POSIX chmod")
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME

    def refuse(*_args: object) -> None:
        raise PermissionError(13, "operation not permitted")

    monkeypatch.setattr("dbf_anonymizer.vault.protection.os.chmod", refuse)
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(
            dictionary,
            create=True,
            expected_source_fingerprint="src-" + "1" * 60,
            expected_policy_fingerprint="pol-" + "2" * 60,
            expected_relationship_fingerprint="rel-" + "3" * 60,
            dbfbridge_version="1.1.0",
        )
    assert excinfo.value.code is ErrorCode.VAULT_ACCESS_DENIED
    # The owner-scoped creation lifecycle removed OUR reservation.
    assert not dictionary.exists()


# ---------------------------------------------------------------------------
# WAL / SHM / journal lifecycle and cleanup failures
# ---------------------------------------------------------------------------
def test_close_checkpoint_failure_surfaces_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from support.vault_sessions import install_failing_execute

    with _create(tmp_path) as vault:
        install_failing_execute(
            vault, fail_when=lambda sql: "wal_checkpoint" in sql, monkeypatch=monkeypatch
        )
        with pytest.raises(VaultError) as excinfo:
            vault.close()
        assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
        detail = str(excinfo.value.to_dict())
        assert "CLOSE_CHECKPOINT" in detail
        # No false success: the failure is recorded AND raised.
        assert vault.cleanup_failure is excinfo.value


def test_close_checkpoint_failure_leaves_the_vault_diagnosable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _create(tmp_path) as vault:
        # A checkpoint that reports an INCOMPLETE status must never be
        # reported as success: the typed failure surfaces (deterministic
        # injection at the close boundary, scoped to THIS instance only).
        def incomplete() -> None:
            raise VaultError(
                ErrorCode.VAULT_UNAVAILABLE,
                context=ErrorContext(
                    operation="vault", detail_code="CLOSE_CHECKPOINT_INCOMPLETE"
                ),
            )

        monkeypatch.setattr(vault, "_checkpoint_wal", incomplete)
        with pytest.raises(VaultError) as excinfo:
            vault.close()
        assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
        assert vault.cleanup_failure is excinfo.value
        assert "CLOSE_CHECKPOINT_INCOMPLETE" in str(excinfo.value.to_dict())
        # The underlying vault remains diagnosable: a plain reopen verifies.
    with VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
    ) as reopened:
        reopened.verify()


def test_crash_dirty_reopen_follows_sqlite_recovery(tmp_path: Path) -> None:
    """Reopen after a REAL process interruption follows SQLite recovery.

    A subprocess creates the vault, acquires the writer lease, commits one
    operation row (STARTED) and dies via ``os._exit`` — no clean close, no
    checkpoint: the deterministic interruption simulation.  The parent then
    proves SQLite recovery semantics: the crash-dirty WAL is recovered, the
    committed state is intact, the interrupted operation stays distinguishable
    from COMPLETED and the stale lease is explicit and reclaimable only by
    naming the stored token.
    """
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    dictionary.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "import os, sys\n"
        "sys.path.insert(0, r'{src}')\n"
        "from dbf_anonymizer.vault import VaultDatabase, VAULT_DATABASE_FILENAME, new_writer_token\n"
        "vault = VaultDatabase.open(\n"
        "    r'{dictionary}', create=True,\n"
        "    expected_source_fingerprint='src-' + '1' * 60,\n"
        "    expected_policy_fingerprint='pol-' + '2' * 60,\n"
        "    expected_relationship_fingerprint='rel-' + '3' * 60,\n"
        "    dbfbridge_version='1.1.0',\n"
        ")\n"
        "token = new_writer_token()\n"
        "vault.acquire_writer_lease(token)\n"
        "with vault.transaction():\n"
        "    vault.begin_operation('op-interrupted')\n"
        "os._exit(9)  # abrupt process death: no clean close, no lease release\n"
    ).format(src=Path(__file__).resolve().parents[1] / "src", dictionary=dictionary)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        timeout=120,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )
    assert completed.returncode == 9, completed.stderr.decode("utf-8", "replace")
    # The crash-dirty WAL sidecar survived inside the vault root only.
    assert (dictionary.parent / (VAULT_DATABASE_FILENAME + "-wal")).is_file()
    with VaultDatabase.open(
        dictionary,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
    ) as reopened:
        reopened.verify()  # SQLite recovery semantics produce a valid vault
        states = [row["state"] for row in reopened.operations()]
        assert "STARTED" in states  # interrupted, never silently completed
        assert "COMPLETED" not in states
        # The crashed writer's lease is explicit crash-state evidence...
        stale = reopened.stale_writer_lease()
        assert stale is not None
        # ...and acquisition without the explicit reclaim fails closed.
        from dbf_anonymizer.vault import new_writer_token

        with pytest.raises(VaultError) as excinfo:
            reopened.acquire_writer_lease(new_writer_token())
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        # Resume is EXPLICIT: naming the stored stale token reclaims.
        reopened.release_writer_lease(str(reopened.stale_writer_lease()))
        token = new_writer_token()
        assert reopened.acquire_writer_lease(token) >= 1
        with reopened.transaction():
            reopened.complete_operation("op-interrupted")
        states = [row["state"] for row in reopened.operations()]
        assert states == ["COMPLETED"]
        reopened.close()
    # The clean resume close removed the WAL sidecar from the vault root.
    assert not (dictionary.parent / (VAULT_DATABASE_FILENAME + "-wal")).exists()


def test_rollback_journal_cannot_escape_the_vault_root(tmp_path: Path) -> None:
    # Journal artifact naming derives from the dictionary path only.
    dictionary = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    names = sensitive_artifact_names(VAULT_DATABASE_FILENAME)
    assert all(
        (dictionary.parent / name) == dictionary.with_name(name) for name in names
    )
    with VaultDatabase.open(
        dictionary,
        create=True,
        expected_source_fingerprint="src-" + "1" * 60,
        expected_policy_fingerprint="pol-" + "2" * 60,
        expected_relationship_fingerprint="rel-" + "3" * 60,
        dbfbridge_version="1.1.0",
    ) as vault:
        assert vault.path == dictionary
    # No sensitive artifact escaped into the parent of the vault root.
    escaped = [p for p in tmp_path.iterdir() if p.name.startswith(VAULT_DATABASE_FILENAME)]
    assert escaped == []


def test_no_secure_deletion_overclaim_in_documentation() -> None:
    text = (Path(__file__).resolve().parents[1] / "docs" / "vault-protection.md").read_text(
        encoding="utf-8"
    )
    assert "NOT secure deletion" in text
    assert "wear leveling" in text
    assert "encrypted volume" in text or "BitLocker" in text
    assert "backups are equally sensitive" in text
    assert "not anonymous" in text
    assert "never" in text and "transfer bundle" in text


# ---------------------------------------------------------------------------
# PR #28 repair regressions (fail on 425a907, pass after the repair)
# ---------------------------------------------------------------------------
def test_protection_module_export_contract_resolves() -> None:
    """EVERY name declared in ``__all__`` must exist on the module.

    Pre-repair behavior: ``__all__`` declared ``SENSITIVE_ARTIFACT_SUFFIXES``
    while the real constant is ``SENSITIVE_VAULT_ARTIFACT_SUFFIXES`` — the
    star-import surface referenced a nonexistent symbol.
    """
    import dbf_anonymizer.vault.protection as protection

    for name in protection.__all__:
        assert hasattr(protection, name), f"missing export: {name}"
    # A REAL star import in an isolated namespace must succeed completely.
    namespace: dict[str, object] = {}
    exec("from dbf_anonymizer.vault.protection import *", namespace)
    star_names = set(namespace) - {"__builtins__", "__annotations__"}
    assert star_names == set(protection.__all__)


def test_sensitive_artifact_vocabulary_is_complete() -> None:
    """ONE helper must represent ALL currently defined sensitive artifacts.

    Pre-repair behavior: the reserved private artifacts
    (``recovery-manifest.private`` / ``recovery-spool.private``) were
    silently omitted from ``sensitive_artifact_names``.
    """
    names = sensitive_artifact_names(VAULT_DATABASE_FILENAME)
    assert names == (
        VAULT_DATABASE_FILENAME,
        VAULT_DATABASE_FILENAME + "-wal",
        VAULT_DATABASE_FILENAME + "-shm",
        VAULT_DATABASE_FILENAME + "-journal",
        "recovery-manifest.private",
        "recovery-spool.private",
    )
    assert len(names) == len(set(names))  # unique


def test_artifact_vocabulary_safety_invariants() -> None:
    """Deterministic vocabulary safety invariants (REQ-P2-009 boundary)."""
    names = sensitive_artifact_names(VAULT_DATABASE_FILENAME)
    vault_root = Path("D:\\") if os.name == "nt" else Path("/")
    for name in names:
        # Basename only: never absolute, never carrying path separators.
        assert Path(name).name == name
        assert not Path(name).is_absolute()
        assert "/" not in name and "\\" not in name
        # The complete vocabulary stays rooted under a supplied vault root.
        joined = vault_root / name
        assert joined.name == name
    # The SQLite sidecars are derived from VAULT_DATABASE_FILENAME.
    assert names[0] == VAULT_DATABASE_FILENAME
    assert all(
        names[index] == VAULT_DATABASE_FILENAME + suffix
        for index, suffix in enumerate(SENSITIVE_VAULT_ARTIFACT_SUFFIXES, start=1)
    )
    # The reserved private artifacts are included, exactly once.
    for reserved in RESERVED_PRIVATE_VAULT_VOCABULARY:
        assert names.count(reserved) == 1
    # No JSON recovery sidecar is introduced by the authoritative vocabulary.
    assert not any(name.endswith(".json") or name.endswith(".jsonl") for name in names)


def test_dictionary_filename_must_be_a_basename() -> None:
    """The vocabulary helper refuses caller-controlled path separators."""
    for hostile in ("dir/dictionary.sqlite3", "..\\dictionary.sqlite3", "/etc/passwd"):
        with pytest.raises(VaultError) as excinfo:
            sensitive_artifact_names(hostile)
        assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
        boundary = str(excinfo.value) + "|" + str(excinfo.value.to_dict())
        assert "SENSITIVE_VOCABULARY_INVALID" in boundary
