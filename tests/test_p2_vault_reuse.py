"""Explicit fresh/reuse contract, corruption matrix and resume (REQ-P2-010).

Proves the complete REQ-P2-010 acceptance contract:

* explicit FRESH vs REUSE semantics of ``VaultDatabase.open(create=...)``;
* the exact fingerprint-compatibility matrix (compatible, single, double
  and triple mismatches) with byte-identical refused vaults;
* cross-domain same-vault reuse (global text + memo + temporal in ONE vault)
  including idempotent memo reruns and conflicting-identity refusal;
* hostile/corrupt recovery storage classes (SQLite dynamic typing) refused
  through stable typed errors — never raw ``ValueError``/``TypeError``;
* deterministic interrupted-operation/resume evidence (subprocess crash);
* fresh-vault independence proven deterministically.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from dbf_anonymizer import ErrorCode, MappingError, VaultError
from dbf_anonymizer.vault import (
    GLOBAL_TEXT_DOMAIN_ID,
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    mappings,
    new_writer_token,
)
from dbf_anonymizer.vault.mappings import (
    VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
    add_text_mapping,
    create_domain,
    get_memo_recovery,
    get_text_pseudonym,
    text_mapping_rows,
)
from dbf_anonymizer.vault.text_allocation import GlobalTextDomainMapping
from dbf_anonymizer.vault.temporal_allocation import TemporalShiftDomain
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60
OTHER_FP = "other-" + "4" * 60

_SRC_ROOT = Path(__file__).resolve().parents[1] / "src"


def _open_create(path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        path,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version="1.1.0",
    )


def _dictionary(tmp_path: Path) -> Path:
    return tmp_path / "vault" / VAULT_DATABASE_FILENAME


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seed_text(vault: VaultDatabase) -> str:
    """Seed one text mapping (caller must hold the writer lease)."""
    with vault.transaction():
        create_domain(
            vault,
            domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT,
            domain_id=GLOBAL_TEXT_DOMAIN_ID,
        )
        add_text_mapping(vault, GLOBAL_TEXT_DOMAIN_ID, "KUND-1", "7XQ2A", logical_byte_length=5)
    return "7XQ2A"


# ---------------------------------------------------------------------------
# explicit fresh / reuse contract
# ---------------------------------------------------------------------------
def test_fresh_intent_refuses_an_existing_vault(tmp_path: Path) -> None:
    with _open_create(tmp_path / "vault" / VAULT_DATABASE_FILENAME) as vault:
        vault_id = vault.vault_id
    with pytest.raises(VaultError) as excinfo:
        _open_create(tmp_path / "vault" / VAULT_DATABASE_FILENAME)
    assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
    # The refused fresh creation never touched the existing vault identity.
    with VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as reopened:
        assert reopened.vault_id == vault_id


def test_reuse_intent_refuses_a_missing_vault(tmp_path: Path) -> None:
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
        )
    assert excinfo.value.code is ErrorCode.VAULT_UNAVAILABLE
    detail = str(excinfo.value.to_dict())
    assert "DICTIONARY_MISSING" in detail


def test_compatible_fingerprints_are_reused(tmp_path: Path) -> None:
    with _open_create(_dictionary(tmp_path)) as vault:
        vault_id = vault.vault_id
    with VaultDatabase.open(
        _dictionary(tmp_path),
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as reused:
        assert reused.vault_id == vault_id  # preserved, never reissued


@pytest.mark.parametrize(
    "mismatches",
    (
        {"source": OTHER_FP},
        {"policy": OTHER_FP},
        {"relationship": OTHER_FP},
        {"source": OTHER_FP, "policy": OTHER_FP},
        {"source": OTHER_FP, "relationship": OTHER_FP},
        {"policy": OTHER_FP, "relationship": OTHER_FP},
        {"source": OTHER_FP, "policy": OTHER_FP, "relationship": OTHER_FP},
    ),
)
def test_every_fingerprint_mismatch_fails_closed_without_mutation(
    tmp_path: Path, mismatches: dict[str, str]
) -> None:
    with _open_create(_dictionary(tmp_path)) as vault:
        vault_id = vault.vault_id
        with writer_session(vault):
            pseudonym = _seed_text(vault)
    before = _sha256(_dictionary(tmp_path))
    with pytest.raises(VaultError) as excinfo:
        VaultDatabase.open(
            _dictionary(tmp_path),
            expected_source_fingerprint=mismatches.get("source", SOURCE_FP),
            expected_policy_fingerprint=mismatches.get("policy", POLICY_FP),
            expected_relationship_fingerprint=mismatches.get("relationship", RELATIONSHIP_FP),
        )
    assert excinfo.value.code is ErrorCode.VAULT_IDENTITY_MISMATCH
    boundary = (
        str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
    )
    # No actual fingerprint values, no source/vault paths in the refusal.
    assert SOURCE_FP not in boundary and OTHER_FP not in boundary
    assert str(tmp_path) not in boundary
    # The refused reuse left the vault byte-identical (real comparison).
    assert _sha256(_dictionary(tmp_path)) == before
    with VaultDatabase.open(
        _dictionary(tmp_path),
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as reopened:
        assert reopened.vault_id == vault_id  # identity never altered
        assert get_text_pseudonym(reopened, GLOBAL_TEXT_DOMAIN_ID, "KUND-1") == pseudonym


# ---------------------------------------------------------------------------
# cross-domain same-vault reuse (text + memo + temporal in ONE vault)
# ---------------------------------------------------------------------------
def _register_memo_field(vault: VaultDatabase, table_id: str) -> str:
    return vault.register_field(table_id, "NOTE", dbf_type="M", width=4)


def test_one_vault_coherently_reuses_all_recovery_classes(tmp_path: Path) -> None:
    dictionary = _dictionary(tmp_path)
    with _open_create(dictionary) as vault:
        vault_id = vault.vault_id
        with writer_session(vault), vault.transaction():
            create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT,
                domain_id=GLOBAL_TEXT_DOMAIN_ID,
            )
            add_text_mapping(vault, GLOBAL_TEXT_DOMAIN_ID, "KUND-1", "7XQ2A", logical_byte_length=5)
            memo_table_id = vault.register_table("data/memos.dbf")
            memo_field_id = _register_memo_field(vault, memo_table_id)
            mappings.add_memo_recovery(
                vault,
                memo_table_id,
                0,
                memo_field_id,
                b"ORIGINAL-PAYLOAD\x00\x01",
                payload_kind="BINARY",
            )
        temporal = TemporalShiftDomain(vault)
        for value in (date(2020, 1, 1), date(2020, 12, 31)):
            temporal.observe(value)
        with writer_session(vault):
            temporal_offset = temporal.finalize()
            assert temporal_offset is not None
        vault.close()

    # Compatible RERUN against the SAME vault: every recovery class reuses.
    with VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as reused:
        assert reused.vault_id == vault_id  # identity preserved across rerun
        with writer_session(reused):
            # TEXT: the mapped original reproduces its exact pseudonym.
            assert get_text_pseudonym(reused, GLOBAL_TEXT_DOMAIN_ID, "KUND-1") == "7XQ2A"
            with reused.transaction():
                add_text_mapping(reused, GLOBAL_TEXT_DOMAIN_ID, "KUND-2", "9B4D1", logical_byte_length=5)
            assert text_mapping_rows(reused, GLOBAL_TEXT_DOMAIN_ID)[0][1] == "7XQ2A"
            # TEMPORAL: compatible persisted offset reused; the CSPRNG seam
            # must never be consulted.
            def refuse_csprng(*_args: object) -> int:
                raise AssertionError("reuse must not invoke the CSPRNG")

            temporal = TemporalShiftDomain(reused, _random_below=refuse_csprng)
            temporal.observe(date(2020, 6, 1))
            assert temporal.finalize() == temporal_offset
            # MEMO: exact idempotent rerun succeeds WITHOUT overwriting.
            from dbf_anonymizer.vault import persist_memo_recovery

            mask = persist_memo_recovery(
                reused,
                table_id=memo_table_id,
                physical_record_index=0,
                field_id=memo_field_id,
                dbf_type="M",
                value=b"ORIGINAL-PAYLOAD\x00\x01",
            )
            assert mask == b"[MASKED-MEMO]"
            # A CONFLICTING payload under the same identity fails closed.
            with pytest.raises(VaultError) as excinfo:
                persist_memo_recovery(
                    reused,
                    table_id=memo_table_id,
                    physical_record_index=0,
                    field_id=memo_field_id,
                    dbf_type="M",
                    value=b"TAMPERED",
                )
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
            detail = str(excinfo.value.to_dict())
            assert "MEMO_IDENTITY_CONFLICT" in detail
            # The original recovery payload was never overwritten.
            assert get_memo_recovery(reused, memo_table_id, 0, memo_field_id) == (
                b"ORIGINAL-PAYLOAD\x00\x01",
                "BINARY",
            )


# ---------------------------------------------------------------------------
# corruption matrix (hostile storage classes, test setup only)
# ---------------------------------------------------------------------------
def _seed_corrupt_temporal(tmp_path: Path, raw_offset: object) -> VaultDatabase:
    dictionary = _dictionary(tmp_path)
    with _open_create(dictionary) as vault:
        domain_id = TemporalShiftDomain(vault, domain_name="corrupt").domain_id
        with writer_session(vault), vault.transaction():
            create_domain(
                vault,
                domain_kind=VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
                domain_id=domain_id,
            )
            vault._internal_connection().execute(
                "INSERT INTO temporal_parameters (domain_id, offset_days) "
                "VALUES (?, ?)",
                (domain_id, raw_offset),
            )
        vault.close()
    return VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


@pytest.mark.parametrize(
    "raw_offset",
    ["not-a-number", 3.5, b"\x00\x01", 0, 9223372036854775807],
)
def test_hostile_temporal_storage_classes_fail_closed(
    tmp_path: Path, raw_offset: object
) -> None:
    with _seed_corrupt_temporal(tmp_path, raw_offset) as vault:
        domain = TemporalShiftDomain(vault, domain_name="corrupt")
        domain.observe(date(2020, 1, 1))
        domain.observe(date(2020, 12, 31))
        with writer_session(vault), pytest.raises(VaultError) as excinfo:
            domain.finalize()
        assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
        with pytest.raises((VaultError, MappingError)) as recovery:
            domain.recover(date(2020, 1, 1))
        assert recovery.value.code in (
            ErrorCode.VAULT_STATE_INVALID,
            ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        )
        boundary = (
            str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
        )
        # No raw conversion detail and no distinctive hostile payload ever
        # escapes (numeric fragments legitimately appear in version metadata,
        # so only distinctive payloads are asserted absent).
        if isinstance(raw_offset, (str, bytes)):
            assert str(raw_offset) not in boundary
        assert "Traceback" not in boundary and "sqlite3." not in boundary


def _seed_corrupt_memo(
    tmp_path: Path, raw_payload: object, raw_kind: object
) -> tuple[VaultDatabase, str, str]:
    dictionary = _dictionary(tmp_path)
    with _open_create(dictionary) as vault:
        with writer_session(vault), vault.transaction():
            create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT,
                domain_id=GLOBAL_TEXT_DOMAIN_ID,
            )
            table_id = vault.register_table("memo/corrupt.dbf")
            field_id = vault.register_field(table_id, "NOTE", dbf_type="M", width=4)
            vault._internal_connection().execute(
                "INSERT INTO memo_recovery (table_id, physical_record_index, "
                "field_id, original_payload, payload_kind) VALUES (?, ?, ?, ?, ?)",
                (table_id, 0, field_id, raw_payload, raw_kind),
            )
        vault.close()
    reopened = VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )
    return reopened, table_id, field_id


@pytest.mark.parametrize(
    ("raw_payload", "raw_kind"),
    [(12345, "BINARY"), ("text-payload", "BINARY")],
)
def test_hostile_memo_storage_classes_fail_closed(
    tmp_path: Path, raw_payload: object, raw_kind: object
) -> None:
    vault, table_id, field_id = _seed_corrupt_memo(tmp_path, raw_payload, raw_kind)
    try:
        from dbf_anonymizer.vault import recover_memo_value

        with pytest.raises((VaultError, MappingError)) as excinfo:
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=0, field_id=field_id
            )
        boundary = (
            str(excinfo.value) + "|" + repr(excinfo.value) + "|" + str(excinfo.value.to_dict())
        )
        # No raw payload value ever escapes the typed refusal.
        if raw_payload != b"\x00":
            assert str(raw_payload) not in boundary
    finally:
        vault.close()


def _seed_corrupt_text(tmp_path: Path, raw_length: object) -> VaultDatabase:
    dictionary = _dictionary(tmp_path)
    with _open_create(dictionary) as vault:
        with writer_session(vault), vault.transaction():
            create_domain(
                vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT,
                domain_id=GLOBAL_TEXT_DOMAIN_ID,
            )
            vault._internal_connection().execute(
                "INSERT INTO text_mappings (domain_id, original_value, "
                "pseudonym_value, logical_byte_length) VALUES (?, ?, ?, ?)",
                (GLOBAL_TEXT_DOMAIN_ID, "KUND-CORRUPT", "7XQ2A", raw_length),
            )
        vault.close()
    return VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


@pytest.mark.parametrize("raw_length", ["not-a-number", 1.5, b"\x00"])
def test_hostile_text_length_storage_classes_fail_closed(
    tmp_path: Path, raw_length: object
) -> None:
    with _seed_corrupt_text(tmp_path, raw_length) as vault:
        with pytest.raises(VaultError) as excinfo:
            text_mapping_rows(vault, GLOBAL_TEXT_DOMAIN_ID)
        assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID


# ---------------------------------------------------------------------------
# interrupted operation / deterministic resume (subprocess crash)
# ---------------------------------------------------------------------------
def test_uncommitted_changes_disappear_after_interruption(tmp_path: Path) -> None:
    """SQLite rollback semantics: uncommitted work never survives a crash."""
    dictionary = _dictionary(tmp_path)
    dictionary.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "import os, sys\n"
        "sys.path.insert(0, r'{src}')\n"
        "from dbf_anonymizer.vault import VaultDatabase, VAULT_DATABASE_FILENAME, new_writer_token, mappings, GLOBAL_TEXT_DOMAIN_ID\n"
        "vault = VaultDatabase.open(\n"
        "    r'{dictionary}', create=True,\n"
        "    expected_source_fingerprint='src-' + '1' * 60,\n"
        "    expected_policy_fingerprint='pol-' + '2' * 60,\n"
        "    expected_relationship_fingerprint='rel-' + '3' * 60,\n"
        "    dbfbridge_version='1.1.0',\n"
        ")\n"
        "vault.acquire_writer_lease(new_writer_token())\n"
        "with vault.transaction():\n"
        "    mappings.create_domain(vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT, domain_id=GLOBAL_TEXT_DOMAIN_ID)\n"
        "    mappings.add_text_mapping(vault, GLOBAL_TEXT_DOMAIN_ID, 'KUND-KEEP', '7XQ2A', logical_byte_length=5)\n"
        "transaction = vault.transaction()\n"
        "transaction.__enter__()\n"
        "mappings.add_text_mapping(vault, GLOBAL_TEXT_DOMAIN_ID, 'KUND-UNCOMMITTED', '9B4D1', logical_byte_length=5)\n"
        "os._exit(9)  # dies mid-transaction: the unit must roll back\n"
    ).format(src=_SRC_ROOT, dictionary=dictionary)
    completed = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, timeout=120
    )
    assert completed.returncode == 9, completed.stderr.decode("utf-8", "replace")
    with VaultDatabase.open(
        dictionary,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as reopened:
        reopened.verify()
        rows = text_mapping_rows(reopened, GLOBAL_TEXT_DOMAIN_ID)
        assert ("KUND-KEEP", "7XQ2A", 5) in rows  # committed before death
        assert all(original != "KUND-UNCOMMITTED" for original, _p, _l in rows)
        assert reopened.stale_writer_lease() is not None  # explicit crash state


# ---------------------------------------------------------------------------
# fresh-vault independence (deterministic, no probabilistic assertion)
# ---------------------------------------------------------------------------
def test_fresh_vaults_are_deterministically_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.vault.store as store_module

    counters: dict[str, int] = {"n": 0}

    def deterministic_id(prefix: str) -> str:
        counters["n"] += 1
        # The injected identity keeps the EXACT valid shape (prefix + 32
        # lowercase hex digits) so the deterministic sequence survives every
        # shape validation while remaining fully deterministic.
        return f"{prefix}{counters['n']:032x}"

    monkeypatch.setattr(store_module, "_new_hex_id", deterministic_id)
    vault_ids: list[str] = []
    offsets: list[int] = []
    for index in (0, 1):
        dictionary = _dictionary(tmp_path / f"vault-{index}")
        with _open_create(dictionary) as vault:
            vault_ids.append(vault.vault_id)
            with writer_session(vault), vault.transaction():
                create_domain(
                    vault, domain_kind=mappings.VAULT_TABLE_DOMAIN_KIND_TEXT,
                    domain_id=GLOBAL_TEXT_DOMAIN_ID,
                )
                add_text_mapping(vault, GLOBAL_TEXT_DOMAIN_ID, "KUND-1", f"7XQ2{index}", logical_byte_length=5)
            temporal = TemporalShiftDomain(
                vault, _random_below=lambda bound, k=index: k
            )
            temporal.observe(date(2020, 1, 1))
            with writer_session(vault):
                offset = temporal.finalize()
            assert offset is not None
            offsets.append(offset)
    # Distinct vault IDs are DETERMINISTIC (injected sequence), never a
    # probabilistic coin flip.
    assert vault_ids[0] != vault_ids[1]
    assert vault_ids[0].startswith("vault-") and vault_ids[1].startswith("vault-")
    # Independently invoked temporal seams produce independent offsets...
    assert offsets[0] != offsets[1]
    # ...and each vault reproduces ITS OWN state exactly on reuse.
    for index in (0, 1):
        with VaultDatabase.open(
            _dictionary(tmp_path / f"vault-{index}"),
            expected_source_fingerprint=SOURCE_FP,
            expected_policy_fingerprint=POLICY_FP,
            expected_relationship_fingerprint=RELATIONSHIP_FP,
        ) as reused:
            assert reused.vault_id == vault_ids[index]
            assert get_text_pseudonym(
                reused, GLOBAL_TEXT_DOMAIN_ID, "KUND-1"
            ) == f"7XQ2{index}"
            temporal = TemporalShiftDomain(
                reused, _random_below=lambda bound: pytest.fail("reuse must not call CSPRNG")
            )
            temporal.observe(date(2020, 1, 1))
            with writer_session(reused):
                assert temporal.finalize() == offsets[index]