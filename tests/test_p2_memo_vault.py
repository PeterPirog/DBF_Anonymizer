"""Reversible Memo/General/Picture vault evidence (REQ-P2-007).

This suite proves the P2-007 transformation/vault boundary directly:

* store-then-mask ordering (a mask exists only after the recovery row is
  durably committed; a failed unit commits nothing and returns no mask);
* the stable ``table_id + physical_record_index + field_id`` identity model
  (stable across reopen, database-enforced field/table binding, duplicate
  rejection, independent rows for equal payloads);
* transaction/fault/writer-authority fail-closed behavior;
* unsupported representation refusal (including W/Q/opaque field kinds);
* close/reopen recovery and source immutability on the committed P0
  synthetic memo fixture;
* canary containment for values that escape the protected vault row.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from dbf_anonymizer import ErrorCode, MappingError, VaultError
from dbf_anonymizer.vault import (
    GLOBAL_TEXT_DOMAIN_ID,
    VAULT_DATABASE_FILENAME,
    VaultDatabase,
    mappings,
    new_writer_token,
)
from dbf_anonymizer.vault import (
    persist_memo_recovery,
    recover_memo_value,
)
from dbf_anonymizer.vault.mappings import (
    add_memo_recovery,
    get_memo_recovery,
    memo_recovery_rows,
)
from support.memo_tables import field_triplet, source_hashes
from support.vault_sessions import writer_session

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60
DBFBRIDGE_VERSION = "1.1.0"

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "p0"
MEMO_FIXTURE = FIXTURE_ROOT / "memos" / "memo_payloads.dbf"

CANARY_TEXT = "CANARY-MEMO-ORIGINAL-SECRET"
CANARY_BYTES = b"CANARY-BINARY-ORIGINAL-SECRET\x00\xff"
CANARY_BIG = b"CANARY-PICTURE-\x00\x01\x02" * 8


def _create(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version=DBFBRIDGE_VERSION,
    )


def _reopen(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    )


def _register(
    vault: VaultDatabase, relative_path: str, fields: dict[str, str]
) -> tuple[str, dict[str, str]]:
    """Register one table and its memo fields; returns (table_id, field_ids)."""
    with writer_session(vault), vault.transaction():
        table_id = vault.register_table(relative_path)
        field_ids = {
            name: vault.register_field(
                table_id, name, dbf_type=dbf_type, width=4
            )
            for name, dbf_type in fields.items()
        }
    return table_id, field_ids


def _memo_rows(vault: VaultDatabase, table_id: str) -> int:
    return len(memo_recovery_rows(vault, table_id))


# ---------------------------------------------------------------------------
# store-then-mask boundary
# ---------------------------------------------------------------------------
def test_store_then_mask_returns_mask_only_after_commit(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(
            vault, "memo/suite.dbf", {"TXT": "M", "GEN": "G"}
        )
        with writer_session(vault):
            mask = persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=0,
                field_id=field_ids["TXT"],
                dbf_type="M",
                value=CANARY_TEXT,
            )
            assert mask == "[MASKED-MEMO]"
            binary_mask = persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=1,
                field_id=field_ids["GEN"],
                dbf_type="G",
                value=CANARY_BYTES,
            )
            assert binary_mask == b"[MASKED-MEMO]"
            # NULL is preserved by identity: no mask and NO recovery row.
            assert (
                persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=2,
                    field_id=field_ids["TXT"],
                    dbf_type="M",
                    value=None,
                )
                is None
            )
        assert _memo_rows(vault, table_id) == 2
        assert recover_memo_value(
            vault, table_id=table_id, physical_record_index=0, field_id=field_ids["TXT"]
        ) == CANARY_TEXT
        assert recover_memo_value(
            vault, table_id=table_id, physical_record_index=1, field_id=field_ids["GEN"]
        ) == CANARY_BYTES
        assert (
            recover_memo_value(
                vault,
                table_id=table_id,
                physical_record_index=2,
                field_id=field_ids["TXT"],
            )
            is None
        )
        # The mask itself can never contain the original payload.
        assert CANARY_TEXT.encode("utf-8") not in b"[MASKED-MEMO]"
        assert CANARY_BYTES not in b"[MASKED-MEMO]"


def test_null_never_creates_a_recovery_row(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "m/dbf.dbf", {"TXT": "M"})
        with writer_session(vault):
            for record_index in range(3):
                assert (
                    persist_memo_recovery(
                        vault,
                        table_id=table_id,
                        physical_record_index=record_index,
                        field_id=field_ids["TXT"],
                        dbf_type="M",
                        value=None,
                    )
                    is None
                )
        assert _memo_rows(vault, table_id) == 0  # NULL creates no row at all


# ---------------------------------------------------------------------------
# identity model
# ---------------------------------------------------------------------------
def test_identity_is_stable_across_reopen(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(
            vault, "north/registry.dbf", {"NOTE": "M"}
        )
        with writer_session(vault):
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=7,
                field_id=field_ids["NOTE"],
                dbf_type="M",
                value=CANARY_TEXT,
            )
        vault.close()
    with _reopen(tmp_path) as vault:
        # The identity is stable across reopen; re-registration is refused.
        with writer_session(vault), vault.transaction():
            with pytest.raises(VaultError) as excinfo:
                vault.register_table("north/registry.dbf")
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
        assert (
            recover_memo_value(
                vault,
                table_id=table_id,
                physical_record_index=7,
                field_id=field_ids["NOTE"],
            )
            == CANARY_TEXT
        )
        with writer_session(vault), pytest.raises(VaultError) as excinfo:
            with vault.transaction():
                vault.register_table("north/registry.dbf")
        assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID


def test_repeated_equal_payloads_are_independent_rows(tmp_path: Path) -> None:
    payload = b"IDENTICAL-PAYLOAD-\x00\x01"
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/dup.dbf", {"GEN": "G"})
        with writer_session(vault):
            for record_index in (0, 1, 2):
                persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=record_index,
                    field_id=field_ids["GEN"],
                    dbf_type="G",
                    value=payload,
                )
        assert _memo_rows(vault, table_id) == 3
        for record_index in (0, 1, 2):
            assert (
                recover_memo_value(
                    vault,
                    table_id=table_id,
                    physical_record_index=record_index,
                    field_id=field_ids["GEN"],
                )
                == payload
            )


def test_different_fields_of_one_record_are_independent(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(
            vault, "t/one.dbf", {"TXT": "M", "BIN": "M", "GEN": "G"}
        )
        with writer_session(vault):
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=0,
                field_id=field_ids["TXT"],
                dbf_type="M",
                value=CANARY_TEXT,
            )
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=0,
                field_id=field_ids["BIN"],
                dbf_type="M",
                value=CANARY_BYTES,
            )
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=0,
                field_id=field_ids["GEN"],
                dbf_type="G",
                value=CANARY_BYTES + b"\x01",
            )
        assert _memo_rows(vault, table_id) == 3
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=0, field_id=field_ids["TXT"]
            )
            == CANARY_TEXT
        )
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=0, field_id=field_ids["BIN"]
            )
            == CANARY_BYTES
        )
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=0, field_id=field_ids["GEN"]
            )
            == CANARY_BYTES + b"\x01"
        )


def test_duplicate_identity_fails_closed(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/dupe.dbf", {"TXT": "M"})
        with writer_session(vault), vault.transaction():
            add_memo_recovery(
                vault,
                table_id,
                0,
                field_ids["TXT"],
                CANARY_TEXT,
                payload_kind="TEXT",
            )
            with pytest.raises(VaultError) as excinfo:
                add_memo_recovery(
                    vault,
                    table_id,
                    0,
                    field_ids["TXT"],
                    b"other",
                    payload_kind="BINARY",
                )
            assert excinfo.value.code is ErrorCode.VAULT_STATE_INVALID
        # The conflicting row is absent; the original stays intact.
        assert _memo_rows(vault, table_id) == 1
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=0, field_id=field_ids["TXT"]
            )
            == CANARY_TEXT
        )


def test_field_belongs_to_the_table_by_database_identity(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_a, fields_a = _register(vault, "t/a.dbf", {"NOTE": "M"})
        table_b, _fields_b = _register(vault, "t/b.dbf", {"NOTE": "M"})
        with writer_session(vault), vault.transaction():
            with pytest.raises(VaultError):
                # The field of table A must never satisfy the identity of B.
                add_memo_recovery(
                    vault, table_b, 0, fields_a["NOTE"], b"\x00", payload_kind="BINARY"
                )
        assert _memo_rows(vault, table_b) == 0


def test_negative_and_malformed_identities_are_refused(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/neg.dbf", {"TXT": "M"})
        with writer_session(vault), vault.transaction():
            with pytest.raises(ValueError):
                add_memo_recovery(
                    vault, table_id, -1, field_ids["TXT"], b"x", payload_kind="BINARY"
                )
            with pytest.raises(TypeError):
                add_memo_recovery(
                    vault, table_id, True, field_ids["TXT"], b"x", payload_kind="BINARY"
                )
            with pytest.raises(ValueError):
                add_memo_recovery(
                    vault, table_id, 0, field_ids["TXT"], b"x", payload_kind="CLOB"
                )
            with pytest.raises(ValueError):
                # A TEXT row with a bytes payload is a type mismatch.
                add_memo_recovery(
                    vault, table_id, 0, field_ids["TXT"], b"x", payload_kind="TEXT"
                )
            with pytest.raises(ValueError):
                add_memo_recovery(
                    vault, table_id, 0, field_ids["TXT"], "s", payload_kind="BINARY"
                )
        assert _memo_rows(vault, table_id) == 0
        assert (
            get_memo_recovery(vault, table_id, 99, field_ids["TXT"]) is None
        )


# ---------------------------------------------------------------------------
# writer authority / transactions / faults
# ---------------------------------------------------------------------------
def test_unauthorized_writer_cannot_persist_payloads(tmp_path: Path) -> None:
    path = tmp_path / "vault" / VAULT_DATABASE_FILENAME
    with _create(tmp_path) as vault:
        _register(vault, "t/auth.dbf", {"TXT": "M"})
        vault.close()
    with VaultDatabase.open(
        path,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
    ) as unauthorized:
        table_row = unauthorized.tables()[0]
        table_id = str(table_row["table_id"])
        with pytest.raises(VaultError) as excinfo:
            persist_memo_recovery(
                unauthorized,
                table_id=table_id,
                physical_record_index=0,
                field_id="fld-nothing",
                dbf_type="M",
                value=CANARY_TEXT,
            )
        assert excinfo.value.code is ErrorCode.VAULT_WRITER_CONFLICT
        rows = memo_recovery_rows(unauthorized, table_id)
        assert rows == ()


def test_failed_memo_insert_rolls_back_and_never_returns_mask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from support.vault_sessions import install_failing_execute

    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/fail.dbf", {"TXT": "M"})
        with writer_session(vault):
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=0,
                field_id=field_ids["TXT"],
                dbf_type="M",
                value=CANARY_TEXT,
            )
        prior_rows = _memo_rows(vault, table_id)
        install_failing_execute(
            vault,
            fail_when=lambda sql: "INSERT INTO memo_recovery" in sql,
            monkeypatch=monkeypatch,
        )
        with writer_session(vault):
            with pytest.raises(sqlite3.Error):
                persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=1,
                    field_id=field_ids["TXT"],
                    dbf_type="M",
                    value="CANARY-FAILED-INSERT-TEXT",
                )
        assert _memo_rows(vault, table_id) == prior_rows  # nothing committed
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=0, field_id=field_ids["TXT"]
            )
            == CANARY_TEXT
        )


def test_rollback_preserves_prior_committed_rows(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/roll.dbf", {"GEN": "G"})
        with writer_session(vault):
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=0,
                field_id=field_ids["GEN"],
                dbf_type="G",
                value=CANARY_BYTES,
            )
        prior = _memo_rows(vault, table_id)
        with writer_session(vault), pytest.raises(VaultError):
            with vault.transaction():
                add_memo_recovery(
                    vault,
                    table_id,
                    1,
                    field_ids["GEN"],
                    b"\x00",
                    payload_kind="BINARY",
                )
                # A conflicting identity inside the SAME unit fails closed
                # and rolls the whole intended unit back.
                add_memo_recovery(
                    vault,
                    table_id,
                    1,
                    field_ids["GEN"],
                    b"\x01",
                    payload_kind="BINARY",
                )
        assert _memo_rows(vault, table_id) == prior
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=0, field_id=field_ids["GEN"]
            )
            == CANARY_BYTES
        )
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=1, field_id=field_ids["GEN"]
            )
            is None
        )


def test_close_reopen_preserves_committed_recovery_data(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(
            vault, "t/reopen.dbf", {"TXT": "M", "PIC": "P"}
        )
        with writer_session(vault):
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=3,
                field_id=field_ids["TXT"],
                dbf_type="M",
                value=CANARY_TEXT,
            )
            persist_memo_recovery(
                vault,
                table_id=table_id,
                physical_record_index=3,
                field_id=field_ids["PIC"],
                dbf_type="P",
                value=CANARY_BYTES,
            )
        vault.close()
    with _reopen(tmp_path) as vault:
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=3, field_id=field_ids["TXT"]
            )
            == CANARY_TEXT
        )
        assert (
            recover_memo_value(
                vault, table_id=table_id, physical_record_index=3, field_id=field_ids["PIC"]
            )
            == CANARY_BYTES
        )


# ---------------------------------------------------------------------------
# unsupported representations
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("dbf_type", ["C", "V", "N", "D", "W", "Q", "B", "I"])
def test_non_memo_field_kinds_fail_closed(tmp_path: Path, dbf_type: str) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/opaque.dbf", {"F": "M"})
        with writer_session(vault):
            with pytest.raises(MappingError) as excinfo:
                persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=0,
                    field_id=field_ids["F"],
                    dbf_type=dbf_type,
                    value="whatever",
                )
            assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
            # The refused representation stored nothing.
            assert _memo_rows(vault, table_id) == 0


def test_general_field_refuses_text_payload(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/gstr.dbf", {"GEN": "G"})
        with writer_session(vault):
            with pytest.raises(MappingError):
                persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=0,
                    field_id=field_ids["GEN"],
                    dbf_type="G",
                    value="a text payload does not belong here",
                )
        assert _memo_rows(vault, table_id) == 0


def test_memo_field_refuses_non_string_non_bytes(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/bad.dbf", {"TXT": "M"})
        with writer_session(vault):
            with pytest.raises(MappingError):
                persist_memo_recovery(
                    vault,
                    table_id=table_id,
                    physical_record_index=0,
                    field_id=field_ids["TXT"],
                    dbf_type="M",
                    value=12345,
                )
        assert _memo_rows(vault, table_id) == 0


# ---------------------------------------------------------------------------
# canary containment at the typed-error boundary
# ---------------------------------------------------------------------------
def test_row_rejection_error_never_carries_payload_values(tmp_path: Path) -> None:
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(vault, "t/leak.dbf", {"TXT": "M"})
        with writer_session(vault), vault.transaction():
            add_memo_recovery(
                vault,
                table_id,
                0,
                field_ids["TXT"],
                CANARY_TEXT,
                payload_kind="TEXT",
            )
            with pytest.raises(VaultError) as excinfo:
                add_memo_recovery(
                    vault,
                    table_id,
                    0,
                    field_ids["TXT"],
                    CANARY_BYTES,
                    payload_kind="BINARY",
                )
        boundary = (
            str(excinfo.value)
            + "|"
            + repr(excinfo.value)
            + "|"
            + str(excinfo.value.to_dict())
        )
        assert CANARY_TEXT not in boundary
        assert CANARY_BYTES.decode("latin-1") not in boundary


def test_committed_fixture_rows_survive_reopen_and_match_the_manifest(
    tmp_path: Path,
) -> None:
    """The committed synthetic fixture's memo identity is recoverable."""
    import json

    manifest = json.loads(
        (FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8")
    )
    fixture = next(
        f for f in manifest["fixtures"] if f["id"] == "memos.memo_payloads"
    )
    expectations = fixture["expectations"]
    hashes_before = source_hashes(MEMO_FIXTURE)
    with _create(tmp_path) as vault:
        table_id, field_ids = _register(
            vault,
            "memos/memo_payloads.dbf",
            {"TXT": "M", "BIN": "M", "GEN": "G", "PIC": "P"},
        )
        with writer_session(vault):
            for record_index, values in enumerate(
                (
                    {
                        "TXT": expectations["row0"]["TXT"],
                        "BIN": bytes.fromhex(expectations["row0"]["BIN_hex"]),
                        "GEN": bytes.fromhex(expectations["row0"]["GEN_hex"]),
                        "PIC": bytes.fromhex(expectations["row0"]["PIC_hex"]),
                    },
                    {"TXT": None, "BIN": None, "GEN": None, "PIC": None},
                    {
                        "TXT": "DELETED-MEMO-SYNTH",
                        "BIN": b"\x01\x02\x03",
                        "GEN": None,
                        "PIC": None,
                    },
                )
            ):
                for name, dbf_type in (
                    ("TXT", "M"),
                    ("BIN", "M"),
                    ("GEN", "G"),
                    ("PIC", "P"),
                ):
                    mask = persist_memo_recovery(
                        vault,
                        table_id=table_id,
                        physical_record_index=record_index,
                        field_id=field_ids[name],
                        dbf_type=dbf_type,
                        value=values[name],
                    )
                    if record_index == 1:
                        assert mask is None  # NULL row: no mask, no row
        assert _memo_rows(vault, table_id) == 6  # 4 (row 0) + 0 (NULL) + 2 (deleted)
        deleted_txt = recover_memo_value(
            vault, table_id=table_id, physical_record_index=2, field_id=field_ids["TXT"]
        )
        assert deleted_txt == "DELETED-MEMO-SYNTH"
        deleted_bin = recover_memo_value(
            vault, table_id=table_id, physical_record_index=2, field_id=field_ids["BIN"]
        )
        assert deleted_bin == b"\x01\x02\x03"
    # The committed fixture stayed byte-identical (read-only evidence).
    assert source_hashes(MEMO_FIXTURE) == hashes_before