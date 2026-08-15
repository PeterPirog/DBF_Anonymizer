"""Testy globalnego, odwracalnego słownika SQLite."""
from __future__ import annotations

from pathlib import Path

import pytest

from dbf_anonymizer.global_store import (
    GlobalDictionaryError,
    GlobalDictionaryStore,
    build_common_single_byte_alphabet,
)


def _build(path: Path, values: list[str], salt: str) -> dict[str, str]:
    with GlobalDictionaryStore(path) as store:
        store.initialize(
            options={
                "memo_mode": "mask",
                "date_offset_days": 0,
                "text_mode": "same_length",
            },
            salt=salt,
            text_encodings=["cp1250"],
        )
        store.add_text_values(
            values,
            encoding="cp1250",
            relative_path="test.dbf",
            field_name="VALUE",
        )
        store.assign_anonymous_values(salt=salt)
        return store.forward_many(values)


def test_mapping_is_global_reversible_and_deterministic(tmp_path: Path):
    values = ["K001", "K002", "Jan Kowalski", "Łódź"]
    first = _build(tmp_path / "first.sqlite3", values, "test-salt")
    second = _build(
        tmp_path / "second.sqlite3",
        list(reversed(values)),
        "test-salt",
    )

    assert first == second
    assert len(set(first.values())) == len(values)
    assert all(original != anonymous for original, anonymous in first.items())
    with GlobalDictionaryStore(tmp_path / "first.sqlite3", read_only=True) as store:
        assert store.reverse_many(first.values()) == {
            anonymous: original for original, anonymous in first.items()
        }


def test_cp1250_alphabet_handles_49_one_byte_values(tmp_path: Path):
    values = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./")
    assert len(values) == 49

    mapping = _build(tmp_path / "49-values.sqlite3", values, "capacity")

    assert len(mapping) == 49
    assert len(set(mapping.values())) == 49
    assert all(len(value.encode("cp1250")) == 1 for value in mapping.values())


def test_capacity_error_contains_code_and_sources(tmp_path: Path):
    values = ["A", "B", "C"]
    with GlobalDictionaryStore(tmp_path / "overflow.sqlite3") as store:
        store.initialize(
            options={"memo_mode": "mask", "date_offset_days": 0},
            salt="capacity",
            text_encodings=["cp1250"],
            text_alphabet="AB",
        )
        store.add_text_values(
            values,
            encoding="cp1250",
            relative_path="folder/status.dbf",
            field_name="STATUS",
        )
        with pytest.raises(GlobalDictionaryError) as error:
            store.assign_anonymous_values(salt="capacity")

    message = str(error.value)
    assert "[TEXT_DOMAIN_CAPACITY]" in message
    assert "alphabet_size=\"2\"" in message
    assert "distinct_values=\"3\"" in message
    assert "folder/status.dbf:STATUS:cp1250:3" in message


def test_full_one_byte_domain_is_a_derangement(tmp_path: Path):
    values = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    mapping = _build(tmp_path / "full.sqlite3", values, "full-domain")

    assert len(set(mapping.values())) == len(values)
    assert all(original != anonymous for original, anonymous in mapping.items())


def test_common_alphabet_uses_printable_codepage_characters():
    cp1250 = build_common_single_byte_alphabet(["cp1250"])
    shared = build_common_single_byte_alphabet(["cp1250", "cp852"])

    assert len(cp1250) > 49
    assert len(shared) > 49
    assert all(len(character.encode("cp1250")) == 1 for character in cp1250)
    assert all(len(character.encode("cp1250")) == 1 for character in shared)
    assert all(len(character.encode("cp852")) == 1 for character in shared)
    assert all(character.isprintable() and not character.isspace() for character in cp1250)
    assert len({character.casefold() for character in cp1250}) == len(cp1250)


def test_incremental_generation_preserves_existing_mapping(tmp_path: Path):
    path = tmp_path / "dictionary.sqlite3"
    with GlobalDictionaryStore(path) as store:
        store.initialize(
            options={"memo_mode": "mask", "date_offset_days": 0, "text_mode": "same_length"},
            salt="stable",
            text_encodings=["cp1250"],
        )
        store.add_text_values(
            ["K001"], encoding="cp1250", relative_path="old.dbf", field_name="ID"
        )
        store.assign_anonymous_values(salt="stable")
        old_value = store.forward_many(["K001"])["K001"]
        store.prepare_incremental(
            options={"memo_mode": "mask", "date_offset_days": 0, "text_mode": "same_length"},
            salt="stable",
            text_encodings=["cp1250"],
        )
        store.add_text_values(
            ["K001", "K002"], encoding="cp1250", relative_path="new.dbf", field_name="ID"
        )
        store.assign_anonymous_values(salt="stable")
        mapping = store.forward_many(["K001", "K002"])

    assert mapping["K001"] == old_value
    assert mapping["K002"] != "K002"


def test_missing_mapping_error_does_not_disclose_value(tmp_path: Path):
    path = tmp_path / "dictionary.sqlite3"
    with GlobalDictionaryStore(path) as store:
        store.initialize(options={}, salt="", text_encodings=["cp1250"])
        with pytest.raises(GlobalDictionaryError) as error:
            store.forward_many(["PESEL-SECRET"])

    assert "PESEL-SECRET" not in str(error.value)
    assert "GLOBAL_MAPPING_MISSING" in str(error.value)
