"""Testy globalnego, odwracalnego słownika SQLite."""
from __future__ import annotations

from pathlib import Path

import pytest

from dbf_anonymizer.global_store import (
    GlobalDictionaryError,
    GlobalDictionaryStore,
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
        )
        store.add_text_values(values)
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


def test_rejects_more_values_than_fixed_length_domain(tmp_path: Path):
    # Pseudonimy korzystają z 36 znaków; 37 różnych wartości C(1) nie może
    # otrzymać odwracalnego mapowania z zachowaniem długości jednego bajtu.
    values = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") + ["!"]
    with GlobalDictionaryStore(tmp_path / "overflow.sqlite3") as store:
        store.initialize(
            options={"memo_mode": "mask", "date_offset_days": 0},
            salt="capacity",
        )
        store.add_text_values(values)
        with pytest.raises(GlobalDictionaryError, match="odwracalne mapowanie"):
            store.assign_anonymous_values(salt="capacity")


def test_full_one_byte_domain_is_a_derangement(tmp_path: Path):
    values = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    mapping = _build(tmp_path / "full.sqlite3", values, "full-domain")

    assert set(mapping.values()) == set(values)
    assert all(original != anonymous for original, anonymous in mapping.items())
