"""Fixtures dla testów DBF_Anonymizer.

Generuje pliki DBF (Visual FoxPro, cp1250, memo) z polskimi znakami,
unikalnymi i nieunikalnymi kolumnami, deleted records — do testów
round-trip anonimizacji.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import dbf
import pytest


@pytest.fixture
def sample_dbf_dir(tmp_path: Path) -> Path:
    """Katalog z jednym plikiem DBF (VFP, cp1250, memo, polskie znaki)."""
    src_dir = tmp_path / "source"
    src_dir.mkdir()
    dbf_path = src_dir / "klienci.dbf"
    _create_sample_table(dbf_path)
    return src_dir


@pytest.fixture
def multi_dbf_dir(tmp_path: Path) -> Path:
    """Katalog z kilkoma plikami DBF w podkatalogach (struktura zagnieżdżona)."""
    src_dir = tmp_path / "source"
    src_dir.mkdir()
    sub = src_dir / "firma"
    sub.mkdir()

    # Tabela 1: klienci.dbf (root) — z memo, polskie znaki, kolumna unikalna (ID)
    _create_sample_table(src_dir / "klienci.dbf")

    # Tabela 2: produkty.dbf (podkatalog) — bez memo, kolumny nieunikalne
    _create_products_table(sub / "produkty.dbf")

    return src_dir


def _create_sample_table(dbf_path: Path) -> None:
    """Tworzy tabelę klienci.dbf: ID C(10) unikalne, NAME C(20), AGE N(3,0),
    ACTIVE L, BORN D, NOTE M (memo), z polskimi znakami i deleted record."""
    # Usuń istniejące pliki jeśli istnieją (idempotentność fixture)
    for ext in (".dbf", ".fpt"):
        p = dbf_path.with_suffix(ext)
        if p.exists():
            p.unlink()

    table = dbf.Table(
        str(dbf_path),
        "ID C(10); NAME C(20); AGE N(3,0); ACTIVE L; BORN D; NOTE M",
        dbf_type="vfp",
        codepage="cp1250",
    )
    table.open(mode=dbf.READ_WRITE)
    records = [
        {"ID": "K001", "NAME": "Jan Kowalski", "AGE": 35, "ACTIVE": True,
         "BORN": dt.date(1980, 5, 12), "NOTE": "Klient VIP — Warszawa"},
        {"ID": "K002", "NAME": "Anna Nowak", "AGE": 28, "ACTIVE": False,
         "BORN": dt.date(1990, 3, 25), "NOTE": ""},
        {"ID": "K003", "NAME": "Piotr Żółw", "AGE": 42, "ACTIVE": True,
         "BORN": dt.date(1975, 11, 30), "NOTE": "Zażółć gęślą jaźń"},
        {"ID": "K004", "NAME": "Maria Skłodowska", "AGE": 51, "ACTIVE": True,
         "BORN": dt.date(1965, 7, 4), "NOTE": "Klient z Krakowa"},
        {"ID": "K005", "NAME": "Zbigniew Wójcik", "AGE": 19, "ACTIVE": False,
         "BORN": dt.date(2001, 1, 15), "NOTE": "Nowy klient"},
    ]
    for rec in records:
        table.append(rec)
    # Oznacz K004 (index 3) jako deleted — bez pack, zachowa fizycznie
    dbf.delete(table[3])
    table.close()


def _create_products_table(dbf_path: Path) -> None:
    """Tworzy tabelę produkty.dbf: bez memo, kolumny nieunikalne, z DateTime."""
    table = dbf.Table(
        str(dbf_path),
        "KOD C(8); NAZWA C(30); CENA N(8,2); ILOSC N(6,0); DATAW D",
        dbf_type="vfp",
        codepage="cp1250",
    )
    table.open(mode=dbf.READ_WRITE)
    records = [
        {"KOD": "P001", "NAZWA": "Klawiatura USB", "CENA": 45.50, "ILOSC": 100,
         "DATAW": dt.date(2024, 1, 15)},
        {"KOD": "P002", "NAZWA": "Mysz optyczna", "CENA": 25.00, "ILOSC": 200,
         "DATAW": dt.date(2024, 2, 20)},
        {"KOD": "P001", "NAZWA": "Klawiatura USB", "CENA": 45.50, "ILOSC": 50,
         "DATAW": dt.date(2024, 3, 10)},  # duplikat KOD/NAZWA — nieunikalne
        {"KOD": "P003", "NAZWA": "Monitor 24\"", "CENA": 350.00, "ILOSC": 30,
         "DATAW": dt.date(2024, 4, 5)},
    ]
    for rec in records:
        table.append(rec)
    table.close()
