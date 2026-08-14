"""Detekcja unikatowych kolumn C i budowa bijekcji do anonimizacji.

Zasada (potwierdzona z użytkownikiem): pole tekstowe jest unikatowe, jeśli wszystkie
wartości w kolumnie są unikalne (liczba unikalnych == liczba rekordów). Wtedy po
anonimizacji wartości muszą pozostać unikatowe — budujemy bijekcję (distinct value
→ distinct masked value o tej samej długości bajtowej).

Dla nieunikatowych kolumn: mapowanie 1:1 (ten sam oryginał → ta sama wartość
zaanonimizowana), co zachowuje powtarzalność wzorców bez kolizji.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .transforms import _byte_len_cp1250, _gen_masked_string


@dataclass
class ColumnMapping:
    """Mapowanie oryginał↔anonim dla jednej kolumny C."""
    field_name: str
    unique: bool
    # oryginał → anonim (używane przy anonymize)
    forward: dict[str, str] = field(default_factory=dict)
    # anonim → oryginał (używane przy recovery; budowane z forward)
    # backward: dict[str, str] = field(default_factory=dict)

    def build_backward(self) -> dict[str, str]:
        """Buduje odwrócone mapowanie anonim→oryginał dla recovery."""
        return {v: k for k, v in self.forward.items()}


def detect_unique_columns(records: list[dict[str, Any]], c_field_names: list[str]) -> dict[str, bool]:
    """Dla każdej kolumny C sprawdza, czy wszystkie wartości są unikalne.

    Pomija None i "" (traktuje jako brak wartości, nie psuje unikalności).
    Rekordy z wartościami None/"" dla pola → pole może nadal być unikatowe
    wśród niepustych wartości, ale zachowujemy ścisłą definicję:
    unikatowe = liczba unikalnych niepustych == liczba niepustych wystąpień
    AND nie ma duplikatów.
    """
    result: dict[str, bool] = {}
    for fname in c_field_names:
        seen: set[str] = set()
        non_empty = 0
        is_unique = True
        for rec in records:
            val = rec.get(fname)
            if val is None or val == "":
                continue
            sval = str(val)
            non_empty += 1
            if sval in seen:
                is_unique = False
                break
            seen.add(sval)
        # Unikatowe tylko jeśli są jakieś dane i brak duplikatów
        result[fname] = is_unique and non_empty > 0
    return result


def build_column_mapping(
    field_name: str,
    records: list[dict[str, Any]],
    length: int | None,
    unique: bool,
    salt: str = "",
) -> ColumnMapping:
    """Buduje mapowanie oryginał→anonim dla kolumny C.

    - Dla każdej unikalnej wartości generuje unikalny ciąg anonimowy tej samej
      długości bajtowej (bijekcja).
    - Gwarantuje, że anonimowane wartości są unikatowe (dla unikatowych kolumn)
      przez dodanie indeksu do soli gdy kolizja.
    """
    mapping = ColumnMapping(field_name=field_name, unique=unique)

    # Zbierz unikalne niepust wartości w kolejności pierwszego wystąpienia
    distinct_values: list[str] = []
    seen: set[str] = set()
    for rec in records:
        val = rec.get(field_name)
        if val is None or val == "":
            continue
        sval = str(val)
        if sval not in seen:
            seen.add(sval)
            distinct_values.append(sval)

    if not distinct_values:
        return mapping

    # Generuj anonimy — unikatowe wewnątrz kolumny (dla unikatowych kolumn
    # to bijekcja; dla nieunikatowych też unikatowe, by mapowanie było 1:1).
    used_anons: set[str] = set()
    for idx, value in enumerate(distinct_values):
        target_bytes = _byte_len_cp1250(value)
        if length is not None:
            target_bytes = min(target_bytes, length)
        if target_bytes <= 0:
            continue
        # Generuj z solą + indeksem (by uniknąć kolizji dla różnych wartości
        # tej samej długości — _gen_masked_string jest deterministyczny z value).
        anon = _gen_masked_string(target_bytes, value, f"{salt}|{field_name}|{idx}")
        # Jeśli kolizja (mało prawdopodobne), próbuj z rosnącym indeksem
        attempt = idx
        while anon in used_anons and attempt < idx + 10000:
            attempt += 1
            anon = _gen_masked_string(target_bytes, value, f"{salt}|{field_name}|{attempt}")
        if anon in used_anons:
            raise ValueError(
                f"Nie można utworzyć odwracalnego mapowania dla pola {field_name}: "
                f"za mało unikalnych masek o długości {target_bytes}"
            )
        used_anons.add(anon)
        mapping.forward[value] = anon

    return mapping
