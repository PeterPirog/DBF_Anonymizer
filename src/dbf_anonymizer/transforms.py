"""Transformacje per typ DBF — anonimizacja i odwracanie (recovery).

Każda funkcja transform_* przyjmuje wartość oryginalną i zwraca zaanonimizowaną.
Funkcja recover_* przyjmuje zaanonimizowaną i zwraca oryginalną (odwrotność).

Zasady:
- C (Character): ciąg o identycznej długości BAJTOWEJ w cp1250, deterministyczny.
  Długość bajtowa ≠ długość znakowa dla znaków >1 bajtu (polskie diakrytyki).
- M/G (Memo/General): 'MEMO' (tryb mask) lub zachowaj (tryb keep).
- D (Date): offset o N dni (stały dla katalogu).
- T (DateTime): offset o N dni (część daty), zachowaj czas.
- N/F (Numeric/Float), L (Logical): identity (bez zmian).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import random
from typing import Any

# Mask dla pól memo (tryb mask)
MEMO_MASK = "MEMO"

# Alfabet do generowania zaanonimizowanych ciągów (ASCII, 1 bajt w cp1250).
# Używamy wielkich liter i cyfr — bezpieczne dla cp1250 i DBF Character.
_MASK_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _seed_for(value: str, salt: str) -> int:
    """Deterministyczna inicjalizacja RNG z wartości i soli."""
    h = hashlib.sha256(f"{salt}|{value}".encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big")


def _byte_len(text: str, encoding: str) -> int:
    """Długość tekstu w bajtach w zadanej stronie kodowej.

    Błąd kodowania jest celowo propagowany. Cichy fallback do UTF-8 dawałby
    długość niezgodną z fizycznym polem DBF i mógłby prowadzić do obcięcia danych.
    """
    return len(text.encode(encoding, errors="strict"))


def _byte_len_cp1250(text: str) -> int:
    """Zgodność starszego API: długość tekstu w bajtach CP1250."""
    return _byte_len(text, "cp1250")


def _gen_masked_string(byte_length: int, value: str, salt: str) -> str:
    """Generuje ciąg o zadanej długości BAJTOWEJ w cp1250, deterministycznie.

    Złożenie znaków z alfabetu 1-bajtowego, więc długość znakowa == bajtowa.
    """
    if byte_length <= 0:
        return ""
    rng = random.Random(_seed_for(value, salt))
    chars = [rng.choice(_MASK_ALPHABET) for _ in range(byte_length)]
    return "".join(chars)


# ---------------------------------------------------------------------------
# Character (C) — same byte length, deterministic
# ---------------------------------------------------------------------------

def mask_char(value: Any, length: int | None, salt: str = "") -> str:
    """Zastępuje ciąg znaków ciągiem o identycznej długości bajtowej cp1250.

    Puste/None → puste. Długość z wymuszenia `length` (z schematu) lub z wartości.
    Spacje końcowe (trailing) są zachowane w długości (typowe dla DBF C).
    """
    if value is None:
        return None  # type: ignore[return-value]
    sval = str(value)
    if sval == "":
        return ""
    # Długość bajtowa oryginału; jeśli podano length z schematu, użyj mniejszej
    # (oryginał nie może być dłuższy niż pole, ale wartość może być krótsza).
    orig_bytes = _byte_len_cp1250(sval)
    target = min(orig_bytes, length) if length else orig_bytes
    if target <= 0:
        return ""
    return _gen_masked_string(target, sval, salt)


def recover_char(anon_value: Any, original_value: str | None = None) -> str | None:
    """Odwrócenie mask_char — wymaga oryginalnej wartości ze słownika.

    Przy recovery wartość oryginalna jest pobierana ze słownika (mapowanie
    anon→original), więc ta funkcja jest tylko passthrough/sprawdzalna.
    """
    # Realne odwrócenie odbywa się przez słownik (bijekcja/mapowanie).
    # Ta funkcja istnieje dla symetriii API i testów.
    return original_value


# ---------------------------------------------------------------------------
# Memo (M) / General (G)
# ---------------------------------------------------------------------------

def mask_memo(value: Any, mode: str = "mask") -> str | None:
    """Anonimizacja memo: 'mask' → 'MEMO', 'keep' → wartość bez zmian."""
    if value is None:
        return None
    if mode == "keep":
        return value
    # mode == 'mask'
    return MEMO_MASK


def recover_memo(anon_value: Any, original_value: Any = None, mode: str = "mask") -> Any:
    """Odwrócenie mask_memo — przywraca oryginał ze słownika (tryb mask)."""
    if mode == "keep":
        return anon_value
    return original_value


# ---------------------------------------------------------------------------
# Date (D) / DateTime (T) — offset dni
# ---------------------------------------------------------------------------

def _parse_iso_date(value: Any) -> dt.date | None:
    if value is None or value == "":
        return None
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.datetime):
        return value.date()
    s = str(value)
    # Format ISO: YYYY-MM-DD
    try:
        return dt.date.fromisoformat(s[:10])
    except ValueError:
        return None


def _parse_iso_datetime(value: Any) -> dt.datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day)
    s = str(value)
    try:
        return dt.datetime.fromisoformat(s)
    except ValueError:
        return None


def shift_date(value: Any, offset_days: int = 0) -> str | None:
    """Przesuwa datę (D) o offset_days. Zwraca ISO string (zgodny z JSONL dbfbridge).

    None/empty → None. offset_days=0 → bez zmian.
    """
    if offset_days == 0:
        return value if value is not None else None
    d = _parse_iso_date(value)
    if d is None:
        return None
    shifted = d + dt.timedelta(days=offset_days)
    return shifted.isoformat()


def shift_datetime(value: Any, offset_days: int = 0) -> str | None:
    """Przesuwa DateTime (T) o offset_days (część daty), zachowuje czas.

    None/empty → None. offset_days=0 → bez zmian.
    """
    if offset_days == 0:
        return value if value is not None else None
    dtm = _parse_iso_datetime(value)
    if dtm is None:
        return None
    shifted = dtm + dt.timedelta(days=offset_days)
    return shifted.isoformat()


def recover_date(anon_value: Any, offset_days: int = 0) -> str | None:
    """Odwrócenie shift_date — przesunięcie w przeciwnym kierunku."""
    return shift_date(anon_value, offset_days=-offset_days)


def recover_datetime(anon_value: Any, offset_days: int = 0) -> str | None:
    """Odwrócenie shift_datetime — przesunięcie w przeciwnym kierunku."""
    return shift_datetime(anon_value, offset_days=-offset_days)


# ---------------------------------------------------------------------------
# Numeric (N/F), Logical (L) — identity
# ---------------------------------------------------------------------------

def identity(value: Any) -> Any:
    """Zwraca wartość bez zmian (N/F/L)."""
    return value


def recover_identity(value: Any) -> Any:
    """Odwrócenie identity — bez zmian."""
    return value
