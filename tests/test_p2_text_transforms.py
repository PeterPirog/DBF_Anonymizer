"""Pure shared text-domain kernels (REQ-P2-004/005/006 + REQ-P1-006 parity).

The single authoritative mathematical model lives in
``dbf_anonymizer.transforms.text``; these tests prove the kernels directly
AND that the read-only preflight capacity proof binds the SAME kernels (one
mathematical model, two consumers — never two independent models).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import dbf_anonymizer.transforms.text as text_kernels
from dbf_anonymizer.transforms.text import (
    SAFE_TEXT_ALPHABET,
    TEXT_ALPHABET_POLICY_VERSION,
    candidate_alphabet,
    encoded_byte_length,
    is_safe_token,
    max_encoded_byte_length,
    reduced_strictest,
    token_at,
    token_index,
    token_space,
    token_space_at_least,
)

_BASE36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


# ---------------------------------------------------------------------------
# safe alphabet policy
# ---------------------------------------------------------------------------
def test_safe_alphabet_is_the_conservative_single_case_base36() -> None:
    assert SAFE_TEXT_ALPHABET == _BASE36
    assert TEXT_ALPHABET_POLICY_VERSION == "1.0"
    assert len(set(SAFE_TEXT_ALPHABET)) == len(SAFE_TEXT_ALPHABET) == 36


def test_candidate_alphabet_provable_single_byte_encodings() -> None:
    for encoding in ("cp1250", "cp852", "ascii", "latin-1"):
        assert candidate_alphabet(frozenset({encoding})) == _BASE36
    # The mixed domain keeps exactly the intersection (still the full set).
    assert candidate_alphabet(frozenset({"cp1250", "cp852"})) == _BASE36


def test_candidate_alphabet_fails_closed_for_unprovable_encodings() -> None:
    # An encoding name that no codec registry can resolve (and that the
    # dbfbridge boundary never establishes) is UNPROVABLE: the provable
    # alphabet is empty and every consumer must fail closed. Mazovia/PIAST
    # become provable through the dbfbridge operation-time codec
    # registration (positive evidence lives in the allocation suite); no
    # Python codec aliases are ever invented by this package.
    assert candidate_alphabet(frozenset({"no-such-codec"})) == ""
    assert candidate_alphabet(frozenset({"cp1250", "no-such-codec"})) == ""


def test_mazovia_piast_become_provable_after_the_public_dbfbridge_read() -> None:
    # The public dbfbridge boundary establishes its custom code pages at
    # operation time: reading the committed Mazovia fixture schema is the
    # exact pipeline step that makes the encoding names provable. This is
    # dependency behavior — this package invents no aliases of its own.
    from dbfbridge import read_schema

    schema = read_schema(
        Path(__file__).resolve().parent / "fixtures" / "p0" / "text" / "text_mazovia.dbf"
    )
    assert schema.encoding == "mazovia"
    assert candidate_alphabet(frozenset({"mazovia"})) == _BASE36
    assert candidate_alphabet(frozenset({"piast"})) == _BASE36
    assert candidate_alphabet(frozenset({"cp1250", "cp852", "mazovia", "piast"})) == _BASE36
    assert encoded_byte_length("A", "mazovia") == 1
    assert encoded_byte_length("A", "piast") == 1


def test_encoded_byte_lengths_are_actual_bytes_not_character_counts() -> None:
    assert encoded_byte_length("AB9", "cp1250") == 3
    assert encoded_byte_length("A", "cp852") == 1
    assert encoded_byte_length("ÄÖÜ", "cp1250") == 3  # single bytes in cp1250
    assert encoded_byte_length("ÄÖÜ", "ascii") is None  # unprovable -> None
    assert encoded_byte_length("AB", "no-such-codec") is None
    assert max_encoded_byte_length("AB", ("cp1250", "cp852")) == 2
    assert max_encoded_byte_length("ÄB", ("cp1250", "ascii")) is None
    assert max_encoded_byte_length("AB", ("cp1250", "ascii")) == 2
    # No participating encoding proves nothing: the conservative result is
    # None (fail closed), never an assumed length.
    assert max_encoded_byte_length("AB", ()) is None


# ---------------------------------------------------------------------------
# strictest-width reduction (order independence)
# ---------------------------------------------------------------------------
def test_reduced_strictest_is_the_minimum_and_order_independent() -> None:
    assert reduced_strictest(None, 7) == 7
    assert reduced_strictest(7, 3) == 3
    assert reduced_strictest(3, 7) == 3  # later wider occurrence changes nothing
    assert reduced_strictest(4, 4) == 4
    with pytest.raises(ValueError):
        reduced_strictest(None, -1)


# ---------------------------------------------------------------------------
# finite token space and the exact/streamed equivalence
# ---------------------------------------------------------------------------
def test_token_space_matches_the_geometric_formula() -> None:
    assert token_space(0, 36) == 0
    assert token_space(1, 36) == 36
    assert token_space(2, 36) == 36 + 36 * 36
    assert token_space(3, 2) == 2 + 4 + 8
    with pytest.raises(ValueError):
        token_space(-1, 36)
    with pytest.raises(ValueError):
        token_space(1, 0)


def test_streamed_predicate_and_exact_count_are_one_formula() -> None:
    for width in range(0, 9):
        for base in (1, 2, 3, 36):
            exact = token_space(width, base)
            assert token_space_at_least(width, base, exact) is True
            assert token_space_at_least(width, base, exact + 1) is False
            for needed in (0, 1, exact // 2 + 1, exact):
                assert token_space_at_least(width, base, needed) == (exact >= needed)
    # Historical preflight edge semantics are preserved exactly.
    assert token_space_at_least(0, 36, 0) is True
    assert token_space_at_least(0, 36, 1) is False
    assert token_space_at_least(-1, 36, -1) is True
    assert token_space_at_least(5, 0, 0) is True


# ---------------------------------------------------------------------------
# exact index/token bijection
# ---------------------------------------------------------------------------
def test_token_at_and_token_index_are_exact_bijections() -> None:
    total_2 = token_space(2, 36)
    seen: set[str] = set()
    for index in range(total_2):
        token = text_kernels.token_at(index, 2, _BASE36)
        assert is_safe_token(token, _BASE36)
        assert len(token) in (1, 2)
        assert token_index(token, _BASE36) == index
        seen.add(token)
    assert len(seen) == total_2
    # Block ordering: all length-1 tokens precede the length-2 block.
    assert text_kernels.token_at(0, 2, _BASE36) == "A"
    assert text_kernels.token_at(35, 2, _BASE36) == "9"
    assert text_kernels.token_at(36, 2, _BASE36) == "AA"
    assert text_kernels.token_at(total_2 - 1, 2, _BASE36) == "99"


def test_token_at_bounds_are_rejected() -> None:
    with pytest.raises(ValueError):
        text_kernels.token_at(-1, 2, _BASE36)
    with pytest.raises(ValueError):
        text_kernels.token_at(token_space(2, 36), 2, _BASE36)
    with pytest.raises(ValueError):
        text_kernels.token_at(0, 0, _BASE36)
    with pytest.raises(ValueError):
        text_kernels.token_at(0, 3, "")


def test_is_safe_token_rejects_normalization_and_non_alphabet_text() -> None:
    assert is_safe_token("ABC", _BASE36) is True
    assert is_safe_token("A0", _BASE36) is True
    assert is_safe_token("", _BASE36) is False
    assert is_safe_token("abc", _BASE36) is False
    assert is_safe_token("AB!", _BASE36) is False
    assert is_safe_token(" AB", _BASE36) is False
    assert is_safe_token("Ä", _BASE36) is False


# ---------------------------------------------------------------------------
# ONE authoritative model for preflight and allocation
# ---------------------------------------------------------------------------
def test_preflight_binds_the_same_shared_kernels() -> None:
    # The preflight capacity proof must not carry a second mathematical
    # model: its private names are the shared pure kernels. The module
    # object is resolved through sys.modules because the package attribute
    # ``preflight`` is shadowed by the public ``preflight`` function.
    module = sys.modules["dbf_anonymizer.preflight"]
    assert module._candidate_alphabet is candidate_alphabet
    assert module._token_space_at_least is token_space_at_least
    assert module._CANDIDATE_ALPHABET is SAFE_TEXT_ALPHABET


def test_transforms_package_is_pure() -> None:
    import ast
    from pathlib import Path

    root = Path(text_kernels.__file__).parent
    for path in (root / "__init__.py", root / "text.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] == "ast" or not alias.name.startswith(
                        ("random", "secrets", "sqlite3", "dbfbridge")
                    ), alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith(("random", "secrets", "sqlite3", "dbfbridge")), module