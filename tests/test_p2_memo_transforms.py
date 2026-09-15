"""Pure Memo/General/Picture transformation kernels (REQ-P2-007).

The single authoritative model lives in ``dbf_anonymizer.transforms.memo``;
these tests prove the kernels directly:

* the EXACT public logical value vocabulary (``None | str | bytes``);
* NULL preservation and explicit empty-vs-NULL semantics;
* the constant, source-independent safe masks;
* the zero-copy/one-copy ownership rules of the recovery payload;
* fail-closed typed refusal of every unsupported representation.
"""

from __future__ import annotations

import pytest

from dbf_anonymizer import ErrorCode, MappingError
from dbf_anonymizer.transforms import memo as memo_kernels
from dbf_anonymizer.vault import VAULT_PAYLOAD_KIND_BINARY, VAULT_PAYLOAD_KIND_TEXT

CANARY_TEXT = "CANARY-MEMO-ORIGINAL-SECRET"
CANARY_BYTES = b"CANARY-BINARY-ORIGINAL-SECRET\x00\xff"


def _unsupported_value_error(value: object) -> MappingError:
    with pytest.raises(MappingError) as excinfo:
        memo_kernels.memo_safe_mask(value)
    return excinfo.value


def test_mask_policy_version_and_constants() -> None:
    assert memo_kernels.MEMO_MASK_POLICY_VERSION == "1.0"
    assert memo_kernels.MEMO_TEXT_MASK == "[MASKED-MEMO]"
    assert memo_kernels.MEMO_BINARY_MASK == b"[MASKED-MEMO]"
    # Both masks are constant, obviously synthetic, bounded ASCII tokens.
    assert memo_kernels.MEMO_TEXT_MASK.isascii()
    assert memo_kernels.MEMO_BINARY_MASK.isascii()
    assert len(memo_kernels.MEMO_TEXT_MASK) == len(memo_kernels.MEMO_BINARY_MASK)
    # The payload-kind vocabulary is exactly the vault schema vocabulary.
    assert memo_kernels.MEMO_PAYLOAD_KIND_TEXT == VAULT_PAYLOAD_KIND_TEXT
    assert memo_kernels.MEMO_PAYLOAD_KIND_BINARY == VAULT_PAYLOAD_KIND_BINARY
    assert memo_kernels.MEMO_FIELD_TYPES == frozenset({"M", "G", "P"})


def test_masks_cannot_contain_original_values_by_construction() -> None:
    # The masks are fixed literals: no original payload (text or binary)
    # can ever leak through them, for ANY input whatsoever.
    assert CANARY_TEXT not in memo_kernels.MEMO_TEXT_MASK
    assert CANARY_BYTES not in memo_kernels.MEMO_BINARY_MASK
    for value in (
        CANARY_TEXT,
        CANARY_BYTES,
        "",
        b"",
        "\x00\x01\x02",
        "Zażółć gęślą jaźń",
    ):
        mask = memo_kernels.memo_safe_mask(value)
        assert mask in (memo_kernels.MEMO_TEXT_MASK, memo_kernels.MEMO_BINARY_MASK)
        if isinstance(value, bytes):
            assert isinstance(mask, bytes)
            original_bytes = bytes(value)
        else:
            assert isinstance(mask, str)
            original_bytes = value.encode("utf-8")
        # No non-empty byte sequence of the original payload can appear
        # inside the (constant) mask.
        if original_bytes:
            assert original_bytes not in (
                mask.encode("utf-8") if isinstance(mask, str) else mask
            )


def test_is_memo_logical_value_is_the_exact_vocabulary() -> None:
    assert memo_kernels.is_memo_logical_value(None)
    assert memo_kernels.is_memo_logical_value("")
    assert memo_kernels.is_memo_logical_value("text")
    assert memo_kernels.is_memo_logical_value(b"")
    assert memo_kernels.is_memo_logical_value(bytearray(b"x"))
    assert not memo_kernels.is_memo_logical_value(0)
    assert not memo_kernels.is_memo_logical_value(3.14)
    assert not memo_kernels.is_memo_logical_value(memoryview(b"x"))
    assert not memo_kernels.is_memo_logical_value(["x"])
    assert not memo_kernels.is_memo_logical_value(object())


def test_payload_kind_is_type_appropriate() -> None:
    assert memo_kernels.memo_payload_kind("text") == "TEXT"
    assert memo_kernels.memo_payload_kind("") == "TEXT"
    assert memo_kernels.memo_payload_kind(b"") == "BINARY"
    assert memo_kernels.memo_payload_kind(bytearray(b"")) == "BINARY"
    assert memo_kernels.memo_payload_kind(b"\x00\x01") == "BINARY"
    with pytest.raises(MappingError):
        memo_kernels.memo_payload_kind(None)  # NULL carries no payload kind
    with pytest.raises(MappingError):
        memo_kernels.memo_payload_kind(7)


def test_null_preserved_and_empty_distinct() -> None:
    # NULL is identity: no mask at all, never an empty-string mask.
    assert memo_kernels.memo_safe_mask(None) is None
    # Empty payloads are legitimate non-NULL values with their own mask.
    assert memo_kernels.memo_safe_mask("") == memo_kernels.MEMO_TEXT_MASK
    assert memo_kernels.memo_safe_mask(b"") == memo_kernels.MEMO_BINARY_MASK
    assert memo_kernels.memo_payload_kind("") == "TEXT"
    assert memo_kernels.memo_payload_kind(b"") == "BINARY"


def test_recovery_payload_storage_image_is_decided_by_the_vault_once() -> None:
    # The transform kernels stay value-typed: they never encode, hash or
    # derive anything from a payload.  The exact storage image (UTF-8 for
    # TEXT, byte-for-byte for BINARY) is owned by the vault row API in ONE
    # place, proven by the vault evidence suite.
    assert hasattr(memo_kernels, "memo_payload_kind")
    assert not hasattr(memo_kernels, "memo_recovery_payload")


def test_unsupported_representations_fail_closed() -> None:
    for value in (7, 3.14, True, memoryview(b"x"), [b"x"], {"a": 1}, object()):
        with pytest.raises(MappingError) as excinfo:
            memo_kernels.memo_safe_mask(value)
        assert excinfo.value.code is ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE
        with pytest.raises(MappingError):
            memo_kernels.memo_payload_kind(value)
        assert not memo_kernels.is_memo_logical_value(value)


def test_unsupported_error_is_stable_and_value_free() -> None:
    # The typed refusal carries only the registry-controlled classification:
    # no repr of the refused object, no canary value, no path, no SQL.
    canary_int = 987654321
    with pytest.raises(MappingError) as excinfo:
        memo_kernels.memo_safe_mask(canary_int)
    boundary = (
        str(excinfo.value)
        + "|"
        + repr(excinfo.value)
        + "|"
        + _safe_json(excinfo.value)
    )
    assert str(canary_int) not in boundary
    assert "MEMO_UNSUPPORTED_REPRESENTATION" in boundary
    assert "MAPPING_CONSTRAINT_INFEASIBLE" in boundary


def _safe_json(error: MappingError) -> str:
    import json

    return str(json.dumps(error.to_dict(), sort_keys=True))


def test_binary_only_field_kinds_refuse_text_payloads() -> None:
    assert memo_kernels.memo_requires_binary("G")
    assert memo_kernels.memo_requires_binary("P")
    assert not memo_kernels.memo_requires_binary("M")
    for dbf_type in ("C", "V", "W", "Q", "D", "N", "", "MM"):
        with pytest.raises(MappingError):
            memo_kernels.memo_requires_binary(dbf_type)