"""Versioned authoritative field-capability contract (REQ-P4-004)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from dbf_anonymizer.policy import (
    FIELD_CAPABILITY_MATRIX_VERSION,
    classify_field_capability,
    field_capability_matrix_snapshot,
    resolve_policy,
)


def _policy() -> dict[str, Any]:
    return resolve_policy(None)[0]


EXPECTED_MATRIX = {
    "schema_version": "1.0",
    "trusted_system_field": {
        "dbf_type": "0",
        "name": "_NULLFLAGS",
        "system": True,
        "disposition": "WRITER_MANAGED",
    },
    "fallback_disposition": "UNSAFE",
    "rules": [
        {
            "dbf_types": ["C", "V"],
            "logical_class": "TEXT",
            "disposition": "TRANSFORM",
            "default_action": "PSEUDONYMIZE_REVERSIBLE",
            "policy_section": "text",
            "policy_key": "default_action",
            "binary_descriptor_allowed": False,
            "nocptrans_allowed": False,
        },
        {
            "dbf_types": ["M"],
            "logical_class": "MEMO_TEXT_OR_BINARY_PAYLOAD",
            "disposition": "TRANSFORM",
            "default_action": "MASK_REVERSIBLE",
            "policy_section": "memo",
            "policy_key": "text",
            "binary_descriptor_allowed": False,
            "nocptrans_allowed": False,
        },
        {
            "dbf_types": ["G", "P"],
            "logical_class": "BINARY_MEMO",
            "disposition": "TRANSFORM",
            "default_action": "MASK_REVERSIBLE",
            "policy_section": "memo",
            "policy_key": "binary",
            "binary_descriptor_allowed": True,
            "nocptrans_allowed": True,
        },
        {
            "dbf_types": ["D"],
            "logical_class": "DATE",
            "disposition": "TRANSFORM",
            "default_action": "SHIFT_REVERSIBLE",
            "policy_section": "temporal",
            "policy_key": "date",
            "binary_descriptor_allowed": False,
            "nocptrans_allowed": True,
        },
        {
            "dbf_types": ["T"],
            "logical_class": "DATETIME",
            "disposition": "TRANSFORM",
            "default_action": "SHIFT_REVERSIBLE",
            "policy_section": "temporal",
            "policy_key": "datetime",
            "binary_descriptor_allowed": False,
            "nocptrans_allowed": True,
        },
        {
            "dbf_types": ["N", "F", "I", "Y", "B", "L"],
            "logical_class": "SCALAR_IDENTITY",
            "disposition": "IDENTITY",
            "default_action": None,
            "policy_section": None,
            "policy_key": None,
            "binary_descriptor_allowed": False,
            "nocptrans_allowed": True,
        },
    ],
}


def test_field_capability_matrix_snapshot_is_exact_and_deterministic() -> None:
    snapshot = field_capability_matrix_snapshot()
    assert FIELD_CAPABILITY_MATRIX_VERSION == "1.0"
    assert snapshot == EXPECTED_MATRIX
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode("ascii")).hexdigest() == (
        "b4cb773346f4ca81e7e356406d20150d6f59db0613883b86f5afdc3197af832c"
    )


@pytest.mark.parametrize(
    ("dbf_type", "is_binary", "expected_action"),
    [
        ("C", False, "PSEUDONYMIZE_REVERSIBLE"),
        ("V", False, "PSEUDONYMIZE_REVERSIBLE"),
        ("M", False, "MASK_REVERSIBLE"),
        ("G", True, "MASK_REVERSIBLE"),
        ("P", True, "MASK_REVERSIBLE"),
        ("D", False, "SHIFT_REVERSIBLE"),
        ("T", False, "SHIFT_REVERSIBLE"),
    ],
)
def test_supported_transform_class(
    dbf_type: str, is_binary: bool, expected_action: str
) -> None:
    assert classify_field_capability(
        dbf_type,
        "VALUE",
        True,
        is_binary,
        False,
        False,
        _policy(),
    ) == (expected_action, False, False)


@pytest.mark.parametrize("dbf_type", ["N", "F", "I", "Y", "B", "L"])
def test_default_identity_class(dbf_type: str) -> None:
    assert classify_field_capability(
        dbf_type, "VALUE", True, False, False, False, _policy()
    ) == (None, False, False)


@pytest.mark.parametrize("dbf_type", ["C", "V", "M"])
@pytest.mark.parametrize(("is_binary", "nocptrans"), [(True, False), (False, True)])
def test_binary_or_nocptrans_textual_field_fails_closed(
    dbf_type: str, is_binary: bool, nocptrans: bool
) -> None:
    assert classify_field_capability(
        dbf_type,
        "VALUE",
        True,
        is_binary,
        False,
        nocptrans,
        _policy(),
    ) == (None, True, False)


@pytest.mark.parametrize("dbf_type", ["Q", "W", "X", "O", "?"])
def test_opaque_or_unknown_user_class_fails_closed(dbf_type: str) -> None:
    assert classify_field_capability(
        dbf_type, "VALUE", True, False, False, False, _policy()
    ) == (None, True, False)


def test_reader_unsupported_user_field_fails_closed() -> None:
    assert classify_field_capability(
        "M", "VALUE", False, False, False, False, _policy()
    ) == (None, True, False)


def test_only_trusted_nullflags_is_writer_managed() -> None:
    assert classify_field_capability(
        "0", "_NullFlags", True, True, True, False, _policy()
    ) == (None, False, True)
    assert classify_field_capability(
        "0", "USER_BITMAP", True, True, True, False, _policy()
    ) == (None, True, False)


def test_planning_preflight_and_engine_consume_the_same_classifier() -> None:
    package = Path(__file__).resolve().parents[1] / "src" / "dbf_anonymizer"
    consumers = (
        package / "planning.py",
        package / "preflight.py",
        package / "engine" / "run.py",
    )
    for path in consumers:
        source = path.read_text(encoding="utf-8")
        assert "classify_field_capability(" in source, path
    engine_source = consumers[-1].read_text(encoding="utf-8")
    assert "def _text_action(" not in engine_source
    assert "def _memo_action(" not in engine_source
    assert "def _temporal_action(" not in engine_source
