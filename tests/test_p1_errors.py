"""REQ-P1-003 — stable privacy-safe public error contract evidence."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest
from dbfbridge import (
    DbfHeaderInvalidError,
    ErrorCode as DBFBridgeErrorCode,
    OptionalDependencyMissingError,
)

from dbf_anonymizer import (
    ERROR_REGISTRY,
    ERROR_REGISTRY_VERSION,
    ERROR_SCHEMA_VERSION,
    AnonymizerError,
    CancellationError,
    DBFBridgeError,
    ErrorCategory,
    ErrorCode,
    ErrorContext,
    MappingError,
    PathError,
    PolicyError,
    PublicationError,
    RecoveryError,
    RelationshipError,
    VaultError,
    VerificationError,
)


def test_error_registry_is_versioned_complete_and_unique() -> None:
    assert ERROR_SCHEMA_VERSION == "1.0"
    assert ERROR_REGISTRY_VERSION == "1.0"
    registered_codes = [definition.code for definition in ERROR_REGISTRY]
    assert len(registered_codes) == len(set(registered_codes))
    assert set(registered_codes) == set(ErrorCode)
    assert all(definition.message and definition.message.endswith(".") for definition in ERROR_REGISTRY)


def test_representative_error_for_every_required_category() -> None:
    cases: tuple[tuple[type[AnonymizerError], ErrorCode, ErrorCategory], ...] = (
        (PathError, ErrorCode.PATH_INVALID, ErrorCategory.PATH),
        (PolicyError, ErrorCode.POLICY_INVALID, ErrorCategory.POLICY),
        (DBFBridgeError, ErrorCode.DBFBRIDGE_FAILURE, ErrorCategory.DBFBRIDGE),
        (VaultError, ErrorCode.VAULT_UNAVAILABLE, ErrorCategory.VAULT),
        (MappingError, ErrorCode.MAPPING_CONFLICT, ErrorCategory.MAPPING),
        (RelationshipError, ErrorCode.RELATIONSHIP_INVALID, ErrorCategory.RELATIONSHIP),
        (PublicationError, ErrorCode.PUBLICATION_FAILED, ErrorCategory.PUBLICATION),
        (VerificationError, ErrorCode.VERIFICATION_FAILED, ErrorCategory.VERIFICATION),
        (RecoveryError, ErrorCode.RECOVERY_FAILED, ErrorCategory.RECOVERY),
        (CancellationError, ErrorCode.OPERATION_CANCELLED, ErrorCategory.CANCELLATION),
    )
    for error_type, code, category in cases:
        error = error_type(code, context=ErrorContext(operation="test_operation"))
        assert isinstance(error, AnonymizerError)
        assert error.code is code
        assert error.category is category
        payload = error.to_dict()
        assert payload["code"] == code.value
        assert payload["category"] == category.value
        json.dumps(payload, sort_keys=True)


def test_error_context_is_frozen_bounded_and_normalizes_relative_paths() -> None:
    context = ErrorContext(
        operation="build_plan",
        artifact_path="output\\dataset",
        table_path="north\\registry.dbf",
        policy_rule="CUSTOMER_NAME",
        relationship_id="CUSTOMER_ORDER_FK",
        detail_code="CAPACITY_CHECK",
    )
    assert context.artifact_path == "output/dataset"
    assert context.table_path == "north/registry.dbf"
    with pytest.raises(FrozenInstanceError):
        context.operation = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "unsafe_path",
    (
        r"C:\private\source.dbf",
        "/private/source.dbf",
        "../source.dbf",
        "safe/../../source.dbf",
    ),
)
def test_error_context_rejects_absolute_or_traversing_paths(unsafe_path: str) -> None:
    with pytest.raises(ValueError):
        ErrorContext(artifact_path=unsafe_path)
    with pytest.raises(ValueError):
        ErrorContext(table_path=unsafe_path)


def test_error_context_rejects_free_form_whitespace_tokens() -> None:
    with pytest.raises(ValueError):
        ErrorContext(detail_code="raw value: Alice Example")
    with pytest.raises(ValueError):
        ErrorContext(operation="a" * 129)


def test_wrong_code_category_is_rejected() -> None:
    with pytest.raises(ValueError):
        PathError(ErrorCode.POLICY_INVALID)
    with pytest.raises(ValueError):
        RecoveryError(ErrorCode.VERIFICATION_FAILED)


def test_public_error_message_is_registry_controlled_not_caller_supplied() -> None:
    error = PolicyError(ErrorCode.POLICY_INVALID)
    assert str(error) == "The policy is invalid."
    assert error.to_dict()["message"] == "The policy is invalid."


def test_dbfbridge_enum_machine_code_is_preserved_without_sensitive_payloads() -> None:
    dependency_error = DbfHeaderInvalidError(
        "CANARY_ORIGINAL_VALUE must never escape",
        path=r"C:\TOP_SECRET\source.dbf",
        context={
            "field_value": "CANARY_FIELD_VALUE",
            "memo_payload": "CANARY_MEMO_PAYLOAD",
        },
    )
    assert dependency_error.code is DBFBridgeErrorCode.DBF_HEADER_INVALID

    wrapped = DBFBridgeError.from_exception(
        dependency_error,
        context=ErrorContext(
            operation="build_plan",
            table_path="north\\registry.dbf",
            detail_code="SCHEMA_READ",
        ),
    )
    payload = wrapped.to_dict()
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["dependency_code"] == "DBF_HEADER_INVALID"
    assert payload["code"] == "DBFBRIDGE_FAILURE"
    assert "CANARY_ORIGINAL_VALUE" not in serialized
    assert "CANARY_FIELD_VALUE" not in serialized
    assert "CANARY_MEMO_PAYLOAD" not in serialized
    assert "TOP_SECRET" not in serialized
    assert "source.dbf" not in serialized
    assert "north/registry.dbf" in serialized


def test_dbfbridge_string_machine_code_is_preserved() -> None:
    dependency_error = OptionalDependencyMissingError(
        dependency="dbf",
        extra="write",
        operation="write_table",
    )
    wrapped = DBFBridgeError.from_exception(dependency_error)
    assert wrapped.dependency_code == "OPTIONAL_DEPENDENCY_MISSING"
    assert wrapped.to_dict()["dependency_code"] == "OPTIONAL_DEPENDENCY_MISSING"


def test_dbfbridge_wrapper_never_parses_exception_text() -> None:
    class CodelessDependencyFailure(RuntimeError):
        pass

    dependency_error = CodelessDependencyFailure(
        "DBF_HEADER_INVALID PATH_NOT_FOUND OPTIONAL_DEPENDENCY_MISSING"
    )
    wrapped = DBFBridgeError.from_exception(dependency_error)
    assert wrapped.dependency_code is None
    serialized = json.dumps(wrapped.to_dict(), sort_keys=True)
    assert "DBF_HEADER_INVALID" not in serialized
    assert "PATH_NOT_FOUND" not in serialized
    assert "OPTIONAL_DEPENDENCY_MISSING" not in serialized


def test_dependency_code_must_be_a_bounded_machine_token() -> None:
    with pytest.raises(ValueError):
        DBFBridgeError(
            ErrorCode.DBFBRIDGE_FAILURE,
            dependency_code="this is not a machine code",
        )


def test_error_payload_schema_snapshot_is_stable() -> None:
    error = RelationshipError(
        ErrorCode.RELATIONSHIP_VERIFICATION_FAILED,
        context=ErrorContext(
            operation="verify_dataset",
            relationship_id="CUSTOMER_ORDER_FK",
            detail_code="ORPHAN_COUNT_NONZERO",
        ),
    )
    assert tuple(error.to_dict()) == (
        "schema_version",
        "registry_version",
        "code",
        "category",
        "message",
        "dependency_code",
        "context",
    )
    assert tuple(error.context.to_dict()) == (
        "operation",
        "artifact_path",
        "table_path",
        "policy_rule",
        "relationship_id",
        "detail_code",
    )
