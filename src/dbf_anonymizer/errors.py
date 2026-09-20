"""Stable privacy-safe error contract for DBF_Anonymizer 1.0.

REQ-P1-003 owns this module.  Public failures are classified by stable machine
codes and a small typed context.  Human-readable messages come exclusively
from the versioned registry; callers must never classify failures by parsing
exception text.

Dependency failures are deliberately redacted.  When wrapping dbfbridge we
preserve only its structured machine code.  We do not copy the dependency
exception message, path or context because those values may contain absolute
paths, field values or other private diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import ClassVar

from .models import JsonDict

ERROR_SCHEMA_VERSION = "1.0"
ERROR_REGISTRY_VERSION = "1.3"


class ErrorCategory(str, Enum):
    """Stable top-level failure categories."""

    PATH = "path"
    POLICY = "policy"
    DBFBRIDGE = "dbfbridge"
    VAULT = "vault"
    MAPPING = "mapping"
    RELATIONSHIP = "relationship"
    PUBLICATION = "publication"
    VERIFICATION = "verification"
    RECOVERY = "recovery"
    CANCELLATION = "cancellation"
    CALLBACK = "callback"


class ErrorCode(str, Enum):
    """Stable DBF_Anonymizer machine-code vocabulary."""

    PATH_INVALID = "PATH_INVALID"
    PATH_NOT_FOUND = "PATH_NOT_FOUND"
    PATH_OVERLAP = "PATH_OVERLAP"
    DESTINATION_CONFLICT = "DESTINATION_CONFLICT"

    POLICY_INVALID = "POLICY_INVALID"
    POLICY_UNSUPPORTED = "POLICY_UNSUPPORTED"

    DBFBRIDGE_FAILURE = "DBFBRIDGE_FAILURE"

    VAULT_UNAVAILABLE = "VAULT_UNAVAILABLE"
    VAULT_CORRUPT = "VAULT_CORRUPT"
    VAULT_ACCESS_DENIED = "VAULT_ACCESS_DENIED"
    VAULT_SCHEMA_UNSUPPORTED = "VAULT_SCHEMA_UNSUPPORTED"
    VAULT_IDENTITY_MISMATCH = "VAULT_IDENTITY_MISMATCH"
    VAULT_STATE_INVALID = "VAULT_STATE_INVALID"
    VAULT_WRITER_CONFLICT = "VAULT_WRITER_CONFLICT"

    MAPPING_CAPACITY_EXHAUSTED = "MAPPING_CAPACITY_EXHAUSTED"
    MAPPING_CONSTRAINT_INFEASIBLE = "MAPPING_CONSTRAINT_INFEASIBLE"
    MAPPING_CONFLICT = "MAPPING_CONFLICT"

    RELATIONSHIP_INVALID = "RELATIONSHIP_INVALID"
    RELATIONSHIP_VERIFICATION_FAILED = "RELATIONSHIP_VERIFICATION_FAILED"

    PUBLICATION_FAILED = "PUBLICATION_FAILED"
    PUBLICATION_INCOMPLETE = "PUBLICATION_INCOMPLETE"

    VERIFICATION_FAILED = "VERIFICATION_FAILED"

    RECOVERY_FAILED = "RECOVERY_FAILED"
    RECOVERY_NOT_PERMITTED = "RECOVERY_NOT_PERMITTED"

    OPERATION_CANCELLED = "OPERATION_CANCELLED"

    PROGRESS_CALLBACK_FAILED = "PROGRESS_CALLBACK_FAILED"
    CANCEL_CALLBACK_FAILED = "CANCEL_CALLBACK_FAILED"


@dataclass(frozen=True, slots=True)
class ErrorDefinition:
    """One immutable entry in the versioned public error registry."""

    code: ErrorCode
    category: ErrorCategory
    message: str

    def to_dict(self) -> JsonDict:
        return {
            "code": self.code.value,
            "category": self.category.value,
            "message": self.message,
        }


ERROR_REGISTRY: tuple[ErrorDefinition, ...] = (
    ErrorDefinition(ErrorCode.PATH_INVALID, ErrorCategory.PATH, "A path is invalid."),
    ErrorDefinition(
        ErrorCode.PATH_NOT_FOUND, ErrorCategory.PATH, "A required path was not found."
    ),
    ErrorDefinition(
        ErrorCode.PATH_OVERLAP,
        ErrorCategory.PATH,
        "Source, output or protected-state paths overlap unsafely.",
    ),
    ErrorDefinition(
        ErrorCode.DESTINATION_CONFLICT,
        ErrorCategory.PATH,
        "The requested destination conflicts with existing state.",
    ),
    ErrorDefinition(
        ErrorCode.POLICY_INVALID, ErrorCategory.POLICY, "The policy is invalid."
    ),
    ErrorDefinition(
        ErrorCode.POLICY_UNSUPPORTED,
        ErrorCategory.POLICY,
        "The policy requests an unsupported transformation or combination.",
    ),
    ErrorDefinition(
        ErrorCode.DBFBRIDGE_FAILURE,
        ErrorCategory.DBFBRIDGE,
        "The DBF/FPT dependency reported a structured failure.",
    ),
    ErrorDefinition(
        ErrorCode.VAULT_UNAVAILABLE,
        ErrorCategory.VAULT,
        "The protected recovery vault is unavailable.",
    ),
    ErrorDefinition(
        ErrorCode.VAULT_CORRUPT,
        ErrorCategory.VAULT,
        "The protected recovery vault failed integrity validation.",
    ),
    ErrorDefinition(
        ErrorCode.VAULT_ACCESS_DENIED,
        ErrorCategory.VAULT,
        "Access to the protected recovery vault is not permitted.",
    ),
    ErrorDefinition(
        ErrorCode.VAULT_SCHEMA_UNSUPPORTED,
        ErrorCategory.VAULT,
        "The protected recovery vault schema version is not supported.",
    ),
    ErrorDefinition(
        ErrorCode.VAULT_IDENTITY_MISMATCH,
        ErrorCategory.VAULT,
        "The protected recovery vault is bound to a different dataset identity.",
    ),
    ErrorDefinition(
        ErrorCode.VAULT_STATE_INVALID,
        ErrorCategory.VAULT,
        "The protected recovery vault rejected an inconsistent state transition.",
    ),
    ErrorDefinition(
        ErrorCode.VAULT_WRITER_CONFLICT,
        ErrorCategory.VAULT,
        "Another writer holds the single logical write authority of the vault.",
    ),
    ErrorDefinition(
        ErrorCode.MAPPING_CAPACITY_EXHAUSTED,
        ErrorCategory.MAPPING,
        "A pseudonymization domain has insufficient representable capacity.",
    ),
    ErrorDefinition(
        ErrorCode.MAPPING_CONSTRAINT_INFEASIBLE,
        ErrorCategory.MAPPING,
        "The finalized pseudonymization mapping constraints cannot be satisfied.",
    ),
    ErrorDefinition(
        ErrorCode.MAPPING_CONFLICT,
        ErrorCategory.MAPPING,
        "A pseudonym mapping conflicts with existing protected state.",
    ),
    ErrorDefinition(
        ErrorCode.RELATIONSHIP_INVALID,
        ErrorCategory.RELATIONSHIP,
        "Relationship metadata is invalid or incompatible.",
    ),
    ErrorDefinition(
        ErrorCode.RELATIONSHIP_VERIFICATION_FAILED,
        ErrorCategory.RELATIONSHIP,
        "Declared relationship verification failed.",
    ),
    ErrorDefinition(
        ErrorCode.PUBLICATION_FAILED,
        ErrorCategory.PUBLICATION,
        "Output publication failed before a completed dataset was committed.",
    ),
    ErrorDefinition(
        ErrorCode.PUBLICATION_INCOMPLETE,
        ErrorCategory.PUBLICATION,
        "Incomplete publication state requires recovery or cleanup.",
    ),
    ErrorDefinition(
        ErrorCode.VERIFICATION_FAILED,
        ErrorCategory.VERIFICATION,
        "Dataset verification failed.",
    ),
    ErrorDefinition(
        ErrorCode.RECOVERY_FAILED, ErrorCategory.RECOVERY, "Recovery failed."
    ),
    ErrorDefinition(
        ErrorCode.RECOVERY_NOT_PERMITTED,
        ErrorCategory.RECOVERY,
        "Recovery is disabled by the active host or operation policy.",
    ),
    ErrorDefinition(
        ErrorCode.OPERATION_CANCELLED,
        ErrorCategory.CANCELLATION,
        "The operation was cooperatively cancelled.",
    ),
    ErrorDefinition(
        ErrorCode.PROGRESS_CALLBACK_FAILED,
        ErrorCategory.CALLBACK,
        "The progress callback raised an exception; the failure was contained.",
    ),
    ErrorDefinition(
        ErrorCode.CANCEL_CALLBACK_FAILED,
        ErrorCategory.CALLBACK,
        "The cancellation-check callback raised an exception; the failure was contained.",
    ),
)

_ERROR_BY_CODE: dict[ErrorCode, ErrorDefinition] = {
    definition.code: definition for definition in ERROR_REGISTRY
}


def _validate_token(value: str, *, field_name: str) -> str:
    """Validate a bounded machine token without interpreting its meaning."""
    if not value or len(value) > 128 or value.strip() != value:
        raise ValueError(
            f"{field_name} must be a non-empty token of at most 128 characters"
        )
    if any(character.isspace() for character in value):
        raise ValueError(f"{field_name} must not contain whitespace")
    return value


def _normalize_relative_path(value: str) -> str:
    """Return a transport-stable relative path or reject unsafe disclosure."""
    if not value or "\x00" in value:
        raise ValueError("public error paths must be non-empty text paths")
    windows = PureWindowsPath(value)
    if windows.is_absolute() or windows.drive or windows.root:
        raise ValueError("public error paths must be relative")
    normalized = PurePosixPath(value.replace("\\", "/"))
    if normalized.is_absolute() or any(part == ".." for part in normalized.parts):
        raise ValueError("public error paths must be relative and traversal-free")
    text = normalized.as_posix()
    if text in {"", "."}:
        raise ValueError("public error paths must identify an artifact")
    return text


@dataclass(frozen=True, slots=True)
class ErrorContext:
    """Bounded privacy-safe context carried by public failures.

    No arbitrary mapping is accepted.  Each field has a defined operational
    meaning and can contain only a machine token or normalized relative path.
    This intentionally prevents accidental serialization of source values,
    memo payloads, secrets, vault data or unrestricted diagnostic objects.
    """

    operation: str | None = None
    artifact_path: str | None = None
    table_path: str | None = None
    policy_rule: str | None = None
    relationship_id: str | None = None
    detail_code: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "operation",
            "policy_rule",
            "relationship_id",
            "detail_code",
        ):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(
                    self, field_name, _validate_token(value, field_name=field_name)
                )
        for field_name in ("artifact_path", "table_path"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _normalize_relative_path(value))

    def to_dict(self) -> JsonDict:
        return {
            "operation": self.operation,
            "artifact_path": self.artifact_path,
            "table_path": self.table_path,
            "policy_rule": self.policy_rule,
            "relationship_id": self.relationship_id,
            "detail_code": self.detail_code,
        }


def _structured_machine_code(value: object) -> str | None:
    """Extract a machine code from a structured attribute, never from text."""
    if isinstance(value, str):
        return _validate_token(value, field_name="dependency_code")
    if isinstance(value, Enum):
        enum_value = value.value
        if isinstance(enum_value, str):
            return _validate_token(enum_value, field_name="dependency_code")
    return None


class AnonymizerError(Exception):
    """Base class for all public DBF_Anonymizer failures."""

    category: ClassVar[ErrorCategory]

    def __init__(
        self,
        code: ErrorCode,
        *,
        context: ErrorContext | None = None,
        dependency_code: str | None = None,
    ) -> None:
        definition = _ERROR_BY_CODE[code]
        if definition.category is not self.category:
            raise ValueError(
                f"{type(self).__name__} cannot carry {code.value}; "
                f"expected category {self.category.value}"
            )
        self.code = code
        self.context = context if context is not None else ErrorContext()
        self.dependency_code = (
            _validate_token(dependency_code, field_name="dependency_code")
            if dependency_code is not None
            else None
        )
        self.message = definition.message
        super().__init__(self.message)

    def to_dict(self) -> JsonDict:
        """Return the stable privacy-safe JSON boundary for this failure."""
        return {
            "schema_version": ERROR_SCHEMA_VERSION,
            "registry_version": ERROR_REGISTRY_VERSION,
            "code": self.code.value,
            "category": self.category.value,
            "message": self.message,
            "dependency_code": self.dependency_code,
            "context": self.context.to_dict(),
        }


class PathError(AnonymizerError):
    category = ErrorCategory.PATH


class PolicyError(AnonymizerError):
    category = ErrorCategory.POLICY


class DBFBridgeError(AnonymizerError):
    """Privacy-safe wrapper for structured dbfbridge failures."""

    category = ErrorCategory.DBFBRIDGE

    @classmethod
    def from_exception(
        cls,
        error: BaseException,
        *,
        context: ErrorContext | None = None,
    ) -> "DBFBridgeError":
        """Wrap *error* using only its structured ``code`` attribute.

        The exception message, path and context are intentionally ignored.
        If the object has no structured machine code we still return the
        generic DBFBRIDGE_FAILURE classification with ``dependency_code=None``;
        message parsing is never attempted.
        """
        dependency_code = _structured_machine_code(getattr(error, "code", None))
        return cls(
            ErrorCode.DBFBRIDGE_FAILURE,
            context=context,
            dependency_code=dependency_code,
        )


class VaultError(AnonymizerError):
    category = ErrorCategory.VAULT


class MappingError(AnonymizerError):
    category = ErrorCategory.MAPPING


class RelationshipError(AnonymizerError):
    category = ErrorCategory.RELATIONSHIP


class PublicationError(AnonymizerError):
    category = ErrorCategory.PUBLICATION


class VerificationError(AnonymizerError):
    category = ErrorCategory.VERIFICATION


class RecoveryError(AnonymizerError):
    category = ErrorCategory.RECOVERY


class CancellationError(AnonymizerError):
    category = ErrorCategory.CANCELLATION


class CallbackError(AnonymizerError):
    """Contained, classified callback failure (REQ-P1-008).

    Raised when a caller-supplied progress or cancellation-check callback
    throws.  The raw exception never escapes: its message may contain private
    paths, source values or secrets, so only the registry-controlled message
    and the stable machine code are exposed.  Classification never parses
    exception text.
    """

    category = ErrorCategory.CALLBACK


__all__ = [
    "ERROR_SCHEMA_VERSION",
    "ERROR_REGISTRY_VERSION",
    "ERROR_REGISTRY",
    "ErrorCategory",
    "ErrorCode",
    "ErrorDefinition",
    "ErrorContext",
    "AnonymizerError",
    "PathError",
    "PolicyError",
    "DBFBridgeError",
    "VaultError",
    "MappingError",
    "RelationshipError",
    "PublicationError",
    "VerificationError",
    "RecoveryError",
    "CancellationError",
    "CallbackError",
]
