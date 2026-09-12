"""Root public API regression evidence for the clean-slate 1.0 line.

The project deliberately does not preserve the historical 0.3 API. This file
protects that clean-slate decision while allowing the current 1.0 model and
error contracts to become public.
"""

from __future__ import annotations

import dbf_anonymizer

OBSOLETE_0_3_EXPORTS = (
    "anonymize_directory",
    "make_dbf_recovery",
    "self_test",
    "AnonymizeResult",
    "SelfTestReport",
    "TableOutcome",
    "AnonymizeOptions",
    "anonymize_records",
    "build_shared_dictionary",
    "recover_records",
    "FieldDict",
    "TableDict",
    "dictionary_filename",
    "save_dictionary",
    "load_dictionary",
    "GLOBAL_DICTIONARY_FILENAME",
    "GlobalDictionaryStore",
    "global_dictionary_path",
    "FieldInfo",
    "TableSchema",
    "load_schema",
    "mask_char",
    "mask_memo",
    "shift_date",
    "shift_datetime",
)

EXPECTED_PUBLIC_EXPORTS = {
    "MODEL_SCHEMA_VERSION",
    "Capabilities",
    "DatasetIdentity",
    "Plan",
    "PlanExecutionContext",
    "TablePlan",
    "PolicySummary",
    "RelationshipMetadata",
    "RelationalAssurance",
    "RelationalAssuranceLevel",
    "ProgressEvent",
    "PreflightResult",
    "PseudonymizationResult",
    "VerificationResult",
    "RecoveryResult",
    "TransferBundleResult",
    "TransferProfile",
    "build_plan",
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
}

FUTURE_OPERATION_EXPORTS = {
    "capabilities",
    "preflight",
    "pseudonymize",
    "verify_dataset",
    "recover",
    "create_transfer_bundle",
    "verify_transfer_bundle",
}


def test_obsolete_0_3_operations_are_not_exported() -> None:
    exported = set(dir(dbf_anonymizer))
    leaked = sorted(set(OBSOLETE_0_3_EXPORTS) & exported)
    assert not leaked, f"obsolete 0.3 exports still present: {leaked}"


def test_public_surface_is_exactly_the_current_1_0_contract() -> None:
    assert set(dbf_anonymizer.__all__) == EXPECTED_PUBLIC_EXPORTS


def test_future_operations_are_not_faked_before_their_requirements() -> None:
    exported = set(dir(dbf_anonymizer))
    assert FUTURE_OPERATION_EXPORTS.isdisjoint(exported)


def test_recovery_result_is_the_new_1_0_model_not_a_legacy_compatibility_alias() -> None:
    assert dbf_anonymizer.RecoveryResult.__module__ == "dbf_anonymizer.models"


def test_error_hierarchy_is_the_new_1_0_contract() -> None:
    assert dbf_anonymizer.AnonymizerError.__module__ == "dbf_anonymizer.errors"
    assert issubclass(dbf_anonymizer.DBFBridgeError, dbf_anonymizer.AnonymizerError)


def test_development_version_is_not_0_3() -> None:
    assert dbf_anonymizer.__version__ == "1.0.0.dev0"
