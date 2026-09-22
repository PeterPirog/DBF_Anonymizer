"""Root public API regression evidence for the clean-slate 1.0 line.

The project deliberately does not preserve the historical 0.3 API. This file
protects that clean-slate decision while allowing the current 1.0 model,
error and operational contracts to become public. The currently implemented
operational surface is exactly ``capabilities``, ``build_plan``, ``preflight``
and ``pseudonymize``; the unfinished operations stay absent (no success
placeholders).
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
    "IDENTITY_PRIVACY_REVIEW_REQUIRED",
    "Capabilities",
    "DatasetIdentity",
    "NumericIdentityReview",
    "Plan",
    "TablePlan",
    "PolicySummary",
    "RelationshipMetadata",
    "RelationalAssurance",
    "RelationalAssuranceLevel",
    "ProgressEvent",
    "PreflightResult",
    "PseudonymizationResult",
    "VerificationStatus",
    "VerificationResult",
    "RawByteEquivalence",
    "RecoveryResult",
    "TransferBundleResult",
    "TransferProfile",
    "VaultStrategy",
    "build_plan",
    "preflight",
    "pseudonymize",
    "verify_dataset",
    "recover",
    "capabilities",
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
    # REQ-P1-008: the contained, classified callback-failure type is public so
    # consumers can catch callback failures without importing private modules.
    "CallbackError",
}

FUTURE_OPERATION_EXPORTS = {
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


def test_capabilities_is_public_and_has_a_single_implementation() -> None:
    import dbf_anonymizer.api as api_module

    assert dbf_anonymizer.capabilities is api_module.capabilities
    assert dbf_anonymizer.capabilities.__module__ == "dbf_anonymizer.capabilities"


def test_recover_is_public_and_has_a_single_implementation() -> None:
    import dbf_anonymizer.api as api_module

    assert dbf_anonymizer.recover is api_module.recover
    assert dbf_anonymizer.recover.__module__ == "dbf_anonymizer.recovery"


def test_verify_dataset_is_public_and_has_a_single_implementation() -> None:
    import dbf_anonymizer.api as api_module

    assert dbf_anonymizer.verify_dataset is api_module.verify_dataset
    assert dbf_anonymizer.verify_dataset.__module__ == "dbf_anonymizer.verification"


def test_pseudonymize_is_public_and_has_a_single_implementation() -> None:
    import dbf_anonymizer.api as api_module

    assert dbf_anonymizer.pseudonymize is api_module.pseudonymize
    assert dbf_anonymizer.pseudonymize.__module__ == "dbf_anonymizer.api"


def test_capabilities_returns_the_immutable_public_model() -> None:
    from dbf_anonymizer import Capabilities

    result = dbf_anonymizer.capabilities()
    assert isinstance(result, Capabilities)
    # REQ-P1-007 truthfulness: the protected canonical dataset recovery
    # (REQ-P5-002/REQ-P5-003) is implemented and derived from the same
    # required direct read/write runtime capability facts.
    assert result.recovery is (result.direct_read and result.direct_write)
    assert result.recovery is True
    assert result.transfer_bundle is False
    assert result.vfp_index_backend is False


def test_recovery_capability_follows_the_direct_runtime_facts() -> None:
    """REQ-P1-007 negative evidence: the recovery capability is derived from
    the required direct read/write runtime facts only — never from
    filesystem probing. The real snapshot derives it from the direct facts,
    so a runtime missing either capability would truthfully report False
    (the capability kernel derives the pair from its own runtime facts)."""
    snapshot = dbf_anonymizer.capabilities()
    assert snapshot.recovery is (snapshot.direct_read and snapshot.direct_write)
    assert snapshot.recovery is True
    assert snapshot.transfer_bundle is False
    assert snapshot.vfp_index_backend is False


def test_recovery_result_is_the_new_1_0_model_not_a_legacy_compatibility_alias() -> None:
    assert dbf_anonymizer.RecoveryResult.__module__ == "dbf_anonymizer.models"


def test_error_hierarchy_is_the_new_1_0_contract() -> None:
    assert dbf_anonymizer.AnonymizerError.__module__ == "dbf_anonymizer.errors"
    assert issubclass(dbf_anonymizer.DBFBridgeError, dbf_anonymizer.AnonymizerError)


def test_development_version_is_not_0_3() -> None:
    assert dbf_anonymizer.__version__ == "1.0.0.dev0"
