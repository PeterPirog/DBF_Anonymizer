"""P0 root public API regression evidence for REQ-P0-001.

Confirms that obsolete 0.3 public operations are no longer exported from
``dbf_anonymizer`` merely for backward compatibility, and that no placeholder
implementations of the future 1.0 API are faked in their place.
"""

from __future__ import annotations

import dbf_anonymizer

OBSOLETE_0_3_EXPORTS = (
    # Pipeline operations
    "anonymize_directory",
    "make_dbf_recovery",
    "self_test",
    # Result / option types of the 0.3 pipeline
    "AnonymizeResult",
    "SelfTestReport",
    "TableOutcome",
    "AnonymizeOptions",
    "anonymize_records",
    "build_shared_dictionary",
    "recover_records",
    # Legacy dictionary objects
    "FieldDict",
    "TableDict",
    "dictionary_filename",
    "save_dictionary",
    "load_dictionary",
    "GLOBAL_DICTIONARY_FILENAME",
    "GlobalDictionaryStore",
    "global_dictionary_path",
    # Legacy 0.3 schema access
    "FieldInfo",
    "TableSchema",
    "load_schema",
    # Legacy low-level transforms exposed as public API
    "mask_char",
    "mask_memo",
    "shift_date",
    "shift_datetime",
)
# Note: the historical 0.3 untyped "RecoveryResult" name is intentionally not
# in this forbidden list any more: REQ-P1-002 legitimately exports a new
# immutable typed `RecoveryResult` public model under the same name (a clean
# replacement, not a compatibility alias — the 0.3 dataclass shape/semantics
# are gone).


def test_obsolete_0_3_operations_are_not_exported() -> None:
    exported = set(dir(dbf_anonymizer))
    leaked = sorted(set(OBSOLETE_0_3_EXPORTS) & exported)
    assert not leaked, f"obsolete 0.3 exports still present: {leaked}"


EXPECTED_PUBLIC_MODELS = frozenset(
    {
        "PUBLIC_MODEL_SCHEMA_VERSION",
        "Capabilities",
        "DatasetIdentity",
        "FieldPlan",
        "Plan",
        "PolicySummary",
        "PreflightIssue",
        "PreflightResult",
        "ProgressEvent",
        "PseudonymizationResult",
        "RelationalAssurance",
        "RecoveryResult",
        "RelationshipGroup",
        "RelationshipMember",
        "RelationshipMetadata",
        "ResultStatus",
        "TablePlan",
        "TransferBundleResult",
        "VerificationResult",
        "VerificationStatus",
    }
)

#: REQ-P1-004 public operation functions must remain absent (typed models
#: only in REQ-P1-002).
FUTURE_SERVICE_FUNCTIONS = (
    "capabilities",
    "build_plan",
    "preflight",
    "pseudonymize",
    "verify_dataset",
    "recover",
    "create_transfer_bundle",
    "verify_transfer_bundle",
)


def test_obsolete_0_3_operations_are_not_exported() -> None:
    exported = set(dir(dbf_anonymizer))
    leaked = sorted(set(OBSOLETE_0_3_EXPORTS) & exported)
    assert not leaked, f"obsolete 0.3 exports still present: {leaked}"


def test_public_model_exports_match_the_p1_002_contract() -> None:
    exported = set(dir(dbf_anonymizer))
    assert exported >= set(dbf_anonymizer.__all__)
    assert set(dbf_anonymizer.__all__) == EXPECTED_PUBLIC_MODELS


def test_future_service_functions_are_not_root_exported() -> None:
    exported = set(dir(dbf_anonymizer))
    leaked = exported & set(FUTURE_SERVICE_FUNCTIONS)
    assert not leaked, f"future P1-004 service functions leaked: {sorted(leaked)}"


def test_development_version_is_not_0_3() -> None:
    assert dbf_anonymizer.__version__ == "1.0.0.dev0"