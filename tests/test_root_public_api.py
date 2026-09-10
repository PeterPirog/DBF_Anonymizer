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
    "RecoveryResult",
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


def test_obsolete_0_3_operations_are_not_exported() -> None:
    exported = set(dir(dbf_anonymizer))
    leaked = sorted(set(OBSOLETE_0_3_EXPORTS) & exported)
    assert not leaked, f"obsolete 0.3 exports still present: {leaked}"


def test_public_surface_stays_intentionally_small() -> None:
    assert dbf_anonymizer.__all__ == []


def test_development_version_is_not_0_3() -> None:
    assert dbf_anonymizer.__version__ == "1.0.0.dev0"