"""Build the explicit DBF_Anonymizer 1.0 public-contract snapshot.

The builder is side-effect free. A maintainer must pass ``--write`` to replace
the committed snapshot; normal test execution only calls ``build_contract``.
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import secrets
import sqlite3
from dataclasses import fields
from enum import Enum
from pathlib import Path
from typing import Any, Callable, cast

import dbf_anonymizer as public
from dbf_anonymizer.cli import COMMANDS, PROGRAM, _build_parser
from dbf_anonymizer.errors import ERROR_REGISTRY
from dbf_anonymizer.models import (
    INDEX_ARTIFACT_CLASSES,
    INDEX_BACKEND_RESULT_DETAIL_CODES,
    INDEX_BACKEND_RESULT_STATUSES,
    INDEX_VERIFICATION_DETAIL_CODES,
    INDEX_VERIFICATION_STATUSES,
    PROGRESS_EVENT_CODES,
    PROGRESS_PHASE_CODES,
    PUBLIC_JSON_MAX_COUNT,
    PUBLIC_JSON_MAX_DATASET_TABLES,
    PUBLIC_JSON_MAX_FINDING_CODES,
    PUBLIC_JSON_MAX_INDEX_ARTIFACTS,
    PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS,
    PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
    PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH,
    PUBLIC_JSON_MAX_TOKEN_LENGTH,
    PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES,
    PUBLIC_MODEL_TYPES,
    STANDALONE_IDX_ASSOCIATION_DETAIL_CODES,
    STANDALONE_IDX_ASSOCIATION_STATUSES,
    STANDALONE_IDX_EVIDENCE_STATUSES,
)
from dbf_anonymizer.policy import (
    DEFAULT_POLICY,
    FIELD_CAPABILITY_MATRIX_VERSION,
    SUPPORTED_SCHEMA_VERSION,
    field_capability_matrix_snapshot,
)
from dbf_anonymizer.progress import PROGRESS_QUANTUM_VERSION
from dbf_anonymizer.recovery_policy import RecoveryPolicy
from dbf_anonymizer.relationships.assurance import RELATIONAL_ASSURANCE_SCOPE_NOTE
from dbf_anonymizer.relationships.models import (
    COMPARISON_SEMANTICS,
    KEY_ROLES,
    NUMERIC_MEMBER_ENCODING,
    NUMERIC_STRATEGIES,
    RELATIONSHIP_METADATA_SCHEMA_VERSION,
    RELATIONSHIP_PROVENANCES,
    SUPPORTED_NUMERIC_RELATIONSHIP_DBF_TYPES,
    SUPPORTED_RELATIONSHIP_DBF_TYPES,
    SUPPORTED_TEXT_RELATIONSHIP_DBF_TYPES,
)
from dbf_anonymizer.relationships.verification import EVIDENCE_SCHEMA_VERSION
from dbf_anonymizer.transfer_bundle import (
    TRANSFER_MANIFEST_FILENAME,
    TRANSFER_MANIFEST_SCHEMA_VERSION,
    _ALLOWED_INDEX_STATES,
    _ALLOWED_VERIFICATION_STATUSES,
    _DATA_STATE_STANDALONE,
    _FORBIDDEN_BASENAME_MARKERS,
    _FORBIDDEN_SUFFIXES,
    _MANIFEST_ASSURANCE_KEYS,
    _MANIFEST_DBF_ARTIFACT_KEYS,
    _MANIFEST_FPT_ARTIFACT_KEYS,
    _MANIFEST_TOP_LEVEL_KEYS,
)
from dbf_anonymizer.transforms.memo import (
    MEMO_FIELD_TYPES,
    MEMO_MASK_POLICY_VERSION,
    MEMO_PAYLOAD_KIND_BINARY,
    MEMO_PAYLOAD_KIND_TEXT,
)
from dbf_anonymizer.transforms.temporal import TEMPORAL_FIELD_TYPES, TEMPORAL_SHIFT_POLICY_VERSION
from dbf_anonymizer.transforms.text import TEXT_ALPHABET_POLICY_VERSION
from dbf_anonymizer.vault.schema import (
    DDL_STATEMENTS,
    EXPECTED_VAULT_TABLES,
    EXPECTED_VAULT_UNIQUE_INDEXES,
    VAULT_CLOSE_CHECKPOINT,
    VAULT_DATABASE_FILENAME,
    VAULT_JOURNAL_MODE,
    VAULT_SCHEMA_VERSION,
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
)
from dbf_anonymizer.vault.text_allocation import (
    GLOBAL_TEXT_DOMAIN_ID,
    GlobalTextDomainMapping,
)


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = ROOT / "contracts" / "public-contract-1.0.json"
PUBLIC_CALLABLES = (
    "capabilities",
    "build_plan",
    "preflight",
    "pseudonymize",
    "verify_dataset",
    "recover",
    "create_transfer_bundle",
    "verify_transfer_bundle",
)


def _annotation(value: object) -> str | None:
    if value is inspect.Parameter.empty or value is inspect.Signature.empty:
        return None
    if isinstance(value, str):
        return value
    return inspect.formatannotation(value)


def _value(value: object) -> object:
    if value is inspect.Parameter.empty:
        return {"required": True}
    if isinstance(value, Enum):
        return {"enum": type(value).__name__, "value": value.value}
    if value is argparse.SUPPRESS:
        return "ARGPARSE_SUPPRESS"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_value(item) for item in value]
    if callable(value):
        return getattr(value, "__name__", type(value).__name__)
    return repr(value)


def _callable_signature(function: Callable[..., object]) -> dict[str, object]:
    signature = inspect.signature(function)
    return {
        "parameters": [
            {
                "name": parameter.name,
                "kind": parameter.kind.name,
                "annotation": _annotation(parameter.annotation),
                "default": _value(parameter.default),
            }
            for parameter in signature.parameters.values()
        ],
        "return": _annotation(signature.return_annotation),
    }


def _cli_contract() -> dict[str, object]:
    parser = _build_parser()
    subparsers_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    commands: dict[str, object] = {}
    for command in COMMANDS:
        command_parser = subparsers_action.choices[command]
        arguments = []
        for action in command_parser._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            arguments.append(
                {
                    "dest": action.dest,
                    "option_strings": list(action.option_strings),
                    "action": (
                        "store_true"
                        if action.nargs == 0 and action.const is True and action.default is False
                        else "store"
                    ),
                    "required": bool(action.required),
                    "nargs": _value(action.nargs),
                    "default": _value(action.default),
                    "const": _value(action.const),
                    "choices": None
                    if action.choices is None
                    else sorted(str(choice) for choice in action.choices),
                    "type": None
                    if action.type is None
                    else getattr(action.type, "__name__", type(action.type).__name__),
                }
            )
        commands[command] = arguments
    return {"program": PROGRAM, "command_order": list(COMMANDS), "commands": commands}


def _model_fields() -> dict[str, list[str]]:
    return {
        model.__name__: [
            "schema_version",
            "model_type",
            *[
                item.name
                for item in fields(model)  # type: ignore[arg-type]
                if item.name != "execution_context"
            ],
        ]
        for model in sorted(PUBLIC_MODEL_TYPES, key=lambda item: item.__name__)
    }


def _vault_schema() -> dict[str, object]:
    connection = sqlite3.connect(":memory:")
    try:
        for statement in DDL_STATEMENTS:
            connection.execute(statement)
        tables: dict[str, object] = {}
        for table in EXPECTED_VAULT_TABLES:
            columns = [
                {
                    "name": str(row[1]),
                    "type": str(row[2]),
                    "not_null": bool(row[3]),
                    "default": row[4],
                    "primary_key_position": int(row[5]),
                }
                for row in connection.execute(f"PRAGMA table_info({table})")
            ]
            foreign_key_rows = connection.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            grouped: dict[int, dict[str, object]] = {}
            for row in foreign_key_rows:
                group = grouped.setdefault(
                    int(row[0]),
                    {
                        "parent_table": str(row[2]),
                        "columns": [],
                        "on_update": str(row[5]),
                        "on_delete": str(row[6]),
                    },
                )
                cast(list[list[str]], group["columns"]).append([str(row[3]), str(row[4])])
            indexes = []
            for row in connection.execute(f"PRAGMA index_list({table})"):
                name = str(row[1])
                indexes.append(
                    {
                        "name": name,
                        "unique": bool(row[2]),
                        "origin": str(row[3]),
                        "columns": [
                            str(index_row[2])
                            for index_row in connection.execute(f"PRAGMA index_info({name})")
                        ],
                    }
                )
            tables[table] = {
                "columns": columns,
                "foreign_keys": [grouped[key] for key in sorted(grouped)],
                "indexes": sorted(indexes, key=lambda item: cast(str, item["name"])),
            }
        return {
            "schema_version": VAULT_SCHEMA_VERSION,
            "database_filename": VAULT_DATABASE_FILENAME,
            "migration_policy": "EXACT_VERSION_ONLY_NO_AUTOMATIC_MIGRATION",
            "vault_strategy": "SINGLE_DATASET_SQLITE",
            "compatibility_identity": [
                "source_fingerprint",
                "policy_fingerprint",
                "relationship_fingerprint",
                "package_version",
                "dbfbridge_version",
            ],
            "journal_mode": VAULT_JOURNAL_MODE,
            "clean_close_checkpoint": VAULT_CLOSE_CHECKPOINT,
            "expected_tables": list(EXPECTED_VAULT_TABLES),
            "named_bijection_indexes": list(EXPECTED_VAULT_UNIQUE_INDEXES),
            "ddl": [" ".join(statement.split()) for statement in DDL_STATEMENTS],
            "tables": tables,
        }
    finally:
        connection.close()


def _mapping_semantics() -> dict[str, object]:
    allocator = GlobalTextDomainMapping(cast(Any, object()))
    random_source = allocator._random_below
    return {
        "text": {
            "policy_version": TEXT_ALPHABET_POLICY_VERSION,
            "action": "PSEUDONYMIZE_REVERSIBLE",
            "domain_name": "GLOBAL_TEXT",
            "domain_id": GLOBAL_TEXT_DOMAIN_ID,
            "domain_kind": VAULT_TABLE_DOMAIN_KIND_TEXT,
            "first_allocation_random_source": (
                f"{random_source.__module__}.{random_source.__name__}"
            ),
            "secure_random_default": random_source is secrets.randbelow,
            "same_compatible_vault": "STABLE_PERSISTED_REUSE_WITHOUT_REALLOCATION",
            "fresh_vault": "INDEPENDENT_SECURE_RANDOM_ALLOCATION",
            "scope": "ONE_GLOBAL_DOMAIN_ACROSS_TABLES_FIELDS_AND_DIRECTORIES",
            "null_semantics": "PRESERVE_NULL_WITHOUT_MAPPING_ROW",
            "empty_semantics": "PRESERVE_EMPTY_WITHOUT_MAPPING_ROW",
            "mapping": "BIJECTIVE_WITH_SELF_EXCLUSION",
        },
        "memo": {
            "policy_version": MEMO_MASK_POLICY_VERSION,
            "action": "MASK_REVERSIBLE",
            "field_types": sorted(MEMO_FIELD_TYPES),
            "payload_kinds": [MEMO_PAYLOAD_KIND_TEXT, MEMO_PAYLOAD_KIND_BINARY],
            "null_semantics": "PRESERVE_NULL_WITHOUT_RECOVERY_ROW",
            "empty_semantics": "MASK_AND_RECOVER_AS_NON_NULL_PAYLOAD",
            "recovery": "ORIGINAL_PAYLOAD_ONLY_IN_PROTECTED_VAULT",
            "mapping": "TYPE_PRESERVING_MASK_WITH_SELF_EXCLUSION",
        },
        "temporal": {
            "policy_version": TEMPORAL_SHIFT_POLICY_VERSION,
            "action": "SHIFT_REVERSIBLE",
            "field_types": sorted(TEMPORAL_FIELD_TYPES),
            "domain_kind": VAULT_TABLE_DOMAIN_KIND_TEMPORAL,
            "null_semantics": "PRESERVE_NULL",
            "mapping": "ONE_NONZERO_REVERSIBLE_SHIFT_PER_COMPATIBLE_DOMAIN",
            "public_material": "NO_PRIVATE_OFFSET_OR_RECOVERY_PARAMETER",
        },
        "numeric_relationships": {
            "strategies": list(NUMERIC_STRATEGIES),
            "reversible_domain_kind": VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
            "identity": "VALUE_IDENTICAL_AND_PRIVACY_REVIEW_REQUIRED",
            "reversible_bijective": "SHARED_DOMAIN_BIJECTION_WITH_SELF_EXCLUSION",
        },
    }


def _dependency_contract() -> dict[str, object]:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'"(dbfbridge\[write\][^"]+)"', pyproject, flags=re.IGNORECASE)
    if match is None:
        raise RuntimeError("pyproject.toml has no dbfbridge[write] dependency")
    return {
        "requirement": match.group(1),
        "supported_major": "1.x",
        "incompatible_major_without_new_contract": "2.x",
        "vcs_dependency_allowed": False,
        "local_path_dependency_allowed": False,
        "private_api_allowed": False,
    }


def _capability_contract(policy: RecoveryPolicy) -> dict[str, object]:
    payload = public.capabilities(policy).to_dict()
    observed_version = cast(str, payload["dbfbridge_version"])
    payload["dbfbridge_version"] = {
        "contract": "RUNTIME_VERSION_IN_DECLARED_SUPPORTED_RANGE",
        "observed_major": observed_version.partition(".")[0],
    }
    return cast(dict[str, object], payload)


def build_contract() -> dict[str, object]:
    """Return the normalized actual 1.0 contract without writing files."""
    enums = (
        public.TransferProfile,
        public.OutputDataState,
        public.VaultStrategy,
        public.RawByteEquivalence,
        public.VerificationStatus,
        public.RelationalAssuranceLevel,
        RecoveryPolicy,
        public.ErrorCategory,
        public.ErrorCode,
    )
    return {
        "contract_version": "1.0",
        "package_version_status": public.__version__,
        "python_api": {
            "root_exports": sorted(public.__all__),
            "callables": {
                name: _callable_signature(getattr(public, name)) for name in PUBLIC_CALLABLES
            },
        },
        "cli": _cli_contract(),
        "public_json": {
            "schema_versions": {
                "model": public.MODEL_SCHEMA_VERSION,
                "error": public.ERROR_SCHEMA_VERSION,
                "error_registry": public.ERROR_REGISTRY_VERSION,
                "index_backend_protocol": public.INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
                "relationship_metadata": RELATIONSHIP_METADATA_SCHEMA_VERSION,
                "relationship_evidence": EVIDENCE_SCHEMA_VERSION,
                "transfer_manifest": TRANSFER_MANIFEST_SCHEMA_VERSION,
                "vault": VAULT_SCHEMA_VERSION,
                "field_capability_matrix": FIELD_CAPABILITY_MATRIX_VERSION,
                "progress_quantum": PROGRESS_QUANTUM_VERSION,
                "policy": str(SUPPORTED_SCHEMA_VERSION),
            },
            "model_fields": _model_fields(),
            "enums": {
                enum.__name__: [member.value for member in enum]
                for enum in sorted(enums, key=lambda item: item.__name__)
            },
            "limits": {
                "count_max": PUBLIC_JSON_MAX_COUNT,
                "dataset_tables_max_items": PUBLIC_JSON_MAX_DATASET_TABLES,
                "finding_codes_max_items": PUBLIC_JSON_MAX_FINDING_CODES,
                "index_artifacts_max_items": PUBLIC_JSON_MAX_INDEX_ARTIFACTS,
                "numeric_identity_reviews_max_items": PUBLIC_JSON_MAX_NUMERIC_IDENTITY_REVIEWS,
                "operation_id_max_length": PUBLIC_JSON_MAX_OPERATION_ID_LENGTH,
                "relative_path_max_length": PUBLIC_JSON_MAX_RELATIVE_PATH_LENGTH,
                "token_max_length": PUBLIC_JSON_MAX_TOKEN_LENGTH,
                "transformation_classes_max_items": PUBLIC_JSON_MAX_TRANSFORMATION_CLASSES,
            },
            "capabilities": {
                "enabled": _capability_contract(RecoveryPolicy.ENABLED),
                "recovery_disabled": _capability_contract(RecoveryPolicy.DISABLED),
            },
            "progress": {
                "phase_codes": list(PROGRESS_PHASE_CODES),
                "event_codes": list(PROGRESS_EVENT_CODES),
                "quantum_version": PROGRESS_QUANTUM_VERSION,
                "privacy_rule": "BOUNDED_METADATA_ONLY_NO_SOURCE_VALUES",
            },
        },
        "errors": {
            "schema_version": public.ERROR_SCHEMA_VERSION,
            "registry_version": public.ERROR_REGISTRY_VERSION,
            "codes": [
                {"code": definition.code.value, "category": definition.category.value}
                for definition in ERROR_REGISTRY
            ],
        },
        "vault": _vault_schema(),
        "mapping_semantics": _mapping_semantics(),
        "field_capability_matrix": field_capability_matrix_snapshot(),
        "relationships": {
            "metadata_schema_version": RELATIONSHIP_METADATA_SCHEMA_VERSION,
            "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
            "key_roles": list(KEY_ROLES),
            "comparison_semantics": list(COMPARISON_SEMANTICS),
            "numeric_strategies": list(NUMERIC_STRATEGIES),
            "provenances": list(RELATIONSHIP_PROVENANCES),
            "supported_dbf_types": list(SUPPORTED_RELATIONSHIP_DBF_TYPES),
            "text_dbf_types": list(SUPPORTED_TEXT_RELATIONSHIP_DBF_TYPES),
            "numeric_dbf_types": list(SUPPORTED_NUMERIC_RELATIONSHIP_DBF_TYPES),
            "numeric_member_encoding": NUMERIC_MEMBER_ENCODING,
            "assurance_levels": [item.value for item in public.RelationalAssuranceLevel],
            "assurance_scope": RELATIONAL_ASSURANCE_SCOPE_NOTE,
        },
        "index_backend": {
            "protocol_schema_version": public.INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            "artifact_classes": list(INDEX_ARTIFACT_CLASSES),
            "result_statuses": list(INDEX_BACKEND_RESULT_STATUSES),
            "result_detail_codes": list(INDEX_BACKEND_RESULT_DETAIL_CODES),
            "verification_statuses": list(INDEX_VERIFICATION_STATUSES),
            "verification_detail_codes": list(INDEX_VERIFICATION_DETAIL_CODES),
            "standalone_idx_association_statuses": list(STANDALONE_IDX_ASSOCIATION_STATUSES),
            "standalone_idx_association_detail_codes": list(
                STANDALONE_IDX_ASSOCIATION_DETAIL_CODES
            ),
            "standalone_idx_evidence_statuses": list(STANDALONE_IDX_EVIDENCE_STATUSES),
            "transport": "INJECTED_SYNCHRONOUS_TRANSPORT_NEUTRAL_PROTOCOL",
        },
        "transfer_bundle": {
            "manifest_filename": TRANSFER_MANIFEST_FILENAME,
            "schema_version": TRANSFER_MANIFEST_SCHEMA_VERSION,
            "profile": "DATA_ONLY",
            "classification": "PSEUDONYMIZED",
            "data_state": _DATA_STATE_STANDALONE,
            "index_states": sorted(_ALLOWED_INDEX_STATES),
            "verification_statuses": sorted(_ALLOWED_VERIFICATION_STATUSES),
            "allowed_artifact_classes": ["DBF", "FPT"],
            "top_level_keys": sorted(_MANIFEST_TOP_LEVEL_KEYS),
            "dbf_artifact_keys": sorted(_MANIFEST_DBF_ARTIFACT_KEYS),
            "fpt_artifact_keys": sorted(_MANIFEST_FPT_ARTIFACT_KEYS),
            "assurance_keys": sorted(_MANIFEST_ASSURANCE_KEYS),
            "forbidden_suffixes": sorted(_FORBIDDEN_SUFFIXES),
            "forbidden_basename_markers": list(_FORBIDDEN_BASENAME_MARKERS),
            "forbidden_material": [
                "SQLITE_VAULT_AND_WAL_SHM_JOURNAL",
                "RECOVERY_MAPPINGS_AND_MATERIAL",
                "PRIVATE_OFFSETS_AND_RECOVERY_PARAMETERS",
                "SECRETS_AND_ORIGINAL_VALUES",
                "PRIVATE_PATHS_AND_LOGS",
                "STALE_OR_UNVERIFIED_CDX_IDX_DBC_DCT_DCX",
            ],
        },
        "dependency_contract": _dependency_contract(),
        "semantic_versioning": {
            "patch": "BUGFIX_WITHOUT_INCOMPATIBLE_PUBLIC_CONTRACT_CHANGE",
            "minor": "BACKWARD_COMPATIBLE_ADDITION_SUBJECT_TO_SCHEMA_VERSION_POLICY",
            "major_required_for": [
                "PUBLIC_API_REMOVAL_OR_RENAME",
                "INCOMPATIBLE_PUBLIC_SIGNATURE",
                "INCOMPATIBLE_CLI_CHANGE",
                "SCHEMA_REINTERPRETATION",
                "ERROR_CODE_REUSE_OR_REMOVAL",
                "INCOMPATIBLE_VAULT_SCHEMA_OR_POLICY",
                "INCOMPATIBLE_MAPPING_SEMANTICS",
                "SUPPORTED_FIELD_BEHAVIOR_REMOVAL",
                "INCOMPATIBLE_RELATIONSHIP_SEMANTICS",
                "INCOMPATIBLE_TRANSFER_BUNDLE_SCHEMA",
                "SUPPORTED_DBFBRIDGE_MAJOR_RANGE_BREAK",
            ],
            "schema_rule": (
                "PACKAGE_MINOR_DOES_NOT_AUTHORIZE_A_VERSIONED_JSON_SCHEMA_CHANGE_"
                "WITHOUT_THE_REQUIRED_SCHEMA_VERSION_CHANGE"
            ),
        },
        "default_policy": DEFAULT_POLICY,
    }


def _serialized_contract() -> str:
    return json.dumps(build_contract(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="explicitly replace contracts/public-contract-1.0.json",
    )
    arguments = parser.parse_args(argv)
    serialized = _serialized_contract()
    if arguments.write:
        SNAPSHOT_PATH.write_text(serialized, encoding="ascii", newline="\n")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
