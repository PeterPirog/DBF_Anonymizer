"""REQ-P8-001: objective freeze of the DBF_Anonymizer 1.0 contract."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from typing import Any

import pytest

from tools.generate_public_contract_snapshot import SNAPSHOT_PATH, build_contract


Mutation = Callable[[dict[str, Any]], None]


def _frozen_contract() -> dict[str, Any]:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="ascii"))


def _assert_frozen(actual: dict[str, Any], expected: dict[str, Any]) -> None:
    def first_difference(left: object, right: object, path: str = "$") -> str | None:
        if type(left) is not type(right):
            return path
        if isinstance(left, dict) and isinstance(right, dict):
            if set(left) != set(right):
                return path
            for key in sorted(left):
                difference = first_difference(left[key], right[key], f"{path}.{key}")
                if difference is not None:
                    return difference
            return None
        if isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                return path
            for index, (left_item, right_item) in enumerate(zip(left, right, strict=True)):
                difference = first_difference(left_item, right_item, f"{path}[{index}]")
                if difference is not None:
                    return difference
            return None
        return None if left == right else path

    difference = first_difference(actual, expected)
    assert difference is None, f"public contract differs at {difference}"


def test_actual_public_contract_matches_committed_1_0_snapshot() -> None:
    expected = _frozen_contract()
    actual = build_contract()
    _assert_frozen(actual, expected)
    assert SNAPSHOT_PATH.name == "public-contract-1.0.json"
    assert SNAPSHOT_PATH.parent.name == "contracts"
    assert SNAPSHOT_PATH.read_text(encoding="ascii") == (
        json.dumps(expected, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    )


def _removed_public_function(contract: dict[str, Any]) -> None:
    del contract["python_api"]["callables"]["recover"]


def _incompatible_signature(contract: dict[str, Any]) -> None:
    contract["python_api"]["callables"]["pseudonymize"]["parameters"][1]["kind"] = (
        "POSITIONAL_OR_KEYWORD"
    )


def _removed_cli_command(contract: dict[str, Any]) -> None:
    contract["cli"]["command_order"].remove("verify-bundle")


def _changed_schema_version(contract: dict[str, Any]) -> None:
    contract["public_json"]["schema_versions"]["model"] = "1.9"


def _removed_error_code(contract: dict[str, Any]) -> None:
    contract["errors"]["codes"].pop()


def _reassigned_error_code(contract: dict[str, Any]) -> None:
    contract["errors"]["codes"][0]["category"] = "vault"


def _changed_vault_schema(contract: dict[str, Any]) -> None:
    contract["vault"]["schema_version"] = "2.0"


def _changed_mapping_domain(contract: dict[str, Any]) -> None:
    contract["mapping_semantics"]["text"]["domain_id"] = "dom-incompatible"


def _removed_field_capability(contract: dict[str, Any]) -> None:
    contract["field_capability_matrix"]["rules"].pop()


def _changed_relationship_assurance(contract: dict[str, Any]) -> None:
    contract["relationships"]["assurance_levels"].remove("INCOMPLETE")


def _changed_bundle_schema(contract: dict[str, Any]) -> None:
    contract["transfer_bundle"]["schema_version"] = "2.0"


def _widened_dbfbridge_major(contract: dict[str, Any]) -> None:
    contract["dependency_contract"]["requirement"] = "dbfbridge[write]>=1.1.0,<3"


@pytest.mark.parametrize(
    ("mutation", "difference_path"),
    [
        (_removed_public_function, r"\$\.python_api\.callables"),
        (_incompatible_signature, r"\$\.python_api\.callables\.pseudonymize"),
        (_removed_cli_command, r"\$\.cli\.command_order"),
        (_changed_schema_version, r"\$\.public_json\.schema_versions\.model"),
        (_removed_error_code, r"\$\.errors\.codes"),
        (_reassigned_error_code, r"\$\.errors\.codes\[0\]\.category"),
        (_changed_vault_schema, r"\$\.vault\.schema_version"),
        (_changed_mapping_domain, r"\$\.mapping_semantics\.text\.domain_id"),
        (_removed_field_capability, r"\$\.field_capability_matrix\.rules"),
        (_changed_relationship_assurance, r"\$\.relationships\.assurance_levels"),
        (_changed_bundle_schema, r"\$\.transfer_bundle\.schema_version"),
        (_widened_dbfbridge_major, r"\$\.dependency_contract\.requirement"),
    ],
    ids=lambda value: value.__name__.removeprefix("_") if callable(value) else None,
)
def test_incompatible_mutation_is_detected(mutation: Mutation, difference_path: str) -> None:
    frozen = _frozen_contract()
    mutated = copy.deepcopy(build_contract())
    mutation(mutated)
    with pytest.raises(AssertionError, match=difference_path):
        _assert_frozen(mutated, frozen)


def test_snapshot_contains_no_sensitive_rows_or_recovery_material() -> None:
    frozen = _frozen_contract()
    frozen_text = SNAPSHOT_PATH.read_text(encoding="ascii").lower()
    forbidden_data_keys = {
        "sample_rows",
        "sample_values",
        "original_values",
        "pseudonyms",
        "reverse_mappings",
        "recovery_parameters",
        "private_paths",
        "secrets",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {key for child in value.values() for key in keys(child)}
        if isinstance(value, list):
            return {key for child in value for key in keys(child)}
        return set()

    def strings(value: object) -> list[str]:
        if isinstance(value, dict):
            return [item for child in value.values() for item in strings(child)]
        if isinstance(value, list):
            return [item for child in value for item in strings(child)]
        return [value] if isinstance(value, str) else []

    assert not (forbidden_data_keys & keys(frozen))
    private_path = re.compile(r"(?i)(?:^[a-z]:[\\/]|^\\\\|^/(?:home|users|private|var)/)")
    assert not [value for value in strings(frozen) if private_path.search(value)]
    assert "production data" not in frozen_text


def test_semver_policy_is_complete_and_keeps_prerelease_version() -> None:
    frozen = _frozen_contract()
    semver = frozen["semantic_versioning"]
    assert frozen["package_version_status"] == "1.0.0.dev0"
    assert semver["patch"] == "BUGFIX_WITHOUT_INCOMPATIBLE_PUBLIC_CONTRACT_CHANGE"
    assert semver["minor"] == ("BACKWARD_COMPATIBLE_ADDITION_SUBJECT_TO_SCHEMA_VERSION_POLICY")
    assert len(semver["major_required_for"]) == 11
    assert semver["schema_rule"].startswith("PACKAGE_MINOR_DOES_NOT_AUTHORIZE")
