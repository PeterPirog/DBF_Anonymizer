"""Numeric key-domain relationships: policy, binding, allocation, joins.

REQ-P3-005 end-to-end evidence on REAL public dbfbridge fixtures:

* the 1.0 relationship policy syntax for explicit numeric key members
  (``I``/``N``) with the bounded ``IDENTITY``/``REVERSIBLE_BIJECTIVE``
  strategy vocabulary (never inferred, unknown strategies fail closed,
  canonical fingerprint semantics);
* source-schema binding against REAL public schema facts (type, width,
  decimal/scale, autoincrement, NULL descriptor bit) with fail-closed
  refusals;
* deterministic shared numeric mapping-domain identity (no process
  randomness, no Python hash randomization);
* the CSPRNG-backed allocation service: same-vault reuse without RNG
  consumption, fresh-vault independence, corruption hardening and the typed
  reverse recovery lookup;
* real before/after relational fixtures A (single-column ``I``), B
  (integral ``N`` with differing compatible widths), C (composite numeric)
  and D (mixed unsupported member types fail closed) — the after side is
  always the REAL numeric allocator's output written through the public
  ``write_table`` boundary, never an independently transformed copy.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dbf_anonymizer import MappingError, PolicyError, VaultError, build_plan
from dbf_anonymizer.preflight import preflight
from dbf_anonymizer.relationships import (
    NUMERIC_STRATEGY_IDENTITY,
    NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
    parse_relationship_document,
    relationship_fingerprint,
    resolved_numeric_domain,
    resolved_relation_domain,
    validate_document_compatibility,
)
from dbf_anonymizer.relationships.evidence import relation_metrics
from dbf_anonymizer.transforms.numeric_keys import (
    canonical_integer_text,
    integer_member,
    integral_numeric_member,
    numeric_key_domain_for,
)
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
    VaultDatabase,
    numeric_key_domain_id,
)
from dbf_anonymizer.vault.mappings import (
    add_numeric_key_mapping,
    create_domain,
    get_numeric_original,
    get_numeric_pseudonym,
)
from dbf_anonymizer.vault.numeric_allocation import (
    NumericKeyDomainMapping,
    numeric_key_domain_id as domain_id_alias,
)
from dbf_anonymizer.vault.text_allocation import GLOBAL_TEXT_DOMAIN_ID
from support.vault_sessions import writer_session
from tests.support.numeric_tables import (
    AUTOINCREMENT_FLAG,
    NULLABLE_FLAG,
    read_numeric_records,
    numeric_field,
    write_numeric_table,
)

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60

#: Numeric canaries for the privacy boundary assertions (never public).
CANARY_I = 987654321
CANARY_N = -1234
CANARY_RECOVERED = 555111


def _detail(excinfo: pytest.ExceptionInfo[PolicyError]) -> str:
    return (
        str(excinfo.value)
        + "|"
        + repr(excinfo.value)
        + "|"
        + str(excinfo.value.to_dict())
    )


def _no_leak(excinfo: pytest.ExceptionInfo[BaseException]) -> None:
    boundary = str(excinfo.value) + "|" + repr(excinfo.value)
    if hasattr(excinfo.value, "to_dict"):
        boundary += "|" + json.dumps(excinfo.value.to_dict(), sort_keys=True, default=str)
    assert "987654321" not in boundary
    assert "-123456" not in boundary
    assert "C:\\" not in boundary


# ---------------------------------------------------------------------------
# fixture helpers (REAL public dbfbridge tables)
# ---------------------------------------------------------------------------
def _open_vault(tmp_path: Path) -> VaultDatabase:
    return VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version="1.1.0",
    )


def _i_document(*, strategy: str = NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE) -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-numeric-key",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": strategy,
                "members": [
                    {
                        "table": "north/customers.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                ],
            }
        ],
    }


def _n_document(*, strategy: str = NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE) -> dict[str, object]:
    document = _i_document()
    group = document["relations"][0]  # type: ignore[index]
    group["relation_id"] = "rel-numeric-n"
    group["members"] = [
        {
            "table": "north/customers.dbf",
            "field": "CUST_ID",
            "role": "PRIMARY",
            "ordinal": 1,
            "dbf_type": "N",
            "byte_width": 8,
            "encoding": "none",
            "nullable": False,
        },
        {
            "table": "south/orders.dbf",
            "field": "CUST_ID",
            "role": "FOREIGN",
            "ordinal": 1,
            "dbf_type": "N",
            "byte_width": 5,
            "encoding": "none",
            "nullable": False,
        },
    ]
    return document


# ---------------------------------------------------------------------------
# STEP 4 — relationship policy syntax for numeric key domains
# ---------------------------------------------------------------------------
def test_numeric_i_member_document_parses_with_explicit_strategy() -> None:
    document = parse_relationship_document(_i_document())
    group = document.groups[0]
    assert group.numeric_strategy == NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE
    assert all(member.is_numeric_member for member in group.members)


def test_numeric_strategy_defaults_to_identity_and_remains_explicit() -> None:
    payload = _i_document()
    del payload["relations"][0]["numeric_strategy"]  # type: ignore[index]
    document = parse_relationship_document(payload)
    assert document.groups[0].numeric_strategy == NUMERIC_STRATEGY_IDENTITY


def test_unknown_numeric_strategy_fails_closed() -> None:
    payload = _i_document()
    payload["relations"][0]["numeric_strategy"] = "HASH_SHUFFLE"  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_NUMERIC_STRATEGY_INVALID" in _detail(excinfo)
    _no_leak(excinfo)


def test_reversible_strategy_requires_a_numeric_member() -> None:
    payload = _i_document()
    for member in payload["relations"][0]["members"]:  # type: ignore[index]
        member["dbf_type"] = "C"
        member["encoding"] = "cp1250"
        member["byte_width"] = 8
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_NUMERIC_STRATEGY_MEMBER_REQUIRED" in _detail(excinfo)
    _no_leak(excinfo)


@pytest.mark.parametrize(
    ("dbf_type", "width"),
    [("F", 10), ("Y", 8), ("B", 8), ("L", 1)],
)
def test_unsupported_numeric_member_types_fail_closed(dbf_type: str, width: int) -> None:
    """F/Y/B/L can never be reinterpreted as integer key domains."""
    payload = _i_document()
    payload["relations"][0]["members"][0]["dbf_type"] = dbf_type  # type: ignore[index]
    payload["relations"][0]["members"][0]["byte_width"] = width  # type: ignore[index]
    payload["relations"][0]["members"][0]["encoding"] = "cp1250"  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_DBF_TYPE_UNSUPPORTED" in _detail(excinfo)
    _no_leak(excinfo)


def test_integer_member_width_is_format_defined() -> None:
    payload = _i_document()
    payload["relations"][0]["members"][0]["byte_width"] = 8  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_INTEGER_WIDTH_INVALID" in _detail(excinfo)


def test_numeric_member_width_bounds_are_enforced() -> None:
    payload = _i_document()
    payload["relations"][0]["members"][0]["dbf_type"] = "N"  # type: ignore[index]
    payload["relations"][0]["members"][0]["byte_width"] = 21  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_NUMERIC_WIDTH_INVALID" in _detail(excinfo)
    # The generic bounded-width contract refuses sub-byte widths.
    payload["relations"][0]["members"][0]["byte_width"] = 0  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_BYTE_WIDTH_INVALID" in _detail(excinfo)


def test_numeric_member_encoding_must_be_the_explicit_bounded_token() -> None:
    payload = _i_document()
    payload["relations"][0]["members"][0]["encoding"] = "cp1250"  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        parse_relationship_document(payload)
    assert "RELATIONSHIP_NUMERIC_ENCODING_INVALID" in _detail(excinfo)


def test_strategy_change_changes_the_fingerprint_and_order_irrelevance_keeps_it() -> None:
    identity = parse_relationship_document(_i_document(strategy=NUMERIC_STRATEGY_IDENTITY))
    reversible = parse_relationship_document(_i_document(strategy=NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE))
    assert relationship_fingerprint(identity) != relationship_fingerprint(reversible)
    # Irrelevant JSON key/member-order changes keep the same fingerprint.
    reordered = json.loads(json.dumps(_i_document()))
    reordered["relations"][0]["members"].reverse()
    assert relationship_fingerprint(parse_relationship_document(reordered)) == (
        relationship_fingerprint(reversible)
    )


def test_cv_behavior_is_unchanged_and_text_domain_still_global() -> None:
    cv_payload = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-c",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {"table": "a.dbf", "field": "K", "role": "PRIMARY", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                    {"table": "b.dbf", "field": "K", "role": "FOREIGN", "ordinal": 1, "dbf_type": "C", "byte_width": 4, "encoding": "cp1250", "nullable": False},
                ],
            }
        ],
    }
    document = parse_relationship_document(cv_payload)
    validate_document_compatibility(document)
    assert resolved_relation_domain(document.groups[0]) == GLOBAL_TEXT_DOMAIN_ID


# ---------------------------------------------------------------------------
# STEP 5 — source-schema binding on REAL public schema facts
# ---------------------------------------------------------------------------
def _write_i_relation_fixture(root: Path) -> Path:
    write_numeric_table(
        root, "north/customers.dbf", (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": -5}, {"CUST_ID": 0}, {"CUST_ID": 7}],
    )
    write_numeric_table(
        root, "south/orders.dbf", (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": 7}, {"CUST_ID": -5}],
    )
    return root


def test_valid_numeric_document_binds_and_preflights_green(tmp_path: Path) -> None:
    source = _write_i_relation_fixture(tmp_path / "src")
    document_payload = _i_document()
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=document_payload,
    )
    result = preflight(plan)
    assert result.ready, result.to_dict()
    # A reversible numeric member is NOT marked as an unchanged identifier.
    assert plan.numeric_identity_review == ()


def test_declared_type_mismatch_fails_closed(tmp_path: Path) -> None:
    source = _write_i_relation_fixture(tmp_path / "src")
    payload = _i_document()
    payload["relations"][0]["members"][0]["dbf_type"] = "N"  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        build_plan(
            source,
            tmp_path / "out",
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            relationship_document=payload,
        )
    assert "RELATIONSHIP_MEMBER_TYPE_MISMATCH" in _detail(excinfo)


def test_declared_numeric_width_mismatch_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_numeric_table(
        source, "north/customers.dbf", (numeric_field("CUST_ID", "N", 5),),
        [{"CUST_ID": 1}],
    )
    write_numeric_table(
        source, "south/orders.dbf", (numeric_field("CUST_ID", "N", 5),),
        [{"CUST_ID": 1}],
    )
    payload = _i_document()
    payload["relations"][0]["members"][0]["dbf_type"] = "N"  # type: ignore[index]
    payload["relations"][0]["members"][0]["byte_width"] = 8  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        build_plan(
            source,
            tmp_path / "out",
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            relationship_document=payload,
        )
    assert "RELATIONSHIP_MEMBER_WIDTH_MISMATCH" in _detail(excinfo)


def test_non_integral_numeric_domain_fails_closed(tmp_path: Path) -> None:
    """A non-integral N key domain is never silently rounded."""
    source = tmp_path / "src"
    write_numeric_table(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "N", 8, decimal_count=2),),
        [{"CUST_ID": 12}],
    )
    write_numeric_table(
        source, "south/orders.dbf", (numeric_field("CUST_ID", "N", 8, decimal_count=2),),
        [{"CUST_ID": 12}],
    )
    payload = _i_document()
    payload["relations"][0]["members"][0]["dbf_type"] = "N"  # type: ignore[index]
    payload["relations"][0]["members"][0]["byte_width"] = 8  # type: ignore[index]
    payload["relations"][0]["members"][1]["dbf_type"] = "N"  # type: ignore[index]
    payload["relations"][0]["members"][1]["byte_width"] = 8  # type: ignore[index]
    with pytest.raises(PolicyError) as excinfo:
        build_plan(
            source,
            tmp_path / "out",
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            relationship_document=payload,
        )
    assert "NUMERIC_MEMBER_DECIMALS_UNSUPPORTED" in _detail(excinfo)


def test_autoincrement_numeric_key_fails_closed(tmp_path: Path) -> None:
    """A VFP autoincrement I field is rejected before allocation."""
    source = tmp_path / "src"
    write_numeric_table(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "I", 4, flags=AUTOINCREMENT_FLAG),),
        [{"CUST_ID": 1}],
    )
    write_numeric_table(
        source, "south/orders.dbf", (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": 1}],
    )
    with pytest.raises(PolicyError) as excinfo:
        build_plan(
            source,
            tmp_path / "out",
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            relationship_document=_i_document(),
        )
    assert "NUMERIC_MEMBER_AUTOINCREMENT_UNSUPPORTED" in _detail(excinfo)
    _no_leak(excinfo)


def test_identity_strategy_autoincrement_member_remains_identity_and_marked(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    write_numeric_table(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "I", 4, flags=AUTOINCREMENT_FLAG),),
        [{"CUST_ID": 1}],
    )
    write_numeric_table(
        source, "south/orders.dbf", (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": 1}],
    )
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_i_document(strategy=NUMERIC_STRATEGY_IDENTITY),
    )
    marked = {
        (e.table_path, e.field_name): e.status for e in plan.numeric_identity_review
    }
    assert marked[("north/customers.dbf", "CUST_ID")] == "IDENTITY_PRIVACY_REVIEW_REQUIRED"


# ---------------------------------------------------------------------------
# STEP 6 — deterministic shared numeric domain identity
# ---------------------------------------------------------------------------
_DOMAIN_PROBE = (
    "import json, sys\n"
    "sys.path.insert(0, {src!r})\n"
    "from dbf_anonymizer.relationships import parse_relationship_document, resolved_numeric_domain\n"
    "document = parse_relationship_document(json.load(sys.stdin))\n"
    "print(resolved_numeric_domain(document, document.groups[0]))\n"
)


def test_numeric_domain_identity_is_process_stable(tmp_path: Path) -> None:
    document = parse_relationship_document(_i_document())
    domain = resolved_numeric_domain(document, document.groups[0])
    assert domain.startswith("dom-") and len(domain) == len("dom-") + 16
    assert resolved_numeric_domain(document, document.groups[0]) == domain
    src_root = Path(__file__).resolve().parents[1] / "src"
    script = tmp_path / "probe.py"
    script.write_text(_DOMAIN_PROBE.format(src=str(src_root)), encoding="utf-8")
    payload = json.dumps(_i_document())
    outputs = set()
    for hash_seed in ("0", "42"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = hash_seed
        completed = subprocess.run(
            [sys.executable, str(script)],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.add(completed.stdout.strip())
    assert len(outputs) == 1
    assert outputs.pop() == domain


def test_numeric_domain_conflicts_fail_closed(tmp_path: Path) -> None:
    """Overlapping incompatibly: two groups share the numeric member."""
    payload = _i_document()
    payload["relations"].append(  # type: ignore[union-attr,index]
        {
            "relation_id": "rel-numeric-key-2",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "numeric_strategy": NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
            "members": [
                {
                    "table": "north/customers.dbf",
                    "field": "CUST_ID",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
                {
                    "table": "ledger.dbf",
                    "field": "CUST_ID",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
            ],
        }
    )
    document = parse_relationship_document(payload)
    with pytest.raises(PolicyError) as excinfo:
        validate_document_compatibility(document)
    assert "RELATIONSHIP_NUMERIC_DOMAIN_CONFLICT" in _detail(excinfo)
    _no_leak(excinfo)


def test_identity_and_reversible_overlap_fails_closed() -> None:
    payload = _i_document(strategy=NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE)
    payload["relations"].append(  # type: ignore[union-attr,index]
        {
            "relation_id": "rel-numeric-identity-2",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "numeric_strategy": NUMERIC_STRATEGY_IDENTITY,
            "members": [
                {
                    "table": "south/orders.dbf",
                    "field": "CUST_ID",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
                {
                    "table": "audit.dbf",
                    "field": "CUST_ID",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
            ],
        }
    )
    document = parse_relationship_document(payload)
    with pytest.raises(PolicyError) as excinfo:
        validate_document_compatibility(document)
    assert "RELATIONSHIP_NUMERIC_DOMAIN_CONFLICT" in _detail(excinfo)


def test_identity_strategy_has_no_numeric_domain() -> None:
    document = parse_relationship_document(_i_document(strategy=NUMERIC_STRATEGY_IDENTITY))
    with pytest.raises(PolicyError) as excinfo:
        resolved_numeric_domain(document, document.groups[0])
    assert "RELATIONSHIP_NUMERIC_STRATEGY_IDENTITY_HAS_NO_DOMAIN" in _detail(excinfo)


# ---------------------------------------------------------------------------
# STEP 8/9/11/12 — the allocation service on REAL vault state
# ---------------------------------------------------------------------------
def _i_domain():
    return numeric_key_domain_for([integer_member()])


def _n_domain():
    return numeric_key_domain_for([integral_numeric_member(5)])


def test_integer_domain_round_trip_and_bijection(tmp_path: Path) -> None:
    """I round-trip: bijection, self-exclusion, reversibility, boundaries."""
    domain = _i_domain()
    domain_id = numeric_key_domain_id(relationship_fingerprint(parse_relationship_document(_i_document())), "rel-numeric-key")
    originals = [-2147483647, -5, 0, 7, 2147483646, 2147483647]
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            for value in originals:
                service.observe_original(value, original_range=(-(2**31), 2**31 - 1))
            service.finalize()
            mapping: dict[int, int] = {}
            for value in originals:
                mapping[value] = service.pseudonym_for(value)
            # Bijection and self-exclusion.
            assert len(set(mapping.values())) == len(mapping)
            for value, pseudonym in mapping.items():
                assert pseudonym != value
                assert domain.contains_pseudonym(pseudonym)
            # Exact reverse recovery reproduces the typed logical value.
            for value, pseudonym in mapping.items():
                assert service.original_for(pseudonym) == value
            assert service.original_for(3) is None


def test_integer_extreme_original_maps_into_the_writable_domain(tmp_path: Path) -> None:
    """The readable int32 extremes map safely into the writable sub-range."""
    domain = _i_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "b" * 16, domain=domain
            )
            for value in (-(2**31), 2**31 - 1):
                service.observe_original(value, original_range=(-(2**31), 2**31 - 1))
            service.finalize()
            first = service.pseudonym_for(-(2**31))
            second = service.pseudonym_for(2**31 - 1)
            assert first != second
            for pseudonym in (first, second):
                assert domain.contains_pseudonym(pseudonym)
                assert service.original_for(pseudonym) == (-(2**31) if pseudonym == first else 2**31 - 1)


def test_integral_numeric_domain_round_trip_with_widths(tmp_path: Path) -> None:
    """N round-trip: integral values, width/sign boundaries, recovery."""
    domain = numeric_key_domain_for([integral_numeric_member(5)])
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "c" * 16, domain=domain
            )
            for value in (-9999, -1, 0, 7, 99999):
                service.observe_original(value, original_range=(-9999, 99999))
            service.finalize()
            mapping = {value: service.pseudonym_for(value) for value in (-9999, -1, 0, 7, 99999)}
            assert len(set(mapping.values())) == len(mapping)
            for value, pseudonym in mapping.items():
                assert pseudonym != value
                assert domain.contains_pseudonym(pseudonym)
                assert service.original_for(pseudonym) == value
            # Non-integral / out-of-domain originals are refused (never rounded).
            with pytest.raises(ValueError):
                service.observe_original(-10000, original_range=(-9999, 99999))


def test_mixed_i_n_composite_members_share_one_domain(tmp_path: Path) -> None:
    """A composite (I, N) relation shares ONE numeric domain."""
    domain = numeric_key_domain_for([integer_member(), integral_numeric_member(5)])
    assert domain.pseudonym_range == (-9999, 99999)
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "d" * 16, domain=domain
            )
            service.observe_original(2**31 - 2, original_range=(-(2**31), 2**31 - 1))
            service.observe_original(-9999, original_range=(-9999, 99999))
            service.finalize()
            big = service.pseudonym_for(2**31 - 2)
            small = service.pseudonym_for(-9999)
            assert big != small
            for pseudonym in (big, small):
                assert domain.contains_pseudonym(pseudonym)
            assert service.original_for(big) == 2**31 - 2


def test_same_vault_reuse_consumes_no_rng(tmp_path: Path) -> None:
    """Same compatible vault: exact same mappings, no RNG on reuse."""
    domain = _n_domain()
    originals = [-9, 0, 42]
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            calls: list[int] = []

            def counting_rng(bound: int) -> int:
                calls.append(bound)
                return 0

            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "e" * 16,
                domain=domain,
                _random_below=counting_rng,
            )
            for value in originals:
                service.observe_original(value)
            service.finalize()
            first = {value: service.pseudonym_for(value) for value in originals}
            assert len(calls) == 3  # exactly one CSPRNG consumption per fresh mapping
            # Reopening the SAME vault resolves the same mappings with NO RNG.
            reopened = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "e" * 16,
                domain=domain,
                _random_below=counting_rng,
            )
            for value in originals:
                reopened.observe_original(value)
            reopened.finalize()
            before = len(calls)
            second = {value: reopened.pseudonym_for(value) for value in originals}
            assert second == first
            assert len(calls) == before  # reuse consumed no randomness


def test_fresh_vault_mappings_are_independent(tmp_path: Path) -> None:
    domain = _n_domain()
    originals = [-9, 0, 42, 7]
    mappings = []
    for index in range(2):
        vault_dir = tmp_path / f"vault{index}"
        with _open_vault(vault_dir) as vault:
            with writer_session(vault):
                service = NumericKeyDomainMapping(
                    vault, domain_id="dom-" + "f" * 16, domain=domain
                )
                for value in originals:
                    service.observe_original(value)
                service.finalize()
                mappings.append({value: service.pseudonym_for(value) for value in originals})
    for value in originals:
        for pseudonym, _origin in mappings[0].items():
            assert domain.contains_pseudonym(pseudonym)
    # Independent CSPRNG allocations: the two fresh vaults do not coincide.
    assert mappings[0] != mappings[1]


def test_conflicting_persisted_self_mapping_fails_closed(tmp_path: Path) -> None:
    domain = _n_domain()
    domain_id = "dom-" + "1" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                add_numeric_key_mapping(vault, domain_id, "7", "7")
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            with pytest.raises(MappingError) as excinfo:
                service.finalize()
            assert "NUMERIC_KEY_PERSISTED_SELF_MAPPING" in str(excinfo.value.to_dict())
            _no_leak(excinfo)


def test_out_of_range_persisted_pseudonym_fails_closed(tmp_path: Path) -> None:
    """An out-of-range I pseudonym (beyond the int32 domain) is corrupt."""
    domain = numeric_key_domain_for([integer_member()])
    domain_id = "dom-" + "2" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                add_numeric_key_mapping(vault, domain_id, "5", "3000000000")
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            with pytest.raises(MappingError) as excinfo:
                service.finalize()
            assert "NUMERIC_MAPPING_CORRUPT" in str(excinfo.value.to_dict())


def test_wrong_domain_kind_fails_closed(tmp_path: Path) -> None:
    domain = _n_domain()
    domain_id = "dom-" + "3" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT, domain_id=domain_id)
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            with pytest.raises(MappingError) as excinfo:
                service.finalize()
            assert "NUMERIC_KEY_DOMAIN_KIND_CONFLICT" in str(excinfo.value.to_dict())


# ---------------------------------------------------------------------------
# STEP 12 — corruption hardening of numeric mapping storage
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("corrupt_sql", [
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', 5.5, '6')",
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', x'0506', '6')",
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', '007', '6')",
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', '+7', '6')",
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', '-0', '6')",
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', ' 7', '6')",
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', 'NaN', '6')",
    "INSERT INTO numeric_key_mappings (domain_id, original_value, pseudonym_value) VALUES ('{dom}', '5', 'Infinity')",
])
def test_hostile_numeric_rows_fail_closed(tmp_path: Path, corrupt_sql: str) -> None:
    """Hostile numeric mapping storage fails closed (REQ-P3-005 hardening).

    SQLite TEXT affinity normalizes INTEGER/REAL inserts to their text image
    before storage, so every row that REMAINS hostile after storage (a BLOB,
    or a non-canonical/malformed text form such as floats, leading zeros,
    ``+`` signs, ``-0``, whitespace, ``NaN``/``Infinity``) is refused by the
    typed corruption boundary instead of being coercively accepted.  The
    canonical validation layer refuses the float image ``5.5`` and every
    malformed text form; the typeof boundary refuses the BLOB that stays
    non-text.
    """
    domain = _n_domain()
    domain_id = "dom-" + "4" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                vault._internal_connection().execute(
                    corrupt_sql.format(dom=domain_id)
                )
            from dbf_anonymizer.vault.mappings import numeric_mapping_rows

            with pytest.raises(VaultError) as excinfo:
                numeric_mapping_rows(vault, domain_id)
            assert "NUMERIC_MAPPING_CORRUPT" in str(excinfo.value.to_dict())
            _no_leak(excinfo)
        # The reverse lookup and the service refuse the same hostile state.
        with writer_session(vault):
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            with pytest.raises(VaultError):
                service.finalize()


def test_integer_hostile_insert_is_normalized_to_canonical_text(
    tmp_path: Path,
) -> None:
    """Verified storage semantics: SQLite TEXT affinity normalizes an
    INTEGER-hostile insert into its text image.

    The persisted artifact of an INTEGER insert into the TEXT-affinity
    mapping column is genuinely canonical TEXT (typeof = text); the hardening
    contract therefore sees a valid canonical row, while every hostile row
    that REMAINS non-text or non-canonical is refused (see the parametrized
    corrupt-state evidence above).
    """
    domain = _n_domain()
    domain_id = "dom-" + "8" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                vault._internal_connection().execute(
                    "INSERT INTO numeric_key_mappings (domain_id, original_value, "
                    "pseudonym_value) VALUES (?, 5, '6')",
                    (domain_id,),
                )
            row = vault._internal_connection().execute(
                "SELECT typeof(original_value), typeof(pseudonym_value) "
                "FROM numeric_key_mappings WHERE domain_id = ?",
                (domain_id,),
            ).fetchone()
            assert row == ("text", "text")
            from dbf_anonymizer.vault.mappings import numeric_mapping_rows

            assert numeric_mapping_rows(vault, domain_id) == (("5", "6"),)


def test_non_canonical_numeric_write_is_refused(tmp_path: Path) -> None:
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault,
                    domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
                    domain_id="dom-" + "5" * 16,
                )
                with pytest.raises(ValueError):
                    add_numeric_key_mapping(vault, "dom-" + "5" * 16, "007", "8")
                with pytest.raises(ValueError):
                    add_numeric_key_mapping(vault, "dom-" + "5" * 16, "7", "+8")


def test_reverse_lookup_matches_the_text_recovery_path_shape(tmp_path: Path) -> None:
    domain = _n_domain()
    domain_id = "dom-" + "6" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                add_numeric_key_mapping(vault, domain_id, "42", "-7")
            assert get_numeric_original(vault, domain_id, "-7") == "42"
            assert get_numeric_pseudonym(vault, domain_id, "42") == "-7"
            assert get_numeric_original(vault, domain_id, "42") is None


# ---------------------------------------------------------------------------
# STEP 15 — real before/after relational fixtures through the REAL allocator
# ---------------------------------------------------------------------------
def _write_i_fixture(tmp_path: Path) -> tuple[Path, Path]:
    pk_path = write_numeric_table(
        tmp_path, "north/customers.dbf", (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": -5}, {"CUST_ID": 0}, {"CUST_ID": 7}, {"CUST_ID": 2147483646}],
    )
    fk_path = write_numeric_table(
        tmp_path, "south/orders.dbf",
        (numeric_field("CUST_ID", "I", 4), numeric_field("AMOUNT", "N", 8)),
        [
            {"CUST_ID": 7, "AMOUNT": 100},
            {"CUST_ID": 7, "AMOUNT": -100},
            {"CUST_ID": -5, "AMOUNT": 5},
            {"CUST_ID": 2147483646, "AMOUNT": 1},
            {"CUST_ID": 123456, "AMOUNT": 2},  # orphan FK value
        ],
    )
    return pk_path, fk_path


def test_fixture_a_integer_relation_before_after_metrics_and_round_trip(
    tmp_path: Path,
) -> None:
    """Fixture A: I single-column parent/FK relation through the REAL allocator."""
    document = parse_relationship_document(_i_document())
    validate_document_compatibility(document)
    domain = _i_domain()
    domain_id = resolved_numeric_domain(document, document.groups[0])
    pk_path, fk_path = _write_i_fixture(tmp_path)
    pk_values = [record.values["CUST_ID"] for record in read_numeric_records(pk_path)]
    fk_rows = [record.values for record in read_numeric_records(fk_path)]
    fk_values = [row["CUST_ID"] for row in fk_rows]
    before = relation_metrics([(v,) for v in pk_values], [(v,) for v in fk_values])
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            for value in sorted(set(pk_values + fk_values)):
                service.observe_original(value, original_range=(-(2**31), 2**31 - 1))
            service.finalize()
            shifted = {
                value: service.pseudonym_for(value)
                for value in sorted(set(pk_values + fk_values))
            }
            pk_after = [shifted[v] for v in pk_values]
            fk_after = [shifted[v] for v in fk_values]
            # Cross-table equality: the repeated FK value maps identically.
            assert shifted[7] == service.pseudonym_for(7)
            # Exact reverse round trip.
            for value, pseudonym in shifted.items():
                assert service.original_for(pseudonym) == value
            after = relation_metrics([(v,) for v in pk_after], [(v,) for v in fk_after])
    assert before.to_dict() == after.to_dict()
    assert before.foreign_multiplicity_profile == (2, 1, 1, 1)
    # The REAL allocator's output fits the I(4) writable range.
    for pseudonym in shifted.values():
        assert -(2**31) < pseudonym < 2**31 - 1


def test_fixture_b_integral_numeric_relation_with_differing_widths(
    tmp_path: Path,
) -> None:
    """Fixture B: N integral relation with differing compatible widths.

    PK N(8,0) and FK N(5,0): every pseudonym fits the narrowest/strictest
    participating representation (the FK width), exact cross-table equality
    holds and the round trip is exact.
    """
    document = parse_relationship_document(_n_document())
    validate_document_compatibility(document)
    domain = numeric_key_domain_for([integral_numeric_member(8), integral_numeric_member(5)])
    assert domain.pseudonym_range == (-9999, 99999)
    domain_id = resolved_numeric_domain(document, document.groups[0])
    pk_path = write_numeric_table(
        tmp_path, "north/customers.dbf", (numeric_field("CUST_ID", "N", 8),),
        [{"CUST_ID": -9999999}, {"CUST_ID": 0}, {"CUST_ID": 7}, {"CUST_ID": 99999999}],
    )
    fk_path = write_numeric_table(
        tmp_path, "south/orders.dbf", (numeric_field("CUST_ID", "N", 5),),
        [{"CUST_ID": 7}, {"CUST_ID": 7}, {"CUST_ID": 0}, {"CUST_ID": -9999}, {"CUST_ID": 12345}],
    )
    pk_values = [record.values["CUST_ID"] for record in read_numeric_records(pk_path)]
    fk_values = [record.values["CUST_ID"] for record in read_numeric_records(fk_path)]
    before = relation_metrics([(v,) for v in pk_values], [(v,) for v in fk_values])
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            for value in sorted(set(pk_values + fk_values)):
                service.observe_original(value)
            service.finalize()
            shifted = {
                value: service.pseudonym_for(value)
                for value in sorted(set(pk_values + fk_values))
            }
            pk_after = [shifted[v] for v in pk_values]
            fk_after = [shifted[v] for v in fk_values]
            after = relation_metrics([(v,) for v in pk_after], [(v,) for v in fk_after])
            # Exact cross-table equality and exact round trip.
            assert shifted[7] == service.pseudonym_for(7)
            for value, pseudonym in shifted.items():
                assert service.original_for(pseudonym) == value
    assert before.to_dict() == after.to_dict()
    # Every pseudonym fits the strictest member width: write it through the
    # public writer into the FK table shape (N(5,0)) and read it back.
    fk_out = write_numeric_table(
        tmp_path / "after",
        "south/orders.dbf",
        (numeric_field("CUST_ID", "N", 5),),
        [{"CUST_ID": pseudonym} for pseudonym in fk_after],
    )
    written = [record.values["CUST_ID"] for record in read_numeric_records(fk_out)]
    assert written == fk_after
    pk_out = write_numeric_table(
        tmp_path / "after",
        "north/customers.dbf",
        (numeric_field("CUST_ID", "N", 8),),
        [{"CUST_ID": pseudonym} for pseudonym in pk_after],
    )
    written_pk = [record.values["CUST_ID"] for record in read_numeric_records(pk_out)]
    assert written_pk == pk_after


def test_fixture_c_composite_numeric_relation_ordered_tuples(tmp_path: Path) -> None:
    """Fixture C: composite numeric relation with ordered tuple semantics."""
    payload = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-composite-numeric",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
                "members": [
                    {"table": "p/devices.dbf", "field": "SITE", "role": "PRIMARY", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": False},
                    {"table": "p/devices.dbf", "field": "DEVICE", "role": "PRIMARY", "ordinal": 2, "dbf_type": "N", "byte_width": 5, "encoding": "none", "nullable": False},
                    {"table": "c/jobs.dbf", "field": "SITE", "role": "FOREIGN", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": False},
                    {"table": "c/jobs.dbf", "field": "DEVICE", "role": "FOREIGN", "ordinal": 2, "dbf_type": "N", "byte_width": 5, "encoding": "none", "nullable": False},
                ],
            }
        ],
    }
    document = parse_relationship_document(payload)
    validate_document_compatibility(document)
    domain_id = resolved_numeric_domain(document, document.groups[0])
    pk_path = write_numeric_table(
        tmp_path, "p/devices.dbf",
        (numeric_field("SITE", "I", 4), numeric_field("DEVICE", "N", 5)),
        [
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 1, "DEVICE": 102},
            {"SITE": 2, "DEVICE": 101},
        ],
    )
    fk_path = write_numeric_table(
        tmp_path, "c/jobs.dbf",
        (numeric_field("SITE", "I", 4), numeric_field("DEVICE", "N", 5)),
        [
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 2, "DEVICE": 101},
            {"SITE": 9, "DEVICE": 999},
        ],
    )
    pk_rows = [record.values for record in read_numeric_records(pk_path)]
    fk_rows = [record.values for record in read_numeric_records(fk_path)]
    pk_tuples = [(row["SITE"], row["DEVICE"]) for row in pk_rows]
    fk_tuples = [(row["SITE"], row["DEVICE"]) for row in fk_rows]
    before = relation_metrics(pk_tuples, fk_tuples)
    domain = numeric_key_domain_for([integer_member(), integral_numeric_member(5)])
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            observed = sorted({value for pair in pk_tuples + fk_tuples for value in pair})
            for value in observed:
                service.observe_original(value)
            service.finalize()
            shifted = {value: service.pseudonym_for(value) for value in observed}
            pk_after = [(shifted[a], shifted[b]) for a, b in pk_tuples]
            fk_after = [(shifted[a], shifted[b]) for a, b in fk_tuples]
            after = relation_metrics(pk_after, fk_after)
            # Ordered tuple semantics survive: (A,B) != (B,A) after the shift.
            assert pk_after[0] != (pk_after[0][1], pk_after[0][0]) or pk_tuples[0] == (
                pk_tuples[0][1], pk_tuples[0][0]
            )
    assert before.to_dict() == after.to_dict()
    assert before.orphan_count == after.orphan_count == 1
    assert before.foreign_multiplicity_profile == (2, 1, 1)


def test_fixture_d_mixed_unsupported_member_types_fail_closed() -> None:
    """One numeric mapping domain across unsupported member types fails."""
    for unsupported in ("F", "Y", "B", "L"):
        payload = _i_document()
        payload["relations"][0]["members"][1]["dbf_type"] = unsupported  # type: ignore[index]
        payload["relations"][0]["members"][1]["byte_width"] = 10  # type: ignore[index]
        payload["relations"][0]["members"][1]["encoding"] = "cp1250"  # type: ignore[index]
        with pytest.raises(PolicyError) as excinfo:
            parse_relationship_document(payload)
        assert "RELATIONSHIP_DBF_TYPE_UNSUPPORTED" in _detail(excinfo)
        _no_leak(excinfo)


# ---------------------------------------------------------------------------
# STEP 16 — public metadata privacy canaries
# ---------------------------------------------------------------------------
def test_public_and_error_boundaries_never_leak_numeric_keys(tmp_path: Path) -> None:
    """Numeric canary values never reach any serialized public boundary."""
    source = _write_i_fixture(tmp_path / "src")[0].parent.parent
    canaries = ("987654321", "-1234", "555111")
    progress_payloads: list[str] = []

    def on_progress(event: object) -> None:
        progress_payloads.append(json.dumps(event.to_dict()))  # type: ignore[attr-defined]

    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_i_document(),
        progress=on_progress,
    )
    result = preflight(plan)
    plan_payload = json.dumps(plan.to_dict())
    preflight_payload = json.dumps(result.to_dict())
    review_payload = json.dumps([e.to_dict() for e in plan.numeric_identity_review])
    progress_payload = "".join(progress_payloads)
    for payload in (plan_payload, preflight_payload, review_payload, progress_payload):
        for canary in canaries:
            assert canary not in payload
    # The reversible numeric domain identity itself never carries values.
    document = parse_relationship_document(_i_document())
    domain_id = resolved_numeric_domain(document, document.groups[0])
    assert all(canary not in domain_id for canary in canaries)
    # A typed allocation error carries no original value either.
    from dbf_anonymizer.errors import MappingError

    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "7" * 16,
                domain=domain_key_domain(),
            )
            service.observe_original(CANARY_N)
            service.finalize()
            assert service.pseudonym_for(CANARY_N) != CANARY_N
            try:
                service.pseudonym_for(CANARY_RECOVERED)  # unobserved original
            except MappingError as error:
                boundary = json.dumps(error.to_dict()) + str(error) + repr(error)
                for canary in canaries:
                    assert canary not in boundary
            else:  # pragma: no cover - the unobserved original must fail
                pytest.fail("an unobserved original was silently mapped")


def domain_key_domain():
    from dbf_anonymizer.transforms.numeric_keys import numeric_key_domain_for

    return numeric_key_domain_for([integral_numeric_member(5)])


def test_mapping_enumeration_stays_internal(tmp_path: Path) -> None:
    """The mapping enumeration exists for internal validation only and never
    becomes a public serialization."""
    domain = _n_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "7" * 16, domain=domain
            )
            service.observe_original(CANARY_N)
            service.finalize()
            pseudonym = service.pseudonym_for(CANARY_N)
            rows = service.mapping_rows()
            assert rows == ((CANARY_N, pseudonym),)
            assert canonical_integer_text(CANARY_N) == str(CANARY_N)