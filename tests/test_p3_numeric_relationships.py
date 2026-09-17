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
    INTEGER_KEY_WRITABLE_HIGH,
    INTEGER_KEY_WRITABLE_LOW,
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
    originals = [-2147483647, -5, 0, 7, 2147483646, -2147483646]
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(vault, domain_id=domain_id, domain=domain)
            for value in originals:
                service.observe_original(value, member=integer_member())
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


def test_integer_extreme_original_fails_closed_before_publication(tmp_path: Path) -> None:
    """The readable int32 extremes are NOT reconstructable through the pinned
    public Direct Write boundary (verified independently with public
    ``write_table``): a reversible I original at an extreme fails closed with
    the stable ``NUMERIC_KEY_RECOVERY_UNWRITABLE`` detail BEFORE any
    allocation or publication — never silently truncated or unmapped."""
    domain = _i_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "9" * 16, domain=domain
            )
            with pytest.raises(MappingError) as low:
                service.observe_original(-(2**31), member=integer_member())
            assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in str(low.value.to_dict())
            _no_leak(low)
            with pytest.raises(MappingError) as high:
                service.observe_original(2**31 - 1, member=integer_member())
            assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in str(high.value.to_dict())
            _no_leak(high)
            # The refusal is stable and pre-publication: no mapping row exists.
            assert service.mapping_rows() == ()


def test_integral_numeric_domain_round_trip_with_widths(tmp_path: Path) -> None:
    """N round-trip: integral values, width/sign boundaries, recovery."""
    domain = numeric_key_domain_for([integral_numeric_member(5)])
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "c" * 16, domain=domain
            )
            for value in (-9999, -1, 0, 7, 99999):
                service.observe_original(value, member=integral_numeric_member(5))
            service.finalize()
            mapping = {value: service.pseudonym_for(value) for value in (-9999, -1, 0, 7, 99999)}
            assert len(set(mapping.values())) == len(mapping)
            for value, pseudonym in mapping.items():
                assert pseudonym != value
                assert domain.contains_pseudonym(pseudonym)
                assert service.original_for(pseudonym) == value
            # Non-integral / out-of-domain originals are refused (never rounded).
            with pytest.raises(ValueError):
                service.observe_original(-10000, member=integral_numeric_member(5))


def test_mixed_i_n_composite_members_share_one_domain(tmp_path: Path) -> None:
    """A composite (I, N) relation shares ONE numeric domain."""
    domain = numeric_key_domain_for([integer_member(), integral_numeric_member(5)])
    assert domain.pseudonym_range == (-9999, 99999)
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "d" * 16, domain=domain
            )
            service.observe_original(2147483646, member=integer_member())
            service.observe_original(-9999, member=integral_numeric_member(5))
            service.finalize()
            big = service.pseudonym_for(2147483646)
            small = service.pseudonym_for(-9999)
            assert big != small
            for pseudonym in (big, small):
                assert domain.contains_pseudonym(pseudonym)
            assert service.original_for(big) == 2147483646


def test_same_vault_reuse_consumes_no_rng(tmp_path: Path) -> None:
    """Same compatible vault: exact same mappings, zero RNG consumption on
    reuse (fresh allocation may legitimately consume the generator more than
    once per mapping — the corrected allocator verifies residual feasibility
    per candidate — but reuse never invokes it)."""
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
                service.observe_original(value, member=integral_numeric_member(5))
            service.finalize()
            first = {value: service.pseudonym_for(value) for value in originals}
            assert len(calls) >= 1  # fresh allocation consumed the generator
            # Reopening the SAME vault resolves the same mappings with NO RNG.
            reopened = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "e" * 16,
                domain=domain,
                _random_below=counting_rng,
            )
            for value in originals:
                reopened.observe_original(value, member=integral_numeric_member(5))
            reopened.finalize()
            before = len(calls)
            second = {value: reopened.pseudonym_for(value) for value in originals}
            assert second == first
            assert len(calls) == before  # reuse consumed no randomness


def test_fresh_vault_mappings_are_independent(tmp_path: Path) -> None:
    """Fresh-vault mapping VALIDITY (deterministic): each fresh vault's
    mappings are a valid in-domain bijection with self-exclusion.

    Range/validity evidence inspects ``mapping.values()`` (the PSEUDONYMS) —
    never the dictionary keys (the originals).  Fresh-vault INDEPENDENCE is
    proven deterministically by the controlled-RNG-sequence evidence in
    :func:`test_fresh_vault_independence_is_deterministic`; production
    CSPRNG binding is proven by the static architecture guard.  No
    probabilistic non-equality of uncontrolled CSPRNG runs is used as
    acceptance evidence.
    """
    domain = _n_domain()
    originals = [-9, 0, 42, 7]
    for index in range(2):
        vault_dir = tmp_path / f"vault{index}"
        with _open_vault(vault_dir) as vault:
            with writer_session(vault):
                service = NumericKeyDomainMapping(
                    vault, domain_id="dom-" + "f" * 16, domain=domain
                )
                for value in originals:
                    service.observe_original(value, member=integral_numeric_member(5))
                service.finalize()
                mapping = {value: service.pseudonym_for(value) for value in originals}
                pseudonyms = list(mapping.values())
                # Bijection, self-exclusion and shared-domain containment.
                assert len(set(pseudonyms)) == len(pseudonyms)
                for value, pseudonym in mapping.items():
                    assert pseudonym != value
                    assert domain.contains_pseudonym(pseudonym)
                    assert service.original_for(pseudonym) == value


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
                service.observe_original(value, member=integer_member())
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
            # Each occurrence is observed under ITS OWN originating member
            # (the PK column is N(8), the FK column is N(5)) — never inferred
            # from the numeric value itself.
            for value in sorted(set(pk_values)):
                service.observe_original(value, member=integral_numeric_member(8))
            for value in sorted(set(fk_values)):
                service.observe_original(value, member=integral_numeric_member(5))
            service.finalize()
            shifted = {
                value: service.pseudonym_for(value)
                for value in sorted(set(pk_values + fk_values))
            }
            pk_after = [shifted[v] for v in pk_values]
            fk_after = [shifted[v] for v in fk_values]
            after = relation_metrics([(v,) for v in pk_after], [(v,) for v in fk_after])
            # Exact cross-table equality and exact round trip
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
                service.observe_original(value, member=integral_numeric_member(5))
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
    # The allocated PSEUDONYMS, the residual candidate tokens and the numeric
    # domain bounds never enter any public payload either.
    plan_payload = plan_payload + json.dumps([e.to_dict() for e in plan.numeric_identity_review])
    assert str(INTEGER_KEY_WRITABLE_LOW) not in preflight_payload
    assert str(INTEGER_KEY_WRITABLE_HIGH) not in preflight_payload
    assert "dom-" not in review_payload  # domain identities are not review data
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id=domain_id,
                domain=numeric_key_domain_for([integer_member()]),
            )
            for value in (-5, 0, 7, 2147483646):
                service.observe_original(value, member=integer_member())
            service.finalize()
            allocated = [service.pseudonym_for(value) for value in (-5, 0, 7, 2147483646)]
            for pseudonym in allocated:
                assert str(pseudonym) not in plan_payload
                assert str(pseudonym) not in preflight_payload
                assert str(pseudonym) not in review_payload
                assert str(pseudonym) not in progress_payload
            # A typed allocation error carries no original value either.
            from dbf_anonymizer.errors import MappingError

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
            service.observe_original(CANARY_N, member=integral_numeric_member(5))
            service.finalize()
            pseudonym = service.pseudonym_for(CANARY_N)
            rows = service.mapping_rows()
            assert rows == ((CANARY_N, pseudonym),)
            assert canonical_integer_text(CANARY_N) == str(CANARY_N)

# ---------------------------------------------------------------------------
# BLOCKER 1 — self-exclusion on EVERY allocation path (probe and exact
# completion alike); these regressions FAIL on the rejected HEAD d17427d.
# ---------------------------------------------------------------------------
def test_adversarial_rng_self_collision_never_self_maps(tmp_path: Path) -> None:
    """Adversarial RNG: every probe attempt draws the index that the old
    buggy allocator resolved to the ORIGINAL itself.

    Domain {5, 6} with originals {5, 6}: the old exact completion removed the
    original from the blocked set and could therefore self-map (5 -> 5). The
    repaired allocator keeps the original blocked on every path and completes
    the two-token swap instead.
    """
    domain = numeric_key_domain_for(
        [integral_numeric_member(1)]  # 0..9 tokens; use an exact sub-range
    )
    del domain
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyMemberRange, NumericKeyDomain

    exact_domain = NumericKeyDomain(pseudonym_low=5, pseudonym_high=6, members=(
        NumericKeyMemberRange(5, 6, 5, 6),
    ))
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "a" * 16,
                domain=exact_domain,
                _random_below=lambda _bound: 0,
            )
            service.observe_original(5, member=exact_domain.members[0])
            service.observe_original(6, member=exact_domain.members[0])
            service.finalize()
            first = service.pseudonym_for(5)
            assert first != 5
            second = service.pseudonym_for(6)
            assert second != 6
            assert first != second
            assert service.original_for(first) == 5
            assert service.original_for(second) == 6
            rows = service.mapping_rows()
            for original, pseudonym in rows:
                assert original != pseudonym


def test_forced_exact_completion_never_self_maps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forcing the probe budget to zero drives every allocation through the
    exact deterministic completion path — which must still guarantee
    ``pseudonym != original`` and residual feasibility."""
    from dbf_anonymizer.vault import numeric_allocation

    monkeypatch.setattr(numeric_allocation, "NUMERIC_KEY_PROBE_BUDGET", 0)
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyDomain, NumericKeyMemberRange

    exact_domain = NumericKeyDomain(pseudonym_low=5, pseudonym_high=6, members=(
        NumericKeyMemberRange(5, 6, 5, 6),
    ))
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "a" * 16,
                domain=exact_domain,
                _random_below=lambda _bound: 0,
            )
            service.observe_original(5, member=exact_domain.members[0])
            service.observe_original(6, member=exact_domain.members[0])
            service.finalize()
            # The exact completion walks the ascending free tokens with the
            # original BLOCKED: 5 -> 6 and 6 -> 5 (never 5 -> 5).
            assert service.pseudonym_for(5) == 6
            assert service.pseudonym_for(6) == 5


def test_original_already_occupied_is_never_unblocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the original's value is already a persisted pseudonym of ANOTHER
    original, the allocator must never treat it as selectable."""
    from dbf_anonymizer.vault import numeric_allocation

    monkeypatch.setattr(numeric_allocation, "NUMERIC_KEY_PROBE_BUDGET", 0)
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyDomain, NumericKeyMemberRange

    exact_domain = NumericKeyDomain(pseudonym_low=5, pseudonym_high=7, members=(
        NumericKeyMemberRange(5, 7, 5, 7),
    ))
    domain_id = "dom-" + "b" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                # Persisted fixed assignment: original 7 -> pseudonym 5.
                add_numeric_key_mapping(vault, domain_id, "7", "5")
            service = NumericKeyDomainMapping(
                vault,
                domain_id=domain_id,
                domain=exact_domain,
                _random_below=lambda _bound: 0,
            )
            service.observe_original(5, member=exact_domain.members[0])
            service.observe_original(6, member=exact_domain.members[0])
            service.finalize()
            # Original 5 is itself occupied (it is 7's pseudonym): the exact
            # completion must still never return 5 for the original 5, and
            # the occupied 5 stays blocked for everyone.
            first = service.pseudonym_for(5)
            assert first != 5
            second = service.pseudonym_for(6)
            assert second not in {5, first}
            rows = service.mapping_rows()
            assert len(rows) == 3
            assert len({pseudonym for _o, pseudonym in rows}) == 3
            for original, pseudonym in rows:
                assert original != pseudonym


# ---------------------------------------------------------------------------
# BLOCKER 2 — residual feasibility is preserved on every commitment
# ---------------------------------------------------------------------------
def test_three_token_greedy_trap_completes_as_derangement(tmp_path: Path) -> None:
    """Domain {1,2,3} with originals {1,2,3}: the adversarial RNG would make
    the old greedy allocator choose 1->2 then 2->1 and strand 3->3 (forbidden).

    The repaired allocator verifies residual feasibility BEFORE committing:
    the 2->1 candidate is rejected and the complete derangement is produced.
    """
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyDomain, NumericKeyMemberRange

    exact_domain = NumericKeyDomain(pseudonym_low=1, pseudonym_high=3, members=(
        NumericKeyMemberRange(1, 3, 1, 3),
    ))
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "c" * 16,
                domain=exact_domain,
                _random_below=lambda _bound: 0,
            )
            for value in (1, 2, 3):
                service.observe_original(value, member=integral_numeric_member(5))
            service.finalize()
            # Greedy trap sequence: the first probe for 1 selects 2 (feasible,
            # committed), and every later probe for 2 keeps selecting the
            # infeasible 1; the exact completion must finish the derangement.
            assert service.pseudonym_for(1) == 2
            assert service.pseudonym_for(2) == 3
            assert service.pseudonym_for(3) == 1
            rows = dict(service.mapping_rows())
            assert rows == {1: 2, 2: 3, 3: 1}


def test_two_token_swap_always_completes(tmp_path: Path) -> None:
    """Domain {1,2} with originals {1,2} always completes as 1->2, 2->1."""
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyDomain, NumericKeyMemberRange

    exact_domain = NumericKeyDomain(pseudonym_low=1, pseudonym_high=2, members=(
        NumericKeyMemberRange(1, 2, 1, 2),
    ))
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "c" * 16,
                domain=exact_domain,
                _random_below=lambda _bound: 0,
            )
            service.observe_original(1, member=exact_domain.members[0])
            service.observe_original(2, member=exact_domain.members[0])
            service.finalize()
            assert service.pseudonym_for(1) == 2
            assert service.pseudonym_for(2) == 1


def test_persisted_fixed_assignment_preserves_residual_feasibility(
    tmp_path: Path,
) -> None:
    """C. Persisted fixed assignments are part of the residual problem."""
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyDomain, NumericKeyMemberRange

    exact_domain = NumericKeyDomain(pseudonym_low=1, pseudonym_high=3, members=(
        NumericKeyMemberRange(1, 3, 1, 3),
    ))
    domain_id = "dom-" + "d" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                add_numeric_key_mapping(vault, domain_id, "1", "2")
            service = NumericKeyDomainMapping(
                vault,
                domain_id=domain_id,
                domain=exact_domain,
                _random_below=lambda _bound: 0,
            )
            service.observe_original(1, member=exact_domain.members[0])
            service.observe_original(2, member=exact_domain.members[0])
            service.observe_original(3, member=exact_domain.members[0])
            service.finalize()
            # Persisted 1->2 is fixed; the residual completes as 2->3, 3->1.
            assert service.pseudonym_for(2) == 3
            assert service.pseudonym_for(3) == 1
            assert dict(service.mapping_rows()) == {1: 2, 2: 3, 3: 1}


def test_infeasible_persisted_residual_fails_closed_at_finalize(
    tmp_path: Path,
) -> None:
    """D. Persisted fixed assignments that destroy the residual feasibility
    fail closed at finalize (before ANY commitment)."""
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyDomain, NumericKeyMemberRange

    exact_domain = NumericKeyDomain(pseudonym_low=1, pseudonym_high=3, members=(
        NumericKeyMemberRange(1, 3, 1, 3),
    ))
    domain_id = "dom-" + "e" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            with vault.transaction():
                create_domain(
                    vault, domain_kind=VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY, domain_id=domain_id
                )
                add_numeric_key_mapping(vault, domain_id, "1", "2")
                add_numeric_key_mapping(vault, domain_id, "2", "1")
            service = NumericKeyDomainMapping(
                vault, domain_id=domain_id, domain=exact_domain
            )
            service.observe_original(1, member=exact_domain.members[0])
            service.observe_original(2, member=exact_domain.members[0])
            service.observe_original(3, member=exact_domain.members[0])
            # The persisted swap leaves original 3 with only its own forbidden
            # token: finalize refuses (no mapping is committed).
            with pytest.raises(MappingError) as excinfo:
                service.finalize()
            assert "NUMERIC_KEY_NO_COMPLETION" in str(excinfo.value.to_dict())
            _no_leak(excinfo)


def test_genuinely_infeasible_candidate_is_never_committed(tmp_path: Path) -> None:
    """The allocator skips candidates whose commitment would strand the
    residual problem (the old greedy trap), then completes feasibly."""
    from dbf_anonymizer.transforms.numeric_keys import NumericKeyDomain, NumericKeyMemberRange

    exact_domain = NumericKeyDomain(pseudonym_low=1, pseudonym_high=3, members=(
        NumericKeyMemberRange(1, 3, 1, 3),
    ))
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            queue = [0, 0, 0, 1, 0, 0]

            def scripted(_bound: int) -> int:
                return queue.pop(0) if queue else 0

            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "f" * 16,
                domain=exact_domain,
                _random_below=scripted,
            )
            for value in (1, 2, 3):
                service.observe_original(value, member=integral_numeric_member(5))
            service.finalize()
            # 1 -> 2 (first probe); for 2 the probes first draw the
            # infeasible candidate 1 (twice) and then the feasible 3; the
            # infeasible candidate is never persisted.
            assert service.pseudonym_for(1) == 2
            assert service.pseudonym_for(2) == 3
            assert service.pseudonym_for(3) == 1
            mapping = {1: 2, 2: 3, 3: 1}
            assert dict(service.mapping_rows()) == mapping
            for original, pseudonym in mapping.items():
                assert original != pseudonym


# ---------------------------------------------------------------------------
# BLOCKER 4 — planning truthfulness: reversible numeric transforms require
# the recovery vault; IDENTITY numerics never do.
# ---------------------------------------------------------------------------
def _reversible_n_fixture_document() -> dict[str, object]:
    document = _n_document()
    return document


def test_reversible_i_only_plan_requires_recovery_and_vault(tmp_path: Path) -> None:
    """A dataset containing ONLY a reversible I relation requires recovery."""
    source = _write_i_relation_fixture(tmp_path / "src")
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_i_document(),
    )
    assert plan.policy.recovery_enabled is True
    assert plan.policy.vault_strategy.value == "SINGLE_DATASET_SQLITE"
    # The declared reversible numeric members are truthfully transformed.
    assert plan.policy.transformation_classes == ("PSEUDONYMIZE_REVERSIBLE",)
    transformed = {
        table.table_path: table.transform_field_count for table in plan.tables
    }
    assert transformed == {"north/customers.dbf": 1, "south/orders.dbf": 1}
    assert plan.policy.transformed_field_count == 2


def test_reversible_n_only_plan_requires_recovery_and_vault(tmp_path: Path) -> None:
    """A dataset containing ONLY an integral N reversible relation requires
    recovery too."""
    source = tmp_path / "src"
    write_numeric_table(
        source, "north/customers.dbf", (numeric_field("CUST_ID", "N", 8),),
        [{"CUST_ID": 1}],
    )
    write_numeric_table(
        source, "south/orders.dbf", (numeric_field("CUST_ID", "N", 5),),
        [{"CUST_ID": 1}],
    )
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_n_document(),
    )
    assert plan.policy.recovery_enabled is True
    assert plan.policy.vault_strategy.value == "SINGLE_DATASET_SQLITE"
    assert "PSEUDONYMIZE_REVERSIBLE" in plan.policy.transformation_classes


def test_identity_numeric_plan_does_not_spuriously_require_recovery(
    tmp_path: Path,
) -> None:
    """IDENTITY numeric relationships stay identity and privacy-review-only."""
    source = _write_i_relation_fixture(tmp_path / "src")
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_i_document(strategy=NUMERIC_STRATEGY_IDENTITY),
    )
    assert plan.policy.recovery_enabled is False
    assert plan.policy.vault_strategy.value == "NONE"
    assert plan.policy.transformation_classes == ()
    # The identity members remain privacy-review-only.
    assert len(plan.numeric_identity_review) == 2


def test_reversible_numeric_plus_text_uses_one_vault(tmp_path: Path) -> None:
    """Reversible numeric + reversible text/memo/date: ONE vault strategy."""
    source = tmp_path / "src"
    write_numeric_table(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "I", 4), numeric_field("NAME", "C", 8)),
        [{"CUST_ID": 1, "NAME": "ALPHA"}],
    )
    write_numeric_table(
        source,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": 1}],
    )
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_i_document(),
    )
    assert plan.policy.recovery_enabled is True
    assert plan.policy.vault_strategy.value == "SINGLE_DATASET_SQLITE"
    # ONE transformation class represents both reversible paths.
    assert plan.policy.transformation_classes == ("PSEUDONYMIZE_REVERSIBLE",)
    transformed = {t.table_path: t.transform_field_count for t in plan.tables}
    assert transformed == {"north/customers.dbf": 2, "south/orders.dbf": 1}


# ---------------------------------------------------------------------------
# BLOCKER 6 — verified public Direct Write Integer boundary evidence
# ---------------------------------------------------------------------------
def test_integer_extreme_direct_write_public_boundary_probe(tmp_path: Path) -> None:
    """Independent re-proof against the pinned dbfbridge[write]==1.1.0.

    The public ``write_table`` boundary refuses BOTH int32 extremes (typed
    write failure) and accepts the interior boundaries exactly; the outcomes
    are classified by the PUBLIC typed error contract (class + stable error
    code), never by parsing human messages and never by treating an
    arbitrary unrelated exception as sufficient proof.
    """
    import dbfbridge

    assert dbfbridge.__version__ == "1.1.0"
    from dbfbridge import ErrorCode, WritePublicationFailedError

    from tests.support.numeric_tables import schema as numeric_schema

    outcomes: dict[int, str] = {}
    for value in (-(2**31), -(2**31) + 1, 2**31 - 2, 2**31 - 1):
        target = tmp_path / f"probe_{value}.dbf"
        outcome: str
        try:
            from dbfbridge import write_table as public_write_table

            public_write_table(
                target,
                schema=numeric_schema((numeric_field("ID", "I", 4),)),
                records=[{"ID": value}],
            )
            outcome = "WRITABLE"
        except Exception as error:  # typed public boundary refusal
            assert isinstance(error, WritePublicationFailedError)
            assert error.code == ErrorCode.WRITE_PUBLICATION_FAILED  # type: ignore[attr-defined]
            outcome = f"REFUSED:{type(error).__name__}:{error.code.value}"  # type: ignore[attr-defined]
        outcomes[value] = outcome
    assert (
        outcomes[-(2**31)]
        == "REFUSED:WritePublicationFailedError:WRITE_PUBLICATION_FAILED"
    )
    assert outcomes[-(2**31) + 1] == "WRITABLE"
    assert outcomes[2**31 - 2] == "WRITABLE"
    assert (
        outcomes[2**31 - 1]
        == "REFUSED:WritePublicationFailedError:WRITE_PUBLICATION_FAILED"
    )
    # Every WRITABLE point round-trips exactly through the public boundary.
    for value in (-(2**31) + 1, 2**31 - 2):
        target = tmp_path / f"probe_{value}.dbf"
        from tests.support.numeric_tables import read_numeric_records

        assert next(iter(read_numeric_records(target))).values["ID"] == value


def test_every_accepted_reversible_i_original_is_recoverable(tmp_path: Path) -> None:
    """Every original accepted for reversible I mapping fits the verified
    WRITABLE range, so recovery can reconstruct it through the only
    architecture-permitted public writer."""
    from dbf_anonymizer.transforms.numeric_keys import (
        INTEGER_KEY_WRITABLE_HIGH,
        INTEGER_KEY_WRITABLE_LOW,
    )

    domain = _i_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "9" * 16,
                domain=domain,
            )
            for value in (INTEGER_KEY_WRITABLE_LOW, -1, 0, INTEGER_KEY_WRITABLE_HIGH):
                service.observe_original(value, member=integer_member())
            service.finalize()
            for value in (INTEGER_KEY_WRITABLE_LOW, -1, 0, INTEGER_KEY_WRITABLE_HIGH):
                pseudonym = service.pseudonym_for(value)
                assert domain.contains_pseudonym(pseudonym)
                recovered = service.original_for(pseudonym)
                assert recovered is not None and recovered == value
                assert INTEGER_KEY_WRITABLE_LOW <= recovered <= INTEGER_KEY_WRITABLE_HIGH


# ---------------------------------------------------------------------------
# TEST HARDENING — deterministic fresh-vault independence and RNG accounting
# ---------------------------------------------------------------------------
def test_fresh_vault_independence_is_deterministic(tmp_path: Path) -> None:
    """Two fresh vaults MAY produce independent mapping sets: the proof is
    deterministic through two controlled CSPRNG sequences injected via the
    private seam.  Production randomness itself is proven CSPRNG by the
    static allocation guard (the production default is secrets.randbelow)."""
    domain = _n_domain()
    mappings = []
    for index, seed in enumerate((0, 1)):
        with _open_vault(tmp_path / f"vault{index}") as vault:
            with writer_session(vault):
                service = NumericKeyDomainMapping(
                    vault,
                    domain_id="dom-" + "f" * 16,
                    domain=domain,
                    _random_below=lambda _bound, _seed=seed: _seed,
                )
                for value in (-9, 0, 42, 7):
                    service.observe_original(value, member=integral_numeric_member(5))
                service.finalize()
                mapping = {value: service.pseudonym_for(value) for value in (-9, 0, 42, 7)}
                # Validity: bijection, self-exclusion, in-domain.
                assert len(set(mapping.values())) == len(mapping)
                for value, pseudonym in mapping.items():
                    assert pseudonym != value
                    assert domain.contains_pseudonym(pseudonym)
                mappings.append(mapping)
    # The two controlled CSPRNG sequences produce INDEPENDENT mapping sets
    # (deterministic: seed 0 vs seed 1 select different free tokens).
    assert mappings[0] != mappings[1]


def test_reuse_consumes_zero_rng_and_fresh_allocation_consumes_csrng(
    tmp_path: Path,
) -> None:
    """Fresh allocation actually consumes CSPRNG; reuse consumes ZERO; a
    failed allocation persists no partial invalid state."""
    domain = _n_domain()
    originals = (-9, 0, 42)
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
                service.observe_original(value, member=integral_numeric_member(5))
            service.finalize()
            first = {value: service.pseudonym_for(value) for value in originals}
            # Fresh allocation actually consumed the (CSPRNG) generator.
            assert len(calls) >= 1
            fresh_calls = len(calls)
            # Reopening the SAME vault resolves the same mappings with NO RNG.
            reopened = NumericKeyDomainMapping(
                vault,
                domain_id="dom-" + "e" * 16,
                domain=domain,
                _random_below=counting_rng,
            )
            for value in originals:
                reopened.observe_original(value, member=integral_numeric_member(5))
            reopened.finalize()
            assert {value: reopened.pseudonym_for(value) for value in originals} == first
            assert len(calls) == fresh_calls


# ---------------------------------------------------------------------------
# TRANSACTION / FAILURE ATOMICITY
# ---------------------------------------------------------------------------
def test_failure_after_candidate_selection_rolls_back_completely(
    tmp_path: Path,
) -> None:
    """Injecting a storage failure AFTER candidate selection but BEFORE the
    commit leaves NO numeric mapping row; the allocator can retry safely; no
    bookkeeping claims a rolled-back token; previously committed mappings
    are never invalidated."""
    import sqlite3 as sqlite3_module

    from tests.support.vault_sessions import install_failing_execute

    domain = _n_domain()
    domain_id = "dom-" + "8" * 16
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault,
                domain_id=domain_id,
                domain=domain,
                _random_below=lambda _bound: 0,
            )
            for value in (-9, 0, 42):
                service.observe_original(value, member=integral_numeric_member(5))
            service.finalize()
            committed_first = service.pseudonym_for(-9)
            assert service.mapping_rows() == ((-9, committed_first),)
            # Inject the storage failure on the numeric mapping INSERT only
            # (the candidate is already selected when the INSERT fails).
            original_connection = vault._connection
            proxy = install_failing_execute(
                vault,
                fail_when=lambda sql: "INSERT INTO numeric_key_mappings" in sql,
            )
            vault._connection = proxy
            try:
                with pytest.raises(sqlite3_module.OperationalError):
                    service.pseudonym_for(0)
            finally:
                vault._connection = original_connection
            # No rolled-back row survived and the bookkeeping claims only the
            # previously COMMITTED token.
            rows = service.mapping_rows()
            assert rows == ((-9, committed_first),)
            # Retry after the failure is safe and completes the mapping.
            retried = service.pseudonym_for(0)
            assert retried != 0
            mapping = dict(service.mapping_rows())
            assert mapping == {-9: committed_first, 0: retried}
            assert committed_first in mapping.values()


# ---------------------------------------------------------------------------
# BLOCKER 5 — REAL side-effect-free numeric key-domain capacity preflight
# ---------------------------------------------------------------------------
def _side_effect_snapshot(root: Path) -> list[str]:
    """The recursive inventory of a preflight tree (side-effect proof)."""
    inventory: list[str] = []
    for path in sorted(root.rglob("*")):
        inventory.append(path.relative_to(root).as_posix())
    return inventory


def test_numeric_capacity_insufficient_detected_before_any_creation(
    tmp_path: Path,
) -> None:
    """Impossible numeric domain: the parent I side carries MORE distinct
    valid originals than the deliberately narrow shared integral-N pseudonym
    domain can represent (FK N(1,0): tokens 0..9).  Preflight detects the
    impossible domain BEFORE creating a vault — zero created output/vault
    state."""
    payload = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-impossible-numeric",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
                "members": [
                    {"table": "north/customers.dbf", "field": "CUST_ID", "role": "PRIMARY", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": False},
                    {"table": "south/orders.dbf", "field": "CUST_ID", "role": "FOREIGN", "ordinal": 1, "dbf_type": "N", "byte_width": 1, "encoding": "none", "nullable": False},
                ],
            }
        ],
    }
    source = tmp_path / "src"
    write_numeric_table(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "I", 4),),
        [{"CUST_ID": value} for value in range(11)],
    )
    write_numeric_table(
        source,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "N", 1),),
        [{"CUST_ID": value} for value in range(10)],
    )
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=payload,
    )
    result = preflight(plan)
    assert not result.ready
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" in result.error_codes
    # Zero filesystem side effects: no vault, no output, no staging tree.
    inventory = _side_effect_snapshot(tmp_path)
    assert not any("dictionary.sqlite3" in name for name in inventory)
    assert not any(name.endswith(("-wal", "-shm", ".journal")) for name in inventory)
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "vault").exists()


def test_numeric_capacity_scan_includes_deleted_records(tmp_path: Path) -> None:
    """Deleted records are transformed later, so their key values consume
    capacity too: the 11th distinct original exists ONLY in a deleted record
    and still triggers the insufficient classification."""
    payload = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-impossible-numeric",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
                "members": [
                    {"table": "north/customers.dbf", "field": "CUST_ID", "role": "PRIMARY", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": False},
                    {"table": "south/orders.dbf", "field": "CUST_ID", "role": "FOREIGN", "ordinal": 1, "dbf_type": "N", "byte_width": 1, "encoding": "none", "nullable": False},
                ],
            }
        ],
    }
    source = tmp_path / "src"
    from tests.support.numeric_tables import write_numeric_table_with_deleted

    write_numeric_table_with_deleted(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "I", 4),),
        [({"CUST_ID": value}, False) for value in range(10)]
        + [({"CUST_ID": 10}, True)],  # the 11th distinct original: deleted only
    )
    write_numeric_table(
        source,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "N", 1),),
        [{"CUST_ID": value} for value in range(10)],
    )
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=payload,
    )
    result = preflight(plan)
    assert not result.ready
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" in result.error_codes
    inventory = _side_effect_snapshot(tmp_path)
    assert not any("dictionary.sqlite3" in name for name in inventory)
    assert not any(name.endswith(("-wal", "-shm", ".journal")) for name in inventory)
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "vault").exists()


def test_numeric_capacity_feasible_cases_remain_green(tmp_path: Path) -> None:
    """Feasible I, feasible N and mixed compatible I/N preflights stay ready
    (including a NULLable numeric member and deleted records)."""
    i_payload = _i_document()
    source = _write_i_relation_fixture(tmp_path / "src")
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=i_payload,
    )
    result = preflight(plan)
    assert result.ready, result.to_dict()
    assert "PSEUDONYM_CAPACITY_INSUFFICIENT" not in result.error_codes
    assert "PSEUDONYM_CAPACITY_UNPROVEN" not in result.error_codes

    n_source = tmp_path / "src_n"
    write_numeric_table(
        n_source, "north/customers.dbf", (numeric_field("CUST_ID", "N", 8),),
        [{"CUST_ID": -9999999}, {"CUST_ID": 0}, {"CUST_ID": 99999999}],
    )
    write_numeric_table(
        n_source, "south/orders.dbf", (numeric_field("CUST_ID", "N", 5),),
        [{"CUST_ID": 7}, {"CUST_ID": -9999}],
    )
    plan = build_plan(
        n_source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_n_document(),
    )
    assert preflight(plan).ready

    mixed_payload = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-mixed-numeric",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": NUMERIC_STRATEGY_REVERSIBLE_BIJECTIVE,
                "members": [
                    {"table": "p/devices.dbf", "field": "SITE", "role": "PRIMARY", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": True},
                    {"table": "p/devices.dbf", "field": "DEVICE", "role": "PRIMARY", "ordinal": 2, "dbf_type": "N", "byte_width": 5, "encoding": "none", "nullable": True},
                    {"table": "c/jobs.dbf", "field": "SITE", "role": "FOREIGN", "ordinal": 1, "dbf_type": "I", "byte_width": 4, "encoding": "none", "nullable": True},
                    {"table": "c/jobs.dbf", "field": "DEVICE", "role": "FOREIGN", "ordinal": 2, "dbf_type": "N", "byte_width": 5, "encoding": "none", "nullable": True},
                ],
            }
        ],
    }
    mixed_source = tmp_path / "src_mixed"
    from tests.support.numeric_tables import write_numeric_table_with_deleted

    write_numeric_table_with_deleted(
        mixed_source,
        "p/devices.dbf",
        (
            numeric_field("SITE", "I", 4, flags=NULLABLE_FLAG),
            numeric_field("DEVICE", "N", 5, flags=NULLABLE_FLAG),
        ),
        [
            ({"SITE": 1, "DEVICE": 101}, False),
            ({"SITE": 2, "DEVICE": 102}, False),
            ({"SITE": None, "DEVICE": 103}, False),
            ({"SITE": 3, "DEVICE": 104}, True),  # deleted record is scanned
        ],
    )
    write_numeric_table_with_deleted(
        mixed_source,
        "c/jobs.dbf",
        (
            numeric_field("SITE", "I", 4, flags=NULLABLE_FLAG),
            numeric_field("DEVICE", "N", 5, flags=NULLABLE_FLAG),
        ),
        [
            ({"SITE": 1, "DEVICE": 103}, False),
            ({"SITE": None, "DEVICE": 104}, False),
        ],
    )
    plan = build_plan(
        mixed_source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=mixed_payload,
    )
    assert preflight(plan).ready


def test_numeric_preflight_is_deterministic(tmp_path: Path) -> None:
    source = _write_i_relation_fixture(tmp_path / "src")
    document = _i_document()
    first = preflight(
        build_plan(
            source,
            tmp_path / "out",
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            relationship_document=document,
        )
    )
    second = preflight(
        build_plan(
            source,
            tmp_path / "out",
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            relationship_document=document,
        )
    )
    assert first.to_dict() == second.to_dict()
    assert first.ready


def test_numeric_capacity_progress_and_cancellation_remain_bounded(
    tmp_path: Path,
) -> None:
    """The numeric scan emits bounded structured progress, stays privacy-safe
    and honors cooperative cancellation deterministically."""
    from dbf_anonymizer import CancellationError

    source = _write_i_relation_fixture(tmp_path / "src")
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_i_document(),
    )
    payloads: list[str] = []

    def on_progress(event: object) -> None:
        payloads.append(json.dumps(event.to_dict()))  # type: ignore[attr-defined]

    result = preflight(plan, progress=on_progress)
    assert result.ready
    joined = "".join(payloads)
    assert "CAPACITY_SCAN" in joined
    for canary in ("-5", "123456"):
        assert canary not in joined
    # Cancellation before the scan starts produces the typed cancellation and
    # never a completed result (a returning truthy check — a raising callback
    # is contained as CANCEL_CALLBACK_FAILED by the P1-008 contract).
    budget = {"calls": 0}

    def cancel_after_two() -> bool:
        budget["calls"] += 1
        return budget["calls"] > 2

    with pytest.raises(CancellationError):
        preflight(plan, cancel_check=cancel_after_two)


def test_unwritable_integer_original_is_caught_in_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A REAL VFP table can contain the readable-but-unwritable Integer
    extremes (real VFP writes them; the pinned public Direct Write boundary
    refuses them).  The public READ boundary decodes such a table, so the
    side-effect-free preflight must detect the unrecoverable original BEFORE
    any publication.  The fixture's record stream is provided through the
    verified public read semantics for exactly those values the public
    writer cannot produce (the extremes); every other layer — document,
    bindings, plan, scan logic — is the REAL implementation.
    """
    import dbfbridge as public_bridge
    from dbfbridge import DirectRecord

    payload = _i_document()
    source = _write_i_relation_fixture(tmp_path / "src")
    # The public-writer fixture carries only writable values; the extreme
    # original is delivered through the verified public read behavior.
    real_iter_records = public_bridge.iter_records

    def extreme_iter_records(path: object, **kwargs: object) -> object:
        rel = Path(str(path)).as_posix().replace("\\", "/")
        if rel.endswith("north/customers.dbf"):
            def stream():
                yield DirectRecord(physical_index=0, deleted=False, values={"CUST_ID": 2**31 - 1})
            return stream()
        return real_iter_records(path, **kwargs)

    monkeypatch.setattr(public_bridge, "iter_records", extreme_iter_records)
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=payload,
    )
    result = preflight(plan)
    assert not result.ready
    assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in result.error_codes
    # Zero filesystem side effects.
    inventory = _side_effect_snapshot(tmp_path)
    assert not any("dictionary.sqlite3" in name for name in inventory)
    assert not any(name.endswith(("-wal", "-shm")) for name in inventory)


# ---------------------------------------------------------------------------
# FINAL DELTA — ORIGIN-MEMBER reversible-original invariant
#
# An observed occurrence is validated against ITS OWN originating member,
# never against the union (ANY) of the relation's member ranges.  A wider or
# different member can never authorize an unrecoverable occurrence, and no
# observation-order/deduplication path can bypass the stricter member.
# These regressions FAIL on the reviewed HEAD 76b94cb.
# ---------------------------------------------------------------------------
def _mixed_i_n_domain():
    return numeric_key_domain_for([integer_member(), integral_numeric_member(10)])


def test_i_high_extreme_refused_in_mixed_i_n_domain(tmp_path: Path) -> None:
    """A. I-origin 2147483647 in a mixed I + N(10) relation fails closed.

    N(10,0) could represent the value, but the ORIGIN is the Integer member
    and the pinned public writer cannot reconstruct it for that member."""
    domain = _mixed_i_n_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a1" * 8, domain=domain
            )
            with pytest.raises(MappingError) as excinfo:
                service.observe_original(2147483647, member=integer_member())
            assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in str(excinfo.value.to_dict())
            _no_leak(excinfo)
            # The unrecoverable occurrence was never recorded.
            assert service.observed_originals == ()


def test_i_low_extreme_refused_in_mixed_i_n_domain(tmp_path: Path) -> None:
    """B. I-origin -2147483648 in a mixed I + N(10) relation fails closed."""
    domain = _mixed_i_n_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a2" * 8, domain=domain
            )
            with pytest.raises(MappingError) as excinfo:
                service.observe_original(-(2**31), member=integer_member())
            assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in str(excinfo.value.to_dict())
            _no_leak(excinfo)
            assert service.observed_originals == ()


def test_n_origin_high_value_is_reversible_in_mixed_domain(tmp_path: Path) -> None:
    """C. The SAME value 2147483647 originating from N(10,0) IS reversible:
    the N member itself admits and reconstructs it; the pseudonym must fit
    the SHARED pseudonym domain and the reverse lookup is exact."""
    domain = _mixed_i_n_domain()
    # Shared pseudonym domain = intersection of member WRITABLE ranges:
    # I writable [-2147483647, 2147483646] ∩ N(10,0) [-999999999, 9999999999].
    assert domain.pseudonym_range == (-999999999, 2147483646)
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a3" * 8, domain=domain
            )
            service.observe_original(2147483647, member=integral_numeric_member(10))
            service.finalize()
            pseudonym = service.pseudonym_for(2147483647)
            assert pseudonym != 2147483647
            assert domain.contains_pseudonym(pseudonym)
            assert service.original_for(pseudonym) == 2147483647


def test_n_first_then_i_occurrence_still_fails(tmp_path: Path) -> None:
    """D. Observation order cannot bypass a stricter member: the N(10)
    occurrence of 2147483647 is observed first; the LATER I occurrence of the
    same value must STILL fail closed (deduplication never skips
    origin-member validation of a later occurrence)."""
    domain = _mixed_i_n_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a4" * 8, domain=domain
            )
            service.observe_original(2147483647, member=integral_numeric_member(10))
            with pytest.raises(MappingError) as excinfo:
                service.observe_original(2147483647, member=integer_member())
            assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in str(excinfo.value.to_dict())
            _no_leak(excinfo)


def test_i_first_then_n_cannot_retroactively_validate(tmp_path: Path) -> None:
    """E. The I occurrence fails IMMEDIATELY; no later N occurrence can
    retroactively make it valid."""
    domain = _mixed_i_n_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a5" * 8, domain=domain
            )
            with pytest.raises(MappingError) as excinfo:
                service.observe_original(2147483647, member=integer_member())
            assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in str(excinfo.value.to_dict())
            _no_leak(excinfo)
            # The later, wider N occurrence does not undo the refusal: the
            # service has no record of the refused I occurrence, and the
            # refusal code stays reproducible for a repeated I occurrence.
            service.observe_original(2147483647, member=integral_numeric_member(10))
            with pytest.raises(MappingError) as again:
                service.observe_original(2147483647, member=integer_member())
            assert "NUMERIC_KEY_RECOVERY_UNWRITABLE" in str(again.value.to_dict())


def test_ordinary_shared_value_maps_to_one_shared_pseudonym(
    tmp_path: Path,
) -> None:
    """F. The value 42 occurring through BOTH the I and the N member is
    accepted from both member contexts and maps to ONE shared pseudonym."""
    domain = numeric_key_domain_for([integer_member(), integral_numeric_member(5)])
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a6" * 8, domain=domain
            )
            service.observe_original(42, member=integer_member())
            service.observe_original(42, member=integral_numeric_member(5))
            service.finalize()
            pseudonym = service.pseudonym_for(42)
            assert pseudonym != 42
            assert domain.contains_pseudonym(pseudonym)
            # ONE shared pseudonym across both member contexts.
            assert service.pseudonym_for(42) == pseudonym
            assert len(service.mapping_rows()) == 1
            assert service.original_for(pseudonym) == 42


def test_narrow_n_width_is_not_rescued_by_a_wider_n_member(
    tmp_path: Path,
) -> None:
    """G. An occurrence must satisfy its ACTUAL originating N width: a wider
    N(10) member in the same relation can never make an out-of-range N(5)
    occurrence valid."""
    domain = numeric_key_domain_for(
        [integral_numeric_member(5), integral_numeric_member(10)]
    )
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a7" * 8, domain=domain
            )
            # 100000 does not fit N(5,0) (99999 is the boundary) even though
            # the relation also contains N(10,0).
            with pytest.raises(ValueError):
                service.observe_original(100000, member=integral_numeric_member(5))
            # The same value from its OWN (wider) member is fine.
            service.observe_original(100000, member=integral_numeric_member(10))
            assert service.observed_originals == (100000,)


def test_origin_refusal_carries_no_source_value(tmp_path: Path) -> None:
    """H. The typed origin-member refusal never contains the source value."""
    canary = "2147483647"
    domain = _mixed_i_n_domain()
    with _open_vault(tmp_path) as vault:
        with writer_session(vault):
            service = NumericKeyDomainMapping(
                vault, domain_id="dom-" + "a8" * 8, domain=domain
            )
            with pytest.raises(MappingError) as excinfo:
                service.observe_original(2147483647, member=integer_member())
            boundary = (
                str(excinfo.value)
                + "|"
                + repr(excinfo.value)
                + "|"
                + json.dumps(excinfo.value.to_dict(), sort_keys=True)
            )
            assert canary not in boundary
            assert "-2147483648" not in boundary
            assert "C:\\" not in boundary


def test_preflight_and_allocator_share_the_origin_member_rule(
    tmp_path: Path,
) -> None:
    """The pure classifier is the ONE origin-member rule: both the allocator
    and the read-only numeric capacity preflight reach the same verdicts."""
    from dbf_anonymizer.transforms.numeric_keys import (
        MEMBER_ORIGINAL_OUT_OF_MEMBER_RANGE,
        MEMBER_ORIGINAL_RECOVERY_UNWRITABLE,
        MEMBER_ORIGINAL_REVERSIBLE,
        classify_member_original,
    )

    i_member = integer_member()
    n10_member = integral_numeric_member(10)
    n5_member = integral_numeric_member(5)
    # I origin: extremes readable but unrecoverable — the classifier verdict
    # is member-specific, identical for the preflight scan and the allocator.
    assert classify_member_original(i_member, 2147483647) == MEMBER_ORIGINAL_RECOVERY_UNWRITABLE
    assert classify_member_original(i_member, -(2**31)) == MEMBER_ORIGINAL_RECOVERY_UNWRITABLE
    assert classify_member_original(n10_member, 2147483647) == MEMBER_ORIGINAL_REVERSIBLE
    assert classify_member_original(n5_member, 100000) == MEMBER_ORIGINAL_OUT_OF_MEMBER_RANGE
    assert classify_member_original(i_member, 42) == MEMBER_ORIGINAL_REVERSIBLE
    assert classify_member_original(n10_member, 42) == MEMBER_ORIGINAL_REVERSIBLE
    with pytest.raises(TypeError):
        classify_member_original(i_member, True)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        classify_member_original(i_member, 1.0)  # type: ignore[arg-type]
