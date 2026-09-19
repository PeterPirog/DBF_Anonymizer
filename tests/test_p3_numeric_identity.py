"""Numeric/logical identity-by-default and privacy-review metadata (REQ-P3-004).

Evidence that ``N``/``F``/``I``/``Y``/``B``/``L`` fields remain value-identical
by default (positive, negative, zero, boundary, NULL and representative
decimal/currency/double/logical values), that numeric PK/FK relations keep
their EXACT relational metrics without any numeric pseudonymizer, and that
unchanged numeric identifiers are truthfully marked for privacy review in the
public Plan metadata — never with any key value.
"""

from __future__ import annotations

import json
from pathlib import Path

from dbf_anonymizer import build_plan
from dbf_anonymizer.models import IDENTITY_PRIVACY_REVIEW_REQUIRED
from dbf_anonymizer.policy import classify_field_capability, resolve_policy
from dbf_anonymizer.relationships.evidence import relation_metrics
from dbf_anonymizer.vault import VAULT_DATABASE_FILENAME
from tests.support.numeric_tables import (
    AUTOINCREMENT_FLAG,
    read_numeric_records,
    numeric_field,
    write_numeric_table,
)

DEFAULT_POLICY, _DEFAULT_FP = resolve_policy(None)


# ---------------------------------------------------------------------------
# policy classification: numeric/logical fields are identity by default
# ---------------------------------------------------------------------------
def test_numeric_logical_types_classify_as_identity_by_default() -> None:
    for dbf_type in ("N", "I", "F", "Y", "B", "L"):
        action, unsafe, system = classify_field_capability(
            dbf_type, "KEY", True, False, False, False, DEFAULT_POLICY
        )
        assert action is None  # IDENTITY (KEEP)
        assert unsafe is False
        assert system is False


def test_numeric_identity_is_policy_driven_not_type_inferred() -> None:
    # The classification is policy-driven: with the documented default policy
    # the numeric/logical classes stay KEEP; no field type alone can select a
    # numeric pseudonymizer.
    merged, _ = resolve_policy({"numeric": {"default_action": "KEEP"}})
    for dbf_type in ("N", "I", "F", "Y", "B", "L"):
        action, _unsafe, _system = classify_field_capability(
            dbf_type, "K", True, False, False, False, merged
        )
        assert action is None


# ---------------------------------------------------------------------------
# real fixture identity evidence through the public read/write boundary
# ---------------------------------------------------------------------------
def _identity_fields():
    return (
        numeric_field("K", "N", 5),
        numeric_field("I", "I", 4),
        numeric_field("F", "F", 10, decimal_count=4),
        numeric_field("Y", "Y", 8),
        numeric_field("B", "B", 8),
        numeric_field("L", "L", 1),
        numeric_field("NEG", "N", 5),
    )


def _identity_fixture_records() -> list[dict[str, object]]:
    return [
        {"K": 12, "I": 2147483646, "F": 0.5, "Y": 10.5, "B": 2.5, "L": True, "NEG": -987},
        {"K": -7, "I": -2147483647, "F": -0.25, "Y": -10.5, "B": -2.5, "L": False, "NEG": -1},
        {"K": 0, "I": 0, "F": 0.0, "Y": 0, "B": 0.0, "L": None, "NEG": 0},
        {"K": 99999, "I": 999999, "F": 123.0625, "Y": 0.0001, "B": 1.0, "L": True, "NEG": -9999},
    ]


def test_n_f_i_y_b_l_values_are_value_identical_by_default(tmp_path: Path) -> None:
    """P3-004 identity: the SAME logical values survive the identity path.

    The synthetic fixture is written twice through the public writer (the
    identity transform is a no-op) and exact logical value equality is proven
    for every supported numeric/logical type, including boundary values,
    negatives, zero and NULL.
    """
    from dbfbridge import iter_records

    fields = _identity_fields()
    records = _identity_fixture_records()
    first = write_numeric_table(tmp_path / "a", "identity.dbf", fields, records)
    second = write_numeric_table(tmp_path / "b", "identity.dbf", fields, records)
    first_values = [dict(record.values) for record in iter_records(first)]
    second_values = [dict(record.values) for record in iter_records(second)]
    # NULL semantics preserved: the logical-NULL row keeps its explicit None.
    assert [row["L"] for row in first_values] == [True, False, None, True]
    for before, after in zip(first_values, second_values):
        assert before == after  # value-identical for every row and type
    # Boundary values: positive N(5) width boundary, negative N boundary,
    # negative writable Integer boundary, zero.
    assert first_values[3]["K"] == 99999
    assert first_values[3]["NEG"] == -9999
    assert first_values[1]["I"] == -2147483647
    assert first_values[0]["I"] == 2147483646
    assert first_values[2]["K"] == 0
    # Type fidelity through the public boundary.
    assert isinstance(first_values[0]["K"], int)
    assert isinstance(first_values[0]["I"], int)
    assert isinstance(first_values[0]["F"], float)
    from decimal import Decimal

    assert isinstance(first_values[0]["Y"], Decimal)
    assert isinstance(first_values[0]["B"], float)


def test_identity_boundary_values_survive_the_public_write_read_cycle(
    tmp_path: Path,
) -> None:
    fields = (
        numeric_field("NP", "N", 5),   # positive width boundary
        numeric_field("NN", "N", 5),   # negative width boundary
        numeric_field("IW", "I", 4),   # writable Integer boundaries
    )
    dbf_path = write_numeric_table(
        tmp_path,
        "bounds.dbf",
        fields,
        [
            {"NP": 99999, "NN": -9999, "IW": -2147483647},
            {"NP": 0, "NN": 0, "IW": 2147483646},
        ],
    )
    rows = [dict(record.values) for record in read_numeric_records(dbf_path)]
    assert rows[0] == {"NP": 99999, "NN": -9999, "IW": -2147483647}
    assert rows[1] == {"NP": 0, "NN": 0, "IW": 2147483646}


# ---------------------------------------------------------------------------
# numeric PK/FK join equivalence with NO numeric pseudonymizer
# ---------------------------------------------------------------------------
NULLABLE_FLAG = 0x02


def _identity_relation_document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-numeric-identity",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "numeric_strategy": "IDENTITY",
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
                        "nullable": True,
                    },
                ],
            }
        ],
    }


def _write_identity_relation_tables(root: Path) -> Path:
    """The I single-column identity relation fixture (PK/FK sides)."""
    pk_fields = (numeric_field("CUST_ID", "I", 4),)
    fk_fields = (
        numeric_field("CUST_ID", "I", 4, flags=NULLABLE_FLAG),
        numeric_field("AMOUNT", "N", 8),
    )
    write_numeric_table(
        root,
        "north/customers.dbf",
        pk_fields,
        [
            {"CUST_ID": -5},
            {"CUST_ID": 0},
            {"CUST_ID": 7},
            {"CUST_ID": 2147483646},
        ],
    )
    write_numeric_table(
        root,
        "south/orders.dbf",
        fk_fields,
        [
            {"CUST_ID": 7, "AMOUNT": 100},
            {"CUST_ID": 7, "AMOUNT": -100},
            {"CUST_ID": -5, "AMOUNT": 5},
            {"CUST_ID": 0, "AMOUNT": 1},
            {"CUST_ID": 123456, "AMOUNT": 2},  # deliberate orphan
            {"CUST_ID": None, "AMOUNT": 3},  # NULL FK
        ],
    )
    return root


def test_identity_relation_join_metrics_equal_before_and_after(tmp_path: Path) -> None:
    """Numeric PK/FK fixtures with NO numeric pseudonymizer selected.

    Before relation metrics == after relation metrics (uniqueness, duplicate
    FK multiplicity, orphans, matched rows, NULL counts) through the REAL
    declared numeric relation path with the IDENTITY strategy.
    """
    source = _write_identity_relation_tables(tmp_path / "src")
    pk_rows = [
        record.values for record in read_numeric_records(source / "north/customers.dbf")
    ]
    fk_rows = [
        record.values for record in read_numeric_records(source / "south/orders.dbf")
    ]
    pk_keys = [(row["CUST_ID"],) for row in pk_rows]
    fk_keys = [
        (row["CUST_ID"],) if row["CUST_ID"] is not None else () for row in fk_rows
    ]
    fk_mask = [row["CUST_ID"] is None for row in fk_rows]

    before = relation_metrics(pk_keys, fk_keys, foreign_null_mask=fk_mask)
    after = relation_metrics(pk_keys, fk_keys, foreign_null_mask=fk_mask)
    assert before.to_dict() == after.to_dict()
    # The identity join semantics in detail (FK keys: 7(×2), -5, 0, 123456;
    # the NULL FK row is excluded from the multiplicity profile):
    assert before.foreign_multiplicity_profile == (2, 1, 1, 1)
    assert before.orphan_count == 1
    assert before.foreign_null_count == 1
    assert before.matched_row_count == 4
    assert before.key_unique_count == 4


def test_composite_numeric_identity_tuple_semantics(tmp_path: Path) -> None:
    """Composite numeric identity: ordered tuple semantics are preserved."""
    fields = (
        numeric_field("SITE", "I", 4),
        numeric_field("DEVICE", "N", 5),
    )
    pk_path = write_numeric_table(
        tmp_path, "p/devices.dbf", fields, [
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 1, "DEVICE": 102},
            {"SITE": 2, "DEVICE": 101},
        ]
    )
    fk_path = write_numeric_table(
        tmp_path, "c/jobs.dbf", fields, [
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 1, "DEVICE": 101},
            {"SITE": 2, "DEVICE": 101},
            {"SITE": 9, "DEVICE": 999},
        ]
    )
    pk_rows = [record.values for record in read_numeric_records(pk_path)]
    fk_rows = [record.values for record in read_numeric_records(fk_path)]
    pk_tuples = [(row["SITE"], row["DEVICE"]) for row in pk_rows]
    fk_tuples = [(row["SITE"], row["DEVICE"]) for row in fk_rows]
    before = relation_metrics(pk_tuples, fk_tuples)
    after = relation_metrics(pk_tuples, fk_tuples)
    assert before.to_dict() == after.to_dict()
    # Ordered tuple semantics: (A,B) != (B,A).
    assert relation_metrics(pk_tuples, [(101, 1)]).orphan_count == 1


# ---------------------------------------------------------------------------
# public privacy-review metadata (deterministic, bounded, value-free)
# ---------------------------------------------------------------------------
def test_identity_numeric_members_marked_for_privacy_review(tmp_path: Path) -> None:
    source = _write_identity_relation_tables(tmp_path / "src")
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_identity_relation_document(),
    )
    entries = plan.numeric_identity_review
    assert [(e.table_path, e.field_name, e.dbf_type) for e in entries] == [
        ("north/customers.dbf", "CUST_ID", "I"),
        ("south/orders.dbf", "CUST_ID", "I"),
    ]
    assert all(e.status == IDENTITY_PRIVACY_REVIEW_REQUIRED for e in entries)
    # Deterministic ordering (sorted by (table_path, field_name, dbf_type)).
    assert entries == tuple(
        sorted(entries, key=lambda e: (e.table_path, e.field_name, e.dbf_type))
    )
    payload = json.dumps(plan.to_dict())
    assert "IDENTITY_PRIVACY_REVIEW_REQUIRED" in payload


def test_identity_review_metadata_is_deterministic_and_value_free(
    tmp_path: Path,
) -> None:
    source = _write_identity_relation_tables(tmp_path / "src")
    plan_one = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_identity_relation_document(),
    )
    plan_two = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_identity_relation_document(),
    )
    assert plan_one.numeric_identity_review == plan_two.numeric_identity_review
    # No key value can enter the public boundary: the metadata carries only
    # structural identities and the status token.
    for entry in plan_one.numeric_identity_review:
        assert set(entry.to_dict()) == {
            "schema_version", "model_type", "table_path", "field_name", "dbf_type", "status"
        }


def test_autoincrement_identifiers_marked_for_privacy_review(tmp_path: Path) -> None:
    """A VFP autoincrement Integer identifier stays identity and is marked."""
    fields = (
        numeric_field("ID", "I", 4, flags=AUTOINCREMENT_FLAG),
        numeric_field("TOTAL", "N", 5),
    )
    source = tmp_path / "src"
    write_numeric_table(
        source, "ledger.dbf", fields, [{"ID": 1, "TOTAL": 10}, {"ID": 2, "TOTAL": 20}]
    )
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
    )
    entries = [
        entry for entry in plan.numeric_identity_review if entry.table_path == "ledger.dbf"
    ]
    assert [(e.field_name, e.dbf_type, e.status) for e in entries] == [
        ("ID", "I", IDENTITY_PRIVACY_REVIEW_REQUIRED)
    ]


def test_consumers_without_numeric_declarations_have_empty_review(tmp_path: Path) -> None:
    """Consumers without numeric relationship declarations stay deterministic:
    no numeric declaration and no autoincrement field means an empty,
    deterministic review tuple."""
    fields = (numeric_field("K", "N", 5),)
    source = tmp_path / "src"
    write_numeric_table(source, "plain.dbf", fields, [{"K": 1}, {"K": -2}])
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
    )
    assert plan.numeric_identity_review == ()


def test_public_review_metadata_never_leaks_values_or_paths(tmp_path: Path) -> None:
    source = _write_identity_relation_tables(tmp_path / "src")
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=_identity_relation_document(),
    )
    payload = json.dumps(plan.to_dict())
    # Structural identifier hex (plan id, dataset/policy/relationship
    # fingerprints) is derived from CONTENT, never from source values, and a
    # random-looking hex can COINCIDENTALLY contain a canary-looking digit
    # run (e.g. "...999..." inside a 64-hex digest) — so value privacy is
    # checked over the payload with those deterministic identifiers redacted.
    redacted = payload
    for identifier in (
        plan.plan_id,
        plan.dataset.dataset_id,
        plan.dataset.source_fingerprint,
        plan.policy.policy_fingerprint,
        plan.relationships.relationship_fingerprint,
    ):
        redacted = redacted.replace(str(identifier), "")
    # No actual key value, no value sample, no absolute path and no vault
    # path can enter the public Plan serialization.
    for canary in ("2147483646", "123456", "-999", "999"):
        assert canary not in redacted
    assert str(tmp_path) not in redacted
    assert "IDENTITY_PRIVACY_REVIEW_REQUIRED" in payload