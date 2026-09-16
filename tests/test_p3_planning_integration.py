# -*- coding: utf-8 -*-
"""Remaining planning-integration evidence (blocks 1/2/3/10, part two)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

from dbf_anonymizer import MappingError, PolicyError, VaultError
from dbf_anonymizer.planning import build_plan
from dbf_anonymizer.preflight import preflight
from dbf_anonymizer.vault import (
    VAULT_DATABASE_FILENAME,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
    VaultDatabase,
)
from dbf_anonymizer.vault.mappings import (
    create_domain,
    text_mapping_rows,
)
from dbf_anonymizer.vault.text_allocation import (
    GLOBAL_TEXT_DOMAIN_ID,
    GlobalTextDomainMapping,
)
from support.vault_sessions import writer_session
from tests.support.memo_tables import field as dbf_field, schema as dbf_schema

SOURCE_FP = "src-" + "1" * 60
POLICY_FP = "pol-" + "2" * 60
RELATIONSHIP_FP = "rel-" + "3" * 60


def _write_source(tmp_path: Path) -> Path:
    from dbfbridge import DirectRecord, write_table

    fields = (
        dbf_field("CUST_ID", "C", 8),
        dbf_field("NOTE", "C", 8),
    )
    dbf_path_c = tmp_path / "src" / "customers" / "customers.dbf"
    dbf_path_o = tmp_path / "src" / "south" / "orders.dbf"
    for path in (dbf_path_c, dbf_path_o):
        path.parent.mkdir(parents=True, exist_ok=True)
        write_table(
            path,
            schema=dbf_schema(fields),
            records=[
                DirectRecord(
                    physical_index=0,
                    deleted=False,
                    values={"CUST_ID": "KUND-01", "NOTE": "NOTE-01"},
                ),
            ],
        )
    return tmp_path / "src"


def _document() -> dict[str, object]:
    return {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-customer-key",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "customers/customers.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }


def test_summary_only_metadata_still_fails_closed(tmp_path: Path) -> None:
    """Summary-only metadata with relation_count > 0 is NEVER faked."""
    source = _write_source(tmp_path)
    from dbf_anonymizer.models import RelationshipMetadata

    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationships=RelationshipMetadata(
            metadata_schema_version="1.0",
            provenance="POLICY_FILE",
            relationship_fingerprint="fp-" + "a" * 60,
            relation_count=2,
            authoritative=False,
        ),
    )
    result = preflight(plan)
    assert not result.ready
    payload = str(result.to_dict())
    assert "RELATIONSHIP_DOMAIN_UNVERIFIED" in payload


def test_incompatible_relationship_document_fails_preflight(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path)
    incompatible: dict[str, Any] = json.loads(json.dumps(_document()))
    incompatible["relations"][0]["comparison"] = "UNSPECIFIED"
    # build_plan parses and binds (read-only); the SEMANTIC compatibility
    # validation runs in preflight, which refuses BEFORE any transformation.
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=incompatible,
    )
    result = preflight(plan)
    assert not result.ready
    payload = str(result.to_dict())
    # The stable preflight relationship-domain failure code surfaces.
    assert "RELATIONSHIP_DOMAIN_UNVERIFIED" in payload
    # No source/vault paths and no key values in the report.
    assert str(tmp_path) not in payload
    assert "KUND" not in payload
    # Nothing was created by the refused pipeline.
    assert not (tmp_path / "vault" / VAULT_DATABASE_FILENAME).exists()


# ---------------------------------------------------------------------------
# BLOCKER-2: source-schema binding fixtures (fail closed before anything)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("mutate", "detail"),
    [
        (
            lambda doc: doc["relations"][0]["members"][0].update(
                {"table": "missing/nowhere.dbf"}
            ),
            "RELATIONSHIP_MEMBER_TABLE_UNKNOWN",
        ),
        (
            lambda doc: doc["relations"][0]["members"][0].update(
                {"field": "NOT_THERE"}
            ),
            "RELATIONSHIP_MEMBER_FIELD_UNKNOWN",
        ),
        (
            lambda doc: doc["relations"][0]["members"][0].update({"dbf_type": "V"}),
            "RELATIONSHIP_MEMBER_TYPE_MISMATCH",
        ),
        (
            lambda doc: doc["relations"][0]["members"][0].update(
                {"byte_width": 10}
            ),
            "RELATIONSHIP_MEMBER_WIDTH_MISMATCH",
        ),
        (
            lambda doc: doc["relations"][0]["members"][0].update(
                {"encoding": "utf-16le"}
            ),
            "RELATIONSHIP_MEMBER_ENCODING_INCOMPATIBLE",
        ),
    ],
)
def test_declared_member_schema_binding_fails_closed(
    tmp_path: Path, mutate: Callable[[dict], None], detail: str
) -> None:
    source = _write_source(tmp_path)
    document: dict[str, Any] = json.loads(json.dumps(_document()))
    mutate(document)
    with pytest.raises(PolicyError) as excinfo:
        build_plan(
            source,
            tmp_path / "out",
            tmp_path / "vault" / VAULT_DATABASE_FILENAME,
            relationship_document=document,
        )
    assert detail in str(excinfo.value.to_dict())
    boundary = str(excinfo.value) + "|" + str(excinfo.value.to_dict())
    # No absolute paths or key values leak with the typed refusal.
    assert str(tmp_path) not in boundary
    assert "KUND" not in boundary
    # Nothing was created: no output, no vault (fail closed BEFORE anything).
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "vault" / VAULT_DATABASE_FILENAME).exists()


# ---------------------------------------------------------------------------
# BLOCKER-10: real capacity incompatibility (the existing P2 kernel)
# ---------------------------------------------------------------------------
def test_binding_width_capacity_impossible_fails_closed(tmp_path: Path) -> None:
    """A shared pseudonym space can be mathematically impossible.

    The declared relation binds every pseudonym to the narrowest member
    width; a one-character C field admits exactly 36 safe single-char
    pseudonyms, so 40 distinct originals are mathematically impossible.  The
    REAL P2 allocation kernel refuses with the typed capacity failure BEFORE
    any publication (no truncation, no weakened self-exclusion, no P4).
    """
    source = tmp_path / "src"
    from dbfbridge import DirectRecord, write_table

    narrow_fields = (dbf_field("CUST_ID", "C", 1),)
    dbf_path_n = source / "narrow" / "keys.dbf"
    dbf_path_w = source / "south" / "orders.dbf"
    for path, fields, values in (
        (dbf_path_n, narrow_fields, {"CUST_ID": "K"}),
        (dbf_path_w, (dbf_field("CUST_ID", "C", 8), dbf_field("NOTE", "C", 8)), {"CUST_ID": "K00001", "NOTE": "NOTE-01"}),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        write_table(
            path,
            schema=dbf_schema(fields),
            records=[
                DirectRecord(
                    physical_index=0,
                    deleted=False,
                    values=values,
                ),
            ],
        )
    narrow: dict[str, Any] = {
        "metadata_schema_version": "1.0",
        "relations": [
            {
                "relation_id": "rel-narrow-key",
                "provenance": "POLICY_FILE",
                "comparison": "EXACT_VALUE",
                "members": [
                    {
                        "table": "narrow/keys.dbf",
                        "field": "CUST_ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 1,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 8,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }
    plan = build_plan(
        source,
        tmp_path / "out",
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        relationship_document=narrow,
    )
    assert preflight(plan).ready  # the declared relation itself is compatible
    with VaultDatabase.open(
        tmp_path / "vault" / VAULT_DATABASE_FILENAME,
        create=True,
        expected_source_fingerprint=SOURCE_FP,
        expected_policy_fingerprint=POLICY_FP,
        expected_relationship_fingerprint=RELATIONSHIP_FP,
        dbfbridge_version="1.1.0",
    ) as vault:
        with writer_session(vault), vault.transaction():
            create_domain(
                vault,
                domain_kind=VAULT_TABLE_DOMAIN_KIND_TEXT,
                domain_id=GLOBAL_TEXT_DOMAIN_ID,
            )
        with writer_session(vault):
            allocator = GlobalTextDomainMapping(vault)
            # The binding width of the declared relation is 1 (the narrow
            # source field): 40 distinct originals exceed the 36-token
            # single-char capacity — mathematically impossible.
            for index in range(40):
                allocator.observe("K" + f"{index:05d}", encoding="cp1250", byte_width=1)
            allocator.finalize()  # the capacity proof runs at ALLOCATION time
            with pytest.raises(MappingError):
                allocator.pseudonym_for("K00001")
            # No publication happened: the vault holds no mappings.
            assert text_mapping_rows(vault, GLOBAL_TEXT_DOMAIN_ID) == ()