"""External VFP metadata injection workflow (public API only).

Run:

    python examples/external_metadata.py [WORK_ROOT]

A higher-level analyzer (for example mcp-vfp9sp2-toolchain) can emit ONE
producer-independent JSON metadata document and inject it through the public
``build_plan(..., relationship_document=...)`` boundary.  DBF_Anonymizer owns
and ships the external metadata contract: the versioned JSON Schema is inside
the wheel and is loaded through the documented public loader
``dbf_anonymizer.relationships.load_external_metadata_schema()``.

The envelope demonstrates:

- ``external_metadata_schema_version`` and the structured producer identity;
- the envelope-level ``authority`` classification (contract metadata only —
  it is NOT a per-claim default);
- ONE authoritative relation claim: explicit ``provenance``, ``authority``
  and ``assurance`` on the claim itself;
- ONE index claim with its own explicit ``verification_state``.

TRUTHFUL INDEX LIMITATION — stated by the example itself:

- a VERIFIED injected index metadata claim is planning/reporting information
  that can raise relational assurance; it does NOT by itself prove that an
  OUTPUT CDX/IDX artifact was rebuilt. Output index validity still requires
  the appropriate authoritative ``IndexBackend`` rebuild/verification
  evidence (injected by the host under the opt-in ``VFP_INDEXED`` profile).
- this example launches NO VFP, provides NO backend and claims NO index
  publication validity; it stays planning/preflight oriented.

Synthetic data only; no network; no VFP/COM.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

import dbf_anonymizer as public
from dbf_anonymizer.relationships import (
    EXTERNAL_METADATA_SCHEMA_VERSION,
    load_external_metadata_schema,
)

try:
    from examples import synthetic_dataset  # package-style execution
except ImportError:  # pragma: no cover - plain script execution
    import synthetic_dataset  # script execution


def external_document() -> dict[str, Any]:
    """A conforming producer-independent external metadata envelope."""
    return {
        "metadata_schema_version": "1.0",
        "external_metadata_schema_version": EXTERNAL_METADATA_SCHEMA_VERSION,
        "producer": {"producer_id": "example-analyzer", "producer_version": "1.0.0"},
        "authority": "CONTRACT_AUTHORITATIVE",
        "relations": [
            {
                "relation_id": "orders-person-id-people-id",
                "comparison": "EXACT_VALUE",
                "provenance": "EXTERNAL_VFP_METADATA",
                "assurance": "VERIFIED",
                "authority": "CONTRACT_AUTHORITATIVE",
                "numeric_strategy": "REVERSIBLE_BIJECTIVE",
                "members": [
                    {
                        "table": "people.dbf",
                        "field": "ID",
                        "role": "PRIMARY",
                        "ordinal": 1,
                        "dbf_type": "I",
                        "byte_width": 4,
                        "encoding": "none",
                        "nullable": False,
                    },
                    {
                        "table": "orders.dbf",
                        "field": "PERSON_ID",
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
        "index_claims": [
            {
                "claim_id": "people-id-structural-cdx",
                "table": "people.dbf",
                "index_file": "people.cdx",
                "index_kind": "STRUCTURAL_CDX",
                "tags": [{"name": "ID", "sort_order": "ASCENDING", "expression": "ID"}],
                "verification_state": "VERIFIED",
                "assurance": "VERIFIED",
                "provenance": "EXTERNAL_VFP_METADATA",
                "authority": "CONTRACT_AUTHORITATIVE",
            }
        ],
    }


def main() -> None:
    if len(sys.argv) > 1:
        work_root = Path(sys.argv[1])
    else:
        work_root = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-example-external-"))

    # The shipped, versioned external-metadata schema is a wheel resource and
    # a documented public loader (producer-independent consumers can use it).
    schema = load_external_metadata_schema()
    assert schema["x-contract-schema-version"] == EXTERNAL_METADATA_SCHEMA_VERSION

    document = external_document()
    source = synthetic_dataset.create_related_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(source, output, vault, relationship_document=document)
    relationships = plan.relationships
    assert relationships.provenance == "EXTERNAL_VFP_METADATA"
    assert relationships.producer_id == "example-analyzer"
    assert relationships.authoritative is True
    preflight_result = public.preflight(plan)
    assert preflight_result.ready

    result = public.pseudonymize(plan)
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS
    assert verification.assurance.level is (public.RelationalAssuranceLevel.VFP_METADATA_VERIFIED)

    print("DBF_Anonymizer external-metadata workflow (synthetic data)")
    print(f"shipped external schema version: {EXTERNAL_METADATA_SCHEMA_VERSION}")
    print(f"producer provenance preserved:   {relationships.producer_id}")
    print(f"verification status: {verification.status.value}")
    print(f"assurance level: {verification.assurance.level.value}")
    print(
        "NOTE: the VERIFIED injected index claim raised relational assurance; "
        "it does NOT by itself prove that an output CDX/IDX was rebuilt "
        "(no backend was launched, none is implied)"
    )


if __name__ == "__main__":
    main()
