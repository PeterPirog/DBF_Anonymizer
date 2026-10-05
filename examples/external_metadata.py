"""External VFP metadata injection workflow (public API only).

Run:

    python examples/external_metadata.py [WORK_ROOT]

A higher-level analyzer (for example mcp-vfp9sp2-toolchain) can emit ONE
producer-independent JSON metadata document and inject it through the public
``build_plan(..., relationship_document=...)`` boundary.  DBF_Anonymizer owns
and ships the external metadata contract: the versioned JSON Schema is inside
the wheel and is loaded through the documented public loader
``dbf_anonymizer.relationships.load_external_metadata_schema()``.

The envelope demonstrates TWO SEPARATE evidence domains:

1. RELATION CLAIM — an eligible authoritative relation claim (per-claim
   ``CONTRACT_AUTHORITATIVE`` + ``assurance: VERIFIED`` + an authoritative
   VFP-metadata provenance class) can support ``VFP_METADATA_VERIFIED``;
   that level additionally requires the adapter-minted authoritative
   binding AND successful post-transform relationship verification.
2. INDEX CLAIM — independent index metadata with its own explicit
   ``verification_state``.  A VERIFIED index claim may become eligible to
   support the EXISTING index-validity machinery; it does NOT cause
   relational assurance, does NOT select the assurance level, and NEVER by
   itself proves that an output CDX/IDX artifact was rebuilt.  Output index
   validity still requires the authoritative ``IndexBackend`` rebuild/
   verification evidence (injected by the host under the opt-in
   ``VFP_INDEXED`` profile).

This example launches NO VFP, provides NO backend and claims NO index
publication validity; it stays planning/preflight oriented.

Synthetic data only; no network; no VFP/COM.  The optional ``WORK_ROOT``
argument must NOT exist yet (fail-closed).  Output stays privacy-safe.
"""

from __future__ import annotations

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


def _require(condition: bool, message: str) -> None:
    """An explicit safety check that cannot disappear under ``python -O``."""
    if not condition:
        raise RuntimeError(message)


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
    work_root = synthetic_dataset.workspace_from_arguments("external")

    # The shipped, versioned external-metadata schema is a wheel resource and
    # a documented public loader (producer-independent consumers can use it).
    schema = load_external_metadata_schema()
    _require(
        schema["x-contract-schema-version"] == EXTERNAL_METADATA_SCHEMA_VERSION,
        "the shipped external schema version is unexpected",
    )

    document = external_document()
    source = synthetic_dataset.create_related_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(source, output, vault, relationship_document=document)
    relationships = plan.relationships
    _require(relationships.provenance == "EXTERNAL_VFP_METADATA", "provenance was not preserved")
    _require(relationships.producer_id == "example-analyzer", "producer was not preserved")
    _require(relationships.authoritative is True, "authoritative relation metadata was not bound")
    preflight_result = public.preflight(plan)
    _require(preflight_result.ready, "preflight refused the external envelope")

    result = public.pseudonymize(plan)
    verification = synthetic_dataset.verify_dataset_with_transient_retry(result, source, vault)
    _require(
        verification.status is public.VerificationStatus.PASS,
        "dataset verification did not reach PASS",
    )
    _require(
        verification.assurance.level is (public.RelationalAssuranceLevel.VFP_METADATA_VERIFIED),
        "the verified authoritative relation metadata did not reach VFP_METADATA_VERIFIED",
    )

    print("DBF_Anonymizer external-metadata workflow (synthetic data)")
    print(f"shipped external schema version: {EXTERNAL_METADATA_SCHEMA_VERSION}")
    print(f"producer provenance preserved:   {relationships.producer_id}")
    print(f"verification status: {verification.status.value}")
    print(f"assurance level: {verification.assurance.level.value}")
    print(
        "evidence domains: the assurance level comes from the VERIFIED "
        "authoritative RELATION claim plus successful relationship "
        "verification; the VERIFIED INDEX claim is independent index "
        "metadata — it does NOT cause relational assurance and does NOT by "
        "itself prove that an output CDX/IDX was rebuilt (no backend was "
        "launched, none is implied)"
    )


if __name__ == "__main__":
    main()
