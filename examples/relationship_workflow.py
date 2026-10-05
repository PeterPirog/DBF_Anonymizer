"""Relationship-preserving DBF_Anonymizer workflow (public API only).

Run:

    python examples/relationship_workflow.py [WORK_ROOT]

A synthetic two-table dataset (``people.dbf`` PRIMARY ``ID`` ->
``orders.dbf`` FOREIGN ``PERSON_ID``) is pseudonymized under a DECLARED
relationship: the declared numeric keys are transformed by the
``REVERSIBLE_BIJECTIVE`` strategy, which keeps the FK and the PK in ONE
consistent transformed domain (declared keys stay joinable; other numeric
fields are not affected).

The example then PROVES the declared relationship objectively after
pseudonymization — value-level FK-join evidence through the public
``dbfbridge`` streaming reads only, never row counts alone:

- every pseudonymized ``PERSON_ID`` still joins to a pseudonymized ``ID``;
- the pseudonymized key domain stays bijective and disjoint from the
  original values.

No original value is printed.  Synthetic data only; no network, no VFP.
The optional ``WORK_ROOT`` argument must NOT exist yet (fail-closed).
"""

from __future__ import annotations

from pathlib import Path

import dbf_anonymizer as public
import dbfbridge

try:
    from examples import synthetic_dataset  # package-style execution
except ImportError:  # pragma: no cover - plain script execution
    import synthetic_dataset  # script execution


def _require(condition: bool, message: str) -> None:
    """An explicit safety check that cannot disappear under ``python -O``."""
    if not condition:
        raise RuntimeError(message)


def _integer_column(dbf_path: Path, field_name: str) -> list[int]:
    """One column of public pseudonymized values (public streaming reads)."""
    return [
        record.values[field_name]
        for record in dbfbridge.iter_records(dbf_path, fields=(field_name,))
    ]


def main() -> None:
    work_root = synthetic_dataset.workspace_from_arguments("rel")

    source = synthetic_dataset.create_related_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(
        source,
        output,
        vault,
        relationship_document=synthetic_dataset.policy_relationship_document(),
    )
    _require(plan.relationships.relation_count == 1, "the declared relation was not planned")
    preflight_result = public.preflight(plan)
    _require(preflight_result.ready, "preflight refused the declared relationship")

    result = public.pseudonymize(plan)
    verification = synthetic_dataset.verify_dataset_with_transient_retry(result, source, vault)
    _require(
        verification.status is public.VerificationStatus.PASS,
        "dataset verification did not reach PASS",
    )
    _require(
        verification.assurance.level
        is (public.RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED),
        "the declared relationship was not verified after transformation",
    )
    _require(
        verification.assurance.declared_relations == 1
        and verification.assurance.verified_relations == 1
        and verification.assurance.failed_relations == 0,
        "relationship evidence counts are inconsistent",
    )

    # Record-level PK/FK evidence through public reads only: the FK join
    # stays valid inside the pseudonymized domain, and the transformed key
    # domain is a genuine bijective pseudonym set (no original survived).
    people_ids = _integer_column(output / "people.dbf", "ID")
    person_ids = _integer_column(output / "orders.dbf", "PERSON_ID")
    _require(set(person_ids) <= set(people_ids), "pseudonymized FK join is broken")
    _require(len(set(people_ids)) == len(people_ids), "pseudonymized PK is not bijective")
    _require(not (set(people_ids) & {1, 2, 3}), "original key values survived pseudonymization")

    print("DBF_Anonymizer relationship workflow (synthetic data)")
    print(f"declared relations: {plan.relationships.relation_count}")
    print(f"verification status: {verification.status.value}")
    print(f"assurance level: {verification.assurance.level.value}")
    print(
        "PK/FK evidence: every pseudonymized PERSON_ID joins the "
        "pseudonymized ID domain (value-level check passed)"
    )


if __name__ == "__main__":
    main()
