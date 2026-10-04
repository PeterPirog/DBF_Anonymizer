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
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import dbf_anonymizer as public
import dbfbridge

try:
    from examples import synthetic_dataset  # package-style execution
except ImportError:  # pragma: no cover - plain script execution
    import synthetic_dataset  # script execution


def _integer_column(dbf_path: Path, field_name: str) -> list[int]:
    """One column of public pseudonymized values (public streaming reads)."""
    return [
        record.values[field_name]
        for record in dbfbridge.iter_records(dbf_path, fields=(field_name,))
    ]


def main() -> None:
    if len(sys.argv) > 1:
        work_root = Path(sys.argv[1])
    else:
        work_root = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-example-rel-"))

    source = synthetic_dataset.create_related_dataset(work_root / "source")
    output = work_root / "output"
    vault = work_root / "protected" / "recovery.sqlite3"

    plan = public.build_plan(
        source,
        output,
        vault,
        relationship_document=synthetic_dataset.policy_relationship_document(),
    )
    assert plan.relationships.relation_count == 1
    preflight_result = public.preflight(plan)
    assert preflight_result.ready

    result = public.pseudonymize(plan)
    verification = public.verify_dataset(result, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS
    assert verification.assurance.level is (
        public.RelationalAssuranceLevel.DECLARED_RELATIONS_VERIFIED
    )
    assert verification.assurance.declared_relations == 1
    assert verification.assurance.verified_relations == 1
    assert verification.assurance.failed_relations == 0

    # Record-level PK/FK evidence through public reads only: the FK join
    # stays valid inside the pseudonymized domain, and the transformed key
    # domain is a genuine bijective pseudonym set (no original survived).
    people_ids = _integer_column(output / "people.dbf", "ID")
    person_ids = _integer_column(output / "orders.dbf", "PERSON_ID")
    assert set(person_ids) <= set(people_ids)
    assert len(set(people_ids)) == len(people_ids)
    original_ids = {1, 2, 3}
    assert not (set(people_ids) & original_ids)

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
