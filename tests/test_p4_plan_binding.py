"""BLOCKER 3 regressions: execution identity is bound to the Plan.

``run_two_pass`` accepts ONLY the immutable Plan: source/output/vault roots,
the resolved policy snapshot and the parsed relationship document come from
the Plan's PRIVATE execution context — no second runtime truth exists.  Every
hostile mismatch below is refused BEFORE the vault, the spool or any output
artifact is created: the source stays exactly as the failure-time input left
it, no output DBF/FPT appears, no vault is created and no spool artifact is
left behind.
"""

from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import pytest

from dbf_anonymizer import PathError, VaultError, build_plan
from dbf_anonymizer.engine import run_two_pass
from dbf_anonymizer.engine.state import spool_artifacts
from dbf_anonymizer.relationships.document import parse_relationship_document
from support.memo_tables import write_memo_table
from support.numeric_tables import numeric_field, write_numeric_table

_DOCUMENT = {
    "metadata_schema_version": "1.0",
    "relations": [
        {
            "relation_id": "rel-customer",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "members": [
                {
                    "table": "north/customers.dbf",
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


def _hash_tree(root: Path) -> dict[str, str]:
    import hashlib

    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _swap_context(plan, **changes):
    context = plan.execution_context
    assert context is not None
    object.__setattr__(plan, "execution_context", replace(context, **changes))
    return plan


def _make_dataset(tmp_path: Path) -> Path:
    source_root = tmp_path / "source"
    write_numeric_table(
        source_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": "KEY-01"}, {"CUST_ID": "KEY-02"}],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": "KEY-01"}],
    )
    return source_root


def _make_memo_dataset(tmp_path: Path) -> Path:
    source_root = tmp_path / "source"
    write_memo_table(
        source_root,
        "north/customers.dbf",
        (
            numeric_field("CUST_ID", "C", 8),
            numeric_field("NOTE", "M", 4),
        ),
        [{"CUST_ID": "KEY-01", "NOTE": "payload-one"}],
    )
    write_numeric_table(
        source_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": "KEY-01"}],
    )
    return source_root


def _plan(tmp_path: Path, source_root: Path):
    return build_plan(
        str(source_root),
        str(tmp_path / "output"),
        str(tmp_path / "vault" / "dictionary.sqlite3"),
        relationship_document=_DOCUMENT,
    )


def _vault_dir(tmp_path: Path) -> Path:
    return tmp_path / "vault"


# ---------------------------------------------------------------------------
# 1/2. Source DBF and FPT mutated after build_plan
# ---------------------------------------------------------------------------
def test_source_dbf_mutated_after_planning_refused_before_side_effects(
    tmp_path: Path,
) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    target = source_root / "north" / "customers.dbf"
    with target.open("ab") as handle:
        handle.write(b"\x00")
    mutated = _hash_tree(source_root)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_SOURCE_FINGERPRINT_MISMATCH"
    )
    assert _hash_tree(source_root) == mutated  # never "repaired"
    assert not (tmp_path / "output").exists() or not any((tmp_path / "output").rglob("*"))
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(_vault_dir(tmp_path)) == []


def test_source_fpt_mutated_after_planning_refused_before_side_effects(
    tmp_path: Path,
) -> None:
    source_root = _make_memo_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    companion = source_root / "north" / "customers.fpt"
    assert companion.is_file()
    with companion.open("ab") as handle:
        handle.write(b"\x00")
    mutated = _hash_tree(source_root)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_SOURCE_FINGERPRINT_MISMATCH"
    )
    assert _hash_tree(source_root) == mutated
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(_vault_dir(tmp_path)) == []


# ---------------------------------------------------------------------------
# 3. Source topology / fingerprinted sidecar changed after planning
# ---------------------------------------------------------------------------
def test_source_topology_change_after_planning_refused(tmp_path: Path) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    # A NEW in-scope artifact changes the enumerated fingerprint topology.
    write_numeric_table(
        source_root,
        "south/extra.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": "EXTRA"}],
    )
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_SOURCE_FINGERPRINT_MISMATCH"
    )
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(_vault_dir(tmp_path)) == []


# ---------------------------------------------------------------------------
# 4. A different source tree with a compatible schema
# ---------------------------------------------------------------------------
def test_compatible_foreign_source_tree_refused(tmp_path: Path) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    # Same schema, DIFFERENT data: only the plan-bound fingerprint kernel
    # (content, not schema) can tell the trees apart — and it refuses.
    foreign_root = tmp_path / "foreign"
    foreign_root.mkdir()
    write_numeric_table(
        foreign_root,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": "OTHER-1"}, {"CUST_ID": "OTHER-2"}],
    )
    write_numeric_table(
        foreign_root,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 8),),
        [{"CUST_ID": "OTHER-1"}],
    )
    _swap_context(plan, source_root=str(foreign_root))
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_SOURCE_FINGERPRINT_MISMATCH"
    )
    assert _hash_tree(source_root) == _hash_tree(source_root)
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()


# ---------------------------------------------------------------------------
# 5/6/7. Trust zones: output, vault or spool inside the wrong tree
# ---------------------------------------------------------------------------
def test_output_inside_source_refused(tmp_path: Path) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    _swap_context(plan, output_root=str(source_root / "output"))
    with pytest.raises(PathError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"] == "ENGINE_PATH_OVERLAP"
    )
    assert not (source_root / "output").exists()
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()


def test_vault_inside_source_refused(tmp_path: Path) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    _swap_context(plan, vault_path=str(source_root / "vault" / "dictionary.sqlite3"))
    with pytest.raises(PathError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"] == "ENGINE_PATH_OVERLAP"
    )
    assert not (source_root / "vault").exists()
    assert spool_artifacts(source_root / "vault") == []


def test_vault_inside_output_refused(tmp_path: Path) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    output_root = tmp_path / "output"
    _swap_context(plan, vault_path=str(output_root / "dictionary.sqlite3"))
    with pytest.raises(PathError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"] == "ENGINE_PATH_OVERLAP"
    )
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(output_root) == []


# ---------------------------------------------------------------------------
# 8. Alias/junction overlap where the platform supports it (Windows)
# ---------------------------------------------------------------------------
def test_junction_alias_overlap_refused(tmp_path: Path) -> None:
    import sys

    if sys.platform != "win32":  # pragma: no cover - platform-specific guard
        pytest.skip("junction aliases are a Windows-only overlap vector")
    import _winapi

    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    alias = tmp_path / "alias"
    _winapi.CreateJunction(str(source_root), str(alias))
    # The alias resolves to the SAME canonical tree: an output planned under
    # the alias would physically live inside the source.
    _swap_context(plan, output_root=str(alias / "output"))
    with pytest.raises(PathError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"] == "ENGINE_PATH_OVERLAP"
    )
    assert not (alias / "output").exists()


# ---------------------------------------------------------------------------
# 9/10. Policy and relationships are NOT runtime parameters (API design)
#       and a tampered context is caught by the fingerprint kernel
# ---------------------------------------------------------------------------
def test_no_runtime_policy_or_relationship_parameters() -> None:
    """The execution API accepts no second policy/relationship truth."""
    signature = inspect.signature(run_two_pass)
    assert "policy" not in signature.parameters
    assert "relationship_document" not in signature.parameters
    assert "source_root" not in signature.parameters
    assert "output_root" not in signature.parameters
    assert "vault_path" not in signature.parameters


def test_tampered_policy_in_context_refused(tmp_path: Path) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    tampered = dict(plan.execution_context.resolved_policy)
    tampered["text"] = {"default_action": "KEEP"}
    _swap_context(plan, resolved_policy=tampered)
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_POLICY_IDENTITY_MISMATCH"
    )
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(_vault_dir(tmp_path)) == []


def test_tampered_relationship_document_in_context_refused(
    tmp_path: Path,
) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    other = dict(_DOCUMENT)
    other["relations"] = [
        dict(_DOCUMENT["relations"][0], relation_id="rel-OTHER"),  # type: ignore[index]
    ]
    from dbf_anonymizer.relationships.document import parse_relationship_document

    _swap_context(
        plan, relationship_document=parse_relationship_document(other)
    )
    with pytest.raises(VaultError) as excinfo:
        run_two_pass(plan)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"]
        == "ENGINE_RELATIONSHIP_IDENTITY_MISMATCH"
    )
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(_vault_dir(tmp_path)) == []


# ---------------------------------------------------------------------------
# The honest path still runs (the binding never refuses a true Plan)
# ---------------------------------------------------------------------------
def test_untampered_plan_still_executes(tmp_path: Path) -> None:
    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    result = run_two_pass(plan)
    assert result.tables_written == ("north/customers.dbf", "south/orders.dbf")
    assert result.all_relations_verified
    assert spool_artifacts(_vault_dir(tmp_path)) == []


# ---------------------------------------------------------------------------
# REQ-P1-008: the pre-execution source refingerprint is cancellable
# ---------------------------------------------------------------------------
def test_cancellation_during_pre_execution_refingerprint(tmp_path: Path) -> None:
    """The cooperative cancellation probe is polled INSIDE the pre-execution
    source fingerprint scan: a returning-true check raises the typed
    CancellationError before ANY side effect — no vault, no spool, no
    output, no source record stream — and the source stays unchanged."""
    import dbfbridge
    from dbf_anonymizer import CancellationError

    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    failure_time = _hash_tree(source_root)
    probes = {"count": 0}

    def cancel() -> bool:
        probes["count"] += 1
        return True  # cancel at the FIRST fingerprint scan safe point

    import pytest as _pytest

    mp = _pytest.MonkeyPatch()

    def forbidden_iter_records(*args: object, **kwargs: object):
        raise AssertionError(
            "no PASS1 source record stream may open before the "
            "pre-execution revalidation completes"
        )

    mp.setattr(dbfbridge, "iter_records", forbidden_iter_records)
    try:
        with pytest.raises(CancellationError) as excinfo:
            run_two_pass(plan, cancel_check=cancel)
    finally:
        mp.undo()
    # The probe was really polled during the refingerprint scan.
    assert probes["count"] >= 1
    assert (
        excinfo.value.to_dict()["context"]["detail_code"] == "CANCELLED_BY_CHECK"
    )
    assert _hash_tree(source_root) == failure_time
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(_vault_dir(tmp_path)) == []
    assert not (tmp_path / "output").exists() or not any(
        (tmp_path / "output").rglob("*")
    )


def test_raising_cancel_check_during_refingerprint_stays_classified(
    tmp_path: Path,
) -> None:
    """P1-008 containment: a RAISING cancel check can never manufacture a
    genuine cancellation — during the pre-execution refingerprint it stays
    classified as CANCEL_CALLBACK_FAILED, with zero side effects."""
    from dbf_anonymizer import CallbackError

    source_root = _make_dataset(tmp_path)
    plan = _plan(tmp_path, source_root)
    failure_time = _hash_tree(source_root)

    def bad_check() -> bool:
        raise RuntimeError("hostile callback")

    with pytest.raises(CallbackError) as excinfo:
        run_two_pass(plan, cancel_check=bad_check)
    assert (
        excinfo.value.to_dict()["context"]["detail_code"] == "CANCEL_CHECK"
    )
    assert _hash_tree(source_root) == failure_time
    assert not (tmp_path / "vault" / "dictionary.sqlite3").exists()
    assert spool_artifacts(_vault_dir(tmp_path)) == []