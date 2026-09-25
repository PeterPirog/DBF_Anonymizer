"""REQ-P6-003 public VFP_INDEXED protected-staging acceptance evidence."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import traceback
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import dbfbridge
import pytest

from dbf_anonymizer import (
    CancellationError,
    ErrorCode,
    IndexBackend,
    IndexBackendError,
    PathError,
    PublicationError,
    TransferProfile,
    build_plan,
    capabilities,
    preflight,
    pseudonymize,
)
from dbf_anonymizer.engine.run import _run_vfp_indexed_rebuild_and_verify
from dbf_anonymizer.index_backend import IndexRebuildOutcome, IndexRebuildRequest
from dbf_anonymizer.models import ProgressEvent
from tests.support.deterministic_index_backend import DeterministicIndexBackend
from tests.support.numeric_tables import (
    NULLABLE_FLAG,
    numeric_field,
    write_numeric_table,
    write_numeric_table_with_deleted,
)

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "p0"
_STRUCTURAL_RELATIVE = "structural/indexed_table.dbf"
_SOURCE_TAGS = ("SYNTHCODE", "SYNTHNOTE")
_PRIVATE_FAILURE_CANARIES = (
    "PRIVATE-DEFINITION-CANARY",
    "PRIVATE-MEMO-CANARY",
    "C:\\protected\\staging",
    "TAG-CANARY",
    "KEY0001",
    "SYNTH-A",
    "SYNTHCODE",
    "SYNTHNOTE",
)


def _copy_fixture(source: Path, fixture_relative: str, relative: str | None = None) -> None:
    destination = source / (relative or fixture_relative)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_FIXTURES / fixture_relative, destination)


def _copy_structural_source(source: Path) -> None:
    _copy_fixture(
        source,
        "vfp/structural/indexed_table.dbf",
        _STRUCTURAL_RELATIVE,
    )
    _copy_fixture(
        source,
        "vfp/structural/indexed_table.cdx",
        "structural/indexed_table.cdx",
    )


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _indexed_plan(
    tmp_path: Path,
    *,
    relationship_document: Mapping[str, Any] | None = None,
):
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    _copy_structural_source(source)
    plan = build_plan(
        str(source),
        str(output),
        str(vault),
        policy={"indexes": {"profile": "VFP_INDEXED"}},
        relationship_document=relationship_document,
    )
    assert plan.output_profile is TransferProfile.VFP_INDEXED
    return plan, source, output, vault


def _assert_not_published(output: Path, events: list[ProgressEvent] | None = None) -> None:
    assert not output.exists()
    if events is not None:
        assert not any(event.event_code == "COMPLETED" for event in events)


def _assert_index_failure(
    error: IndexBackendError,
    detail_code: str,
    *,
    private_paths: tuple[Path, ...] = (),
) -> None:
    assert error.code is ErrorCode.INDEX_BACKEND_FAILED
    assert error.context.detail_code == detail_code
    rendered = json.dumps(error.to_dict(), sort_keys=True) + "".join(
        traceback.format_exception(error)
    )
    for canary in _PRIVATE_FAILURE_CANARIES:
        assert canary not in rendered
    for path in private_paths:
        assert str(path.resolve()) not in rendered


class _BackendIdMismatchBackend(DeterministicIndexBackend):
    def rebuild_index(self, request: IndexRebuildRequest) -> IndexRebuildOutcome:
        outcome = super().rebuild_index(request)
        return IndexRebuildOutcome(
            result=replace(outcome.result, backend_id="foreign-backend"),
            expected_tag_inventory=outcome.expected_tag_inventory,
        )


class _MissingRebuiltArtifactBackend(DeterministicIndexBackend):
    def rebuild_index(self, request: IndexRebuildRequest) -> IndexRebuildOutcome:
        outcome = super().rebuild_index(request)
        request.staged_table_path.with_suffix(".cdx").unlink()
        return outcome


def test_missing_backend_fails_closed_before_transformation(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    source_before = _hash_tree(source)

    with pytest.raises(PublicationError) as caught:
        pseudonymize(plan)

    assert caught.value.context.detail_code == "PREFLIGHT_REJECTED"
    _assert_not_published(output)
    assert not vault.exists()
    assert _hash_tree(source) == source_before


def test_public_preflight_missing_backend_is_read_only_and_fails_closed(
    tmp_path: Path,
) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    before = _hash_tree(tmp_path)

    check = preflight(plan)

    assert check.ready is False
    assert "CAPABILITY_MISSING" in check.error_codes
    assert _hash_tree(tmp_path) == before
    assert _hash_tree(source)
    assert not output.exists()
    assert not vault.exists()


@pytest.mark.parametrize(
    "capability_override",
    (
        {"supports_structural_cdx_rebuild": False},
        {"supports_verification": False},
        {"vfp_runtime_available": False},
    ),
    ids=("no-structural-rebuild", "no-verification", "runtime-unavailable"),
)
def test_public_preflight_rejects_missing_backend_capability_without_mutation(
    tmp_path: Path, capability_override: dict[str, bool]
) -> None:
    plan, _source, output, vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        supports_structural_cdx_rebuild=capability_override.get(
            "supports_structural_cdx_rebuild", True
        ),
        supports_verification=capability_override.get("supports_verification", True),
        vfp_runtime_available=capability_override.get("vfp_runtime_available", True),
    )
    before = _hash_tree(tmp_path)

    check = preflight(plan, index_backend=backend)

    assert check.ready is False
    assert "CAPABILITY_MISSING" in check.error_codes
    assert backend.capabilities_calls == 1
    assert not backend.rebuild_requests
    assert not backend.verification_requests
    assert _hash_tree(tmp_path) == before
    assert not output.exists()
    assert not vault.exists()


class _MalformedPreflightBackend(DeterministicIndexBackend):
    def capabilities(self) -> object:  # type: ignore[override]
        return {
            "backend_id": "PRIVATE-BACKEND-CANARY",
            "private_path": "C:\\private\\source.dbf",
        }


def test_public_preflight_malformed_backend_has_typed_privacy_safe_refusal(
    tmp_path: Path,
) -> None:
    plan, _source, output, vault = _indexed_plan(tmp_path)
    before = _hash_tree(tmp_path)

    with pytest.raises(IndexBackendError) as caught:
        preflight(
            plan,
            index_backend=_MalformedPreflightBackend(),  # type: ignore[arg-type]
        )

    assert caught.value.context.detail_code == "INDEX_BACKEND_CAPABILITY_MALFORMED"
    rendered = json.dumps(caught.value.to_dict()) + "".join(
        traceback.format_exception(caught.value)
    )
    assert "PRIVATE-BACKEND-CANARY" not in rendered
    assert "private\\source" not in rendered
    assert _hash_tree(tmp_path) == before
    assert not output.exists()
    assert not vault.exists()


def test_public_success_uses_fresh_protected_staging_and_publishes_fresh_cdx(
    tmp_path: Path,
) -> None:
    plan, source, output, _vault = _indexed_plan(tmp_path)
    source_before = _hash_tree(source)
    source_rows = tuple(
        dbfbridge.iter_records(source / _STRUCTURAL_RELATIVE, include_deleted=True)
    )
    backend = DeterministicIndexBackend(
        expected_tag_inventory=_SOURCE_TAGS,
        actual_tag_inventory=_SOURCE_TAGS,
    )

    before_preflight = _hash_tree(tmp_path)
    check = preflight(plan, index_backend=backend)
    assert check.ready is True
    assert _hash_tree(tmp_path) == before_preflight
    assert not output.exists()

    result = pseudonymize(plan, index_backend=backend)

    assert result.record_count == 4
    assert len(backend.rebuild_requests) == len(backend.verification_requests) == 1
    rebuild = backend.rebuild_requests[0]
    verify = backend.verification_requests[0]
    final_table = (output / _STRUCTURAL_RELATIVE).resolve()
    assert backend.staged_table_existed_at_rebuild
    assert backend.rebuilt_cdx_existed_before_return
    assert rebuild.staged_table_path == verify.staged_table_path
    assert rebuild.staged_table_path != rebuild.source_table_path
    assert rebuild.staged_table_path != final_table
    assert rebuild.source_table_path == (source / _STRUCTURAL_RELATIVE).resolve()
    assert ".staging/" in rebuild.staged_table_path.as_posix()
    assert backend.staged_rows_at_rebuild
    assert backend.staged_rows_at_rebuild[0]["CODE"] != source_rows[0].values["CODE"]
    assert (output / "structural/indexed_table.cdx").read_bytes() == (
        b"DETERMINISTIC_FRESH_CDX_CONTENT"
    )
    assert (
        hashlib.sha256((output / "structural/indexed_table.cdx").read_bytes()).hexdigest()
        != source_before["structural/indexed_table.cdx"]
    )
    assert _hash_tree(source) == source_before
    assert backend.capabilities_calls == 2


def test_rebuild_exception_is_sanitized_and_never_published(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    write_numeric_table_with_deleted(
        source,
        "memo/private.dbf",
        (numeric_field("KEY", "C", 12), numeric_field("NOTE", "M", 4)),
        [({"KEY": "PRIVATE00001", "NOTE": "PRIVATE-MEMO-CANARY"}, False)],
    )
    plan = build_plan(
        str(source),
        str(output),
        str(vault),
        policy={"indexes": {"profile": "VFP_INDEXED"}},
    )
    source_before = _hash_tree(source)
    assert "memo/private.fpt" in source_before
    backend = DeterministicIndexBackend()
    backend.fail_rebuild_with = RuntimeError(
        "PRIVATE-DEFINITION-CANARY C:\\protected\\staging TAG-CANARY"
    )

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    _assert_index_failure(
        caught.value,
        "INDEX_BACKEND_REBUILD_FAILED",
        private_paths=(source, output, vault),
    )
    _assert_not_published(output)
    assert _hash_tree(source) == source_before


@pytest.mark.parametrize(
    ("status", "detail_code"),
    (("REFUSED", "REFUSED"), ("FAILED", "INTERNAL_ERROR")),
    ids=("refused", "failed"),
)
def test_non_rebuilt_status_never_publishes(
    tmp_path: Path, status: str, detail_code: str
) -> None:
    plan, source, output, _vault = _indexed_plan(tmp_path)
    source_before = _hash_tree(source)
    backend = DeterministicIndexBackend(status=status, detail_code=detail_code)

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    expected_detail = {
        "REFUSED": "INDEX_BACKEND_REBUILD_REFUSED",
        "FAILED": "INDEX_BACKEND_REBUILD_FAILED",
    }[status]
    _assert_index_failure(caught.value, expected_detail, private_paths=(source, output))
    _assert_not_published(output)
    assert _hash_tree(source) == source_before


def test_backend_id_mismatch_is_typed_and_never_published(tmp_path: Path) -> None:
    plan, source, output, _vault = _indexed_plan(tmp_path)

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=_BackendIdMismatchBackend())

    _assert_index_failure(
        caught.value,
        "INDEX_BACKEND_ID_MISMATCH",
        private_paths=(source, output),
    )
    _assert_not_published(output)


def test_missing_rebuilt_cdx_is_typed_and_never_published(tmp_path: Path) -> None:
    plan, source, output, _vault = _indexed_plan(tmp_path)

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=_MissingRebuiltArtifactBackend())

    _assert_index_failure(
        caught.value,
        "INDEX_BACKEND_REBUILT_ARTIFACT_MISSING",
        private_paths=(source, output),
    )
    _assert_not_published(output)


def test_table_open_failure_never_publishes(tmp_path: Path) -> None:
    plan, _source, output, _vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        verification_status="FAILED",
        verification_detail_code="OPEN_FAILED",
        table_opened=False,
        actual_tag_inventory=(),
    )

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    _assert_index_failure(
        caught.value,
        "INDEX_BACKEND_TABLE_NOT_OPENED",
        private_paths=(output,),
    )
    _assert_not_published(output)


def test_nominal_success_with_wrong_record_count_is_rejected(tmp_path: Path) -> None:
    plan, _source, output, _vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(actual_record_count=999)

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    _assert_index_failure(
        caught.value,
        "INDEX_BACKEND_RECORD_COUNT_MISMATCH",
        private_paths=(output,),
    )
    _assert_not_published(output)


def test_reported_tag_mismatch_never_publishes(tmp_path: Path) -> None:
    plan, _source, output, _vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        verification_status="MISMATCH",
        verification_detail_code="TAG_INVENTORY_MISMATCH",
        actual_tag_inventory=("WRONGTAG",),
    )

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    _assert_index_failure(
        caught.value,
        "INDEX_BACKEND_TAG_INVENTORY_MISMATCH",
        private_paths=(output,),
    )
    _assert_not_published(output)


def test_nominal_success_with_wrong_tag_evidence_is_rejected(tmp_path: Path) -> None:
    plan, _source, output, _vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(actual_tag_inventory=("WRONGTAG",))

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    _assert_index_failure(
        caught.value,
        "INDEX_BACKEND_TAG_INVENTORY_MISMATCH",
        private_paths=(output,),
    )
    _assert_not_published(output)


def test_genuine_staging_path_failure_remains_path_error(tmp_path: Path) -> None:
    with pytest.raises(PathError) as caught:
        _run_vfp_indexed_rebuild_and_verify(
            object(),  # type: ignore[arg-type]
            source_root=tmp_path,
            staging=SimpleNamespace(  # type: ignore[arg-type]
                dataset_root=tmp_path / "missing-staging"
            ),
            backend_contract=object(),  # type: ignore[arg-type]
            control=object(),  # type: ignore[arg-type]
        )

    assert caught.value.code is ErrorCode.PATH_INVALID
    assert caught.value.context.detail_code == "ENGINE_VFP_INDEXED_STAGING_UNAVAILABLE"


@pytest.mark.parametrize(
    "capability_override",
    (
        {"supports_structural_cdx_rebuild": False},
        {"supports_verification": False},
        {"vfp_runtime_available": False},
    ),
    ids=("rebuild", "verification", "runtime"),
)
def test_declared_missing_capability_fails_before_transformation(
    tmp_path: Path, capability_override: dict[str, bool]
) -> None:
    plan, _source, output, vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        supports_structural_cdx_rebuild=capability_override.get(
            "supports_structural_cdx_rebuild", True
        ),
        supports_verification=capability_override.get(
            "supports_verification", True
        ),
        vfp_runtime_available=capability_override.get(
            "vfp_runtime_available", True
        ),
    )

    with pytest.raises(PublicationError) as caught:
        pseudonymize(plan, index_backend=backend)

    assert caught.value.context.detail_code == "PREFLIGHT_REJECTED"
    _assert_not_published(output)
    assert not vault.exists()
    assert not backend.rebuild_requests


def test_cancellation_during_index_stage_has_no_completed_publication(
    tmp_path: Path,
) -> None:
    plan, _source, output, _vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend()
    events: list[ProgressEvent] = []
    index_stage_started = False

    def progress(event: ProgressEvent) -> None:
        nonlocal index_stage_started
        events.append(event)
        if event.phase_code == "INDEX_REBUILD":
            index_stage_started = True

    def cancel_check() -> bool:
        return index_stage_started

    with pytest.raises(CancellationError):
        pseudonymize(
            plan,
            index_backend=backend,
            progress=progress,
            cancel_check=cancel_check,
        )

    assert index_stage_started
    _assert_not_published(output, events)


def test_protected_paths_and_tag_canaries_are_absent_from_public_surfaces(
    tmp_path: Path,
) -> None:
    plan, _source, _output, _vault = _indexed_plan(tmp_path)
    tag_canary = "PROTECTEDTAGCANARY"
    backend = DeterministicIndexBackend(
        expected_tag_inventory=(tag_canary,),
        actual_tag_inventory=(tag_canary,),
    )
    events: list[ProgressEvent] = []

    result = pseudonymize(plan, index_backend=backend, progress=events.append)

    protected_path = str(backend.rebuild_requests[0].staged_table_path)
    surfaces = [
        json.dumps(result.to_dict(), sort_keys=True),
        *(json.dumps(event.to_dict(), sort_keys=True) for event in events),
    ]
    assert all(protected_path not in surface for surface in surfaces)
    assert all(tag_canary not in surface for surface in surfaces)
    assert not hasattr(backend.rebuild_requests[0], "definition")
    assert capabilities().vfp_index_backend is False


def test_deleted_null_varchar_memo_and_declared_relations_regressions(
    tmp_path: Path,
) -> None:
    relationship_document = {
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
                        "byte_width": 14,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                    {
                        "table": "south/orders.dbf",
                        "field": "CUST_ID",
                        "role": "FOREIGN",
                        "ordinal": 1,
                        "dbf_type": "C",
                        "byte_width": 14,
                        "encoding": "cp1250",
                        "nullable": False,
                    },
                ],
            }
        ],
    }
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    _copy_structural_source(source)
    write_numeric_table_with_deleted(
        source,
        "archive/data.dbf",
        (numeric_field("LEG_ID", "C", 12), numeric_field("NOTE", "M", 4)),
        [
            (
                {"LEG_ID": f"LEG{index:08d}", "NOTE": f"PRIVATE-MEMO-{index}"},
                index % 3 == 2,
            )
            for index in range(9)
        ],
    )
    write_numeric_table_with_deleted(
        source,
        "nullable/varchar.dbf",
        (numeric_field("TXT", "V", 8, flags=NULLABLE_FLAG),),
        [
            ({"TXT": value}, False)
            for value in (None, "", "A", "A ", "A  ")
        ],
    )
    write_numeric_table(
        source,
        "north/customers.dbf",
        (numeric_field("CUST_ID", "C", 14),),
        [{"CUST_ID": f"CUST{index:09d}"} for index in range(6)],
    )
    write_numeric_table(
        source,
        "south/orders.dbf",
        (numeric_field("CUST_ID", "C", 14), numeric_field("ORD_N", "N", 9)),
        [
            {"CUST_ID": f"CUST{index % 6:09d}", "ORD_N": index + 1}
            for index in range(12)
        ],
    )
    # Rebuild the immutable plan after adding all synthetic source tables.
    plan = build_plan(
        str(source),
        str(output),
        str(vault),
        policy={"indexes": {"profile": "VFP_INDEXED"}},
        relationship_document=relationship_document,
    )
    source_before = _hash_tree(source)
    backend = DeterministicIndexBackend()

    result = pseudonymize(plan, index_backend=backend)

    assert _hash_tree(source) == source_before
    source_archive = tuple(
        dbfbridge.iter_records(
            source / "archive/data.dbf", include_deleted=True, memo="inline"
        )
    )
    output_archive = tuple(
        dbfbridge.iter_records(
            output / "archive/data.dbf", include_deleted=True, memo="inline"
        )
    )
    assert [row.deleted for row in output_archive] == [
        row.deleted for row in source_archive
    ]
    assert all(
        output_row.values["LEG_ID"] != source_row.values["LEG_ID"]
        for source_row, output_row in zip(source_archive, output_archive)
    )
    assert all(
        output_row.values["NOTE"] != source_row.values["NOTE"]
        for source_row, output_row in zip(source_archive, output_archive)
    )
    assert b"PRIVATE-MEMO" not in (output / "archive/data.fpt").read_bytes()

    varchar_rows = tuple(
        dbfbridge.iter_records(output / "nullable/varchar.dbf", include_deleted=True)
    )
    varchar_values = [row.values["TXT"] for row in varchar_rows]
    assert varchar_values[:2] == [None, ""]
    assert len(set(varchar_values[2:])) == 3

    customer_keys = {
        row.values["CUST_ID"]
        for row in dbfbridge.iter_records(output / "north/customers.dbf")
    }
    order_keys = [
        row.values["CUST_ID"]
        for row in dbfbridge.iter_records(output / "south/orders.dbf")
    ]
    assert set(order_keys) <= customer_keys
    assert result.assurance.incomplete_relations == 0


def test_data_only_backend_none_still_omits_stale_structural_artifacts(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    _copy_structural_source(source)
    _copy_fixture(source, "vfp/idx/code_idx.idx", "structural/code_idx.idx")
    _copy_fixture(source, "vfp/fixture.dbc", "fixture.dbc")
    plan = build_plan(str(source), str(output), str(vault))

    before_preflight = _hash_tree(tmp_path)
    check = preflight(plan)
    assert check.ready is True
    assert _hash_tree(tmp_path) == before_preflight

    result = pseudonymize(plan, index_backend=None)

    assert plan.output_profile is TransferProfile.DATA_ONLY
    assert result.record_count == 4
    assert (output / _STRUCTURAL_RELATIVE).is_file()
    assert not any(
        path.suffix.lower() in {".cdx", ".idx", ".dbc", ".dct", ".dcx"}
        for path in output.rglob("*")
        if path.is_file()
    )


def _load_real_vfp_backend() -> IndexBackend:
    availability = os.environ.get("DBF_ANONYMIZER_REAL_VFP9_AVAILABLE")
    if availability is None or availability == "0":
        pytest.skip("trusted real VFP9 runtime is not declared available")
    assert availability == "1", (
        "DBF_ANONYMIZER_REAL_VFP9_AVAILABLE must be exactly 0 or 1"
    )
    factory_reference = os.environ.get("DBF_ANONYMIZER_REAL_VFP9_BACKEND_FACTORY")
    assert factory_reference, (
        "real VFP9 availability requires DBF_ANONYMIZER_REAL_VFP9_BACKEND_FACTORY"
    )
    module_name, separator, attribute_name = factory_reference.partition(":")
    assert separator and module_name and attribute_name, (
        "backend factory must use module.path:callable syntax"
    )
    factory = getattr(importlib.import_module(module_name), attribute_name)
    assert callable(factory)
    backend = factory()
    assert isinstance(backend, IndexBackend)
    capability = backend.capabilities()
    assert capability.vfp_runtime_available is True
    assert capability.supports_structural_cdx_rebuild is True
    assert capability.supports_verification is True
    return backend


def test_real_vfp9_rebuild_open_count_and_tag_inventory_when_declared(
    tmp_path: Path,
) -> None:
    backend = _load_real_vfp_backend()
    source = tmp_path / "source"
    output = tmp_path / "output"
    vault = tmp_path / "vault" / "dictionary.sqlite3"
    _copy_structural_source(source)
    write_numeric_table_with_deleted(
        source,
        "memo/private.dbf",
        (numeric_field("KEY", "C", 12), numeric_field("NOTE", "M", 4)),
        [({"KEY": "PRIVATE00001", "NOTE": "PRIVATE-MEMO-CANARY"}, False)],
    )
    plan = build_plan(
        str(source),
        str(output),
        str(vault),
        policy={"indexes": {"profile": "VFP_INDEXED"}},
    )
    structural = next(
        table for table in plan.tables if table.table_path == _STRUCTURAL_RELATIVE
    )
    assert structural.structural_cdx is True
    assert structural.structural_cdx_companion_present is True
    source_before = _hash_tree(source)
    assert "structural/indexed_table.dbf" in source_before
    assert "structural/indexed_table.cdx" in source_before
    assert "memo/private.dbf" in source_before
    assert "memo/private.fpt" in source_before

    preflight_before = _hash_tree(tmp_path)
    check = preflight(plan, index_backend=backend)
    assert check.ready is True
    assert _hash_tree(tmp_path) == preflight_before
    events: list[ProgressEvent] = []

    result = pseudonymize(plan, index_backend=backend, progress=events.append)

    output_dbf = output / _STRUCTURAL_RELATIVE
    output_cdx = output / "structural/indexed_table.cdx"
    assert result.record_count == 5
    assert getattr(backend, "staged_table_existed_before_rebuild") is True
    assert getattr(backend, "staged_cdx_existed_before_rebuild") is False
    assert getattr(backend, "table_opened") is True
    assert getattr(backend, "actual_record_count") == structural.record_count == 4
    assert getattr(backend, "expected_tag_inventory") == _SOURCE_TAGS
    assert getattr(backend, "actual_tag_inventory") == _SOURCE_TAGS
    assert output_dbf.is_file()
    assert output_cdx.is_file()
    assert getattr(backend, "source_cdx_hash_at_rebuild") == source_before[
        "structural/indexed_table.cdx"
    ]
    output_cdx_hash = hashlib.sha256(output_cdx.read_bytes()).hexdigest()
    output_dbf_hash = hashlib.sha256(output_dbf.read_bytes()).hexdigest()
    assert getattr(backend, "rebuilt_cdx_hash") == output_cdx_hash
    assert output_cdx_hash != source_before["structural/indexed_table.cdx"]
    published_record_count, published_tags = getattr(
        backend, "inspect_published_table"
    )(output_dbf)
    assert getattr(backend, "published_table_opened") is True
    assert published_record_count == structural.record_count == 4
    assert published_tags == _SOURCE_TAGS
    source_after = _hash_tree(source)
    assert source_after == source_before

    public_surfaces = [
        json.dumps(check.to_dict(), sort_keys=True),
        json.dumps(result.to_dict(), sort_keys=True),
        *(json.dumps(event.to_dict(), sort_keys=True) for event in events),
    ]
    private_tokens = (
        "KEY0001",
        "SYNTH-A",
        "PRIVATE00001",
        "PRIVATE-MEMO-CANARY",
        "SYNTHCODE",
        "SYNTHNOTE",
        "CODE",
        "NOTE",
        str(source.resolve()),
        str(output.resolve()),
        str(vault.resolve()),
    )
    assert all(
        token not in surface for token in private_tokens for surface in public_surfaces
    )

    print(f"VFP_VERSION={getattr(backend, 'runtime_version')}")
    print(f"VFP_TABLE_OPENED={getattr(backend, 'table_opened')}")
    print(f"VFP_PUBLISHED_TABLE_OPENED={getattr(backend, 'published_table_opened')}")
    print(f"VFP_RECORD_COUNT={getattr(backend, 'actual_record_count')}")
    print(
        "VFP_EXPECTED_TAGS="
        + ",".join(getattr(backend, "expected_tag_inventory"))
    )
    print(
        "VFP_ACTUAL_TAGS=" + ",".join(getattr(backend, "actual_tag_inventory"))
    )
    print(
        "VFP_STAGED_TABLE_EXISTED_BEFORE_REBUILD="
        f"{getattr(backend, 'staged_table_existed_before_rebuild')}"
    )
    print(
        "VFP_STAGED_CDX_EXISTED_BEFORE_REBUILD="
        f"{getattr(backend, 'staged_cdx_existed_before_rebuild')}"
    )
    print(f"SOURCE_DBF_SHA256_BEFORE={source_before['structural/indexed_table.dbf']}")
    print(f"SOURCE_DBF_SHA256_AFTER={source_after['structural/indexed_table.dbf']}")
    print(f"SOURCE_CDX_SHA256_BEFORE={source_before['structural/indexed_table.cdx']}")
    print(f"SOURCE_CDX_SHA256_AFTER={source_after['structural/indexed_table.cdx']}")
    print(f"SOURCE_FPT_SHA256_BEFORE={source_before['memo/private.fpt']}")
    print(f"SOURCE_FPT_SHA256_AFTER={source_after['memo/private.fpt']}")
    print(f"OUTPUT_DBF_SHA256={output_dbf_hash}")
    print(f"OUTPUT_CDX_SHA256={output_cdx_hash}")
    print(f"SOURCE_IMMUTABLE={source_after == source_before}")
    fresh_cdx = (
        not getattr(backend, "staged_cdx_existed_before_rebuild")
        and output_cdx.is_file()
    )
    print(f"FRESH_CDX={fresh_cdx}")
