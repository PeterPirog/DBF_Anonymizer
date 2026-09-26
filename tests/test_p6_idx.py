"""Focused REQ-P6-004 standalone-IDX acceptance evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import traceback
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from dbf_anonymizer import (
    CancellationError,
    INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
    IndexBackendError,
    PublicationError,
    VerificationStatus,
    build_plan,
    preflight,
    pseudonymize,
    verify_dataset,
)
from dbf_anonymizer.index_backend import (
    IndexRebuildOutcome,
    IndexRebuildRequest,
    IndexVerificationOutcome,
    IndexVerificationRequest,
    StandaloneIdxAssociationOutcome,
    StandaloneIdxAssociationRequest,
)
from dbf_anonymizer.models import ProgressEvent, StandaloneIdxAssociationResult
from tests.support.deterministic_index_backend import DeterministicIndexBackend
from tests.support.numeric_tables import numeric_field, write_numeric_table


_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "p0" / "vfp"


def _roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    return (
        tmp_path / "source",
        tmp_path / "output",
        tmp_path / "vault" / "dictionary.sqlite3",
    )


def _write_table(source: Path, relative_path: str) -> None:
    write_numeric_table(
        source,
        relative_path,
        (numeric_field("CODE", "C", 12),),
        [{"CODE": "PRIVATE0001"}],
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
    tables: tuple[str, ...] = ("north/registry.dbf",),
    indexes: tuple[tuple[str, bytes], ...] = (("indexes/code.idx", b"SOURCE-IDX"),),
):
    source, output, vault = _roots(tmp_path)
    for table in tables:
        _write_table(source, table)
    for relative, content in indexes:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    plan = build_plan(
        source,
        output,
        vault,
        policy={"indexes": {"profile": "VFP_INDEXED"}},
    )
    return plan, source, output, vault


def _assert_not_published(output: Path, events: list[ProgressEvent] | None = None) -> None:
    assert not output.exists()
    if events is not None:
        assert not any(event.event_code == "COMPLETED" for event in events)


class _WrongAssociationIdentityBackend(DeterministicIndexBackend):
    def associate_standalone_idx(
        self, request: StandaloneIdxAssociationRequest
    ) -> StandaloneIdxAssociationOutcome:
        outcome = super().associate_standalone_idx(request)
        return StandaloneIdxAssociationOutcome(
            result=replace(outcome.result, artifact_path="foreign.idx")
        )


class _WrongRebuildIdentityBackend(DeterministicIndexBackend):
    def rebuild_index(self, request: IndexRebuildRequest) -> IndexRebuildOutcome:
        outcome = super().rebuild_index(request)
        return IndexRebuildOutcome(
            result=replace(outcome.result, artifact_path="foreign.idx"),
            expected_tag_inventory=outcome.expected_tag_inventory,
        )


class _WrongVerificationIdentityBackend(DeterministicIndexBackend):
    def verify_index(
        self, request: IndexVerificationRequest
    ) -> IndexVerificationOutcome:
        outcome = super().verify_index(request)
        return IndexVerificationOutcome(
            result=replace(outcome.result, artifact_path="foreign.idx"),
            table_opened=outcome.table_opened,
            actual_record_count=outcome.actual_record_count,
            actual_tag_inventory=outcome.actual_tag_inventory,
        )


class _WrongTargetBackend(DeterministicIndexBackend):
    def rebuild_index(self, request: IndexRebuildRequest) -> IndexRebuildOutcome:
        outcome = super().rebuild_index(request)
        assert request.staged_idx_path is not None
        request.staged_idx_path.unlink()
        request.staged_idx_path.with_name("foreign.idx").write_bytes(b"WRONG-TARGET")
        return outcome


class _MutatingVerificationBackend(DeterministicIndexBackend):
    def verify_index(
        self, request: IndexVerificationRequest
    ) -> IndexVerificationOutcome:
        outcome = super().verify_index(request)
        assert request.staged_idx_path is not None
        request.staged_idx_path.write_bytes(b"MUTATED-AFTER-VERIFY")
        return outcome


class _AssociationExceptionBackend(DeterministicIndexBackend):
    def associate_standalone_idx(
        self, request: StandaloneIdxAssociationRequest
    ) -> StandaloneIdxAssociationOutcome:
        raise RuntimeError("PRIVATE-INDEX-DEFINITION C:\\private\\source.idx")


def test_dataset_inventory_is_independent_of_table_ownership(tmp_path: Path) -> None:
    source, output, vault = _roots(tmp_path)
    _write_table(source, "north/registry.dbf")
    _write_table(source, "south/registry.dbf")
    (source / "north" / "registry.idx").write_bytes(b"SOURCE-IDX")

    plan = build_plan(source, output, vault)

    assert plan.dataset.standalone_idx_paths == ("north/registry.idx",)
    assert all(not hasattr(table, "standalone_idx_paths") for table in plan.tables)


def test_zero_idx_inventory_is_explicitly_empty(tmp_path: Path) -> None:
    source, output, vault = _roots(tmp_path)
    _write_table(source, "data/table.dbf")

    plan = build_plan(source, output, vault)

    assert plan.dataset.standalone_idx_paths == ()


def test_same_stem_does_not_invent_authoritative_ownership(tmp_path: Path) -> None:
    source, output, vault = _roots(tmp_path)
    _write_table(source, "data/registry.dbf")
    baseline = build_plan(source, output, vault)
    (source / "data" / "registry.idx").write_bytes(b"SOURCE-IDX")

    with_idx = build_plan(source, output, vault)

    assert baseline.tables == with_idx.tables
    assert with_idx.dataset.standalone_idx_paths == ("data/registry.idx",)


def test_multiple_idx_have_distinct_deterministic_inventory(tmp_path: Path) -> None:
    source, output, vault = _roots(tmp_path)
    _write_table(source, "data/table.dbf")
    (source / "zeta.idx").write_bytes(b"Z")
    (source / "data" / "alpha.IDX").write_bytes(b"A")

    first = build_plan(source, output, vault)
    second = build_plan(source, output, vault)

    expected = ("data/alpha.IDX", "zeta.idx")
    assert first.dataset.standalone_idx_paths == expected
    assert second.dataset.standalone_idx_paths == expected
    assert len(set(expected)) == 2


def test_data_only_records_each_idx_as_omitted(tmp_path: Path) -> None:
    source, output, vault = _roots(tmp_path)
    _write_table(source, "data/table.dbf")
    (source / "first.idx").write_bytes(b"FIRST-SOURCE-IDX")
    (source / "second.idx").write_bytes(b"SECOND-SOURCE-IDX")
    plan = build_plan(source, output, vault)

    result = pseudonymize(plan)

    assert [item.artifact_path for item in result.index_artifacts] == [
        "first.idx",
        "second.idx",
    ]
    assert {item.status for item in result.index_artifacts} == {"OMITTED_DATA_ONLY"}
    assert not list(output.rglob("*.idx"))


def test_vfp_indexed_missing_backend_is_bounded_preflight_refusal(
    tmp_path: Path,
) -> None:
    source, output, vault = _roots(tmp_path)
    destination = source / "idx" / "standalone_idx_table.dbf"
    destination.parent.mkdir(parents=True)
    shutil.copy2(_FIXTURE_ROOT / "idx" / "standalone_idx_table.dbf", destination)
    shutil.copy2(_FIXTURE_ROOT / "idx" / "code_idx.idx", source / "idx" / "code_idx.idx")
    plan = build_plan(
        source,
        output,
        vault,
        policy={"indexes": {"profile": "VFP_INDEXED"}},
    )

    check = preflight(plan)

    assert check.ready is False
    assert check.error_codes == ("CAPABILITY_MISSING",)
    assert not output.exists()
    assert not vault.exists()


def test_inventory_is_deterministic_when_walk_enumeration_is_reversed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.discovery as discovery

    source, output, vault = _roots(tmp_path)
    _write_table(source, "data/table.dbf")
    for name in ("z.idx", "A.IDX", "middle.idx"):
        (source / name).write_bytes(name.encode("ascii"))
    baseline = build_plan(source, output, vault)
    real_walk = discovery.os.walk

    def reversed_walk(*args: Any, **kwargs: Any):
        for current, directories, files in real_walk(*args, **kwargs):
            yield current, list(reversed(directories)), list(reversed(files))

    monkeypatch.setattr(discovery.os, "walk", reversed_walk)
    reordered = build_plan(source, output, vault)

    assert reordered.dataset.standalone_idx_paths == baseline.dataset.standalone_idx_paths
    assert reordered.plan_id == baseline.plan_id


def test_case_variant_inventory_path_is_normalized_and_bounded(tmp_path: Path) -> None:
    source, output, vault = _roots(tmp_path)
    _write_table(source, "data/table.dbf")
    path = source / "Mixed" / "Case.IDX"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"IDX")

    plan = build_plan(source, output, vault)

    assert plan.dataset.standalone_idx_paths == ("Mixed/Case.IDX",)
    assert "\\" not in plan.dataset.standalone_idx_paths[0]


def test_data_only_omits_all_idx_and_preserves_every_source_hash(tmp_path: Path) -> None:
    source, output, vault = _roots(tmp_path)
    _write_table(source, "data/table.dbf")
    for relative, content in (("a.idx", b"IDX-A"), ("nested/b.idx", b"IDX-B")):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    before = _hash_tree(source)

    result = pseudonymize(build_plan(source, output, vault))

    assert _hash_tree(source) == before
    assert not list(output.rglob("*.idx"))
    assert tuple(item.artifact_path for item in result.index_artifacts) == (
        "a.idx",
        "nested/b.idx",
    )
    assert all(item.status == "OMITTED_DATA_ONLY" for item in result.index_artifacts)
    assert tuple(item.source_sha256 for item in result.index_artifacts) == (
        before["a.idx"],
        before["nested/b.idx"],
    )
    assert len({item.artifact_id for item in result.index_artifacts}) == 2


def test_authoritative_backend_associates_without_filename_inference(
    tmp_path: Path,
) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    source_before = _hash_tree(source)
    backend = DeterministicIndexBackend(
        standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"}
    )

    result = pseudonymize(plan, index_backend=backend)
    verification = verify_dataset(result, source=source, vault=vault)

    assert verification.status is VerificationStatus.PASS
    assert len(backend.association_requests) == 1
    assert len(backend.rebuild_requests) == len(backend.verification_requests) == 1
    rebuild = backend.rebuild_requests[0]
    verify = backend.verification_requests[0]
    assert rebuild.table_path == verify.table_path == "north/registry.dbf"
    assert rebuild.artifact_path == verify.artifact_path == "indexes/code.idx"
    assert rebuild.source_idx_path == (source / "indexes/code.idx").resolve()
    assert rebuild.staged_idx_path == verify.staged_idx_path
    assert rebuild.staged_idx_path is not None
    assert ".staging/" in rebuild.staged_idx_path.as_posix()
    assert (output / "indexes/code.idx").read_bytes() == (
        b"DETERMINISTIC_FRESH_IDX_CONTENT"
    )
    evidence = result.index_artifacts[0]
    assert evidence.status == "REBUILT_VERIFIED"
    assert evidence.table_path == "north/registry.dbf"
    assert evidence.source_sha256 == source_before["indexes/code.idx"]
    assert evidence.output_sha256 == hashlib.sha256(
        b"DETERMINISTIC_FRESH_IDX_CONTENT"
    ).hexdigest()
    assert evidence.output_sha256 != evidence.source_sha256
    assert _hash_tree(source) == source_before


def test_duplicate_dbf_basenames_use_only_backend_selected_table(tmp_path: Path) -> None:
    plan, _source, output, _vault = _indexed_plan(
        tmp_path,
        tables=("north/registry.dbf", "south/registry.dbf"),
        indexes=(("north/registry.idx", b"SOURCE-IDX"),),
    )
    backend = DeterministicIndexBackend(
        standalone_idx_associations={"north/registry.idx": "south/registry.dbf"}
    )

    result = pseudonymize(plan, index_backend=backend)

    assert result.index_artifacts[0].table_path == "south/registry.dbf"
    assert backend.rebuild_requests[0].table_path == "south/registry.dbf"
    assert (output / "north/registry.idx").is_file()


def test_multiple_idx_are_rebuilt_and_verified_independently(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(
        tmp_path,
        indexes=(("first.idx", b"SOURCE-A"), ("nested/second.idx", b"SOURCE-B")),
    )
    backend = DeterministicIndexBackend(
        standalone_idx_associations={
            "first.idx": "north/registry.dbf",
            "nested/second.idx": "north/registry.dbf",
        }
    )

    result = pseudonymize(plan, index_backend=backend)

    assert len(backend.association_requests) == 2
    assert len(backend.rebuild_requests) == len(backend.verification_requests) == 2
    assert {request.artifact_path for request in backend.rebuild_requests} == {
        "first.idx",
        "nested/second.idx",
    }
    assert all(item.status == "REBUILT_VERIFIED" for item in result.index_artifacts)
    assert (output / "first.idx").is_file()
    assert (output / "nested/second.idx").is_file()
    assert verify_dataset(result, source=source, vault=vault).status is VerificationStatus.PASS


def test_unavailable_definition_is_omitted_and_verifies_partial(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend()

    result = pseudonymize(plan, index_backend=backend)
    verification = verify_dataset(result, source=source, vault=vault)

    assert result.index_artifacts[0].status == "OMITTED_UNVERIFIED"
    assert result.index_artifacts[0].table_path is None
    assert not list(output.rglob("*.idx"))
    assert verification.status is VerificationStatus.PARTIAL
    assert verification.check_codes == ("STANDALONE_IDX_DEFINITION_UNAVAILABLE",)


def test_backend_refusal_after_association_is_durable_partial(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"},
        status="REFUSED",
        detail_code="REFUSED",
    )

    result = pseudonymize(plan, index_backend=backend)
    verification = verify_dataset(result, source=source, vault=vault)

    assert result.index_artifacts[0].status == "OMITTED_UNVERIFIED"
    assert result.index_artifacts[0].table_path == "north/registry.dbf"
    assert not list(output.rglob("*.idx"))
    assert verification.status is VerificationStatus.PARTIAL


def test_partial_rebuild_never_promotes_full_set_to_pass(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(
        tmp_path,
        indexes=(("first.idx", b"SOURCE-A"), ("second.idx", b"SOURCE-B")),
    )
    backend = DeterministicIndexBackend(
        standalone_idx_associations={"first.idx": "north/registry.dbf"}
    )

    result = pseudonymize(plan, index_backend=backend)
    verification = verify_dataset(result, source=source, vault=vault)

    assert [item.status for item in result.index_artifacts] == [
        "REBUILT_VERIFIED",
        "OMITTED_UNVERIFIED",
    ]
    assert (output / "first.idx").is_file()
    assert not (output / "second.idx").exists()
    assert verification.status is VerificationStatus.PARTIAL


@pytest.mark.parametrize(
    ("backend_factory", "detail_code"),
    (
        (
            lambda: DeterministicIndexBackend(
                standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"},
                create_standalone_idx_artifact=False,
            ),
            "INDEX_BACKEND_REBUILT_ARTIFACT_MISSING",
        ),
        (
            lambda: _WrongTargetBackend(
                standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"}
            ),
            "INDEX_BACKEND_REBUILT_ARTIFACT_MISSING",
        ),
        (
            lambda: DeterministicIndexBackend(
                standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"},
                standalone_idx_bytes=b"SOURCE-IDX",
            ),
            "INDEX_BACKEND_STALE_ARTIFACT_COPY",
        ),
    ),
    ids=("missing-artifact", "wrong-target", "stale-source-copy"),
)
def test_invalid_rebuilt_artifact_fails_closed_without_publication(
    tmp_path: Path, backend_factory: object, detail_code: str
) -> None:
    plan, source, output, _vault = _indexed_plan(tmp_path)
    source_before = _hash_tree(source)
    backend = backend_factory()  # type: ignore[operator]

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    assert caught.value.context.detail_code == detail_code
    _assert_not_published(output)
    assert _hash_tree(source) == source_before


@pytest.mark.parametrize(
    "backend_type",
    (
        _WrongAssociationIdentityBackend,
        _WrongRebuildIdentityBackend,
        _WrongVerificationIdentityBackend,
    ),
    ids=("association", "rebuild", "verification"),
)
def test_mismatched_per_idx_identity_fails_closed(
    tmp_path: Path, backend_type: type[DeterministicIndexBackend]
) -> None:
    plan, _source, output, _vault = _indexed_plan(tmp_path)
    backend = backend_type(
        standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"}
    )

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    assert caught.value.context.detail_code in {
        "INDEX_BACKEND_ASSOCIATION_MISMATCH",
        "INDEX_BACKEND_RESULT_MISMATCH",
        "INDEX_BACKEND_VERIFICATION_RESULT_MISMATCH",
    }
    _assert_not_published(output)


@pytest.mark.parametrize(
    ("backend", "detail_code"),
    (
        (
            DeterministicIndexBackend(
                standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"},
                verification_status="FAILED",
                verification_detail_code="OPEN_FAILED",
                table_opened=False,
                actual_tag_inventory=(),
            ),
            "INDEX_BACKEND_TABLE_NOT_OPENED",
        ),
        (
            DeterministicIndexBackend(
                standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"},
                actual_record_count=999,
            ),
            "INDEX_BACKEND_RECORD_COUNT_MISMATCH",
        ),
        (
            _MutatingVerificationBackend(
                standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"}
            ),
            "INDEX_BACKEND_VERIFICATION_RESULT_MISMATCH",
        ),
    ),
    ids=("table-open", "record-count", "artifact-mutated"),
)
def test_verification_failure_is_atomic(
    tmp_path: Path, backend: DeterministicIndexBackend, detail_code: str
) -> None:
    plan, source, output, _vault = _indexed_plan(tmp_path)
    source_before = _hash_tree(source)

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    assert caught.value.context.detail_code == detail_code
    _assert_not_published(output)
    assert _hash_tree(source) == source_before


def test_backend_exception_is_privacy_safe_and_atomic(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=_AssociationExceptionBackend())

    assert caught.value.context.detail_code == "INDEX_BACKEND_ASSOCIATION_FAILED"
    rendered = json.dumps(caught.value.to_dict()) + "".join(
        traceback.format_exception(caught.value)
    )
    for forbidden in (
        "PRIVATE-INDEX-DEFINITION",
        str(source.resolve()),
        str(output.resolve()),
        str(vault.resolve()),
    ):
        assert forbidden not in rendered
    _assert_not_published(output)


def test_backend_without_standalone_support_is_preflight_refusal(tmp_path: Path) -> None:
    plan, _source, output, vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(supports_standalone_idx_rebuild=False)

    check = preflight(plan, index_backend=backend)

    assert check.ready is False
    assert check.error_codes == ("CAPABILITY_MISSING",)
    assert not output.exists()
    assert not vault.exists()


@pytest.mark.parametrize("cancel_after", ("rebuild", "verification"))
def test_cancellation_after_idx_backend_step_has_no_completed_output(
    tmp_path: Path, cancel_after: str
) -> None:
    plan, source, output, _vault = _indexed_plan(tmp_path)
    source_before = _hash_tree(source)
    backend = DeterministicIndexBackend(
        standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"}
    )
    events: list[ProgressEvent] = []

    def cancelled() -> bool:
        if cancel_after == "rebuild":
            return backend.rebuilt_idx_existed_before_return
        return bool(backend.verification_requests)

    with pytest.raises(CancellationError):
        pseudonymize(
            plan,
            index_backend=backend,
            progress=events.append,
            cancel_check=cancelled,
        )

    assert backend.rebuild_requests
    if cancel_after == "rebuild":
        assert not backend.verification_requests
    else:
        assert backend.verification_requests
    _assert_not_published(output, events)
    assert _hash_tree(source) == source_before


@pytest.mark.parametrize("failure_stage", ("rebuild", "verification"))
def test_backend_operation_exception_is_sanitized(
    tmp_path: Path, failure_stage: str
) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"}
    )
    failure = RuntimeError("RAW-EXCEPTION C:\\private\\vfp9.exe INDEX ON SECRET")
    if failure_stage == "rebuild":
        backend.fail_rebuild_with = failure
        expected = "INDEX_BACKEND_REBUILD_FAILED"
    else:
        backend.fail_verification_with = failure
        expected = "INDEX_BACKEND_VERIFICATION_FAILED"

    with pytest.raises(IndexBackendError) as caught:
        pseudonymize(plan, index_backend=backend)

    assert caught.value.context.detail_code == expected
    rendered = json.dumps(caught.value.to_dict()) + "".join(
        traceback.format_exception(caught.value)
    )
    for forbidden in (
        "RAW-EXCEPTION",
        "INDEX ON SECRET",
        str(source.resolve()),
        str(output.resolve()),
        str(vault.resolve()),
    ):
        assert forbidden not in rendered
    _assert_not_published(output)


def test_process_local_idx_paths_are_root_bounded_and_not_serializable(
    tmp_path: Path,
) -> None:
    source, staging, _vault = _roots(tmp_path)
    _write_table(source, "north/registry.dbf")
    _write_table(staging, "north/registry.dbf")
    source_idx = source / "indexes" / "code.idx"
    source_idx.parent.mkdir(parents=True)
    source_idx.write_bytes(b"SOURCE-IDX")
    valid = StandaloneIdxAssociationRequest(
        protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
        artifact_path="indexes/code.idx",
        source_dataset_root=source.resolve(),
        source_idx_path=source_idx.resolve(),
        table_paths=("north/registry.dbf",),
    )
    assert not hasattr(valid, "to_dict")

    with pytest.raises(ValueError):
        StandaloneIdxAssociationRequest(
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_path="../escape.idx",
            source_dataset_root=source.resolve(),
            source_idx_path=source_idx.resolve(),
            table_paths=("north/registry.dbf",),
        )
    with pytest.raises(ValueError):
        IndexRebuildRequest(
            protocol_schema_version=INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION,
            artifact_class="STANDALONE_IDX",
            table_path="north/registry.dbf",
            source_table_path=(source / "north/registry.dbf").resolve(),
            staged_table_path=(staging / "north/registry.dbf").resolve(),
            source_idx_path=source_idx.resolve(),
            staged_idx_path=(tmp_path / "outside.idx").resolve(),
            artifact_path="indexes/code.idx",
            source_dataset_root=source.resolve(),
            staged_dataset_root=staging.resolve(),
        )


def test_cancellation_during_idx_stage_has_no_completion_or_output(
    tmp_path: Path,
) -> None:
    plan, _source, output, _vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"}
    )
    events: list[ProgressEvent] = []
    index_started = False

    def progress(event: ProgressEvent) -> None:
        nonlocal index_started
        events.append(event)
        if event.phase_code == "INDEX_REBUILD":
            index_started = True

    with pytest.raises(CancellationError):
        pseudonymize(
            plan,
            index_backend=backend,
            progress=progress,
            cancel_check=lambda: index_started,
        )

    assert index_started
    _assert_not_published(output, events)


def test_public_surfaces_contain_no_private_index_material(tmp_path: Path) -> None:
    plan, source, output, vault = _indexed_plan(tmp_path)
    backend = DeterministicIndexBackend(
        backend_id="safe-backend-id",
        standalone_idx_associations={"indexes/code.idx": "north/registry.dbf"},
    )
    events: list[ProgressEvent] = []

    result = pseudonymize(plan, index_backend=backend, progress=events.append)
    verification = verify_dataset(result, source=source, vault=vault)
    surfaces = [
        json.dumps(plan.to_dict(), sort_keys=True),
        json.dumps(result.to_dict(), sort_keys=True),
        json.dumps(verification.to_dict(), sort_keys=True),
        *(json.dumps(event.to_dict(), sort_keys=True) for event in events),
    ]
    private_values = (
        "PRIVATE0001",
        "INDEX ON",
        str(source.resolve()),
        str(output.resolve()),
        str(vault.resolve()),
        str(backend.rebuild_requests[0].staged_table_path),
    )
    assert all(value not in surface for value in private_values for surface in surfaces)
    assert not hasattr(backend.rebuild_requests[0], "definition")
