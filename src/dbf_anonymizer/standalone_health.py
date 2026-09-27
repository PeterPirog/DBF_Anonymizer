"""Executable standalone health test over the accepted service layer."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import dbfbridge
from dbfbridge import DirectRecord, FieldInfo, TableSchema  # type: ignore[attr-defined]

from dbf_anonymizer.api import (
    build_plan,
    create_transfer_bundle,
    preflight,
    pseudonymize,
    recover,
    verify_dataset,
    verify_transfer_bundle,
)
from dbf_anonymizer.errors import ErrorCode, ErrorContext, VerificationError
from dbf_anonymizer.models import VerificationStatus

SELF_TEST_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class SelfTestResult:
    """Bounded, deterministic and privacy-safe standalone self-test verdict."""

    schema_version: ClassVar[str] = SELF_TEST_SCHEMA_VERSION
    model_type: ClassVar[str] = "SelfTestResult"
    preflight_ready: bool
    dataset_verification: str
    recovery_verified: bool
    canonical_match: bool
    bundle_verified: bool
    table_count: int
    record_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "model_type": self.model_type,
            "preflight_ready": self.preflight_ready,
            "dataset_verification": self.dataset_verification,
            "recovery_verified": self.recovery_verified,
            "canonical_match": self.canonical_match,
            "bundle_verified": self.bundle_verified,
            "table_count": self.table_count,
            "record_count": self.record_count,
        }


def _failure(detail_code: str) -> VerificationError:
    return VerificationError(
        ErrorCode.VERIFICATION_FAILED,
        context=ErrorContext(operation="self_test", detail_code=detail_code),
    )


def _schema() -> TableSchema:
    field = FieldInfo(
        ordinal=0,
        name="NAME",
        dbf_type="C",
        length=24,
        decimal_count=0,
        address=0,
        flags=0,
        index_field_flag=0,
        autoincrement_next_value=0,
        autoincrement_step=1,
        is_memo=False,
        is_binary=False,
        supported=True,
        dbversion_byte=0x30,
    )
    return TableSchema(
        path=Path("memory:self-test-synthetic"),
        record_count=0,
        header_length=65,
        record_length=25,
        language_driver=0x03,
        encoding="cp1252",
        has_memo=False,
        has_memo_flag=False,
        has_structural_cdx=False,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
        table_flags=0,
        fields=(field,),
        warnings=(),
        dbversion_byte=0x30,
        dbversion_name="Visual FoxPro",
        last_update="2026-01-01",
        incomplete_transaction=False,
        encryption_flag=False,
        memo_companion_format=None,
        memo_companion_present=False,
        memo_companion_path=None,
        memo_companion_size_bytes=None,
        memo_block_size=None,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


def _logical_table(path: Path) -> tuple[object, tuple[tuple[object, ...], ...]]:
    schema = dbfbridge.read_schema(path)  # type: ignore[attr-defined]
    schema_facts = (
        tuple(
            (
                str(field.name),
                str(field.dbf_type).upper(),
                int(field.length),
                int(field.decimal_count),
                bool(field.is_memo),
            )
            for field in schema.fields
        ),
        str(schema.encoding),
        int(schema.language_driver),
    )
    records = tuple(
        (
            record.physical_index,
            record.deleted,
            tuple(sorted(record.values.items())),
        )
        for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
            path, include_deleted=True, memo="inline"
        )
    )
    return schema_facts, records


def run_self_test() -> SelfTestResult:
    """Run a complete local synthetic service workflow with no network or VFP."""
    with tempfile.TemporaryDirectory(prefix="dbf-anonymizer-self-test-") as raw:
        root = Path(raw)
        source = root / "source"
        source.mkdir()
        source_table = source / "people.dbf"
        dbfbridge.write_table(
            source_table,
            schema=_schema(),
            records=[
                DirectRecord(
                    physical_index=0,
                    deleted=False,
                    values={"NAME": "SYNTHETIC-SELF-TEST"},
                )
            ],
        )

        pseudonymized = root / "pseudonymized"
        vault = root / "protected" / "recovery.sqlite3"
        plan = build_plan(source, pseudonymized, vault)
        check = preflight(plan)
        if not check.ready:
            raise _failure("SELF_TEST_PREFLIGHT_FAILED")
        result = pseudonymize(plan)
        verification = verify_dataset(result, source=source, vault=vault)
        if verification.status is not VerificationStatus.PASS:
            raise _failure("SELF_TEST_VERIFICATION_FAILED")

        recovered_root = root / "recovered"
        recovery = recover(pseudonymized, vault=vault, output=recovered_root)
        if not recovery.canonical_verified:
            raise _failure("SELF_TEST_RECOVERY_FAILED")
        canonical_match = _logical_table(source_table) == _logical_table(
            recovered_root / "people.dbf"
        )
        if not canonical_match:
            raise _failure("SELF_TEST_CANONICAL_MISMATCH")

        bundle_root = root / "bundle"
        bundle = create_transfer_bundle(
            result, destination=bundle_root, profile="DATA_ONLY"
        )
        bundle_check = verify_transfer_bundle(bundle_root)
        if not bundle.verified or not bundle_check.verified:
            raise _failure("SELF_TEST_BUNDLE_FAILED")

        return SelfTestResult(
            preflight_ready=True,
            dataset_verification=verification.status.value,
            recovery_verified=True,
            canonical_match=True,
            bundle_verified=True,
            table_count=result.table_count,
            record_count=result.record_count,
        )
