"""REQ-P7-003 independently controllable recovery-policy evidence."""

from __future__ import annotations

import io
import json
import sqlite3
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import dbfbridge
import pytest

import dbf_anonymizer as public
import dbf_anonymizer.recovery as recovery_module
from dbf_anonymizer import ErrorCode, RecoveryError, RecoveryPolicy
from dbf_anonymizer.capabilities import capabilities
from dbf_anonymizer.cli import main as cli_main
from tests.support.numeric_tables import numeric_field, write_numeric_table


CANARIES = (
    "CHAR_ORIGINAL_Z7Q4Y2P9",
    "VARCHAR_ORIGINAL_R8M3K6W1",
    "MEMO_TEXT_H5N9C2L7",
    "BINARY_MEMO_7f4a9c31d8e2",
    "VAULT_SECRET_B6T1J8Q5",
    "REVERSE_MAPPING_F3P7X2V9",
    "TEMPORAL_OFFSET_MINUS_1739",
    r"C:\Users\private-canary\dataset.dbf",
    "/home/private-canary/dataset.dbf",
    "BACKEND_EXCEPTION_SECRET_K9D4S7A2",
    "credential_sk_live_8H2Q5M9X",
)


def _synthetic_workflow(
    root: Path,
) -> tuple[Path, Path, Path, public.PseudonymizationResult]:
    """Create a real valid recovery vault through the production workflow."""
    source = root / "source"
    pseudonymized = root / "pseudonymized"
    vault = root / "vault" / "VAULT_SECRET_B6T1J8Q5.sqlite"
    write_numeric_table(
        source,
        "people.dbf",
        (numeric_field("ID", "I", 4), numeric_field("SECRET", "C", 96)),
        [{"ID": index, "SECRET": value} for index, value in enumerate(CANARIES, start=1)],
    )
    plan = public.build_plan(
        source=source,
        output=pseudonymized,
        vault=vault,
        policy={
            "text": {
                "default_action": "PSEUDONYMIZE_REVERSIBLE",
                "domain": "GLOBAL_TEXT",
            },
            "numeric": {"default_action": "KEEP"},
        },
    )
    result = public.pseudonymize(plan)
    assert result.table_count == 1
    assert result.record_count == len(CANARIES)
    assert vault.is_file()
    assert pseudonymized.is_dir()
    return source, pseudonymized, vault, result


def _schema_facts(path: Path) -> tuple[object, ...]:
    schema = dbfbridge.read_schema(path)  # type: ignore[attr-defined]
    return (
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


def _logical_records(path: Path) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            record.physical_index,
            record.deleted,
            tuple(sorted(record.values.items())),
        )
        for record in dbfbridge.iter_records(  # type: ignore[attr-defined]
            path, include_deleted=True, memo="inline"
        )
    )


def _assert_canonical_dataset_equal(source: Path, recovered: Path) -> None:
    source_files = tuple(
        path.relative_to(source).as_posix() for path in sorted(source.rglob("*")) if path.is_file()
    )
    recovered_files = tuple(
        path.relative_to(recovered).as_posix()
        for path in sorted(recovered.rglob("*"))
        if path.is_file()
    )
    assert recovered_files == source_files
    for relative in source_files:
        if not relative.lower().endswith(".dbf"):
            continue
        assert _schema_facts(recovered / relative) == _schema_facts(source / relative)
        assert _logical_records(recovered / relative) == _logical_records(source / relative)


def _tree_snapshot(root: Path) -> tuple[tuple[str, bool, int], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            path.is_dir(),
            path.stat().st_size if path.is_file() else 0,
        )
        for path in sorted(root.rglob("*"))
    )


class HostAdapter:
    """Small transport-neutral host adapter with an immutable local policy."""

    def __init__(self, recovery_policy: RecoveryPolicy) -> None:
        self._recovery_policy = recovery_policy

    def capabilities(self) -> public.Capabilities:
        return public.capabilities(self._recovery_policy)

    def pseudonymize(self, plan: public.Plan) -> public.PseudonymizationResult:
        return public.pseudonymize(plan)

    def verify_dataset(
        self,
        result: public.PseudonymizationResult,
        *,
        source: Path,
        vault: Path,
    ) -> public.VerificationResult:
        return public.verify_dataset(result, source=source, vault=vault)

    def recover(self, pseudonymized: Path, *, vault: Path, output: Path) -> public.RecoveryResult:
        return public.recover(
            pseudonymized,
            vault=vault,
            output=output,
            recovery_policy=self._recovery_policy,
        )


def test_enabled_recovery_round_trips_real_synthetic_dataset(tmp_path: Path) -> None:
    source, pseudonymized, vault, _ = _synthetic_workflow(tmp_path)
    recovered = tmp_path / "recovered"

    result = public.recover(
        pseudonymized,
        vault=vault,
        output=recovered,
        recovery_policy=RecoveryPolicy.ENABLED,
    )

    assert result.canonical_verified is True
    assert result.table_count == 1
    assert result.record_count == len(CANARIES)
    _assert_canonical_dataset_equal(source, recovered)


def test_host_adapter_allows_pseudonymization_and_verification_but_denies_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = HostAdapter(RecoveryPolicy.DISABLED)
    caps = host.capabilities()
    assert caps.recovery is False
    assert caps.direct_read is True
    assert caps.direct_write is True

    source = tmp_path / "source"
    pseudonymized = tmp_path / "pseudonymized"
    vault = tmp_path / "vault" / "VAULT_SECRET_B6T1J8Q5.sqlite"
    write_numeric_table(
        source,
        "people.dbf",
        (numeric_field("ID", "I", 4), numeric_field("SECRET", "C", 96)),
        [{"ID": index, "SECRET": value} for index, value in enumerate(CANARIES, start=1)],
    )
    plan = public.build_plan(
        source=source,
        output=pseudonymized,
        vault=vault,
        policy={
            "text": {
                "default_action": "PSEUDONYMIZE_REVERSIBLE",
                "domain": "GLOBAL_TEXT",
            },
            "numeric": {"default_action": "KEEP"},
        },
    )

    pseudonymization = host.pseudonymize(plan)
    assert pseudonymization.table_count == 1
    assert pseudonymization.record_count == len(CANARIES)
    verification = host.verify_dataset(pseudonymization, source=source, vault=vault)
    assert verification.status is public.VerificationStatus.PASS
    assert verification.verified is True

    calls: Counter[str] = Counter()

    def forbidden(name: str) -> Any:
        def fail(*args: object, **kwargs: object) -> Any:
            calls[name] += 1
            raise AssertionError(f"disabled recovery crossed {name}")

        return fail

    verify_vault_type = recovery_module._VerifyVault
    staging_type = recovery_module.DatasetStaging
    for method_name in (
        "completed_operation",
        "dataset_row",
        "table_rows",
        "field_rows",
    ):
        monkeypatch.setattr(
            verify_vault_type,
            method_name,
            forbidden("vault_metadata"),
        )
    monkeypatch.setattr(staging_type, "promote", forbidden("publication"))
    monkeypatch.setattr(recovery_module, "_VerifyVault", forbidden("verify_vault_constructor"))
    monkeypatch.setattr(sqlite3, "connect", forbidden("sqlite_connect"))
    monkeypatch.setattr(recovery_module, "read_source_table", forbidden("recovery_dbf_read"))
    monkeypatch.setattr(
        recovery_module,
        "stream_table_records",
        forbidden("recovery_dbf_fpt_stream"),
    )
    monkeypatch.setattr(recovery_module, "DatasetStaging", forbidden("staging_constructor"))
    monkeypatch.setattr(recovery_module, "DestinationLock", forbidden("destination_lock"))

    recovered = tmp_path / "recovered"
    before = _tree_snapshot(tmp_path)
    with pytest.raises(RecoveryError) as caught:
        host.recover(pseudonymized, vault=vault, output=recovered)

    assert caught.value.code is ErrorCode.RECOVERY_NOT_PERMITTED
    assert caught.value.context.detail_code == "POLICY_DISABLED"
    assert calls == Counter()
    assert _tree_snapshot(tmp_path) == before
    assert not recovered.exists()
    assert not tuple(tmp_path.glob("*.staging"))

    serialized = json.dumps(caught.value.to_dict(), sort_keys=True)
    assert str(vault.resolve()) not in serialized
    for canary in CANARIES:
        assert canary not in serialized


def test_disabled_public_recovery_precedes_path_and_vault_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: Counter[str] = Counter()

    def fail_vault(*args: object, **kwargs: object) -> Any:
        calls["verify_vault"] += 1
        raise AssertionError("vault opened")

    def fail_sqlite(*args: object, **kwargs: object) -> Any:
        calls["sqlite"] += 1
        raise AssertionError("SQLite opened")

    monkeypatch.setattr(recovery_module, "_VerifyVault", fail_vault)
    monkeypatch.setattr(sqlite3, "connect", fail_sqlite)
    output = tmp_path / "recovered"
    with pytest.raises(RecoveryError) as caught:
        public.recover(
            tmp_path / "missing-pseudonymized",
            vault=tmp_path / "missing-private-vault.sqlite",
            output=output,
            recovery_policy=RecoveryPolicy.DISABLED,
        )
    assert caught.value.code is ErrorCode.RECOVERY_NOT_PERMITTED
    assert calls == Counter()
    assert not output.exists()


def test_capability_policy_projection_has_one_canonical_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    capabilities_module = importlib.import_module("dbf_anonymizer.capabilities")
    observed: list[RecoveryPolicy] = []
    expected = public.Capabilities(
        direct_read=True,
        direct_write=True,
        recovery=False,
        transfer_bundle=True,
        vfp_index_backend=False,
        dbfbridge_version="synthetic",
    )

    def canonical_snapshot(policy: RecoveryPolicy) -> public.Capabilities:
        observed.append(policy)
        return expected

    monkeypatch.setattr(capabilities_module, "snapshot", canonical_snapshot)
    assert capabilities_module.capabilities(RecoveryPolicy.DISABLED) is expected
    assert observed == [RecoveryPolicy.DISABLED]


def test_disabled_capability_changes_only_recovery_permission() -> None:
    enabled = capabilities(RecoveryPolicy.ENABLED)
    disabled = capabilities(RecoveryPolicy.DISABLED)
    assert disabled.recovery is False
    assert disabled.direct_read == enabled.direct_read
    assert disabled.direct_write == enabled.direct_write
    assert disabled.transfer_bundle == enabled.transfer_bundle
    assert disabled.vfp_index_backend == enabled.vfp_index_backend
    assert disabled.dbfbridge_version == enabled.dbfbridge_version


def test_cli_passes_explicit_enabled_policy_to_public_recover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[RecoveryPolicy] = []

    def fake_recover(
        pseudonymized: Path,
        *,
        vault: Path,
        output: Path,
        progress: object,
        recovery_policy: RecoveryPolicy,
    ) -> public.RecoveryResult:
        observed.append(recovery_policy)
        raise RuntimeError("delegated")

    monkeypatch.setattr("dbf_anonymizer.cli.recover", fake_recover)
    with pytest.raises(RuntimeError, match="delegated"):
        cli_main(
            [
                "recover",
                "pseudonymized",
                "vault.sqlite",
                "recovered",
                "--recovery-policy",
                "enabled",
            ]
        )
    assert observed == [RecoveryPolicy.ENABLED]


def test_cli_disabled_policy_is_typed_bounded_and_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: Counter[str] = Counter()

    def fail_vault(*args: object, **kwargs: object) -> Any:
        calls["verify_vault"] += 1
        raise AssertionError("vault opened")

    def fail_sqlite(*args: object, **kwargs: object) -> Any:
        calls["sqlite"] += 1
        raise AssertionError("SQLite opened")

    monkeypatch.setattr(recovery_module, "_VerifyVault", fail_vault)
    monkeypatch.setattr(sqlite3, "connect", fail_sqlite)
    vault = tmp_path / "VAULT_SECRET_B6T1J8Q5.sqlite"
    output = tmp_path / "recovered"
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli_main(
            [
                "recover",
                str(tmp_path / "missing-pseudonymized"),
                str(vault),
                str(output),
                "--recovery-policy",
                "disabled",
                "--json",
            ]
        )

    assert code == 1
    payload = json.loads(stdout.getvalue())
    assert payload["code"] == ErrorCode.RECOVERY_NOT_PERMITTED.value
    assert calls == Counter()
    assert not output.exists()
    combined = stdout.getvalue() + stderr.getvalue()
    assert len(combined.encode("utf-8")) < 4096
    assert str(vault.resolve()) not in combined
    for canary in CANARIES:
        assert canary not in combined


def test_cli_rejects_unknown_policy_with_argparse_error() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli_main(
            [
                "recover",
                "pseudonymized",
                "vault.sqlite",
                "recovered",
                "--recovery-policy",
                "unknown",
            ]
        )
    assert code == 2
    assert stdout.getvalue() == ""
    assert "invalid choice" in stderr.getvalue()


def test_invalid_public_policy_type_fails_closed_before_vault_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_constructor_called = False

    def fail_vault(*args: object, **kwargs: object) -> Any:
        nonlocal vault_constructor_called
        vault_constructor_called = True
        raise AssertionError("vault opened")

    monkeypatch.setattr(recovery_module, "_VerifyVault", fail_vault)
    with pytest.raises(TypeError, match="RecoveryPolicy"):
        public.recover(
            "pseudonymized",
            vault="vault.sqlite",
            output="recovered",
            recovery_policy="disabled",  # type: ignore[arg-type]
        )
    assert vault_constructor_called is False


def test_policy_enum_has_only_enabled_and_disabled() -> None:
    assert tuple(RecoveryPolicy) == (
        RecoveryPolicy.ENABLED,
        RecoveryPolicy.DISABLED,
    )
    assert RecoveryPolicy.from_cli("enabled") is RecoveryPolicy.ENABLED
    assert RecoveryPolicy.from_cli("disabled") is RecoveryPolicy.DISABLED
    with pytest.raises(ValueError, match="recovery-policy must be one of"):
        RecoveryPolicy.from_cli("unknown")
