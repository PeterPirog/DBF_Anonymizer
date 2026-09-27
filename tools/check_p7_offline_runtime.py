"""Installed-wheel REQ-P7-004 standalone and network-free runtime contract."""

from __future__ import annotations

import argparse
import http.client
import io
import json
import os
import re
import socket
import subprocess
import sys
import urllib.request
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import dbf_anonymizer as public
import dbfbridge
from dbf_anonymizer.cli import main as cli_main


def _blocked(kind: str, attempts: list[str]):
    def fail(*args: object, **kwargs: object) -> object:
        del args, kwargs
        attempts.append(kind)
        raise AssertionError(f"REQ-P7-004 blocked runtime boundary: {kind}")

    return fail


def _runtime_sentinels(attempts: list[str]) -> ExitStack:
    stack = ExitStack()
    network_targets = (
        (socket.socket, "connect"),
        (socket.socket, "connect_ex"),
        (socket, "create_connection"),
        (urllib.request, "urlopen"),
        (http.client.HTTPConnection, "connect"),
        (http.client.HTTPSConnection, "connect"),
    )
    for owner, attribute in network_targets:
        stack.enter_context(
            patch.object(owner, attribute, _blocked(f"network:{attribute}", attempts))
        )
    for attribute in ("Popen", "run", "call", "check_call", "check_output"):
        stack.enter_context(
            patch.object(
                subprocess,
                attribute,
                _blocked(f"process:subprocess.{attribute}", attempts),
            )
        )
    stack.enter_context(patch.object(os, "system", _blocked("process:os.system", attempts)))
    stack.enter_context(patch.object(os, "popen", _blocked("process:os.popen", attempts)))
    return stack


def _synthetic_schema() -> dbfbridge.TableSchema:
    field = dbfbridge.FieldInfo(
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
    return dbfbridge.TableSchema(
        path=Path("memory:p7-offline-synthetic"),
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


def _assert_cli(arguments: list[str], expected_code: int) -> tuple[str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli_main(arguments)
    if code != expected_code:
        raise AssertionError(
            f"CLI {arguments!r} returned {code}, expected {expected_code}: {stderr.getvalue()}"
        )
    return stdout.getvalue(), stderr.getvalue()


def _assert_installed_origin(repository_root: Path | None) -> Path:
    origin = Path(public.__file__).resolve()
    environment = Path(sys.prefix).resolve()
    if not origin.is_relative_to(environment):
        raise AssertionError(f"package import is outside the clean venv: {origin}")
    if not {"site-packages", "dist-packages"} & {part.lower() for part in origin.parts}:
        raise AssertionError(f"package import is not from site-packages: {origin}")
    if repository_root is not None:
        checkout = repository_root.resolve()
        if origin.is_relative_to(checkout):
            raise AssertionError(f"package imported from repository checkout: {origin}")
        checkout_entries = []
        for entry in sys.path:
            candidate = Path(entry or Path.cwd()).resolve()
            if candidate == checkout or candidate.is_relative_to(checkout):
                checkout_entries.append(str(candidate))
        if checkout_entries:
            raise AssertionError(
                f"repository checkout remains importable at runtime: {checkout_entries}"
            )
    return origin


def _write_synthetic_source(source: Path) -> None:
    source.mkdir(parents=True)
    dbfbridge.write_table(
        source / "people.dbf",
        schema=_synthetic_schema(),
        records=[
            dbfbridge.DirectRecord(
                physical_index=0,
                deleted=False,
                values={"NAME": "SYNTHETIC-OFFLINE"},
            )
        ],
    )


def _json_cli(arguments: list[str], expected_code: int = 0) -> dict[str, object]:
    stdout, stderr = _assert_cli(arguments, expected_code)
    if stderr:
        raise AssertionError(f"JSON CLI wrote diagnostics to stderr: {arguments!r}")
    payload = json.loads(stdout)
    if not isinstance(payload, dict):
        raise AssertionError(f"JSON CLI returned a non-object: {arguments!r}")
    return payload


def run_contract(
    work_root: Path,
    *,
    require_installed: bool,
    repository_root: Path | None = None,
) -> dict[str, object]:
    if work_root.exists():
        raise AssertionError(f"runtime work root already exists: {work_root}")
    work_root.mkdir(parents=True)
    origin = (
        _assert_installed_origin(repository_root)
        if require_installed
        else Path(public.__file__).resolve()
    )

    attempts: list[str] = []
    with _runtime_sentinels(attempts):
        caps = public.capabilities()
        if not caps.direct_read or not caps.direct_write or not caps.recovery:
            raise AssertionError(f"standalone capabilities unavailable: {caps}")

        api_root = work_root / "api"
        source = api_root / "source"
        _write_synthetic_source(source)
        output = api_root / "pseudonymized"
        vault = api_root / "protected" / "recovery.sqlite3"
        plan = public.build_plan(source, output, vault)
        if not public.preflight(plan).ready:
            raise AssertionError("offline standalone preflight is not ready")
        result = public.pseudonymize(plan)
        verification = public.verify_dataset(result, source=source, vault=vault)
        if verification.status is not public.VerificationStatus.PASS:
            raise AssertionError(f"offline dataset verification failed: {verification}")

        bundle_path = api_root / "bundle"
        bundle = public.create_transfer_bundle(result, destination=bundle_path, profile="DATA_ONLY")
        standalone = public.verify_transfer_bundle(bundle_path)
        if not bundle.verified or not standalone.verified:
            raise AssertionError("offline DATA_ONLY bundle verification failed")

        disabled_output = api_root / "disabled-recovery"
        try:
            public.recover(
                output,
                vault=vault,
                output=disabled_output,
                recovery_policy=public.RecoveryPolicy.DISABLED,
            )
        except public.RecoveryError as error:
            if error.code is not public.ErrorCode.RECOVERY_NOT_PERMITTED:
                raise
        else:
            raise AssertionError("disabled recovery unexpectedly succeeded")
        if disabled_output.exists():
            raise AssertionError("disabled recovery created output")

        recovered_path = api_root / "recovered"
        recovered = public.recover(
            output,
            vault=vault,
            output=recovered_path,
            recovery_policy=public.RecoveryPolicy.ENABLED,
        )
        if not recovered.canonical_verified:
            raise AssertionError("enabled recovery was not canonically verified")

        help_stdout, help_stderr = _assert_cli(["--help"], 0)
        version_stdout, _ = _assert_cli(["--version"], 0)
        if "dbf-anonymizer" not in help_stdout or public.__version__ not in version_stdout:
            raise AssertionError("installed CLI help/version contract failed")
        if help_stderr:
            raise AssertionError("CLI help unexpectedly wrote to stderr")
        target_commands = {
            "capabilities",
            "plan",
            "preflight",
            "pseudonymize",
            "verify",
            "recover",
            "export-bundle",
            "verify-bundle",
            "self-test",
        }
        command_listing = re.search(r"\{([^}]+)\}", help_stdout)
        if command_listing is None or set(command_listing.group(1).split(",")) != target_commands:
            raise AssertionError("installed CLI help command set is not exact")

        cli_root = work_root / "cli"
        cli_source = cli_root / "source"
        _write_synthetic_source(cli_source)
        cli_output = cli_root / "pseudonymized"
        cli_vault = cli_root / "protected" / "recovery.sqlite3"
        common = [str(cli_source), str(cli_output), str(cli_vault)]

        capabilities_payload = _json_cli(["capabilities", "--json"])
        if capabilities_payload.get("model_type") != "Capabilities":
            raise AssertionError("CLI capabilities did not return Capabilities")

        plan_payload = _json_cli(["plan", *common, "--json"])
        if plan_payload.get("model_type") != "Plan":
            raise AssertionError("CLI plan did not return Plan")
        if cli_output.exists() or cli_vault.exists():
            raise AssertionError("CLI plan created output or vault")

        preflight_payload = _json_cli(["preflight", *common, "--json"])
        if preflight_payload.get("ready") is not True:
            raise AssertionError("CLI preflight was not ready")
        if cli_output.exists() or cli_vault.exists():
            raise AssertionError("CLI preflight created output or vault")

        pseudonymize_payload = _json_cli(["pseudonymize", *common, "--json"])
        if pseudonymize_payload.get("model_type") != "PseudonymizationResult":
            raise AssertionError("CLI pseudonymize did not return its public result")

        human_stdout, human_stderr = _assert_cli(["pseudonymize", *common], 0)
        if human_stdout or not human_stderr:
            raise AssertionError("human CLI did not keep progress exclusively on stderr")

        verification_payload = _json_cli(["verify", *common, "--json"])
        if verification_payload.get("status") != "PASS":
            raise AssertionError("CLI dataset verification failed")

        cli_recovered = cli_root / "recovered"
        recovery_payload = _json_cli(
            [
                "recover",
                str(cli_output),
                str(cli_vault),
                str(cli_recovered),
                "--recovery-policy",
                "enabled",
                "--json",
            ]
        )
        if recovery_payload.get("canonical_verified") is not True:
            raise AssertionError("CLI recovery was not canonically verified")

        cli_bundle = cli_root / "bundle"
        bundle_payload = _json_cli(
            [
                "export-bundle",
                *common,
                str(cli_bundle),
                "--json",
            ]
        )
        if bundle_payload.get("verified") is not True:
            raise AssertionError("CLI bundle creation was not verified")
        bundle_verification_payload = _json_cli(["verify-bundle", str(cli_bundle), "--json"])
        if bundle_verification_payload.get("verified") is not True:
            raise AssertionError("CLI standalone bundle verification failed")

        self_test_payload = _json_cli(["self-test", "--json"])
        if (
            not all(
                self_test_payload.get(field) is True
                for field in (
                    "preflight_ready",
                    "recovery_verified",
                    "canonical_match",
                    "bundle_verified",
                )
            )
            or self_test_payload.get("dataset_verification") != "PASS"
        ):
            raise AssertionError("CLI self-test did not execute the complete workflow")

        disabled_stdout, disabled_stderr = _assert_cli(
            [
                "recover",
                str(cli_output),
                str(cli_vault),
                str(cli_root / "disabled-recovery"),
                "--recovery-policy",
                "disabled",
                "--json",
            ],
            1,
        )
        disabled_payload = json.loads(disabled_stdout)
        if disabled_payload["code"] != public.ErrorCode.RECOVERY_NOT_PERMITTED.value:
            raise AssertionError("CLI disabled recovery policy was not enforced")
        if str(cli_vault) in disabled_stdout + disabled_stderr:
            raise AssertionError("CLI disclosed the protected vault path")

    if attempts:
        raise AssertionError(f"runtime attempted forbidden boundaries: {attempts}")

    original_rows = tuple(dbfbridge.iter_records(source / "people.dbf", include_deleted=True))
    recovered_rows = tuple(
        dbfbridge.iter_records(recovered_path / "people.dbf", include_deleted=True)
    )
    if original_rows != recovered_rows:
        raise AssertionError("offline recovery did not reproduce the synthetic dataset")
    cli_original_rows = tuple(
        dbfbridge.iter_records(cli_source / "people.dbf", include_deleted=True)
    )
    cli_recovered_rows = tuple(
        dbfbridge.iter_records(cli_recovered / "people.dbf", include_deleted=True)
    )
    if cli_original_rows != cli_recovered_rows:
        raise AssertionError("CLI recovery did not reproduce the synthetic dataset")

    return {
        "package_origin": str(origin),
        "package_version": public.__version__,
        "dbfbridge_version": dbfbridge.__version__,
        "network_attempts": 0,
        "process_attempts": 0,
        "preflight_ready": True,
        "dataset_verification": verification.status.value,
        "bundle_verified": standalone.verified,
        "enabled_recovery_verified": recovered.canonical_verified,
        "disabled_recovery_code": public.ErrorCode.RECOVERY_NOT_PERMITTED.value,
        "cli_help": "PASS",
        "cli_version": "PASS",
        "cli_recovery_policy": "PASS",
        "cli_commands": sorted(target_commands),
        "cli_complete_workflow": "PASS",
        "cli_machine_stdout": "PASS",
        "cli_machine_stderr": "EMPTY",
        "cli_human_stdout": "EMPTY",
        "cli_human_stderr": "PROGRESS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--repository-root", type=Path)
    args = parser.parse_args()
    evidence = run_contract(
        args.work_root,
        require_installed=True,
        repository_root=args.repository_root,
    )
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
