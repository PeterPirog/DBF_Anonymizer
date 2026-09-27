"""REQ-P7-005 privacy-safe diagnostics and public-report evidence."""

from __future__ import annotations

import ast
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

import dbfbridge
import pytest

import dbf_anonymizer as public
from dbf_anonymizer.cli import main as cli_main
from dbf_anonymizer.index_backend import IndexBackend, validate_backend_capabilities
from dbf_anonymizer.standalone_health import run_self_test
from tests.support.numeric_tables import numeric_field, schema


ORIGINAL_TEXT = "P7_ORIGINAL_TEXT_CANARY_7C91A6F2"
VARCHAR_TEXT = "P7_VARCHAR_TEXT_CANARY_2B6F4E8D"
MEMO_PAYLOAD = "P7_MEMO_PAYLOAD_CANARY_4E28B9D1"
MEMO_BINARY_MARKER = b"P7-MEMO-BINARY-MARKER-CANARY-3F81A2C4"
REVERSE_MAPPING = "P7_REVERSE_MAPPING_CANARY_0A63D8F5"
TEMPORAL_OFFSET = "P7_PRIVATE_TEMPORAL_OFFSET_CANARY_92C4E7B1"
VAULT_ROW = "P7_VAULT_ROW_CANARY_5D17A3C8"
RECOVERY_SECRET = "P7_RECOVERY_SECRET_CANARY_8B40F2E6"
POLICY_SECRET = "P7_POLICY_SECRET_CANARY_1F95C7A3"
BACKEND_EXCEPTION = "P7_BACKEND_EXCEPTION_SECRET_6A31D9E4"
DBFBRIDGE_EXCEPTION = "P7_DBFBRIDGE_EXCEPTION_SECRET_3C86A1F9"
CALLBACK_EXCEPTION = "P7_CALLBACK_EXCEPTION_SECRET_9D52B7A8"
TOKEN = "P7_TOKEN_CANARY_7E24B5D0"
WINDOWS_PRIVATE_PATH = r"C:\P7_PRIVATE_PATH_CANARY\source\secret.dbf"
POSIX_PRIVATE_PATH = "/p7-private-path-canary/source/secret.dbf"

CANARIES = (
    ORIGINAL_TEXT,
    VARCHAR_TEXT,
    MEMO_PAYLOAD,
    REVERSE_MAPPING,
    TEMPORAL_OFFSET,
    VAULT_ROW,
    RECOVERY_SECRET,
    POLICY_SECRET,
    BACKEND_EXCEPTION,
    DBFBRIDGE_EXCEPTION,
    CALLBACK_EXCEPTION,
    TOKEN,
    WINDOWS_PRIVATE_PATH,
    POSIX_PRIVATE_PATH,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "src" / "dbf_anonymizer"


def _serialized(value: object) -> str:
    if isinstance(value, public.AnonymizerError):
        payload = value.to_dict()
    else:
        payload = value.to_dict()  # type: ignore[union-attr]
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _assert_private_data_absent(*texts: str) -> None:
    combined = "\n".join(texts)
    for canary in CANARIES:
        assert canary not in combined
    assert MEMO_BINARY_MARKER.decode("ascii") not in combined


def _assert_error_safe(error: public.AnonymizerError) -> None:
    payload = error.to_dict()
    serialized = json.dumps(payload, sort_keys=True)
    _assert_private_data_absent(str(error), repr(error), serialized)
    assert payload["code"] == error.code.value
    assert payload["category"] == error.category.value
    assert error.context.operation is not None
    assert len(serialized.encode("utf-8")) < 4096


def _write_canary_source(source: Path) -> None:
    fields = (
        numeric_field("ID", "I", 4),
        numeric_field("SECRET", "C", 180),
        numeric_field("VAR", "V", 64),
        numeric_field("NOTE", "M", 4),
        numeric_field("GEN", "G", 4),
        numeric_field("WHEN_D", "D", 8),
    )
    source.mkdir(parents=True)
    dbfbridge.write_table(  # type: ignore[attr-defined]
        source / "people.dbf",
        schema=schema(fields),
        records=[
            dbfbridge.DirectRecord(  # type: ignore[attr-defined]
                physical_index=0,
                deleted=index % 3 == 0,
                values={
                    "ID": index,
                    "SECRET": canary,
                    "VAR": VARCHAR_TEXT,
                    "NOTE": MEMO_PAYLOAD if index == 1 else f"SYNTHETIC-MEMO-{index}",
                    "GEN": MEMO_BINARY_MARKER,
                    "WHEN_D": date(2026, 1, min(index, 28)),
                },
            )
            for index, canary in enumerate(CANARIES, start=1)
        ],
    )


def _workflow(
    root: Path,
) -> tuple[
    Path,
    Path,
    Path,
    public.Plan,
    public.PseudonymizationResult,
    list[public.ProgressEvent],
]:
    source = root / "source"
    output = root / "pseudonymized"
    vault = root / "protected" / f"{VAULT_ROW}.sqlite3"
    _write_canary_source(source)
    events: list[public.ProgressEvent] = []
    plan = public.build_plan(source, output, vault, progress=events.append)
    check = public.preflight(plan, progress=events.append)
    assert check.ready is True
    result = public.pseudonymize(plan, progress=events.append)
    return source, output, vault, plan, result, events


def _capture_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli_main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


def test_real_success_workflow_reports_and_progress_are_value_free(
    tmp_path: Path,
) -> None:
    source, output, vault, plan, result, events = _workflow(tmp_path)
    check = public.preflight(plan, progress=events.append)
    verification = public.verify_dataset(
        result, source=source, vault=vault, progress=events.append
    )
    assert verification.status is public.VerificationStatus.PASS

    bundle_path = tmp_path / "bundle"
    bundle = public.create_transfer_bundle(
        result, destination=bundle_path, progress=events.append
    )
    standalone = public.verify_transfer_bundle(bundle_path, progress=events.append)
    recovered = public.recover(
        output,
        vault=vault,
        output=tmp_path / "recovered",
        progress=events.append,
    )
    self_test = run_self_test()
    reports = (
        public.capabilities(),
        plan,
        check,
        result,
        verification,
        recovered,
        bundle,
        standalone,
        self_test,
        *events,
    )
    serialized = "\n".join(_serialized(report) for report in reports)
    manifest = (bundle_path / "transfer-manifest.json").read_text(encoding="ascii")

    _assert_private_data_absent(serialized, manifest)
    assert str(tmp_path.resolve()) not in serialized
    assert str(tmp_path.resolve()) not in manifest
    assert events
    assert all(
        event.table_path is None
        or (
            "\\" not in event.table_path
            and not event.table_path.startswith("/")
            and ".." not in Path(event.table_path).parts
        )
        for event in events
    )
    assert all(len(_serialized(event).encode("ascii")) < 2048 for event in events)
    assert recovered.canonical_verified is True
    assert bundle.verified is True and standalone.verified is True


def test_all_typed_error_families_keep_causes_private_and_codes_useful() -> None:
    cases: tuple[
        tuple[type[public.AnonymizerError], public.ErrorCode], ...
    ] = (
        (public.PathError, public.ErrorCode.PATH_INVALID),
        (public.PolicyError, public.ErrorCode.POLICY_INVALID),
        (public.DBFBridgeError, public.ErrorCode.DBFBRIDGE_FAILURE),
        (public.VaultError, public.ErrorCode.VAULT_CORRUPT),
        (public.MappingError, public.ErrorCode.MAPPING_CONFLICT),
        (public.RelationshipError, public.ErrorCode.RELATIONSHIP_INVALID),
        (public.PublicationError, public.ErrorCode.PUBLICATION_FAILED),
        (public.VerificationError, public.ErrorCode.VERIFICATION_FAILED),
        (public.RecoveryError, public.ErrorCode.RECOVERY_FAILED),
        (public.TransferError, public.ErrorCode.TRANSFER_FAILED),
        (public.IndexBackendError, public.ErrorCode.INDEX_BACKEND_FAILED),
        (public.CancellationError, public.ErrorCode.OPERATION_CANCELLED),
        (public.CallbackError, public.ErrorCode.PROGRESS_CALLBACK_FAILED),
    )
    for error_type, code in cases:
        try:
            raise error_type(
                code,
                context=public.ErrorContext(
                    operation="privacy_test",
                    table_path="tables/people.dbf",
                    detail_code="SYNTHETIC_FAILURE",
                ),
            ) from RuntimeError("|".join(CANARIES))
        except public.AnonymizerError as error:
            _assert_error_safe(error)
            assert error.context.table_path == "tables/people.dbf"
            assert error.context.detail_code == "SYNTHETIC_FAILURE"


def test_path_policy_relationship_preflight_and_pseudonymize_failures_are_safe(
    tmp_path: Path,
) -> None:
    missing = tmp_path / ORIGINAL_TEXT
    with pytest.raises(public.PathError) as missing_error:
        public.build_plan(missing, tmp_path / "out", tmp_path / VAULT_ROW)
    _assert_error_safe(missing_error.value)

    source = tmp_path / "source"
    _write_canary_source(source)
    with pytest.raises(public.PolicyError) as policy_error:
        public.build_plan(
            source,
            tmp_path / "policy-out",
            tmp_path / "policy-vault.sqlite3",
            policy={"schema_version": 1, POLICY_SECRET: TOKEN},
        )
    _assert_error_safe(policy_error.value)

    with pytest.raises(public.AnonymizerError) as relationship_error:
        public.build_plan(
            source,
            tmp_path / "relationship-out",
            tmp_path / "relationship-vault.sqlite3",
            relationship_document={
                "schema_version": "1.0",
                "groups": REVERSE_MAPPING,
            },
        )
    _assert_error_safe(relationship_error.value)

    output = tmp_path / "refused-output"
    plan = public.build_plan(source, output, tmp_path / "refused-vault.sqlite3")
    output.mkdir()
    (output / TOKEN).write_text(POLICY_SECRET, encoding="ascii")
    check = public.preflight(plan)
    assert check.ready is False
    assert "DESTINATION_CONFLICT" in check.error_codes
    _assert_private_data_absent(_serialized(check))
    failure_events: list[public.ProgressEvent] = []
    with pytest.raises(public.PublicationError) as publication_error:
        public.pseudonymize(plan, progress=failure_events.append)
    _assert_error_safe(publication_error.value)
    assert failure_events
    _assert_private_data_absent(*map(_serialized, failure_events))


def test_callback_cancellation_and_dbfbridge_failures_are_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    _write_canary_source(source)

    def hostile_progress(_event: public.ProgressEvent) -> None:
        raise RuntimeError("|".join(CANARIES))

    with pytest.raises(public.CallbackError) as callback_error:
        public.build_plan(
            source,
            tmp_path / "callback-out",
            tmp_path / "callback-vault.sqlite3",
            progress=hostile_progress,
        )
    _assert_error_safe(callback_error.value)
    assert callback_error.value.code is public.ErrorCode.PROGRESS_CALLBACK_FAILED

    with pytest.raises(public.CancellationError) as cancellation_error:
        public.build_plan(
            source,
            tmp_path / "cancel-out",
            tmp_path / "cancel-vault.sqlite3",
            cancel_check=lambda: True,
        )
    _assert_error_safe(cancellation_error.value)
    assert cancellation_error.value.code is public.ErrorCode.OPERATION_CANCELLED

    def hostile_cancel_check() -> bool:
        raise RuntimeError(f"{CALLBACK_EXCEPTION}|{REVERSE_MAPPING}")

    with pytest.raises(public.CallbackError) as cancel_callback_error:
        public.build_plan(
            source,
            tmp_path / "cancel-callback-out",
            tmp_path / "cancel-callback-vault.sqlite3",
            cancel_check=hostile_cancel_check,
        )
    _assert_error_safe(cancel_callback_error.value)
    assert cancel_callback_error.value.code is public.ErrorCode.CANCEL_CALLBACK_FAILED

    class HostileDBFBridgeFailure(RuntimeError):
        code = "SYNTHETIC_DBF_FAILURE"

    def fail_schema(_path: Path) -> object:
        raise HostileDBFBridgeFailure(
            f"{DBFBRIDGE_EXCEPTION}|{ORIGINAL_TEXT}|{WINDOWS_PRIVATE_PATH}"
        )

    monkeypatch.setattr(dbfbridge, "read_schema", fail_schema)
    with pytest.raises(public.DBFBridgeError) as dependency_error:
        public.build_plan(
            source,
            tmp_path / "dependency-out",
            tmp_path / "dependency-vault.sqlite3",
        )
    _assert_error_safe(dependency_error.value)
    assert dependency_error.value.dependency_code == "SYNTHETIC_DBF_FAILURE"
    assert dependency_error.value.context.table_path == "people.dbf"


class _HostileBackend:
    def capabilities(self) -> public.IndexBackendCapability:
        raise RuntimeError(
            f"{BACKEND_EXCEPTION}|{TOKEN}|{WINDOWS_PRIVATE_PATH}"
        )

    def rebuild_index(self, request: object) -> object:
        del request
        raise AssertionError("not reached")

    def verify_index(self, request: object) -> object:
        del request
        raise AssertionError("not reached")


def test_injected_index_backend_exception_is_redacted_on_real_service_path(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _write_canary_source(source)
    plan = public.build_plan(
        source, tmp_path / "output", tmp_path / "vault.sqlite3"
    )
    backend = _HostileBackend()
    assert isinstance(backend, IndexBackend)
    with pytest.raises(public.IndexBackendError) as backend_error:
        public.pseudonymize(plan, index_backend=backend)
    _assert_error_safe(backend_error.value)
    assert backend_error.value.context.detail_code == (
        "INDEX_BACKEND_CAPABILITIES_FAILED"
    )
    with pytest.raises(public.IndexBackendError):
        validate_backend_capabilities(backend)


def test_verification_recovery_transfer_and_corrupt_vault_failures_are_safe(
    tmp_path: Path,
) -> None:
    source, output, vault, _plan, result, events = _workflow(tmp_path / "valid")
    table = output / "people.dbf"
    table.write_bytes(table.read_bytes() + b"P7-SYNTHETIC-TAMPER")
    verification = public.verify_dataset(
        result, source=source, vault=vault, progress=events.append
    )
    assert verification.status is public.VerificationStatus.FAIL
    assert "OUTPUT_FINGERPRINT_MISMATCH" in verification.check_codes
    _assert_private_data_absent(_serialized(verification), *map(_serialized, events))

    with pytest.raises(public.PathError) as transfer_error:
        destination = tmp_path / RECOVERY_SECRET
        destination.mkdir()
        public.create_transfer_bundle(result, destination=destination)
    _assert_error_safe(transfer_error.value)

    invalid_bundle = tmp_path / "invalid-bundle"
    invalid_bundle.mkdir()
    (invalid_bundle / ORIGINAL_TEXT).write_text(MEMO_PAYLOAD, encoding="ascii")
    bundle_events: list[public.ProgressEvent] = []
    with pytest.raises(public.TransferError) as bundle_error:
        public.verify_transfer_bundle(invalid_bundle, progress=bundle_events.append)
    _assert_error_safe(bundle_error.value)
    assert bundle_events
    _assert_private_data_absent(*map(_serialized, bundle_events))

    corrupt_vault = tmp_path / "corrupt-vault" / f"{VAULT_ROW}.sqlite3"
    corrupt_vault.parent.mkdir()
    corrupt_vault.write_text(
        f"{VAULT_ROW}|{RECOVERY_SECRET}|{REVERSE_MAPPING}", encoding="ascii"
    )
    recovery_events: list[public.ProgressEvent] = []
    with pytest.raises(public.RecoveryError) as recovery_error:
        public.recover(
            output,
            vault=corrupt_vault,
            output=tmp_path / "recovery-output",
            progress=recovery_events.append,
        )
    _assert_error_safe(recovery_error.value)
    assert recovery_events
    _assert_private_data_absent(*map(_serialized, recovery_events))
    verification_events: list[public.ProgressEvent] = []
    with pytest.raises(public.VerificationError) as vault_error:
        public.verify_dataset(
            result,
            source=source,
            vault=corrupt_vault,
            progress=verification_events.append,
        )
    _assert_error_safe(vault_error.value)
    assert verification_events
    _assert_private_data_absent(*map(_serialized, verification_events))


def test_recovery_disabled_refuses_before_vault_access_without_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dbf_anonymizer.recovery as recovery_module

    def vault_must_not_open(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("vault was accessed")

    monkeypatch.setattr(recovery_module, "_VerifyVault", vault_must_not_open)
    with pytest.raises(public.RecoveryError) as caught:
        public.recover(
            tmp_path / ORIGINAL_TEXT,
            vault=tmp_path / f"{VAULT_ROW}-{RECOVERY_SECRET}.sqlite3",
            output=tmp_path / REVERSE_MAPPING,
            recovery_policy=public.RecoveryPolicy.DISABLED,
        )
    _assert_error_safe(caught.value)
    assert caught.value.code is public.ErrorCode.RECOVERY_NOT_PERMITTED
    assert caught.value.context.detail_code == "POLICY_DISABLED"


@pytest.mark.parametrize("json_mode", (True, False))
def test_cli_success_and_failure_channels_are_private(
    tmp_path: Path, json_mode: bool
) -> None:
    root = tmp_path / ("json" if json_mode else "human")
    source = root / "source"
    output = root / "pseudonymized"
    vault = root / "protected" / f"{VAULT_ROW}.sqlite3"
    recovered = root / "recovered"
    bundle = root / "bundle"
    _write_canary_source(source)
    suffix = ["--json"] if json_mode else []
    commands = (
        ["capabilities", *suffix],
        ["plan", str(source), str(output), str(vault), *suffix],
        ["preflight", str(source), str(output), str(vault), *suffix],
        ["pseudonymize", str(source), str(output), str(vault), *suffix],
        ["verify", str(source), str(output), str(vault), *suffix],
        [
            "export-bundle",
            str(source),
            str(output),
            str(vault),
            str(bundle),
            *suffix,
        ],
        ["verify-bundle", str(bundle), *suffix],
        ["recover", str(output), str(vault), str(recovered), *suffix],
        ["self-test", *suffix],
    )
    outputs: list[str] = []
    for command in commands:
        code, stdout, stderr = _capture_cli(command)
        assert code == 0
        outputs.extend((stdout, stderr))
        if json_mode:
            assert stderr == ""
            assert isinstance(json.loads(stdout), dict)
        else:
            assert stdout == ""
            assert stderr

    missing = root / ORIGINAL_TEXT
    code, stdout, stderr = _capture_cli(
        ["plan", str(missing), str(root / "failed"), str(vault), *suffix]
    )
    assert code == 1
    outputs.extend((stdout, stderr))
    if json_mode:
        assert stderr == ""
        assert json.loads(stdout)["code"] == "PATH_NOT_FOUND"
    else:
        assert stdout == ""
        assert "PATH_NOT_FOUND" in stderr

    _assert_private_data_absent(*outputs)
    combined = "".join(outputs)
    assert str(root.resolve()) not in combined


def _call_name(node: ast.expr) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    return ".".join((current.id, *reversed(parts)))


def _exception_names(handler: ast.ExceptHandler) -> set[str]:
    return {handler.name} if handler.name is not None else set()


def test_production_has_no_diagnostic_value_dump_or_raw_exception_text_sink() -> None:
    violations: list[str] = []
    diagnostic_sinks = {
        "print",
        "pprint",
        "warnings.warn",
        "traceback.print_exc",
        "traceback.print_exception",
        "traceback.format_exc",
        "logger.debug",
        "logger.info",
        "logger.warning",
        "logger.error",
        "logger.exception",
        "logging.debug",
        "logging.info",
        "logging.warning",
        "logging.error",
        "logging.exception",
    }
    sensitive_fragments = {
        ".values",
        "original_value",
        "original_payload",
        "memo_payload",
        "reverse_mapping",
        "temporal_offset",
        "offset_days",
        "vault_row",
        "exc.args",
        "error.args",
        "repr(",
        "vars(",
    }
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imported = (
                    {alias.name.split(".")[0] for alias in node.names}
                    if isinstance(node, ast.Import)
                    else {(node.module or "").split(".")[0]}
                )
                if imported & {"logging", "pprint", "traceback"}:
                    violations.append(
                        f"{relative}:{node.lineno}:diagnostic dump module import"
                    )
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if name not in diagnostic_sinks:
                continue
            segment = ast.get_source_segment(source, node) or ""
            if relative != "cli.py" and name == "print":
                violations.append(f"{relative}:{node.lineno}:print outside CLI")
            lowered = segment.casefold()
            for fragment in sensitive_fragments:
                if fragment.casefold() in lowered:
                    violations.append(
                        f"{relative}:{node.lineno}:diagnostic value dump {fragment}"
                    )

        for handler in (
            item for item in ast.walk(tree) if isinstance(item, ast.ExceptHandler)
        ):
            names = _exception_names(handler)
            if not names:
                continue
            for child in ast.walk(handler):
                if isinstance(child, ast.Call) and _call_name(child.func) in diagnostic_sinks:
                    if any(
                        isinstance(argument, ast.Name) and argument.id in names
                        for argument in child.args
                    ):
                        violations.append(
                            f"{relative}:{child.lineno}:raw exception diagnostic sink"
                        )
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                    if child.func.id not in {"str", "repr"} or not child.args:
                        continue
                    argument = child.args[0]
                    if isinstance(argument, ast.Name) and argument.id in names:
                        violations.append(
                            f"{relative}:{child.lineno}:raw exception text"
                        )
                if (
                    isinstance(child, ast.Attribute)
                    and child.attr == "args"
                    and isinstance(child.value, ast.Name)
                    and child.value.id in names
                ):
                    violations.append(
                        f"{relative}:{child.lineno}:raw exception args"
                    )
    assert violations == []


def test_public_path_boundaries_reject_private_absolute_paths() -> None:
    factories: Iterable[Callable[[str], object]] = (
        lambda path: public.ErrorContext(table_path=path),
        lambda path: public.ErrorContext(artifact_path=path),
        lambda path: public.ProgressEvent(
            "op-" + ("a" * 32), "SCAN", "PROGRESS", 1, table_path=path
        ),
    )
    for private_path in (WINDOWS_PRIVATE_PATH, POSIX_PRIVATE_PATH):
        for factory in factories:
            with pytest.raises(ValueError):
                factory(private_path)
