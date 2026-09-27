"""REQ-P7-005 privacy-safe diagnostics and public-report evidence.

The canary labels below are HOSTILE CONTENT canaries: they are injected into
records, paths, policies and synthetic dependency/callback exceptions and
must never reach an outward surface.  The SEPARATE semantic evidence tests
extract the REAL private vault material (actual ``text_mappings`` original/
pseudonym pairs, actual ``memo_recovery.original_payload`` images, the actual
persisted ``temporal_parameters.offset_days``) from the synthetic vault of a
real public workflow — read-only — and prove THAT material stays out of every
diagnostic channel on success and on a real valid-vault corruption failure.
"""

from __future__ import annotations

import ast
import io
import json
import sqlite3
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable

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


def _drive_cli_channels(root: Path) -> tuple[list[str], tuple[Path, ...]]:
    """Run all nine accepted CLI commands in BOTH modes (separate roots per
    mode); collect stdout+stderr and the resulting vault paths."""
    outputs: list[str] = []
    vaults: list[Path] = []
    for json_mode in (True, False):
        run_root = root / ("json" if json_mode else "human")
        source = run_root / "source"
        output = run_root / "pseudonymized"
        vault = run_root / "protected" / f"{VAULT_ROW}.sqlite3"
        recovered = run_root / "recovered"
        bundle = run_root / "bundle"
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
        for command in commands:
            code, stdout, stderr = _capture_cli(command)
            assert code == 0
            outputs.extend((stdout, stderr))
        vaults.append(vault)
    return outputs, tuple(vaults)


def _capture_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli_main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


@dataclass(frozen=True)
class _VaultMaterial:
    """The REAL private material extracted from one synthetic vault."""

    text_pairs: tuple[tuple[str, str], ...]
    memo_text_payloads: tuple[str, ...]
    memo_binary_payloads: tuple[bytes, ...]
    offset_days: int
    numeric_mapping_rows: int

    @property
    def tokens(self) -> tuple[str, ...]:
        """Bounded text forms of the private material (never emitted)."""
        candidates = (
            *[original for original, _pseudonym in self.text_pairs],
            *[pseudonym for _original, pseudonym in self.text_pairs],
            *self.memo_text_payloads,
            *(
                payload.decode("ascii", errors="ignore")
                for payload in self.memo_binary_payloads
            ),
            str(self.offset_days),
        )
        return tuple(
            dict.fromkeys(token for token in candidates if len(token) >= 6)
        )


def _read_only_vault_connection(vault: Path) -> sqlite3.Connection:
    """Open the synthetic test vault strictly READ-ONLY (SQLite URI mode=ro
    plus immutable): no -shm/-wal sidecar is ever created or left behind."""
    connection = sqlite3.connect(
        vault.resolve().as_uri() + "?mode=ro&immutable=1", uri=True
    )
    connection.execute("PRAGMA query_only = 1")
    return connection


def _extract_vault_material(vault: Path) -> _VaultMaterial:
    """Inspect the frozen vault schema read-only; zero-row queries fail."""
    connection = _read_only_vault_connection(vault)
    try:
        text_pairs = tuple(
            (str(original), str(pseudonym))
            for original, pseudonym in connection.execute(
                "SELECT original_value, pseudonym_value FROM text_mappings"
            ).fetchall()
        )
        memo_rows = tuple(
            (str(kind), bytes(payload))
            for kind, payload in connection.execute(
                "SELECT payload_kind, original_payload FROM memo_recovery"
            ).fetchall()
        )
        temporal_rows = tuple(
            connection.execute(
                "SELECT offset_days, typeof(offset_days) FROM temporal_parameters"
            ).fetchall()
        )
        numeric_rows = int(
            connection.execute(
                "SELECT COUNT(*) FROM numeric_key_mappings"
            ).fetchone()[0]
        )
    finally:
        connection.close()
    assert text_pairs, "the fixture must produce real text_mappings rows"
    assert memo_rows, "the fixture must produce real memo_recovery rows"
    assert len(temporal_rows) == 1, "the fixture must produce one temporal row"
    offset_storage = str(temporal_rows[0][1])
    assert offset_storage == "integer"
    offset = int(temporal_rows[0][0])
    assert offset != 0
    memo_text_payloads = tuple(
        payload.decode("utf-8") for kind, payload in memo_rows if kind == "TEXT"
    )
    memo_binary_payloads = tuple(
        payload for kind, payload in memo_rows if kind == "BINARY"
    )
    assert memo_text_payloads and memo_binary_payloads
    return _VaultMaterial(
        text_pairs=text_pairs,
        memo_text_payloads=memo_text_payloads,
        memo_binary_payloads=memo_binary_payloads,
        offset_days=offset,
        numeric_mapping_rows=numeric_rows,
    )


def _assert_material_absent(text: str, material: _VaultMaterial) -> None:
    """No actual vault material (values, pairs, payloads, offset) in *text*.

    Failure messages report only counts — never any extracted vault value.
    """
    leak_count = sum(1 for token in material.tokens if token in text)
    assert leak_count == 0, (
        f"{leak_count} private vault value(s) leaked into diagnostics"
    )
    assert "offset_days" not in text
    assert "temporal_offset" not in text


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


def test_real_vault_material_stays_outward_value_free(tmp_path: Path) -> None:
    """REAL vault material (pairs, memo payloads, offset) never reaches any
    success-path diagnostic surface of the real workflow or the CLI."""
    source, output, vault, plan, result, events = _workflow(tmp_path / "service")
    verification = public.verify_dataset(
        result, source=source, vault=vault, progress=events.append
    )
    assert verification.status is public.VerificationStatus.PASS
    bundle_path = tmp_path / "service" / "bundle"
    bundle = public.create_transfer_bundle(
        result, destination=bundle_path, progress=events.append
    )
    standalone = public.verify_transfer_bundle(bundle_path, progress=events.append)
    assert standalone.verified is True
    recovered = public.recover(
        output, vault=vault, output=tmp_path / "service" / "recovered", progress=events.append
    )
    assert recovered.canonical_verified is True

    material = _extract_vault_material(vault)
    # REAL reverse-mapping pair: the actual original Character canary has
    # exactly one persisted, distinct pseudonym in the real vault.
    distinct_pseudonyms = tuple(
        pseudonym
        for original, pseudonym in material.text_pairs
        if original == ORIGINAL_TEXT and pseudonym != original
    )
    assert len(distinct_pseudonyms) == 1, (
        "the real vault must hold exactly one reverse mapping for the actual original"
    )
    # REAL memo evidence: the text canary payload and the binary marker row.
    assert any(MEMO_PAYLOAD in payload for payload in material.memo_text_payloads)
    assert MEMO_BINARY_MARKER in material.memo_binary_payloads
    # REAL numeric-key scope: the accepted policy vocabulary only supports
    # numeric KEEP, so the minimal fixture legitimately has no numeric rows;
    # text mapping evidence is the mandatory mapping class here.
    assert material.numeric_mapping_rows == 0

    service_surfaces = (
        public.capabilities(),
        plan,
        result,
        verification,
        recovered,
        bundle,
        standalone,
        run_self_test(),
        *events,
    )
    service_texts = [_serialized(report) for report in service_surfaces]
    service_texts.append(
        (bundle_path / "transfer-manifest.json").read_text(encoding="ascii")
    )
    service_combined = "\n".join(service_texts)
    _assert_private_data_absent(service_combined)
    _assert_material_absent(service_combined, material)

    cli_outputs, cli_vaults = _drive_cli_channels(tmp_path / "cli")
    cli_combined = "\n".join(cli_outputs)
    _assert_private_data_absent(cli_combined)
    for cli_vault in cli_vaults:
        cli_material = _extract_vault_material(cli_vault)
        assert len(
            tuple(
                pair
                for pair in cli_material.text_pairs
                if pair[0] == ORIGINAL_TEXT and pair[1] != pair[0]
            )
        ) == 1
        _assert_material_absent(cli_combined, cli_material)


def test_temporal_offset_is_a_real_persisted_secret_never_emitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The persisted temporal_parameters.offset_days is REAL, deterministic
    through the accepted test-only randomness seam, and never outward."""
    import dbf_anonymizer.engine.run as engine_run_module
    from dbf_anonymizer.transforms.temporal import (
        temporal_feasible_interval,
        temporal_offset_at,
    )

    real_factory = engine_run_module.TemporalShiftDomain

    def deterministic_factory(
        vault: Any, *, domain_name: str | None = None
    ) -> Any:
        return real_factory(
            vault, domain_name=domain_name, _random_below=lambda bound: 0
        )

    monkeypatch.setattr(engine_run_module, "TemporalShiftDomain", deterministic_factory)

    source, output, vault, _plan, result, events = _workflow(tmp_path)
    assert events
    material = _extract_vault_material(vault)
    lower, upper = temporal_feasible_interval(
        date(2026, 1, 1).toordinal(), date(2026, 1, 14).toordinal()
    )
    expected_offset = temporal_offset_at(lower, upper, 0)
    assert material.offset_days == expected_offset
    assert material.offset_days != 0
    assert abs(material.offset_days) > 1000  # collision-safe versus small counts

    surfaces = (
        public.capabilities(),
        result,
        public.verify_dataset(result, source=source, vault=vault),
        *events,
    )
    combined = "\n".join([_serialized(surface) for surface in surfaces])
    cli_outputs, cli_vaults = _drive_cli_channels(tmp_path / "cli")
    combined = "\n".join([combined, *cli_outputs])
    _assert_private_data_absent(combined)
    for cli_vault in cli_vaults:
        cli_material = _extract_vault_material(cli_vault)
        assert cli_material.offset_days == expected_offset
        _assert_material_absent("\n".join(cli_outputs), cli_material)


def test_real_vault_corruption_failures_keep_real_vault_material_private(
    tmp_path: Path,
) -> None:
    """A REAL valid vault with actual private material fails typed and safe
    under controlled architecture-relevant corruption."""
    source, output, vault, _plan, result, _events = _workflow(tmp_path / "valid")
    material = _extract_vault_material(vault)
    assert any(
        original == ORIGINAL_TEXT and pseudonym != original
        for original, pseudonym in material.text_pairs
    )
    snapshot = vault.read_bytes()
    failure_surfaces: list[tuple[str, list[public.ProgressEvent]]] = []

    # 1) delete one REAL text mapping row -> bijection refusal
    connection = sqlite3.connect(str(vault))
    try:
        connection.execute(
            "DELETE FROM text_mappings WHERE original_value = ?", (ORIGINAL_TEXT,)
        )
        connection.commit()
    finally:
        connection.close()
    mapping_events: list[public.ProgressEvent] = []
    with pytest.raises(public.RecoveryError) as mapping_error:
        public.recover(
            output,
            vault=vault,
            output=tmp_path / "recovered-mapping",
            progress=mapping_events.append,
        )
    _assert_error_safe(mapping_error.value)
    failure_surfaces.append(
        (
            "\n".join(
                (
                    str(mapping_error.value),
                    repr(mapping_error.value),
                    _serialized(mapping_error.value),
                    *(_serialized(event) for event in mapping_events),
                )
            ),
            mapping_events,
        )
    )
    vault.write_bytes(snapshot)

    # 2) delete one REAL memo_recovery row -> recovery-row refusal
    connection = sqlite3.connect(str(vault))
    try:
        connection.execute(
            "DELETE FROM memo_recovery WHERE physical_record_index = "
            "(SELECT MIN(physical_record_index) FROM memo_recovery)"
        )
        connection.commit()
    finally:
        connection.close()
    memo_events: list[public.ProgressEvent] = []
    with pytest.raises(public.RecoveryError) as memo_error:
        public.recover(
            output,
            vault=vault,
            output=tmp_path / "recovered-memo",
            progress=memo_events.append,
        )
    _assert_error_safe(memo_error.value)
    failure_surfaces.append(
        (
            "\n".join(
                (
                    str(memo_error.value),
                    repr(memo_error.value),
                    _serialized(memo_error.value),
                    *(_serialized(event) for event in memo_events),
                )
            ),
            memo_events,
        )
    )

    for text, events_for_surface in failure_surfaces:
        _assert_private_data_absent(text)
        _assert_material_absent(text, material)
        assert events_for_surface
        _assert_private_data_absent(*(_serialized(event) for event in events_for_surface))
    assert str((tmp_path / "valid").resolve()) not in "\n".join(
        text for text, _events in failure_surfaces
    )


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


_SINK_ATTRS = frozenset(
    {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "exception",
        "critical",
        "log",
        "print_exc",
        "print_exception",
        "format_exc",
        "format_exception",
    }
)
_NAME_SINKS = frozenset({"print", "pprint"})
_SENSITIVE_SINK_FRAGMENTS = (
    ".values",
    "original_value",
    "pseudonym_value",
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
)


def _is_diagnostic_sink(func: ast.expr) -> bool:
    """Behavior-based sink detection: ANY diagnostic-style call receiver.

    Normal logging is ALLOWED by the architecture; a sink call becomes a
    violation only when it carries sensitive material (see fragments and the
    raw-exception rules).  A bare module import is never a violation.
    """
    if isinstance(func, ast.Name):
        return func.id in _NAME_SINKS
    if isinstance(func, ast.Attribute):
        return func.attr in _SINK_ATTRS
    return False


def _exception_names(handler: ast.ExceptHandler) -> set[str]:
    return {handler.name} if handler.name is not None else set()


def _diagnostic_violations(source: str, relative: str) -> list[str]:
    """Privacy-unsafe diagnostic BEHAVIOR in one module (REQ-P7-005).

    Encodes the architecture requirement, not an invented style rule:
    normal logs are permitted and must stay privacy-safe, so the guard
    flags SENSITIVE MATERIAL flowing into diagnostic sinks (original
    values, memo payloads, mapping pairs, temporal offsets, vault rows,
    raw exception text/args/interpolation) — never the mere presence of a
    logging import.
    """
    violations: list[str] = []
    tree = ast.parse(source, filename=relative)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_diagnostic_sink(node.func):
            segment = ast.get_source_segment(source, node) or ""
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "print"
                and relative != "cli.py"
            ):
                violations.append(f"{relative}:{node.lineno}:print outside CLI")
            lowered = segment.casefold()
            for fragment in _SENSITIVE_SINK_FRAGMENTS:
                if fragment.casefold() in lowered:
                    violations.append(
                        f"{relative}:{node.lineno}:diagnostic value dump {fragment}"
                    )
        if not isinstance(node, ast.ExceptHandler):
            continue
        names = _exception_names(node)
        if not names:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if _is_diagnostic_sink(child.func) and any(
                    isinstance(argument, ast.Name) and argument.id in names
                    for argument in child.args
                ):
                    violations.append(
                        f"{relative}:{child.lineno}:raw exception diagnostic sink"
                    )
                if (
                    isinstance(child.func, ast.Name)
                    and child.func.id in {"str", "repr"}
                    and child.args
                    and isinstance(child.args[0], ast.Name)
                    and child.args[0].id in names
                ):
                    violations.append(
                        f"{relative}:{child.lineno}:raw exception text"
                    )
            if (
                isinstance(child, ast.FormattedValue)
                and isinstance(child.value, ast.Name)
                and child.value.id in names
            ):
                violations.append(
                    f"{relative}:{child.lineno}:raw exception interpolation"
                )
            if (
                isinstance(child, ast.Attribute)
                and child.attr == "args"
                and isinstance(child.value, ast.Name)
                and child.value.id in names
            ):
                violations.append(f"{relative}:{child.lineno}:raw exception args")
    return violations


def test_production_has_no_diagnostic_value_dump_or_raw_exception_text_sink() -> None:
    violations: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        violations.extend(
            _diagnostic_violations(path.read_text(encoding="utf-8"), relative)
        )
    assert violations == []


def test_static_guard_accepts_safe_structured_diagnostics() -> None:
    """SAFE logging examples (counts, statuses, bounded paths, structured
    codes) must be ACCEPTED — the guard is behavior-based, not censorship."""
    safe_modules: tuple[tuple[str, str], ...] = (
        (
            "synthetic_safe.py",
            'import logging\n\n\ndef audit(count: int) -> None:\n'
            '    logger.info("verified %d tables", count)\n',
        ),
        (
            "synthetic_safe.py",
            'import logging\n\n\ndef audit(relative_path: str, total: int) -> None:\n'
            '    logging.warning("dataset %s finished", relative_path)\n'
            '    logging.info("processed %d records", total)\n',
        ),
        (
            "synthetic_safe.py",
            "import logging\n\n\ndef audit() -> None:\n"
            "    try:\n        pass\n"
            "    except Exception as exc:\n"
            '        logging.info("classified failure %s", exc.code)\n',
        ),
        (
            "cli.py",
            'import sys\n\n\ndef emit(total: int) -> None:\n'
            '    print(f"processed {total} records", file=sys.stderr)\n',
        ),
    )
    for relative, source in safe_modules:
        assert _diagnostic_violations(source, relative) == []


def test_static_guard_rejects_sensitive_and_raw_exception_diagnostics() -> None:
    """UNSAFE diagnostics (original values, mapping pairs, memo payloads,
    temporal offsets, raw exception text/args/interpolation) must be REJECTED."""
    unsafe_modules: tuple[tuple[str | None, str], ...] = (
        (
            ".values",
            "import logging\n\n\ndef leak(record) -> None:\n"
            '    logging.info("original values: %s", record.values)\n',
        ),
        (
            "original_payload",
            "import logging\n\n\ndef leak(memo) -> None:\n"
            '    logger.debug("memo payload %s", memo.original_payload)\n',
        ),
        (
            "pseudonym_value",
            'def leak(pair) -> None:\n    print(f"reverse mapping {pair.pseudonym_value}")\n',
        ),
        (
            "raw exception text",
            "import logging\n\n\ndef leak() -> None:\n"
            "    try:\n        pass\n"
            "    except Exception as exc:\n"
            '        logging.error("failure detail: %s", str(exc))\n',
        ),
        (
            "raw exception interpolation",
            "import logging\n\n\ndef leak() -> None:\n"
            "    try:\n        pass\n"
            "    except Exception as exc:\n"
            '        logging.warning(f"failure: {exc}")\n',
        ),
        (
            "exc.args",
            "def leak() -> None:\n"
            "    try:\n        pass\n"
            "    except Exception as exc:\n        print(exc.args)\n",
        ),
        (
            "offset_days",
            "import logging\n\n\ndef leak(domain) -> None:\n"
            '    logging.info("temporal offset %s", domain.offset_days)\n',
        ),
    )
    for expected, source in unsafe_modules:
        violations = _diagnostic_violations(source, "synthetic_unsafe.py")
        assert violations, "an unsafe synthetic diagnostic module was accepted"
        assert any(expected in violation for violation in violations)


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
