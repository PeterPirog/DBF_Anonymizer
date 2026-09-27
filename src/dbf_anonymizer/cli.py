"""Thin standalone CLI adapter over the DBF_Anonymizer service layer."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

from dbf_anonymizer import __version__
from dbf_anonymizer.api import (
    _load_completed_result,
    build_plan,
    capabilities,
    create_transfer_bundle,
    preflight,
    pseudonymize,
    recover,
    RecoveryPolicy,
    verify_dataset,
    verify_transfer_bundle,
)
from dbf_anonymizer.errors import (
    AnonymizerError,
    ErrorCode,
    ErrorContext,
    PolicyError,
    RelationshipError,
)
from dbf_anonymizer.models import Plan, ProgressEvent
from dbf_anonymizer.progress import ProgressCallback
from dbf_anonymizer.standalone_health import run_self_test

PROGRAM = "dbf-anonymizer"
COMMANDS = (
    "capabilities",
    "plan",
    "preflight",
    "pseudonymize",
    "verify",
    "recover",
    "export-bundle",
    "verify-bundle",
    "self-test",
)


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit exactly one machine-readable JSON result to stdout",
    )


def _add_recovery_policy(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--recovery-policy",
        choices=["enabled", "disabled"],
        default="enabled",
        help="recovery capability policy (default: enabled)",
    )


def _add_plan_arguments(
    parser: argparse.ArgumentParser, *, output_name: str = "output"
) -> None:
    parser.add_argument("source", type=Path, help="source dataset directory")
    parser.add_argument(output_name, type=Path, help="pseudonymized output directory")
    parser.add_argument("vault", type=Path, help="protected SQLite vault path")
    parser.add_argument("--policy", type=Path, help="versioned JSON policy file")
    parser.add_argument(
        "--relationships", type=Path, help="versioned JSON relationship document"
    )
    _add_json(parser)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "DBF_Anonymizer 1.0: pseudonymization for Visual FoxPro "
            "DBF/FPT datasets."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROGRAM} {__version__}",
        help="print the installed package version and exit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    caps = subparsers.add_parser(
        "capabilities", help="report standalone runtime capabilities"
    )
    _add_recovery_policy(caps)
    _add_json(caps)

    plan_parser = subparsers.add_parser(
        "plan", help="build a read-only deterministic dataset plan"
    )
    _add_plan_arguments(plan_parser)

    preflight_parser = subparsers.add_parser(
        "preflight", help="evaluate read-only execution preconditions"
    )
    _add_plan_arguments(preflight_parser)

    pseudonymize_parser = subparsers.add_parser(
        "pseudonymize", help="pseudonymize a dataset through the service layer"
    )
    _add_plan_arguments(pseudonymize_parser)
    pseudonymize_parser.add_argument(
        "--workers", type=int, default=1, help="bounded worker count (default: 1)"
    )

    verify_parser = subparsers.add_parser(
        "verify", help="independently verify a completed pseudonymization"
    )
    _add_plan_arguments(verify_parser, output_name="pseudonymized")

    recover_parser = subparsers.add_parser(
        "recover",
        help="reconstruct the original logical dataset from output and vault",
    )
    recover_parser.add_argument(
        "pseudonymized", type=Path, help="pseudonymized dataset directory"
    )
    recover_parser.add_argument("vault", type=Path, help="protected SQLite vault")
    recover_parser.add_argument(
        "output", type=Path, help="recovered output directory (must not exist)"
    )
    _add_recovery_policy(recover_parser)
    _add_json(recover_parser)

    export_parser = subparsers.add_parser(
        "export-bundle", help="create a verified standalone DATA_ONLY bundle"
    )
    export_parser.add_argument("source", type=Path, help="source dataset directory")
    export_parser.add_argument(
        "pseudonymized", type=Path, help="pseudonymized dataset directory"
    )
    export_parser.add_argument("vault", type=Path, help="protected SQLite vault")
    export_parser.add_argument("destination", type=Path, help="bundle destination")
    export_parser.add_argument("--policy", type=Path, help="versioned JSON policy file")
    export_parser.add_argument(
        "--relationships", type=Path, help="versioned JSON relationship document"
    )
    _add_json(export_parser)

    verify_bundle_parser = subparsers.add_parser(
        "verify-bundle", help="verify a standalone DATA_ONLY bundle"
    )
    verify_bundle_parser.add_argument("bundle", type=Path, help="bundle directory")
    _add_json(verify_bundle_parser)

    self_test_parser = subparsers.add_parser(
        "self-test", help="run a complete synthetic standalone health test"
    )
    _add_json(self_test_parser)
    return parser


def _progress_to_stderr(event: ProgressEvent) -> None:
    total = event.total_units if event.total_units is not None else "?"
    table = f" [{event.table_path}]" if event.table_path else ""
    print(
        f"[{event.phase_code}] {event.event_code}: "
        f"{event.completed_units}/{total}{table}",
        file=sys.stderr,
    )


def _progress(args: argparse.Namespace) -> ProgressCallback | None:
    return None if args.json else _progress_to_stderr


def _document_error(kind: str, detail_code: str) -> AnonymizerError:
    context = ErrorContext(operation="cli", detail_code=detail_code)
    if kind == "policy":
        return PolicyError(ErrorCode.POLICY_INVALID, context=context)
    return RelationshipError(ErrorCode.RELATIONSHIP_INVALID, context=context)


def _load_document(path: Path | None, *, kind: str) -> Mapping[str, Any] | None:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise _document_error(kind, f"CLI_{kind.upper()}_DOCUMENT_INVALID") from None
    if not isinstance(payload, dict):
        raise _document_error(kind, f"CLI_{kind.upper()}_DOCUMENT_NOT_OBJECT")
    return payload


def _build_plan_from_args(args: argparse.Namespace) -> Plan:
    output = getattr(args, "output", None)
    if output is None:
        output = args.pseudonymized
    return build_plan(
        source=args.source,
        output=output,
        vault=args.vault,
        policy=_load_document(args.policy, kind="policy"),
        relationship_document=_load_document(
            args.relationships, kind="relationship"
        ),
        progress=_progress(args),
    )


def _emit(args: argparse.Namespace, result: object, human: str) -> int:
    if args.json:
        to_dict = getattr(result, "to_dict")
        print(
            json.dumps(
                to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
        )
    else:
        print(human, file=sys.stderr)
    return 0


def _run_capabilities(args: argparse.Namespace) -> int:
    result = capabilities(RecoveryPolicy.from_cli(args.recovery_policy))
    return _emit(args, result, "capabilities: available")


def _run_plan(args: argparse.Namespace) -> int:
    plan = _build_plan_from_args(args)
    return _emit(args, plan, f"plan: {plan.plan_id}")


def _run_preflight(args: argparse.Namespace) -> int:
    plan = _build_plan_from_args(args)
    result = preflight(plan, progress=_progress(args))
    return _emit(args, result, f"preflight: {'ready' if result.ready else 'not ready'}")


def _run_pseudonymize(args: argparse.Namespace) -> int:
    plan = _build_plan_from_args(args)
    try:
        result = pseudonymize(plan, workers=args.workers, progress=_progress(args))
    except ValueError:
        raise PolicyError(
            ErrorCode.POLICY_INVALID,
            context=ErrorContext(
                operation="cli", detail_code="CLI_WORKER_COUNT_INVALID"
            ),
        ) from None
    return _emit(
        args,
        result,
        f"pseudonymized: {result.output_path} "
        f"({result.table_count} tables, {result.record_count} records)",
    )


def _run_verify(args: argparse.Namespace) -> int:
    plan = _build_plan_from_args(args)
    completed = _load_completed_result(plan)
    result = verify_dataset(
        completed,
        source=args.source,
        vault=args.vault,
        progress=_progress(args),
    )
    return _emit(args, result, f"verification: {result.status.value}")


def _run_recover(args: argparse.Namespace) -> int:
    result = recover(
        pseudonymized=args.pseudonymized,
        vault=args.vault,
        output=args.output,
        progress=_progress(args),
        recovery_policy=RecoveryPolicy.from_cli(args.recovery_policy),
    )
    return _emit(
        args,
        result,
        f"recovered: {result.output_path} "
        f"({result.table_count} tables, {result.record_count} records)",
    )


def _run_export_bundle(args: argparse.Namespace) -> int:
    plan = _build_plan_from_args(args)
    completed = _load_completed_result(plan)
    result = create_transfer_bundle(
        completed,
        destination=args.destination,
        profile="DATA_ONLY",
        progress=_progress(args),
    )
    return _emit(args, result, f"bundle: {result.bundle_path}")


def _run_verify_bundle(args: argparse.Namespace) -> int:
    result = verify_transfer_bundle(args.bundle, progress=_progress(args))
    return _emit(args, result, f"bundle verification: {result.verified}")


def _run_self_test(args: argparse.Namespace) -> int:
    result = run_self_test()
    return _emit(args, result, "self-test: PASS")


_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "capabilities": _run_capabilities,
    "plan": _run_plan,
    "preflight": _run_preflight,
    "pseudonymize": _run_pseudonymize,
    "verify": _run_verify,
    "recover": _run_recover,
    "export-bundle": _run_export_bundle,
    "verify-bundle": _run_verify_bundle,
    "self-test": _run_self_test,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point."""
    parser = _build_parser()
    arguments = list(sys.argv[1:]) if argv is None else list(argv)
    try:
        args = parser.parse_args(arguments)
    except SystemExit as exit_request:
        return int(exit_request.code or 0)
    try:
        return _HANDLERS[args.command](args)
    except AnonymizerError as exc:
        if args.json:
            print(
                json.dumps(
                    exc.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
            )
        else:
            print(f"{PROGRAM}: {exc.code.value}: {exc.message}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
