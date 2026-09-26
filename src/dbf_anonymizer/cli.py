"""Console entry point for DBF_Anonymizer (REQ-P1-001 foundation).

The CLI is an adapter over the Python service layer, not a second
implementation.  Common machine integration uses ``--json``; human progress
goes to stderr; machine result JSON goes to stdout.

Implemented commands:
* ``capabilities`` — side-effect-free capability discovery (REQ-P1-007)
* ``recover`` — protected canonical dataset recovery (REQ-P5-002/REQ-P5-003,
  REQ-P7-003) with explicit ``--recovery-policy enabled|disabled`` control
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from dbf_anonymizer import __version__
from dbf_anonymizer.api import (
    capabilities,
    recover,
    RecoveryPolicy,
)
from dbf_anonymizer.errors import AnonymizerError
from dbf_anonymizer.models import ProgressEvent
from dbf_anonymizer.progress import ProgressController, ProgressPhase

PROGRAM = "dbf-anonymizer"


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

    # capabilities
    cap_parser = subparsers.add_parser(
        "capabilities",
        help="show side-effect-free capability snapshot",
    )
    cap_parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON to stdout",
    )

    # recover
    rec_parser = subparsers.add_parser(
        "recover",
        help="reconstruct original logical dataset from pseudonymized dataset and vault",
    )
    rec_parser.add_argument(
        "pseudonymized",
        type=Path,
        help="path to pseudonymized dataset directory",
    )
    rec_parser.add_argument(
        "vault",
        type=Path,
        help="path to protected SQLite vault",
    )
    rec_parser.add_argument(
        "output",
        type=Path,
        help="output directory for recovered dataset (must not exist)",
    )
    rec_parser.add_argument(
        "--recovery-policy",
        choices=["enabled", "disabled"],
        default="enabled",
        help="recovery capability policy (default: enabled)",
    )
    rec_parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON result to stdout; human progress to stderr",
    )

    return parser


def _run_capabilities(json_output: bool) -> int:
    caps = capabilities()
    if json_output:
        print(json.dumps(caps.to_dict(), separators=(",", ":"), ensure_ascii=True))
    else:
        print(f"direct_read: {caps.direct_read}")
        print(f"direct_write: {caps.direct_write}")
        print(f"recovery: {caps.recovery}")
        print(f"transfer_bundle: {caps.transfer_bundle}")
        print(f"vfp_index_backend: {caps.vfp_index_backend}")
        print(f"dbfbridge_version: {caps.dbfbridge_version}")
    return 0


def _progress_to_stderr(event: ProgressEvent) -> None:
    """Emit human-readable progress to stderr."""
    phase = event.phase_code
    code = event.event_code
    completed = event.completed_units
    total = event.total_units if event.total_units is not None else "?"
    table = f" [{event.table_path}]" if event.table_path else ""
    print(
        f"[{phase}] {code}: {completed}/{total}{table}",
        file=sys.stderr,
    )


def _run_recover(args: argparse.Namespace) -> int:
    policy = RecoveryPolicy.from_cli(args.recovery_policy)
    try:
        result = recover(
            pseudonymized=args.pseudonymized,
            vault=args.vault,
            output=args.output,
            progress=_progress_to_stderr if not args.json else None,
            recovery_policy=policy,
        )
    except AnonymizerError as exc:
        if args.json:
            print(json.dumps(exc.to_dict(), separators=(",", ":"), ensure_ascii=True))
        else:
            print(
                f"{PROGRAM}: {exc.code.value}: {exc.message}",
                file=sys.stderr,
            )
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), separators=(",", ":"), ensure_ascii=True))
    else:
        print(
            f"recovered: {result.output_path} "
            f"({result.table_count} tables, {result.record_count} records)",
            file=sys.stderr,
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point."""
    parser = _build_parser()
    arguments = list(sys.argv[1:]) if argv is None else list(argv)
    try:
        parsed = parser.parse_args(arguments)
    except SystemExit as exit_request:
        return int(exit_request.code or 0)

    if parsed.command == "capabilities":
        return _run_capabilities(parsed.json)
    if parsed.command == "recover":
        return _run_recover(parsed)

    parser.print_usage(sys.stderr)
    print(f"{PROGRAM}: unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover - direct module execution
    raise SystemExit(main(sys.argv[1:]))
