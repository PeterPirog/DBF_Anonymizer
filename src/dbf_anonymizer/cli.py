"""Console entry point for DBF_Anonymizer (REQ-P1-001 foundation).

The CLI is a minimal truthful foundation: at this stage it supports only
``--help`` and ``--version``.  No future target command
(``capabilities``, ``plan``, ``preflight``, ``pseudonymize``, ``verify``,
``recover``, ``export-bundle``, ``verify-bundle``, ``self-test``) is
implemented yet, and none of them is advertised or faked; unknown arguments
return non-zero.  Later requirements (P1-002..P1-004) own the real command
surface.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from dbf_anonymizer import __version__

PROGRAM = "dbf-anonymizer"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "DBF_Anonymizer 1.0 development baseline: pseudonymization for "
            "Visual FoxPro DBF/FPT datasets (clean-slate 1.0; product "
            "operations are under development)."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROGRAM} {__version__}",
        help="print the installed package version and exit",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point.

    Supports ``--help`` and ``--version`` only.  A bare invocation and any
    other argument are rejected with exit code 2 and a stderr message; no
    placeholder success is ever reported.
    """
    parser = _build_parser()
    arguments = list(sys.argv[1:]) if argv is None else list(argv)
    if not arguments:
        parser.print_usage(sys.stderr)
        print(
            f"{PROGRAM}: no product operations are implemented yet "
            "(clean-slate 1.0 development baseline; see --help).",
            file=sys.stderr,
        )
        return 2
    try:
        parser.parse_args(arguments)
    except SystemExit as exit_request:  # argparse convention: exit codes 0/2
        return int(exit_request.code or 0)
    return 0


if __name__ == "__main__":  # pragma: no cover - direct module execution
    raise SystemExit(main(sys.argv[1:]))