"""Direct execution adapter: ``python -m dbf_anonymizer`` delegates to the
console entry point without duplicating any CLI implementation."""

from __future__ import annotations

import sys

from dbf_anonymizer.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))