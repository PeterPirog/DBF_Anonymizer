"""DBF_Anonymizer 1.0 development baseline (clean slate).

This package is the clean-slate 1.0 line established by REQ-P0-001. It has no
compatibility obligation toward the historical 0.3 Python API, CLI, JSONL
pipeline, salt-based pseudonym generator, legacy reversible-store schema, JSON
v1/v2 recovery formats, legacy module layout or the old VFP/CDX coupling; see
``docs/migration-1.0-clean-slate.md``.

The public 1.0 operation surface (``capabilities``, ``build_plan``,
``preflight``, ``pseudonymize``, ``verify_dataset``, ``recover``,
``create_transfer_bundle``, ``verify_transfer_bundle``) is defined by the
immutable target architecture and is intentionally NOT implemented yet. This
package does not export placeholder or stub operations in its place: at this
stage an intentionally small public surface is preferable to false
functionality.

The sole DBF/FPT parser and writer boundary for 1.0 is the published public
``dbfbridge[write]>=1.1.0,<2`` distribution, imported through the public
``dbfbridge`` namespace (Direct Read + Direct Write).
"""

from __future__ import annotations

__version__ = "1.0.0.dev0"

__all__: list[str] = []