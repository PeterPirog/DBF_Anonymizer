"""Public API entry point for DBF_Anonymizer 1.0 operational functions.

Currently exposes only ``build_plan`` (REQ-P1-005). The remaining seven
operations (capabilities, preflight, pseudonymize, verify_dataset, recover,
create_transfer_bundle, verify_transfer_bundle) are intentionally absent until
their owning requirements are implemented.
"""

from __future__ import annotations

from dbf_anonymizer.planning import build_plan

__all__ = ["build_plan"]
