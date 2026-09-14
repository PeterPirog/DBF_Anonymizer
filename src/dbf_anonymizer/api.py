"""Public API entry point for DBF_Anonymizer 1.0 operational functions.

Currently exposes the side-effect-free capability discovery ``capabilities``
(REQ-P1-007) plus the read-only deterministic operations ``build_plan``
(REQ-P1-005) and ``preflight`` (REQ-P1-006). The remaining operations
(pseudonymize, verify_dataset, recover, create_transfer_bundle,
verify_transfer_bundle) are intentionally absent until their owning
requirements are implemented.
"""

from __future__ import annotations

from dbf_anonymizer.capabilities import capabilities
from dbf_anonymizer.planning import build_plan
from dbf_anonymizer.preflight import preflight

__all__ = ["capabilities", "build_plan", "preflight"]
