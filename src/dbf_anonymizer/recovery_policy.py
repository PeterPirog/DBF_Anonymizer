"""Recovery policy for REQ-P7-003.

Explicit, transport-neutral policy controlling whether the protected canonical
dataset recovery capability is permitted. This enables an embedding host to
expose pseudonymization and verification while disabling recovery.
"""

from __future__ import annotations

from enum import Enum


class RecoveryPolicy(str, Enum):
    """Host-controlled recovery capability policy.

    ENABLED  — recovery is permitted (default for standalone CLI).
    DISABLED — recovery is refused before any vault access.

    This is a closed enum: no arbitrary values, no environment variables,
    no process-global mutable switches.
    """

    ENABLED = "enabled"
    DISABLED = "disabled"

    @classmethod
    def from_cli(cls, value: str) -> "RecoveryPolicy":
        """Parse CLI value, failing closed on invalid input."""
        try:
            return cls(value.lower())
        except ValueError:
            valid = ", ".join(item.value for item in cls)
            raise ValueError(
                f"recovery-policy must be one of: {valid}"
            ) from None