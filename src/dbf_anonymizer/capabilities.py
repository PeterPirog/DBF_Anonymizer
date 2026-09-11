"""Side-effect-free runtime capability discovery.

Capability discovery describes the currently installed service boundary.  It
never opens a dataset, creates files, imports any VFP/COM backend, starts a
subprocess, or probes the network.
"""

from __future__ import annotations

import dbfbridge

from .models import Capabilities


def capabilities() -> Capabilities:
    """Return immutable runtime capability facts.

    The required ``dbfbridge[write]`` dependency is the only DBF/FPT engine.
    Accessing its public lazy symbols is safe: Direct Write imports the
    physical ``dbf`` backend only when bytes are actually written.

    Capabilities for product phases that have not been implemented remain
    explicitly false rather than advertising placeholders.
    """

    direct_read = callable(getattr(dbfbridge, "read_schema", None))
    direct_write = callable(getattr(dbfbridge, "write_table", None))
    return Capabilities(
        direct_read=direct_read,
        direct_write=direct_write,
        planning=True,
        preflight=False,
        pseudonymization=False,
        verification=False,
        recovery=False,
        transfer_bundle=False,
        vfp_index_backend=False,
        dbfbridge_version=dbfbridge.__version__,
    )


__all__ = ["capabilities"]
