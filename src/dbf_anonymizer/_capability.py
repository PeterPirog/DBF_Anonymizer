"""Side-effect-free runtime capability snapshot for REQ-P1-006 preflight.

This module only reports *truthful* capability facts derived from the public
``dbfbridge`` namespace and the installed distribution. It creates no files,
opens no DBF, starts no subprocess, instantiates no COM object and touches no
network endpoint. Capability discovery begins only when it is explicitly
requested (preflight calls it); importing this module performs no I/O.

The snapshot is intentionally private: ``capabilities()`` is a future public
operation (REQ-P1-007) and is NOT exposed through the package root in this
iteration. Preflight consumes it as an internal helper.
"""

from __future__ import annotations

import importlib.util
from typing import Callable

import dbfbridge

from dbf_anonymizer.models import Capabilities

__all__ = ["snapshot", "direct_read_available", "direct_write_available"]


def _importlib_metadata_version() -> str:
    import importlib.metadata as metadata

    try:
        return metadata.version("dbfbridge")
    except metadata.PackageNotFoundError:  # pragma: no cover - defensive
        return "unknown"


def direct_read_available() -> bool:
    """True only when the public dbfbridge direct-read API is present."""
    return callable(getattr(dbfbridge, "read_schema", None))


def direct_write_available() -> bool:
    """True only when the public dbfbridge direct-write API is present."""
    return callable(getattr(dbfbridge, "write_table", None))


def snapshot() -> Capabilities:
    """Return a truthful, side-effect-free capability snapshot.

    ``vfp_index_backend`` is false in this standalone implementation (it will
    be supplied later by the REQ-P6 index backend), and ``recovery`` /
    ``transfer_bundle`` remain false until their owning requirements exist.
    """
    return Capabilities(
        direct_read=direct_read_available(),
        direct_write=direct_write_available(),
        recovery=False,
        transfer_bundle=False,
        vfp_index_backend=False,
        dbfbridge_version=_importlib_metadata_version(),
    )


#: Provider seam for preflight. Tests may replace this callable to simulate a
#: missing direct-read/write capability deterministically.
capabilities_provider: Callable[[], Capabilities] = snapshot
