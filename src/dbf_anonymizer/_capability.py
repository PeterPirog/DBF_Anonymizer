"""Side-effect-free runtime capability snapshot for REQ-P1-006/REQ-P1-007.

This module only reports *truthful* capability facts derived from the public
``dbfbridge`` namespace and the installed distribution. It creates no files,
opens no DBF, starts no subprocess, instantiates no COM object and touches no
network endpoint. Capability discovery begins only when it is explicitly
requested; importing this module performs no I/O.

The snapshot logic is intentionally private: the supported public discovery
operation is :func:`dbf_anonymizer.capabilities.capabilities` (REQ-P1-007),
which delegates to :func:`snapshot`. Preflight consumes the same logic
through the ``capabilities_provider`` seam — there is exactly one discovery
implementation in the package.

REQ-P7-003: The ``capabilities_provider`` seam now accepts an optional
``recovery_policy`` parameter for host policy projection.
"""

from __future__ import annotations

import importlib.util
from typing import Callable

import dbfbridge

from dbf_anonymizer.models import Capabilities
from dbf_anonymizer.recovery_policy import RecoveryPolicy

__all__ = ["snapshot", "direct_read_available", "direct_write_available"]


def _importlib_metadata_version() -> str:
    import importlib.metadata as metadata

    try:
        return metadata.version("dbfbridge")
    except metadata.PackageNotFoundError:  # pragma: no cover - defensive
        return "unknown"


def _read_dependency_available() -> bool:
    """True when the reader's runtime dependency (dbfread) is discoverable."""
    try:
        return importlib.util.find_spec("dbfread") is not None
    except (ImportError, ValueError):
        return False


def _write_dependency_available() -> bool:
    """True when the writer's runtime dependency (dbf) is discoverable.

    The ``write_table`` symbol alone does not establish a usable writer: the
    ``dbfbridge[write]`` extra must actually be installed.
    """
    try:
        return importlib.util.find_spec("dbf") is not None
    except (ImportError, ValueError):
        return False


def direct_read_available() -> bool:
    """True only when EVERY public dbfbridge direct-read operation required by
    preflight is callable and the runtime dependency (dbfread) is discoverable.

    Preflight needs ``read_schema`` (schema/companion facts, capacity domain)
    AND ``iter_records`` (streaming GLOBAL_TEXT capacity scan, deleted records
    included). Missing either symbol means direct read is unavailable.
    """
    return (
        callable(getattr(dbfbridge, "read_schema", None))
        and callable(getattr(dbfbridge, "iter_records", None))
        and _read_dependency_available()
    )


def direct_write_available() -> bool:
    """True only when the public dbfbridge direct-write API and its runtime
    dependency (dbf) are both present."""
    return (
        callable(getattr(dbfbridge, "write_table", None))
        and _write_dependency_available()
    )


def snapshot(recovery_policy: RecoveryPolicy = RecoveryPolicy.ENABLED) -> Capabilities:
    """Return a truthful, side-effect-free capability snapshot.

    Direct read/write truthfulness requires both the public API symbol and
    the discoverable runtime dependency of the ``dbfbridge[write]`` extra.
    The protected canonical dataset recovery (REQ-P5-002/REQ-P5-003) and the
    safe standalone DATA_ONLY transfer bundle (REQ-P5-004..P5-007) are REAL
    implemented services: their capabilities are derived from the SAME
    required direct read/write runtime capability facts (both read the
    pseudonymized dataset through the direct reader and write through the
    direct writer; no additional backend is involved) — no filesystem
    probing, no DBF/vault open, no subprocess/COM/network.
    ``vfp_index_backend`` remains false in standalone discovery. REQ-P6-003
    validates an explicitly injected backend only for its current operation.

    REQ-P7-003: ``recovery_policy`` controls the projected recovery capability.
    """
    direct_read = direct_read_available()
    direct_write = direct_write_available()
    recovery = direct_read and direct_write
    if recovery_policy is RecoveryPolicy.DISABLED:
        recovery = False
    return Capabilities(
        direct_read=direct_read,
        direct_write=direct_write,
        recovery=recovery,
        transfer_bundle=direct_read and direct_write,
        vfp_index_backend=False,
        dbfbridge_version=_importlib_metadata_version(),
    )


#: Provider seam for preflight. Tests may replace this callable to simulate a
#: missing direct-read/write capability deterministically.
#: REQ-P7-003: accepts optional recovery_policy for host policy projection.
capabilities_provider: Callable[[RecoveryPolicy], Capabilities] = snapshot
