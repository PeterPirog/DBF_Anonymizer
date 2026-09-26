"""Public side-effect-free capability discovery (REQ-P1-007).

``capabilities()`` is the supported public discovery operation of the 1.0
package: it returns the immutable, truthful :class:`~dbf_anonymizer.Capabilities`
snapshot.

Discovery only — ``capabilities()`` performs no other action:

* it creates no file, directory, log or temporary artifact of any kind;
* it opens no DBF/FPT/CDX/IDX/DBC/DCT/DCX artifact and invokes no
  ``dbfbridge`` data operation (``inspect_table``, ``read_schema``,
  ``iter_records``, ``iter_raw_records``, ``write_table``);
* it starts no subprocess and invokes no shell;
* it instantiates no COM object and imports no optional VFP/index backend;
* it contacts no network endpoint;
* it mutates no global service configuration.

Discovery may only inspect installed Python distribution metadata and the
public ``dbfbridge`` namespace (symbol presence/callability), never execute
the data operations themselves. The implementation delegates to the existing
side-effect-free private snapshot logic; there is exactly one capability
discovery implementation in the package.

Future capabilities remain ``False`` until their owning requirements are
implemented; nothing is advertised that does not exist.

REQ-P7-003: The ``recovery_policy`` parameter allows a host to project
the effective recovery capability. When ``RecoveryPolicy.DISABLED``, the
returned ``recovery`` capability is ``False`` even though the underlying
runtime support (direct read/write) remains available. This distinguishes
runtime support from host permission without global mutable state.
"""

from __future__ import annotations

from dbf_anonymizer._capability import snapshot
from dbf_anonymizer.models import Capabilities
from dbf_anonymizer.recovery_policy import RecoveryPolicy

__all__ = ["capabilities"]


def capabilities(recovery_policy: RecoveryPolicy = RecoveryPolicy.ENABLED) -> Capabilities:
    """Return the immutable, truthful runtime capability snapshot.

    This is discovery only and is side-effect-free: no file is created, no
    DBF/FPT/CDX/IDX/DBC artifact is opened, no ``dbfbridge`` data operation is
    executed, no subprocess, COM object or network endpoint is touched and no
    optional VFP backend is imported or activated.

    The protected canonical dataset recovery (``recovery``) and the safe
    standalone DATA_ONLY transfer bundle (``transfer_bundle``) are ``True``
    exactly when the implemented REQ-P5-002..P5-007 services' required
    runtime facts hold (direct read AND direct write — derived from the same
    public dbfbridge capability facts, never from filesystem probing).
    ``vfp_index_backend`` remains ``False`` for standalone discovery because
    an injected backend is available only within one explicit operation.

    REQ-P7-003: ``recovery_policy`` controls the projected recovery capability.
    When ``RecoveryPolicy.DISABLED``, ``recovery`` is ``False`` in the returned
    snapshot while ``direct_read`` and ``direct_write`` remain truthful. This
    enables a host to expose pseudonymization and verification while
    truthfully representing ``recovery = false`` without changing physical
    package support.
    """
    base = snapshot()
    if recovery_policy is RecoveryPolicy.DISABLED:
        return Capabilities(
            direct_read=base.direct_read,
            direct_write=base.direct_write,
            recovery=False,
            transfer_bundle=base.transfer_bundle,
            vfp_index_backend=base.vfp_index_backend,
            dbfbridge_version=base.dbfbridge_version,
        )
    return base
