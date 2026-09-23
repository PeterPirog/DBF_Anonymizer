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
"""

from __future__ import annotations

from dbf_anonymizer._capability import snapshot
from dbf_anonymizer.models import Capabilities

__all__ = ["capabilities"]


def capabilities() -> Capabilities:
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
    ``vfp_index_backend`` is ``False`` until its owning requirement is
    implemented.
    """
    return snapshot()