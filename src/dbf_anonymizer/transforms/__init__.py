"""Pure transformation semantics shared by planning and vault allocation.

This internal package holds the PURE, side-effect-free kernels of the
transformation layers. It performs no I/O, opens no file, imports no
``dbfbridge`` namespace, touches no vault state and draws no randomness —
DBF/FPT parsing and writing stay exclusively inside the public ``dbfbridge``
boundary and never move into this package.
"""

from dbf_anonymizer.transforms import text

__all__ = ["text"]