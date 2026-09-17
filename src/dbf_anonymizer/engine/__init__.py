"""The Phase 4 bounded two-pass production engine (REQ-P4-001/P4-002).

The engine is an INTERNAL implementation boundary: it is deliberately NOT
part of the root public API and no public ``pseudonymize`` operation exists
yet.  Every production DBF read goes through the ONE public
``dbfbridge.iter_records`` Direct Read stream and every production DBF/FPT
write through the ONE public ``dbfbridge.write_table`` boundary — no JSONL/
CSV intermediates, no private ``dbfbridge`` modules, no direct
``dbfread``/``dbf`` access, no raw record-byte rewriting and no source
copying as transformed output.

Bounded two-pass architecture (REQ-P4-002): pass 1 direct-reads the source
dataset in deterministic order, observes mapping constraints and declared
relationship evidence into the protected ephemeral SQLite spool (Zone B,
next to the ONE authoritative recovery vault) and finalizes the vault
allocations; pass 2 re-reads the source and streams every record through the
finalized vault state into the public Direct Write boundary.  No dataset-
sized or distinct-value-sized Python dictionary, set or list is kept in
engine RAM; the multiplicity profiles are compared by streaming SQL
aggregation.
"""

from __future__ import annotations

from dbf_anonymizer.engine.directives import (
    EnginePlan,
    RelationDirective,
    RelationPassSummary,
    TableDirective,
    TwoPassResult,
)
from dbf_anonymizer.engine.run import (
    build_engine_plan,
    run_two_pass,
)
from dbf_anonymizer.engine.state import (
    MAX_RECORD_BATCH,
    MAX_SQL_BATCH,
    EVIDENCE_SPOOL_SCHEMA_VERSION,
    PASS1_STATE_FILENAME,
    PassOneSpool,
)

__all__ = [
    "EnginePlan",
    "RelationDirective",
    "RelationPassSummary",
    "TableDirective",
    "TwoPassResult",
    "build_engine_plan",
    "run_two_pass",
    "MAX_RECORD_BATCH",
    "MAX_SQL_BATCH",
    "EVIDENCE_SPOOL_SCHEMA_VERSION",
    "PASS1_STATE_FILENAME",
]