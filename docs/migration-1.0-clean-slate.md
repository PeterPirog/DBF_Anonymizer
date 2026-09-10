# Migration note — 1.0 clean-slate reset (REQ-P0-001)

Status: 1.0 development baseline (`1.0.0.dev0`). Supersedes the historical 0.3
line. This note is version-controlled evidence for REQ-P0-001 of the immutable
target architecture
(`DBF_ANONYMIZER_TARGET_ARCHITECTURE_CONVERGE_FINAL_2026-09-10.md`).

## What changed

The repository has been reset from an active historical 0.3 implementation to an
explicit clean-slate 1.0 development baseline. Git history remains the archive
of the 0.3 implementation; the installable package no longer carries it.

## 1.0 has NO compatibility obligation toward

- the historical 0.3 Python API (for example `anonymize_directory`,
  `make_dbf_recovery`, `self_test`, `anonymize_records`, `recover_records`);
- the historical 0.3 CLI and its `python -m dbf_anonymizer` entry point;
- the JSONL production pipeline (`export_dbf` -> JSONL -> `reconstruct_dbf`);
- the salt-based, deterministic pseudonym generator;
- the legacy reversible-store schema (JSON dictionaries, the 0.3
  `dictionary.sqlite3` layout);
- legacy JSON v1/v2 recovery-dictionary compatibility;
- the legacy module layout (`rawpatch`, `layout`, `jsonstream`, `tableio`,
  `pipeline`, `worker_tasks`, `vfp`, and related modules);
- the old VFP/CDX COM-automation coupling.

None of these surfaces are preserved merely for compatibility. They are not
replaced by fake or stub implementations of the future 1.0 API either: at the
end of Phase 0 the package surface is intentionally small.

## Reuse rule for old implementation fragments

Useful old implementation fragments may be reintroduced only when they
independently satisfy the immutable 1.0 requirements and their acceptance
evidence gates. Nothing is retained solely because it has existing tests.
Every reintroduction must be justified against the architecture, not against
the 0.3 codebase.

## Removed in this reset

All 0.3 runtime modules implementing the superseded architecture were removed
from `src/dbf_anonymizer` (the active package now contains only the module
`__init__.py` with the development version marker), together with their 0.3
test modules, the 0.3 benchmark script, the 0.3 documentation pages, the
`.env.example` private-path configuration file, and the release gates whose
only purpose was preserving obsolete 0.3 behavior.

No active 1.0 production path may reintroduce, without a new requirement-driven
decision:

- JSONL as the DBF transformation pipeline;
- `export_dbf` -> JSONL -> `reconstruct_dbf`;
- local DBF binary reconstruction or raw source-record byte restoration;
- compatibility code for legacy JSON dictionaries;
- salt-derived pseudonym generation.

## The 1.0 DBF/FPT boundary (REQ-P0-002)

The sole DBF/FPT parser and writer boundary for 1.0 is the published public
distribution `dbfbridge[write]>=1.1.0,<2`, imported through the public
`dbfbridge` namespace. The approved boundary is Direct Read plus Direct Write:

- `inspect_table`
- `read_schema`
- `iter_records`
- `iter_raw_records`
- `write_table`

DBF_Anonymizer 1.0 does not use `export_dbf` or `reconstruct_dbf` as its
production data pipeline, does not depend on the `dbf` library directly, does
not import dbfbridge private internals, and does not implement its own DBF/FPT
binary parsing or writing.

## Versioning

The development baseline is identified as `1.0.0.dev0`. No stable 1.0 release
is declared by this reset.