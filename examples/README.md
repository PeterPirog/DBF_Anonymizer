# DBF_Anonymizer examples

Executable, copy/pasteable recipes for the stable 1.0 public API. Every
example is downstream-consumer code: it imports only the public package root
`dbf_anonymizer` (plus the documented public `dbf_anonymizer.relationships`
schema loader where stated) and the public `dbfbridge` writer/reader — never
a private `dbf_anonymizer.*` module, never MCP/transport/server code.

## Prerequisites

- Python 3.10+ with the `dbf-anonymizer` wheel installed (see the README
  installation section — public PyPI publication is a separate privileged
  lane; install from a built wheel or a prepared offline wheelhouse);
- the public `dbfbridge[write]>=1.1.0,<2` runtime dependency (installed with
  the wheel).

## What the examples do and do not do

- ALL examples use SYNTHETIC data only: deterministic canary values written
  through the public `dbfbridge` Direct Write API. No production, customer
  or organizational DBF/FPT/CDX/IDX/DBC content is ever read.
- No example needs a network, VFP/COM, or any private path. No example
  launches VFP; `VFP_INDEXED` is an OPT-IN profile that requires an
  authoritative `IndexBackend` explicitly injected by the host — the
  examples use the default DATA_ONLY output profile.
- Each example creates a disposable workspace and prints a BOUNDED,
  PRIVACY-SAFE summary (roles, counts, stable status/level vocabulary) —
  never resolved absolute paths, never TEMP roots, never original values,
  never vault contents. Pass an optional argument to choose the workspace
  root; a supplied workspace must NOT exist yet (the examples refuse an
  existing target fail-closed, before writing anything), otherwise a fresh
  system-TEMP directory is used. Synthetic canaries are the only "data"
  involved.

## Recommended order

1. [basic_workflow.py](basic_workflow.py) — the canonical end-to-end
   workflow: capabilities, build_plan, preflight, pseudonymize,
   verify_dataset (PASS), with SOURCE/OUTPUT/VAULT roles shown explicitly.
2. [relationship_workflow.py](relationship_workflow.py) — a declared PK/FK
   relationship (people PRIMARY `ID` -> orders FOREIGN `PERSON_ID`) with
   value-level FK-join proof after pseudonymization.
3. [recovery_workflow.py](recovery_workflow.py) — both authorization paths:
   `RecoveryPolicy.ENABLED` (canonical recovery) and
   `RecoveryPolicy.DISABLED` (typed refusal before any vault access).
4. [progress_cancellation.py](progress_cancellation.py) — bounded
   synchronous progress callbacks and deterministic cooperative
   cancellation (typed `OPERATION_CANCELLED`, no published output).
5. [data_only_bundle.py](data_only_bundle.py) — create and standalone-verify
   the transferable DATA_ONLY bundle; the vault never becomes part of it.
6. [external_metadata.py](external_metadata.py) — inject a
   producer-independent external VFP metadata envelope (one VERIFIED
   relation claim + one index claim) through the public planning boundary,
   and load the shipped schema through the documented public loader. The
   two evidence domains are kept separate: relational assurance comes from
   the authoritative RELATION claim plus relationship verification; the
   INDEX claim never causes relational assurance.
7. [field_semantics_workflow.py](field_semantics_workflow.py) — advanced
   DBF/VFP field semantics on synthetic data: deleted records stay deleted
   with transformed content, NULL/empty identities, Varchar domain sharing,
   memo/FPT masking with canary leakage checks, recovery and DATA_ONLY.
8. [consumer_adapter.py](consumer_adapter.py) — the thin, synchronous,
   transport-neutral reference adapter for a downstream host (NOT an MCP
   server; the host owns transport, authentication and orchestration).

Standalone execution:

```console
python examples/basic_workflow.py
python examples/relationship_workflow.py
python examples/recovery_workflow.py
python examples/progress_cancellation.py
python examples/data_only_bundle.py
python examples/external_metadata.py
python examples/field_semantics_workflow.py
```

Each example prints a concise privacy-safe summary (roles, counts, status
codes, fingerprint/level vocabulary) — never resolved paths, never original
values, never vault rows, never reverse mappings.

## Artifacts and trust boundaries

| Artifact | Created where | Transferable? |
| --- | --- | --- |
| synthetic SOURCE | workspace `source/` (input, read-only) | n/a — demo input only |
| pseudonymized OUTPUT | workspace `output/` | only as a verified DATA_ONLY bundle |
| protected VAULT | workspace `protected/recovery.sqlite3` | NEVER — stays in the trusted environment |
| DATA_ONLY bundle | workspace `bundle/` | YES — the only transferable artifact |
| recovered copy | workspace `recovered/` | NEVER — internal-environment material |

(Roles are shown relative to the example workspace; the examples never print
resolved absolute paths.)

The protected vault (and every recovery artifact) must stay inside the
trusted internal environment and must NEVER be copied into a transfer.
The bundle directory is the only artifact designed to leave — and a DATA_ONLY
bundle is pseudonymized data, NOT anonymous data.

## CLI-ready configuration

The example policy and relationship documents are provided as real files so
the CLI recipe in `docs/operations.md` can be reproduced:

- [config/policy-data-only.json](config/policy-data-only.json) — the
  documented default policy with the DATA_ONLY index profile;
- [config/relationships.json](config/relationships.json) — the declared
  PK/FK relationship for the synthetic `people.dbf`/`orders.dbf` dataset
  (created by [synthetic_dataset.py](synthetic_dataset.py), which doubles as
  the demo-dataset generator for CLI experiments and carries the shared
  bounded transient-read resilience wrapper: the FIRST post-write read of a
  fresh DBF/FPT can transiently fail on Windows (antivirus/indexer file
  locks), so the examples retry ONLY the typed dependency error a few
  times).

## Pseudonymized is not anonymous

Reversible pseudonymized data plus the protected vault is recoverable by
authorized operators; DATA_ONLY output removes the direct recovery material
but remains pseudonymized data. Read
[../docs/pseudonymization-vs-anonymization.md](../docs/pseudonymization-vs-anonymization.md)
before making any statement about anonymity.