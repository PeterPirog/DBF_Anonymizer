# Index, VFP and DBC limitations (truthful capability boundaries)

This document states exactly what DBF_Anonymizer (the current 1.0.0.dev0
development line, targeting the stable 1.0 contract) does and does not claim
about Visual FoxPro indexes, DBC containers and VFP project integration. It is
deliberately conservative: unsupported or unverified capabilities are reported
honestly, never glossed over.

## Output profiles

The `indexes.profile` policy section supports exactly two profiles:

- `DATA_ONLY` (default) — the output is a fresh, standalone DBF/FPT dataset
  where supported. Structural index artifacts from the source are NOT copied
  into the output as valid: stale CDX/IDX/DBC artifacts are never transferred
  or claimed as rebuilt. The transfer bundle additionally refuses any
  `.cdx`/`.idx`/`.dbc`/`.dct`/`.dcx` artifact by construction.
- `VFP_INDEXED` — an opt-in profile for indexed output. It REQUIRES
  authoritative backend evidence: an `IndexBackend` implementation must be
  explicitly injected by the host, and the backend's injected capability
  evidence decides what may be claimed. The injected backend must declare the
  authoritative index-backend protocol schema version `1.2` (the public
  `INDEX_BACKEND_PROTOCOL_SCHEMA_VERSION` contract). Without a real,
  authoritative backend the indexed profile cannot be used, and standalone
  runs without a backend honestly report the corresponding capability as
  unavailable.

## What structural indexes can and cannot claim

- A structural index (CDX) can only be claimed REBUILT or VALIDATED after a
  backend verification; absent that verification DBF_Anonymizer reports the
  index state as unverified and does not copy stale index artifacts as valid.
- Standalone IDX files are separately inventoried and reported as standalone
  index evidence; they are never silently merged into a structural index
  claim.
- A DBC-bound source remains reported as DBC-bound in the source inventory,
  the plan and the public source facts: the truthfulness of the SOURCE's
  database-container binding is never lost from the inventory. That reporting
  describes the source only — it is not an output claim. Fresh Direct Write
  output is STANDALONE data unless authoritative higher-level metadata is
  injected by the host, and the standalone output schema does NOT retain the
  source DBC binding or the source DBC backlink. Standalone output therefore
  does NOT imply preservation of DBC rules, triggers, persistent relations,
  views or stored procedures — those live in the DBC/VFP project layer, not
  in the standalone DBF/FPT files, and DBF_Anonymizer invents, rewrites or
  copies none of them. The DATA_ONLY transfer additionally omits
  DBC/DCT/DCX and stale CDX/IDX artifacts by construction.
- Unsupported or unverified capabilities are reported honestly in
  `capabilities()` output and in typed results; nothing pretends success.

## What DBF_Anonymizer does NOT claim

- No automatic VFP project understanding: DBF_Anonymizer does not read, infer
  or reconstruct VFP project semantics, DBC stored procedures, views or
  triggers.
- No claim that a standalone Direct Write output preserves DBC-side rules or
  behaviors.
- No claim that stale CDX/IDX/DBC files are valid after transfer: they are
  excluded from DATA_ONLY bundles by construction.
- No claim that REQ-P6-006 turns DBF_Anonymizer into a VFP analyzer:
  DBF_Anonymizer owns and ships the external VFP relationship/index metadata
  CONSUMER contract (see
  [external-vfp-metadata-contract.md](external-vfp-metadata-contract.md)),
  while the concrete VFP/DBC/CDX project knowledge stays owned by the
  downstream host, and authoritative claims may affect mapping/relationship
  assurance only under the implemented per-claim
  provenance/authority/assurance/verification rules.

## Where authoritative VFP metadata comes from

The supported path for authoritative VFP/DBC/CDX project metadata is the
downstream mcp-vfp9sp2-toolchain integration (adapter boundary only): the host
gathers authoritative project knowledge, emits a conforming
producer-independent transport-neutral JSON metadata document, and injects it
through DBF_Anonymizer's existing public synchronous planning boundary, where
it is validated, fingerprinted and bound fail-closed (see
[external-vfp-metadata-contract.md](external-vfp-metadata-contract.md) and
[mcp-integration.md](mcp-integration.md) for the boundary). Injected metadata
does NOT recreate source DBC semantics in the standalone output, and an
injected verified index claim does NOT by itself prove that an output CDX/IDX
was rebuilt: output index validity still requires the appropriate
authoritative backend rebuild/verification evidence. When no host supplies
metadata, DBF_Anonymizer keeps reporting the standalone truth.

Within the standalone core boundary, default operation and import/capability
discovery require no VFP, no COM, start no VFP/index subprocess, contact no
network, and never scan the machine for VFP installations: the standalone
core does not search for, probe or auto-discover any VFP installation, and
import/capability discovery does not instantiate COM, does not discover or
search for VFP, starts no subprocesses, and has no import-time VFP backend
dependency. `VFP_INDEXED` is deliberately different: the host explicitly
injects an authoritative `IndexBackend`, and that injected backend — under
the host's own policy, outside the standalone core boundary — may perform
the authoritative VFP work, including launching VFP. That backend capability
is legitimate and is never denied by this boundary; what the core itself
never does is discover or launch VFP on its own.

## Runtime boundary reminder

The installed runtime is offline and install-free. The P7-004 runtime
guarantee is: no HTTP, no Git, no package installation, no dependency
download (see [operations.md](operations.md), offline installation). It is
not a blanket prohibition on every process in every scenario: the default
standalone run with `index_backend=None` starts no VFP/index subprocess, and
an explicitly injected `IndexBackend` performs its authoritative VFP work
outside the standalone core boundary under the host's policy. The DBF/FPT
boundary is the public `dbfbridge[write]>=1.1.0,<2` distribution;
DBF_Anonymizer implements no DBF/FPT parsing or writing of its own.