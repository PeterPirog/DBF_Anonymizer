# Index, VFP and DBC limitations (truthful capability boundaries)

This document states exactly what DBF_Anonymizer 1.0 does and does not claim
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
  supplied, and the backend's injected capability evidence decides what may be
  claimed. Without a real, authoritative backend the indexed profile cannot
  be used, and standalone runs without a backend honestly report the
  corresponding capability as unavailable.

## What structural indexes can and cannot claim

- A structural index (CDX) can only be claimed REBUILT or VALIDATED after a
  backend verification; absent that verification DBF_Anonymizer reports the
  index state as unverified and does not copy stale index artifacts as valid.
- Standalone IDX files are separately inventoried and reported as standalone
  index evidence; they are never silently merged into a structural index
  claim.
- A DBC-bound source remains reported as DBC-bound: the truthfulness of the
  source's database-container binding is preserved in the output and in the
  public results. Direct Write standalone output does NOT imply preservation
  of DBC rules, triggers, persistent relations, views or stored procedures —
  those live in the DBC/VFP project layer, not in the standalone DBF/FPT
  files.
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
- No claim that REQ-P6-006 (frozen authoritative VFP index/DBC metadata
  producer/consumer contract) is complete. P6-006 remains BLOCKED/DEFERRED
  because the frozen authoritative metadata contract from
  mcp-vfp9sp2-toolchain is not yet available.

## Where authoritative VFP metadata would come from

The only supported path for authoritative VFP/DBC/CDX project metadata is the
downstream mcp-vfp9sp2-toolchain integration (adapter boundary only). When
such a host supplies authoritative metadata, DBF_Anonymizer binds it
fail-closed through the declared relationship/index contract and reports
backend-verified index results; when it does not, DBF_Anonymizer keeps
reporting the standalone truth. See [mcp-integration.md](mcp-integration.md)
for the boundary. DBF_Anonymizer never launches VFP and never reads VFP
installations.

## Runtime boundary reminder

The installed runtime is offline and install-free: no HTTP, no package index,
no Git, no subprocess execution during operation (see
[operations.md](operations.md), offline installation). The DBF/FPT boundary is
the public `dbfbridge[write]>=1.1.0,<2` distribution; DBF_Anonymizer
implements no DBF/FPT parsing or writing of its own.