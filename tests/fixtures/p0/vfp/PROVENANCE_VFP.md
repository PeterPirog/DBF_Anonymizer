# REQ-P0-003 — VFP9-generated index/container fixture provenance

Status: authoritative, committed, fully synthetic evidence artifacts for the
three index/container dimensions of the immutable requirement `REQ-P0-003`
(structural-CDX metadata, DBC-bound metadata, standalone IDX inventory).

## Authoritative producer

The artifacts in this directory were **created by Visual FoxPro 9.0 itself**
(`Visual FoxPro 09.00.0000.5815 for Windows`, automation ProgID
`VisualFoxPro.Application`) from the committed generation program
[`generate_vfp_fixtures.prg`](generate_vfp_fixtures.prg). DBF_Anonymizer does
**not** implement CDX/IDX/DBC generation; VFP9 is the authoritative producer
for these index/container evidence artifacts. No DBF header bytes were
modified by any tool; no custom CDX/IDX/DBC parser or writer exists in
DBF_Anonymizer; no pre-existing sample files were reused.

Machine-readable verification record:
[`vfp_fixture_evidence.json`](vfp_fixture_evidence.json) (evidence schema
version 1.0). Raw VFP verification log (sanitized):
[`vfp_gen_log.txt`](vfp_gen_log.txt).

## Generation (deterministic synthetic constants only)

- Table schema for all three families: `CODE C(10), AMOUNT N(10,2), NOTE C(20)`.
- Record values are the constants `KEY0001`..`KEY0004`, `100`, `200`,
  `SYNTH-A`, `SYNTH-B`; 4 records per table.
- No production, customer or organizational data was read or used.

## Families and VFP verification results (from the committed evidence record)

1. **Structural CDX** — `structural/indexed_table.dbf`:
   `INDEX ON CODE TAG SYNTHCODE` + `INDEX ON NOTE TAG SYNTHNOTE` created the
   structural `INDEXED_TABLE.CDX` (2 tags: `SYNTHCODE -> CODE`,
   `SYNTHNOTE -> NOTE`). The table was closed and reopened in VFP;
   `SET ORDER TO TAG SYNTHCODE` then `ORDER()` = `SYNTHCODE`;
   `RECCOUNT()` = 4. Through the public pinned `dbfbridge==1.1.1` API:
   `has_structural_cdx = true`, `companion_cdx_present = true`.
2. **DBC-bound** — `dbc/dbc_bound_table.dbf` + `fixture.dbc`/`fixture.dct`/
   `fixture.dcx`: the table was created inside a fresh minimal DBC; VFP
   reopened the DBC and the table (`INDBC(...) = .T.`, `RECCOUNT()` = 4).
   Through the public API: `dbc_bound = true`, `is_database_container = false`,
   `dbc_backlink_path = "..\fixture.dbc"` — a genuine VFP-written relative
   backlink. The committed layout preserves it unchanged: the DBF lives in
   `vfp/dbc/` and resolves `..\fixture.dbc` to `vfp/fixture.dbc`. The binary
   backlink bytes are NOT patched.
3. **Standalone IDX** — `idx/standalone_idx_table.dbf` + `idx/code_idx.idx`:
   VFP ran `INDEX ON CODE TO code_idx`; the table and IDX were closed and
   reopened, `SET INDEX TO CODE_IDX` succeeded, `ORDER()` = `CODE_IDX`
   (IDX base name), `RECCOUNT()` = 4. The table remains readable through the
   public dbfbridge API. IDX semantic validity is established by this VFP
   reopen/ORDER evidence, **not** by a handwritten parser; dbfbridge's public
   inspection surface does not report standalone IDX companions.

## Sanitization

- All committed files were scanned (case-insensitive raw-byte substring
  search, no binary structure parsing) for workspace-private path sentinels:
  drive-letter workspace prefixes, workspace and staging directory names,
  user-profile fragments and the local user name — **zero hits** in all 8
  binary artifacts.
- The raw VFP log printed one absolute staging path inside the DBC result
  line; the committed `vfp_gen_log.txt` masks exactly that path fragment as
  `<sanitized-staging-path>\FIXTURE.DBC`. `vfp_fixture_evidence.json` carries
  the same masking (`dbc_value_after_close_sanitized`), and its scan-sentinel
  list is masked for commit (the unmasked literals existed only in the
  ephemeral staging cycle).
- No VFP executable paths, user identities, secrets or real source data are
  present. All artifact paths in evidence and manifest are relative.

## Integrity and verification policy

- The 8 binary artifacts are committed byte-for-byte after independent
  SHA-256 recomputation; every hash is recorded in `manifest.json` and in the
  evidence record. Commit-time verification re-hashes each artifact and fails
  on any mismatch.
- Static committed binaries are verified by cryptographic hashes plus public
  dbfbridge metadata facts; no Python CDX/IDX/DBC parser exists.
- VFP semantic facts (tags, reopen, ORDER, record counts) come from the
  authoritative committed VFP evidence record, not from re-parsing binaries.

## Regeneration scope (explicit, non-faked)

- The dbfbridge-generated fixture subset is deterministically regenerable by
  `tools/generate_p0_fixtures.py` (byte-identical, proven by test).
- The VFP9-generated subset is **static committed evidence**: CI verifies its
  committed SHA-256 values and the public metadata facts, and does NOT
  require VFP/COM. The committed `generate_vfp_fixtures.prg` reproduces the
  same synthetic schema/data/index/container semantics in a VFP9-enabled
  environment; byte-identical VFP regeneration has NOT been proven and is
  NOT claimed — the committed, hash-verified binaries are the deterministic
  evidence. The ordinary CI corpus regeneration test copies this committed
  static VFP evidence byte-for-byte, which verifies the committed corpus,
  not VFP byte-determinism.

## Licensing

Same as the corpus: original synthetic test data, MIT-licensed with the
repository, self-contained and redistributable.
