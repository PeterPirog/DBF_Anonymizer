# REQ-P0-003 — Synthetic fixture corpus provenance

Status: deterministic, redistributable, synthetic-only evidence corpus for the
immutable requirement `REQ-P0-003` of
`DBF_ANONYMIZER_TARGET_ARCHITECTURE_CONVERGE_FINAL_2026-09-10.md`.
Machine-readable inventory: `manifest.json` (schema `req-p0-003/1`).

## Synthetic origin — objective statement

Every artifact in this directory is **synthetic**. It was generated from
literal, deterministic constants by one of the two legitimate generation
classes below; no production, customer or organizational DBF/FPT/CDX/IDX/DBC
content was used, viewed or copied. No data was taken from any file on this
machine; every value (including all text strings, keys, dates and binary
payloads) is a constant defined in the committed generator or in the
committed VFP generation program.

## The two legitimate generation classes

1. **Public dbfbridge-generated DBF/FPT fixtures** — created through the
   **public** dbfbridge **1.1.0** Direct Write API
   (`dbfbridge.write_table` with public `TableSchema`/`FieldInfo`/
   `DirectRecord` models) and verified through the public Direct Read API
   (`read_schema`, `iter_records`, `inspect_table`). These are deterministic
   and byte-identically regenerable (see Regeneration).
2. **VFP9-generated index/container fixtures** (`vfp/` subtree) — structural
   CDX, DBC-bound table with DBC/DCT/DCX companions and a standalone IDX,
   created by **Visual FoxPro 9 itself** per
   [`vfp/PROVENANCE_VFP.md`](vfp/PROVENANCE_VFP.md). DBF_Anonymizer does
   **not** implement CDX/IDX/DBC generation; VFP9 is the authoritative
   producer for those evidence artifacts. The committed binaries are verified
   by cryptographic hashes and public metadata checks only — no custom
   CDX/IDX/DBC parser exists in DBF_Anonymizer — and the standalone IDX
   semantic validity was verified through real VFP reopen/ORDER evidence,
   not by a handwritten parser.

## How each fixture class was generated

| Class | Method |
| --- | --- |
| Valid DBF tables | public `write_table()` with a public `TableSchema`; scalar, codepage, nullable, topology and memo tables |
| FPT companion | produced by public `write_table()` for memo-bearing tables (deterministic memo block size 64) |
| `text_mazovia.dbf` | public `write_table()` with language driver `0x69` and encoding `mazovia` (the Mazovia OEM page; PIAST is the same codec table under its public alias) |
| `text_cp852.dbf` | public `write_table()` with language driver `0x64` (`cp852`) |
| cp1250 tables | public `write_table()` with language driver `0xC8` |
| `nullable_varchar.dbf` | dialect `0x32` with a Varchar field, nullable application fields and the writer-managed `_NULLFLAGS` system column; the bitmap column width follows the canonical VFP allocation and is re-validated by the public Direct Write contract |
| `vfp/structural/*`, `vfp/dbc/*`, `vfp/idx/*` | created by VFP9 per `vfp/PROVENANCE_VFP.md` and the committed authoritative evidence record |
| `missing_memo_companion.dbf` | produced by construction: a valid synthetic memo table was built in a temporary staging directory through public `write_table()` and only the DBF was published; the FPT companion was intentionally not shipped |
| malformed DBFs | three documented deterministic mutations of wholly synthetic tables (see below), applied in temporary staging by the generator and published as new artifacts |

### Intentionally malformed artifacts and their exact provenance

All three malformed artifacts were built from a synthetic 3-row table
(`KEY` C(8), `AMOUNT` N(8,2)) generated in a temporary staging directory and
are NOT valid inputs by design:

1. `malformed/truncated_records.dbf` — exactly one trailing record image
   (17 bytes) was removed from the byte image of a synthetic table.
2. `malformed/unknown_version.dbf` — header byte 0 was set to `0x99`
   (single-byte mutation).
3. `malformed/corrupt_header_length.dbf` — header bytes 8-9 were set to the
   little-endian value 65000, declaring a header length far beyond EOF
   (2-byte mutation).

The mutation code lives only in `tools/generate_p0_fixtures.py` (test/fixture
tooling, never `src/dbf_anonymizer`), performs only the smallest documented
mutation, and never touches anything but artifacts this tool itself created.
It is not a DBF parser or writer. The VFP9-generated binaries are committed
byte-for-byte and are never rewritten or patched by any tool.

## Negative / opaque evidence

`dbfbridge`-supported negative/opaque user-field cases are covered as
negative-construction and negative-read evidence through the public API
(typed refusals of `Q`/`W` schemas and typed read failures
`FIELD_PROJECTION_INVALID`, `DBF_TRUNCATED`, `DBF_FORMAT_UNSUPPORTED`,
`FPT_REQUIRED_MISSING`) instead of fabricated DBFs with unsupported field
types.

## Licensing / redistributability

The fixtures are original synthetic test data created for this repository.
They contain no third-party content and are distributed under the same MIT
license as the repository. Redistribution is intended: every artifact is
self-contained, path-free and deterministic.

## Regeneration and verification

- Deterministic regeneration of the dbfbridge-generated subset:
  `python tools/generate_p0_fixtures.py --out <dir>` (pinned `last_update`,
  fixed records; the corpus originated with dbfbridge 1.1.0 and is
  byte-identically revalidated with the pinned tested artifact
  `dbfbridge[write]==1.1.1`, see `requirements/p0-dbfbridge-tested.txt`).
  The generator incorporates the committed static VFP evidence
  byte-for-byte (without modifying it) and re-verifies every VFP artifact
  hash against the committed authoritative evidence record. Re-running the
  generator reproduces the complete committed corpus byte-identically
  (verified by `test_regeneration_is_byte_deterministic`); this verifies the
  committed corpus, not that VFP itself is byte-deterministic on
  re-execution.
- The VFP9-generated subset is static committed evidence; ordinary hosted CI
  verifies committed SHA-256 values and public dbfbridge metadata facts and
  does NOT require VFP/COM. The committed VFP PRG reproduces the same
  synthetic schema/data/index/container semantics in a VFP9-enabled
  environment; byte-identical VFP regeneration has NOT been proven and is
  NOT claimed — the committed, hash-verified binaries are the deterministic
  evidence.
- Committed-artifact verification:
  `python -m pytest tests/test_p0_fixture_corpus.py` verifies every declared
  artifact's existence and SHA-256, rejects undeclared artifacts, and
  re-verifies every manifest claim through public dbfbridge APIs.

## Facts verified before claiming

All public-API facts stated above (round trips, typed errors, codepage
round trips, trailing-space semantics, `write_table` refusals, the
structural-CDX flag behavior, and the VFP9 evidence facts) were verified
empirically against public dbfbridge 1.1.0, revalidated against the pinned
public distribution `dbfbridge==1.1.1`, and checked against the committed
authoritative VFP evidence record before being encoded here.
No property is claimed beyond what the committed tests assert.
