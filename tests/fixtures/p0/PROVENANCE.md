# REQ-P0-003 — Synthetic fixture corpus provenance

Status: deterministic, redistributable, synthetic-only evidence corpus for the
immutable requirement `REQ-P0-003` of
`DBF_ANONYMIZER_TARGET_ARCHITECTURE_CONVERGE_FINAL_2026-09-10.md`.
Machine-readable inventory: `manifest.json` (schema `req-p0-003/1`).

## Synthetic origin — objective statement

Every artifact in this directory is **synthetic**. It was generated from
literal, deterministic constants by `tools/generate_p0_fixtures.py` through
the **public** dbfbridge **1.1.0** Direct Write API
(`dbfbridge.write_table` with public `TableSchema`/`FieldInfo`/`DirectRecord`
models) and verified through the public Direct Read API
(`read_schema`, `iter_records`, `inspect_table`).

- **No production, customer or organizational DBF/FPT/CDX/IDX/DBC content was
  used, viewed or copied.** No data was taken from any file on this machine;
  every value (including all text strings, keys, dates and binary payloads)
  is a constant defined in the generator source.
- Text strings are the classic Polish pangram "Zażółć gęślą jaźń" plus
  explicit `SYNTH-*` markers; keys are `KEY0001`-style placeholders.
- Binary memo payloads (`MEMO_BINARY`, `GENERAL_PAYLOAD`, `PICTURE_PAYLOAD`)
  are deterministic synthetic byte strings defined in the generator; no real
  document, image or file content is embedded.

## How each fixture class was generated

| Class | Method |
| --- | --- |
| Valid DBF tables | public `write_table()` with a public `TableSchema`; scalar, codepage, nullable, topology and memo tables |
| FPT companion | produced by public `write_table()` for memo-bearing tables (deterministic memo block size 64) |
| `text_mazovia.dbf` | public `write_table()` with language driver `0x69` and encoding `mazovia` (the Mazovia OEM page; PIAST is the same codec table under its public alias) |
| `text_cp852.dbf` | public `write_table()` with language driver `0x64` (`cp852`) |
| cp1250 tables | public `write_table()` with language driver `0xC8` |
| `nullable_varchar.dbf` | dialect `0x32` with a Varchar field, nullable application fields and the writer-managed `_NULLFLAGS` system column; the bitmap column width follows the canonical VFP allocation and is re-validated by the public Direct Write contract |
| `missing_memo_companion.dbf` | produced by construction: a valid synthetic memo table was built in a temporary staging directory through public `write_table()` and only the DBF was published; the FPT companion was intentionally not shipped |
| malformed DBFs | three documented deterministic mutations of wholly synthetic tables (see below), applied in temporary staging by the generator and published as new artifacts |

### Intentionally malformed artifacts and their exact provenance

All three malformed artifacts were built from a synthetic 3-row table
(`KEY` C(8), `AMOUNT` N(8,2)) generated in a temporary staging directory and
are NOT valid inputs by design:

1. `malformed/truncated_records.dbf` — exactly one trailing record image
   (17 bytes) was removed from the byte image of a synthetic table
   (`truncated_records.dbf` keeps `len(data) - record_length` bytes).
2. `malformed/unknown_version.dbf` — header byte 0 was set to `0x99`
   (single-byte mutation).
3. `malformed/corrupt_header_length.dbf` — header bytes 8-9 were set to the
   little-endian value 65000, declaring a header length far beyond EOF
   (2-byte mutation).

The mutation code lives only in `tools/generate_p0_fixtures.py` (test/fixture
tooling, never `src/dbf_anonymizer`), performs only the smallest documented
mutation, and never touches anything but artifacts this tool itself created.
It is not a DBF parser or writer.

## Explicitly declared gaps (no fabricated artifacts)

The following REQ-P0-003 dimensions are **not** covered by committed
artifacts because no public dbfbridge 1.1.0 mechanism can produce
architecture-truthful artifacts for them; fabricating them is forbidden:

- `structural_cdx_metadata` — `write_table()` accepts
  `schema.has_structural_cdx=True` and reports
  `structural_cdx`/`index_rebuild_required` with the authoritative warning,
  but the published header flag is not persisted and no CDX file is created.
- `dbc_bound_metadata` — Direct Write publishes standalone tables; no
  public mechanism writes the VFP 263-byte DBC backlink.
- `standalone_idx_inventory` — no public mechanism writes standalone `.idx`
  artifacts and no index writer may be implemented here.

These gaps are machine-declared in `manifest.json` (`gaps`) and verified by
tests. Authoritative CDX/IDX/DBC evidence belongs to REQ-P6 with the VFP
toolchain. `dbfbridge`-supported negative/opaque user-field cases are covered
as negative-construction and negative-read evidence (typed refusals and typed
read failures) instead of fabricated DBFs with unsupported field types.

## Licensing / redistributability

The fixtures are original synthetic test data created for this repository.
They contain no third-party content and are distributed under the same MIT
license as the repository. Redistribution is intended: every artifact is
self-contained, path-free and deterministic.

## Regeneration and verification

- Deterministic regeneration:
  `python tools/generate_p0_fixtures.py --out <dir>` (pinned `last_update`,
  fixed records; requires the pinned tested artifact
  `dbfbridge[write]==1.1.0`, see `requirements/p0-dbfbridge-tested.txt`).
  Re-running the generator reproduces byte-identical artifacts (verified by
  `test_regeneration_is_byte_deterministic`).
- Committed-artifact verification:
  `python -m pytest tests/test_p0_fixture_corpus.py` verifies every declared
  artifact's existence and SHA-256, rejects undeclared artifacts, and
  re-verifies every manifest claim through public dbfbridge APIs.

## Facts verified before claiming

All public-API facts stated above (round trips, typed errors, codepage
round trips, trailing-space semantics, `write_table` refusals and the
structural-CDX flag behavior) were verified empirically against the pinned
public distribution `dbfbridge==1.1.0` before being encoded here.  No
property is claimed beyond what the committed tests assert.