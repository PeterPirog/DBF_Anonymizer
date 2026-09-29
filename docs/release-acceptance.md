# Release acceptance (REQ-P8-002)

One deterministic command proves the whole 1.0 release candidate from a clean
commit:

```console
python tools/run_release_acceptance.py --output-dir build/p8-release-acceptance
```

CI executes the same single entry point through
[`.github/workflows/p8-release-acceptance.yml`](../.github/workflows/p8-release-acceptance.yml).
The command is fail-closed: any failed stage writes a manifest with
`final_status: FAIL` and exits non-zero.  A failing test never regenerates a
snapshot or any evidence, and the tool refuses to run when the tracked working
tree is dirty.

## Stages

| Stage | Evidence |
| --- | --- |
| `source_binding` | exact clean-tree check, commit SHA, package version, Python/platform identity, frozen contract hash |
| `quality_gates` | `ruff format --check .`, `ruff check .`, `mypy --strict src/dbf_anonymizer`, `compileall -q src tests tools`, the full test suite |
| `public_contract_freeze` | `tests/test_p8_contract_freeze.py` (REQ-P8-001 snapshot never auto-updated) |
| `dependency_audit` | `pip check` and the exact pinned acceptance artifact from `requirements/p0-dbfbridge-tested.txt` |
| `release_build` | the reproducible two-build evidence bundle (`tools/build_release_evidence.py`), independent fail-closed verifier, tamper self-test, and the copied release candidate (wheel + sdist, hashes re-verified) |
| `offline_fresh_wheel` | wheelhouse validation, fresh venv, `--no-index` install of the exact release wheel, `pip check`, pinned-artifact check |
| `installed_wheel_contract` | installed-wheel recovery-boundary contract and the nine-command standalone runtime contract under network/process sentinels |
| `canonical_roundtrip` | synthetic declared PK/FK dataset through `build_plan -> preflight -> pseudonymize -> verify_dataset -> DATA_ONLY bundle -> standalone verify (source absent) -> recover -> logical oracle`, from the INSTALLED wheel, with forbidden-artifact and canary scans |
| `no_vfp_standalone` | hosted no-VFP import-purity and standalone workflow smoke |
| `evidence_manifest` | deterministic aggregation into `release-acceptance-evidence.json` + SHA-256 sidecar |

The first six stages are the ONLINE PREPARATION phase (including the public
PyPI wheelhouse download performed by the accepted P7-008 tool); the last
three stages are the OFFLINE RUNTIME ACCEPTANCE phase: local wheels only,
`--no-index`, controlled pip cache, no runtime HTTP, no Git, and no package
installation after the environment is prepared.

## Evidence manifest

`release-acceptance-evidence.json` (schema `1.0`, kind
`dbf-anonymizer-release-acceptance-manifest`) is deterministic, sorted-key,
and privacy-safe: no absolute machine paths, usernames, source values,
pseudonyms, reverse mappings or recovery material.  It binds the exact
commit, the frozen public contract snapshot hash, the release candidate
wheel/sdist hashes, the exact dbfbridge pin/install/provenance, per-stage
results, and the fail-closed `final_status`.  Its SHA-256 is written to
`release-acceptance-evidence.sha256`.

Dependency provenance proves the tested artifact is the intended public
acceptance artifact: the exact pin `dbfbridge[write]==1.1.1` satisfies the
runtime range `dbfbridge[write]>=1.1.0,<2`, the installed version matches the
pin in both the main and the fresh environment, the wheelhouse artifact hash
is recorded, and no VCS/local direct URL is present.

## VFP evidence

The manifest records VFP truthfully with the project vocabulary.  This
workflow never schedules a trusted VFP machine and claims no real-VFP
capability: `vfp_evidence_status` is `NOT_RUN`,
`real_vfp9_execution_claimed` is `false`, and the standalone no-VFP path
remains fully valid.  Real VFP execution stays the isolated
workflow_dispatch/main-only trusted lane (`p6-trusted-vfp-acceptance.yml`).

## Scope

REQ-P6-006 remains **BLOCKED/DEFERRED** (no consumer fixture is invented) and
REQ-P8-003 is **NOT STARTED**.  The package version remains `1.0.0.dev0`;
this acceptance produces a release candidate, not a stable publication.