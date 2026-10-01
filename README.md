# DBF_Anonymizer

Stable 1.0 release (clean-slate architecture). DBF_Anonymizer pseudonymizes
Visual FoxPro DBF/FPT datasets while keeping one protected, reversible SQLite
recovery vault inside the internal environment, and produces transferable
pseudonymized data-only bundles.

- Distribution: `dbf-anonymizer`
- Import package: `dbf_anonymizer`
- Version: `1.0.0` (stable)
- DBF/FPT boundary: the public `dbfbridge[write]>=1.1.0,<2` distribution
  (Direct Read + Direct Write); DBF_Anonymizer implements no DBF/FPT parsing
  or writing of its own.

The 1.0 line has no compatibility obligation toward the historical 0.3 API,
CLI, JSONL pipeline, salt-based generator or legacy recovery formats; see
[docs/migration-1.0-clean-slate.md](docs/migration-1.0-clean-slate.md).

The public 1.0-line operation surface (the frozen stable 1.0 contract) is the
synchronous, transport-neutral
package root `dbf_anonymizer` (capabilities, build_plan, preflight,
pseudonymize, verify_dataset, recover, create_transfer_bundle,
verify_transfer_bundle) plus the standalone `dbf-anonymizer` console script
with exactly nine commands: `capabilities`, `plan`, `preflight`,
`pseudonymize`, `verify`, `recover`, `export-bundle`, `verify-bundle`,
`self-test`. DBF_Anonymizer is not an MCP server: it ships no transport, no
authentication/authorization and no job orchestration — those belong to the
downstream host (see [docs/mcp-integration.md](docs/mcp-integration.md)).

**Pseudonymized is not anonymous.** Reversible data with a protected recovery
vault is pseudonymized data; DATA_ONLY output removes direct recovery
material but is still not anonymized. See
[docs/pseudonymization-vs-anonymization.md](docs/pseudonymization-vs-anonymization.md).

## Documentation

English-first operational and security documentation (validated by
`tests/test_p7_documentation_contract.py`, including executable examples):

- [docs/operations.md](docs/operations.md) — internal-network offline
  installation, one-vault-per-dataset operation, policy configuration,
  relationship configuration, pseudonymization, verification, recovery, and
  DATA_ONLY transfer bundles, with executable examples.
- [docs/limits-and-integrity.md](docs/limits-and-integrity.md) — index/VFP/DBC
  limitations, the VFP_INDEXED backend-evidence requirement and the
  authoritative-metadata boundaries.
- [docs/external-vfp-metadata-contract.md](docs/external-vfp-metadata-contract.md) —
  the package-owned, producer-independent external VFP relationship/index
  metadata consumer contract (versioned JSON Schema shipped with the wheel).
- [docs/mcp-integration.md](docs/mcp-integration.md) — how a downstream host
  (mcp-vfp9sp2-toolchain) wraps the synchronous public API.
- [docs/threat-model.md](docs/threat-model.md) — protected/transferable
  assets, trust boundaries, attack/failure classes.
- [docs/pseudonymization-vs-anonymization.md](docs/pseudonymization-vs-anonymization.md) —
  the pseudonymized-vs-anonymous distinction.
- [docs/public-models-1.0.md](docs/public-models-1.0.md) — public model
  contract.
- [docs/errors-1.0.md](docs/errors-1.0.md) — public error contract.
- [docs/public-contract-1.0.md](docs/public-contract-1.0.md) — frozen 1.0
  contract matrix and semantic-versioning rules.
- [docs/release-acceptance.md](docs/release-acceptance.md) — the one-command
  REQ-P8-002 release-acceptance entry point and evidence manifest.
- [docs/vault-protection.md](docs/vault-protection.md) — protected vault
  security notes.
- [docs/migration-1.0-clean-slate.md](docs/migration-1.0-clean-slate.md) —
  1.0 clean-slate reset.

## Development

```text
python -m pip install -e ".[dev]"
python -m pip install -r requirements/p0-dbfbridge-tested.txt
python -m pytest
python -m build
```

The P0 acceptance environment uses the exact public dbfbridge artifact pinned
in `requirements/p0-dbfbridge-tested.txt` (REQ-P0-002); the runtime metadata
range stays `dbfbridge[write]>=1.1.0,<2`.

P0 boundary evidence lives in `tests/` (dependency contract, public dbfbridge
capability contract, architecture boundary, root public API regression) and is
proven from a clean environment by `.github/workflows/p0-package-boundary.yml`.
Operational release evidence (reproducible distributions, SBOM, tamper-evident
manifest) is produced by `tools/build_release_evidence.py` and validated by
`.github/workflows/p7-release-evidence.yml`.
