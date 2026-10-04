# DBF_Anonymizer

Stable 1.0 contract (clean-slate architecture); the package version is
`1.0.0` (stable). Public PyPI publication is a separate privileged release
process and is not proven by repository metadata alone. DBF_Anonymizer
pseudonymizes
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

## Installation

The package version is stable `1.0.0`. Public PyPI publication is a separate
privileged release lane and has NOT happened; repository metadata alone does
not prove a public package. Until publication, install from a built wheel:

```powershell
python -m build
python -m pip install --no-cache-dir dist\dbf_anonymizer-1.0.0-py3-none-any.whl
```

For the internal-network offline installation (pinned wheelhouse, `--no-index`,
`--find-links`, no runtime downloads), see
[docs/operations.md](docs/operations.md).

## 5-minute quick start

The complete public API is the package root `dbf_anonymizer`. Replace the
placeholder paths with YOUR OWN authorized dataset paths (the fully
executable synthetic version of this workflow is
[examples/basic_workflow.py](examples/basic_workflow.py)):

```python
from pathlib import Path

import dbf_anonymizer as public

source = Path("<your-source-dataset>")  # read-only input (trusted environment)
output = Path("<your-pseudonymized-output>")  # written by pseudonymize
vault = Path("<protected>/recovery.sqlite3")  # ONE protected vault per dataset (trusted)

plan = public.build_plan(source, output, vault)
preflight_result = public.preflight(plan)
assert preflight_result.ready

result = public.pseudonymize(plan)
verification = public.verify_dataset(result, source=source, vault=vault)
assert verification.status is public.VerificationStatus.PASS
```

Failures are typed, privacy-safe, registry-controlled objects — never parse
exception text:

```python
try:
    plan = public.build_plan(source, output, vault, policy={"schema_version": 99})
except public.PolicyError as error:
    payload = error.to_dict()  # versioned JSON contract, no private material
    assert error.code is public.ErrorCode.POLICY_INVALID
```

Executable recipes (synthetic data, progressive complexity) live in
[examples/README.md](examples/README.md); the authoritative detailed guide is
[docs/operations.md](docs/operations.md).

## Safety model

- `SOURCE` stays in the trusted internal environment and is never modified.
- Exactly ONE protected `VAULT` spans the whole dataset. The vault is what
  makes the output recoverable — it belongs to the trusted environment and
  must NEVER be transferred or published.
- `DATA_ONLY` transfer bundles are the only transferable artifact: verified,
  standalone, free of vault/recovery material — pseudonymized data, NOT
  anonymous data.

## Documentation

English-first operational and security documentation (validated by
`tests/test_p7_documentation_contract.py`, including executable examples):

- [examples/README.md](examples/README.md) — the executable example recipes
  (synthetic data, progressive complexity, downstream-consumer adapter).
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
