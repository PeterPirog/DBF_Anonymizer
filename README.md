# DBF_Anonymizer

Clean-slate 1.0 development baseline. DBF_Anonymizer will pseudonymize Visual
FoxPro DBF/FPT datasets while keeping one protected, reversible SQLite recovery
vault inside the internal environment, and produce transferable
pseudonymized data-only bundles.

- Distribution: `dbf-anonymizer`
- Import package: `dbf_anonymizer`
- Development version: `1.0.0.dev0` (no stable release declared yet)
- DBF/FPT boundary: the public `dbfbridge[write]>=1.1.0,<2` distribution
  (Direct Read + Direct Write); DBF_Anonymizer implements no DBF/FPT parsing
  or writing of its own.

The 1.0 line has no compatibility obligation toward the historical 0.3 API,
CLI, JSONL pipeline, salt-based generator or legacy recovery formats; see
[docs/migration-1.0-clean-slate.md](docs/migration-1.0-clean-slate.md).

The public 1.0 operation surface and CLI are specified by the immutable target
architecture and are under active development; this repository does not yet
ship working 1.0 product operations.

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