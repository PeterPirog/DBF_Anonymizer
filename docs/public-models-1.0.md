# DBF_Anonymizer 1.0 — public model contract

Status: frozen stable 1.0 contract (REQ-P8-001 freeze; REQ-P1-002 delivered).

DBF_Anonymizer 1.0 is a clean-slate API. The historical 0.3 Python API is not a compatibility target. The public contract is the set of immutable data models exported from `dbf_anonymizer`.

## Design rules

- Public models are frozen dataclasses and use immutable tuples for collections.
- Every model exposes `to_dict()` and serializes to a JSON-safe dictionary.
- Every serialized model contains `schema_version = "1.8"` and an explicit `model_type`.
- Public paths are relative only and are normalized to POSIX separators (`/`). Absolute paths, drive-qualified Windows paths and `..` traversal are rejected.
- Public result/progress models contain operational codes, counters, fingerprints and normalized relative paths, not original DBF values, memo payloads, reverse mappings, vault contents, secrets or arbitrary diagnostic messages.
- The package ships `py.typed`; the public source tree is checked with `mypy --strict`.
- The complete frozen operation surface (the synchronous public root operations and the standalone CLI) is part of the same stable 1.0 contract; see [public-contract-1.0.md](public-contract-1.0.md) and [operations.md](operations.md).

## Public models

| Model | Purpose |
|---|---|
| `Capabilities` | Runtime feature/dependency capability facts. |
| `DatasetIdentity` | Opaque dataset identity, source fingerprint and normalized table paths. |
| `TablePlan` | Per-table planning facts without source values. |
| `PolicySummary` | Sanitized policy metadata and transformation-class summary. |
| `RelationshipMetadata` | Sanitized relationship metadata provenance/fingerprint. |
| `RelationalAssurance` | Explicit relationship-assurance result and counts. |
| `Plan` | Dataset-level immutable planning contract. |
| `ProgressEvent` | Privacy-safe machine event using codes and counters, not free-form messages. |
| `PreflightResult` | Readiness plus check/warning/error codes. |
| `PseudonymizationResult` | Sanitized output summary and relational assurance. |
| `VerificationResult` | Verification outcome and relational assurance. |
| `RecoveryResult` | Recovery output summary; this is the new 1.0 type, not the historical 0.3 implementation. |
| `TransferBundleResult` | Transfer-bundle publication/verification summary. |

Two public enums support these models:

- `RelationalAssuranceLevel`: `GLOBAL_EXACT_VALUE`, `DECLARED_RELATIONS_VERIFIED`, `VFP_METADATA_VERIFIED`, `INCOMPLETE`.
- `TransferProfile`: `DATA_ONLY`, `VFP_INDEXED`.

## Example

```python
from dbf_anonymizer import DatasetIdentity

identity = DatasetIdentity(
    dataset_id="dataset-001",
    source_fingerprint="sha256:example",
    table_paths=("north\\registry.dbf",),
)

assert identity.table_paths == ("north/registry.dbf",)
print(identity.to_dict())
```

The resulting dictionary is suitable for JSON transport. It deliberately contains no absolute source location or source record values.

## Compatibility policy

This is a frozen stable 1.0 contract. Backward-incompatible changes to the
model contract require a MAJOR version bump under the semantic-versioning
rules of [public-contract-1.0.md](public-contract-1.0.md); additive changes
still require deliberate updates to the relevant schema version, snapshot,
tests and documentation. Historical 0.3 names and semantics do not constrain
this contract.
