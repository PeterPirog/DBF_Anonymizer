# DBF_Anonymizer 1.0 — public model contract

Status: development contract for `REQ-P1-002`.

DBF_Anonymizer 1.0 is a clean-slate API. The historical 0.3 Python API is not a compatibility target. The first public contract is therefore the set of immutable data models exported from `dbf_anonymizer`.

## Design rules

- Public models are frozen dataclasses and use immutable tuples for collections.
- Every model exposes `to_dict()` and serializes to a JSON-safe dictionary.
- Every serialized model contains `schema_version = "1.0"` and an explicit `model_type`.
- Public paths are relative only and are normalized to POSIX separators (`/`). Absolute paths, drive-qualified Windows paths and `..` traversal are rejected.
- Public result/progress models contain operational codes, counters, fingerprints and normalized relative paths, not original DBF values, memo payloads, reverse mappings, vault contents, secrets or arbitrary diagnostic messages.
- The package ships `py.typed`; the public source tree is checked with `mypy --strict`.
- Future service functions are intentionally absent until `REQ-P1-004`. No placeholder operation reports success.

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

## Compatibility policy before 1.0

These contracts are being designed for the first real release. Until the repository reaches the Phase 8 contract freeze, breaking improvements may still be made when they improve correctness, privacy, or usability. Historical 0.3 names and semantics do not constrain this design.
