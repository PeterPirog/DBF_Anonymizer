# Frozen public contract 1.0

REQ-P8-001 freezes the stable 1.0 contract in
[`contracts/public-contract-1.0.json`](../contracts/public-contract-1.0.json).
The frozen package version state is `1.0.0` (the stable version). Public PyPI
publication is a separate privileged release process; repository metadata alone
does not prove that a public publication has happened.
Normal test execution never updates the snapshot. A maintainer may explicitly
regenerate it with:

```console
python tools/generate_public_contract_snapshot.py --write
```

Any snapshot change requires review as a public-contract decision. The
acceptance test compares independently collected runtime/source facts against
the committed literal values. Its negative tests mutate an in-memory copy of
that normalized actual contract and require the detector to report the
affected contract path.

This freeze covers the completed DBF_Anonymizer-side contract: REQ-P6-006
(the producer-independent external VFP metadata contract), REQ-P8-002 (the
release-acceptance entry point) and REQ-P8-003 (the downstream-consumer
acceptance contract) are complete, with acceptance evidence in
[release-acceptance.md](release-acceptance.md) and the P8 test suites. No
external consumer fixture was invented for the freeze itself.

## Freeze matrix

| Contract surface | Authoritative source | Current value/version | Existing test evidence | Pre-freeze gap (historical) | Freeze evidence |
| --- | --- | --- | --- | --- | --- |
| Package-root Python API | `dbf_anonymizer.__all__` | Exact exported 1.0 symbol set | `test_root_public_api.py` | No cross-contract snapshot | `python_api.root_exports` |
| Public callable signatures | Package-root callables | Eight synchronous operations with normalized parameter kinds/defaults | `test_p7_transport_boundary.py` | Signatures not frozen together | `python_api.callables` |
| Public enums/models/types | `models.py`, `errors.py`, `recovery_policy.py` | Exact enum values and public model fields | `test_p1_public_models.py`, P7 JSON snapshot | Separate snapshots only | `public_json.enums`, `public_json.model_fields` |
| CLI command set | `cli.COMMANDS` | Nine commands, no tenth command | P7 documentation/offline tests | No 1.0 umbrella snapshot | `cli.command_order` |
| CLI stable arguments | `cli._build_parser()` | Exact positional/options, actions, defaults, choices and types | CLI tests | Argument semantics not centrally frozen | `cli.commands` |
| Model JSON schema | `MODEL_SCHEMA_VERSION` | `1.8` | `test_p7_public_json_contract.py` | Separate schema snapshot | `public_json.schema_versions.model` |
| Error JSON schema | `ERROR_SCHEMA_VERSION` | `1.1` | `test_p1_errors.py` | No umbrella snapshot | `public_json.schema_versions.error` |
| Error registry version | `ERROR_REGISTRY_VERSION` | `1.5` | `test_p1_errors.py` | No umbrella snapshot | `errors.registry_version` |
| Public error-code set | `ERROR_REGISTRY` | Complete code/category pairs; prose excluded | `test_p1_errors.py` | Removal/reassignment mutation evidence absent | `errors.codes` plus mutation tests |
| Capability JSON | `capabilities()` and `Capabilities` | Enabled/disabled recovery payloads | root API and P7 JSON tests | Not in 1.0 umbrella | `public_json.capabilities` |
| Progress JSON | `ProgressEvent`, progress constants | Quantum `1.4`, closed phase/event vocabularies | P1/P7 progress tests | Not in 1.0 umbrella | `public_json.progress` |
| SQLite vault schema | `vault/schema.py` DDL | Schema `1.1`, exact tables/columns/FKs/indexes/check DDL | `test_p2_vault_schema.py` | Not bound to full public freeze | `vault.ddl`, `vault.tables` |
| SQLite migration/version policy | vault open validation | Exact version only; no automatic migration | `test_p2_vault_schema.py` | Policy not machine-frozen | `vault.migration_policy` |
| Vault strategy | planning and vault modules | One `dictionary.sqlite3` per dataset, `SINGLE_DATASET_SQLITE` | P2 and documentation tests | No umbrella marker | `vault.database_filename`, `vault.vault_strategy` |
| Mapping-domain semantics | vault mapping modules | `TEXT`, `NUMERIC_KEY`, `TEMPORAL`; stable global text domain | P2 allocation/reuse tests | Domain identity not umbrella-frozen | `mapping_semantics` |
| Text allocation | text allocation module | CSPRNG first allocation, compatible reuse, independent fresh vaults, global bijection/self-exclusion, NULL/empty identity | P2 text allocation/adversarial tests | Semantic markers distributed | `mapping_semantics.text` |
| Memo semantics | memo transform/allocation modules | Policy `1.1`, reversible type-preserving masks, NULL distinct from empty | P2 memo tests | Semantic markers distributed | `mapping_semantics.memo` |
| Temporal semantics | temporal transform/allocation modules | Policy `1.0`, reversible domain shift, NULL identity, no public offset | P2 temporal tests | Semantic markers distributed | `mapping_semantics.temporal` |
| Numeric relationship strategies | relationship/numeric modules | `IDENTITY`, `REVERSIBLE_BIJECTIVE` | P3/P4 numeric relationship tests | No umbrella marker | `mapping_semantics.numeric_relationships` |
| Field capability matrix | `policy.FIELD_CAPABILITY_MATRIX` | Version `1.0`; unsupported sensitive types fail closed | `test_p4_field_capability_matrix.py` | Separate exact snapshot only | `field_capability_matrix` |
| Relationship metadata schema | relationship models/parser | `1.0`, exact roles/types/provenance | `test_p3_relationship_documents.py` | No umbrella snapshot | `relationships` |
| Relationship assurance | assurance derivation | Four exact levels and bounded scope marker | P1/P3/P5 tests | Mutation evidence absent | `relationships.assurance_levels` plus mutation test |
| Index backend protocol | index models/backend | Schema `1.2`, closed artifact/status/detail vocabularies | P6 and P7 JSON tests | No 1.0 umbrella snapshot | `index_backend` |
| DATA_ONLY bundle/manifest | `transfer_bundle.py` | Manifest `1.1`, DBF/FPT only, sanitized exact keys | `test_p5_transfer_bundle.py` | Mutation evidence absent | `transfer_bundle` plus mutation test |
| Forbidden DATA_ONLY material | transfer allowlist/denylist | Vault/SQLite sidecars, recovery material, secrets, originals, private paths/logs and unverified indexes forbidden | `test_p5_transfer_bundle.py` | Rules distributed | `transfer_bundle.forbidden_*` |
| dbfbridge range | `pyproject.toml` | `dbfbridge[write]>=1.1.0,<2`, supported major `1.x` | `test_dependency_contract.py` | Widening mutation evidence absent | `dependency_contract` plus mutation test |
| Semantic-versioning rules | This document and committed snapshot | PATCH/MINOR/MAJOR rules below | None | Rules not version-controlled | `semantic_versioning` and this document |

## Semantic versioning

### PATCH

A PATCH release may contain a bug fix only when it makes no incompatible
change to the frozen public contract.

### MINOR

A MINOR release may add backward-compatible public behavior only when the
relevant schema/version policy permits that addition. A package MINOR version
does not itself authorize changing or reinterpreting a versioned JSON schema;
the corresponding schema version must change according to that schema's own
policy.

### MAJOR

A MAJOR release is required for any of the following incompatible changes:

- removal or rename of a public API symbol;
- an incompatible public callable signature or CLI change;
- reinterpretation of a versioned schema;
- reuse or removal of a public error code;
- an incompatible vault schema, migration policy or compatibility policy;
- incompatible mapping-domain, text, memo, temporal or numeric semantics;
- removal of supported field behavior;
- incompatible relationship metadata or assurance semantics;
- incompatible DATA_ONLY bundle/manifest semantics;
- breaking the supported dbfbridge major-version range.

Additive changes still require deliberate updates to the relevant version,
snapshot, tests and documentation. The snapshot is never auto-updated after a
test failure.
