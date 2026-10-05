# DBF_Anonymizer 1.0 — public error contract

Status: frozen stable 1.0 contract (REQ-P8-001 freeze; REQ-P1-003 delivered).

DBF_Anonymizer exposes a typed error hierarchy for machine consumers, CLI adapters and MCP/toolchain integration. Error classification is based only on stable structured codes. Human-readable exception text is never an API discriminator.

## Contract

Every public DBF_Anonymizer failure derives from `AnonymizerError` and serializes through `to_dict()` with:

- `schema_version` — public error payload schema (`1.1`);
- `registry_version` — version of the error-code registry (`1.5`);
- `code` — stable DBF_Anonymizer machine code;
- `category` — stable failure category;
- `message` — fixed registry-controlled English message;
- `dependency_code` — optional machine code preserved from a structured dependency failure;
- `context` — bounded typed operational metadata.

The registry is exported as `ERROR_REGISTRY` and contains exactly one immutable definition for every public `ErrorCode`.

## Privacy boundary

`ErrorContext` intentionally is not an arbitrary dictionary. It permits only machine tokens and normalized relative paths:

- operation code;
- artifact path;
- table path;
- policy rule code;
- relationship identifier;
- detail code.

Absolute paths, drive-qualified paths, parent traversal and free-form whitespace text are rejected. Public errors do not provide fields for original values, memo payloads, reverse mappings, vault contents or secrets.

## dbfbridge wrapping

`DBFBridgeError.from_exception()` reads only the structured `code` attribute of the supplied dependency exception. It supports both string codes and enum codes, which covers the public dbfbridge 1.1 read/write error families and `OptionalDependencyMissingError`.

The wrapper deliberately does **not** copy the dependency exception message, path or context. Those fields may contain absolute paths or sensitive diagnostics. If an exception has no structured code, DBF_Anonymizer reports the generic `DBFBRIDGE_FAILURE` code and leaves `dependency_code` unset; it never attempts to infer a code from `str(exception)`.

```python
from dbfbridge import DbfHeaderInvalidError
from dbf_anonymizer import DBFBridgeError, ErrorContext

dependency_error = DbfHeaderInvalidError(
    "header rejected",
    path="private/source.dbf",
)

error = DBFBridgeError.from_exception(
    dependency_error,
    context=ErrorContext(
        operation="build_plan",
        table_path="tables/source.dbf",
        detail_code="SCHEMA_READ",
    ),
)

assert error.code.value == "DBFBRIDGE_FAILURE"
assert error.dependency_code == "DBF_HEADER_INVALID"
```

## Categories

The 1.0 registry separates path, policy, dbfbridge, vault, mapping, relationship, publication, verification, recovery and cancellation failures. Codes are intentionally more specific than categories so CLI/MCP hosts can decide whether a failure is retryable, requires policy correction, requires protected-vault access, or represents an integrity failure without parsing prose.

## Compatibility and semantic versioning

This is a frozen stable 1.0 contract. Backward-incompatible changes to the code vocabulary or payload shape require a MAJOR version bump under the semantic-versioning rules of [public-contract-1.0.md](public-contract-1.0.md); additive changes still require a deliberate version bump of the affected schema/registry version together with its snapshot, tests and documentation. Historical 0.3 exceptions do not constrain this contract.
