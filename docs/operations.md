# DBF_Anonymizer operations guide

This guide documents the public operation surface of the DBF_Anonymizer
1.0.0 stable version (the frozen 1.0 contract): internal-network offline
installation, one-vault-per-dataset
operation, policy configuration, relationship configuration, the
pseudonymization workflow, dataset verification, protected recovery, and
DATA_ONLY transfer bundles.

All statements in this document describe the public, synchronous,
transport-neutral Python API (`dbf_anonymizer`) and the standalone
`dbf-anonymizer` CLI. They are validated by
`tests/test_p7_documentation_contract.py`; fenced blocks marked
`python p7-009-exec` are executed against synthetic TEMP data on every test
run. Every example uses synthetic fixtures only — never production DBF/FPT
files, never production vaults.

Terminology used throughout:

- **Source dataset** — a directory tree of DBF tables (and their FPT memo
  companions) to pseudonymize.
- **Protected recovery vault** — the single authoritative SQLite recovery
  vault inside the internal environment.
- **Pseudonymized output** — the transformed dataset DBF_Anonymizer writes.
- **DATA_ONLY bundle** — the standalone, verified, transferable output
  package.

## Public API and CLI truth

The supported public API is the package root `dbf_anonymizer`:

`capabilities`, `build_plan`, `preflight`, `pseudonymize`,
`verify_dataset`, `recover`, `create_transfer_bundle`,
`verify_transfer_bundle`, `RecoveryPolicy`, plus the immutable public
models (for example `Plan`, `PreflightResult`, `PseudonymizationResult`,
`VerificationStatus`, `RecoveryResult`, `TransferBundleResult`).

The public API is synchronous and transport-neutral. DBF_Anonymizer ships no
server: it is not an MCP server, and it does not provide authentication,
authorization, transport or job orchestration. See
[mcp-integration.md](mcp-integration.md) for the consumer boundary.

The standalone console script `dbf-anonymizer` exposes exactly nine commands:

| Command | Purpose | Machine mode |
| --- | --- | --- |
| `capabilities` | report standalone runtime capabilities | `--json` |
| `plan` | build a read-only deterministic plan | `--json` |
| `preflight` | evaluate plan readiness (read-only) | `--json` |
| `pseudonymize` | run the pseudonymization operation | `--json`, `--workers` |
| `verify` | independently verify output against the source | `--json` |
| `recover` | protected canonical recovery from the vault | `--json`, `--recovery-policy` |
| `export-bundle` | create the verified transfer bundle | `--json` |
| `verify-bundle` | verify an existing bundle standalone | `--json` |
| `self-test` | run the complete standalone workflow in one call | `--json` |

Every command shares the same argument conventions: common dataset arguments
are positional (`source`, `output`, `vault`), policy and relationship
documents are optional files (`--policy`, `--relationships`), machine
readable results go to stdout with `--json` (progress and human messaging go
to stderr), and unknown invocations fail rather than pretend success.

## Quick start (Python API)

The core public workflow is five calls. Replace the placeholders with YOUR
OWN authorized dataset paths; the fully executable synthetic version of this
workflow is [../examples/basic_workflow.py](../examples/basic_workflow.py)
(with the complete recipe index in [../examples/README.md](../examples/README.md)):

```python
import dbf_anonymizer as public

plan = public.build_plan(source, output, vault)  # read-only, deterministic
preflight_result = public.preflight(plan)  # fail-closed readiness evaluation
assert preflight_result.ready
result = public.pseudonymize(plan)  # the mutable operation
verification = public.verify_dataset(result, source=source, vault=vault)
assert verification.status is public.VerificationStatus.PASS
```

### Executable synthetic fixture setup

The following executable example builds a small SYNTHETIC dataset through the
public dbfbridge boundary (this is the deterministic fixture construction the
documentation acceptance test executes in CI — the pedagogic examples keep
this boilerplate in one reusable helper), then reports capabilities. Synthetic
canary values (such as `DOC-CANARY-1`) stand in for what would be production
data; never run these examples against production files.

```python p7-009-exec
from pathlib import Path
import tempfile

import dbf_anonymizer as public
import dbfbridge

work_root = Path(tempfile.mkdtemp(prefix="dbf-anonymizer-doc-"))
source = work_root / "source"
output = work_root / "pseudonymized"
vault = work_root / "protected" / "recovery.sqlite3"

field = dbfbridge.FieldInfo(
    ordinal=0,
    name="NAME",
    dbf_type="C",
    length=24,
    decimal_count=0,
    address=0,
    flags=0,
    index_field_flag=0,
    autoincrement_next_value=0,
    autoincrement_step=1,
    is_memo=False,
    is_binary=False,
    supported=True,
    dbversion_byte=0x30,
)
schema = dbfbridge.TableSchema(
    path=source / "people.dbf",
    record_count=0,
    header_length=65,
    record_length=25,
    language_driver=0x03,
    encoding="cp1252",
    has_memo=False,
    has_memo_flag=False,
    has_structural_cdx=False,
    is_database_container=False,
    dbc_bound=False,
    dbc_backlink_path=None,
    table_flags=0,
    fields=(field,),
    warnings=(),
    dbversion_byte=0x30,
    dbversion_name="Visual FoxPro",
    last_update="2026-01-01",
    incomplete_transaction=False,
    encryption_flag=False,
    memo_companion_format=None,
    memo_companion_present=False,
    memo_companion_path=None,
    memo_companion_size_bytes=None,
    memo_block_size=None,
    memo_next_free_block=None,
    companion_cdx_present=False,
    companion_cdx_path=None,
)
dbfbridge.write_table(
    source / "people.dbf",
    schema=schema,
    records=[
        dbfbridge.DirectRecord(
            physical_index=0,
            deleted=False,
            values={"NAME": "DOC-CANARY-1"},
        )
    ],
)

caps = public.capabilities()
assert caps.direct_read and caps.direct_write and caps.recovery
```

`capabilities()` reports what the installed runtime can do (standalone
Direct Read/Direct Write through dbfbridge, recovery, transfer bundles). It
never mutates anything.

## Plan, preflight, pseudonymize, verify

`build_plan` is read-only and side-effect-free: it discovers tables, computes
fingerprints and produces a deterministic `Plan`. Nothing is created until
`pseudonymize` runs. `preflight` evaluates plan readiness (including
relationship-domain validation) without creating files; a refused preflight
prevents the mutable operation from starting.

```python p7-009-exec
plan = public.build_plan(source, output, vault)
preflight_result = public.preflight(plan)
assert preflight_result.ready

result = public.pseudonymize(plan)
verification = public.verify_dataset(result, source=source, vault=vault)
assert verification.status is public.VerificationStatus.PASS
```

`pseudonymize` accepts a bounded `workers` count (default 1). Long operations
support cooperative cancellation and bounded progress through keyword-only
`progress` and `cancel_check` arguments. `verify_dataset` re-reads the
pseudonymized output and the source independently and returns a typed
`VerificationResult`; `PASS` is the only success value.

The progress/cancellation pattern is synchronous (no async API): the callback
receives bounded structured `ProgressEvent` objects (codes and counters, not
free-form text), and a `cancel_check` returning `True` stops the operation at
the next safe point with the typed `CancellationError`:

```python
def on_progress(event: public.ProgressEvent) -> None:
    print(event.phase_code, event.event_code, event.completed_units)


result = public.pseudonymize(plan, progress=on_progress, cancel_check=lambda: False)
```

A caller-supplied callback failure is contained as the typed `CallbackError`
(the raw exception text never escapes), so callbacks can be host-owned code.

## Recovery

Exactly one protected vault backs the whole dataset (see
[One vault per dataset](#one-vault-per-dataset)). Recovery restores a
canonical copy of the original data from the pseudonymized output plus the
vault. The host controls recovery authorization through
`RecoveryPolicy`: `ENABLED` permits recovery, `DISABLED` refuses it
BEFORE any vault access.

```python p7-009-exec
recovered = public.recover(
    output,
    vault=vault,
    output=work_root / "recovered",
    recovery_policy=public.RecoveryPolicy.ENABLED,
)
assert recovered.canonical_verified
```

A host that must not be able to recover data (for example an external
consumer environment) sets the policy to `DISABLED`. The refusal is typed
(`RecoveryError` with `ErrorCode.RECOVERY_NOT_PERMITTED`), produces no output
directory, and happens before the vault is opened.

```python p7-009-exec
try:
    public.recover(
        output,
        vault=vault,
        output=work_root / "blocked",
        recovery_policy=public.RecoveryPolicy.DISABLED,
    )
except public.RecoveryError as error:
    assert error.code is public.ErrorCode.RECOVERY_NOT_PERMITTED
```

The CLI exposes the same control: `dbf-anonymizer recover ... --recovery-policy
disabled` fails with the typed error code on stdout (machine mode) and the
protected vault path is never disclosed in diagnostics.

## One vault per dataset

DBF_Anonymizer enforces a SINGLE authoritative SQLite recovery vault per
dataset (`VaultStrategy.SINGLE_DATASET_SQLITE`):

- exactly ONE vault spans all converted tables/files of the dataset; there is
  no vault per table;
- the vault is internal and protected: it must live inside the trusted
  internal environment (the conventional location used throughout this
  repository is `protected/recovery.sqlite3` beside the operational
  workspace);
- the same mapping domains remain consistent across all tables of the
  dataset: a given original key value maps to one pseudonymized value
  everywhere, and declared relationships preserve their PK/FK domains;
- the vault is what makes the output RECOVERABLE: pseudonymized data plus the
  vault is reversible by authorized operators;
- the vault must NEVER be copied into a DATA_ONLY transfer (see
  [DATA_ONLY transfer bundles](#data_only-transfer-bundles)); SQLite
  WAL/SHM/journal files and any other recovery material are excluded from
  transfer by construction (they are forbidden artifacts, not merely
  discouraged).

## Internal-network offline installation

The supported installation model is the P7-004 pinned wheelhouse: prepare
exact wheels in the trusted connected environment, move them to the internal
environment, and install with local wheels only. The runtime never downloads
or installs anything at run time: no HTTP, no package indexes, no Git, no
`pip install` inside DBF_Anonymizer — the complete standalone feature set
(including recovery and bundles) works with the network removed.

Step 1 — in the trusted connected environment (Windows PowerShell), build the
release artifacts and download the exact pinned runtime wheelhouse:

```powershell
# Windows PowerShell, trusted connected environment
python -m pip install --upgrade pip build
python -m build
python -m pip download --only-binary=:all: --no-cache-dir --no-deps --dest WHEELHOUSE --requirement requirements/p7-offline-wheelhouse.txt
Copy-Item -Path "dist\*.whl" -Destination "WHEELHOUSE"
```

Step 2 — verify the wheelhouse is the exact pinned closure:

```text
python tools/check_p7_offline_wheelhouse.py requirements/p7-offline-wheelhouse.txt WHEELHOUSE
```

The exact pinned runtime closure is:

| Runtime dependency | Pinned version |
| --- | --- |
| dbfbridge | 1.1.1 (the `dbfbridge[write]` acceptance artifact) |
| dbfread | 2.0.7 |
| dbf | 0.99.11 |
| aenum | 3.1.17 |

The application wheel must be the DBF_Anonymizer distribution itself
(`dbf-anonymizer==1.0.0`). The runtime metadata range in `pyproject.toml`
stays `dbfbridge[write]>=1.1.0,<2`; the pin files record the exact tested
closure, they do not change the range.

Step 3 — move `WHEELHOUSE` (and the bundle of your release artifacts) to the
internal environment, then install with local wheels only (Windows
PowerShell; the `INTERNAL_VENV\Scripts\...` layout is Windows-specific, which
matches the Windows P7-004 clean offline acceptance):

```powershell
# Windows PowerShell, internal environment
python -m venv INTERNAL_VENV
INTERNAL_VENV\Scripts\python.exe -m pip install --no-index --find-links WHEELHOUSE --no-cache-dir dbf-anonymizer==1.0.0
INTERNAL_VENV\Scripts\python.exe -m pip check
INTERNAL_VENV\Scripts\dbf-anonymizer --version
INTERNAL_VENV\Scripts\dbf-anonymizer self-test --json
```

`--no-index` disables every remote index; `--find-links` points pip at the
local wheelhouse only. `pip check` verifies the installed metadata matches
the environment. After installation the runtime performs no network use, no
Git access, no package installation and no dependency download during
operation; the default standalone run with `index_backend=None` additionally
starts no VFP/index subprocess, while the opt-in `VFP_INDEXED` profile's
explicitly injected backend performs its authoritative VFP work outside the
standalone core boundary under the host's policy (see
[limits-and-integrity.md](limits-and-integrity.md) for what that means for
indexes).

## Policy configuration

Policies are plain JSON-serializable mappings validated fail-closed. The
policy schema version is `1` (`schema_version` must be exactly the integer
`1`); unknown top-level or nested keys, unknown actions and non-JSON leaf
values are typed refusals, never silent normalization. The resolved policy is
bound to the plan through a deterministic SHA-256 fingerprint
(`plan.policy.policy_fingerprint`).

The supported top-level sections and their documented defaults:

| Section | Keys | Default | Allowed actions/values |
| --- | --- | --- | --- |
| (top level) | `schema_version`, `profile` | `1`, `SAFE_TRANSFER` | profile must be `SAFE_TRANSFER` |
| `text` | `default_action`, `domain` | `PSEUDONYMIZE_REVERSIBLE`, `GLOBAL_TEXT` | `PSEUDONYMIZE_REVERSIBLE`, `KEEP`; domain `GLOBAL_TEXT` |
| `memo` | `text`, `binary` | `MASK_REVERSIBLE` / `MASK_REVERSIBLE` | `MASK_REVERSIBLE`, `KEEP` |
| `temporal` | `date`, `datetime` | `SHIFT_REVERSIBLE` / `SHIFT_REVERSIBLE` | `SHIFT_REVERSIBLE`, `KEEP` |
| `numeric` | `default_action` | `KEEP` | `KEEP` |
| `relationships` | `metadata_file` | `None` | must stay `None` (relationship documents are passed separately) |
| `indexes` | `profile` | `DATA_ONLY` | `DATA_ONLY`, `VFP_INDEXED` |

A mapping-domain is the identity domain shared by one text policy domain
(`GLOBAL_TEXT`): all transformed text fields draw their pseudonyms from the
same mapping domains, so a given original text value maps to the same
pseudonym everywhere in the dataset. Numeric keys are kept as keys (numeric
default action is `KEEP`); declared numeric relationship keys are protected by
the numeric strategy of the relationship group instead.

Policies can be passed as a mapping (`build_plan(..., policy=policy)`) or as a
file for the CLI (`--policy policy.json`). A policy file must contain the same
versioned structure; the CLI fails closed on unknown or unsupported content.

```python p7-009-exec
policy = {
    "schema_version": 1,
    "profile": "SAFE_TRANSFER",
    "text": {"default_action": "PSEUDONYMIZE_REVERSIBLE", "domain": "GLOBAL_TEXT"},
    "memo": {"text": "MASK_REVERSIBLE", "binary": "MASK_REVERSIBLE"},
    "temporal": {"date": "SHIFT_REVERSIBLE", "datetime": "SHIFT_REVERSIBLE"},
    "numeric": {"default_action": "KEEP"},
    "relationships": {"metadata_file": None},
    "indexes": {"profile": "DATA_ONLY"},
}
policy_plan = public.build_plan(
    source, output, work_root / "protected" / "recovery-policy-doc.sqlite3", policy
)
assert policy_plan.policy.policy_schema_version == "1"
assert policy_plan.policy.recovery_enabled is True
```

## Relationship configuration

Relationship metadata is an explicit, versioned document — DBF_Anonymizer
never invents relationships by scanning DBC files, and there is no automatic
DBC relationship discovery. Pass the document as a mapping
(`relationship_document=`) or as a file for the CLI (`--relationships`).

The document schema version is `metadata_schema_version == "1.0"` (anything
else fails closed). Top level: `metadata_schema_version` and `relations` (a
non-empty list of relation groups). Each relation group:

| Key | Required | Values |
| --- | --- | --- |
| `relation_id` | yes | bounded stable token, unique in the document |
| `provenance` | yes | `POLICY_FILE`, `MCP_VFP9SP2_TOOLCHAIN` or `EXTERNAL_VFP_METADATA` |
| `comparison` | yes | `EXACT_VALUE` or `UNSPECIFIED` |
| `numeric_strategy` | optional | `IDENTITY` (default) or `REVERSIBLE_BIJECTIVE` |
| `assurance` | external envelope: yes | `VERIFIED` or `UNVERIFIED` (external claims must state it) |
| `authority` | external envelope: yes | `CONTRACT_AUTHORITATIVE` or `INFERRED` (per claim; only CONTRACT_AUTHORITATIVE + VERIFIED claims are effective) |
| `source_digest` | optional | bounded token |
| `members` | yes | ordered member list (see below) |

Each member: `table` (dataset-relative forward-slash path, e.g.
`people.dbf`; absolute paths and `..` traversal are refused), `field`, `role`
(`PRIMARY`, `CANDIDATE`, `FOREIGN`), `ordinal` (1-based composite position),
`dbf_type` (`C`, `V`, `I`, `N`), `byte_width` (format-defined, `4` for
Integer), `encoding` (`none` for numeric members; a bounded code-page name
for text members), `nullable`.

Declared relationships preserve PK/FK consistency: text key domains share the
mapping domains of the dataset, and numeric relationship keys follow the
group's `numeric_strategy` (`REVERSIBLE_BIJECTIVE` keeps transformed numeric
keys consistent across the FK and the PK; `IDENTITY` keeps the declared
numeric keys untransformed so their values remain comparable). Preflight
validates declared relationships against the discovered DBF schemas and the
discovered key domains; an incompatible declaration is a typed refusal before
any mutable operation.

The following executable example declares one relationship across two tables
of a separate synthetic dataset. The foreign key value is drawn from the
primary key domain so the declared relationship is valid for preflight.

```python p7-009-exec
rel_source = work_root / "rel-source"
rel_output = work_root / "rel-output"


def synthetic_schema(path: Path, fields: tuple[tuple[str, str, int], ...]) -> dbfbridge.TableSchema:
    fields_info = tuple(
        dbfbridge.FieldInfo(
            ordinal=index,
            name=name,
            dbf_type=dbf_type,
            length=length,
            decimal_count=0,
            address=0,
            flags=0,
            index_field_flag=0,
            autoincrement_next_value=0,
            autoincrement_step=1,
            is_memo=False,
            is_binary=False,
            supported=True,
            dbversion_byte=0x30,
        )
        for index, (name, dbf_type, length) in enumerate(fields)
    )
    return dbfbridge.TableSchema(
        path=path,
        record_count=0,
        header_length=65,
        record_length=1 + sum(length for _, _, length in fields),
        language_driver=0x03,
        encoding="cp1252",
        has_memo=False,
        has_memo_flag=False,
        has_structural_cdx=False,
        is_database_container=False,
        dbc_bound=False,
        dbc_backlink_path=None,
        table_flags=0,
        fields=fields_info,
        warnings=(),
        dbversion_byte=0x30,
        dbversion_name="Visual FoxPro",
        last_update="2026-01-01",
        incomplete_transaction=False,
        encryption_flag=False,
        memo_companion_format=None,
        memo_companion_present=False,
        memo_companion_path=None,
        memo_companion_size_bytes=None,
        memo_block_size=None,
        memo_next_free_block=None,
        companion_cdx_present=False,
        companion_cdx_path=None,
    )


dbfbridge.write_table(
    rel_source / "people.dbf",
    schema=synthetic_schema(rel_source / "people.dbf", (("ID", "I", 4), ("NAME", "C", 20))),
    records=[
        dbfbridge.DirectRecord(
            physical_index=0, deleted=False, values={"ID": 1, "NAME": "DOC-CANARY-2"}
        )
    ],
)
dbfbridge.write_table(
    rel_source / "orders.dbf",
    schema=synthetic_schema(
        rel_source / "orders.dbf", (("ORDER_NO", "I", 4), ("PERSON_ID", "I", 4))
    ),
    records=[
        dbfbridge.DirectRecord(
            physical_index=0, deleted=False, values={"ORDER_NO": 100, "PERSON_ID": 1}
        )
    ],
)

relationship_document = {
    "metadata_schema_version": "1.0",
    "relations": [
        {
            "relation_id": "orders-person-id-people-id",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "numeric_strategy": "REVERSIBLE_BIJECTIVE",
            "members": [
                {
                    "table": "people.dbf",
                    "field": "ID",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
                {
                    "table": "orders.dbf",
                    "field": "PERSON_ID",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
            ],
        }
    ],
}
relationship_plan = public.build_plan(
    rel_source,
    rel_output,
    work_root / "protected" / "recovery-rel-doc.sqlite3",
    relationship_document=relationship_document,
)
assert relationship_plan.policy.relationship_count == 1
assert public.preflight(relationship_plan).ready
```

A refused declaration fails fail-closed during planning, before any mutable
operation. The next example declares a member whose declared type does not
match the discovered DBF schema:

```python p7-009-exec
incompatible = {
    "metadata_schema_version": "1.0",
    "relations": [
        {
            "relation_id": "people-id-declared-as-text",
            "provenance": "POLICY_FILE",
            "comparison": "EXACT_VALUE",
            "members": [
                {
                    "table": "people.dbf",
                    "field": "ID",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "C",
                    "byte_width": 24,
                    "encoding": "cp1252",
                    "nullable": False,
                },
                {
                    "table": "orders.dbf",
                    "field": "PERSON_ID",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
            ],
        }
    ],
}
try:
    public.build_plan(
        rel_source,
        rel_output,
        work_root / "protected" / "recovery-bad-doc.sqlite3",
        relationship_document=incompatible,
    )
except public.PolicyError as refusal:
    assert refusal.code is public.ErrorCode.POLICY_INVALID
```

## External VFP metadata envelope (completed P6-006 contract)

The completed P6-006 contract defines the full EXTERNAL metadata envelope,
owned and shipped by DBF_Anonymizer (see
[external-vfp-metadata-contract.md](external-vfp-metadata-contract.md)): the
envelope carries the external `external_metadata_schema_version` ("1.0"), the
structured producer provenance (`producer_id`/`producer_version`), the
envelope-level `authority` classification, and — on EVERY relation claim and
index claim — its own explicit `provenance`, `authority` and `assurance`.
Only a claim that is both `CONTRACT_AUTHORITATIVE` and `VERIFIED` (index
claims additionally `VERIFIED` in `verification_state`) and whose provenance
is an authoritative VFP-metadata class may affect authoritative
relationship-domain grouping or become eligible for
`VFP_METADATA_VERIFIED`; inferred or unverified claims remain retained as
non-authoritative planning/reporting information. The following executable
example injects a conforming external envelope through the same public
planning boundary:

```python p7-009-exec
external_document = {
    "metadata_schema_version": "1.0",
    "external_metadata_schema_version": "1.0",
    "producer": {"producer_id": "doc-example-analyzer", "producer_version": "1.0.0"},
    "authority": "CONTRACT_AUTHORITATIVE",
    "relations": [
        {
            "relation_id": "doc-example-fk",
            "comparison": "EXACT_VALUE",
            "provenance": "EXTERNAL_VFP_METADATA",
            "assurance": "VERIFIED",
            "authority": "CONTRACT_AUTHORITATIVE",
            "members": [
                {
                    "table": "people.dbf",
                    "field": "ID",
                    "role": "PRIMARY",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
                {
                    "table": "orders.dbf",
                    "field": "PERSON_ID",
                    "role": "FOREIGN",
                    "ordinal": 1,
                    "dbf_type": "I",
                    "byte_width": 4,
                    "encoding": "none",
                    "nullable": False,
                },
            ],
        }
    ],
}
external_plan = public.build_plan(
    rel_source,
    rel_output,
    work_root / "protected" / "recovery-external-doc.sqlite3",
    relationship_document=external_document,
)
assert external_plan.relationships.external_metadata_schema_version == "1.0"
assert external_plan.relationships.producer_id == "doc-example-analyzer"
assert external_plan.relationships.authoritative is True
assert public.preflight(external_plan).ready
```

## DATA_ONLY transfer bundles

`create_transfer_bundle(result, destination=..., profile="DATA_ONLY")` builds
a brand-new, allowlisted, standalone bundle of pseudonymized data. The bundle
is verified at creation and can be re-verified anywhere by
`verify_transfer_bundle` without the source or the vault.

A DATA_ONLY bundle contains ONLY the expected pseudonymized DBF tables, their
required fresh FPT companions and the sanitized public manifest. It EXCLUDES
and refuses by construction:

- the recovery vault (`dictionary.sqlite3` / `recovery.sqlite3`) and every
  foreign SQLite database,
- SQLite WAL/SHM/journal sidecars,
- the protected mapping material (the authoritative original → pseudonym
  mappings and any reverse lookup) and recovery parameters,
- secrets, salts, keyfiles and private manifests,
- original source values and private paths or logs,
- stale/unverified index artifacts (`.cdx`, `.idx`, `.dbc`, `.dct`, `.dcx`),
- executables, libraries, scripts and any other non-allowlisted artifact.

```python p7-009-exec
bundle_path = work_root / "bundle"
bundle = public.create_transfer_bundle(result, destination=bundle_path, profile="DATA_ONLY")
standalone = public.verify_transfer_bundle(bundle_path)
assert bundle.verified and standalone.verified
```

DATA_ONLY is the transferable form of the pseudonymized data. It is NOT proof
of full anonymity; see
[pseudonymization-vs-anonymization.md](pseudonymization-vs-anonymization.md).
The transferable output never includes recovery material; copying the vault
(or any WAL/SHM/journal/recovery sidecar) into a transfer is neither supported
nor permitted.

## Typed errors

Every public failure derives from `public.AnonymizerError` and serializes to
the versioned privacy-safe JSON contract. Classify failures by the stable
machine code — never by parsing exception text:

```python
try:
    public.recover(
        output,
        vault=vault,
        output=work_root / "blocked",
        recovery_policy=public.RecoveryPolicy.DISABLED,
    )
except public.AnonymizerError as error:
    payload = error.to_dict()  # versioned contract fields only
    assert error.code is public.ErrorCode.RECOVERY_NOT_PERMITTED
```

The complete code vocabulary and categories are documented in
[errors-1.0.md](errors-1.0.md).

## The complete CLI workflow

Every CLI command mirrors the Python API above. Machine results print to
stdout with `--json`; progress and human messages stay on stderr. Example
invocations (paths are placeholders — use your own dataset directories):

```text
dbf-anonymizer capabilities --json
dbf-anonymizer plan SOURCE OUTPUT VAULT --policy policy.json --relationships relations.json --json
dbf-anonymizer preflight SOURCE OUTPUT VAULT --json
dbf-anonymizer pseudonymize SOURCE OUTPUT VAULT --workers 4 --json
dbf-anonymizer verify SOURCE OUTPUT VAULT --json
dbf-anonymizer recover PSEUDONYMIZED VAULT RECOVERED --recovery-policy enabled --json
dbf-anonymizer export-bundle SOURCE PSEUDONYMIZED VAULT DESTINATION --json
dbf-anonymizer verify-bundle DESTINATION --json
dbf-anonymizer self-test --json
```

`self-test` runs the complete workflow (plan → preflight → pseudonymize →
verify → recovery → bundle) against its own synthetic dataset in one call and
is the quickest end-to-end health check of an installed environment.

### Worked CLI recipe (synthetic example data)

The repository ships ready-made example configuration files, so the complete
workflow can be reproduced without inventing any JSON. Run this from a
repository checkout with the package installed (Windows PowerShell; the same
commands work in any shell with forward slashes):

```powershell
# Synthetic demo dataset only — never production data.
$work = "demo-work"
python examples\synthetic_dataset.py "$work\source"

dbf-anonymizer capabilities --json
dbf-anonymizer plan "$work\source" "$work\output" "$work\protected\recovery.sqlite3" --policy examples\config\policy-data-only.json --relationships examples\config\relationships.json --json
dbf-anonymizer preflight "$work\source" "$work\output" "$work\protected\recovery.sqlite3" --policy examples\config\policy-data-only.json --relationships examples\config\relationships.json --json
dbf-anonymizer pseudonymize "$work\source" "$work\output" "$work\protected\recovery.sqlite3" --policy examples\config\policy-data-only.json --relationships examples\config\relationships.json --json
dbf-anonymizer verify "$work\source" "$work\output" "$work\protected\recovery.sqlite3" --policy examples\config\policy-data-only.json --relationships examples\config\relationships.json --json
dbf-anonymizer recover "$work\output" "$work\protected\recovery.sqlite3" "$work\recovered" --recovery-policy enabled --json
dbf-anonymizer export-bundle "$work\source" "$work\output" "$work\protected\recovery.sqlite3" "$work\bundle" --json
dbf-anonymizer verify-bundle "$work\bundle" --json
dbf-anonymizer self-test --json
```

The configuration files are
[examples/config/policy-data-only.json](../examples/config/policy-data-only.json)
(the documented default policy with the DATA_ONLY index profile) and
[examples/config/relationships.json](../examples/config/relationships.json)
(the declared PK/FK relationship matching the synthetic
`people.dbf`/`orders.dbf` demo dataset). Every command prints exactly one
machine-readable JSON result with `--json`.