# External VFP metadata consumer contract

DBF_Anonymizer owns external VFP metadata schema version `1.0`. The contract
is transport-neutral and producer-independent. A producer emits JSON only; it
does not need to import DBF_Anonymizer, MCP, or a VFP runtime.

The schema is shipped in the wheel as
`dbf_anonymizer/schemas/external-vfp-metadata-1.0.schema.json`. Installed-wheel
consumers can load it through the stable package API:

```python
from dbf_anonymizer.relationships import load_external_metadata_schema

schema = load_external_metadata_schema()
```

Pass a conforming JSON mapping to the existing `relationship_document`
argument of `dbf_anonymizer.build_plan`. The same parsed relationship document
drives planning, preflight, operation binding, vault compatibility, verification,
and the existing relationship fingerprint. Root-public function signatures are
unchanged. A runnable synthetic demonstration is
[../examples/external_metadata.py](../examples/external_metadata.py).

Every external relation claim carries explicit provenance, authority and
assurance. Envelope-level `authority` is supplied contract metadata carried in
the document fingerprint; it is NOT a per-claim default — every relation and
index claim carries its OWN explicit `authority`.

The relation and index claim domains are separate:

- an authoritative ELIGIBLE RELATION claim (`CONTRACT_AUTHORITATIVE` +
  `VERIFIED` + an authoritative VFP-metadata provenance class) may affect
  relationship-driven mapping and — after successful post-transform
  relationship verification — support `VFP_METADATA_VERIFIED`;
- an INDEX claim is independent index metadata: it does not affect
  relationship-driven mapping, does not cause relational assurance and never
  by itself proves that an output CDX/IDX was rebuilt (see the index-claim
  section below).

A `POLICY_FILE` provenance claim is
retained as non-authoritative planning/reporting information — the shipped
schema and the runtime both refuse any `POLICY_FILE` claim that claims
authoritative strength — and `INFERRED` or `UNVERIFIED` claims are retained in
the canonical metadata fingerprint for planning/reporting but do not affect
mapping domains or relational assurance.

A `REVERSIBLE_BIJECTIVE` numeric-strategy declaration is itself a
strengthening-capability declaration (reversible mapping-domain grouping);
the shipped schema and the runtime therefore both reject such a declaration on
any claim that is not contract-authoritative and verified, and require at
least one numeric member on the effective claim (fail closed, same typed
codes as the planner). Effective claims may use DIFFERENT authoritative
VFP-metadata classes within one document: provenance eligibility is per
claim, and the public provenance summary is then the truthful `MIXED` token.

Index claims carry explicit provenance, authority, and verification state. Only
a contract-authoritative claim whose assurance and verification state are both
`VERIFIED` and whose provenance is an authoritative VFP-metadata class may
support the existing index-validity machinery. It does not by itself assert
that an output CDX/IDX was rebuilt or authorize publication of a source index.
Output validity still requires the existing backend rebuild and verification
evidence.

Unknown or missing contract versions, malformed structures, inconsistent
authority/assurance, unsafe paths, and dataset references that do not resolve to
an inspected table or field fail closed with the package's typed policy errors.
The contract contains structural metadata only and never original record values,
memo contents, recovery mappings, vault paths, credentials, or secrets.

## Validation model

The shipped JSON Schema (`dbf_anonymizer/schemas/external-vfp-metadata-1.0.schema.json`,
Draft 2020-12) is the SYNTACTIC acceptance contract. The test suite validates it
with the `jsonschema` Draft 2020-12 validator (a test/dev-only dependency;
never a runtime dependency) and proves schema/runtime parity:

- **Tier 1 — exact parity.** Every single-claim syntactic constraint (contract
  versions, structured producer, bounded tokens, path identity syntax, encoding
  vocabulary, index expression bounds and path-material rejection, per-claim
  authority/assurance consistency, index kind/suffix consistency) accepts
  exactly the same payloads on both sides: schema ACCEPT ⇔ runtime ACCEPT.
- **Tier 2 — runtime-only rules.** Cross-claim structural rules (member
  identity uniqueness, composite ordinal sequences, parent/foreign arity,
  one parent key family) and dataset-reference validation (a referenced table
  or field must exist in the inspected dataset) cannot be expressed in JSON
  Schema; the runtime enforces them after schema validation. The runtime is a
  fail-closed superset: it NEVER accepts a payload the schema rejects.
