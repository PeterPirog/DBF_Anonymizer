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
unchanged.

Every external relation carries explicit provenance and assurance. Envelope
authority `CONTRACT_AUTHORITATIVE` combined with relation assurance `VERIFIED`
is required before a claim can affect relationship-driven mapping or become
eligible for `VFP_METADATA_VERIFIED`. That level additionally requires successful
post-transform relationship verification. `INFERRED` or `UNVERIFIED` claims are
retained in the canonical metadata fingerprint for planning/reporting but do not
affect mapping domains or relational assurance.

Index claims carry explicit provenance, assurance, and verification state. Only
a contract-authoritative claim whose assurance and verification state are both
`VERIFIED` may support the existing index-validity machinery. It does not by
itself assert that an output CDX/IDX was rebuilt or authorize publication of a
source index. Output validity still requires the existing backend rebuild and
verification evidence.

Unknown or missing contract versions, malformed structures, inconsistent
authority/assurance, unsafe paths, and dataset references that do not resolve to
an inspected table or field fail closed with the package's typed policy errors.
The contract contains structural metadata only and never original record values,
memo contents, recovery mappings, vault paths, credentials, or secrets.
