# Pseudonymized is not anonymous

This distinction is explicit and prominent because it is the most common
misreading of the tool's output: reversible pseudonymized data with a
protected recovery vault is PSEUDONYMIZED data, not anonymized data. The
absence of the vault in a transfer does not change that classification.

## What pseudonymization means here

DBF_Anonymizer performs reversible pseudonymization backed by a protected
vault. Text pseudonyms are allocated with cryptographically secure randomness
when a mapping is first created; the persisted mapping is then reused
consistently by the same compatible vault. Pseudonymized data plus the vault
is, by design, fully recoverable by authorized operators
([operations.md](operations.md), "Recovery"). That reversibility is a feature
for the internal environment and simultaneously the reason the output is not
anonymous.

### Reversibility through the protected vault

Recovery is possible because the protected vault persists the authoritative
reversible mapping and recovery material. The vault is the single source of
truth for reversing pseudonymized values back to their originals.

### Fresh vault independence

When a fresh compatible vault is used, text pseudonym allocation uses
cryptographically secure randomness; the same original value is NOT guaranteed
to receive the same pseudonym in a different fresh vault. Each vault produces
an independent pseudonym set.

### Same compatible vault stability

When the SAME compatible vault is reused, the previously stored mapping is
stable and reused consistently. Within one dataset and vault, the same exact
mapped domain value receives the same persisted pseudonym across all
participating tables and fields.

### Domain consistency

Within one dataset and vault, the same exact mapped domain value receives the
same persisted pseudonym across all participating tables and fields. This
consistency is achieved through vault-persisted mappings, not through
deterministic derivation from the original value.

## What DATA_ONLY changes — and what it does not

A verified DATA_ONLY bundle removes direct recovery material (the vault,
WAL/SHM/journal sidecars, the protected mapping material, recovery
parameters, secrets).
Removing recovery material makes the DATA_ONLY bundle non-reversible by its
recipient, but it does NOT make the data anonymous. A DATA_ONLY bundle may
still preserve:

- quasi-identifiers (combinations of fields that can single out individuals
  or entities),
- relational structure (which rows belong together, foreign-key
  relationships, cardinalities),
- dates or other transformed structure (shifted, but structurally present),
- application and domain characteristics (value patterns, ordering,
  distributions of derived fields).

Recipients of DATA_ONLY output must therefore treat it as pseudonymized data
whose recovery material is absent — not as data whose identity has been
destroyed.

## What this documentation does not claim

- No claim of GDPR-grade or any other legal-grade anonymization merely
  because the vault is absent from a transfer.
- No claim that pseudonymized output is safe to publish.
- No claim that removing the vault makes the transformation irreversible
  against every adversary: determinism, residual structure and domain
  knowledge can support re-identification research on any dataset.

Operators who need de-identified data for a specific purpose must evaluate
the residual risk of that specific dataset and purpose themselves; this
repository provides the pseudonymization mechanics and the honest boundaries
([threat-model.md](threat-model.md)), not a compliance verdict.

## Practical rules

1. Keep the vault and every recovery artifact inside the trusted internal
   environment.
2. Transfer only verified DATA_ONLY bundles.
3. Treat DATA_ONLY recipients as holders of pseudonymized, potentially
   re-identifiable data.
4. Disable recovery on hosts that must not be able to reverse data.
5. Never describe DBF_Anonymizer output as "anonymized" without an explicit,
   dataset-specific anonymization analysis that this tool does not perform.