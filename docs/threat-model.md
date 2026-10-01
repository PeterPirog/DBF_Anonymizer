# Threat model

This document describes the concrete threat model of the DBF_Anonymizer
1.0.0 stable release (the frozen 1.0 contract):
what is protected, what is transferable, where the trust boundaries are, which
attack/failure classes the design defends against, and — equally important —
what the tool does NOT protect against.

DBF_Anonymizer produces pseudonymized data, not anonymous data. Read
[pseudonymization-vs-anonymization.md](pseudonymization-vs-anonymization.md)
before making any statement about anonymity.

## Protected assets (internal environment only)

- The original source dataset (DBF/FPT files) — stays in the trusted internal
  environment.
- The recovery vault — the single authoritative SQLite recovery vault
  (`VaultStrategy.SINGLE_DATASET_SQLITE`), conventionally
  `protected/recovery.sqlite3`.
- Recovery parameters and vault-internal state (SQLite WAL/SHM/journal and
  other recovery sidecars).
- The protected mapping material (the authoritative forward mappings,
  original value → pseudonym, from which recovery derives the reverse lookup
  pseudonym → original) — exists only inside the vault.
- Secrets, salts, keyfiles, private manifests and private paths/logs.

These artifacts are internal by construction: the transfer bundle creation
refuses them as forbidden artifacts (see [operations.md](operations.md),
"DATA_ONLY transfer bundles"), and diagnostics are privacy-safe by contract
([errors-1.0.md](errors-1.0.md)).

## Transferable assets

- ONLY the verified DATA_ONLY bundle: pseudonymized DBF tables, their
  required fresh FPT companions and the sanitized public manifest. The bundle
  is verified at creation and re-verifiable standalone anywhere.

Nothing else is meant to leave the internal environment. In particular, the
vault and any recovery material must never be transferred.

## Trust boundaries

1. The trusted internal environment (operators, original data, vault).
2. The DBF_Anonymizer process itself (reads the source, writes the
   pseudonymized output, updates the vault).
3. The protected vault (SQLite, recovery-capable).
4. The external / Internet-connected DATA_ONLY consumer (receives only the
   verified bundle; has no vault, no mapping/recovery material, no recovery).

Recovery authorization is a host decision: a host can independently disable
recovery, and a disabled policy fails before any vault access
([operations.md](operations.md), "Recovery").

## Attack and failure classes

- **Accidental vault transfer** — the vault (or a WAL/SHM/journal sidecar)
  reaching the transfer layer. Defense: vault and sidecars are forbidden
  artifacts in the transfer allowlist; bundles are brand-new allowlisted
  trees, never directory copies.
- **Stale index leakage** — old CDX/IDX/DBC files leaving as if valid.
  Defense: DATA_ONLY excludes index artifacts by construction; index validity
  claims require backend verification
  ([limits-and-integrity.md](limits-and-integrity.md)).
- **Original-value leakage** — originals appearing in outputs, logs or
  diagnostics. Defense: privacy-safe diagnostics (value-free typed errors),
  synthetic-only documentation examples, sanitized public manifest.
- **Logs/errors leakage** — verbose or private diagnostics escaping to
  consumers. Defense: machine stdout is a versioned JSON contract; private
  sentinels and vault rows are redacted; paths are portable/bounded/private.
- **Mapping inconsistency** — two tables disagreeing about one key's
  pseudonym. Defense: one vault spans the whole dataset with shared mapping
  domains; declared relationships are validated in preflight and preserved.
- **Malicious/hostile paths** — hostile names, casing or nesting smuggling
  protected state into a transfer tree. Defense: artifact classification by
  suffix/name pattern, case-insensitive; absolute paths and traversal are
  refused; foreign manifests and executables are forbidden.
- **Malformed input** — broken DBF/FPT structures or invalid policy/relationship
  documents. Defense: fail-closed typed refusals (public dbfbridge facts and
  versioned documents), never silent normalization.
- **Crash/cancellation residue** — partial output after a crash or
  cancellation. Defense: publication of results is transactional (a dataset
  only becomes the verified output on success), and staging/locks/temporaries
  are excluded from transfers.

## What DBF_Anonymizer does NOT protect against

- Compromise of the trusted internal environment itself (an attacker with
  vault access can recover data by design — that is what recovery is for).
- Inference from DATA_ONLY output: quasi-identifiers, relational structure,
  dates or other transformed structure can remain informative. DATA_ONLY is
  not anonymity (see
  [pseudonymization-vs-anonymization.md](pseudonymization-vs-anonymization.md)).
- Attacks against the downstream host/transport (authentication bypass,
  session abuse, transport downgrade): those layers belong to the host.
- Misconfiguration by operators (e.g., pointing the vault at an unprotected
  location). The vault protection contract
  ([vault-protection.md](vault-protection.md)) documents operator
  requirements.
- Legal/compliance determinations: this is a technical document, not legal
  advice.