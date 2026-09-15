# Protected vault security notes (REQ-P2-009)

The recovery vault (`dictionary.sqlite3` inside the protected vault
directory) contains **sensitive reversible recovery material**: original
Memo/General/Picture payloads, the secret temporal offsets of every
Date/DateTime domain, and the original→pseudonym bijections.  Anyone who can
read this database can reverse the pseudonymization completely.

## Operator requirements

* The vault directory must stay inside a **protected internal environment**.
  It must never be published, transferred or backed up together with
  pseudonymized output.  The future transfer bundle (REQ-P5-004) will never
  contain the recovery vault — the path policy in
  `dbf_anonymizer.vault.protection` already refuses vault roots that overlap
  the source, working-output or transfer-output trees.
* **Operator-controlled filesystem ACLs are required.**  On POSIX the vault
  applies owner-only modes (`0700` directory, `0600` dictionary) as
  best-effort at creation.  On Windows, chmod-style POSIX bits do **not**
  create robust NTFS ACL isolation; place the vault inside an
  ACL-restricted directory that only the operator account can access.
* **Volume or full-disk encryption is recommended** (for example BitLocker)
  for the volume holding the vault.
* **Vault backups are equally sensitive** as the vault itself and must
  receive the same protection.
* **Ordinary deletion is NOT secure deletion.**  Filesystem journaling,
  snapshots, SSD wear leveling, copy-on-write filesystems and backups may
  retain old vault data after deletion.  No forensic or cryptographic
  secure-deletion guarantee is made or implied anywhere in this package.
* The **pseudonymized output is still pseudonymized, not anonymous** —
  linkage and inference risks remain and are reported by the verification
  tooling; the output must still be treated as confidential.

## Artifact containment

All sensitive artifacts are derived from the single dictionary filename and
stay beside it inside the vault root:

* `dictionary.sqlite3`
* `dictionary.sqlite3-wal` / `-shm` (WAL mode; removed by a clean close)
* `dictionary.sqlite3-journal` (rollback-journal forms during hot journals)
* the reserved private vocabulary for future recovery manifests and
  original-bearing spools (`*.private`)

There is no recovery JSON sidecar, no second SQLite recovery database and no
ordinary output copy of the vault.  Clean close truncates the WAL and
removes the sidecars; a checkpoint failure surfaces as a typed error and is
never reported as success.  Ordinary deletion of vault artifacts does not
overwrite the underlying bytes.