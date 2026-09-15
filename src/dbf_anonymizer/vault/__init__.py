"""One protected SQLite recovery vault per pseudonymization dataset.

This internal package implements the REQ-P2-001/002/003 storage foundation:

* exactly ONE authoritative ``dictionary.sqlite3`` per dataset
  (:func:`VaultDatabase.open` is the only creation/open path);
* an explicit versioned schema (schema 1.0, exact-match migration policy,
  fail-closed integrity/identity validation);
* database-enforced mapping bijections, enforced foreign keys, deterministic
  ``BEGIN IMMEDIATE`` transaction units and a durable single logical writer
  authority (``writer_authority`` lease row).

The vault is an internal subsystem for the execution engine: it is NOT
exported through the public package root and NOT reachable from
``build_plan``/``preflight`` (which stay source-read-only), never parses or
writes DBF/FPT files and never imports the ``dbfbridge`` namespace. Secure
pseudonym ALLOCATION for the one global text domain (REQ-P2-004/005/006)
lives in :mod:`dbf_anonymizer.vault.text_allocation` on top of this storage
foundation.
"""

from __future__ import annotations

from dbf_anonymizer.vault.schema import (
    DDL_STATEMENTS,
    EXPECTED_VAULT_TABLES,
    EXPECTED_VAULT_UNIQUE_INDEXES,
    VAULT_CLOSE_CHECKPOINT,
    VAULT_DATABASE_FILENAME,
    VAULT_ID_PREFIX,
    VAULT_JOURNAL_MODE,
    VAULT_OPERATION_ID_PREFIX,
    VAULT_PAYLOAD_KIND_BINARY,
    VAULT_PAYLOAD_KIND_TEXT,
    VAULT_SCHEMA_VERSION,
    VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY,
    VAULT_TABLE_DOMAIN_KIND_TEXT,
    VAULT_WRITER_TOKEN_PREFIX,
)
from dbf_anonymizer.vault.store import (
    VaultDatabase,
    default_dictionary_path,
    new_writer_token,
)
from dbf_anonymizer.vault.transactions import VaultTransaction
from dbf_anonymizer.vault.text_allocation import (
    GLOBAL_TEXT_DOMAIN_ID,
    GLOBAL_TEXT_PROBE_BUDGET,
    GlobalTextDomainMapping,
)

__all__ = [
    "VAULT_SCHEMA_VERSION",
    "VAULT_DATABASE_FILENAME",
    "VAULT_ID_PREFIX",
    "VAULT_OPERATION_ID_PREFIX",
    "VAULT_WRITER_TOKEN_PREFIX",
    "VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY",
    "VAULT_TABLE_DOMAIN_KIND_TEXT",
    "VAULT_PAYLOAD_KIND_BINARY",
    "VAULT_PAYLOAD_KIND_TEXT",
    "VAULT_JOURNAL_MODE",
    "VAULT_CLOSE_CHECKPOINT",
    "EXPECTED_VAULT_TABLES",
    "EXPECTED_VAULT_UNIQUE_INDEXES",
    "DDL_STATEMENTS",
    "VaultDatabase",
    "VaultTransaction",
    "default_dictionary_path",
    "new_writer_token",
    "GLOBAL_TEXT_DOMAIN_ID",
    "GLOBAL_TEXT_PROBE_BUDGET",
    "GlobalTextDomainMapping",
]
