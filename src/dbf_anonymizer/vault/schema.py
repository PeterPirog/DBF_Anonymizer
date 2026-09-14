"""Explicit versioned SQLite schema for the protected recovery vault (REQ-P2-002).

This module is PURE: only version/identifier constants, the ordered DDL that
creates the dictionary database, and the expected structural snapshot
vocabularies. It performs no I/O and opens no connection.

Migration policy (frozen for schema 1.0 — no implicit best-effort migration):

* a database whose ``meta.schema_version`` equals
  :data:`VAULT_SCHEMA_VERSION` exactly opens normally;
* any other version (older or newer) fails CLOSED with the typed
  ``VaultError`` code ``VAULT_SCHEMA_UNSUPPORTED``;
* no silent destructive upgrade happens and no unknown database is ever
  dropped or recreated — creation over an existing file is refused.

Journal policy (explicit, never SQLite-default ambiguity):

* the dictionary is created with ``PRAGMA journal_mode = WAL`` for
  deterministic single-writer/multi-reader transaction semantics and
  crash recoverability;
* every clean close runs ``PRAGMA wal_checkpoint(TRUNCATE)`` first, so a
  normal close leaves NO persistent ``-wal``/``-shm`` sidecars behind;
* sidecars that exist while connections are open are internal SQLite
  lifecycle state (the protected-zone treatment of those files is REQ-P2-009,
  which is NOT claimed by this foundation).
"""

from __future__ import annotations

__all__ = [
    "VAULT_SCHEMA_VERSION",
    "VAULT_DATABASE_FILENAME",
    "VAULT_ID_PREFIX",
    "VAULT_OPERATION_ID_PREFIX",
    "VAULT_WRITER_TOKEN_PREFIX",
    "VAULT_TABLE_DOMAIN_KIND_TEXT",
    "VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY",
    "VAULT_OPERATION_STATE_STARTED",
    "VAULT_OPERATION_STATE_COMPLETED",
    "VAULT_PAYLOAD_KIND_TEXT",
    "VAULT_PAYLOAD_KIND_BINARY",
    "VAULT_JOURNAL_MODE",
    "VAULT_CLOSE_CHECKPOINT",
    "EXPECTED_VAULT_TABLES",
    "EXPECTED_VAULT_UNIQUE_INDEXES",
    "DDL_STATEMENTS",
]


#: The only supported dictionary schema version for this release.
VAULT_SCHEMA_VERSION = "1.0"

#: The single database file of one dataset vault (architecture section 8).
VAULT_DATABASE_FILENAME = "dictionary.sqlite3"

#: Stable, privacy-safe, bounded identifier prefixes.
VAULT_ID_PREFIX = "vault-"
VAULT_OPERATION_ID_PREFIX = "vop-"
VAULT_WRITER_TOKEN_PREFIX = "wauth-"

#: Bounded mapping-domain kind vocabulary (structural only; the allocation
#: policy for pseudonyms is REQ-P2-004 and is NOT implemented here).
VAULT_TABLE_DOMAIN_KIND_TEXT = "TEXT"
VAULT_TABLE_DOMAIN_KIND_NUMERIC_KEY = "NUMERIC_KEY"

#: Bounded operation-state vocabulary (REQ-P2-002 operations table).
VAULT_OPERATION_STATE_STARTED = "STARTED"
VAULT_OPERATION_STATE_COMPLETED = "COMPLETED"


VAULT_PAYLOAD_KIND_TEXT = "TEXT"
VAULT_PAYLOAD_KIND_BINARY = "BINARY"

#: Explicit journal policy: write-ahead logging with a truncate checkpoint on
#: every clean close (see module docstring).
VAULT_JOURNAL_MODE = "WAL"
VAULT_CLOSE_CHECKPOINT = "TRUNCATE"

#: The structural snapshot expected after schema 1.0 creation (proven by the
#: schema snapshot tests). Ordered for readable diagnostics only.
EXPECTED_VAULT_TABLES = (
    "meta",
    "dataset",
    "writer_authority",
    "operations",
    "publication",
    "mapping_domains",
    "tables",
    "fields",
    "text_mappings",
    "numeric_key_mappings",
    "memo_recovery",
    "temporal_parameters",
)

#: The named bijection constraints (REQ-P2-003) as stable index names.
EXPECTED_VAULT_UNIQUE_INDEXES = (
    "uq_text_mappings_domain_original",
    "uq_text_mappings_domain_pseudonym",
    "uq_numeric_key_mappings_domain_original",
    "uq_numeric_key_mappings_domain_pseudonym",
)

#: Ordered DDL executed inside ONE creation transaction (deterministic
#: commit boundary; referenced tables are created before their dependants).
DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        schema_version TEXT NOT NULL,
        vault_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        package_version TEXT NOT NULL,
        dbfbridge_version TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE dataset (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        source_fingerprint TEXT NOT NULL,
        policy_fingerprint TEXT NOT NULL,
        relationship_fingerprint TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE writer_authority (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        owner_token TEXT,
        acquire_tick INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE operations (
        operation_id TEXT PRIMARY KEY,
        state TEXT NOT NULL CHECK (state IN ('STARTED', 'COMPLETED')),
        source_fingerprint TEXT,
        output_fingerprint TEXT,
        started_at TEXT,
        completed_at TEXT
    )
    """,
    """
    CREATE TABLE publication (
        operation_id TEXT NOT NULL REFERENCES operations(operation_id),
        phase TEXT NOT NULL,
        output_fingerprint TEXT,
        vault_fingerprint TEXT,
        PRIMARY KEY (operation_id, phase)
    )
    """,
    """
    CREATE TABLE mapping_domains (
        domain_id TEXT PRIMARY KEY,
        domain_kind TEXT NOT NULL CHECK (length(domain_kind) BETWEEN 1 AND 64),
        normalization TEXT,
        relational_role TEXT
    )
    """,
    """
    CREATE TABLE tables (
        table_id TEXT PRIMARY KEY,
        relative_path TEXT NOT NULL UNIQUE,
        schema_fingerprint TEXT,
        source_fingerprint TEXT
    )
    """,
    """
    CREATE TABLE fields (
        field_id TEXT PRIMARY KEY,
        table_id TEXT NOT NULL REFERENCES tables(table_id),
        name TEXT NOT NULL,
        dbf_type TEXT NOT NULL,
        encoding TEXT,
        width INTEGER NOT NULL CHECK (width >= 0),
        transform_action TEXT,
        mapping_domain_id TEXT REFERENCES mapping_domains(domain_id),
        UNIQUE (table_id, name)
    )
    """,
    """
    CREATE TABLE text_mappings (
        domain_id TEXT NOT NULL REFERENCES mapping_domains(domain_id),
        original_value TEXT NOT NULL,
        pseudonym_value TEXT NOT NULL,
        logical_byte_length INTEGER NOT NULL CHECK (logical_byte_length >= 0)
    )
    """,
    """
    CREATE UNIQUE INDEX uq_text_mappings_domain_original
        ON text_mappings (domain_id, original_value)
    """,
    """
    CREATE UNIQUE INDEX uq_text_mappings_domain_pseudonym
        ON text_mappings (domain_id, pseudonym_value)
    """,
    """
    CREATE TABLE numeric_key_mappings (
        domain_id TEXT NOT NULL REFERENCES mapping_domains(domain_id),
        original_value TEXT NOT NULL,
        pseudonym_value TEXT NOT NULL
    )
    """,
    """
    CREATE UNIQUE INDEX uq_numeric_key_mappings_domain_original
        ON numeric_key_mappings (domain_id, original_value)
    """,
    """
    CREATE UNIQUE INDEX uq_numeric_key_mappings_domain_pseudonym
        ON numeric_key_mappings (domain_id, pseudonym_value)
    """,
    """
    CREATE TABLE memo_recovery (
        table_id TEXT NOT NULL REFERENCES tables(table_id),
        physical_record_index INTEGER NOT NULL CHECK (physical_record_index >= 0),
        field_id TEXT NOT NULL REFERENCES fields(field_id),
        original_payload BLOB NOT NULL,
        payload_kind TEXT NOT NULL CHECK (payload_kind IN ('TEXT', 'BINARY')),
        PRIMARY KEY (table_id, physical_record_index, field_id)
    )
    """,
    """
    CREATE TABLE temporal_parameters (
        domain_id TEXT PRIMARY KEY REFERENCES mapping_domains(domain_id),
        offset_days INTEGER NOT NULL
    )
    """,
    # Lookup-support indexes for the enforced foreign keys.
    "CREATE INDEX idx_fields_table ON fields (table_id)",
    "CREATE INDEX idx_fields_domain ON fields (mapping_domain_id)",
    "CREATE INDEX idx_memo_recovery_field ON memo_recovery (field_id)",
)

#: Writer-authority lease seed row and the single meta/dataset rows.
CREATE_META_SEED: tuple[tuple[str, tuple[object, ...]], ...] = (
    (
        "INSERT INTO writer_authority (singleton, owner_token, acquire_tick) "
        "VALUES (1, NULL, 0)",
        (),
    ),
)