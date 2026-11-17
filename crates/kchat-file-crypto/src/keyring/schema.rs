//! Key store schema. Once deployed, migrations are forward-only: never edit one, append to
//! `MIGRATIONS`.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::FileCryptoError;

const SCHEMA_VERSION_KEY: &str = "schema_version";
const ACCOUNT_ID_KEY: &str = "account_id";

/// Applied in order; entry `n` upgrades the schema from version `n` to `n + 1`.
const MIGRATIONS: &[&str] = &[V1];

// kkey_floors holds rollback floors per signing root and tenant: they outlive the signed rows, so
// reopening with an old root still rejects older configuration. node_keys.generation is the root
// epoch for roots and `file_epoch` for File NodeKeys; root_id keeps personal-branch keys out of
// groups; root_epoch drives rotate-on-write. processed_events expire, hence the time index.
const V1: &str = "
CREATE TABLE peppers (
    tenant      TEXT    NOT NULL,
    generation  INTEGER NOT NULL,
    pepper      BLOB    NOT NULL,
    commitment  BLOB    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('pending', 'active')),
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (tenant, generation)
) WITHOUT ROWID;

CREATE TABLE kkey_keys (
    tenant      TEXT    NOT NULL,
    key_gen     INTEGER NOT NULL,
    public_key  BLOB    NOT NULL,
    signature   BLOB    NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (tenant, key_gen)
) WITHOUT ROWID;

CREATE TABLE kkey_policies (
    tenant         TEXT    NOT NULL PRIMARY KEY,
    policy         TEXT    NOT NULL,
    policy_version INTEGER NOT NULL,
    signature      BLOB    NOT NULL,
    received_at    INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE prepared_ops (
    operation_id     TEXT    NOT NULL PRIMARY KEY,
    kind             TEXT    NOT NULL CHECK (kind IN ('content')),
    plaintext_sha256 BLOB    NOT NULL,
    plaintext_len    INTEGER NOT NULL,
    profile          TEXT    NOT NULL,
    tenant           TEXT,
    key_gen          INTEGER,
    pepper_gen       INTEGER,
    dek              BLOB    NOT NULL,
    nonce_prefix     BLOB    NOT NULL,
    random_reason    TEXT,
    created_at       INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE processed_events (
    event_id       BLOB    NOT NULL PRIMARY KEY,
    kind           TEXT    NOT NULL,
    sender_account TEXT    NOT NULL,
    sender_device  TEXT    NOT NULL,
    tenant         TEXT    NOT NULL,
    result         TEXT    NOT NULL,
    processed_at   INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE node_keys (
    tenant      TEXT    NOT NULL,
    node_id     TEXT    NOT NULL,
    generation  INTEGER NOT NULL CHECK (generation >= 0),
    kind        INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    root_id     TEXT    NOT NULL,
    root_epoch  INTEGER CHECK (root_epoch >= 0),
    node_key    BLOB    NOT NULL,
    key_hash    BLOB    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('pending', 'active')),
    source      TEXT    NOT NULL CHECK (source IN ('created', 'received', 'link')),
    updated_at  INTEGER NOT NULL,
    CHECK ((kind = 3) = (root_epoch IS NOT NULL)),
    PRIMARY KEY (tenant, node_id, generation)
) WITHOUT ROWID;

CREATE TABLE encrypted_descriptors (
    tenant          TEXT    NOT NULL,
    file_id         TEXT    NOT NULL,
    blob_id         TEXT    NOT NULL,
    request_digest  BLOB    NOT NULL,
    ciphertext      BLOB    NOT NULL,
    file_node_id    TEXT    NOT NULL,
    file_generation INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (tenant, file_id, blob_id)
) WITHOUT ROWID;

CREATE TABLE kkey_floors (
    root           BLOB    NOT NULL,
    tenant         TEXT    NOT NULL,
    key_gen        INTEGER,
    policy_version INTEGER,
    PRIMARY KEY (root, tenant)
) WITHOUT ROWID;

CREATE INDEX processed_events_by_time ON processed_events (processed_at);
";

/// Creates or upgrades the schema and binds the store to `account_id`, in one transaction. The
/// account is checked first, so another account's store is never modified.
pub(super) fn migrate(
    connection: &mut Connection,
    account_id: &str,
) -> Result<(), FileCryptoError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL) \
         WITHOUT ROWID;",
    )?;

    match read_meta(&transaction, ACCOUNT_ID_KEY)? {
        Some(stored) if stored != account_id => return Err(FileCryptoError::account_mismatch()),
        Some(_) => {}
        None => write_meta(&transaction, ACCOUNT_ID_KEY, account_id)?,
    }

    let version = match read_meta(&transaction, SCHEMA_VERSION_KEY)? {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| FileCryptoError::store_error())?,
        None => 0,
    };
    // A store written by a newer SDK cannot be interpreted safely.
    if version > MIGRATIONS.len() {
        return Err(FileCryptoError::store_error());
    }
    for migration in &MIGRATIONS[version..] {
        transaction.execute_batch(migration)?;
    }
    if version != MIGRATIONS.len() {
        write_meta(
            &transaction,
            SCHEMA_VERSION_KEY,
            &MIGRATIONS.len().to_string(),
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn read_meta(connection: &Connection, key: &str) -> Result<Option<String>, FileCryptoError> {
    Ok(connection
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

fn write_meta(connection: &Connection, key: &str, value: &str) -> Result<(), FileCryptoError> {
    connection.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}
