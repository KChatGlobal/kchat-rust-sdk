//! Root keys and File NodeKeys in the key store (format in `crate::key_tree`).
//!
//! Root keys are created and rotated through a server CAS, like peppers. File NodeKeys rotate on
//! write: once the root moves to a newer epoch, the next write needs a new File NodeKey wrapped at
//! that epoch. Active keys are never deleted or replaced (`KeyConflict`).

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    FileCryptoError, KeyProposal, NewFileKey, NodeKeyRef, NodeLink, RootId, TenantId,
    control::RootKeyEntry,
    ids::validate_id,
    key_tree::{KEY_HASH_BYTES, NodeKind, SecretKey, validate_generation},
};

use super::{FileKeyring, blob, from_sql_integer, now_unix_seconds, to_sql_integer};

const STATE_PENDING: &str = "pending";
pub(super) const STATE_ACTIVE: &str = "active";
const SOURCE_CREATED: &str = "created";
pub(super) const SOURCE_RECEIVED: &str = "received";
const SOURCE_LINK: &str = "link";

impl FileKeyring {
    /// Generates a pending key for `root` and returns `(epoch, key_hash)` for the host's CAS: epoch
    /// 0 for a root without keys, otherwise the highest active epoch + 1. Retries return the same
    /// pending key.
    pub fn propose_root_key(&self, root: &RootId) -> Result<KeyProposal, FileCryptoError> {
        let (tenant, node) = (root.tenant(), root.node_id());
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_root(&transaction, root)?;

        let latest = max_active_generation(&transaction, tenant, node)?;
        if let Some((epoch, key_hash)) = pending_key(&transaction, tenant, node)? {
            if latest.is_none_or(|latest| epoch > latest) {
                return Ok(KeyProposal::new(
                    NodeKeyRef::new(tenant, node, epoch)?,
                    key_hash,
                ));
            }
            // Stale: the CAS winner's key for that epoch has arrived.
            delete_pending(&transaction, tenant, node)?;
        }

        let epoch = latest.map_or(Ok(0), next_generation)?;
        let key = SecretKey::generate()?;
        let key_hash = key.key_hash(tenant, node, epoch);
        insert_key(
            &transaction,
            &NewRow {
                tenant,
                node_id: node,
                generation: epoch,
                kind: root.kind().node_kind(),
                root_id: node,
                root_epoch: None,
                key: &key,
                key_hash: &key_hash,
                state: STATE_PENDING,
                source: SOURCE_CREATED,
            },
        )?;
        transaction.commit()?;
        Ok(KeyProposal::new(
            NodeKeyRef::new(tenant, node, epoch)?,
            key_hash,
        ))
    }

    /// Activates a pending root key or File NodeKey once the server accepts it. Idempotent.
    pub fn activate_node_key(&self, key: &NodeKeyRef) -> Result<(), FileCryptoError> {
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE node_keys SET state = ?4, updated_at = ?5 \
             WHERE tenant = ?1 AND node_id = ?2 AND generation = ?3",
            params![
                key.tenant().as_str(),
                key.node_id(),
                to_sql_integer(key.generation())?,
                STATE_ACTIVE,
                now_unix_seconds()
            ],
        )?;
        if changed == 0 {
            return Err(FileCryptoError::invalid_argument());
        }
        Ok(())
    }

    /// Discards a pending key after **definitely** losing the CAS (after a timeout, ask the server
    /// first: discarding the winner would leave nobody with that epoch). No-op on active keys.
    pub fn discard_node_key(&self, key: &NodeKeyRef) -> Result<(), FileCryptoError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM node_keys \
             WHERE tenant = ?1 AND node_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                key.tenant().as_str(),
                key.node_id(),
                to_sql_integer(key.generation())?,
                STATE_PENDING
            ],
        )?;
        Ok(())
    }

    pub fn root_epoch(&self, root: &RootId) -> Result<Option<u64>, FileCryptoError> {
        let connection = self.lock()?;
        check_root(&connection, root)?;
        max_active_generation(&connection, root.tenant(), root.node_id())
    }

    /// Returns a File NodeKey for `file_node_id` wrapped at the root's current epoch, plus the link
    /// for `CommitUpload.file_key_operation`.
    ///
    /// Generation 0 (`CREATE`) for a file without an active key; the latest generation + 1
    /// (`ROTATE`) if the latest key was wrapped at an older root epoch; otherwise the latest key
    /// with a fresh link. New keys stay pending until `activate_node_key`. Only keys on this device
    /// count: if the server has a newer `file_epoch`, `open_file_key` it first.
    pub fn create_file_key(
        &self,
        root: &RootId,
        file_node_id: &str,
    ) -> Result<NewFileKey, FileCryptoError> {
        validate_id(file_node_id)?;
        let (tenant, root_node) = (root.tenant(), root.node_id());
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_root(&transaction, root)?;
        let root_epoch = max_active_generation(&transaction, tenant, root_node)?
            .ok_or_else(FileCryptoError::key_sync_required)?;
        let root_key = load_key(&transaction, tenant, root_node, root_epoch)?
            .ok_or_else(FileCryptoError::invalid_state)?;
        // A file belongs to one root, so personal-branch keys never get wrapped into a group.
        check_node(
            &transaction,
            tenant,
            file_node_id,
            NodeKind::File,
            root_node,
        )?;

        let latest = latest_file_key(&transaction, tenant, file_node_id, STATE_ACTIVE)?;
        if latest.is_some_and(|latest| latest.root_epoch > root_epoch) {
            return Err(FileCryptoError::key_sync_required());
        }
        // Reuse an unresolved candidate at this epoch, else the latest key if the root has not
        // rotated since it was wrapped.
        let reused = match latest_file_key(&transaction, tenant, file_node_id, STATE_PENDING)? {
            Some(pending)
                if pending.root_epoch == root_epoch
                    && latest.is_none_or(|latest| pending.generation > latest.generation) =>
            {
                Some(pending.generation)
            }
            _ => {
                delete_pending(&transaction, tenant, file_node_id)?;
                latest
                    .filter(|latest| latest.root_epoch == root_epoch)
                    .map(|latest| latest.generation)
            }
        };

        let (generation, file_key) = match reused {
            Some(generation) => {
                let stored = load_key(&transaction, tenant, file_node_id, generation)?
                    .ok_or_else(FileCryptoError::store_error)?;
                (generation, stored.key)
            }
            None => {
                let generation =
                    latest.map_or(Ok(0), |latest| next_generation(latest.generation))?;
                let key = SecretKey::generate()?;
                insert_key(
                    &transaction,
                    &NewRow {
                        tenant,
                        node_id: file_node_id,
                        generation,
                        kind: NodeKind::File,
                        root_id: root_node,
                        root_epoch: Some(root_epoch),
                        key: &key,
                        key_hash: &key.key_hash(tenant, file_node_id, generation),
                        state: STATE_PENDING,
                        source: SOURCE_CREATED,
                    },
                )?;
                (generation, key)
            }
        };
        let link = NodeLink::wrap(
            root,
            root_epoch,
            &root_key.key,
            file_node_id,
            generation,
            &file_key,
        )?;
        transaction.commit()?;
        Ok(NewFileKey::new(link))
    }

    /// Unwraps a File NodeKey from a server link with the root key of `link.epoch()` and stores it
    /// as active.
    pub fn open_file_key(&self, link: &NodeLink) -> Result<NodeKeyRef, FileCryptoError> {
        let root = link.root();
        let (tenant, root_node) = (root.tenant(), root.node_id());
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_root(&transaction, root)?;
        let root_key = require_active(
            &transaction,
            tenant,
            root_node,
            link.epoch(),
            FileCryptoError::key_sync_required,
        )?;
        let file_key = link.unwrap(&root_key.key)?;

        check_node(
            &transaction,
            tenant,
            link.file_node_id(),
            NodeKind::File,
            root_node,
        )?;
        store_received_key(
            &transaction,
            &NewRow {
                tenant,
                node_id: link.file_node_id(),
                generation: link.file_generation(),
                kind: NodeKind::File,
                root_id: root_node,
                root_epoch: Some(link.epoch()),
                key: &file_key,
                key_hash: &file_key.key_hash(tenant, link.file_node_id(), link.file_generation()),
                state: STATE_ACTIVE,
                source: SOURCE_LINK,
            },
        )?;
        transaction.commit()?;
        Ok(link.file_key_ref())
    }
}

pub(super) struct StoredKey {
    pub(super) kind: NodeKind,
    pub(super) root_id: String,
    /// Root epoch that wrapped a File NodeKey; `None` for root keys.
    pub(super) root_epoch: Option<u64>,
    pub(super) key: SecretKey,
    pub(super) key_hash: [u8; KEY_HASH_BYTES],
    pub(super) active: bool,
}

pub(super) struct NewRow<'a> {
    pub(super) tenant: &'a TenantId,
    pub(super) node_id: &'a str,
    pub(super) generation: u64,
    pub(super) kind: NodeKind,
    pub(super) root_id: &'a str,
    /// Root epoch that wrapped a File NodeKey; `None` for root keys.
    pub(super) root_epoch: Option<u64>,
    pub(super) key: &'a SecretKey,
    pub(super) key_hash: &'a [u8; KEY_HASH_BYTES],
    pub(super) state: &'a str,
    pub(super) source: &'a str,
}

pub(super) fn load_key(
    connection: &Connection,
    tenant: &TenantId,
    node_id: &str,
    generation: u64,
) -> Result<Option<StoredKey>, FileCryptoError> {
    let mut statement = connection.prepare(
        "SELECT kind, root_id, node_key, key_hash, state, root_epoch FROM node_keys \
         WHERE tenant = ?1 AND node_id = ?2 AND generation = ?3",
    )?;
    let mut rows = statement.query(params![
        tenant.as_str(),
        node_id,
        to_sql_integer(generation)?
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let root_epoch: Option<i64> = row.get(5)?;
    Ok(Some(StoredKey {
        kind: NodeKind::from_u8(row.get(0)?).ok_or_else(FileCryptoError::store_error)?,
        root_id: row.get(1)?,
        root_epoch: root_epoch.map(from_sql_integer).transpose()?,
        key: SecretKey::from_slice(blob(row, 2)?).map_err(|_| FileCryptoError::store_error())?,
        key_hash: blob(row, 3)?
            .try_into()
            .map_err(|_| FileCryptoError::store_error())?,
        active: row.get::<_, String>(4)? == STATE_ACTIVE,
    }))
}

/// A missing key returns `KeySyncRequired`; a pending one returns `pending_error()`.
pub(super) fn require_active(
    connection: &Connection,
    tenant: &TenantId,
    node_id: &str,
    generation: u64,
    pending_error: fn() -> FileCryptoError,
) -> Result<StoredKey, FileCryptoError> {
    match load_key(connection, tenant, node_id, generation)? {
        None => Err(FileCryptoError::key_sync_required()),
        Some(stored) if !stored.active => Err(pending_error()),
        Some(stored) => Ok(stored),
    }
}

/// Active root key `epoch` of `root`, as `require_active`.
pub(super) fn active_root_key(
    connection: &Connection,
    root: &RootId,
    epoch: u64,
    pending_error: fn() -> FileCryptoError,
) -> Result<RootKeyEntry, FileCryptoError> {
    let stored = require_active(
        connection,
        root.tenant(),
        root.node_id(),
        epoch,
        pending_error,
    )?;
    Ok(RootKeyEntry {
        epoch,
        key: stored.key,
        key_hash: stored.key_hash,
    })
}

/// The newest `limit` active epochs of `root`, in ascending order.
pub(super) fn active_root_keys(
    connection: &Connection,
    root: &RootId,
    limit: usize,
) -> Result<Vec<RootKeyEntry>, FileCryptoError> {
    let mut statement = connection.prepare(
        "SELECT generation FROM (SELECT generation FROM node_keys \
         WHERE tenant = ?1 AND node_id = ?2 AND state = ?3 ORDER BY generation DESC LIMIT ?4) \
         ORDER BY generation",
    )?;
    let limit = i64::try_from(limit).map_err(|_| FileCryptoError::invalid_argument())?;
    let generations = statement
        .query_map(
            params![root.tenant().as_str(), root.node_id(), STATE_ACTIVE, limit],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    generations
        .into_iter()
        .map(|generation| {
            active_root_key(
                connection,
                root,
                from_sql_integer(generation)?,
                FileCryptoError::store_error,
            )
        })
        .collect()
}

/// `root` must not share its node id with a node of another kind.
pub(super) fn check_root(connection: &Connection, root: &RootId) -> Result<(), FileCryptoError> {
    check_node(
        connection,
        root.tenant(),
        root.node_id(),
        root.kind().node_kind(),
        root.node_id(),
    )
}

/// Ensures `node_id` was never used with another kind or under another root.
pub(super) fn check_node(
    connection: &Connection,
    tenant: &TenantId,
    node_id: &str,
    kind: NodeKind,
    root_id: &str,
) -> Result<(), FileCryptoError> {
    // All rows of a node share its kind and root (this function's invariant): one row suffices.
    let existing: Option<(u8, String)> = connection
        .query_row(
            "SELECT kind, root_id FROM node_keys WHERE tenant = ?1 AND node_id = ?2 LIMIT 1",
            params![tenant.as_str(), node_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match existing {
        Some((stored_kind, stored_root))
            if stored_kind != kind.as_u8() || stored_root != root_id =>
        {
            Err(FileCryptoError::policy_violation())
        }
        _ => Ok(()),
    }
}

pub(super) fn max_active_generation(
    connection: &Connection,
    tenant: &TenantId,
    node_id: &str,
) -> Result<Option<u64>, FileCryptoError> {
    let generation: Option<i64> = connection.query_row(
        "SELECT MAX(generation) FROM node_keys WHERE tenant = ?1 AND node_id = ?2 AND state = ?3",
        params![tenant.as_str(), node_id, STATE_ACTIVE],
        |row| row.get(0),
    )?;
    generation.map(from_sql_integer).transpose()
}

/// Stores a received key (over MLS or from a link) as active, in the caller's transaction. A
/// pending local candidate is replaced; a different active key returns `KeyConflict`.
pub(super) fn store_received_key(
    connection: &Connection,
    row: &NewRow<'_>,
) -> Result<(), FileCryptoError> {
    match load_key(connection, row.tenant, row.node_id, row.generation)? {
        Some(stored) if stored.active => {
            return if stored.key_hash == *row.key_hash {
                Ok(())
            } else {
                Err(FileCryptoError::key_conflict())
            };
        }
        Some(_) => {
            connection.execute(
                "DELETE FROM node_keys WHERE tenant = ?1 AND node_id = ?2 AND generation = ?3",
                params![
                    row.tenant.as_str(),
                    row.node_id,
                    to_sql_integer(row.generation)?
                ],
            )?;
        }
        None => {}
    }
    insert_key(connection, row)
}

fn next_generation(latest: u64) -> Result<u64, FileCryptoError> {
    latest
        .checked_add(1)
        .filter(|generation| validate_generation(*generation).is_ok())
        .ok_or_else(FileCryptoError::resource_limit_exceeded)
}

fn delete_pending(
    connection: &Connection,
    tenant: &TenantId,
    node_id: &str,
) -> Result<(), FileCryptoError> {
    connection.execute(
        "DELETE FROM node_keys WHERE tenant = ?1 AND node_id = ?2 AND state = ?3",
        params![tenant.as_str(), node_id, STATE_PENDING],
    )?;
    Ok(())
}

fn pending_key(
    connection: &Connection,
    tenant: &TenantId,
    node_id: &str,
) -> Result<Option<(u64, [u8; KEY_HASH_BYTES])>, FileCryptoError> {
    let row: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT generation, key_hash FROM node_keys \
             WHERE tenant = ?1 AND node_id = ?2 AND state = ?3 \
             ORDER BY generation DESC LIMIT 1",
            params![tenant.as_str(), node_id, STATE_PENDING],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(generation, key_hash)| {
        Ok((
            from_sql_integer(generation)?,
            key_hash
                .as_slice()
                .try_into()
                .map_err(|_| FileCryptoError::store_error())?,
        ))
    })
    .transpose()
}

#[derive(Clone, Copy)]
struct FileKeyHead {
    generation: u64,
    root_epoch: u64,
}

fn latest_file_key(
    connection: &Connection,
    tenant: &TenantId,
    file_node_id: &str,
    state: &str,
) -> Result<Option<FileKeyHead>, FileCryptoError> {
    let row: Option<(i64, Option<i64>)> = connection
        .query_row(
            "SELECT generation, root_epoch FROM node_keys \
             WHERE tenant = ?1 AND node_id = ?2 AND state = ?3 \
             ORDER BY generation DESC LIMIT 1",
            params![tenant.as_str(), file_node_id, state],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(generation, root_epoch)| {
        Ok(FileKeyHead {
            generation: from_sql_integer(generation)?,
            root_epoch: from_sql_integer(root_epoch.ok_or_else(FileCryptoError::store_error)?)?,
        })
    })
    .transpose()
}

fn insert_key(connection: &Connection, row: &NewRow<'_>) -> Result<(), FileCryptoError> {
    connection.execute(
        "INSERT INTO node_keys (tenant, node_id, generation, kind, root_id, root_epoch, node_key, \
         key_hash, state, source, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            row.tenant.as_str(),
            row.node_id,
            to_sql_integer(row.generation)?,
            row.kind.as_u8(),
            row.root_id,
            row.root_epoch.map(to_sql_integer).transpose()?,
            row.key.as_bytes().as_slice(),
            row.key_hash.as_slice(),
            row.state,
            row.source,
            now_unix_seconds()
        ],
    )?;
    Ok(())
}
