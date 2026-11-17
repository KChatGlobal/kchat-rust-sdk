use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    ContentKey, EncryptedDescriptor, FileCryptoError, NodeKeyRef, OpenedBlob, TenantId,
    descriptor::{open_blob, open_raw_descriptor, request_digest, reseal_blob, seal_blob},
    ids::validate_id,
    key_tree::NodeKind,
};

use super::{
    FileKeyring, from_sql_integer,
    node_keys::{StoredKey, max_active_generation, require_active},
    now_unix_seconds, to_sql_integer,
};

impl FileKeyring {
    /// Seals the descriptor of blob `blob_id` (object `object_id`, its `key`, optional `app`
    /// manifest) with `file_key`, which must be the file's newest active File NodeKey wrapped at the
    /// root's current epoch (`PolicyViolation` otherwise; after a root rotation, `create_file_key`).
    ///
    /// Idempotent per `(tenant, file_id, blob_id)`: the same request returns the stored ciphertext
    /// (even after a reseal); a different one returns `OperationConflict`.
    pub fn seal_descriptor(
        &self,
        file_key: &NodeKeyRef,
        file_id: &str,
        blob_id: &str,
        object_id: &str,
        key: &ContentKey,
        app: Option<&[u8]>,
    ) -> Result<EncryptedDescriptor, FileCryptoError> {
        validate_id(file_id)?;
        validate_id(blob_id)?;
        validate_id(object_id)?;
        let tenant = file_key.tenant();
        let request = request_digest(file_key, object_id, key, app);

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(stored) = load_sealed(&transaction, tenant, file_id, blob_id)? {
            return if stored.request_digest == request {
                Ok(stored.descriptor)
            } else {
                Err(FileCryptoError::operation_conflict())
            };
        }

        let stored_key = file_key_for_write(&transaction, file_key)?;
        let descriptor = seal_blob(file_key, &stored_key.key, file_id, object_id, key, app)?;
        transaction.execute(
            "INSERT INTO encrypted_descriptors (tenant, file_id, blob_id, request_digest, \
             ciphertext, file_node_id, file_generation, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                tenant.as_str(),
                file_id,
                blob_id,
                request.as_slice(),
                descriptor.ciphertext(),
                file_key.node_id(),
                to_sql_integer(file_key.generation())?,
                now_unix_seconds()
            ],
        )?;
        transaction.commit()?;
        Ok(descriptor)
    }

    /// Opens a blob with the descriptor's File NodeKey (from `open_file_key`); the DEK is in the
    /// descriptor, so no pepper or KKey is needed.
    pub fn open_descriptor(
        &self,
        tenant: &TenantId,
        file_id: &str,
        descriptor: &EncryptedDescriptor,
    ) -> Result<OpenedBlob, FileCryptoError> {
        validate_id(file_id)?;
        let stored_key = {
            let connection = self.lock()?;
            // A pending key is an unaccepted candidate: open the server's link first.
            file_key_for_read(&connection, tenant, descriptor)?
        };
        open_blob(tenant, file_id, &stored_key.key, descriptor)
    }

    /// Re-encrypts a blob's descriptor under another File NodeKey, e.g. after
    /// `FILE_EPOCH_MISMATCH` or to publish a private blob to the group lane (`blob_id` is then the
    /// `draft_blob_id`). `new_file_key` must pass the checks of [`FileKeyring::seal_descriptor`],
    /// and within one node its generation must increase (`PolicyViolation`). Retrying returns the
    /// stored descriptor.
    pub fn reseal_descriptor(
        &self,
        file_id: &str,
        blob_id: &str,
        descriptor: &EncryptedDescriptor,
        new_file_key: &NodeKeyRef,
    ) -> Result<EncryptedDescriptor, FileCryptoError> {
        validate_id(file_id)?;
        validate_id(blob_id)?;
        let tenant = new_file_key.tenant();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let old_key = file_key_for_read(&transaction, tenant, descriptor)?;
        let stored = load_sealed(&transaction, tenant, file_id, blob_id)?;
        let mut floor = None;
        if let Some(stored) = &stored {
            let current = &stored.descriptor;
            // A blob has one content: another ciphertext (e.g. pre-reseal) must hold the same plaintext.
            if current != descriptor {
                let current_key = file_key_for_read(&transaction, tenant, current)
                    .map_err(|_| FileCryptoError::store_error())?;
                let current_plaintext =
                    open_raw_descriptor(tenant, file_id, &current_key.key, current)
                        .map_err(|_| FileCryptoError::store_error())?;
                let plaintext = open_raw_descriptor(tenant, file_id, &old_key.key, descriptor)?;
                if *current_plaintext != *plaintext {
                    return Err(FileCryptoError::operation_conflict());
                }
            }
            if current.file_node_id() == new_file_key.node_id()
                && current.file_generation() == new_file_key.generation()
            {
                return Ok(current.clone());
            }
            if current.file_node_id() == new_file_key.node_id() {
                floor = Some(current.file_generation());
            }
        }
        if descriptor.file_node_id() == new_file_key.node_id() {
            floor = floor.max(Some(descriptor.file_generation()));
        }
        if floor.is_some_and(|floor| new_file_key.generation() <= floor) {
            return Err(FileCryptoError::policy_violation());
        }

        let new_key = file_key_for_write(&transaction, new_file_key)?;
        let resealed = reseal_blob(
            tenant,
            file_id,
            (descriptor, &old_key.key),
            (new_file_key, &new_key.key),
        )?;
        if stored.is_some() {
            transaction.execute(
                "UPDATE encrypted_descriptors SET ciphertext = ?4, file_node_id = ?5, \
                 file_generation = ?6, updated_at = ?7 \
                 WHERE tenant = ?1 AND file_id = ?2 AND blob_id = ?3",
                params![
                    tenant.as_str(),
                    file_id,
                    blob_id,
                    resealed.ciphertext(),
                    new_file_key.node_id(),
                    to_sql_integer(new_file_key.generation())?,
                    now_unix_seconds()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(resealed)
    }
}

fn file_key_for_read(
    connection: &Connection,
    tenant: &TenantId,
    descriptor: &EncryptedDescriptor,
) -> Result<StoredKey, FileCryptoError> {
    let stored = require_active(
        connection,
        tenant,
        descriptor.file_node_id(),
        descriptor.file_generation(),
        FileCryptoError::key_sync_required,
    )?;
    if stored.kind != NodeKind::File {
        return Err(FileCryptoError::policy_violation());
    }
    Ok(stored)
}

/// A File NodeKey that may encrypt a descriptor.
fn file_key_for_write(
    connection: &Connection,
    file_key: &NodeKeyRef,
) -> Result<StoredKey, FileCryptoError> {
    let tenant = file_key.tenant();
    let stored = require_active(
        connection,
        tenant,
        file_key.node_id(),
        file_key.generation(),
        FileCryptoError::policy_violation,
    )?;
    if stored.kind != NodeKind::File {
        return Err(FileCryptoError::policy_violation());
    }
    // Rotate-on-write: once the root moves past the epoch that wrapped this key, removed members
    // still hold it, so new content must not use it.
    let wrapped_at = stored.root_epoch.ok_or_else(FileCryptoError::store_error)?;
    if max_active_generation(connection, tenant, &stored.root_id)?
        .is_some_and(|epoch| epoch > wrapped_at)
    {
        return Err(FileCryptoError::policy_violation());
    }
    // KFiles only accepts descriptors at the current `file_epoch`.
    if max_active_generation(connection, tenant, file_key.node_id())?
        .is_some_and(|generation| generation > file_key.generation())
    {
        return Err(FileCryptoError::policy_violation());
    }
    Ok(stored)
}

struct StoredSet {
    request_digest: Vec<u8>,
    descriptor: EncryptedDescriptor,
}

fn load_sealed(
    connection: &Connection,
    tenant: &TenantId,
    file_id: &str,
    blob_id: &str,
) -> Result<Option<StoredSet>, FileCryptoError> {
    type Row = (Vec<u8>, Vec<u8>, String, i64);
    let row: Option<Row> = connection
        .query_row(
            "SELECT request_digest, ciphertext, file_node_id, file_generation \
             FROM encrypted_descriptors WHERE tenant = ?1 AND file_id = ?2 AND blob_id = ?3",
            params![tenant.as_str(), file_id, blob_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((request_digest, ciphertext, file_node_id, file_generation)) = row else {
        return Ok(None);
    };
    let descriptor = EncryptedDescriptor::from_stored(
        file_node_id,
        from_sql_integer(file_generation)?,
        ciphertext,
    );
    Ok(Some(StoredSet {
        request_digest,
        descriptor,
    }))
}
