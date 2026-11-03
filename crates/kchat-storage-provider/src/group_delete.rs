use std::marker::PhantomData;

use openmls_traits::storage::Key;
use rusqlite::params;

use crate::{
    STORAGE_PROVIDER_VERSION, codec::Codec, sqlite_error_context,
    storage_provider::TransactionalStorageProvider, wrappers::KeyRefWrapper,
};

impl<C: Codec> TransactionalStorageProvider<'_, C> {
    /// Delete all group-scoped rows without decoding potentially incomplete state.
    /// Account credentials, key packages and unscoped keys are preserved.
    /// The caller must propagate errors to roll back the enclosing transaction.
    pub fn delete_group_by_id<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        for table in [
            "openmls_group_data",
            "openmls_epoch_keys_pairs",
            "openmls_own_leaf_nodes",
            "openmls_proposals",
            "openmls_group_epoch_message_secrets",
            "openmls_decrypted_application_messages",
        ] {
            self.tx()
                .execute(
                    &format!("DELETE FROM {table} WHERE provider_version = ?1 AND group_id = ?2"),
                    params![
                        STORAGE_PROVIDER_VERSION,
                        KeyRefWrapper::<C, _>(group_id, PhantomData)
                    ],
                )
                .map_err(|error| {
                    sqlite_error_context(error, &format!("delete_group MLS table {table}"))
                })?;
        }
        Ok(())
    }
}
