use std::marker::PhantomData;

use openmls_traits::storage::{Key, traits};
use rusqlite::{OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    group_data::GroupDataType,
    group_epoch_meta::StorableGroupEpochMeta,
    storage_provider::{SqliteConnectionPool, SqliteStorageProvider, TransactionalStorageProvider},
    wrappers::{KeyRefWrapper, KeyWrapper},
};

const DEFAULT_MIGRATION_BATCH_SIZE: usize = 20;

pub(crate) struct StorableGroupEpochMessageSecrets(pub Vec<u8>);

impl StorableGroupEpochMessageSecrets {
    fn from_row(row: &rusqlite::Row<'_>) -> Result<Self, rusqlite::Error> {
        Ok(Self(row.get(0)?))
    }

    pub(super) fn load<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "SELECT message_secrets
            FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2
                AND epoch = ?3",
        )?;
        stmt.query_row(
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                epoch,
            ],
            Self::from_row,
        )
        .map(|value| value.0)
        .optional()
    }

    pub(super) fn load_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT message_secrets
            FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2
                AND epoch = ?3",
        )?;
        stmt.query_row(
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                epoch,
            ],
            Self::from_row,
        )
        .map(|value| value.0)
        .optional()
    }

    pub(super) fn store<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
        epoch: u64,
        message_secrets: &[u8],
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "INSERT INTO openmls_group_epoch_message_secrets
                (provider_version, group_id, epoch, message_secrets)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(provider_version, group_id, epoch) DO UPDATE SET
                message_secrets = excluded.message_secrets",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            epoch,
            message_secrets,
        ])?;
        Ok(())
    }

    pub(super) fn store_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
        epoch: u64,
        message_secrets: &[u8],
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO openmls_group_epoch_message_secrets
                (provider_version, group_id, epoch, message_secrets)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(provider_version, group_id, epoch) DO UPDATE SET
                message_secrets = excluded.message_secrets",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            epoch,
            message_secrets,
        ])?;
        Ok(())
    }

    pub(super) fn replace_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
        message_secrets: Vec<(u64, Vec<u8>)>,
    ) -> Result<(), rusqlite::Error> {
        Self::delete_in_tx::<C, _>(tx, group_id)?;
        for (epoch, bytes) in message_secrets {
            Self::store_in_tx::<C, _>(tx, group_id, epoch, &bytes)?;
        }
        StorableGroupEpochMeta::mark_migration_done_in_tx::<C, _>(tx, group_id, true)
    }

    pub(super) fn delete<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
        ])?;
        Ok(())
    }

    pub(super) fn delete_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "DELETE FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
        ])?;
        Ok(())
    }

    pub(super) fn prune<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
        keep_from_epoch: u64,
        current_epoch: u64,
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2
                AND (epoch < ?3 OR epoch > ?4)",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            keep_from_epoch,
            current_epoch,
        ])?;
        Ok(())
    }

    pub(super) fn prune_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
        keep_from_epoch: u64,
        current_epoch: u64,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "DELETE FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2
                AND (epoch < ?3 OR epoch > ?4)",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            keep_from_epoch,
            current_epoch,
        ])?;
        Ok(())
    }

    pub(super) fn list_group_ids_with_message_secrets<
        C: Codec,
        GroupIdT: traits::GroupId<STORAGE_PROVIDER_VERSION> + serde::de::DeserializeOwned,
    >(
        connection: &SqliteConnectionPool,
        limit: usize,
    ) -> Result<Vec<GroupIdT>, rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "SELECT gd.group_id
            FROM openmls_group_data gd
            WHERE gd.provider_version = ?1
                AND gd.data_type = ?2
            ORDER BY gd.rowid DESC
            LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![
                STORAGE_PROVIDER_VERSION,
                GroupDataType::MessageSecrets,
                limit as i64,
            ],
            |row| {
                row.get::<_, KeyWrapper<C, GroupIdT>>(0)
                    .map(|wrapper| wrapper.0)
            },
        )?;
        rows.collect()
    }

    pub(super) fn has_legacy_message_secrets(
        connection: &SqliteConnectionPool,
    ) -> Result<bool, rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "SELECT EXISTS(
                SELECT 1
                FROM openmls_group_data
                WHERE provider_version = ?1
                    AND data_type = ?2
            )",
        )?;
        let exists = stmt.query_row(
            params![STORAGE_PROVIDER_VERSION, GroupDataType::MessageSecrets],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }
}

impl<C: Codec> SqliteStorageProvider<C> {
    pub fn is_group_epoch_message_secrets_migrated<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, rusqlite::Error> {
        StorableGroupEpochMeta::is_migration_done::<C, _>(&self.connection_pool(), group_id)
    }

    pub fn mark_group_epoch_message_secrets_migrated<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMeta::mark_migration_done::<C, _>(&self.connection_pool(), group_id, done)
    }

    pub fn load_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, rusqlite::Error> {
        StorableGroupEpochMessageSecrets::load::<C, _>(&self.connection_pool(), group_id, epoch)
    }

    pub fn upsert_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
        message_secrets: &[u8],
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMessageSecrets::store::<C, _>(
            &self.connection_pool(),
            group_id,
            epoch,
            message_secrets,
        )
    }

    pub fn replace_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_secrets: Vec<(u64, Vec<u8>)>,
    ) -> Result<(), rusqlite::Error> {
        self.connection_pool().transaction(|tx| {
            StorableGroupEpochMessageSecrets::replace_in_tx::<C, _>(tx, group_id, message_secrets)
        })
    }

    pub fn delete_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMessageSecrets::delete::<C, _>(&self.connection_pool(), group_id)
    }

    pub fn prune_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        keep_from_epoch: u64,
        current_epoch: u64,
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMessageSecrets::prune::<C, _>(
            &self.connection_pool(),
            group_id,
            keep_from_epoch,
            current_epoch,
        )
    }

    pub fn list_group_ids_with_message_secrets<
        GroupIdT: traits::GroupId<STORAGE_PROVIDER_VERSION> + serde::de::DeserializeOwned,
    >(
        &self,
    ) -> Result<Vec<GroupIdT>, rusqlite::Error> {
        StorableGroupEpochMessageSecrets::list_group_ids_with_message_secrets::<C, _>(
            &self.connection_pool(),
            DEFAULT_MIGRATION_BATCH_SIZE,
        )
    }

    pub fn has_legacy_message_secrets(&self) -> Result<bool, rusqlite::Error> {
        StorableGroupEpochMessageSecrets::has_legacy_message_secrets(&self.connection_pool())
    }
}

impl<'tx, C: Codec> TransactionalStorageProvider<'tx, C> {
    pub fn load_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, rusqlite::Error> {
        StorableGroupEpochMessageSecrets::load_in_tx::<C, _>(self.tx(), group_id, epoch)
    }

    pub fn upsert_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
        message_secrets: &[u8],
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMessageSecrets::store_in_tx::<C, _>(
            self.tx(),
            group_id,
            epoch,
            message_secrets,
        )
    }

    pub fn replace_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_secrets: Vec<(u64, Vec<u8>)>,
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMessageSecrets::replace_in_tx::<C, _>(
            self.tx(),
            group_id,
            message_secrets,
        )
    }

    pub fn delete_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMessageSecrets::delete_in_tx::<C, _>(self.tx(), group_id)
    }

    pub fn prune_group_epoch_message_secrets<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        keep_from_epoch: u64,
        current_epoch: u64,
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMessageSecrets::prune_in_tx::<C, _>(
            self.tx(),
            group_id,
            keep_from_epoch,
            current_epoch,
        )
    }
}
