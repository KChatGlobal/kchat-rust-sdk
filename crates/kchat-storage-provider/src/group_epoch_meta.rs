use std::marker::PhantomData;

use openmls_traits::storage::Key;
use rusqlite::{OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    storage_provider::{SqliteConnectionPool, TransactionalStorageProvider},
    wrappers::KeyRefWrapper,
};

pub(crate) struct StorableGroupEpochMeta;

impl StorableGroupEpochMeta {
    pub(super) fn is_migration_done<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
    ) -> Result<bool, rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "SELECT migration_done
            FROM openmls_group_epoch_meta
            WHERE provider_version = ?1
                AND group_id = ?2",
        )?;
        let done = stmt
            .query_row(
                params![
                    STORAGE_PROVIDER_VERSION,
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(done != 0)
    }

    pub(super) fn is_migration_done_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<bool, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT migration_done
            FROM openmls_group_epoch_meta
            WHERE provider_version = ?1
                AND group_id = ?2",
        )?;
        let done = stmt
            .query_row(
                params![
                    STORAGE_PROVIDER_VERSION,
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(done != 0)
    }

    pub(super) fn mark_migration_done<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "INSERT INTO openmls_group_epoch_meta (provider_version, group_id, migration_done)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(provider_version, group_id) DO UPDATE SET
                migration_done = excluded.migration_done",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            i64::from(done),
        ])?;
        Ok(())
    }

    pub(super) fn mark_migration_done_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO openmls_group_epoch_meta (provider_version, group_id, migration_done)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(provider_version, group_id) DO UPDATE SET
                migration_done = excluded.migration_done",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            i64::from(done),
        ])?;
        Ok(())
    }
}

impl<'tx, C: Codec> TransactionalStorageProvider<'tx, C> {
    pub fn is_group_epoch_message_secrets_migrated<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, rusqlite::Error> {
        StorableGroupEpochMeta::is_migration_done_in_tx::<C, _>(self.tx(), group_id)
    }

    pub fn mark_group_epoch_message_secrets_migrated<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        StorableGroupEpochMeta::mark_migration_done_in_tx::<C, _>(self.tx(), group_id, done)
    }
}
