use rusqlite::{OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    storage_provider::{SqliteConnectionPool, SqliteStorageProvider, TransactionalStorageProvider},
};

pub(crate) struct StorableEpochMigrationState;

impl StorableEpochMigrationState {
    pub(super) fn is_legacy_message_secrets_migration_done(
        connection: &SqliteConnectionPool,
    ) -> Result<bool, rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "SELECT legacy_message_secrets_migration_done
            FROM openmls_epoch_migration_state
            WHERE provider_version = ?1",
        )?;
        let done = stmt
            .query_row(params![STORAGE_PROVIDER_VERSION], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .unwrap_or(0);
        Ok(done != 0)
    }

    pub(super) fn is_legacy_message_secrets_migration_done_in_tx(
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<bool, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT legacy_message_secrets_migration_done
            FROM openmls_epoch_migration_state
            WHERE provider_version = ?1",
        )?;
        let done = stmt
            .query_row(params![STORAGE_PROVIDER_VERSION], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .unwrap_or(0);
        Ok(done != 0)
    }

    pub(super) fn mark_legacy_message_secrets_migration_done(
        connection: &SqliteConnectionPool,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        let mut stmt = connection.prepare_cached(
            "INSERT INTO openmls_epoch_migration_state
                (provider_version, legacy_message_secrets_migration_done)
            VALUES (?1, ?2)
            ON CONFLICT(provider_version) DO UPDATE SET
                legacy_message_secrets_migration_done = excluded.legacy_message_secrets_migration_done",
        )?;
        stmt.execute(params![STORAGE_PROVIDER_VERSION, i64::from(done)])?;
        Ok(())
    }

    pub(super) fn mark_legacy_message_secrets_migration_done_in_tx(
        tx: &rusqlite::Transaction<'_>,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO openmls_epoch_migration_state
                (provider_version, legacy_message_secrets_migration_done)
            VALUES (?1, ?2)
            ON CONFLICT(provider_version) DO UPDATE SET
                legacy_message_secrets_migration_done = excluded.legacy_message_secrets_migration_done",
        )?;
        stmt.execute(params![STORAGE_PROVIDER_VERSION, i64::from(done)])?;
        Ok(())
    }
}

impl<C: Codec> SqliteStorageProvider<C> {
    pub fn is_legacy_message_secrets_migration_done(&self) -> Result<bool, rusqlite::Error> {
        StorableEpochMigrationState::is_legacy_message_secrets_migration_done(
            &self.connection_pool(),
        )
    }

    pub fn mark_legacy_message_secrets_migration_done(
        &self,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        StorableEpochMigrationState::mark_legacy_message_secrets_migration_done(
            &self.connection_pool(),
            done,
        )
    }
}

impl<'tx, C: Codec> TransactionalStorageProvider<'tx, C> {
    pub fn is_legacy_message_secrets_migration_done(&self) -> Result<bool, rusqlite::Error> {
        StorableEpochMigrationState::is_legacy_message_secrets_migration_done_in_tx(self.tx())
    }

    pub fn mark_legacy_message_secrets_migration_done(
        &self,
        done: bool,
    ) -> Result<(), rusqlite::Error> {
        StorableEpochMigrationState::mark_legacy_message_secrets_migration_done_in_tx(
            self.tx(),
            done,
        )
    }
}
