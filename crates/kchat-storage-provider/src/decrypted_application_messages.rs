use std::marker::PhantomData;

use openmls_traits::storage::Key;
use rusqlite::{OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    storage_provider::{SqliteConnectionPool, SqliteStorageProvider, TransactionalStorageProvider},
    wrappers::KeyRefWrapper,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedApplicationMessage {
    pub ciphertext_digest: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
}

struct StorableDecryptedApplicationMessage;

impl StorableDecryptedApplicationMessage {
    fn from_row(row: &rusqlite::Row<'_>) -> Result<DecryptedApplicationMessage, rusqlite::Error> {
        Ok(DecryptedApplicationMessage {
            ciphertext_digest: row.get(0)?,
            plaintext: row.get(1)?,
            created_at: row.get(2)?,
            expires_at: row.get(3)?,
        })
    }

    fn load_in_connection<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
        message_id: &str,
        now: i64,
    ) -> Result<Option<DecryptedApplicationMessage>, rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "SELECT ciphertext_digest, plaintext, created_at, expires_at
            FROM openmls_decrypted_application_messages
            WHERE provider_version = ?1
                AND group_id = ?2
                AND message_id = ?3
                AND expires_at > ?4",
        )?;
        stmt.query_row(
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                message_id,
                now,
            ],
            Self::from_row,
        )
        .optional()
    }

    pub(super) fn load<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
        message_id: &str,
        now: i64,
    ) -> Result<Option<DecryptedApplicationMessage>, rusqlite::Error> {
        let connection = connection.checkout()?;
        Self::load_in_connection::<C, _>(&connection, group_id, message_id, now)
    }

    pub(super) fn load_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
        message_id: &str,
        now: i64,
    ) -> Result<Option<DecryptedApplicationMessage>, rusqlite::Error> {
        Self::load_in_connection::<C, _>(tx, group_id, message_id, now)
    }

    fn insert_in_connection<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
        message_id: &str,
        entry: &DecryptedApplicationMessage,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "INSERT INTO openmls_decrypted_application_messages
                (provider_version, group_id, message_id, ciphertext_digest, plaintext, created_at, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(group_id, message_id) DO UPDATE SET
                provider_version = excluded.provider_version,
                ciphertext_digest = excluded.ciphertext_digest,
                plaintext = excluded.plaintext,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
            WHERE openmls_decrypted_application_messages.expires_at <= excluded.created_at",
        )?;
        stmt.execute(params![
            STORAGE_PROVIDER_VERSION,
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            message_id,
            entry.ciphertext_digest,
            entry.plaintext,
            entry.created_at,
            entry.expires_at,
        ])?;
        Ok(())
    }

    pub(super) fn insert<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
        message_id: &str,
        entry: &DecryptedApplicationMessage,
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        Self::insert_in_connection::<C, _>(&connection, group_id, message_id, entry)
    }

    pub(super) fn insert_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
        message_id: &str,
        entry: &DecryptedApplicationMessage,
    ) -> Result<(), rusqlite::Error> {
        Self::insert_in_connection::<C, _>(tx, group_id, message_id, entry)
    }

    fn prune_in_connection(
        connection: &rusqlite::Connection,
        now: i64,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_decrypted_application_messages
            WHERE provider_version = ?1
                AND expires_at <= ?2",
            params![STORAGE_PROVIDER_VERSION, now],
        )?;
        Ok(())
    }

    pub(super) fn prune(
        connection: &SqliteConnectionPool,
        now: i64,
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        Self::prune_in_connection(&connection, now)
    }

    pub(super) fn prune_in_tx(
        tx: &rusqlite::Transaction<'_>,
        now: i64,
    ) -> Result<(), rusqlite::Error> {
        Self::prune_in_connection(tx, now)
    }

    fn delete_in_connection<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_decrypted_application_messages
            WHERE provider_version = ?1
                AND group_id = ?2",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
            ],
        )?;
        Ok(())
    }

    pub(super) fn delete<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &SqliteConnectionPool,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        let connection = connection.checkout()?;
        Self::delete_in_connection::<C, _>(&connection, group_id)
    }

    pub(super) fn delete_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        Self::delete_in_connection::<C, _>(tx, group_id)
    }
}

impl<C: Codec> SqliteStorageProvider<C> {
    pub fn load_decrypted_application_message<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_id: &str,
        now: i64,
    ) -> Result<Option<DecryptedApplicationMessage>, rusqlite::Error> {
        StorableDecryptedApplicationMessage::load::<C, _>(
            &self.connection_pool(),
            group_id,
            message_id,
            now,
        )
    }

    pub fn insert_decrypted_application_message<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_id: &str,
        entry: &DecryptedApplicationMessage,
    ) -> Result<(), rusqlite::Error> {
        StorableDecryptedApplicationMessage::insert::<C, _>(
            &self.connection_pool(),
            group_id,
            message_id,
            entry,
        )
    }

    pub fn prune_decrypted_application_messages(&self, now: i64) -> Result<(), rusqlite::Error> {
        StorableDecryptedApplicationMessage::prune(&self.connection_pool(), now)
    }

    pub fn delete_decrypted_application_messages<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        StorableDecryptedApplicationMessage::delete::<C, _>(&self.connection_pool(), group_id)
    }
}

impl<'tx, C: Codec> TransactionalStorageProvider<'tx, C> {
    pub fn load_decrypted_application_message<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_id: &str,
        now: i64,
    ) -> Result<Option<DecryptedApplicationMessage>, rusqlite::Error> {
        StorableDecryptedApplicationMessage::load_in_tx::<C, _>(
            self.tx(),
            group_id,
            message_id,
            now,
        )
    }

    pub fn insert_decrypted_application_message<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_id: &str,
        entry: &DecryptedApplicationMessage,
    ) -> Result<(), rusqlite::Error> {
        StorableDecryptedApplicationMessage::insert_in_tx::<C, _>(
            self.tx(),
            group_id,
            message_id,
            entry,
        )
    }

    pub fn prune_decrypted_application_messages(&self, now: i64) -> Result<(), rusqlite::Error> {
        StorableDecryptedApplicationMessage::prune_in_tx(self.tx(), now)
    }

    pub fn delete_decrypted_application_messages<GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        StorableDecryptedApplicationMessage::delete_in_tx::<C, _>(self.tx(), group_id)
    }
}
