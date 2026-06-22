//! SQLite-based storage implementation for MLS.
//!
//! This module provides a SQLite-based storage implementation for the Uq MLS
//! crate. It implements the [`OpenMlsProvider`] trait, allowing it to be used within the MLS context.
//!
//! SQLite-based storage is persistent and will be saved to a file. It's useful for production applications
//! where data persistence is required.

use std::time::Duration;

use kchat_storage_provider::{
    Codec, SqliteConnectionPool, SqliteStorageProvider, TransactionalStorageProvider,
};
use openmls::{
    group::{GroupId, MlsGroup},
    prelude::OpenMlsProvider,
};
use openmls_rust_crypto::RustCrypto;
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};

use crate::error::Error;

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    #[inline]
    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    #[inline]
    fn from_slice<T>(slice: &[u8]) -> Result<T, Self::Error>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(slice)
    }
}

pub struct SqliteProvider {
    crypto: RustCrypto,
    mls_storage: SqliteStorageProvider<JsonCodec>,
}

impl Clone for SqliteProvider {
    fn clone(&self) -> Self {
        Self {
            crypto: self.crypto.clone(),
            mls_storage: self.mls_storage.clone(),
        }
    }
}

pub struct TransactionalSqliteProvider<'tx> {
    crypto: &'tx RustCrypto,
    mls_storage: TransactionalStorageProvider<'tx, JsonCodec>,
}

const SQLITE_PRAGMA_NAME_KEY: &str = "key";
const SQLITE_PRAGMA_NAME_JOURNAL_MODE: &str = "journal_mode";
const SQLITE_JOURNAL_MODE_WAL: &str = "WAL";
const SQLITE_CONNECTION_POOL_SIZE: usize = 8;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn configure_connection(
    connection: &Connection,
    secret: &Option<SecretString>,
) -> Result<(), rusqlite::Error> {
    if let Some(secret) = secret {
        connection.pragma_update(None, SQLITE_PRAGMA_NAME_KEY, secret.expose_secret())?;
    }
    connection.pragma_update(
        None,
        SQLITE_PRAGMA_NAME_JOURNAL_MODE,
        SQLITE_JOURNAL_MODE_WAL,
    )?;
    connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
    Ok(())
}

fn migrate_group_epoch_message_secrets(
    provider: &TransactionalSqliteProvider<'_>,
    group_id: &GroupId,
) -> Result<(), Error> {
    let Some(message_secrets) =
        MlsGroup::export_epoch_message_secrets_snapshot_from_storage(provider.storage(), group_id)
            .map_err(|e| Error::Storage(e.to_string()))?
    else {
        return Ok(());
    };

    provider
        .storage()
        .replace_group_epoch_message_secrets(group_id, message_secrets)
        .map_err(Error::from)
}

impl SqliteProvider {
    pub fn new(storage_path: &str, secret: &Option<SecretString>) -> Result<Self, Error> {
        Self::new_with_log(storage_path, secret, None)
    }

    pub fn new_with_log(
        storage_path: &str,
        secret: &Option<SecretString>,
        log: Option<&dyn Fn(String)>,
    ) -> Result<Self, Error> {
        let emit = |msg: String| {
            if let Some(log) = log {
                log(msg);
            }
        };
        let storage_path = storage_path.to_owned();
        emit(format!(
            "SqliteProvider::new start storage_path={}",
            storage_path
        ));
        let secret = secret.clone();
        let connection_storage_path = storage_path.clone();
        let pool = SqliteConnectionPool::new(SQLITE_CONNECTION_POOL_SIZE, move || {
            let connection = Connection::open(&connection_storage_path)?;
            configure_connection(&connection, &secret)?;
            Ok(connection)
        });
        let mut mls_storage = SqliteStorageProvider::new(pool);
        mls_storage.run_migrations().map_err(|e| {
            emit(format!(
                "sqlite schema migration error storage_path={}: {}",
                storage_path, e
            ));
            Error::SqliteMigration(e.to_string())
        })?;
        emit(format!(
            "sqlite schema migration done storage_path={}",
            storage_path
        ));

        let provider = Self {
            crypto: RustCrypto::default(),
            mls_storage,
        };
        emit(format!(
            "epoch message secrets migration start storage_path={}",
            storage_path
        ));
        provider.migrate_epoch_message_secrets(log);
        emit(format!(
            "epoch message secrets migration end storage_path={}",
            storage_path
        ));

        Ok(provider)
    }

    /// Execute a closure within a single SQLite transaction-backed provider.
    ///
    /// Use this to wrap multi-step MLS operations so all storage writes are atomic.
    pub fn transaction<F, T>(&self, f: F) -> Result<T, rusqlite::Error>
    where
        F: for<'tx> FnOnce(&TransactionalSqliteProvider<'tx>) -> Result<T, crate::error::Error>,
    {
        self.mls_storage.transaction(|tx| {
            let tx_provider = TransactionalSqliteProvider {
                crypto: &self.crypto,
                mls_storage: TransactionalStorageProvider::new(tx),
            };
            f(&tx_provider).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })
    }

    fn migrate_epoch_message_secrets(&self, log: Option<&dyn Fn(String)>) {
        if let Err(err) = self.try_migrate_epoch_message_secrets(log)
            && let Some(log) = log {
                log(format!("epoch message secrets migration error err={}", err));
            }
    }

    fn try_migrate_epoch_message_secrets(&self, log: Option<&dyn Fn(String)>) -> Result<(), Error> {
        let emit = |msg: String| {
            if let Some(log) = log {
                log(msg);
            }
        };
        let group_ids = self
            .mls_storage
            .list_group_ids_with_message_secrets::<GroupId>()?;
        emit(format!(
            "epoch message secrets migration selected batch count={}",
            group_ids.len()
        ));

        for group_id in group_ids {
            let group_id_text = String::from_utf8_lossy(group_id.as_slice()).to_string();
            emit(format!(
                "epoch message secrets migration group start group_id={}",
                group_id_text
            ));
            match self.mls_storage.transaction(|tx| {
                let tx_provider = TransactionalSqliteProvider {
                    crypto: &self.crypto,
                    mls_storage: TransactionalStorageProvider::new(tx),
                };
                migrate_group_epoch_message_secrets(&tx_provider, &group_id)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
            }) {
                Ok(_) => emit(format!(
                    "epoch message secrets migration group done group_id={}",
                    group_id_text
                )),
                Err(err) => emit(format!(
                    "epoch message secrets migration group error group_id={} err={}",
                    group_id_text, err
                )),
            }
        }

        Ok(())
    }
}

impl OpenMlsProvider for SqliteProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.mls_storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl<'tx> OpenMlsProvider for TransactionalSqliteProvider<'tx> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = TransactionalStorageProvider<'tx, JsonCodec>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.mls_storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto
    }
}
