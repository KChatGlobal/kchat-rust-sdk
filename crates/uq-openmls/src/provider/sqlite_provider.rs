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
use openmls::prelude::OpenMlsProvider;
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

impl SqliteProvider {
    pub fn new(storage_path: &str, secret: &Option<SecretString>) -> Result<Self, Error> {
        let storage_path = storage_path.to_owned();
        let secret = secret.clone();
        let pool = SqliteConnectionPool::new(SQLITE_CONNECTION_POOL_SIZE, move || {
            let connection = Connection::open(&storage_path)?;
            configure_connection(&connection, &secret)?;
            Ok(connection)
        });
        let mut mls_storage = SqliteStorageProvider::new(pool);
        mls_storage
            .run_migrations()
            .map_err(|e| Error::SqliteMigration(e.to_string()))?;

        Ok(Self {
            crypto: RustCrypto::default(),
            mls_storage,
        })
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
