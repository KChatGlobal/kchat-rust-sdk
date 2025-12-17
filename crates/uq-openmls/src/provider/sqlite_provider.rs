//! SQLite-based storage implementation for MLS.
//!
//! This module provides a SQLite-based storage implementation for the Uq MLS
//! crate. It implements the [`OpenMlsProvider`] trait, allowing it to be used within the MLS context.
//!
//! SQLite-based storage is persistent and will be saved to a file. It's useful for production applications
//! where data persistence is required.

use openmls::prelude::OpenMlsProvider;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
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
    mls_storage: SqliteStorageProvider<JsonCodec, Connection>,
}

const SQLITE_PRAGMA_NAME_KEY: &str = "key";

impl SqliteProvider {
    pub fn new(storage_path: &str, secret: &Option<SecretString>) -> Result<Self, Error> {
        let connection = Connection::open(storage_path)?;
        if let Some(secret) = secret {
            connection.pragma_update(None, SQLITE_PRAGMA_NAME_KEY, secret.expose_secret())?;
        }

        let mut mls_storage = SqliteStorageProvider::new(connection);
        mls_storage
            .run_migrations()
            .map_err(|e| Error::SqliteMigration(e.to_string()))?;

        Ok(Self {
            crypto: RustCrypto::default(),
            mls_storage,
        })
    }
}

impl OpenMlsProvider for SqliteProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

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
