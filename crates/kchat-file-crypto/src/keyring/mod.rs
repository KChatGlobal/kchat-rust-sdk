//! SQLCipher key store for one account on one device, separate from MLS storage. The host
//! supplies the 32-byte DB key; the SDK never derives or stores it.
//!
//! Each `FileKeyring` guards one connection with a `Mutex`. Several handles may share the file
//! (WAL + busy timeout); every write is an `IMMEDIATE` transaction.

mod control;
mod descriptors;
mod key_config;
mod node_keys;
mod operations;
mod peppers;
mod schema;

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, ErrorCode, Row};
use zeroize::Zeroizing;

use crate::{FileCryptoError, KKeyRootKey, ids::validate_id};

pub const KEY_STORE_KEY_BYTES: usize = 32;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SQLITE_SIDE_FILE_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

pub struct FileKeyring {
    connection: Mutex<Connection>,
    account_id: String,
    root: Option<KKeyRootKey>,
}

impl FileKeyring {
    /// Opens or creates the encrypted key store at `path`.
    ///
    /// `kkey_root` is the only trusted signer of key-service configuration (`None` allows random
    /// plans only). Stored configuration is re-verified against it on every open and rows that
    /// fail are deleted; per-root rollback floors are kept.
    pub fn open(
        path: &Path,
        db_key: &[u8],
        account_id: &str,
        kkey_root: Option<KKeyRootKey>,
    ) -> Result<Self, FileCryptoError> {
        // Validate before touching the file, so bad input never creates one.
        let db_key: &[u8; KEY_STORE_KEY_BYTES] = db_key
            .try_into()
            .map_err(|_| FileCryptoError::invalid_argument())?;
        validate_id(account_id)?;

        let created = claim_new_file(path)?;
        let result = Connection::open(path)
            .map_err(FileCryptoError::from)
            .and_then(|mut connection| {
                configure(&mut connection, db_key, account_id)?;
                key_config::prune_untrusted_key_config(&mut connection, kkey_root.as_ref())?;
                Ok(connection)
            });
        let connection = match result {
            Ok(connection) => connection,
            Err(error) => {
                // Remove only a file this call created; an existing one (e.g. wrong key) stays.
                if created {
                    remove_store_files(path);
                }
                return Err(error);
            }
        };
        Ok(Self {
            connection: Mutex::new(connection),
            account_id: account_id.to_owned(),
            root: kkey_root,
        })
    }

    pub fn close(self) -> Result<(), FileCryptoError> {
        let connection = self
            .connection
            .into_inner()
            .map_err(|_| FileCryptoError::invalid_state())?;
        connection.close().map_err(|(_, error)| error.into())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, FileCryptoError> {
        self.connection
            .lock()
            .map_err(|_| FileCryptoError::invalid_state())
    }
}

impl core::fmt::Debug for FileKeyring {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FileKeyring")
            .field("has_root", &self.root.is_some())
            .finish_non_exhaustive()
    }
}

fn configure(
    connection: &mut Connection,
    db_key: &[u8; KEY_STORE_KEY_BYTES],
    account_id: &str,
) -> Result<(), FileCryptoError> {
    require_sqlcipher(connection)?;
    apply_key(connection, db_key)?;
    // The first read checks page 1's HMAC: a wrong key or plaintext file fails with `NotADatabase`.
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|error| match error.sqlite_error_code() {
            Some(ErrorCode::NotADatabase) => FileCryptoError::invalid_store_key(),
            _ => FileCryptoError::store_error(),
        })?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    // Zero deleted pages so discarded secrets do not linger.
    connection.pragma_update(None, "secure_delete", true)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    schema::migrate(connection, account_id)
}

/// Rejects a plain SQLite build, which would write plaintext (it ignores `cipher_version`).
fn require_sqlcipher(connection: &Connection) -> Result<(), FileCryptoError> {
    let version: Option<String> = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .ok();
    match version {
        Some(version) if !version.is_empty() => Ok(()),
        _ => Err(FileCryptoError::store_error()),
    }
}

/// Raw SQLCipher key (`x'…'`): the host key is already random, so PBKDF2 is skipped.
fn apply_key(
    connection: &Connection,
    db_key: &[u8; KEY_STORE_KEY_BYTES],
) -> Result<(), FileCryptoError> {
    let mut statement = Zeroizing::new(String::with_capacity(96));
    statement.push_str("PRAGMA key = \"x'");
    for byte in db_key {
        write!(statement, "{byte:02X}").map_err(|_| FileCryptoError::invalid_state())?;
    }
    statement.push_str("'\";");
    connection.execute_batch(&statement)?;
    Ok(())
}

/// Creates `path` if missing and says whether this call did; `create_new` is atomic, so exactly
/// one of several concurrent opens is the creator.
fn claim_new_file(path: &Path) -> Result<bool, FileCryptoError> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(_) => Err(FileCryptoError::store_error()),
    }
}

fn remove_store_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in SQLITE_SIDE_FILE_SUFFIXES {
        let mut side = PathBuf::from(path).into_os_string();
        side.push(suffix);
        let _ = std::fs::remove_file(side);
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn to_sql_integer(value: u64) -> Result<i64, FileCryptoError> {
    i64::try_from(value).map_err(|_| FileCryptoError::invalid_argument())
}

fn from_sql_integer(value: i64) -> Result<u64, FileCryptoError> {
    u64::try_from(value).map_err(|_| FileCryptoError::store_error())
}

/// Borrows a blob column, so secrets are not copied into a non-zeroizing buffer.
fn blob<'row>(row: &'row Row<'_>, index: usize) -> Result<&'row [u8], FileCryptoError> {
    row.get_ref(index)?
        .as_blob()
        .map_err(|_| FileCryptoError::store_error())
}
