mod common;

use std::{fs, path::Path};

use kchat_file_crypto::{FileCryptoErrorCode, FileKeyring, RandomPlanReason};

use crate::common::{
    ACCOUNT, DB_KEY, FakeKKey, TENANT, TestKeyring, install_pepper, reopen, tenant,
};

/// Recognizable 32 bytes that must never appear on disk.
const CANARY_PEPPER: [u8; 32] = *b"pepper-canary-do-not-leak-012345";

fn open_error(path: &Path, db_key: &[u8], account: &str) -> FileCryptoErrorCode {
    FileKeyring::open(path, db_key, account, None)
        .unwrap_err()
        .code()
}

fn files_contain(dir: &Path, needle: &[u8]) -> bool {
    fs::read_dir(dir).unwrap().any(|entry| {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        bytes.windows(needle.len()).any(|window| window == needle)
    })
}

#[test]
fn nothing_readable_is_written_to_disk() {
    let kkey = FakeKKey::new(1, 1_700_000_000);
    let keyring = kkey.keyring("HYBRID");
    install_pepper(&keyring, 2, &CANARY_PEPPER);
    keyring
        .plan_random(&common::hash(b"x"), RandomPlanReason::SmallFile)
        .unwrap();

    let needles: [&[u8]; 4] = [
        &CANARY_PEPPER,
        TENANT.as_bytes(),
        b"CREATE TABLE",
        ACCOUNT.as_bytes(),
    ];
    for needle in needles {
        assert!(!files_contain(keyring.dir.path(), needle));
    }

    let (dir, path) = keyring.close();
    let header = fs::read(&path).unwrap();
    assert_ne!(&header[..16], b"SQLite format 3\0");
    for needle in needles {
        assert!(!files_contain(dir.path(), needle));
    }
}

#[test]
fn reopening_keeps_state() {
    let kkey = FakeKKey::new(1, 1_700_000_000);
    let keyring = kkey.keyring("HYBRID");
    let before = keyring.key_source_status(&tenant()).unwrap();
    let (_dir, path) = keyring.close();

    let reopened = reopen(&path, Some(kkey.root_key()));
    assert_eq!(reopened.key_source_status(&tenant()).unwrap(), before);
    assert_eq!(before.pepper_gen(), Some(1));
}

fn open_raw(path: &Path) -> rusqlite::Connection {
    let raw = rusqlite::Connection::open(path).unwrap();
    let key: String = DB_KEY.iter().map(|byte| format!("{byte:02X}")).collect();
    raw.execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))
        .unwrap();
    raw
}

fn set_schema_version(path: &Path, version: &str) {
    open_raw(path)
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
            [version],
        )
        .unwrap();
}

#[test]
fn rejects_a_store_from_a_newer_sdk() {
    let kkey = FakeKKey::new(1, 1_700_000_000);
    let (_dir, path) = kkey.keyring("HYBRID").close();

    // A store written by an SDK with more migrations cannot be interpreted, so it is not opened. The
    // current schema version is 1.
    set_schema_version(&path, "2");
    assert_eq!(
        open_error(&path, &DB_KEY, ACCOUNT),
        FileCryptoErrorCode::StoreError
    );

    set_schema_version(&path, "1");
    let reopened = reopen(&path, Some(kkey.root_key()));
    assert_eq!(
        reopened.key_source_status(&tenant()).unwrap().pepper_gen(),
        Some(1)
    );
}

#[test]
fn rejects_wrong_key_without_damaging_the_store() {
    let keyring = TestKeyring::new(None);
    install_pepper(&keyring, 1, &CANARY_PEPPER);
    let (_dir, path) = keyring.close();

    assert_eq!(
        open_error(&path, &[0xA5; 32], ACCOUNT),
        FileCryptoErrorCode::InvalidStoreKey
    );
    let reopened = reopen(&path, None);
    assert_eq!(
        reopened.key_source_status(&tenant()).unwrap().pepper_gen(),
        Some(1)
    );
}

#[test]
fn rejects_another_account() {
    let keyring = TestKeyring::new(None);
    let (_dir, path) = keyring.close();
    assert_eq!(
        open_error(&path, &DB_KEY, "account-2"),
        FileCryptoErrorCode::AccountMismatch
    );
    reopen(&path, None).close().unwrap();
}

#[test]
fn refuses_plaintext_databases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.db");
    let plain = rusqlite::Connection::open(&path).unwrap();
    plain
        .execute_batch("CREATE TABLE notes (body TEXT); INSERT INTO notes VALUES ('hello');")
        .unwrap();
    drop(plain);

    assert_eq!(
        open_error(&path, &DB_KEY, ACCOUNT),
        FileCryptoErrorCode::InvalidStoreKey
    );
    assert!(fs::read(&path).unwrap().starts_with(b"SQLite format 3\0"));
}

#[test]
fn validates_arguments_before_touching_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("never.db");
    assert_eq!(
        open_error(&path, &[0; 31], ACCOUNT),
        FileCryptoErrorCode::InvalidArgument
    );
    assert_eq!(
        open_error(&path, &DB_KEY, ""),
        FileCryptoErrorCode::InvalidArgument
    );
    assert_eq!(
        open_error(&path, &DB_KEY, &"a".repeat(257)),
        FileCryptoErrorCode::InvalidArgument
    );
    assert!(!path.exists());
}

#[test]
fn two_handles_share_one_store() {
    let first = TestKeyring::new(None);
    let second = reopen(&first.path, None);
    install_pepper(&first, 3, &CANARY_PEPPER);
    assert_eq!(
        second.key_source_status(&tenant()).unwrap().pepper_gen(),
        Some(3)
    );
}
