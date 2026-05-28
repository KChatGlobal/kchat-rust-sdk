//! Smoke tests for the SQLCipher-backed `UqMls` FFI constructor.
//!
//! `UqMls::new` accepts an optional password that is forwarded to the
//! underlying `SqliteProvider`, which applies it via `PRAGMA key` so the
//! database is opened/created as an SQLCipher-encrypted file.
//!
//! These tests verify the round-trip and failure modes of that flow through
//! the public uniffi-exported surface, ensuring SQLCipher integration keeps
//! working as we change dependencies and build profiles.

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use mls_mobile_sdk_rs::mls::UqMls;

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

const MAX_PAST_EPOCHS: u16 = 10;
const OUT_OF_ORDER_TOLERANCE: u32 = 5;
const MAXIMUM_FORWARD_DISTANCE: u32 = 10;

const PLAIN_SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

#[derive(Clone)]
struct PathSet {
    storage_path: String,
    group_storage_path: String,
}

fn unique_name(test_name: &str, suffix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(
        "{test_name}-{suffix}-{}-{nanos}-{counter}",
        std::process::id()
    )
}

fn db_path(name: &str) -> String {
    let path: PathBuf = std::env::temp_dir().join(format!("{name}.sqlite"));
    path.to_string_lossy().into_owned()
}

/// Pretty-print the first `max_bytes` of a file as a `hexdump -C`-style
/// table so we can eyeball the on-disk contents (encrypted vs. plain).
fn dump_file_head(label: &str, path: &str, max_bytes: usize) {
    let bytes = fs::read(path).expect("file should exist on disk");
    let total = bytes.len();
    let take = total.min(max_bytes);
    let slice = &bytes[..take];

    println!("---- {label} ----");
    println!("path : {path}");
    println!("size : {total} bytes (showing first {take})");

    for (row, chunk) in slice.chunks(16).enumerate() {
        let offset = row * 16;
        let hex: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("{:08x}  {:<47}  |{}|", offset, hex, ascii);
    }
    println!("---- end {label} ----");
}

fn make_paths(test_name: &str, client_id: &str) -> PathSet {
    let unique = unique_name(test_name, client_id);
    PathSet {
        storage_path: db_path(&format!("{unique}-mls")),
        group_storage_path: db_path(&format!("{unique}-group-status")),
    }
}

fn open(paths: &PathSet, client_id: &str, password: Option<&str>) -> Result<UqMls, String> {
    UqMls::new(
        client_id.to_owned(),
        paths.storage_path.clone(),
        paths.group_storage_path.clone(),
        MAX_PAST_EPOCHS,
        password.map(|p| p.to_owned()),
        OUT_OF_ORDER_TOLERANCE,
        MAXIMUM_FORWARD_DISTANCE,
        None,
    )
    .map_err(|e| e.to_string())
}

fn open_expect(paths: &PathSet, client_id: &str, password: Option<&str>, ctx: &str) -> UqMls {
    open(paths, client_id, password).unwrap_or_else(|e| panic!("{ctx}: {e}"))
}

#[test]
fn sqlcipher_encrypted_db_round_trips_with_same_password() {
    let paths = make_paths("sqlcipher_round_trip", "alice");
    let password = "correct-horse-battery-staple";

    // First open: creates the encrypted database and runs migrations.
    let client = open_expect(
        &paths,
        "alice",
        Some(password),
        "initial open with password",
    );

    // Perform a write so we know the encrypted DB has real MLS content,
    // not just empty migration tables.
    let signature_key = client
        .generate_signature_key()
        .expect("generate_signature_key should succeed on encrypted DB");
    assert!(
        !signature_key.public.is_empty(),
        "signature key should be populated"
    );

    let group_id = "sqlcipher-group";
    client
        .create_group(group_id, None)
        .expect("create_group should succeed on encrypted DB");

    drop(client);

    // Reopen with the same password: existing data must remain accessible.
    let reopened = open_expect(&paths, "alice", Some(password), "reopen with same password");

    let members = reopened
        .members(group_id)
        .expect("members should be readable after reopen with same password");
    assert_eq!(members, vec!["alice".to_string()]);
}

#[test]
fn sqlcipher_db_file_is_not_plain_sqlite() {
    let paths = make_paths("sqlcipher_file_header", "alice");
    let password = "encryption-required";

    let client = open_expect(&paths, "alice", Some(password), "open with password");
    // Make sure at least one write reaches the file before we inspect it.
    client
        .generate_signature_key()
        .expect("generate_signature_key should succeed");
    drop(client);

    let bytes = fs::read(&paths.storage_path).expect("encrypted DB file should exist on disk");
    assert!(
        bytes.len() >= PLAIN_SQLITE_MAGIC.len(),
        "encrypted DB file should be non-empty"
    );

    // Log the encrypted bytes so they can be verified by eye.
    // Run with: `cargo test -p kchat-mls-uniffi --test ffi_sqlcipher -- --nocapture`
    dump_file_head("ENCRYPTED DB (password set)", &paths.storage_path, 256);

    assert_ne!(
        &bytes[..PLAIN_SQLITE_MAGIC.len()],
        PLAIN_SQLITE_MAGIC,
        "DB opened with a password must not start with the plain-text SQLite magic header"
    );
}

#[test]
fn sqlcipher_plain_db_starts_with_sqlite_magic_header() {
    // Sanity check: without a password the file is a regular SQLite database
    // and starts with the well-known magic header. This guards against a
    // regression where SQLCipher would silently encrypt everything (which
    // would break consumers relying on `password = None`).
    let paths = make_paths("sqlcipher_plain_header", "alice");

    let client = open_expect(&paths, "alice", None, "open without password");
    client
        .generate_signature_key()
        .expect("generate_signature_key should succeed without password");
    drop(client);

    let bytes = fs::read(&paths.storage_path).expect("plain DB file should exist on disk");
    assert!(
        bytes.len() >= PLAIN_SQLITE_MAGIC.len(),
        "plain DB file should be non-empty"
    );

    // Log the plain bytes for visual comparison against the encrypted dump above.
    dump_file_head("PLAIN DB (no password)", &paths.storage_path, 256);

    assert_eq!(
        &bytes[..PLAIN_SQLITE_MAGIC.len()],
        PLAIN_SQLITE_MAGIC,
        "DB opened without a password must be a standard SQLite database"
    );
}

#[test]
fn sqlcipher_wrong_password_fails_to_open() {
    let paths = make_paths("sqlcipher_wrong_password", "alice");

    let client = open_expect(&paths, "alice", Some("right-password"), "initial open");
    client
        .generate_signature_key()
        .expect("generate_signature_key should succeed");
    drop(client);

    let err = open(&paths, "alice", Some("wrong-password"))
        .err()
        .expect("opening encrypted DB with the wrong password must fail");
    // SQLCipher reports a generic "not a database" / "file is encrypted" error
    // through rusqlite when the key is wrong. We don't pin the exact message,
    // we just require the constructor to surface a failure.
    assert!(
        !err.is_empty(),
        "wrong-password error should carry a message, got: {err}"
    );
}

#[test]
fn sqlcipher_missing_password_fails_to_open_encrypted_db() {
    let paths = make_paths("sqlcipher_missing_password", "alice");

    let client = open_expect(&paths, "alice", Some("required-password"), "initial open");
    client
        .generate_signature_key()
        .expect("generate_signature_key should succeed");
    drop(client);

    let err = open(&paths, "alice", None)
        .err()
        .expect("opening encrypted DB without any password must fail");
    assert!(
        !err.is_empty(),
        "missing-password error should carry a message, got: {err}"
    );
}
