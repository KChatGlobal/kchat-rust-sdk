use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use kchat_mls::{open_compatible_group_status_connection, open_group_status_connection};
use secrecy::SecretString;

fn path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "group-status-{label}-{}-{nonce}.sqlite",
        std::process::id()
    ))
}

fn password() -> Option<SecretString> {
    Some(SecretString::from("local-compatibility-test-password"))
}

#[test]
fn existing_plaintext_status_opens_with_client_password_and_preserves_rows() {
    let file = path("legacy");
    let db = open_group_status_connection(file.to_str().unwrap(), &None).unwrap();
    db.checkout()
        .unwrap()
        .execute(
            "INSERT INTO group_statuses VALUES ('target', 'legacy-marker')",
            [],
        )
        .unwrap();
    drop(db);
    let db = open_compatible_group_status_connection(file.to_str().unwrap(), &password()).unwrap();
    let marker: String = db
        .checkout()
        .unwrap()
        .query_row(
            "SELECT pending_operation FROM group_statuses WHERE group_id='target'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, "legacy-marker");
    assert_eq!(&fs::read(file).unwrap()[..16], b"SQLite format 3\0");
}

#[test]
fn absent_or_empty_status_is_created_plaintext_even_with_client_password() {
    for empty in [false, true] {
        let file = path(if empty { "empty" } else { "absent" });
        if empty {
            fs::write(&file, []).unwrap();
        }
        let db =
            open_compatible_group_status_connection(file.to_str().unwrap(), &password()).unwrap();
        db.checkout()
            .unwrap()
            .execute("INSERT INTO group_statuses VALUES ('target', 'marker')", [])
            .unwrap();
        assert_eq!(&fs::read(file).unwrap()[..16], b"SQLite format 3\0");
    }
}

#[test]
fn already_encrypted_status_keeps_working_and_remains_encrypted() {
    let file = path("encrypted");
    let db = open_group_status_connection(file.to_str().unwrap(), &password()).unwrap();
    db.checkout()
        .unwrap()
        .execute(
            "INSERT INTO group_statuses VALUES ('target', 'encrypted-marker')",
            [],
        )
        .unwrap();
    drop(db);
    let db = open_compatible_group_status_connection(file.to_str().unwrap(), &password()).unwrap();
    let marker: String = db
        .checkout()
        .unwrap()
        .query_row(
            "SELECT pending_operation FROM group_statuses WHERE group_id='target'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, "encrypted-marker");
    assert_ne!(&fs::read(file).unwrap()[..16], b"SQLite format 3\0");
}

#[test]
fn truncated_status_is_preserved_and_rejected_without_creating_a_new_database() {
    let file = path("truncated");
    fs::write(&file, [1, 2, 3]).unwrap();
    assert!(open_compatible_group_status_connection(file.to_str().unwrap(), &password()).is_err());
    assert_eq!(fs::read(file).unwrap(), vec![1, 2, 3]);
}

#[test]
fn encrypted_status_wrong_or_missing_password_never_falls_back_or_changes_data() {
    let file = path("wrong-key");
    let db = open_group_status_connection(file.to_str().unwrap(), &password()).unwrap();
    db.checkout()
        .unwrap()
        .execute(
            "INSERT INTO group_statuses VALUES ('target', 'preserved')",
            [],
        )
        .unwrap();
    db.checkout()
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(db);
    let before = fs::read(&file).unwrap();
    for key in [Some(SecretString::from("incorrect-test-password")), None] {
        assert!(open_compatible_group_status_connection(file.to_str().unwrap(), &key).is_err());
        assert_eq!(fs::read(&file).unwrap(), before);
    }
    let db = open_compatible_group_status_connection(file.to_str().unwrap(), &password()).unwrap();
    let marker: String = db
        .checkout()
        .unwrap()
        .query_row(
            "SELECT pending_operation FROM group_statuses WHERE group_id='target'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, "preserved");
}
