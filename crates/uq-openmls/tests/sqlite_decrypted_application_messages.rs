use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use kchat_storage_provider::DecryptedApplicationMessage;
use openmls::group::GroupId;
use openmls_traits::OpenMlsProvider;
use uq_openmls::{error::Error, provider::SqliteProvider};

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    temp_db_path_at_nanos(nanos)
}

fn temp_db_path_at_nanos(nanos: u128) -> PathBuf {
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "uq-openmls-decrypted-application-message-{}-{counter}-{nanos}.sqlite",
        std::process::id(),
    ))
}

#[test]
fn temp_db_paths_are_unique_when_clock_values_match() {
    let first = temp_db_path_at_nanos(42);
    let second = temp_db_path_at_nanos(42);

    assert_ne!(
        first, second,
        "concurrent tests with the same clock reading must not share a SQLite database"
    );
}

fn entry(
    ciphertext_digest: &[u8],
    plaintext: &[u8],
    created_at: i64,
    expires_at: i64,
) -> DecryptedApplicationMessage {
    DecryptedApplicationMessage {
        ciphertext_digest: ciphertext_digest.to_vec(),
        plaintext: plaintext.to_vec(),
        created_at,
        expires_at,
    }
}

#[test]
fn cache_entry_is_visible_only_before_expiry() {
    let db_path = temp_db_path();
    let provider = SqliteProvider::new(&db_path.to_string_lossy(), &None)
        .expect("should create sqlite provider");
    let group_id = GroupId::from_slice(b"cache-group");

    provider
        .storage()
        .insert_decrypted_application_message(
            &group_id,
            "message-1",
            &entry(b"digest", b"plaintext", 100, 200),
        )
        .expect("should store cache entry");

    let cached = provider
        .storage()
        .load_decrypted_application_message(&group_id, "message-1", 199)
        .expect("should load cache entry")
        .expect("entry should be valid before expiry");
    assert_eq!(cached.plaintext, b"plaintext");

    assert!(
        provider
            .storage()
            .load_decrypted_application_message(&group_id, "message-1", 200)
            .expect("expired lookup should succeed")
            .is_none()
    );

    provider
        .storage()
        .prune_decrypted_application_messages(200)
        .expect("should prune expired entry");
    provider
        .storage()
        .insert_decrypted_application_message(
            &group_id,
            "message-1",
            &entry(b"new-digest", b"new-plaintext", 200, 300),
        )
        .expect("pruned primary key should be reusable");

    let _ = fs::remove_file(db_path);
}

#[test]
fn expired_cache_entry_can_be_replaced_without_pruning() {
    let db_path = temp_db_path();
    let provider = SqliteProvider::new(&db_path.to_string_lossy(), &None)
        .expect("should create sqlite provider");
    let group_id = GroupId::from_slice(b"expired-cache-group");

    provider
        .storage()
        .insert_decrypted_application_message(
            &group_id,
            "message-1",
            &entry(b"old-digest", b"old-plaintext", 100, 200),
        )
        .expect("should store expired cache entry");
    provider
        .storage()
        .insert_decrypted_application_message(
            &group_id,
            "message-1",
            &entry(b"new-digest", b"new-plaintext", 200, 300),
        )
        .expect("expired cache key should be reusable without a prune");

    let replacement = provider
        .storage()
        .load_decrypted_application_message(&group_id, "message-1", 200)
        .expect("lookup should succeed")
        .expect("replacement should be readable");
    assert_eq!(replacement.plaintext, b"new-plaintext");

    let _ = fs::remove_file(db_path);
}

#[test]
fn rolled_back_transaction_does_not_persist_cache_entry() {
    let db_path = temp_db_path();
    let provider = SqliteProvider::new(&db_path.to_string_lossy(), &None)
        .expect("should create sqlite provider");
    let group_id = GroupId::from_slice(b"rollback-group");

    let result: Result<(), rusqlite::Error> = provider.transaction(|tx_provider| {
        tx_provider.storage().insert_decrypted_application_message(
            &group_id,
            "message-1",
            &entry(b"digest", b"plaintext", 100, 200),
        )?;
        Err(Error::Storage("force rollback".to_owned()))
    });
    assert!(result.is_err(), "forced transaction error must be returned");

    assert!(
        provider
            .storage()
            .load_decrypted_application_message(&group_id, "message-1", 100)
            .expect("lookup should succeed")
            .is_none()
    );

    let _ = fs::remove_file(db_path);
}

#[test]
fn deleting_one_group_keeps_other_groups_cache_entries() {
    let db_path = temp_db_path();
    let provider = SqliteProvider::new(&db_path.to_string_lossy(), &None)
        .expect("should create sqlite provider");
    let deleted_group = GroupId::from_slice(b"deleted-group");
    let retained_group = GroupId::from_slice(b"retained-group");

    provider
        .storage()
        .insert_decrypted_application_message(
            &deleted_group,
            "message-1",
            &entry(b"digest-a", b"deleted", 100, 200),
        )
        .expect("should store deleted-group entry");
    provider
        .storage()
        .insert_decrypted_application_message(
            &retained_group,
            "message-1",
            &entry(b"digest-b", b"retained", 100, 200),
        )
        .expect("should store retained-group entry");

    provider
        .storage()
        .delete_decrypted_application_messages(&deleted_group)
        .expect("should delete one group cache");

    assert!(
        provider
            .storage()
            .load_decrypted_application_message(&deleted_group, "message-1", 100)
            .expect("lookup should succeed")
            .is_none()
    );
    assert_eq!(
        provider
            .storage()
            .load_decrypted_application_message(&retained_group, "message-1", 100)
            .expect("lookup should succeed")
            .expect("other group entry should remain")
            .plaintext,
        b"retained"
    );

    let _ = fs::remove_file(db_path);
}
