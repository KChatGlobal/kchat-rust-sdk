use std::{
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use openmls::group::{GroupId, MlsGroupCreateConfig};
use openmls_traits::OpenMlsProvider;
use rusqlite::params;
use secrecy::SecretString;
use uq_openmls::{core, provider::SqliteProvider};

#[test]
fn delete_removes_a_group_with_an_unreadable_overflow_page_and_allows_recreation() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mls-corrupt-cleanup-{}-{nonce}.sqlite",
        std::process::id()
    ));
    let secret = Some(SecretString::from("synthetic-corrupt-page-test-password"));
    let provider = SqliteProvider::new(path.to_str().unwrap(), &secret).unwrap();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(core::DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(8)
        .build();
    for id in ["healthy", "damaged"] {
        provider
            .transaction(|tx| {
                core::create_group(tx, "alice", id, core::DEFAULT_CIPHERSUITE, &config, None)
            })
            .unwrap();
    }
    let key = serde_json::to_vec(&GroupId::from_slice(b"damaged")).unwrap();
    let pool = provider.storage().connection_pool();
    let connection = pool.checkout().unwrap();
    let original: Vec<u8> = connection.query_row(
        "SELECT message_secrets FROM openmls_group_epoch_message_secrets WHERE group_id=?1 AND epoch=0",
        params![&key], |r| r.get(0),
    ).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value.as_object_mut().unwrap().insert(
        "cleanup_test_padding".into(),
        serde_json::Value::String("x".repeat(5000usize.saturating_sub(original.len()))),
    );
    connection.execute(
        "UPDATE openmls_group_epoch_message_secrets SET message_secrets=?1 WHERE group_id=?2 AND epoch=0",
        params![serde_json::to_vec(&value).unwrap(), &key],
    ).unwrap();
    drop(connection);
    assert!(
        provider.load_group("damaged").is_ok(),
        "padding must preserve a valid group before corruption"
    );
    let connection = pool.checkout().unwrap();
    let pages: Vec<u64> = connection.prepare(
        "SELECT pageno FROM dbstat WHERE name='openmls_group_epoch_message_secrets' AND pagetype='overflow' ORDER BY path"
    ).unwrap().query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        pages.len(),
        1,
        "fixture must corrupt only the damaged group's single overflow page"
    );
    let page_size: u64 = connection
        .query_row::<String, _, _>("PRAGMA cipher_page_size", [], |r| r.get(0))
        .unwrap()
        .parse()
        .unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(connection);
    drop(pool);
    drop(provider);
    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start((pages[0] - 1) * page_size))
        .unwrap();
    file.write_all(&vec![0; page_size as usize]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let provider = SqliteProvider::new(path.to_str().unwrap(), &secret).unwrap();
    assert!(provider.load_group("damaged").is_err());
    let pool = provider.storage().connection_pool();
    let connection = pool.open_fresh_connection().unwrap();
    connection
        .execute_batch("DROP TABLE openmls_decrypted_application_messages")
        .unwrap();
    drop(connection);
    let error = provider.delete_group("damaged").unwrap_err().to_string();
    assert!(error.contains("isolated cleanup"), "{error}");
    assert!(
        error.contains("openmls_decrypted_application_messages"),
        "{error}"
    );
    let connection = pool.open_fresh_connection().unwrap();
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM openmls_group_data WHERE group_id=?1",
            params![&key],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        rows > 0,
        "late fallback failure must roll back earlier deletes"
    );
    connection
        .execute_batch(include_str!(
            "../../kchat-storage-provider/migrations/V6__decrypted_application_messages.sql"
        ))
        .unwrap();
    drop(connection);
    provider.delete_group("damaged").expect("cleanup must remove the unreadable group without decoding or scrubbing its damaged overflow page");
    assert!(provider.load_group("healthy").is_ok());
    assert!(provider.load_group("damaged").is_err());
    provider.delete_group("damaged").unwrap();
    provider
        .transaction(|tx| {
            core::create_group(
                tx,
                "alice",
                "damaged",
                core::DEFAULT_CIPHERSUITE,
                &config,
                None,
            )
        })
        .unwrap();
    assert!(provider.load_group("damaged").is_ok());
    let connection = provider.storage().connection_pool().checkout().unwrap();
    let secure_delete: i64 = connection
        .query_row("PRAGMA secure_delete", [], |r| r.get(0))
        .unwrap();
    assert_ne!(
        secure_delete, 0,
        "normal pooled connections must retain secure deletion"
    );
}
