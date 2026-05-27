use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use kchat_storage_provider::STORAGE_PROVIDER_VERSION;
use openmls::{
    group::{GroupId, MlsGroupCreateConfig, MlsGroupJoinConfig},
    prelude::{MlsMessageIn, tls_codec::Deserialize as _},
};
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, params};
use uq_openmls::{
    core::{
        self, DEFAULT_CIPHERSUITE, create_group, group as load_group,
        group_current_epoch_message_secrets, group_signer, merge_pending_commit, update_leaf_node,
    },
    provider::SqliteProvider,
};

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> PathBuf {
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "uq-openmls-epoch-migration-{}-{counter}-{nanos}.sqlite",
        std::process::id(),
    ))
}

fn group_config(max_past_epochs: usize) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build()
}

fn join_config(max_past_epochs: usize) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build()
}

fn create_group_legacy(
    provider: &SqliteProvider,
    creator_id: &str,
    group_id: &str,
    max_past_epochs: usize,
) {
    provider
        .transaction(|tx_provider| {
            create_group(
                tx_provider,
                creator_id,
                group_id,
                DEFAULT_CIPHERSUITE,
                &group_config(max_past_epochs),
                None,
            )?;
            Ok(())
        })
        .expect("should create legacy group");
}

fn advance_group_epoch(provider: &SqliteProvider, group_id: &str) {
    let mut group = load_group(provider, group_id, []).expect("should load group");
    let signer = group_signer(&group, provider).expect("should load signer");
    update_leaf_node(&mut group, provider, &signer).expect("should update leaf node");
    merge_pending_commit(&mut group, provider).expect("should merge pending commit");
}

fn table_exists(connection: &Connection, table_name: &str) -> bool {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table'
                    AND name = ?1
            )",
            [table_name],
            |row| row.get::<_, i64>(0),
        )
        .expect("should query sqlite_master")
        != 0
}

fn count_rows(connection: &Connection, table_name: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
            row.get(0)
        })
        .expect("should count rows")
}

fn count_legacy_message_secrets(provider: &SqliteProvider, group_id: &GroupId) -> i64 {
    let connection = provider
        .storage()
        .connection_pool()
        .checkout()
        .expect("should get sqlite connection");
    let group_id_blob = serde_json::to_vec(group_id).expect("should serialize group id");
    connection
        .query_row(
            "SELECT COUNT(*)
            FROM openmls_group_data
            WHERE provider_version = ?1
                AND group_id = ?2
                AND data_type = 'message_secrets'",
            params![STORAGE_PROVIDER_VERSION, group_id_blob],
            |row| row.get::<_, i64>(0),
        )
        .expect("should count legacy message secrets")
}

fn delete_epoch_message_secrets(provider: &SqliteProvider, group_id: &GroupId, epoch: u64) {
    let connection = provider
        .storage()
        .connection_pool()
        .checkout()
        .expect("should get sqlite connection");
    let group_id_blob = serde_json::to_vec(group_id).expect("should serialize group id");
    connection
        .execute(
            "DELETE FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2
                AND epoch = ?3",
            params![STORAGE_PROVIDER_VERSION, group_id_blob, epoch],
        )
        .expect("should delete epoch message secrets");
}

fn list_epoch_message_secret_epochs(provider: &SqliteProvider, group_id: &GroupId) -> Vec<u64> {
    let connection = provider
        .storage()
        .connection_pool()
        .checkout()
        .expect("should get sqlite connection");
    let group_id_blob = serde_json::to_vec(group_id).expect("should serialize group id");
    let mut stmt = connection
        .prepare(
            "SELECT epoch
            FROM openmls_group_epoch_message_secrets
            WHERE provider_version = ?1
                AND group_id = ?2
            ORDER BY epoch",
        )
        .expect("should prepare epoch row query");
    stmt.query_map(params![STORAGE_PROVIDER_VERSION, group_id_blob], |row| {
        row.get::<_, u64>(0)
    })
    .expect("should query epoch rows")
    .collect::<Result<Vec<_>, _>>()
    .expect("should collect epoch rows")
}

#[test]
fn epoch_migration_creates_schema_for_empty_db() {
    let db_path = temp_db_path();
    let db_path_str = db_path.to_string_lossy().into_owned();

    let provider = SqliteProvider::new(&db_path_str, &None).expect("should create provider");
    let connection = provider
        .storage()
        .connection_pool()
        .checkout()
        .expect("should get sqlite connection");

    assert!(table_exists(&connection, "openmls_group_data"));
    assert!(!table_exists(&connection, "openmls_epoch_migration_state"));
    assert!(table_exists(&connection, "openmls_group_epoch_meta"));
    assert!(table_exists(
        &connection,
        "openmls_group_epoch_message_secrets"
    ));
    assert_eq!(count_rows(&connection, "openmls_group_epoch_meta"), 0);
    assert_eq!(
        count_rows(&connection, "openmls_group_epoch_message_secrets"),
        0
    );

    let _ = fs::remove_file(db_path);
}

#[test]
fn new_groups_are_persisted_as_epoch_message_secrets_only() {
    let db_path = temp_db_path();
    let db_path_str = db_path.to_string_lossy().into_owned();

    let provider = SqliteProvider::new(&db_path_str, &None).expect("should create provider");
    create_group_legacy(&provider, "alice", "epoch-only-group", 5);
    advance_group_epoch(&provider, "epoch-only-group");

    let group_id = GroupId::from_slice(b"epoch-only-group");
    assert!(
        provider
            .storage()
            .is_group_epoch_message_secrets_migrated(&group_id)
            .expect("should read migration status")
    );
    assert!(
        provider
            .storage()
            .load_group_epoch_message_secrets(&group_id, 1)
            .expect("should load current message secrets")
            .is_some()
    );
    assert!(
        provider
            .storage()
            .load_group_epoch_message_secrets(&group_id, 0)
            .expect("should load past message secrets")
            .is_some()
    );
    assert_eq!(count_legacy_message_secrets(&provider, &group_id), 0);

    let reopened_provider =
        SqliteProvider::new(&db_path_str, &None).expect("should reopen epoch-only db");
    assert!(
        reopened_provider
            .storage()
            .list_group_ids_with_message_secrets::<GroupId>()
            .expect("should list pending groups")
            .is_empty(),
        "epoch-only groups should not be pending legacy migration"
    );

    let _ = fs::remove_file(db_path);
}

#[test]
fn epoch_only_groups_are_not_listed_as_pending_migration() {
    let db_path = temp_db_path();
    let db_path_str = db_path.to_string_lossy().into_owned();

    let provider = SqliteProvider::new(&db_path_str, &None).expect("should create provider");
    create_group_legacy(&provider, "alice", "older-good", 5);
    create_group_legacy(&provider, "alice", "newer-good", 5);
    create_group_legacy(&provider, "alice", "newest-good", 5);

    let pending_groups = provider
        .storage()
        .list_group_ids_with_message_secrets::<GroupId>()
        .expect("should list pending group ids");
    assert!(pending_groups.is_empty());

    let _ = fs::remove_file(db_path);
}

#[test]
fn migrated_group_missing_epoch_message_secrets_returns_error() {
    let db_path = temp_db_path();
    let db_path_str = db_path.to_string_lossy().into_owned();

    let provider = SqliteProvider::new(&db_path_str, &None).expect("should create provider");
    create_group_legacy(&provider, "alice", "missing-current-epoch", 5);

    let group_id = GroupId::from_slice(b"missing-current-epoch");
    assert!(
        provider
            .storage()
            .is_group_epoch_message_secrets_migrated(&group_id)
            .expect("should read migration status")
    );

    delete_epoch_message_secrets(&provider, &group_id, 0);

    let err = group_current_epoch_message_secrets(&provider, "missing-current-epoch")
        .expect_err("missing current epoch row should not fallback to legacy");
    assert!(
        err.to_string()
            .contains("Missing current epoch MessageSecrets"),
        "unexpected error: {err}"
    );

    let _ = fs::remove_file(db_path);
}

#[test]
fn exact_past_epoch_processing_keeps_other_retained_epoch_rows() {
    let alice_db_path = temp_db_path();
    let bob_db_path = temp_db_path();
    let alice_db_path_str = alice_db_path.to_string_lossy().into_owned();
    let bob_db_path_str = bob_db_path.to_string_lossy().into_owned();

    let alice = SqliteProvider::new(&alice_db_path_str, &None).expect("should create alice");
    let bob = SqliteProvider::new(&bob_db_path_str, &None).expect("should create bob");
    let group_id = "retained-rows-group";
    let max_past_epochs = 5;

    create_group(
        &alice,
        "alice",
        group_id,
        DEFAULT_CIPHERSUITE,
        &group_config(max_past_epochs),
        None,
    )
    .expect("should create group");
    let bob_key_package = core::generate_key_package("bob", &bob, DEFAULT_CIPHERSUITE, true, None)
        .expect("should generate bob key package");
    let mut alice_group = load_group(&alice, group_id, []).expect("should load alice group");
    let alice_signer = group_signer(&alice_group, &alice).expect("should load alice signer");
    let add_result = core::add_members(&mut alice_group, &alice, &alice_signer, &[bob_key_package])
        .expect("should add bob");
    merge_pending_commit(&mut alice_group, &alice).expect("should merge add commit");
    core::process_welcome(&bob, &add_result.welcome, &join_config(max_past_epochs))
        .expect("should process welcome");

    for _ in 0..max_past_epochs {
        let mut alice_group = load_group(&alice, group_id, []).expect("should load alice group");
        let alice_signer = group_signer(&alice_group, &alice).expect("should load alice signer");
        let update =
            update_leaf_node(&mut alice_group, &alice, &alice_signer).expect("should update alice");
        merge_pending_commit(&mut alice_group, &alice).expect("should merge alice commit");

        let mut bob_group = load_group(&bob, group_id, []).expect("should load bob group");
        core::process_operation_message(&mut bob_group, &bob, &update.commit)
            .expect("bob should process epoch advance");
    }

    let mut alice_group = load_group(&alice, group_id, []).expect("should load alice group");
    let alice_signer = group_signer(&alice_group, &alice).expect("should load alice signer");
    let past_message =
        core::encrypt_message(&mut alice_group, &alice, &alice_signer, b"message-past")
            .expect("should encrypt past message");
    let past_message_epoch = MlsMessageIn::tls_deserialize_exact(past_message.as_slice())
        .expect("should deserialize past message")
        .try_into_protocol_message()
        .expect("should parse past protocol message")
        .epoch()
        .as_u64();

    let mut alice_group = load_group(&alice, group_id, []).expect("should load alice group");
    let alice_signer = group_signer(&alice_group, &alice).expect("should load alice signer");
    let update =
        update_leaf_node(&mut alice_group, &alice, &alice_signer).expect("should update alice");
    merge_pending_commit(&mut alice_group, &alice).expect("should merge alice commit");
    let mut bob_group = load_group(&bob, group_id, []).expect("should load bob group");
    core::process_operation_message(&mut bob_group, &bob, &update.commit)
        .expect("bob should advance beyond message epoch");

    let openmls_group_id = GroupId::from_slice(group_id.as_bytes());
    let before = list_epoch_message_secret_epochs(&bob, &openmls_group_id);
    assert!(
        before.len() > 2,
        "test needs more than current + exact epoch rows, got {before:?}"
    );

    let mut bob_group = load_group(&bob, group_id, [past_message.as_slice()])
        .expect("should preload exact past epoch for bob group");
    let result = core::process_application_message(&mut bob_group, &bob, &past_message)
        .expect("bob should process past application message");
    assert_eq!(result.message, b"message-past");

    let after = list_epoch_message_secret_epochs(&bob, &openmls_group_id);
    assert_eq!(
        after, before,
        "processing one exact past epoch must not replace away other retained rows"
    );

    delete_epoch_message_secrets(&bob, &openmls_group_id, past_message_epoch);
    let err = load_group(&bob, group_id, [past_message.as_slice()])
        .expect_err("missing preloaded past epoch should fail during group load");
    assert!(
        err.to_string()
            .contains("Missing past epoch MessageSecrets"),
        "unexpected error: {err}"
    );

    let _ = fs::remove_file(alice_db_path);
    let _ = fs::remove_file(bob_db_path);
}
