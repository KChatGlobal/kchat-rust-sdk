use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use openmls::group::{MlsGroupCreateConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY};
use uq_openmls::{
    core::{DEFAULT_CIPHERSUITE, create_group},
    provider::SqliteProvider,
};

use kchat_mls::get_all_group_ids;

fn temp_db_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "kchat-mls-get-all-group-ids-{}-{}.sqlite",
        std::process::id(),
        nanos
    ))
}

fn group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

fn setup_provider() -> (PathBuf, SqliteProvider) {
    let db_path = temp_db_path();
    let db_path_str = db_path.to_string_lossy().into_owned();
    let provider = SqliteProvider::new(&db_path_str, &None).expect("should create sqlite provider");
    (db_path, provider)
}

fn cleanup_provider(db_path: &PathBuf) {
    let _ = fs::remove_file(db_path);
}

#[test]
fn test_get_all_group_ids_empty() {
    let (db_path, provider) = setup_provider();

    let group_ids = get_all_group_ids(&provider);

    assert!(
        group_ids.is_empty(),
        "should return empty list when no groups exist"
    );

    cleanup_provider(&db_path);
}

#[test]
fn test_get_all_group_ids_single_group() {
    let (db_path, provider) = setup_provider();
    let group_id = "test-group-1";

    provider
        .transaction(|tx_provider| {
            create_group(
                tx_provider,
                "alice",
                group_id,
                DEFAULT_CIPHERSUITE,
                &group_config(),
                None,
            )?;
            Ok(())
        })
        .expect("should create group");

    let group_ids = get_all_group_ids(&provider);

    assert_eq!(group_ids.len(), 1, "should return exactly one group");
    assert!(
        group_ids.contains(&group_id.to_string()),
        "should contain the created group"
    );

    cleanup_provider(&db_path);
}

#[test]
fn test_get_all_group_ids_multiple_groups() {
    let (db_path, provider) = setup_provider();
    let group_ids_to_create = vec!["group-alpha", "group-beta", "group-gamma"];

    for group_id in &group_ids_to_create {
        provider
            .transaction(|tx_provider| {
                create_group(
                    tx_provider,
                    "alice",
                    group_id,
                    DEFAULT_CIPHERSUITE,
                    &group_config(),
                    None,
                )?;
                Ok(())
            })
            .expect(&format!("should create group {}", group_id));
    }

    let group_ids = get_all_group_ids(&provider);

    assert_eq!(group_ids.len(), 3, "should return exactly three groups");
    for group_id in &group_ids_to_create {
        assert!(
            group_ids.contains(&group_id.to_string()),
            "should contain group {}",
            group_id
        );
    }

    cleanup_provider(&db_path);
}

#[test]
fn test_get_all_group_ids_no_duplicates() {
    let (db_path, provider) = setup_provider();
    let group_id = "test-group-dedup";

    provider
        .transaction(|tx_provider| {
            create_group(
                tx_provider,
                "alice",
                group_id,
                DEFAULT_CIPHERSUITE,
                &group_config(),
                None,
            )?;
            Ok(())
        })
        .expect("should create group");

    let group_ids = get_all_group_ids(&provider);
    let first_count = group_ids.len();

    let group_ids_again = get_all_group_ids(&provider);
    let second_count = group_ids_again.len();

    assert_eq!(
        first_count, second_count,
        "calling get_all_group_ids multiple times should return same count"
    );
    assert_eq!(first_count, 1, "should still return exactly one group");

    cleanup_provider(&db_path);
}

#[test]
fn test_get_all_group_ids_returns_strings() {
    let (db_path, provider) = setup_provider();
    let group_id = "string-test-group";

    provider
        .transaction(|tx_provider| {
            create_group(
                tx_provider,
                "alice",
                group_id,
                DEFAULT_CIPHERSUITE,
                &group_config(),
                None,
            )?;
            Ok(())
        })
        .expect("should create group");

    let group_ids = get_all_group_ids(&provider);

    assert!(!group_ids.is_empty(), "should not be empty");
    let returned_group_id = &group_ids[0];
    assert_eq!(
        returned_group_id.as_str(),
        group_id,
        "returned group_id should match created group_id"
    );

    cleanup_provider(&db_path);
}
