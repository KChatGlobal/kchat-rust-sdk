use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls_traits::OpenMlsProvider;
use uq_openmls::{
    core::{DEFAULT_CIPHERSUITE, create_group},
    error::Error,
    provider::SqliteProvider,
};

fn temp_db_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "uq-openmls-sqlite-transaction-{}-{}.sqlite",
        std::process::id(),
        nanos
    ))
}

fn group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

#[test]
fn transaction_commits_group_creation() {
    let db_path = temp_db_path();
    let db_path_str = db_path.to_string_lossy().into_owned();
    let provider = SqliteProvider::new(&db_path_str, &None).expect("should create sqlite provider");
    let group_id = "group-transaction-commit";

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
        .expect("transaction should commit group creation");

    let loaded = MlsGroup::load(
        provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("group load should succeed");

    assert!(
        loaded.is_some(),
        "committed transaction should persist group"
    );

    let _ = fs::remove_file(db_path);
}

#[test]
fn transaction_rolls_back_group_creation_on_error() {
    let db_path = temp_db_path();
    let db_path_str = db_path.to_string_lossy().into_owned();
    let provider = SqliteProvider::new(&db_path_str, &None).expect("should create sqlite provider");
    let group_id = "group-transaction-rollback";

    let result: Result<(), rusqlite::Error> = provider.transaction(|tx_provider| {
        create_group(
            tx_provider,
            "alice",
            group_id,
            DEFAULT_CIPHERSUITE,
            &group_config(),
            None,
        )?;
        Err(Error::Storage("force rollback".to_owned()))
    });

    assert!(
        result.is_err(),
        "transaction should return the forced error"
    );

    let loaded = MlsGroup::load(
        provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("group load should succeed");

    assert!(
        loaded.is_none(),
        "rolled back transaction should not persist any group state"
    );

    let _ = fs::remove_file(db_path);
}
