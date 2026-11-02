//! Diagnostic reproduction: a healthy DB can yield InvalidCurrentMessageSecrets
//! when an epoch changes between the group-context and message-secrets reads.
use std::{
    cell::RefCell,
    time::{SystemTime, UNIX_EPOCH},
};

use kchat_storage_provider::{Codec, SqliteStorageProvider, TransactionalStorageProvider};
use openmls::group::{GroupId, LoadOptimizeError, MlsGroup, MlsGroupCreateConfig};
use openmls_traits::OpenMlsProvider;
use serde::{Serialize, de::DeserializeOwned};
use uq_openmls::{core, provider::SqliteProvider};

thread_local! {
    static AFTER_CONTEXT: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

#[derive(Default)]
struct InterleavingCodec;

impl Codec for InterleavingCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Self::Error> {
        let value = serde_json::from_slice(bytes)?;
        if std::any::type_name::<T>().ends_with("::GroupContext") {
            let callback = AFTER_CONTEXT.with(|slot| slot.borrow_mut().take());
            if let Some(callback) = callback {
                callback();
            }
        }
        Ok(value)
    }
}

fn reproduce(transactional_reader: bool) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mls-epoch-load-race-{}-{nonce}.sqlite",
        std::process::id()
    ));
    let provider = SqliteProvider::new(path.to_str().unwrap(), &None).unwrap();
    let group_name = "epoch-load-race";
    let group_id = GroupId::from_slice(group_name.as_bytes());
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(core::DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(8)
        .build();
    provider
        .transaction(|tx| {
            core::create_group(
                tx,
                "alice",
                group_name,
                core::DEFAULT_CIPHERSUITE,
                &config,
                None,
            )?;
            Ok(())
        })
        .unwrap();

    let storage =
        SqliteStorageProvider::<InterleavingCodec>::new(provider.storage().connection_pool());
    assert_eq!(
        MlsGroup::load_optimize(&storage, &group_id, [])
            .unwrap()
            .unwrap()
            .epoch()
            .as_u64(),
        0
    );
    let writer = provider.clone();
    AFTER_CONTEXT.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            writer
                .transaction(|tx| {
                    let mut group = core::group(tx, group_name, [])?;
                    let signer = core::group_signer(&group, tx)?;
                    core::update_leaf_node(&mut group, tx, &signer)?;
                    core::merge_pending_commit(&mut group, tx)?;
                    assert_eq!(group.epoch().as_u64(), 1);
                    Ok(())
                })
                .unwrap();
        }))
    });

    if transactional_reader {
        storage
            .transaction(|tx| {
                let storage = TransactionalStorageProvider::<InterleavingCodec>::new(tx);
                let loaded = MlsGroup::load_optimize(&storage, &group_id, [])
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    loaded.epoch().as_u64(),
                    0,
                    "reader retains its pre-commit snapshot"
                );
                Ok(())
            })
            .unwrap();
    } else {
        let error = MlsGroup::load_optimize(&storage, &group_id, []).unwrap_err();
        assert_eq!(error, LoadOptimizeError::InvalidCurrentMessageSecrets);
        eprintln!("reproduced exact error: {error}");
    }
    AFTER_CONTEXT
        .with(|slot| assert!(slot.borrow().is_none(), "interleaving hook must have fired"));

    // A new read succeeds immediately, without repairing any data.
    assert_eq!(
        MlsGroup::load_optimize(&storage, &group_id, [])
            .unwrap()
            .unwrap()
            .epoch()
            .as_u64(),
        1
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let invalid_json: u64 = connection.query_row(
        "SELECT count(*) FROM openmls_group_epoch_message_secrets WHERE NOT json_valid(CAST(message_secrets AS TEXT))",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(invalid_json, 0);
    let past_bytes = storage
        .load_group_epoch_message_secrets(&group_id, 0)
        .unwrap()
        .unwrap();
    let current_bytes = storage
        .load_group_epoch_message_secrets(&group_id, 1)
        .unwrap()
        .unwrap();
    let past: serde_json::Value = serde_json::from_slice(&past_bytes).unwrap();
    let current: serde_json::Value = serde_json::from_slice(&current_bytes).unwrap();
    assert!(past.get("message_secrets").is_some());
    assert!(past.get("sender_data_secret").is_none());
    assert!(current.get("sender_data_secret").is_some());
    assert!(current.get("message_secrets").is_none());
    eprintln!(
        "transactional_reader={transactional_reader}, fresh load epoch=1, integrity={integrity}, invalid_json={invalid_json}"
    );
}

#[test]
fn healthy_db_nontransactional_load_reproduces_invalid_current_secrets() {
    reproduce(false);
}

#[test]
fn transactional_load_keeps_consistent_snapshot_across_epoch_change() {
    reproduce(true);
}
