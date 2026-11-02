// Regression coverage for incomplete local groups and concurrent reads.
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use kchat_mobile_sdk_rs::mls::UqMls;
use rusqlite::Connection;

fn fixture() -> (UqMls, Connection) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("delete-group-debug-{}-{nonce}", std::process::id()));
    let mls_path = base.with_extension("mls.sqlite");
    let status_path = base.with_extension("status.sqlite");
    let api = UqMls::new(
        "alice".to_owned(),
        mls_path.to_string_lossy().into_owned(),
        status_path.to_string_lossy().into_owned(),
        10,
        48,
        None,
        5,
        10,
        None,
    )
    .unwrap();
    api.create_group("debug-delete", None).unwrap();
    (api, Connection::open(mls_path).unwrap())
}

fn retained_rows(db: &Connection) -> u64 {
    db.query_row("SELECT count(*) FROM openmls_group_data", [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn assert_delete_succeeds(api: &UqMls, db: &Connection) {
    assert!(retained_rows(db) > 0);
    for _ in 0..3 {
        api.delete_group("debug-delete")
            .expect("delete must not depend on decodable group state");
        assert_eq!(retained_rows(db), 0);
    }
    let integrity: String = db
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
}

#[test]
fn deletes_malformed_current_secrets() {
    let (api, db) = fixture();
    db.execute(
        "UPDATE openmls_group_epoch_message_secrets SET message_secrets = ?1",
        [vec![0xffu8]],
    )
    .unwrap();
    assert_delete_succeeds(&api, &db);
}

#[test]
fn deletes_missing_current_secrets() {
    let (api, db) = fixture();
    db.execute("DELETE FROM openmls_group_epoch_message_secrets", [])
        .unwrap();
    assert_delete_succeeds(&api, &db);
}

#[test]
fn deletes_partial_group_without_own_leaf_index() {
    let (api, db) = fixture();
    assert_eq!(
        db.execute(
            "DELETE FROM openmls_group_data WHERE data_type = 'own_leaf_index'",
            []
        )
        .unwrap(),
        1
    );
    assert_delete_succeeds(&api, &db);
}

#[test]
fn delete_is_idempotent() {
    let (api, db) = fixture();
    api.delete_group("debug-delete").unwrap();
    assert_eq!(retained_rows(&db), 0);
    api.delete_group("debug-delete")
        .expect("repeated delete succeeds");
}

#[test]
fn writer_lock_returns_error_then_delete_succeeds_after_release() {
    let (api, db) = fixture();
    let before = retained_rows(&db);
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let start = Instant::now();
    let error = api.delete_group("debug-delete").unwrap_err().to_string();
    eprintln!(
        "held writer lock: elapsed={:?}, error={error}",
        start.elapsed()
    );
    assert!(error.contains("locked"), "unexpected error: {error}");
    assert_eq!(retained_rows(&db), before);
    db.execute_batch("ROLLBACK").unwrap();
    api.delete_group("debug-delete").unwrap();
    assert_eq!(retained_rows(&db), 0);
}

#[test]
fn readers_keep_a_consistent_snapshot_while_epochs_change() {
    use std::sync::{Arc, Barrier};
    let (api, _db) = fixture();
    let api = Arc::new(api);
    let start = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        let writer = Arc::clone(&api);
        let writer_start = Arc::clone(&start);
        let handle = scope.spawn(move || {
            writer_start.wait();
            for _ in 0..80 {
                writer.update_leaf_node("debug-delete").unwrap();
                writer.merge_pending_commit("debug-delete").unwrap();
            }
        });
        start.wait();
        for _ in 0..800 {
            assert_eq!(api.members("debug-delete").unwrap(), vec!["alice"]);
            api.pending_commit("debug-delete").unwrap();
            api.pending_proposals("debug-delete").unwrap();
            api.export_group_info("debug-delete").unwrap();
        }
        handle.join().unwrap();
    });
}

#[test]
fn deletes_all_group_scoped_rows_and_preserves_other_groups_and_identity() {
    let (api, db) = fixture();
    let key: Vec<u8> = db
        .query_row(
            "SELECT group_id FROM openmls_group_data LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    api.update_leaf_node("debug-delete").unwrap();
    api.merge_pending_commit("debug-delete").unwrap();
    api.create_group("preserved", None).unwrap();
    let signature_keys: u64 = db
        .query_row("SELECT count(*) FROM openmls_signature_keys", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(signature_keys > 0);
    // Deliberately undecodable orphan rows must also be removable by group ID.
    db.execute(
        "INSERT INTO openmls_epoch_keys_pairs VALUES (1, ?1, X'ff', 123, X'ff')",
        [&key],
    )
    .unwrap();
    db.execute("INSERT INTO openmls_own_leaf_nodes (provider_version, group_id, leaf_node) VALUES (1, ?1, X'ff')", [&key]).unwrap();
    db.execute(
        "INSERT INTO openmls_proposals VALUES (1, ?1, X'ff', X'ff')",
        [&key],
    )
    .unwrap();
    db.execute("INSERT INTO openmls_decrypted_application_messages VALUES (1, ?1, 'cached', X'01', X'02', 0, 100)", [&key]).unwrap();
    api.delete_group("debug-delete").unwrap();
    for table in [
        "openmls_group_data",
        "openmls_epoch_keys_pairs",
        "openmls_own_leaf_nodes",
        "openmls_proposals",
        "openmls_group_epoch_message_secrets",
        "openmls_decrypted_application_messages",
    ] {
        let remaining: u64 = db
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE group_id = ?1"),
                [&key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "rows remain in {table}");
    }
    assert_eq!(api.members("preserved").unwrap(), vec!["alice"]);
    assert_eq!(
        db.query_row("SELECT count(*) FROM openmls_signature_keys", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        signature_keys
    );
    api.create_group("debug-delete", None)
        .expect("deleted group can be recreated");
    assert_eq!(api.members("debug-delete").unwrap(), vec!["alice"]);
}

#[test]
fn deletion_rolls_back_if_a_later_table_delete_fails() {
    let (api, db) = fixture();
    let key: Vec<u8> = db
        .query_row(
            "SELECT group_id FROM openmls_group_data LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    db.execute(
        "INSERT INTO openmls_proposals VALUES (1, ?1, X'ff', X'ff')",
        [&key],
    )
    .unwrap();
    let before = retained_rows(&db);
    db.execute_batch("CREATE TRIGGER fail_delete BEFORE DELETE ON openmls_proposals BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END").unwrap();
    let error = api.delete_group("debug-delete").unwrap_err().to_string();
    assert!(error.contains("injected delete failure"));
    assert_eq!(retained_rows(&db), before, "earlier deletes must roll back");
    db.execute_batch("DROP TRIGGER fail_delete").unwrap();
    api.delete_group("debug-delete").unwrap();
    assert_eq!(retained_rows(&db), 0);
}

#[test]
fn status_cleanup_failure_is_reported_and_can_be_retried() {
    let (api, db) = fixture();
    let status_path = format!(
        "{}.status.sqlite",
        db.path().unwrap().strip_suffix(".mls.sqlite").unwrap()
    );
    let status = Connection::open(status_path).unwrap();
    status.execute_batch("CREATE TRIGGER fail_status_delete BEFORE DELETE ON group_statuses BEGIN SELECT RAISE(ABORT, 'injected status failure'); END").unwrap();
    let error = api.delete_group("debug-delete").unwrap_err().to_string();
    assert!(error.contains("injected status failure"));
    assert_eq!(retained_rows(&db), 0, "MLS data was already deleted");
    status
        .execute_batch("DROP TRIGGER fail_status_delete")
        .unwrap();
    api.delete_group("debug-delete")
        .expect("retry finishes status cleanup despite absent MLS group");
    let rows: u64 = status
        .query_row("SELECT count(*) FROM group_statuses", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn deletes_orphan_secrets_when_public_group_is_missing() {
    let (api, db) = fixture();
    db.execute(
        "DELETE FROM openmls_group_data WHERE data_type = 'context'",
        [],
    )
    .unwrap();
    assert_delete_succeeds(&api, &db);
    let rows: u64 = db
        .query_row(
            "SELECT count(*) FROM openmls_group_epoch_message_secrets",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn create_does_not_overwrite_a_group_whose_secrets_cannot_be_decoded() {
    let (api, db) = fixture();
    db.execute(
        "UPDATE openmls_group_epoch_message_secrets SET message_secrets = X'ff'",
        [],
    )
    .unwrap();
    let error = api
        .create_group("debug-delete", None)
        .expect_err("load failure must not be treated as absence")
        .to_string();
    assert!(error.contains("MessageSecrets is invalid"));
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT message_secrets FROM openmls_group_epoch_message_secrets",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bytes, vec![0xff]);
}

#[test]
fn delete_clears_pending_commit_and_allows_recreation() {
    let (api, db) = fixture();
    api.update_leaf_node("debug-delete").unwrap();
    assert!(api.pending_commit("debug-delete").unwrap().is_some());
    api.delete_group("debug-delete").unwrap();
    assert_eq!(retained_rows(&db), 0);
    api.create_group("debug-delete", None).unwrap();
    assert!(api.pending_commit("debug-delete").unwrap().is_none());
    assert_eq!(api.members("debug-delete").unwrap(), vec!["alice"]);
}
