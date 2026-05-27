use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use kchat_mls::{
    AllMessagesOfGroupArgs, MessageType, MlsMessage, ProcessAllMessagesArgs,
    open_group_status_connection, process_all_messages,
};
use openmls::group::{MlsGroupCreateConfig, MlsGroupJoinConfig};
use uq_openmls::{
    core::{
        DEFAULT_CIPHERSUITE, add_members, create_group, generate_key_package, group, group_context,
        group_signer, merge_pending_commit, process_welcome, update_leaf_node,
    },
    provider::SqliteProvider,
};

const SENDER_ID: &str = "alice";
const RECEIVER_ID: &str = "bob";

fn temp_db_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.sqlite", std::process::id()))
}

fn cleanup_db(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
}

fn create_group_config(max_past_epochs: usize) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build()
}

fn create_join_config(max_past_epochs: usize) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(max_past_epochs)
        .build()
}

fn bootstrap_group(
    sender_provider: &SqliteProvider,
    receiver_provider: &SqliteProvider,
    group_id: &str,
    max_past_epochs: usize,
) {
    create_group(
        sender_provider,
        SENDER_ID,
        group_id,
        DEFAULT_CIPHERSUITE,
        &create_group_config(max_past_epochs),
        None,
    )
    .expect("should create sender group");

    let receiver_key_package = generate_key_package(
        RECEIVER_ID,
        receiver_provider,
        DEFAULT_CIPHERSUITE,
        false,
        None,
    )
    .expect("should generate receiver key package");

    let mut sender_group = group(sender_provider, group_id, []).expect("should load sender group");
    let sender_signer =
        group_signer(&sender_group, sender_provider).expect("should get sender signer");
    let add_result = add_members(
        &mut sender_group,
        sender_provider,
        &sender_signer,
        &[receiver_key_package],
    )
    .expect("should add receiver");
    merge_pending_commit(&mut sender_group, sender_provider)
        .expect("should merge pending commit on sender");

    let _ = process_welcome(
        receiver_provider,
        &add_result.welcome,
        &create_join_config(max_past_epochs),
    )
    .expect("receiver should process welcome");
}

fn build_commit_messages(
    sender_provider: &SqliteProvider,
    group_id: &str,
    count: usize,
) -> Vec<MlsMessage> {
    let mut sender_group = group(sender_provider, group_id, []).expect("should load sender group");
    let sender_signer =
        group_signer(&sender_group, sender_provider).expect("should get sender signer");

    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        let update_result = update_leaf_node(&mut sender_group, sender_provider, &sender_signer)
            .expect("should update leaf node");
        merge_pending_commit(&mut sender_group, sender_provider)
            .expect("should merge pending commit");

        messages.push(MlsMessage {
            blob: update_result.commit,
            epoch: update_result.current_epoch,
            sender: SENDER_ID.to_owned(),
            message_type: MessageType::Commit,
        });
    }

    messages
}

#[test]
fn test_process_all_messages_commits_success() {
    let sender_db = temp_db_path("kchat-mls-process-all-messages-sender-success");
    let receiver_db = temp_db_path("kchat-mls-process-all-messages-receiver-success");
    let status_db = temp_db_path("kchat-mls-process-all-messages-status-success");
    let sender_db_str = sender_db.to_string_lossy().into_owned();
    let receiver_db_str = receiver_db.to_string_lossy().into_owned();
    let status_db_str = status_db.to_string_lossy().into_owned();
    let max_past_epochs = 32;
    let group_id = "group_process_all_messages_success";

    let sender_provider =
        SqliteProvider::new(&sender_db_str, &None).expect("should create sender provider");
    let receiver_provider =
        SqliteProvider::new(&receiver_db_str, &None).expect("should create receiver provider");
    let group_status_conn =
        open_group_status_connection(&status_db_str).expect("should open group status connection");

    bootstrap_group(
        &sender_provider,
        &receiver_provider,
        group_id,
        max_past_epochs,
    );
    let commits = build_commit_messages(&sender_provider, group_id, 3);

    let before_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let before_epoch = before_context.epoch().as_u64() as i64;
    let before_tree_hash = before_context.tree_hash().to_vec();

    let args = ProcessAllMessagesArgs {
        group_messages: vec![AllMessagesOfGroupArgs {
            group_id: group_id.to_owned(),
            messages: commits,
            current_epoch: before_epoch,
            current_tree_hash: before_tree_hash.clone(),
            pending_epoch: before_epoch,
            pending_tree_hash: before_tree_hash,
        }],
    };

    let result = process_all_messages(
        &group_status_conn,
        &receiver_provider,
        args,
        &create_join_config(max_past_epochs),
        None,
    )
    .expect("process_all_messages should succeed");

    let after_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let after_epoch = after_context.epoch().as_u64() as i64;

    assert_eq!(
        result.group_results.len(),
        1,
        "should have one group result"
    );
    assert!(
        result.group_results[0].error.is_none(),
        "group result should not contain error"
    );
    assert!(
        result.deleted_groups.is_empty(),
        "no group should be deleted in success case"
    );
    assert_eq!(
        after_epoch,
        before_epoch + 3,
        "receiver epoch should advance by number of commits"
    );

    drop(group_status_conn);
    drop(receiver_provider);
    drop(sender_provider);
    cleanup_db(&status_db);
    cleanup_db(&receiver_db);
    cleanup_db(&sender_db);
}

#[test]
fn test_process_all_messages_invalid_commit_keeps_prior_progress() {
    let sender_db = temp_db_path("kchat-mls-process-all-messages-sender-error");
    let receiver_db = temp_db_path("kchat-mls-process-all-messages-receiver-error");
    let status_db = temp_db_path("kchat-mls-process-all-messages-status-error");
    let sender_db_str = sender_db.to_string_lossy().into_owned();
    let receiver_db_str = receiver_db.to_string_lossy().into_owned();
    let status_db_str = status_db.to_string_lossy().into_owned();
    let max_past_epochs = 32;
    let group_id = "group_process_all_messages_error";

    let sender_provider =
        SqliteProvider::new(&sender_db_str, &None).expect("should create sender provider");
    let receiver_provider =
        SqliteProvider::new(&receiver_db_str, &None).expect("should create receiver provider");
    let group_status_conn =
        open_group_status_connection(&status_db_str).expect("should open group status connection");

    bootstrap_group(
        &sender_provider,
        &receiver_provider,
        group_id,
        max_past_epochs,
    );
    let mut commits = build_commit_messages(&sender_provider, group_id, 3);
    assert_eq!(
        commits.len(),
        3,
        "should have exactly three commit messages"
    );
    commits[1].blob[0] ^= 0xFF;

    let before_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let before_epoch = before_context.epoch().as_u64() as i64;
    let before_tree_hash = before_context.tree_hash().to_vec();

    let args = ProcessAllMessagesArgs {
        group_messages: vec![AllMessagesOfGroupArgs {
            group_id: group_id.to_owned(),
            messages: commits,
            current_epoch: before_epoch,
            current_tree_hash: before_tree_hash.clone(),
            pending_epoch: before_epoch,
            pending_tree_hash: before_tree_hash,
        }],
    };

    let result = process_all_messages(
        &group_status_conn,
        &receiver_provider,
        args,
        &create_join_config(max_past_epochs),
        None,
    )
    .expect("process_all_messages should return result even when a group has error");

    let after_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let after_epoch = after_context.epoch().as_u64() as i64;

    assert_eq!(
        result.group_results.len(),
        1,
        "should have one group result"
    );
    assert!(
        result.group_results[0].error.is_none(),
        "non-storage commit processing errors should not set group error"
    );
    assert_eq!(
        after_epoch,
        before_epoch + 1,
        "only the first valid commit should be applied when later commits cannot be processed"
    );

    drop(group_status_conn);
    drop(receiver_provider);
    drop(sender_provider);
    cleanup_db(&status_db);
    cleanup_db(&receiver_db);
    cleanup_db(&sender_db);
}

#[test]
fn test_process_all_messages_non_fatal_commit_error_keeps_processing() {
    let sender_db = temp_db_path("kchat-mls-process-all-messages-sender-non-fatal");
    let receiver_db = temp_db_path("kchat-mls-process-all-messages-receiver-non-fatal");
    let status_db = temp_db_path("kchat-mls-process-all-messages-status-non-fatal");
    let sender_db_str = sender_db.to_string_lossy().into_owned();
    let receiver_db_str = receiver_db.to_string_lossy().into_owned();
    let status_db_str = status_db.to_string_lossy().into_owned();
    let max_past_epochs = 32;
    let group_id = "group_process_all_messages_non_fatal";

    let sender_provider =
        SqliteProvider::new(&sender_db_str, &None).expect("should create sender provider");
    let receiver_provider =
        SqliteProvider::new(&receiver_db_str, &None).expect("should create receiver provider");
    let group_status_conn =
        open_group_status_connection(&status_db_str).expect("should open group status connection");

    bootstrap_group(
        &sender_provider,
        &receiver_provider,
        group_id,
        max_past_epochs,
    );

    let commits = build_commit_messages(&sender_provider, group_id, 2);
    assert_eq!(commits.len(), 2, "should have exactly two commit messages");

    let before_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let before_epoch = before_context.epoch().as_u64() as i64;
    let before_tree_hash = before_context.tree_hash().to_vec();

    let args = ProcessAllMessagesArgs {
        group_messages: vec![AllMessagesOfGroupArgs {
            group_id: group_id.to_owned(),
            messages: vec![commits[0].clone(), commits[0].clone(), commits[1].clone()],
            current_epoch: before_epoch,
            current_tree_hash: before_tree_hash.clone(),
            pending_epoch: before_epoch,
            pending_tree_hash: before_tree_hash,
        }],
    };

    let result = process_all_messages(
        &group_status_conn,
        &receiver_provider,
        args,
        &create_join_config(max_past_epochs),
        None,
    )
    .expect("process_all_messages should succeed with non-fatal commit error");

    let after_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let after_epoch = after_context.epoch().as_u64() as i64;

    assert_eq!(
        result.group_results.len(),
        1,
        "should have one group result"
    );
    assert!(
        result.group_results[0].error.is_none(),
        "non-fatal processing error should not set group error"
    );
    assert_eq!(
        after_epoch,
        before_epoch + 2,
        "receiver epoch should still advance past the duplicate commit error"
    );

    drop(group_status_conn);
    drop(receiver_provider);
    drop(sender_provider);
    cleanup_db(&status_db);
    cleanup_db(&receiver_db);
    cleanup_db(&sender_db);
}

#[test]
fn test_process_all_messages_empty_message_batch() {
    let sender_db = temp_db_path("kchat-mls-process-all-messages-sender-empty");
    let receiver_db = temp_db_path("kchat-mls-process-all-messages-receiver-empty");
    let status_db = temp_db_path("kchat-mls-process-all-messages-status-empty");
    let sender_db_str = sender_db.to_string_lossy().into_owned();
    let receiver_db_str = receiver_db.to_string_lossy().into_owned();
    let status_db_str = status_db.to_string_lossy().into_owned();
    let max_past_epochs = 32;
    let group_id = "group_process_all_messages_empty";

    let sender_provider =
        SqliteProvider::new(&sender_db_str, &None).expect("should create sender provider");
    let receiver_provider =
        SqliteProvider::new(&receiver_db_str, &None).expect("should create receiver provider");
    let group_status_conn =
        open_group_status_connection(&status_db_str).expect("should open group status connection");

    bootstrap_group(
        &sender_provider,
        &receiver_provider,
        group_id,
        max_past_epochs,
    );

    let before_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let before_epoch = before_context.epoch().as_u64() as i64;
    let before_tree_hash = before_context.tree_hash().to_vec();

    let args = ProcessAllMessagesArgs {
        group_messages: vec![AllMessagesOfGroupArgs {
            group_id: group_id.to_owned(),
            messages: Vec::new(),
            current_epoch: before_epoch,
            current_tree_hash: before_tree_hash.clone(),
            pending_epoch: before_epoch,
            pending_tree_hash: before_tree_hash,
        }],
    };

    let result = process_all_messages(
        &group_status_conn,
        &receiver_provider,
        args,
        &create_join_config(max_past_epochs),
        None,
    )
    .expect("process_all_messages should succeed with empty message batch");

    let after_context =
        group_context(&receiver_provider, group_id).expect("should get receiver context");
    let after_epoch = after_context.epoch().as_u64() as i64;

    assert_eq!(
        result.group_results.len(),
        1,
        "should have one group result"
    );
    assert!(
        result.group_results[0].error.is_none(),
        "empty batch should not create error"
    );
    assert_eq!(
        after_epoch, before_epoch,
        "receiver epoch should not change for empty batch"
    );

    drop(group_status_conn);
    drop(receiver_provider);
    drop(sender_provider);
    cleanup_db(&status_db);
    cleanup_db(&receiver_db);
    cleanup_db(&sender_db);
}
