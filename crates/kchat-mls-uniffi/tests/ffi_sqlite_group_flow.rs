use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use mls_mobile_sdk_rs::mls::{AddMembersResult, RemoveMembersResult, UpdateLeafNodeResult, UqMls};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

const MAX_PAST_EPOCHS: u16 = 10;
const OUT_OF_ORDER_TOLERANCE: u32 = 5;
const MAXIMUM_FORWARD_DISTANCE: u32 = 10;

#[derive(Clone)]
struct TestClientConfig {
    client_id: String,
    storage_path: String,
    group_storage_path: String,
}

struct TestClient {
    config: TestClientConfig,
    api: UqMls,
}

impl TestClient {
    fn new(test_name: &str, client_id: &str) -> Self {
        let unique = unique_name(test_name, client_id);
        let config = TestClientConfig {
            client_id: client_id.to_owned(),
            storage_path: db_path(&format!("{unique}-mls")),
            group_storage_path: db_path(&format!("{unique}-group-status")),
        };

        let api = UqMls::new(
            config.client_id.clone(),
            config.storage_path.clone(),
            config.group_storage_path.clone(),
            MAX_PAST_EPOCHS,
            None,
            OUT_OF_ORDER_TOLERANCE,
            MAXIMUM_FORWARD_DISTANCE,
            None,
        )
        .expect("should create sqlite-backed UqMls");

        Self { config, api }
    }

    fn reopen(&self) -> Self {
        let api = UqMls::new(
            self.config.client_id.clone(),
            self.config.storage_path.clone(),
            self.config.group_storage_path.clone(),
            MAX_PAST_EPOCHS,
            None,
            OUT_OF_ORDER_TOLERANCE,
            MAXIMUM_FORWARD_DISTANCE,
            None,
        )
        .expect("should reopen sqlite-backed UqMls");

        Self {
            config: self.config.clone(),
            api,
        }
    }
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

fn sorted_members(client: &TestClient, group_id: &str) -> Vec<String> {
    let mut members = client
        .api
        .members(group_id)
        .expect("should load members from sqlite-backed FFI surface");
    members.sort();
    members
}

fn assert_group_sync(
    left: &TestClient,
    right: &TestClient,
    group_id: &str,
    expected_members: &[&str],
) {
    let left_epoch = left
        .api
        .group_epoch(group_id)
        .expect("left group_epoch should succeed");
    let right_epoch = right
        .api
        .group_epoch(group_id)
        .expect("right group_epoch should succeed");

    assert_eq!(left_epoch.err, None, "left group should be loadable");
    assert_eq!(right_epoch.err, None, "right group should be loadable");
    assert_eq!(left_epoch.epoch, right_epoch.epoch, "epochs must match");
    assert_eq!(
        left_epoch.tree_hash, right_epoch.tree_hash,
        "tree_hash must match for synchronized groups"
    );

    let mut expected_members = expected_members
        .iter()
        .map(|member| member.to_string())
        .collect::<Vec<_>>();
    expected_members.sort();

    assert_eq!(sorted_members(left, group_id), expected_members);
    assert_eq!(sorted_members(right, group_id), expected_members);
}

fn generate_one_key_package(client: &TestClient) -> Vec<u8> {
    client
        .api
        .generate_key_packages(1, false, None)
        .expect("should generate one key package")
        .key_packages
        .into_iter()
        .next()
        .expect("should return one key package")
}

fn create_two_member_group(
    test_name: &str,
    group_id: &str,
) -> (TestClient, TestClient, AddMembersResult) {
    let alice = TestClient::new(test_name, "alice");
    let bob = TestClient::new(test_name, "bob");

    let bob_key_package = generate_one_key_package(&bob);

    alice
        .api
        .create_group(group_id, None)
        .expect("alice should create group");

    let add_members_result = alice
        .api
        .add_members(group_id, &[bob_key_package])
        .expect("alice should add bob");

    alice
        .api
        .merge_pending_commit(group_id)
        .expect("alice should merge pending commit");

    bob.api
        .process_welcome(&add_members_result.welcome)
        .expect("bob should process welcome");

    assert_group_sync(&alice, &bob, group_id, &["alice", "bob"]);

    (alice, bob, add_members_result)
}

fn create_three_member_group(
    test_name: &str,
    group_id: &str,
) -> (TestClient, TestClient, TestClient, AddMembersResult) {
    let (alice, bob, _) = create_two_member_group(test_name, group_id);
    let charlie = TestClient::new(test_name, "charlie");
    let charlie_key_package = generate_one_key_package(&charlie);

    let add_members_result = alice
        .api
        .add_members(group_id, &[charlie_key_package])
        .expect("alice should add charlie");

    alice
        .api
        .merge_pending_commit(group_id)
        .expect("alice should merge pending commit for charlie");
    bob.api
        .process_operation_message(group_id, &add_members_result.commit)
        .expect("bob should process add-charlie commit");
    charlie
        .api
        .process_welcome(&add_members_result.welcome)
        .expect("charlie should process welcome");

    assert_group_sync(&alice, &bob, group_id, &["alice", "bob", "charlie"]);
    assert_group_sync(&alice, &charlie, group_id, &["alice", "bob", "charlie"]);

    (alice, bob, charlie, add_members_result)
}

#[test]
fn create_group_and_add_member_round_trip() {
    let group_id = "group-create-add";
    let (alice, bob, _) =
        create_two_member_group("create_group_and_add_member_round_trip", group_id);

    let alice_reopened = alice.reopen();
    let bob_reopened = bob.reopen();

    assert_group_sync(&alice_reopened, &bob_reopened, group_id, &["alice", "bob"]);
}

#[test]
fn commit_processed_by_other_member_keeps_state_consistent() {
    let group_id = "group-process-commit";
    let (alice, bob, charlie, _) = create_three_member_group(
        "commit_processed_by_other_member_keeps_state_consistent",
        group_id,
    );

    assert_group_sync(&alice, &bob, group_id, &["alice", "bob", "charlie"]);
    assert_group_sync(&alice, &charlie, group_id, &["alice", "bob", "charlie"]);
}

#[test]
fn remove_member_round_trip() {
    let group_id = "group-remove-member";
    let (alice, bob, _charlie, _) = create_three_member_group("remove_member_round_trip", group_id);

    let RemoveMembersResult { commit, .. } = alice
        .api
        .remove_members(group_id, &[String::from("charlie")])
        .expect("alice should remove charlie");

    alice
        .api
        .merge_pending_commit(group_id)
        .expect("alice should merge remove-members commit");
    bob.api
        .process_operation_message(group_id, &commit)
        .expect("bob should process remove-members commit");

    assert_group_sync(&alice, &bob, group_id, &["alice", "bob"]);
}

#[test]
fn update_leaf_node_round_trip() {
    let group_id = "group-update-leaf";
    let (alice, bob, _) = create_two_member_group("update_leaf_node_round_trip", group_id);

    let UpdateLeafNodeResult { commit, .. } = alice
        .api
        .update_leaf_node(group_id)
        .expect("alice should update leaf node");

    alice
        .api
        .merge_pending_commit(group_id)
        .expect("alice should merge update-leaf commit");
    bob.api
        .process_operation_message(group_id, &commit)
        .expect("bob should process update-leaf commit");

    assert_group_sync(&alice, &bob, group_id, &["alice", "bob"]);
}

#[test]
fn failed_operation_does_not_break_follow_up_valid_flow() {
    let group_id = "group-failed-then-valid";
    let (alice, bob, _) = create_two_member_group(
        "failed_operation_does_not_break_follow_up_valid_flow",
        group_id,
    );

    let bob_duplicate_key_package = generate_one_key_package(&bob);
    let duplicate_add_error = match alice
        .api
        .add_members(group_id, &[bob_duplicate_key_package])
    {
        Ok(_) => panic!("adding bob again should fail"),
        Err(err) => err,
    };
    assert!(
        duplicate_add_error
            .to_string()
            .contains("Some members already existed in group"),
        "unexpected duplicate-add error: {duplicate_add_error}"
    );

    let charlie = TestClient::new(
        "failed_operation_does_not_break_follow_up_valid_flow",
        "charlie",
    );
    let charlie_key_package = generate_one_key_package(&charlie);

    let add_charlie_result = alice
        .api
        .add_members(group_id, &[charlie_key_package])
        .expect("subsequent valid add should succeed");

    alice
        .api
        .merge_pending_commit(group_id)
        .expect("alice should merge add-charlie commit");
    bob.api
        .process_operation_message(group_id, &add_charlie_result.commit)
        .expect("bob should process add-charlie commit");
    charlie
        .api
        .process_welcome(&add_charlie_result.welcome)
        .expect("charlie should process welcome");

    assert_group_sync(&alice, &bob, group_id, &["alice", "bob", "charlie"]);
    assert_group_sync(&alice, &charlie, group_id, &["alice", "bob", "charlie"]);
}

#[test]
fn delete_group_and_post_delete_behavior() {
    let group_id = "group-delete";
    let (alice, _bob, _) =
        create_two_member_group("delete_group_and_post_delete_behavior", group_id);

    alice
        .api
        .delete_group(group_id)
        .expect("alice should delete group");

    assert!(
        alice.api.members(group_id).is_err(),
        "deleted group should not be accessible from the current FFI object"
    );

    let deleted_epoch = alice
        .api
        .group_epoch(group_id)
        .expect("group_epoch wrapper should still return");
    assert!(
        deleted_epoch.err.is_some(),
        "deleted group should no longer be loadable from sqlite storage"
    );

    let alice_reopened = alice.reopen();
    assert!(
        alice_reopened.api.members(group_id).is_err(),
        "deleted group should remain deleted after reopening the same sqlite-backed client"
    );
    let reopened_epoch = alice_reopened
        .api
        .group_epoch(group_id)
        .expect("group_epoch wrapper should still return after reopen");
    assert!(
        reopened_epoch.err.is_some(),
        "reopened client should also observe the deleted group as missing"
    );
}
