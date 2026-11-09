//! A device that leaves deletes its local group, but its leaf stays in the tree
//! until someone commits the removal. Rejoining (external join) and being added
//! again must replace that leaf instead of failing or leaving a duplicate.

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use openmls::group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig};
use uq_openmls::{
    core::{
        DEFAULT_CIPHERSUITE, add_members, create_group, delete_group, encrypt_message,
        export_group_info, generate_key_package, group, group_signer, join_by_external_commit,
        leave_group, merge_pending_commit, process_application_message, process_operation_message,
        process_welcome,
    },
    error::Error,
    provider::SqliteProvider,
};

const GROUP_ID: &str = "rejoin-group";
const ALICE: &str = "alice@example/alice-device";
const BOB: &str = "bob@example/bob-device";
const CHARLIE: &str = "charlie@example/charlie-device";

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Client {
    path: PathBuf,
    provider: SqliteProvider,
}

impl Client {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "uq-openmls-rejoin-{}-{counter}-{nanos}.sqlite",
            std::process::id(),
        ));
        let provider =
            SqliteProvider::new(path.to_str().expect("utf-8 path"), &None).expect("provider");
        Self { path, provider }
    }

    fn group(&self) -> MlsGroup {
        group(&self.provider, GROUP_ID, []).expect("group should exist")
    }

    fn key_package(&self, identity: &str) -> Vec<u8> {
        generate_key_package(identity, &self.provider, DEFAULT_CIPHERSUITE, false, None)
            .expect("key package")
    }

    fn leave_and_delete(&self) {
        let mut mls_group = self.group();
        let signer = group_signer(&mls_group, &self.provider).expect("signer");
        leave_group(&mut mls_group, &self.provider, &signer).expect("leave");
        delete_group(&mut mls_group, &self.provider).expect("delete local group");
    }

    fn process_commit(&self, commit: &[u8]) {
        let mut mls_group = self.group();
        process_operation_message(&mut mls_group, &self.provider, commit).expect("process commit");
    }

    fn send(&self, text: &[u8]) -> Vec<u8> {
        let mut mls_group = self.group();
        let signer = group_signer(&mls_group, &self.provider).expect("signer");
        encrypt_message(&mut mls_group, &self.provider, &signer, text).expect("encrypt")
    }

    fn read(&self, message: &[u8]) -> Vec<u8> {
        let mut mls_group = self.group();
        process_application_message(&mut mls_group, &self.provider, message)
            .expect("decrypt")
            .message
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(16)
        .build()
}

fn identities(mls_group: &MlsGroup) -> Vec<String> {
    let mut identities: Vec<String> = mls_group
        .members()
        .map(|member| String::from_utf8_lossy(member.credential.serialized_content()).into_owned())
        .collect();
    identities.sort();
    identities
}

/// Alice owns a group with Bob and Charlie.
fn three_member_group() -> (Client, Client, Client) {
    let (alice, bob, charlie) = (Client::new(), Client::new(), Client::new());
    let create_config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .ciphersuite(DEFAULT_CIPHERSUITE)
        .build();
    let mut alice_group = create_group(
        &alice.provider,
        ALICE,
        GROUP_ID,
        DEFAULT_CIPHERSUITE,
        &create_config,
        None,
    )
    .expect("create group");
    let signer = group_signer(&alice_group, &alice.provider).expect("signer");
    let added = add_members(
        &mut alice_group,
        &alice.provider,
        &signer,
        &[bob.key_package(BOB), charlie.key_package(CHARLIE)],
    )
    .expect("add bob and charlie");
    merge_pending_commit(&mut alice_group, &alice.provider).expect("merge");
    process_welcome(&bob.provider, &added.welcome, &join_config()).expect("bob welcome");
    process_welcome(&charlie.provider, &added.welcome, &join_config()).expect("charlie welcome");
    (alice, bob, charlie)
}

fn group_info(owner: &Client) -> Vec<u8> {
    let mls_group = owner.group();
    let signer = group_signer(&mls_group, &owner.provider).expect("signer");
    export_group_info(&mls_group, &owner.provider, &signer).expect("group info")
}

#[test]
fn external_join_replaces_leaf_left_behind_by_leave() {
    let (alice, bob, charlie) = three_member_group();
    charlie.leave_and_delete();

    let joined = join_by_external_commit(
        &charlie.provider,
        CHARLIE,
        &group_info(&alice),
        DEFAULT_CIPHERSUITE,
        &join_config(),
        None,
    )
    .expect("rejoin should replace the stale leaf");
    merge_pending_commit(&mut charlie.group(), &charlie.provider).expect("merge join");
    alice.process_commit(&joined.commit);
    bob.process_commit(&joined.commit);

    assert_eq!(identities(&alice.group()), vec![ALICE, BOB, CHARLIE]);
    assert_eq!(identities(&bob.group()), vec![ALICE, BOB, CHARLIE]);
    assert_eq!(bob.read(&charlie.send(b"back again")), b"back again");
    assert_eq!(charlie.read(&alice.send(b"welcome back")), b"welcome back");
}

#[test]
fn external_join_is_refused_while_local_group_exists() {
    let (alice, _bob, charlie) = three_member_group();

    let result = join_by_external_commit(
        &charlie.provider,
        CHARLIE,
        &group_info(&alice),
        DEFAULT_CIPHERSUITE,
        &join_config(),
        None,
    );

    assert!(matches!(result, Err(Error::CredentialIsExisted)));
    assert_eq!(identities(&charlie.group()), vec![ALICE, BOB, CHARLIE]);
}

#[test]
fn external_join_without_the_stale_leaf_key_joins_with_a_new_key() {
    let (alice, bob, charlie) = three_member_group();
    charlie.leave_and_delete();
    // Same identity, but the local MLS storage was lost with the old private key.
    let restored = Client::new();

    let joined = join_by_external_commit(
        &restored.provider,
        CHARLIE,
        &group_info(&alice),
        DEFAULT_CIPHERSUITE,
        &join_config(),
        None,
    )
    .expect("join should not be blocked by a leaf whose key is gone");
    merge_pending_commit(&mut restored.group(), &restored.provider).expect("merge join");
    alice.process_commit(&joined.commit);
    bob.process_commit(&joined.commit);

    // The stale leaf cannot be removed without its key, so it stays next to the new one.
    assert_eq!(
        identities(&alice.group()),
        vec![ALICE, BOB, CHARLIE, CHARLIE]
    );
    assert_eq!(bob.read(&restored.send(b"restored")), b"restored");
    assert_eq!(restored.read(&alice.send(b"welcome")), b"welcome");
}

fn add_bob_again_with_dave(alice: &Client, bob: &Client, dave: &Client) -> (Vec<u8>, Vec<u8>) {
    let mut alice_group = alice.group();
    let signer = group_signer(&alice_group, &alice.provider).expect("signer");
    let added = add_members(
        &mut alice_group,
        &alice.provider,
        &signer,
        &[
            bob.key_package(BOB),
            dave.key_package("dave@example/dave-device"),
        ],
    )
    .expect("adding an identity that is already in the tree should replace its leaf");
    merge_pending_commit(&mut alice_group, &alice.provider).expect("merge");
    (added.commit, added.welcome)
}

#[test]
fn add_replaces_leaf_of_device_that_left() {
    let (alice, bob, charlie) = three_member_group();
    let dave = Client::new();
    bob.leave_and_delete();

    let (commit, welcome) = add_bob_again_with_dave(&alice, &bob, &dave);
    charlie.process_commit(&commit);
    process_welcome(&bob.provider, &welcome, &join_config()).expect("bob welcome");
    process_welcome(&dave.provider, &welcome, &join_config()).expect("dave welcome");

    let expected = vec![ALICE, BOB, CHARLIE, "dave@example/dave-device"];
    assert_eq!(identities(&alice.group()), expected);
    assert_eq!(identities(&charlie.group()), expected);
    assert_eq!(alice.read(&bob.send(b"hello again")), b"hello again");
}

#[test]
fn add_replaces_leaf_of_active_device_which_recovers_through_welcome() {
    let (alice, bob, charlie) = three_member_group();
    let dave = Client::new();

    let (commit, welcome) = add_bob_again_with_dave(&alice, &bob, &dave);
    charlie.process_commit(&commit);
    bob.process_commit(&commit);
    process_welcome(&bob.provider, &welcome, &join_config()).expect("bob replaces his group");

    assert_eq!(
        identities(&bob.group()),
        vec![ALICE, BOB, CHARLIE, "dave@example/dave-device"]
    );
    assert_eq!(charlie.read(&bob.send(b"still here")), b"still here");
}

#[test]
fn add_of_own_identity_is_still_refused() {
    let (alice, _bob, _charlie) = three_member_group();
    let other_alice_install = Client::new();
    let mut alice_group = alice.group();
    let signer = group_signer(&alice_group, &alice.provider).expect("signer");

    let result = add_members(
        &mut alice_group,
        &alice.provider,
        &signer,
        &[other_alice_install.key_package(ALICE)],
    );

    assert!(matches!(
        result,
        Err(Error::SomeMembersAlreadyExistedInGroup)
    ));
}
