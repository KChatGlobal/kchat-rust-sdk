//! `Server` fakes the server side the host talks to: a per-epoch `key_hash` CAS
//! (`CreateRootKey` / `RotateRootKey`) plus stored links and descriptors. The SDK never calls it.

mod common;

use std::{cell::RefCell, collections::HashMap};

use ciborium::Value;
use kchat_file_crypto::{
    ContentKey, ControlAuthority, ControlOutcome, ControlPeer, ControlRecipient, ControlRequest,
    EncryptedDescriptor, FileCryptoErrorCode, FileKeyring, NodeKeyRef, NodeLink, OpenedBlob,
    RandomPlanReason, RootId, TenantId, open_content, seal_content,
};
use sha2::{Digest, Sha256};

use crate::common::{Field, MemorySource, RecordingSink, TestKeyring, encode, hash, tenant};

const GROUP: &str = "group-1";
const FILE_ID: &str = "file-1";
const FILE_NODE: &str = "file-node-1";

#[derive(Default)]
struct Server {
    /// One value per (root, epoch); the first writer wins.
    root_key_hashes: RefCell<HashMap<(String, u64), [u8; 32]>>,
    /// One link per (file node, generation); the first writer wins.
    links: RefCell<HashMap<(String, u64), NodeLink>>,
    denied: RefCell<Vec<String>>,
    /// Epochs the history policy hides from key-sync requesters.
    hidden_epochs: RefCell<Vec<u64>>,
}

impl Server {
    /// CAS like KFiles: new roots start at epoch 0 and rotation must be exactly current + 1.
    fn rotate_group_key(&self, root: &RootId, epoch: u64, key_hash: &[u8; 32]) -> bool {
        let mut hashes = self.root_key_hashes.borrow_mut();
        let expected = hashes
            .keys()
            .filter(|(node, _)| node == root.node_id())
            .map(|(_, epoch)| *epoch)
            .max()
            .map_or(0, |latest| latest + 1);
        if epoch != expected {
            return false;
        }
        hashes.insert((root.node_id().to_owned(), epoch), *key_hash);
        true
    }

    fn put_link(&self, link: &NodeLink) -> bool {
        let key = (link.file_node_id().to_owned(), link.file_generation());
        let mut links = self.links.borrow_mut();
        if links.contains_key(&key) {
            return false;
        }
        links.insert(key, link.clone());
        true
    }

    fn link(&self, file_node: &str, generation: u64) -> NodeLink {
        let links = self.links.borrow();
        let link = &links[&(file_node.to_owned(), generation)];
        NodeLink::from_parts(
            link.root(),
            link.epoch(),
            link.file_node_id(),
            link.file_generation(),
            link.key_hash().map(|hash| hash.as_slice()),
            link.ciphertext(),
        )
        .unwrap()
    }
}

impl ControlAuthority for Server {
    fn allow(&self, sender: &ControlPeer, request: &ControlRequest<'_>) -> bool {
        if let ControlRequest::KeySyncRequest { epoch, .. } = request
            && self.hidden_epochs.borrow().contains(epoch)
        {
            return false;
        }
        !self
            .denied
            .borrow()
            .iter()
            .any(|account| account == sender.account_id())
    }

    fn published_pepper_commitment(&self, _: &TenantId, _: u64) -> Option<[u8; 32]> {
        None
    }

    fn published_root_key_hash(&self, root: &RootId, epoch: u64) -> Option<[u8; 32]> {
        self.root_key_hashes
            .borrow()
            .get(&(root.node_id().to_owned(), epoch))
            .copied()
    }
}

fn group() -> RootId {
    RootId::group(&tenant(), GROUP).unwrap()
}

fn device(account: &str) -> TestKeyring {
    TestKeyring::with_account(None, account)
}

fn peer(account: &str) -> ControlPeer {
    ControlPeer::new(account, &format!("{account}-device")).unwrap()
}

fn rotate(server: &Server, keyring: &FileKeyring, root: &RootId) -> u64 {
    let proposal = keyring.propose_root_key(root).unwrap();
    assert!(server.rotate_group_key(root, proposal.epoch(), proposal.key_hash()));
    keyring.activate_node_key(proposal.key()).unwrap();
    proposal.epoch()
}

fn send_bundle(
    server: &Server,
    from: (&str, &FileKeyring),
    to: (&str, &FileKeyring),
    root: &RootId,
) {
    let message = from
        .1
        .build_root_key_bundle(root, &ControlRecipient::account(to.0).unwrap())
        .unwrap();
    to.1.process_control(
        &peer(from.0),
        &format!("{}-device", to.0),
        message.as_bytes(),
        server,
    )
    .unwrap();
}

fn new_file_key(
    server: &Server,
    keyring: &FileKeyring,
    root: &RootId,
    file_node: &str,
) -> NodeKeyRef {
    let created = keyring.create_file_key(root, file_node).unwrap();
    assert!(server.put_link(created.link()));
    keyring.activate_node_key(&created.file_key()).unwrap();
    created.file_key()
}

fn upload_blob(keyring: &FileKeyring, plaintext: &[u8]) -> (ContentKey, Vec<u8>) {
    let plan = keyring
        .plan_random(&hash(plaintext), RandomPlanReason::NoTenant)
        .unwrap();
    let mut sink = RecordingSink::default();
    let sealed = seal_content(&plan, &mut MemorySource::new(plaintext), &mut sink).unwrap();
    (ContentKey::from_sealed(&plan, &sealed).unwrap(), sink.bytes)
}

fn seal(
    keyring: &FileKeyring,
    file_key: &NodeKeyRef,
    blob_id: &str,
    object_id: &str,
    key: &ContentKey,
) -> Result<EncryptedDescriptor, FileCryptoErrorCode> {
    keyring
        .seal_descriptor(file_key, FILE_ID, blob_id, object_id, key, None)
        .map_err(|error| error.code())
}

fn from_server(sealed: &EncryptedDescriptor) -> EncryptedDescriptor {
    EncryptedDescriptor::from_parts(
        sealed.profile_id(),
        sealed.file_node_id(),
        sealed.file_generation(),
        sealed.ciphertext(),
    )
    .unwrap()
}

fn open_blob(
    keyring: &FileKeyring,
    sealed: &EncryptedDescriptor,
) -> Result<OpenedBlob, FileCryptoErrorCode> {
    keyring
        .open_descriptor(&tenant(), FILE_ID, &from_server(sealed))
        .map_err(|error| error.code())
}

fn read_blob(blob: &OpenedBlob, ciphertext: &[u8]) -> Vec<u8> {
    let mut sink = RecordingSink::default();
    open_content(
        blob.content_key(),
        &mut MemorySource::new(ciphertext),
        &mut sink,
    )
    .unwrap();
    assert!(sink.committed);
    sink.bytes
}

#[test]
fn group_key_starts_at_epoch_zero_and_rotates_by_one() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    assert_eq!(alice.root_epoch(&root).unwrap(), None);

    let first = alice.propose_root_key(&root).unwrap();
    assert_eq!(first.epoch(), 0);
    assert_eq!(alice.propose_root_key(&root).unwrap(), first);
    assert_eq!(alice.root_epoch(&root).unwrap(), None);
    assert!(server.rotate_group_key(&root, first.epoch(), first.key_hash()));
    alice.activate_node_key(first.key()).unwrap();
    assert_eq!(alice.root_epoch(&root).unwrap(), Some(0));

    assert_eq!(rotate(&server, &alice, &root), 1);
    assert_eq!(rotate(&server, &alice, &root), 2);
    assert_eq!(alice.root_epoch(&root).unwrap(), Some(2));
}

#[test]
fn control_message_follows_the_documented_layout_and_key_hash() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    rotate(&server, &alice, &root);

    let message = alice
        .build_root_key_bundle(&root, &ControlRecipient::account("bob").unwrap())
        .unwrap();
    assert_eq!(&message.as_bytes()[..5], b"KSTC\x01");
    let top: Value = ciborium::from_reader(&message.as_bytes()[5..]).unwrap();
    let top = top.as_map().unwrap();
    assert_eq!(get(top, "type").as_text(), Some("NodeKeyDistribution"));
    let body = get(top, "body").as_map().unwrap();
    assert_eq!(get(body, "node").as_text(), Some(GROUP));
    assert_eq!(get(body, "kind"), &Value::Integer(2.into()));
    let keys = get(body, "keys").as_array().unwrap();
    assert_eq!(keys.len(), 2);

    // key_hash = HMAC-SHA256(key, encode("kchat-storage/node-key-commit/v1", tenant, node, gen)),
    // recomputed independently; it matches what the server stored at CAS time.
    for (index, entry) in keys.iter().enumerate() {
        let entry = entry.as_map().unwrap();
        let epoch = index as u64;
        assert_eq!(get(entry, "generation"), &Value::Integer(epoch.into()));
        let key: [u8; 32] = get(entry, "key")
            .as_bytes()
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let message = encode(
            "kchat-storage/node-key-commit/v1",
            &[
                Field::Bytes(common::TENANT.as_bytes()),
                Field::Bytes(GROUP.as_bytes()),
                Field::U64(epoch),
            ],
        );
        let expected = hmac_sha256(&key, &message);
        assert_eq!(
            get(entry, "key_hash").as_bytes().unwrap(),
            &expected.to_vec()
        );
        assert_eq!(server.published_root_key_hash(&root, epoch), Some(expected));
    }
}

#[test]
fn upload_then_read_on_a_new_members_device() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let root = group();
    rotate(&server, &alice, &root);

    let alice_key = new_file_key(&server, &alice, &root, FILE_NODE);
    assert_eq!(alice_key.generation(), 0);
    let plaintext = b"hop dong so 1".to_vec();
    let (content_key, ciphertext) = upload_blob(&alice, &plaintext);
    let sealed = seal(&alice, &alice_key, "blob-1", "obj-1", &content_key).unwrap();
    assert_eq!(sealed.file_generation(), 0);

    let link = server.link(FILE_NODE, 0);
    assert_eq!(
        bob.open_file_key(&link).unwrap_err().code(),
        FileCryptoErrorCode::KeySyncRequired
    );
    assert_eq!(
        open_blob(&bob, &sealed).unwrap_err(),
        FileCryptoErrorCode::KeySyncRequired
    );

    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);
    assert_eq!(bob.open_file_key(&link).unwrap(), alice_key);
    let blob = open_blob(&bob, &sealed).unwrap();
    assert_eq!(blob.object_id(), "obj-1");
    assert_eq!(read_blob(&blob, &ciphertext), plaintext);
}

#[test]
fn rotation_keeps_old_files_readable_and_new_files_out_of_reach() {
    let server = Server::default();
    let (alice, bob, carol) = (device("alice"), device("bob"), device("carol"));
    let root = group();
    rotate(&server, &alice, &root);
    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);

    let key_1 = new_file_key(&server, &alice, &root, FILE_NODE);
    let (base_key, base) = upload_blob(&alice, b"base");
    let blob_1 = seal(&alice, &key_1, "blob-1", "base", &base_key).unwrap();

    // Bob leaves the group: rotate to epoch 1 without him.
    assert_eq!(rotate(&server, &alice, &root), 1);

    // Writing with the old epoch's File NodeKey is blocked (rotate-on-write).
    let (delta_key, delta) = upload_blob(&alice, b"delta");
    assert_eq!(
        seal(&alice, &key_1, "blob-2", "delta", &delta_key).unwrap_err(),
        FileCryptoErrorCode::PolicyViolation
    );

    let key_2 = new_file_key(&server, &alice, &root, FILE_NODE);
    assert_eq!(key_2.generation(), 1);
    let blob_2 = seal(&alice, &key_2, "blob-2", "delta", &delta_key).unwrap();
    assert_eq!(blob_2.file_generation(), 1);

    // Bob still reads blob 1 but cannot open the epoch 1 path.
    bob.open_file_key(&server.link(FILE_NODE, 0)).unwrap();
    let bob_blob_1 = open_blob(&bob, &blob_1).unwrap();
    assert_eq!(read_blob(&bob_blob_1, &base), b"base");
    assert_eq!(
        bob.open_file_key(&server.link(FILE_NODE, 1))
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::KeySyncRequired
    );
    assert_eq!(
        open_blob(&bob, &blob_2).unwrap_err(),
        FileCryptoErrorCode::KeySyncRequired
    );

    // Carol joins later: the bundle carries both epochs, so she reads both blobs.
    send_bundle(&server, ("alice", &alice), ("carol", &carol), &root);
    assert_eq!(carol.root_epoch(&root).unwrap(), Some(1));
    carol.open_file_key(&server.link(FILE_NODE, 0)).unwrap();
    carol.open_file_key(&server.link(FILE_NODE, 1)).unwrap();
    let carol_blob_1 = open_blob(&carol, &blob_1).unwrap();
    let carol_blob_2 = open_blob(&carol, &blob_2).unwrap();
    assert_eq!(carol_blob_2.object_id(), "delta");
    assert_eq!(read_blob(&carol_blob_1, &base), b"base");
    assert_eq!(read_blob(&carol_blob_2, &delta), b"delta");
}

#[test]
fn file_key_epochs_count_like_kfiles_not_like_the_root() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    rotate(&server, &alice, &root);
    assert_eq!(rotate(&server, &alice, &root), 2);

    let created = alice.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(
        (created.link().epoch(), created.link().file_generation()),
        (2, 0)
    );
    let retried = alice.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(retried.file_key(), created.file_key());
    assert_eq!(retried.link().key_hash(), created.link().key_hash());
    assert!(server.put_link(created.link()));
    alice.activate_node_key(&created.file_key()).unwrap();
    let same = alice.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(same.file_key(), created.file_key());
    let (content_key, _) = upload_blob(&alice, b"v1");
    seal(&alice, &created.file_key(), "blob-1", "obj-1", &content_key).unwrap();

    // The root jumps 2 -> 4 before the next write: ROTATE bumps the file epoch by just 1.
    rotate(&server, &alice, &root);
    assert_eq!(rotate(&server, &alice, &root), 4);
    let (content_key, _) = upload_blob(&alice, b"v2");
    assert_eq!(
        seal(&alice, &created.file_key(), "blob-2", "obj-2", &content_key).unwrap_err(),
        FileCryptoErrorCode::PolicyViolation
    );
    let stale = alice.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(
        (stale.link().epoch(), stale.link().file_generation()),
        (4, 1)
    );

    // The root rotates again before commit: the stale pending key is replaced at the same file epoch.
    assert_eq!(rotate(&server, &alice, &root), 5);
    let rotated = alice.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(
        (rotated.link().epoch(), rotated.link().file_generation()),
        (5, 1)
    );
    assert_ne!(rotated.link().key_hash(), stale.link().key_hash());
    assert!(server.put_link(rotated.link()));
    alice.activate_node_key(&rotated.file_key()).unwrap();
    let blob_2 = seal(&alice, &rotated.file_key(), "blob-2", "obj-2", &content_key).unwrap();
    assert_eq!(blob_2.file_generation(), 1);
}

#[test]
fn a_link_without_key_hash_opens_and_still_detects_conflicts() {
    let server = Server::default();
    let (alice, bob, carol) = (device("alice"), device("bob"), device("carol"));
    let root = group();
    rotate(&server, &alice, &root);
    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);
    send_bundle(&server, ("alice", &alice), ("carol", &carol), &root);
    let key = new_file_key(&server, &alice, &root, FILE_NODE);
    let (content_key, ciphertext) = upload_blob(&alice, b"no key hash");
    let sealed = seal(&alice, &key, "blob-1", "obj-1", &content_key).unwrap();

    // No key_hash, as in the KFiles `EncryptedFileKey` response.
    let without_hash = |link: &NodeLink| {
        NodeLink::from_parts(
            link.root(),
            link.epoch(),
            link.file_node_id(),
            link.file_generation(),
            None,
            link.ciphertext(),
        )
        .unwrap()
    };
    let link = without_hash(&server.link(FILE_NODE, 0));
    assert_eq!(link.key_hash(), None);
    assert_eq!(bob.open_file_key(&link).unwrap(), key);
    bob.open_file_key(&link).unwrap();
    let blob = open_blob(&bob, &sealed).unwrap();
    assert_eq!(read_blob(&blob, &ciphertext), b"no key hash");

    // Carol (who also holds the root key) wraps a different key for the same file epoch: AEAD passes,
    // but Bob already has that epoch, so `KeyConflict` keeps the old key.
    let forged = carol.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(forged.file_key(), key);
    assert_eq!(
        bob.open_file_key(&without_hash(forged.link()))
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::KeyConflict
    );
    assert_eq!(
        read_blob(&open_blob(&bob, &sealed).unwrap(), &ciphertext),
        b"no key hash"
    );

    let other = server.link(FILE_NODE, 0);
    let wrong_hash = NodeLink::from_parts(
        other.root(),
        other.epoch(),
        other.file_node_id(),
        other.file_generation(),
        Some(&[0; 32]),
        other.ciphertext(),
    )
    .unwrap();
    assert_eq!(
        carol.open_file_key(&wrong_hash).unwrap_err().code(),
        FileCryptoErrorCode::KeyEnvelopeInvalid
    );
}

#[test]
fn a_device_opens_the_current_file_key_before_rotating_it() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let root = group();
    rotate(&server, &alice, &root);
    new_file_key(&server, &alice, &root, FILE_NODE);
    assert_eq!(rotate(&server, &alice, &root), 1);
    assert_eq!(
        new_file_key(&server, &alice, &root, FILE_NODE).generation(),
        1
    );

    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);
    assert_eq!(rotate(&server, &bob, &root), 2);

    // Bob opens the server's current file key first (`current_file_key`), then rotates to epoch 2.
    bob.open_file_key(&server.link(FILE_NODE, 1)).unwrap();
    let rotated = bob.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(
        (rotated.link().epoch(), rotated.link().file_generation()),
        (2, 2)
    );
    assert!(server.put_link(rotated.link()));
}

#[test]
fn losing_the_rotate_cas_adopts_the_winners_key() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let root = group();
    rotate(&server, &alice, &root);
    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);

    // Two devices rotate to epoch 1; Alice wins the CAS.
    let alice_proposal = alice.propose_root_key(&root).unwrap();
    let bob_proposal = bob.propose_root_key(&root).unwrap();
    assert_eq!((alice_proposal.epoch(), bob_proposal.epoch()), (1, 1));
    assert_ne!(alice_proposal.key_hash(), bob_proposal.key_hash());
    assert!(server.rotate_group_key(&root, 1, alice_proposal.key_hash()));
    assert!(!server.rotate_group_key(&root, 1, bob_proposal.key_hash()));
    alice.activate_node_key(alice_proposal.key()).unwrap();

    // Alice's key reaches Bob before he discards: the winner's key replaces his pending proposal.
    let message = alice.build_root_key_distribution(&root, 1, None).unwrap();
    let outcome = bob
        .process_control(&peer("alice"), "bob-device", message.as_bytes(), &server)
        .unwrap();
    assert_eq!(
        outcome,
        ControlOutcome::RootKeysImported {
            root: root.clone(),
            epochs: vec![1],
        }
    );
    assert_eq!(bob.root_epoch(&root).unwrap(), Some(1));
    // The later discard leaves the winner's (now active) key alone; the next proposal is epoch 2.
    bob.discard_node_key(bob_proposal.key()).unwrap();
    assert_eq!(bob.root_epoch(&root).unwrap(), Some(1));
    assert_eq!(bob.propose_root_key(&root).unwrap().epoch(), 2);
}

#[test]
fn discard_only_removes_pending_keys() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    let proposal = alice.propose_root_key(&root).unwrap();
    alice.discard_node_key(proposal.key()).unwrap();
    assert_eq!(alice.root_epoch(&root).unwrap(), None);
    alice.discard_node_key(proposal.key()).unwrap();
    assert_eq!(
        alice.activate_node_key(proposal.key()).unwrap_err().code(),
        FileCryptoErrorCode::InvalidArgument
    );

    rotate(&server, &alice, &root);
    let active = NodeKeyRef::new(&tenant(), GROUP, 0).unwrap();
    alice.discard_node_key(&active).unwrap();
    assert_eq!(alice.root_epoch(&root).unwrap(), Some(0));
    let pending = alice.propose_root_key(&root).unwrap();
    assert_eq!(
        alice
            .build_root_key_distribution(&root, pending.epoch(), None)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::PolicyViolation
    );
}

#[test]
fn received_root_keys_are_checked_against_the_server() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let root = group();
    rotate(&server, &alice, &root);
    let to_bob = ControlRecipient::account("bob").unwrap();
    let process = |message: &[u8], authority: &Server| {
        bob.process_control(&peer("alice"), "bob-device", message, authority)
            .map_err(|error| error.code())
    };

    let message = alice.build_root_key_bundle(&root, &to_bob).unwrap();
    assert_eq!(
        process(message.as_bytes(), &Server::default()),
        Err(FileCryptoErrorCode::KeyConfigRequired)
    );
    let other = Server::default();
    other
        .root_key_hashes
        .borrow_mut()
        .insert((GROUP.to_owned(), 0), [9; 32]);
    assert_eq!(
        process(message.as_bytes(), &other),
        Err(FileCryptoErrorCode::KeyConflict)
    );
    server.denied.borrow_mut().push("alice".to_owned());
    assert_eq!(
        process(message.as_bytes(), &server),
        Err(FileCryptoErrorCode::UnauthorizedSender)
    );
    server.denied.borrow_mut().clear();
    assert_eq!(bob.root_epoch(&root).unwrap(), None);

    let to_carol = alice
        .build_root_key_bundle(&root, &ControlRecipient::account("carol").unwrap())
        .unwrap();
    assert_eq!(
        process(to_carol.as_bytes(), &server),
        Err(FileCryptoErrorCode::WrongRecipient)
    );

    assert!(matches!(
        process(message.as_bytes(), &server),
        Ok(ControlOutcome::RootKeysImported { .. })
    ));
    assert_eq!(
        process(message.as_bytes(), &server),
        Ok(ControlOutcome::AlreadyProcessed)
    );
    assert_eq!(bob.root_epoch(&root).unwrap(), Some(0));
}

#[test]
fn personal_root_stays_with_its_own_account() {
    let server = Server::default();
    let alice_phone = device("alice");
    let alice_laptop = device("alice");
    let bob = device("bob");
    let personal = RootId::personal(&tenant(), "personal-alice").unwrap();
    rotate(&server, &alice_phone, &personal);

    for recipient in [None, Some(ControlRecipient::account("bob").unwrap())] {
        assert_eq!(
            alice_phone
                .build_root_key_distribution(&personal, 0, recipient.as_ref())
                .unwrap_err()
                .code(),
            FileCryptoErrorCode::PolicyViolation
        );
    }

    let to_alice = ControlRecipient::device("alice", "alice-laptop").unwrap();
    let message = alice_phone
        .build_root_key_distribution(&personal, 0, Some(&to_alice))
        .unwrap();
    alice_laptop
        .process_control(&peer("alice"), "alice-laptop", message.as_bytes(), &server)
        .unwrap();
    let draft_key = new_file_key(&server, &alice_phone, &personal, "draft-node");
    let (content_key, ciphertext) = upload_blob(&alice_phone, b"draft");
    let sealed = seal(
        &alice_phone,
        &draft_key,
        "draft-blob",
        "obj-1",
        &content_key,
    )
    .unwrap();
    alice_laptop
        .open_file_key(&server.link("draft-node", 0))
        .unwrap();
    let blob = open_blob(&alice_laptop, &sealed).unwrap();
    assert_eq!(read_blob(&blob, &ciphertext), b"draft");

    // Personal keys from another account (e.g. forwarded by Bob) are rejected even if the host allows
    // them.
    let relayed = alice_phone
        .build_root_key_distribution(&personal, 0, Some(&to_alice))
        .unwrap();
    assert_eq!(
        alice_laptop
            .process_control(&peer("bob"), "alice-laptop", relayed.as_bytes(), &server)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::UnauthorizedSender
    );
    assert_eq!(
        bob.process_control(&peer("alice"), "bob-device", relayed.as_bytes(), &server)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::WrongRecipient
    );

    let group_root = group();
    rotate(&server, &alice_phone, &group_root);
    assert_eq!(
        alice_phone
            .create_file_key(&group_root, "draft-node")
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::PolicyViolation
    );
}

#[test]
fn records_are_bound_to_their_file_lane_and_epoch() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    let key = new_file_key(&server, &alice, &root, FILE_NODE);
    let (key_a, _) = upload_blob(&alice, b"a");
    let (key_b, _) = upload_blob(&alice, b"b");
    let blob_a = from_server(&seal(&alice, &key, "blob-a", "obj-a", &key_a).unwrap());
    let blob_b = from_server(&seal(&alice, &key, "blob-b", "obj-b", &key_b).unwrap());
    let open = |file_id: &str, descriptor: &EncryptedDescriptor| {
        alice
            .open_descriptor(&tenant(), file_id, descriptor)
            .map(|blob| blob.object_id().to_owned())
            .map_err(|error| error.code())
    };

    assert_eq!(open(FILE_ID, &blob_a), Ok("obj-a".to_owned()));
    assert_eq!(
        open("file-2", &blob_a),
        Err(FileCryptoErrorCode::KeyEnvelopeInvalid)
    );
    // blob_id is not in the AAD (publish assigns it after sealing): another blob's descriptor in the
    // same lane opens, and the object id tells the host which object it is.
    assert_eq!(open(FILE_ID, &blob_b), Ok("obj-b".to_owned()));
    let other_lane = new_file_key(&server, &alice, &root, "file-node-2");
    let moved = EncryptedDescriptor::from_parts(
        blob_a.profile_id(),
        other_lane.node_id(),
        0,
        blob_a.ciphertext(),
    )
    .unwrap();
    assert_eq!(
        open(FILE_ID, &moved),
        Err(FileCryptoErrorCode::KeyEnvelopeInvalid)
    );

    // The link claims the wrong epoch (epoch 1 exists, but the link was wrapped at epoch 0).
    rotate(&server, &alice, &root);
    let link = server.link(FILE_NODE, 0);
    let forged = NodeLink::from_parts(
        link.root(),
        1,
        link.file_node_id(),
        link.file_generation(),
        link.key_hash().map(|hash| hash.as_slice()),
        link.ciphertext(),
    )
    .unwrap();
    assert_eq!(
        alice.open_file_key(&forged).unwrap_err().code(),
        FileCryptoErrorCode::KeyEnvelopeInvalid
    );
    let mut bytes = blob_a.ciphertext().to_vec();
    bytes[30] ^= 1;
    let tampered =
        EncryptedDescriptor::from_parts(blob_a.profile_id(), FILE_NODE, 0, &bytes).unwrap();
    assert_eq!(
        open(FILE_ID, &tampered),
        Err(FileCryptoErrorCode::KeyEnvelopeInvalid)
    );
    // The server stores a wrong file_epoch next to the descriptor: that key exists but the AAD
    // differs.
    let key_1 = new_file_key(&server, &alice, &root, FILE_NODE);
    assert_eq!(key_1.generation(), 1);
    let wrong_epoch =
        EncryptedDescriptor::from_parts(blob_a.profile_id(), FILE_NODE, 1, blob_a.ciphertext())
            .unwrap();
    assert_eq!(
        open(FILE_ID, &wrong_epoch),
        Err(FileCryptoErrorCode::KeyEnvelopeInvalid)
    );
    // V1 descriptors (DK-encrypted, with a separate EncryptedSetKey) and blob envelopes are rejected.
    for format in [
        "kchat-storage/descriptor/v1",
        "kchat-storage/set-envelope/v1",
        "kchat-storage/set-envelope/v2",
    ] {
        assert_eq!(
            EncryptedDescriptor::from_parts(format, FILE_NODE, 0, blob_a.ciphertext())
                .unwrap_err()
                .code(),
            FileCryptoErrorCode::UnsupportedProfile
        );
    }
    assert_eq!(
        EncryptedDescriptor::from_parts(blob_a.profile_id(), FILE_NODE, 0, &[0; 40])
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::InvalidArgument
    );
    assert_eq!(
        EncryptedDescriptor::from_parts(
            blob_a.profile_id(),
            FILE_NODE,
            0,
            &vec![0; (1 << 20) + 41]
        )
        .unwrap_err()
        .code(),
        FileCryptoErrorCode::ResourceLimitExceeded
    );
}

#[test]
fn sealing_is_idempotent_per_blob_and_needs_an_active_file_key() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);

    let created = alice.create_file_key(&root, FILE_NODE).unwrap();
    let (first, _) = upload_blob(&alice, b"one");
    let (second, _) = upload_blob(&alice, b"two");
    assert_eq!(
        seal(&alice, &created.file_key(), "blob-1", "obj-1", &first).unwrap_err(),
        FileCryptoErrorCode::PolicyViolation
    );
    let again = alice.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(again.file_key(), created.file_key());
    assert_eq!(again.link().key_hash(), created.link().key_hash());
    assert_ne!(again.link().ciphertext(), created.link().ciphertext());
    assert!(server.put_link(again.link()));
    alice.activate_node_key(&again.file_key()).unwrap();
    let key = again.file_key();

    let sealed = seal(&alice, &key, "blob-1", "obj-1", &first).unwrap();
    assert_eq!(
        seal(&alice, &key, "blob-1", "obj-1", &first).unwrap(),
        sealed
    );
    assert_eq!(
        seal(&alice, &key, "blob-1", "obj-1", &second).unwrap_err(),
        FileCryptoErrorCode::OperationConflict
    );
    assert_eq!(
        seal(&alice, &key, "blob-1", "obj-2", &first).unwrap_err(),
        FileCryptoErrorCode::OperationConflict
    );
    assert_eq!(
        seal(&alice, &key, "blob-x", "", &first).unwrap_err(),
        FileCryptoErrorCode::InvalidArgument
    );
}

#[test]
fn app_manifest_travels_with_the_descriptor() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let root = group();
    rotate(&server, &alice, &root);
    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);
    let key = new_file_key(&server, &alice, &root, FILE_NODE);
    let (content_key, ciphertext) = upload_blob(&alice, b"with manifest");
    let seal_app = |blob_id: &str, app: Option<&[u8]>| {
        alice
            .seal_descriptor(&key, FILE_ID, blob_id, "obj-1", &content_key, app)
            .map_err(|error| error.code())
    };

    // A manifest larger than the CBOR scratch buffer (4 KiB) still reaches the reader intact.
    let manifest: Vec<u8> = (0..300_000_u32).map(|value| value as u8).collect();
    let sealed = seal_app("blob-1", Some(&manifest)).unwrap();
    bob.open_file_key(&server.link(FILE_NODE, 0)).unwrap();
    let blob = open_blob(&bob, &sealed).unwrap();
    assert_eq!(blob.app_manifest(), Some(manifest.as_slice()));
    assert_eq!(read_blob(&blob, &ciphertext), b"with manifest");
    let plain = seal_app("blob-2", None).unwrap();
    assert_eq!(open_blob(&bob, &plain).unwrap().app_manifest(), None);

    assert_eq!(seal_app("blob-1", Some(&manifest)).unwrap(), sealed);
    assert_eq!(
        seal_app("blob-1", None).unwrap_err(),
        FileCryptoErrorCode::OperationConflict
    );
    assert_eq!(
        seal_app("blob-1", Some(b"other")).unwrap_err(),
        FileCryptoErrorCode::OperationConflict
    );
    assert_eq!(
        seal_app("blob-3", Some(&[])).unwrap_err(),
        FileCryptoErrorCode::InvalidArgument
    );
    let too_big = vec![0_u8; kchat_file_crypto::MAX_DESCRIPTOR_BYTES];
    assert_eq!(
        seal_app("blob-4", Some(&too_big)).unwrap_err(),
        FileCryptoErrorCode::ResourceLimitExceeded
    );

    rotate(&server, &alice, &root);
    let key_1 = new_file_key(&server, &alice, &root, FILE_NODE);
    let resealed = alice
        .reseal_descriptor(FILE_ID, "blob-1", &from_server(&sealed), &key_1)
        .unwrap();
    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);
    bob.open_file_key(&server.link(FILE_NODE, 1)).unwrap();
    assert_eq!(
        open_blob(&bob, &resealed).unwrap().app_manifest(),
        Some(manifest.as_slice())
    );
}

#[test]
fn reseal_moves_an_uncommitted_blob_to_the_new_epoch() {
    let server = Server::default();
    let (alice, carol) = (device("alice"), device("carol"));
    let root = group();
    rotate(&server, &alice, &root);
    let key_1 = new_file_key(&server, &alice, &root, FILE_NODE);
    let (content_key, ciphertext) = upload_blob(&alice, b"payload");
    let sealed = seal(&alice, &key_1, "blob-1", "obj-1", &content_key).unwrap();

    // KFiles rejects the commit with FILE_EPOCH_MISMATCH: the file key just moved to epoch 1.
    rotate(&server, &alice, &root);
    let key_2 = new_file_key(&server, &alice, &root, FILE_NODE);
    let descriptor = from_server(&sealed);
    let resealed = alice
        .reseal_descriptor(FILE_ID, "blob-1", &descriptor, &key_2)
        .unwrap();
    assert_eq!(resealed.file_node_id(), FILE_NODE);
    assert_eq!(resealed.file_generation(), 1);
    assert_ne!(resealed.ciphertext(), sealed.ciphertext());
    for input in [&descriptor, &resealed] {
        assert_eq!(
            alice
                .reseal_descriptor(FILE_ID, "blob-1", input, &key_2)
                .unwrap(),
            resealed
        );
    }
    assert_eq!(
        alice
            .reseal_descriptor(FILE_ID, "blob-1", &resealed, &key_1)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::PolicyViolation
    );
    // Retrying the old seal request returns the resealed copy: a blob has one descriptor.
    assert_eq!(
        seal(&alice, &key_1, "blob-1", "obj-1", &content_key).unwrap(),
        resealed
    );

    send_bundle(&server, ("alice", &alice), ("carol", &carol), &root);
    carol.open_file_key(&server.link(FILE_NODE, 1)).unwrap();
    let blob = open_blob(&carol, &resealed).unwrap();
    assert_eq!(blob.object_id(), "obj-1");
    assert_eq!(read_blob(&blob, &ciphertext), b"payload");
    assert_eq!(
        open_blob(&carol, &sealed).unwrap_err(),
        FileCryptoErrorCode::KeySyncRequired
    );

    let other = seal(&carol, &key_2, "blob-1", "obj-2", &content_key).unwrap();
    assert_eq!(
        alice
            .reseal_descriptor(FILE_ID, "blob-1", &other, &key_2)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::OperationConflict
    );
}

#[test]
fn publish_reseals_a_draft_under_the_group_file_key() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let personal = RootId::personal(&tenant(), "personal-alice").unwrap();
    rotate(&server, &alice, &personal);
    let root = group();
    rotate(&server, &alice, &root);
    send_bundle(&server, ("alice", &alice), ("bob", &bob), &root);

    let draft_key = new_file_key(&server, &alice, &personal, "file-1:user:alice");
    let (content_key, ciphertext) = upload_blob(&alice, b"draft");
    let draft = seal(&alice, &draft_key, "draft-1", "obj-1", &content_key).unwrap();
    assert_eq!(
        open_blob(&bob, &draft).unwrap_err(),
        FileCryptoErrorCode::KeySyncRequired
    );

    // PublishFile: reseal with the group file key; the server assigns a new blob id afterwards.
    let group_key = new_file_key(&server, &alice, &root, FILE_NODE);
    let published = alice
        .reseal_descriptor(FILE_ID, "draft-1", &from_server(&draft), &group_key)
        .unwrap();
    assert_eq!(published.file_node_id(), FILE_NODE);
    assert_eq!(published.file_generation(), 0);
    assert_eq!(
        alice
            .reseal_descriptor(FILE_ID, "draft-1", &from_server(&draft), &group_key)
            .unwrap(),
        published
    );

    bob.open_file_key(&server.link(FILE_NODE, 0)).unwrap();
    let blob = open_blob(&bob, &published).unwrap();
    assert_eq!(blob.object_id(), "obj-1");
    assert_eq!(read_blob(&blob, &ciphertext), b"draft");
}

#[test]
fn keys_and_sealed_blobs_survive_a_restart() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    let key = new_file_key(&server, &alice, &root, FILE_NODE);
    let (content_key, ciphertext) = upload_blob(&alice, b"persisted");
    let sealed = seal(&alice, &key, "blob-1", "obj-1", &content_key).unwrap();
    let (_dir, path) = alice.close();

    let reopened = FileKeyring::open(&path, &common::DB_KEY, "alice", None).unwrap();
    assert_eq!(reopened.root_epoch(&root).unwrap(), Some(0));
    assert_eq!(
        seal(&reopened, &key, "blob-1", "obj-1", &content_key).unwrap(),
        sealed
    );
    let blob = open_blob(&reopened, &sealed).unwrap();
    assert_eq!(read_blob(&blob, &ciphertext), b"persisted");
}

fn get<'a>(map: &'a [(Value, Value)], key: &str) -> &'a Value {
    map.iter()
        .find(|(name, _)| name.as_text() == Some(key))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

/// HMAC-SHA256 written from RFC 2104, to check key_hash independently of the crate.
fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    block[..32].copy_from_slice(key);
    let inner_pad: Vec<u8> = block.iter().map(|byte| byte ^ 0x36).collect();
    let outer_pad: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();
    let inner = Sha256::new()
        .chain_update(&inner_pad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(&outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

#[test]
fn root_keys_never_reach_the_disk_in_clear() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    new_file_key(&server, &alice, &root, FILE_NODE);

    // The root key bytes appear in plaintext only inside the control message.
    let message = alice
        .build_root_key_bundle(&root, &ControlRecipient::account("bob").unwrap())
        .unwrap();
    let top: Value = ciborium::from_reader(&message.as_bytes()[5..]).unwrap();
    let body = get(top.as_map().unwrap(), "body").as_map().unwrap();
    let entry = get(body, "keys").as_array().unwrap()[0].as_map().unwrap();
    let root_key = get(entry, "key").as_bytes().unwrap().clone();

    for needle in [root_key.as_slice(), GROUP.as_bytes(), FILE_NODE.as_bytes()] {
        let found = std::fs::read_dir(alice.dir.path()).unwrap().any(|file| {
            let bytes = std::fs::read(file.unwrap().path()).unwrap();
            bytes.windows(needle.len()).any(|window| window == needle)
        });
        assert!(!found, "plaintext found on disk");
    }
}

fn deliver(
    server: &Server,
    from: &str,
    to: (&str, &FileKeyring),
    message: &[u8],
) -> Result<ControlOutcome, FileCryptoErrorCode> {
    to.1.process_control(&peer(from), &format!("{}-device", to.0), message, server)
        .map_err(|error| error.code())
}

#[test]
fn key_sync_request_gets_exactly_the_missing_epoch() {
    let server = Server::default();
    let (alice, bob, carol) = (device("alice"), device("bob"), device("carol"));
    let root = group();
    rotate(&server, &alice, &root);
    rotate(&server, &alice, &root);
    new_file_key(&server, &alice, &root, FILE_NODE);
    send_bundle(&server, ("alice", &alice), ("carol", &carol), &root);

    // The epoch 0 file key was wrapped at root epoch 1, which Bob lacks: request exactly that epoch
    // from the whole group.
    let link = server.link(FILE_NODE, 0);
    assert_eq!((link.epoch(), link.file_generation()), (1, 0));
    assert_eq!(
        bob.open_file_key(&link).unwrap_err().code(),
        FileCryptoErrorCode::KeySyncRequired
    );
    let request = bob
        .build_key_sync_request(&root, &[link.epoch()], None)
        .unwrap();

    let top: Value = ciborium::from_reader(&request.as_bytes()[5..]).unwrap();
    let top = top.as_map().unwrap();
    assert_eq!(get(top, "type").as_text(), Some("KeySyncRequest"));
    let body = get(top, "body").as_map().unwrap();
    let names: Vec<_> = body
        .iter()
        .map(|(name, _)| name.as_text().unwrap())
        .collect();
    assert_eq!(names, ["node", "kind", "generations"]);

    let Ok(ControlOutcome::KeySyncRequested(received)) =
        deliver(&server, "bob", ("alice", &alice), request.as_bytes())
    else {
        panic!("expected KeySyncRequested");
    };
    assert_eq!(received.root(), &root);
    assert_eq!(received.epochs(), [1]);
    assert_eq!(received.requester(), &peer("bob"));

    let response = alice.build_key_sync_response(&received, &server).unwrap();
    assert_eq!(
        deliver(&server, "alice", ("carol", &carol), response.as_bytes()),
        Err(FileCryptoErrorCode::WrongRecipient)
    );
    assert_eq!(
        deliver(&server, "alice", ("bob", &bob), response.as_bytes()),
        Ok(ControlOutcome::RootKeysImported {
            root: root.clone(),
            epochs: vec![1],
        })
    );
    bob.open_file_key(&link).unwrap();
    assert_eq!(bob.root_epoch(&root).unwrap(), Some(1));
    let epoch_zero = NodeLink::from_parts(
        link.root(),
        0,
        link.file_node_id(),
        link.file_generation(),
        link.key_hash().map(|hash| hash.as_slice()),
        link.ciphertext(),
    )
    .unwrap();
    assert_eq!(
        bob.open_file_key(&epoch_zero).unwrap_err().code(),
        FileCryptoErrorCode::KeySyncRequired
    );
}

#[test]
fn key_sync_response_follows_what_the_responder_has_and_may_share() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let root = group();
    rotate(&server, &alice, &root);
    rotate(&server, &alice, &root);
    let ask = |epochs: &[u64]| {
        let request = bob.build_key_sync_request(&root, epochs, None).unwrap();
        match deliver(&server, "bob", ("alice", &alice), request.as_bytes()) {
            Ok(ControlOutcome::KeySyncRequested(received)) => received,
            other => panic!("{other:?}"),
        }
    };

    // Requests epochs 0..2; Alice holds 0 and 1 and the history policy hides 0, so only 1 is sent.
    server.hidden_epochs.borrow_mut().push(0);
    let response = alice
        .build_key_sync_response(&ask(&[0, 1, 2]), &server)
        .unwrap();
    assert_eq!(
        deliver(&server, "alice", ("bob", &bob), response.as_bytes()),
        Ok(ControlOutcome::RootKeysImported {
            root: root.clone(),
            epochs: vec![1],
        })
    );

    assert_eq!(
        alice
            .build_key_sync_response(&ask(&[0]), &server)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::UnauthorizedSender
    );
    assert_eq!(
        alice
            .build_key_sync_response(&ask(&[7]), &server)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::KeySyncRequired
    );

    server.hidden_epochs.borrow_mut().clear();
    server.denied.borrow_mut().push("bob".to_owned());
    assert_eq!(
        alice
            .build_key_sync_response(&ask(&[0]), &server)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::UnauthorizedSender
    );
}

#[test]
fn key_sync_for_a_personal_root_stays_within_the_account() {
    let server = Server::default();
    let alice_phone = device("alice");
    let alice_laptop = device("alice");
    let bob = device("bob");
    let personal = RootId::personal(&tenant(), "personal-alice").unwrap();
    rotate(&server, &alice_phone, &personal);

    for recipient in [None, Some(ControlRecipient::account("bob").unwrap())] {
        assert_eq!(
            alice_laptop
                .build_key_sync_request(&personal, &[0], recipient.as_ref())
                .unwrap_err()
                .code(),
            FileCryptoErrorCode::PolicyViolation
        );
    }

    let to_alice = ControlRecipient::account("alice").unwrap();
    let request = alice_laptop
        .build_key_sync_request(&personal, &[0], Some(&to_alice))
        .unwrap();
    let received = match deliver(
        &server,
        "alice",
        ("alice", &alice_phone),
        request.as_bytes(),
    ) {
        Ok(ControlOutcome::KeySyncRequested(received)) => received,
        other => panic!("{other:?}"),
    };
    let response = alice_phone
        .build_key_sync_response(&received, &server)
        .unwrap();
    assert!(matches!(
        deliver(
            &server,
            "alice",
            ("alice", &alice_laptop),
            response.as_bytes()
        ),
        Ok(ControlOutcome::RootKeysImported { .. })
    ));
    assert_eq!(alice_laptop.root_epoch(&personal).unwrap(), Some(0));

    // Same request, but MLS reports Bob as the sender: rejected on receipt.
    assert_eq!(
        deliver(&server, "bob", ("alice", &alice_phone), request.as_bytes()),
        Err(FileCryptoErrorCode::UnauthorizedSender)
    );
    assert_eq!(
        bob.build_key_sync_request(&personal, &[0], Some(&to_alice))
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::PolicyViolation
    );
}

#[test]
fn key_sync_request_rejects_bad_epoch_lists() {
    let bob = device("bob");
    let root = group();
    // Epoch 0 is valid (KFiles starts at 0); epochs above i64::MAX, descending or duplicated are not.
    let too_large = i64::MAX as u64 + 1;
    for epochs in [&[][..], &[too_large], &[1, 0], &[0, 0]] {
        assert_eq!(
            bob.build_key_sync_request(&root, epochs, None)
                .unwrap_err()
                .code(),
            FileCryptoErrorCode::InvalidArgument,
            "{epochs:?}"
        );
    }
}

#[test]
fn a_link_opens_only_with_the_fields_it_was_wrapped_with() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    let other_root = RootId::group(&tenant(), "group-2").unwrap();
    rotate(&server, &alice, &other_root);
    let created = alice.create_file_key(&root, FILE_NODE).unwrap();
    let link = created.link();
    let rebuilt = |root: &RootId, file_node: &str, generation: u64, key_hash: Option<&[u8; 32]>| {
        NodeLink::from_parts(
            root,
            link.epoch(),
            file_node,
            generation,
            key_hash.map(|hash| hash.as_slice()),
            link.ciphertext(),
        )
        .unwrap()
    };

    // With and without key_hash (KFiles does not return it), the AEAD binds every field.
    for key_hash in [link.key_hash(), None] {
        for forged in [
            rebuilt(&root, "file-node-2", link.file_generation(), key_hash),
            rebuilt(&root, FILE_NODE, link.file_generation() + 1, key_hash),
            rebuilt(&other_root, FILE_NODE, link.file_generation(), key_hash),
        ] {
            assert_eq!(
                alice.open_file_key(&forged).unwrap_err().code(),
                FileCryptoErrorCode::KeyEnvelopeInvalid
            );
        }
        let genuine = rebuilt(&root, FILE_NODE, link.file_generation(), key_hash);
        assert_eq!(alice.open_file_key(&genuine).unwrap(), created.file_key());
    }
}

#[test]
fn every_record_gets_a_fresh_nonce() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    let key = new_file_key(&server, &alice, &root, FILE_NODE);

    // The same File NodeKey wrapped twice: same key, different link bytes.
    let first = alice.create_file_key(&root, FILE_NODE).unwrap();
    let second = alice.create_file_key(&root, FILE_NODE).unwrap();
    assert_eq!(first.file_key(), second.file_key());
    assert_eq!(first.link().key_hash(), second.link().key_hash());
    assert_ne!(first.link().ciphertext(), second.link().ciphertext());

    // The same descriptor plaintext sealed for two blobs: different ciphertexts.
    let (content_key, _) = upload_blob(&alice, b"same");
    let blob_1 = seal(&alice, &key, "blob-1", "obj-1", &content_key).unwrap();
    let blob_2 = seal(&alice, &key, "blob-2", "obj-1", &content_key).unwrap();
    assert_ne!(blob_1.ciphertext(), blob_2.ciphertext());
}

fn field_mut<'a>(map: &'a mut [(Value, Value)], key: &str) -> &'a mut Value {
    map.iter_mut()
        .find(|(name, _)| name.as_text() == Some(key))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

/// Re-encodes a control message after editing its top-level CBOR map.
fn edited(message: &[u8], edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut top: Value = ciborium::from_reader(&message[5..]).unwrap();
    edit(top.as_map_mut().unwrap());
    let mut bytes = message[..5].to_vec();
    ciborium::into_writer(&top, &mut bytes).unwrap();
    bytes
}

#[test]
fn root_key_messages_with_inconsistent_content_are_malformed() {
    let server = Server::default();
    let (alice, bob) = (device("alice"), device("bob"));
    let root = group();
    rotate(&server, &alice, &root);
    rotate(&server, &alice, &root);
    let message = alice
        .build_root_key_bundle(&root, &ControlRecipient::account("bob").unwrap())
        .unwrap();

    let cases = [
        // The same epoch twice.
        edited(message.as_bytes(), |top| {
            let body = field_mut(top, "body").as_map_mut().unwrap();
            let keys = field_mut(body, "keys").as_array_mut().unwrap();
            keys[1] = keys[0].clone();
        }),
        // key_hash computed for another node.
        edited(message.as_bytes(), |top| {
            let body = field_mut(top, "body").as_map_mut().unwrap();
            *field_mut(body, "node") = Value::Text("group-2".into());
        }),
        // A personal root key addressed to a whole group (no recipient).
        edited(message.as_bytes(), |top| {
            let body = field_mut(top, "body").as_map_mut().unwrap();
            *field_mut(body, "kind") = Value::Integer(1.into());
            top.retain(|(name, _)| name.as_text() != Some("recipient"));
        }),
    ];
    for bytes in cases {
        assert_eq!(
            deliver(&server, "alice", ("bob", &bob), &bytes),
            Err(FileCryptoErrorCode::MalformedMessage)
        );
    }
    assert!(deliver(&server, "alice", ("bob", &bob), message.as_bytes()).is_ok());
}

#[test]
fn reseal_refuses_a_file_key_from_before_the_root_rotated() {
    let server = Server::default();
    let alice = device("alice");
    let personal = RootId::personal(&tenant(), "personal-alice").unwrap();
    rotate(&server, &alice, &personal);
    let root = group();
    rotate(&server, &alice, &root);
    let group_key = new_file_key(&server, &alice, &root, FILE_NODE);

    let draft_key = new_file_key(&server, &alice, &personal, "file-1:user:alice");
    let (content_key, ciphertext) = upload_blob(&alice, b"draft");
    let draft = from_server(&seal(&alice, &draft_key, "draft-1", "obj-1", &content_key).unwrap());

    // A member leaves and the group root rotates: removed members still hold the old group file
    // key, so publishing must not reseal under it.
    rotate(&server, &alice, &root);
    assert_eq!(
        alice
            .reseal_descriptor(FILE_ID, "draft-1", &draft, &group_key)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::PolicyViolation
    );

    let rotated = new_file_key(&server, &alice, &root, FILE_NODE);
    assert_eq!(rotated.generation(), 1);
    let published = alice
        .reseal_descriptor(FILE_ID, "draft-1", &draft, &rotated)
        .unwrap();
    assert_eq!(published.file_generation(), 1);
    assert_eq!(
        read_blob(&open_blob(&alice, &published).unwrap(), &ciphertext),
        b"draft"
    );
}

#[test]
fn opened_blob_debug_hides_the_object_id() {
    let server = Server::default();
    let alice = device("alice");
    let root = group();
    rotate(&server, &alice, &root);
    let key = new_file_key(&server, &alice, &root, FILE_NODE);
    let (content_key, _) = upload_blob(&alice, b"debug");
    let sealed = seal(&alice, &key, "blob-1", "obj-private", &content_key).unwrap();
    let blob = open_blob(&alice, &sealed).unwrap();
    assert!(!format!("{blob:?}").contains("obj-private"));
}
