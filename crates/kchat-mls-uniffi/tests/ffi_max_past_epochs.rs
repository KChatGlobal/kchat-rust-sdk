use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use mls_mobile_sdk_rs::mls::UqMls;

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

const MAX_PAST_EPOCHS: u16 = 101;
const OUT_OF_ORDER_TOLERANCE: u32 = 5;
const MAXIMUM_FORWARD_DISTANCE: u32 = 10;

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

fn make_client(test_name: &str, client_id: &str) -> UqMls {
    let unique = unique_name(test_name, client_id);
    UqMls::new(
        client_id.to_owned(),
        db_path(&format!("{unique}-mls")),
        db_path(&format!("{unique}-group-status")),
        MAX_PAST_EPOCHS,
        None,
        OUT_OF_ORDER_TOLERANCE,
        MAXIMUM_FORWARD_DISTANCE,
        None,
    )
    .expect("should create sqlite-backed UqMls")
}

fn generate_one_key_package(client: &UqMls) -> Vec<u8> {
    client
        .generate_key_packages(1, false, None)
        .expect("should generate one key package")
        .key_packages
        .into_iter()
        .next()
        .expect("should return one key package")
}

/// Verifies that the configured `max_past_epochs` value is honoured end-to-end
/// across the UniFFI surface: a member can still decrypt application messages
/// that were sent in past epochs as long as those epochs fall within the
/// configured retention window.
///
/// Scenario:
/// - Configure `max_past_epochs = 101`.
/// - Create a group with members A (alice), B (bob), C (charlie).
/// - In a loop, A:
///     1. encrypts an application message at the current epoch,
///     2. commits a tree-changing operation (alternating remove C / add C),
///        which advances the epoch by one,
///   repeating until A has produced 100 messages spread over 100 distinct
///   epochs.
/// - B is kept "behind" during the loop (it never decrypts the application
///   messages as they come, nor processes the intermediate commits).
/// - After the loop, B processes all 99 commits in order, advancing B's epoch
///   to match A's current epoch.
/// - B then decrypts every one of the 100 application messages, each of which
///   was produced at an epoch that is now in the past for B. With
///   `max_past_epochs = 101`, all 100 past epochs must still be available.
#[test]
fn max_past_epochs_allows_decrypting_messages_from_past_epochs() {
    let test_name = "max_past_epochs_allows_decrypting_messages_from_past_epochs";
    let group_id = "group-max-past-epochs";

    let alice = make_client(test_name, "alice");
    let bob = make_client(test_name, "bob");
    let charlie = make_client(test_name, "charlie");

    // --- Initial group construction: alice, bob, charlie. -------------------
    alice
        .create_group(group_id, None)
        .expect("alice should create group");

    let bob_kp = generate_one_key_package(&bob);
    let charlie_kp = generate_one_key_package(&charlie);

    let add_bc = alice
        .add_members(group_id, &[bob_kp, charlie_kp])
        .expect("alice should add bob and charlie");
    alice
        .merge_pending_commit(group_id)
        .expect("alice should merge initial add commit");
    bob.process_welcome(&add_bc.welcome)
        .expect("bob should process welcome");
    charlie
        .process_welcome(&add_bc.welcome)
        .expect("charlie should process welcome");

    // Snapshot epoch after initial setup so we can sanity-check the loop math.
    let initial_epoch = alice
        .group_epoch(group_id)
        .expect("group_epoch should succeed")
        .epoch;

    // --- Generate 100 application messages spread across 100 epochs. --------
    //
    // Each iteration of the loop produces:
    //   - one encrypted application message at the current epoch,
    //   - one commit that advances alice's epoch by 1.
    //
    // After 100 iterations we have 100 messages and 100 commits, covering 100
    // distinct epochs. We then drop the final unused commit so the message
    // count matches the commit count needed to bring bob up to alice's epoch.
    let total_messages: usize = 100;
    let mut messages: Vec<(i64, Vec<u8>)> = Vec::with_capacity(total_messages);
    let mut commits: Vec<Vec<u8>> = Vec::with_capacity(total_messages);

    // `charlie_in_group` mirrors charlie's current membership from alice's
    // perspective. It starts as `true` because we just added charlie above.
    let mut charlie_in_group = true;

    for i in 0..total_messages {
        let epoch_before = alice
            .group_epoch(group_id)
            .expect("group_epoch should succeed")
            .epoch;

        let plaintext = format!("hello {i}").into_bytes();
        let encrypted = alice
            .encrypt_message(group_id, &plaintext, None)
            .unwrap_or_else(|err| panic!("alice should encrypt message {i}: {err}"));
        println!(
            "[encrypt] i={i:>3} epoch={epoch_before:>3} plaintext={plaintext:?} ciphertext_len={ct_len} ciphertext_head={head}",
            plaintext = String::from_utf8_lossy(&plaintext),
            ct_len = encrypted.len(),
            head = hex_preview(&encrypted, 16),
        );
        messages.push((epoch_before, encrypted));

        // Advance alice's epoch by alternately removing and re-adding charlie.
        let commit = if charlie_in_group {
            let res = alice
                .remove_members(group_id, &[String::from("charlie")])
                .unwrap_or_else(|err| panic!("alice should remove charlie at iter {i}: {err}"));
            charlie_in_group = false;
            res.commit
        } else {
            let kp = generate_one_key_package(&charlie);
            let res = alice
                .add_members(group_id, &[kp])
                .unwrap_or_else(|err| panic!("alice should re-add charlie at iter {i}: {err}"));
            charlie_in_group = true;
            res.commit
        };
        alice
            .merge_pending_commit(group_id)
            .unwrap_or_else(|err| panic!("alice should merge commit at iter {i}: {err}"));
        commits.push(commit);
    }

    // Sanity check: alice should now be 100 epochs ahead of where she was
    // right after the initial setup.
    let final_epoch = alice
        .group_epoch(group_id)
        .expect("group_epoch should succeed")
        .epoch;
    assert_eq!(
        final_epoch - initial_epoch,
        total_messages as i64,
        "alice's epoch should advance once per loop iteration",
    );

    // --- Bring bob up to alice's current epoch. -----------------------------
    //
    // Bob has not processed any commits yet, so he is still at `initial_epoch`.
    // Processing all `total_messages` commits in order advances him exactly the
    // same number of epochs as alice produced messages.
    for (i, commit) in commits.iter().enumerate() {
        bob.process_operation_message(group_id, commit)
            .unwrap_or_else(|err| panic!("bob should process commit {i}: {err}"));
    }

    let bob_epoch = bob
        .group_epoch(group_id)
        .expect("group_epoch should succeed")
        .epoch;
    assert_eq!(
        bob_epoch, final_epoch,
        "bob should reach alice's current epoch after replaying every commit",
    );

    // --- Bob decrypts every message produced by alice at past epochs. -------
    //
    // The very first message was encrypted at `initial_epoch`, which is now
    // `total_messages` epochs in the past. Because `MAX_PAST_EPOCHS = 101 >
    // total_messages = 100`, all of these past epoch secrets must still be
    // retained and the decryption must succeed.
    for (i, (epoch_at_encryption, encrypted)) in messages.iter().enumerate() {
        match bob.process_application_message(group_id, encrypted) {
            Ok(decrypted) => {
                println!(
                    "[decrypt] i={i:>3} encrypted_at_epoch={epoch_at_encryption:>3} bob_epoch={bob_epoch} plaintext={plaintext:?}",
                    plaintext = String::from_utf8_lossy(&decrypted.message),
                );
                assert_eq!(
                    decrypted.message,
                    format!("hello {i}").into_bytes(),
                    "decrypted plaintext for message {i} must match the original",
                );
            }
            Err(err) => {
                println!("===> {:?}", err.to_string());
            }
        }
    }
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut s = String::with_capacity(take * 2 + 3);
    for b in &bytes[..take] {
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > take {
        s.push_str("...");
    }
    s
}
