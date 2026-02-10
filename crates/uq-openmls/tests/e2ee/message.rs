use openmls::group::MlsGroupCreateConfig;
use uq_openmls::{
    core::{
        AddMembersResult, DEFAULT_CIPHERSUITE, add_members, encrypt_message, merge_pending_commit,
        process_application_message, process_operation_message,
    },
    error::Error,
};

use crate::helper::{init_group_with_members, init_members};

#[test]
fn test_add_member_and_encrypt_decrypte_message() {
    let group_id = "group_1";
    let members = init_group_with_members(
        &["alice", "bob", "charlie"],
        group_id,
        MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
    );
    let (_alice_id, alice_provider) = &members[0];
    let (_bob_id, bob_provider) = &members[1];
    let (_charlie_id, charlie_provider) = &members[2];

    let (_, _, danny_key_package) = &init_members(&["danny"])[0];

    // Alice add Danny
    let AddMembersResult { commit, .. } =
        add_members(alice_provider, group_id, &[danny_key_package.clone()]).unwrap();
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    // Bob and Charlie process commit (add Danny)
    process_operation_message(bob_provider, group_id, &commit).unwrap();
    process_operation_message(charlie_provider, group_id, &commit).unwrap();

    let alice_raw_msg_1 = "message from alice 1";
    let alice_msg_1 = encrypt_message(alice_provider, group_id, alice_raw_msg_1.as_bytes())
        .expect("should return alice's encrypted message");

    let bob_result = process_application_message(bob_provider, group_id, &alice_msg_1)
        .expect("bob should decrypted message success");

    let charlie_result = process_application_message(charlie_provider, group_id, &alice_msg_1)
        .expect("charlie should decrypted message success");

    println!(
        "bob decrypted message: {:?}",
        String::from_utf8(bob_result.message.clone()).unwrap()
    );

    assert_eq!(alice_raw_msg_1.as_bytes(), bob_result.message);
    assert_eq!(alice_raw_msg_1.as_bytes(), charlie_result.message);
}

#[test]
fn test_decrypte_message_at_old_epoch() {
    // Init group with Bob and Alice
    let group_id = "group_1";
    let members = init_group_with_members(
        &["alice", "bob"],
        group_id,
        MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
    );
    let (_alice_id, alice_provider) = &members[0];
    let (_bob_id, bob_provider) = &members[1];

    let alice_raw_msg_1 = "message from alice 1";
    let alice_msg_1 = encrypt_message(alice_provider, group_id, alice_raw_msg_1.as_bytes())
        .expect("should return alice's encrypted message");

    let (_, _, charlie_key_package) = &init_members(&["charlie"])[0];

    // Alice Add Charlie => epoch advances
    let AddMembersResult { commit, .. } =
        add_members(alice_provider, group_id, &[charlie_key_package.clone()])
            .expect("should add Charlie success");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    // Bob process commit (add Charlie)
    process_operation_message(bob_provider, group_id, &commit)
        .expect("Bob should process commit success");

    // Bob decrypt Alice message 1
    let err = process_application_message(bob_provider, group_id, &alice_msg_1)
        .expect_err("should return error when decrypting message at old epoch");

    assert!(matches!(err, Error::ProcessMessage(_)));
}

#[test]
fn test_decrypte_message_at_old_epoch_with_max_past_epochs_config() {
    // Init group with Bob and Alice
    let group_id = "group_1";
    let members = init_group_with_members(
        &["alice", "bob"],
        group_id,
        MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .build(),
    );
    let (_alice_id, alice_provider) = &members[0];
    let (_bob_id, bob_provider) = &members[1];

    // Alice encrypt message 1
    let alice_raw_msg_1 = "message from alice 1";
    let alice_msg_1 = encrypt_message(alice_provider, group_id, alice_raw_msg_1.as_bytes())
        .expect("should return alice's encrypted message");

    let members = init_members(&["charlie", "danny"]);
    let (_, _, charlie_key_package) = &members[0];
    let (_, _, danny_key_package) = &members[1];

    // Alice Add Charlie => epoch advances
    let AddMembersResult { commit, .. } =
        add_members(alice_provider, group_id, &[charlie_key_package.clone()])
            .expect("should add Charlie success");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    // Bob process commit (add Charlie)
    process_operation_message(bob_provider, group_id, &commit)
        .expect("Bob should process commit success");

    // Bob decrypt Alice message 1 at old epochs
    let result = process_application_message(bob_provider, group_id, &alice_msg_1)
        .expect("should return decrypted message");

    println!(
        "bob decrypted message 1: {:?}",
        String::from_utf8(result.message.clone()).unwrap()
    );

    assert_eq!(alice_raw_msg_1.as_bytes(), result.message);

    // Alice encrypte message 2
    let alice_raw_msg_2 = "message from alice 2";
    let alice_msg_2 = encrypt_message(alice_provider, group_id, alice_raw_msg_2.as_bytes())
        .expect("should return alice's encrypted message");

    // Bob decrypt Alice message 2 at current epochs
    let result = process_application_message(bob_provider, group_id, &alice_msg_2)
        .expect("should return decrypted message");

    println!(
        "bob decrypted message 2: {:?}",
        String::from_utf8(result.message.clone()).unwrap()
    );

    assert_eq!(alice_raw_msg_2.as_bytes(), result.message);

    // Alice Add Danny => epoch advances
    let AddMembersResult { commit, .. } =
        add_members(alice_provider, group_id, &[danny_key_package.clone()])
            .expect("should add Danny success");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    // Bob process commit (add Danny)
    process_operation_message(bob_provider, group_id, &commit)
        .expect("Bob should process commit success");

    // Bob decrypt Alice message 1 at too old epochs
    let err = process_application_message(bob_provider, group_id, &alice_msg_1)
        .expect_err("should return error for message at too old epoch");

    assert!(matches!(err, Error::ProcessMessage(_)));
}
