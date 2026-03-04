use openmls::group::{MlsGroupCreateConfig, MlsGroupJoinConfig};
use openmls_rust_crypto::OpenMlsRustCrypto;
use uq_openmls::core::{
    AddMembersResult, DEFAULT_CIPHERSUITE, create_group, generate_key_package, process_welcome,
};

use crate::helper::{add_members, merge_pending_commit};

#[test]
fn test_key_package_last_resort() {
    // Init alice device.
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_user_id = "alice";

    // Init bob device
    let bob_provider = OpenMlsRustCrypto::default();
    let bob_user_id = "bob";

    // Generate bob key package with last_resort = true
    let bob_key_package =
        generate_key_package(bob_user_id, &bob_provider, DEFAULT_CIPHERSUITE, true, None)
            .expect("should return key package");

    // Alice create group 1
    let group_1_id = "group_1";
    create_group(
        &alice_provider,
        alice_user_id,
        group_1_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add Bob to group 1
    let AddMembersResult { welcome, .. } =
        add_members(&alice_provider, group_1_id, &[bob_key_package.clone()])
            .expect("should add Bob to group success");
    merge_pending_commit(&alice_provider, group_1_id).expect("should merge pending commit success");

    // Bob process welcome of group 1
    let bob_group_1 = process_welcome(
        &bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process `welcome` success");

    // Alice create group 2
    let group_2_id = "group_2";
    create_group(
        &alice_provider,
        alice_user_id,
        group_2_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add Bob to group 2
    let AddMembersResult { welcome, .. } =
        add_members(&alice_provider, group_2_id, &[bob_key_package])
            .expect("should add Bob to group success");
    merge_pending_commit(&alice_provider, group_2_id).expect("should merge pending commit success");

    // Bob process welcome of group 1
    let bob_group_2 = process_welcome(
        &bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process `welcome` success");

    assert_eq!(bob_group_1.members().count(), 2);
    assert_eq!(bob_group_2.members().count(), 2);
}
