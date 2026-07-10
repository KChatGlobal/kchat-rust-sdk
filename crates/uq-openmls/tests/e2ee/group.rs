use openmls::{
    group::{
        GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::{
        BasicCredential, Capabilities, Ciphersuite, CredentialWithKey, ExtensionType, KeyPackage,
        Lifetime, SenderRatchetConfiguration, tls_codec::Serialize,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use uq_openmls::{
    core::{
        AddMembersResult, DEFAULT_CIPHERSUITE, JoinByExternalCommitResult, ReAddResult,
        RemoveMembersResult, create_group, encrypt_message as core_encrypt_message,
        generate_key_package, group_signer, join_by_external_commit, process_welcome,
    },
    error::Error,
};

use crate::helper::{
    add_members, delete_group, encrypt_message, export_group_info, init_group_with_members,
    init_members, leave_group, merge_pending_commit, process_application_message,
    process_operation_message, readd, remove_members, update_leaf_node,
};

#[test]
fn test_three_members_create_group_and_add_member() {
    // Init alice device.
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_user_id = "alice";

    // Init bob device
    let bob_provider = OpenMlsRustCrypto::default();
    let bob_user_id = "bob";

    // Generate bob key package
    let bob_key_package =
        generate_key_package(bob_user_id, &bob_provider, DEFAULT_CIPHERSUITE, false, None)
            .expect("should return signature key pair");

    // Alice create group
    let group_id = "group_1";
    create_group(
        &alice_provider,
        alice_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add Bob
    let AddMembersResult { welcome, .. } =
        add_members(&alice_provider, group_id, &[bob_key_package])
            .expect("should add Bob to group success");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");

    // Bob process welcome
    let bob_group = process_welcome(
        &bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process `welcome` success");

    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.members().count(), bob_group.members().count());
    assert_eq!(alice_group.members().count(), 2);

    // Init charlie device
    let charlie_provider = OpenMlsRustCrypto::default();
    let charlie_user_id = "charlie";

    // Generate charlie key package
    let charlie_key_package = generate_key_package(
        charlie_user_id,
        &charlie_provider,
        DEFAULT_CIPHERSUITE,
        false,
        None,
    )
    .expect("should generate key package success");

    // Alice add Charlie
    let AddMembersResult {
        commit, welcome, ..
    } = add_members(&alice_provider, group_id, &[charlie_key_package])
        .expect("should add charlie to group success");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");
    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    // Charlie process welcome
    let charlie_group = process_welcome(
        &charlie_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process `welcome` success");

    // Bob process commit (add charlie)
    process_operation_message(&bob_provider, group_id, &commit)
        .expect("should process `commit` success");
    let bob_group = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.members().count(), bob_group.members().count());
    assert_eq!(
        alice_group.members().count(),
        charlie_group.members().count()
    );
    assert_eq!(alice_group.members().count(), 3);
}

#[test]
fn test_add_duplicate_member() {
    // Init alice device.
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_user_id = "alice";

    // Init bob device
    let bob_provider = OpenMlsRustCrypto::default();
    let bob_user_id = "bob";

    // Generate bob key package
    let bob_key_package =
        generate_key_package(bob_user_id, &bob_provider, DEFAULT_CIPHERSUITE, false, None)
            .expect("should generate key package success");

    // Alice create group
    let group_id = "group_1";
    create_group(
        &alice_provider,
        alice_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add Bob
    let AddMembersResult { welcome, .. } =
        add_members(&alice_provider, group_id, &[bob_key_package]).expect("should add Bob success");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");

    // Bob process welcome
    let _ = process_welcome(
        &bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process `welcome` success");

    // Bob generate new key package
    let bob_new_key_package =
        generate_key_package(bob_user_id, &bob_provider, DEFAULT_CIPHERSUITE, false, None)
            .expect("should generate key package success");

    // Alice add Bob duplicate
    let result = add_members(&alice_provider, group_id, &[bob_new_key_package]);

    assert!(matches!(
        result,
        Err(Error::SomeMembersAlreadyExistedInGroup)
    ));
}

#[test]
fn test_create_group_and_add_multiple_members() {
    // Init alice device.
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_user_id = "alice";

    // Init 10 devices
    let mut member_key_packages = Vec::new();
    let mut member_providers = Vec::new();

    for i in 0..10 {
        let member_id = format!("member_{i}");
        // Init member i device
        let member_i_provider = OpenMlsRustCrypto::default();

        // Generate member i key package
        member_key_packages.push(
            generate_key_package(
                &member_id,
                &member_i_provider,
                DEFAULT_CIPHERSUITE,
                false,
                None,
            )
            .expect("should generate key package success"),
        );
        member_providers.push(member_i_provider);
    }

    // Alice create group
    let group_id = "group_1";
    create_group(
        &alice_provider,
        alice_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add 10 members
    let AddMembersResult { welcome, .. } =
        add_members(&alice_provider, group_id, &member_key_packages)
            .expect("should add members success and return `commit` and `welcome`");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");

    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.members().count(), 11);

    for i in 0..10 {
        let member_provider = member_providers.get(i).unwrap();
        // Member i process welcome
        let member_group = process_welcome(
            member_provider,
            &welcome.clone(),
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build(),
        )
        .expect("should process `welcome` success");

        assert_eq!(member_group.members().count(), 11);
    }
}

#[test]
fn test_process_commit_wrong_order() {
    // Init members
    let members = init_members(&["alice", "bob", "charlie", "danny"]);
    let (alice_user_id, alice_provider, _) = &members[0];
    let (_, bob_provider, bob_key_package) = &members[1];
    let (_charlie_user_id, _charlie_provider, charlie_key_package) = &members[2];
    let (_danny_user_id, _danny_provider, danny_key_package) = &members[3];

    // Alice create group
    let group_id = "group_1";
    create_group(
        alice_provider,
        alice_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add Bob
    let AddMembersResult { welcome, .. } = add_members(
        alice_provider,
        group_id,
        std::slice::from_ref(bob_key_package),
    )
    .expect("should add bob success and return `commit` and `welcome`");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    // Bob process welcome
    process_welcome(
        bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process `welcome` success");

    // Alice add Charlie
    let _ = add_members(
        alice_provider,
        group_id,
        std::slice::from_ref(charlie_key_package),
    )
    .expect("should add charlie success and return `commit` and `welcome`");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    // Alice add Danny
    let AddMembersResult {
        commit: add_danny_commit,
        ..
    } = add_members(
        alice_provider,
        group_id,
        std::slice::from_ref(danny_key_package),
    )
    .expect("should add danny success and return `commit` and `welcome`");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    // Bob process commit (add charlie)
    let result = process_operation_message(bob_provider, group_id, &add_danny_commit);

    // Should return error, because Bob should process add_charlie_commit first
    assert!(matches!(result, Err(Error::ProcessMessage(_))));
}

#[test]
fn test_export_group_info_and_external_join() {
    // Init group with members
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

    // Alice export group info
    let group_info =
        export_group_info(alice_provider, group_id).expect("should return group info success");

    // Init Charlie
    let (charlie_id, charlie_provider, _) = &init_members(&["charlie"])[0];

    // Charlie join by external commit
    let JoinByExternalCommitResult { commit, .. } = join_by_external_commit(
        charlie_provider,
        charlie_id,
        &group_info,
        DEFAULT_CIPHERSUITE,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .unwrap();

    // Alice and Bob process commit (external join)
    process_operation_message(alice_provider, group_id, &commit)
        .expect("should process commit success");
    process_operation_message(bob_provider, group_id, &commit)
        .expect("should process commit success");

    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.members().count(), 3);
}

#[test]
fn test_external_join_from_existed_user() {
    // Init group with members
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
    let (bob_id, bob_provider) = &members[1];

    // Alice export group info
    let group_info =
        export_group_info(alice_provider, group_id).expect("should return group info success");

    // Old Bob device re-join by external commit
    let result = join_by_external_commit(
        bob_provider,
        bob_id,
        &group_info,
        DEFAULT_CIPHERSUITE,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    );

    assert!(matches!(result, Err(Error::CredentialIsExisted)));

    // Bob re-init
    let bob_device_2_id = "bob_device_2";
    let (_, new_bob_provider, _) = &init_members(&[bob_device_2_id])[0];

    // New Bob device join by external commit
    let result = join_by_external_commit(
        new_bob_provider,
        bob_device_2_id,
        &group_info,
        DEFAULT_CIPHERSUITE,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    );

    assert!(result.is_ok());
}

#[test]
fn test_remove_members_from_group() {
    // Init group with member
    let group_id = "group_1";
    let members = init_group_with_members(
        &["alice", "bob", "charlie", "danny"],
        group_id,
        MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
    );
    let (_alice_id, alice_provider) = &members[0];
    let (_bob_id, bob_provider) = &members[1];
    let (charlie_id, _) = &members[2];
    let (danny_id, _danny_provider) = &members[3];

    // Alice remove Charlie and Danny
    let RemoveMembersResult { commit, .. } =
        remove_members(alice_provider, group_id, &[charlie_id, danny_id])
            .expect("should remove members success");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    process_operation_message(bob_provider, group_id, &commit)
        .expect("should process commit success");

    // Alice group
    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    // Bob group
    let bob_group = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.members().count(), bob_group.members().count());
    assert_eq!(alice_group.members().count(), 2);
}

#[test]
fn test_re_join_after_leave_group() {
    // Init group with member
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
    let (bob_id, bob_provider) = &members[1];

    // Alice remove Charlie and Danny
    let RemoveMembersResult { commit, .. } =
        remove_members(alice_provider, group_id, &[bob_id]).expect("should remove members success");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    process_operation_message(bob_provider, group_id, &commit)
        .expect("should process commit success");

    // Bob group
    let bob_group = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert!(!bob_group.is_active());

    // Bob regenerate key package
    let bob_key_package =
        generate_key_package(bob_id, bob_provider, DEFAULT_CIPHERSUITE, true, None).unwrap();

    // Alice add Bob to group again
    let result = add_members(alice_provider, group_id, &[bob_key_package]).unwrap();

    process_welcome(
        bob_provider,
        &result.welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .unwrap();

    // Bob group
    let bob_group = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert!(bob_group.is_active());
}

#[test]
fn test_member_self_remove_from_group() {
    // Init group with member
    let group_id = "group_1";
    let members = init_group_with_members(
        &["alice", "bob", "charlie"],
        group_id,
        MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
    );
    let (alice_id, alice_provider) = &members[0];

    // Alice self remove from group
    let err = remove_members(alice_provider, group_id, &[alice_id])
        .expect_err("should return error when member self remove");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    assert!(matches!(err, Error::RemoveMembers(_)));
}

#[test]
fn test_leave_group() {
    // Init group with member
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

    let (_, _, charlie_key_package) = &init_members(&["charlie"])[0];

    // Alice leave group
    let result = leave_group(alice_provider, group_id).expect("should leave group success");

    // Bob process proposal (alice leave)
    let result = process_operation_message(bob_provider, group_id, &result.proposal)
        .expect("should process leave proposal success");

    let commit = result
        .commit
        .expect("should return commit after process leave proposal");

    // Alice process commit (self leave)
    process_operation_message(alice_provider, group_id, &commit)
        .expect("alice should process commit success");

    let mut bob_group = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    bob_group.merge_pending_commit(bob_provider).unwrap();

    assert_eq!(bob_group.members().count(), 1);

    // Alice try to add Charlie after leave group.
    let result = add_members(
        alice_provider,
        group_id,
        std::slice::from_ref(charlie_key_package),
    );

    assert!(matches!(result, Err(Error::MissingOwnLeafNodeInGroup)));
}

#[test]
fn test_update_leaf_node() {
    // Init group with member
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

    // Alice update leaf node
    let update_result =
        update_leaf_node(alice_provider, group_id).expect("should update leaf node success");
    merge_pending_commit(alice_provider, group_id).expect("should merge pending commit success");

    process_operation_message(bob_provider, group_id, &update_result.commit)
        .expect("should process commit success");

    // Alice group
    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    // Bob group
    let bob_group = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.tree_hash(), bob_group.tree_hash());
}

#[test]
fn test_readd() {
    // Init alice device.
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_user_id = "alice";

    // Init bob device
    let bob_provider = OpenMlsRustCrypto::default();
    let bob_user_id = "bob";

    // Generate bob key package
    let bob_key_package =
        generate_key_package(bob_user_id, &bob_provider, DEFAULT_CIPHERSUITE, true, None)
            .expect("should return signature key pair");

    // Alice create group
    let group_id = "group_1";
    create_group(
        &alice_provider,
        alice_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1000)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(1000, 1000))
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add Bob
    let AddMembersResult { welcome, .. } = add_members(
        &alice_provider,
        group_id,
        std::slice::from_ref(&bob_key_package),
    )
    .expect("should add Bob to group success");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");

    // Bob process welcome
    let bob_group = process_welcome(
        &bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1000)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(1000, 1000))
            .build(),
    )
    .expect("should process `welcome` success");

    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.members().count(), bob_group.members().count());
    assert_eq!(alice_group.tree_hash(), bob_group.tree_hash());
    assert_eq!(alice_group.members().count(), 2);

    // Test message
    let encrypted = encrypt_message(&alice_provider, group_id, "alice message".as_bytes()).unwrap();
    let encrypted_2 =
        encrypt_message(&alice_provider, group_id, "alice message 2".as_bytes()).unwrap();

    let decrypted = process_application_message(&bob_provider, group_id, &encrypted).unwrap();
    println!(
        "bob decrypted message: {:?}",
        String::from_utf8(decrypted.message.clone()).unwrap()
    );

    // Init charlie device
    let charlie_provider = OpenMlsRustCrypto::default();
    let charlie_user_id = "charlie";

    // Generate charlie key package
    let charlie_key_package = generate_key_package(
        charlie_user_id,
        &charlie_provider,
        DEFAULT_CIPHERSUITE,
        true,
        None,
    )
    .expect("should generate key package success");

    // Alice add Charlie
    let AddMembersResult { .. } = add_members(
        &alice_provider,
        group_id,
        std::slice::from_ref(&charlie_key_package),
    )
    .expect("should add charlie to group success");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");

    // Bob add Charlie
    let AddMembersResult { .. } = add_members(&bob_provider, group_id, &[charlie_key_package])
        .expect("should add charlie to group success");
    merge_pending_commit(&bob_provider, group_id).expect("should merge pending commit success");

    let ReAddResult {
        welcome: readd_welcome,
        ..
    } = readd(
        &alice_provider,
        group_id,
        &[bob_user_id],
        std::slice::from_ref(&bob_key_package),
    )
    .unwrap();
    merge_pending_commit(&alice_provider, group_id).unwrap();

    let bob_group = process_welcome(
        &bob_provider,
        &readd_welcome.unwrap(),
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .unwrap();
    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.tree_hash(), bob_group.tree_hash());

    // Test
    let decrypted_2 = process_application_message(&bob_provider, group_id, &encrypted_2);
    println!("bob decrypted message 2 err: {:?}", decrypted_2);

    // Init Danny device
    let danny_provider = OpenMlsRustCrypto::default();
    let danny_user_id = "danny";

    // Danny create new group
    create_group(
        &danny_provider,
        danny_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .unwrap();
    let danny_key_package = generate_key_package(
        danny_user_id,
        &danny_provider,
        DEFAULT_CIPHERSUITE,
        true,
        None,
    )
    .expect("should generate key package success");

    let ReAddResult {
        welcome: readd_welcome,
        ..
    } = readd(
        &alice_provider,
        group_id,
        &[danny_user_id],
        std::slice::from_ref(&danny_key_package),
    )
    .unwrap();
    merge_pending_commit(&alice_provider, group_id).unwrap();

    let danny_group = process_welcome(
        &danny_provider,
        &readd_welcome.unwrap(),
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .unwrap();
    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    // println!("{:?}", alice_group.tree_hash());
    // println!("{:?}", danny_group.tree_hash());
    assert_eq!(alice_group.tree_hash(), danny_group.tree_hash());

    println!("old danny tree hash {:?}", danny_group.tree_hash());

    // E device
    let e_provider = OpenMlsRustCrypto::default();
    let e_user_id = "E";

    let group_info = export_group_info(&alice_provider, group_id).unwrap();

    let JoinByExternalCommitResult {
        commit,
        pre_tree_hash,
        ..
    } = join_by_external_commit(
        &e_provider,
        e_user_id,
        &group_info,
        DEFAULT_CIPHERSUITE,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .unwrap();

    // Verify that pre_tree_hash was captured (should not be empty for valid group)
    assert!(
        !pre_tree_hash.is_empty(),
        "pre_tree_hash should be captured"
    );

    delete_group(&e_provider, group_id).unwrap();

    process_operation_message(&alice_provider, group_id, &commit).unwrap();

    let e_key_package =
        generate_key_package(e_user_id, &e_provider, DEFAULT_CIPHERSUITE, true, None).unwrap();

    let ReAddResult {
        welcome: readd_welcome,
        ..
    } = readd(&alice_provider, group_id, &[e_user_id], &[e_key_package]).unwrap();
    merge_pending_commit(&alice_provider, group_id).unwrap();

    let e_group = process_welcome(
        &e_provider,
        &readd_welcome.unwrap(),
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .unwrap();
    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .unwrap()
    .unwrap();

    println!("alice group hash: {:?}", alice_group.tree_hash());
    println!("e group hash: {:?}", e_group.tree_hash());
    assert_eq!(alice_group.tree_hash(), e_group.tree_hash());

    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .unwrap()
    .unwrap();
    println!(
        "==============> {:?}",
        alice_group
            .members()
            .filter_map(|member| {
                if let Ok(credential) = BasicCredential::try_from(member.credential)
                    && let Ok(member_id) = String::from_utf8(credential.identity().to_vec())
                {
                    return Some(member_id);
                }

                None
            })
            .collect::<Vec<String>>()
    );

    let danny_key_package_2 = generate_key_package(
        danny_user_id,
        &danny_provider,
        DEFAULT_CIPHERSUITE,
        true,
        None,
    )
    .expect("should generate key package success");

    let ReAddResult {
        welcome: readd_welcome,
        ..
    } = readd(
        &alice_provider,
        group_id,
        &[bob_user_id],
        &[danny_key_package_2, bob_key_package],
    )
    .unwrap();
    merge_pending_commit(&alice_provider, group_id).unwrap();

    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .unwrap()
    .unwrap();
    println!(
        "==============> {:?}",
        alice_group
            .members()
            .filter_map(|member| {
                if let Ok(credential) = BasicCredential::try_from(member.credential)
                    && let Ok(member_id) = String::from_utf8(credential.identity().to_vec())
                {
                    return Some(member_id);
                }

                None
            })
            .collect::<Vec<String>>()
    );

    let bob_group = process_welcome(
        &bob_provider,
        &readd_welcome.clone().unwrap(),
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .unwrap();
    let danny_group = process_welcome(
        &danny_provider,
        &readd_welcome.unwrap(),
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .unwrap();
    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .unwrap()
    .unwrap();

    println!("new alice tree hash {:?}", alice_group.tree_hash());
    println!("new danny tree hash {:?}", danny_group.tree_hash());

    assert_eq!(alice_group.tree_hash(), danny_group.tree_hash());
    assert_eq!(alice_group.tree_hash(), bob_group.tree_hash());
}

#[test]
fn test_key_package_lifetime() {
    // Init alice device.
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_user_id = "alice";

    // Init bob device
    let bob_provider = OpenMlsRustCrypto::default();
    let bob_user_id = "bob";

    // Generate bob key package
    let bob_key_package = generate_key_package_with_lifetime(
        bob_user_id,
        &bob_provider,
        DEFAULT_CIPHERSUITE,
        true,
        None,
        1,
    )
    .expect("should return signature key pair");

    // Alice create group
    let group_id = "group_1";
    create_group(
        &alice_provider,
        alice_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group success");

    // Alice add Bob
    let AddMembersResult { welcome, .. } = add_members(
        &alice_provider,
        group_id,
        std::slice::from_ref(&bob_key_package),
    )
    .expect("should add Bob to group success");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");

    // Bob process welcome
    let bob_group = process_welcome(
        &bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process `welcome` success");

    let alice_group = MlsGroup::load(
        alice_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("should load group from storage success")
    .expect("should be returned Option::Some");

    assert_eq!(alice_group.members().count(), bob_group.members().count());
    assert_eq!(alice_group.members().count(), 2);

    // Init charlie device
    let charlie_provider = OpenMlsRustCrypto::default();
    let charlie_user_id = "charlie";

    // Generate charlie key package
    let charlie_key_package = generate_key_package(
        charlie_user_id,
        &charlie_provider,
        DEFAULT_CIPHERSUITE,
        false,
        None,
    )
    .expect("should generate key package success");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let AddMembersResult { .. } =
        add_members(&alice_provider, group_id, &[charlie_key_package]).unwrap();
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");

    let group_info = export_group_info(&alice_provider, group_id).unwrap();

    let danny_provider = OpenMlsRustCrypto::default();
    let danny_user_id = "danny";

    // Danny joins via external commit
    // Even though Bob's key package is expired, we should still get the pre_tree_hash
    let JoinByExternalCommitResult { pre_tree_hash, .. } = join_by_external_commit(
        &danny_provider,
        danny_user_id,
        &group_info,
        DEFAULT_CIPHERSUITE,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .unwrap();

    // Verify tree hash was captured (critical for server verification)
    assert!(
        !pre_tree_hash.is_empty(),
        "pre_tree_hash must be captured even with expired key packages"
    );

    println!(
        "Successfully captured tree hash: {} bytes",
        pre_tree_hash.len()
    );

    // Alice self remove from group
    remove_members(&alice_provider, group_id, &[bob_user_id]).unwrap();
    merge_pending_commit(&alice_provider, group_id).unwrap();

    let e_provider = OpenMlsRustCrypto::default();
    let e_user_id = "e";
    let e_key_package =
        generate_key_package(e_user_id, &e_provider, DEFAULT_CIPHERSUITE, false, None)
            .expect("should generate key package success");

    let AddMembersResult { .. } =
        add_members(&alice_provider, group_id, &[bob_key_package, e_key_package])
            .expect("should add Bob to group success");
    merge_pending_commit(&alice_provider, group_id).expect("should merge pending commit success");
}

#[test]
fn test_forward_secrecy_error() {
    // This test demonstrates the "requested secret was deleted to preserve forward secrecy" error
    // which occurs when trying to decrypt the same message twice

    // Init alice and bob
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_user_id = "alice";
    let bob_provider = OpenMlsRustCrypto::default();
    let bob_user_id = "bob";

    // Generate bob key package
    let bob_key_package =
        generate_key_package(bob_user_id, &bob_provider, DEFAULT_CIPHERSUITE, false, None)
            .expect("should generate key package");

    // Alice creates group
    let group_id = "group_forward_secrecy";
    create_group(
        &alice_provider,
        alice_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        None,
    )
    .expect("should create group");

    // Alice adds Bob
    let AddMembersResult { welcome, .. } =
        add_members(&alice_provider, group_id, &[bob_key_package]).unwrap();
    merge_pending_commit(&alice_provider, group_id).unwrap();

    // Bob processes welcome
    let _ = process_welcome(
        &bob_provider,
        &welcome,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
    )
    .expect("should process welcome");

    // Bob encrypts a message
    let mut bob_group_1 = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .unwrap()
    .unwrap();

    let mut bob_group_2 = MlsGroup::load(
        bob_provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .unwrap()
    .unwrap();

    let signer = group_signer(&bob_group_1, &bob_provider).unwrap();

    let msg1 = core_encrypt_message(&mut bob_group_1, &bob_provider, &signer, b"msg1").unwrap();
    let msg2 = core_encrypt_message(&mut bob_group_2, &bob_provider, &signer, b"msg2").unwrap();

    let r1 = process_application_message(&alice_provider, group_id, &msg1);
    println!("{:?}", r1);

    let r2 = process_application_message(&alice_provider, group_id, &msg2);
    println!("{:?}", r2);
}

pub fn generate_key_package_with_lifetime<Provider: OpenMlsProvider>(
    user_id: &str,
    provider: &Provider,
    ciphersuite: Ciphersuite,
    last_resort: bool,
    public_key: Option<Vec<u8>>,
    lifetime: u64,
) -> Result<Vec<u8>, Error> {
    let (credential_with_key, signer) =
        get_credential_with_key(user_id, provider, ciphersuite, public_key)?;

    let mut key_package_builder = KeyPackage::builder();

    if last_resort {
        key_package_builder = key_package_builder
            .leaf_node_capabilities(Capabilities::new(
                None,
                None,
                Some(&[ExtensionType::LastResort]),
                None,
                None,
            ))
            .key_package_lifetime(Lifetime::new(lifetime))
            .mark_as_last_resort();
    }

    let key_package = key_package_builder
        .build(ciphersuite, provider, &signer, credential_with_key)?
        .key_package()
        .clone();

    Ok(key_package.tls_serialize_detached()?)
}

fn get_credential_with_key<Provider: OpenMlsProvider>(
    user_id: &str,
    provider: &Provider,
    ciphersuite: Ciphersuite,
    public_key: Option<Vec<u8>>,
) -> Result<(CredentialWithKey, SignatureKeyPair), Error> {
    let credential = BasicCredential::new(user_id.into());
    let signature_scheme = ciphersuite.signature_algorithm();
    let signature_key = if let Some(public_key) = public_key {
        SignatureKeyPair::read(provider.storage(), &public_key, signature_scheme)
            .ok_or(Error::MissingSignatureKeyPair)?
    } else {
        SignatureKeyPair::new(signature_scheme)?
    };

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_key.to_public_vec().into(),
    };

    signature_key
        .store(provider.storage())
        .map_err(|e| Error::Storage(e.to_string()))?;

    Ok((credential_with_key, signature_key))
}
