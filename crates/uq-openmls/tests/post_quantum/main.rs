use openmls::{
    extensions::Extensions,
    group::{
        GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::{
        BasicCredential, Capabilities, Ciphersuite, CredentialWithKey, KeyPackageIn,
        ProtocolVersion,
        tls_codec::{Deserialize, Serialize},
    },
    test_utils::OpenMlsLibcrux,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use uq_openmls::{
    ciphersuite::KchatCiphersuite,
    core::{
        DEFAULT_CIPHERSUITE, add_members, create_group, encrypt_message, export_ratchet_tree,
        generate_key_package, generate_signature_key, process_application_message, process_welcome,
        process_welcome_with_ratchet_tree,
    },
};

const GROUP_ID: &str = "post_quantum_poc_group";
const ALICE: &str = "alice";
const BOB: &str = "bob";
const MAX_PAST_EPOCHS: usize = 30;

#[test]
fn kchat_ciphersuite_uses_canonical_values() {
    assert_eq!(
        KchatCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519.to_openmls(),
        DEFAULT_CIPHERSUITE
    );
    assert_eq!(
        KchatCiphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519.to_openmls(),
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    );
    assert_eq!(
        KchatCiphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87.to_openmls(),
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
    );
}

#[test]
fn new_group_lifecycle_works_for_supported_ciphersuites() {
    for ciphersuite in benchmark_and_correctness_ciphersuites() {
        let group_id = format!("post_quantum_new_group_{:04x}", ciphersuite as u16);
        let alice_provider = OpenMlsLibcrux::default();
        let bob_provider = OpenMlsLibcrux::default();

        let bob_signer = generate_signature_key(&bob_provider, ciphersuite)
            .expect("Bob should generate selected ciphersuite signature key");
        let bob_key_package = generate_key_package(
            BOB,
            &bob_provider,
            ciphersuite,
            false,
            Some(bob_signer.public().to_vec()),
        )
        .expect("Bob should generate selected ciphersuite key package");

        create_group(
            &alice_provider,
            ALICE,
            &group_id,
            ciphersuite,
            &create_config(ciphersuite),
            None,
        )
        .expect("Alice should create selected ciphersuite group");

        let mut alice_group = load_group(&alice_provider, &group_id);
        let alice_signer = uq_openmls::core::group_signer(&alice_group, &alice_provider)
            .expect("Alice should have selected ciphersuite signer");
        let add_result = add_members(
            &mut alice_group,
            &alice_provider,
            &alice_signer,
            &[bob_key_package],
        )
        .expect("Alice should add Bob to selected ciphersuite group");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("Alice should merge add commit");

        let mut bob_group = process_welcome(
            &bob_provider,
            &add_result.welcome,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .max_past_epochs(MAX_PAST_EPOCHS)
                .build(),
        )
        .expect("Bob should join selected ciphersuite group");

        assert_eq!(alice_group.ciphersuite(), ciphersuite);
        assert_eq!(bob_group.ciphersuite(), ciphersuite);
        assert_eq!(alice_group.members().count(), 2);
        assert_eq!(bob_group.members().count(), 2);

        let plaintext = format!("hello from {:04x}", ciphersuite as u16);
        let encrypted = encrypt_message(
            &mut alice_group,
            &alice_provider,
            &alice_signer,
            plaintext.as_bytes(),
        )
        .expect("Alice should encrypt selected ciphersuite application message");
        let decrypted = process_application_message(&mut bob_group, &bob_provider, &encrypted)
            .expect("Bob should decrypt selected ciphersuite application message");

        assert_eq!(decrypted.message, plaintext.as_bytes());
    }
}

#[test]
fn full_pq_group_joins_with_external_ratchet_tree_for_ten_members() {
    let ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
    let member_count = 10;
    let group_id = "post_quantum_external_tree_group_10";
    let alice_provider = OpenMlsLibcrux::default();
    let mut member_providers = Vec::new();
    let mut key_packages = Vec::new();

    for member_index in 1..member_count {
        let provider = OpenMlsLibcrux::default();
        let member_id = format!("member_{member_index}");
        let signer = generate_signature_key(&provider, ciphersuite)
            .expect("member should generate full-PQ signature key");
        let key_package = generate_key_package(
            &member_id,
            &provider,
            ciphersuite,
            false,
            Some(signer.public().to_vec()),
        )
        .expect("member should generate full-PQ key package");

        member_providers.push(provider);
        key_packages.push(key_package);
    }

    let mut alice_group = create_group(
        &alice_provider,
        ALICE,
        group_id,
        ciphersuite,
        &create_config_with_ratchet_tree_extension(ciphersuite, false),
        None,
    )
    .expect("Alice should create full-PQ group without embedded ratchet tree extension");
    let alice_signer = uq_openmls::core::group_signer(&alice_group, &alice_provider)
        .expect("Alice should have full-PQ signer");

    let add_result = add_members(
        &mut alice_group,
        &alice_provider,
        &alice_signer,
        &key_packages,
    )
    .expect("Alice should add ten full-PQ members using external ratchet tree");
    assert!(add_result.group_info.is_none());

    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("Alice should merge add commit");
    let ratchet_tree =
        export_ratchet_tree(&alice_group).expect("external ratchet tree should serialize");

    for provider in &member_providers {
        let joined_group = process_welcome_with_ratchet_tree(
            provider,
            &add_result.welcome,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(false)
                .max_past_epochs(MAX_PAST_EPOCHS)
                .build(),
            &ratchet_tree,
        )
        .expect("member should join full-PQ group with external ratchet tree");

        assert_eq!(joined_group.ciphersuite(), ciphersuite);
        assert_eq!(joined_group.members().count(), member_count);
    }

    assert_eq!(alice_group.members().count(), member_count);
}

#[test]
fn reboot_default_group_with_pq_ciphersuite_key_packages() {
    let pq_ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    let alice_provider = OpenMlsLibcrux::default();
    let bob_provider = OpenMlsLibcrux::default();

    let bob_default_key_package =
        generate_key_package(BOB, &bob_provider, DEFAULT_CIPHERSUITE, false, None)
            .expect("Bob should generate a default ciphersuite key package");

    create_group(
        &alice_provider,
        ALICE,
        GROUP_ID,
        DEFAULT_CIPHERSUITE,
        &MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build(),
        None,
    )
    .expect("Alice should create the default ciphersuite group");

    let mut alice_old_group = load_group(&alice_provider, GROUP_ID);
    let alice_default_signer = uq_openmls::core::group_signer(&alice_old_group, &alice_provider)
        .expect("Alice should have a default ciphersuite signer");
    let add_result = add_members(
        &mut alice_old_group,
        &alice_provider,
        &alice_default_signer,
        &[bob_default_key_package],
    )
    .expect("Alice should add Bob to the default ciphersuite group");
    alice_old_group
        .merge_pending_commit(&alice_provider)
        .expect("Alice should merge the default group add commit");

    let bob_old_group = process_welcome(
        &bob_provider,
        &add_result.welcome,
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build(),
    )
    .expect("Bob should join the default ciphersuite group");

    assert_eq!(alice_old_group.ciphersuite(), DEFAULT_CIPHERSUITE);
    assert_eq!(bob_old_group.ciphersuite(), DEFAULT_CIPHERSUITE);
    assert_eq!(alice_old_group.members().count(), 2);
    assert_eq!(bob_old_group.members().count(), 2);

    let before_reboot_plaintext = b"hello from the default ciphersuite group before reboot";
    let encrypted_before_reboot = encrypt_message(
        &mut alice_old_group,
        &alice_provider,
        &alice_default_signer,
        before_reboot_plaintext,
    )
    .expect("Alice should encrypt an application message before reboot");

    let alice_pq_signer = generate_signature_key(&alice_provider, pq_ciphersuite)
        .expect("Alice should generate a PQ ciphersuite signature key");
    let bob_pq_signer = generate_signature_key(&bob_provider, pq_ciphersuite)
        .expect("Bob should generate a PQ ciphersuite signature key");

    let alice_pq_key_package = generate_key_package(
        ALICE,
        &alice_provider,
        pq_ciphersuite,
        false,
        Some(alice_pq_signer.public().to_vec()),
    )
    .expect("Alice should generate a PQ ciphersuite key package");
    let bob_pq_key_package = generate_key_package(
        BOB,
        &bob_provider,
        pq_ciphersuite,
        false,
        Some(bob_pq_signer.public().to_vec()),
    )
    .expect("Bob should generate a PQ ciphersuite key package");

    assert!(!alice_pq_key_package.is_empty());
    let bob_pq_key_package = KeyPackageIn::tls_deserialize_exact(&bob_pq_key_package)
        .expect("Bob's PQ key package should deserialize")
        .validate(bob_provider.crypto(), ProtocolVersion::default())
        .expect("Bob's PQ key package should validate");

    let alice_pq_credential = credential_with_key(ALICE, &alice_pq_signer);

    let (mut alice_new_group, reboot_bundle) = alice_old_group
        .reboot(GroupId::from_slice(GROUP_ID.as_bytes()))
        .refine_group_builder(|builder| {
            builder
                .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .ciphersuite(pq_ciphersuite)
                .use_ratchet_tree_extension(true)
                .max_past_epochs(MAX_PAST_EPOCHS)
                .replace_old_group()
        })
        .finish(
            Extensions::empty(),
            vec![bob_pq_key_package],
            |builder| builder,
            &alice_provider,
            &alice_pq_signer,
            alice_pq_credential,
        )
        .expect("Alice should reboot the group with the PQ ciphersuite");

    let (_commit, welcome, _group_info) = reboot_bundle.into_messages();
    alice_new_group
        .merge_pending_commit(&alice_provider)
        .expect("Alice should merge the reboot commit");

    let mut bob_new_group = process_welcome(
        &bob_provider,
        &welcome
            .expect("Reboot should produce a Welcome for Bob")
            .tls_serialize_detached()
            .expect("Reboot Welcome should serialize"),
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build(),
    )
    .expect("Bob should join the rebooted PQ ciphersuite group");

    let decrypted_after_reboot =
        process_application_message(&mut bob_new_group, &bob_provider, &encrypted_before_reboot);
    println!("decrypted_after_reboot: {:?}", decrypted_after_reboot);

    assert_eq!(alice_new_group.ciphersuite(), pq_ciphersuite);
    assert_eq!(bob_new_group.ciphersuite(), pq_ciphersuite);
    assert_eq!(alice_new_group.members().count(), 2);
    assert_eq!(bob_new_group.members().count(), 2);

    let alice_new_signer = uq_openmls::core::group_signer(&alice_new_group, &alice_provider)
        .expect("Alice should have a PQ ciphersuite signer after reboot");
    let plaintext = b"hello from the rebooted post-quantum group";
    let encrypted = encrypt_message(
        &mut alice_new_group,
        &alice_provider,
        &alice_new_signer,
        plaintext,
    )
    .expect("Alice should encrypt an application message after reboot");
    let decrypted = process_application_message(&mut bob_new_group, &bob_provider, &encrypted)
        .expect("Bob should decrypt the application message after reboot");
    println!("decrypted: {:?}", decrypted);

    assert_eq!(decrypted.message, plaintext);
}

fn benchmark_and_correctness_ciphersuites() -> [Ciphersuite; 3] {
    [
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
    ]
}

fn create_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    create_config_with_ratchet_tree_extension(ciphersuite, true)
}

fn create_config_with_ratchet_tree_extension(
    ciphersuite: Ciphersuite,
    use_ratchet_tree_extension: bool,
) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            None,
            None,
            None,
        ))
        .use_ratchet_tree_extension(use_ratchet_tree_extension)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

fn load_group(provider: &impl OpenMlsProvider, group_id: &str) -> MlsGroup {
    MlsGroup::load(
        provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .expect("group storage should be readable")
    .expect("group should exist")
}

fn credential_with_key(identity: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}
