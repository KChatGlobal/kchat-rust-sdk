use openmls::{
    group::{MlsGroupCreateConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY},
    prelude::{Capabilities, Ciphersuite},
    test_utils::OpenMlsLibcrux,
};
use uq_openmls::ciphersuite::requires_external_ratchet_tree;
use uq_openmls::core::{
    add_members, create_group, export_ratchet_tree, generate_key_package, generate_signature_key,
};

const GROUP_SIZES: [usize; 3] = [2, 10, 100];
const CIPHERSUITES: [Ciphersuite; 3] = [
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
];

#[derive(Debug)]
struct SizeRow {
    ciphersuite: &'static str,
    group_size: usize,
    ratchet_tree_mode: &'static str,
    signature_public_key_bytes: usize,
    signature_private_key_bytes: usize,
    key_package_total_bytes: usize,
    key_package_avg_bytes: usize,
    welcome_bytes: usize,
    commit_bytes: usize,
    group_info_bytes: usize,
    external_ratchet_tree_bytes: usize,
    onboarding_payload_bytes: usize,
}

fn main() {
    println!(
        "ciphersuite,group_size,ratchet_tree_mode,signature_public_key_bytes,signature_private_key_bytes,key_package_total_bytes,key_package_avg_bytes,welcome_bytes,commit_bytes,group_info_bytes,external_ratchet_tree_bytes,onboarding_payload_bytes"
    );

    for ciphersuite in CIPHERSUITES {
        for group_size in GROUP_SIZES {
            let row = measure_sizes(ciphersuite, group_size);
            println!(
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                row.ciphersuite,
                row.group_size,
                row.ratchet_tree_mode,
                row.signature_public_key_bytes,
                row.signature_private_key_bytes,
                row.key_package_total_bytes,
                row.key_package_avg_bytes,
                row.welcome_bytes,
                row.commit_bytes,
                row.group_info_bytes,
                row.external_ratchet_tree_bytes,
                row.onboarding_payload_bytes
            );
        }
    }
}

fn measure_sizes(ciphersuite: Ciphersuite, group_size: usize) -> SizeRow {
    let group_id = format!("size_pq_group_{:04x}_{group_size}", ciphersuite as u16);
    let alice_provider = OpenMlsLibcrux::default();
    let probe_provider = OpenMlsLibcrux::default();
    let probe_signer = generate_signature_key(&probe_provider, ciphersuite)
        .expect("probe signature key generation should succeed");

    let mut key_packages = Vec::with_capacity(group_size.saturating_sub(1));
    for member_index in 1..group_size {
        let provider = OpenMlsLibcrux::default();
        let member_id = format!("member_{member_index}");
        let signer = generate_signature_key(&provider, ciphersuite)
            .expect("member signature key generation should succeed");
        let key_package = generate_key_package(
            &member_id,
            &provider,
            ciphersuite,
            false,
            Some(signer.public().to_vec()),
        )
        .expect("member key package generation should succeed");

        key_packages.push(key_package);
    }

    let key_package_total_bytes = key_packages.iter().map(Vec::len).sum::<usize>();
    let key_package_avg_bytes = if key_packages.is_empty() {
        0
    } else {
        key_package_total_bytes / key_packages.len()
    };

    let mut alice_group = create_group(
        &alice_provider,
        "alice",
        &group_id,
        ciphersuite,
        &create_config(ciphersuite),
        None,
    )
    .expect("Alice group creation should succeed");
    let alice_signer = uq_openmls::core::group_signer(&alice_group, &alice_provider)
        .expect("Alice signer should exist");

    let add_result = add_members(
        &mut alice_group,
        &alice_provider,
        &alice_signer,
        &key_packages,
    )
    .expect("add members should succeed");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("merge pending commit should succeed");

    let external_ratchet_tree = if requires_external_ratchet_tree(ciphersuite) {
        export_ratchet_tree(&alice_group).expect("ratchet tree export should succeed")
    } else {
        Vec::new()
    };
    let group_info_bytes = add_result.group_info.as_ref().map_or(0, Vec::len);
    let onboarding_payload_bytes = add_result.welcome.len()
        + add_result.commit.len()
        + group_info_bytes
        + external_ratchet_tree.len();

    SizeRow {
        ciphersuite: ciphersuite_name(ciphersuite),
        group_size,
        ratchet_tree_mode: if requires_external_ratchet_tree(ciphersuite) {
            "external"
        } else {
            "embedded"
        },
        signature_public_key_bytes: probe_signer.public().len(),
        signature_private_key_bytes: probe_signer.private().len(),
        key_package_total_bytes,
        key_package_avg_bytes,
        welcome_bytes: add_result.welcome.len(),
        commit_bytes: add_result.commit.len(),
        group_info_bytes,
        external_ratchet_tree_bytes: external_ratchet_tree.len(),
        onboarding_payload_bytes,
    }
}

fn create_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
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
        .use_ratchet_tree_extension(!requires_external_ratchet_tree(ciphersuite))
        .build()
}

fn ciphersuite_name(ciphersuite: Ciphersuite) -> &'static str {
    match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            "classic_x25519_chacha_ed25519"
        }
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => "xwing_chacha_ed25519",
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => {
            "mlkem1024_aes256_sha384_mldsa87"
        }
        _ => "out_of_scope",
    }
}
