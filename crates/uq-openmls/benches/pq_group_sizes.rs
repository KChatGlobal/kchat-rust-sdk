use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use openmls::{
    group::{MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY},
    prelude::{Capabilities, Ciphersuite},
    test_utils::OpenMlsLibcrux,
};
use uq_openmls::ciphersuite::requires_external_ratchet_tree;
use uq_openmls::core::{
    add_members, create_group, export_ratchet_tree, generate_key_package, generate_signature_key,
    process_welcome, process_welcome_with_ratchet_tree,
};

const GROUP_SIZES: [usize; 3] = [2, 10, 100];
const CIPHERSUITES: [Ciphersuite; 3] = [
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
];

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

fn join_config(ciphersuite: Ciphersuite) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(!requires_external_ratchet_tree(ciphersuite))
        .build()
}

fn create_add_and_process_welcome(ciphersuite: Ciphersuite, member_count: usize) -> usize {
    let group_id = format!("bench_pq_group_{:04x}_{}", ciphersuite as u16, member_count);
    let alice_provider = OpenMlsLibcrux::default();
    let mut member_providers = Vec::with_capacity(member_count.saturating_sub(1));
    let mut key_packages = Vec::with_capacity(member_count.saturating_sub(1));

    for member_index in 1..member_count {
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

        member_providers.push(provider);
        key_packages.push(key_package);
    }

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
    let ratchet_tree = if requires_external_ratchet_tree(ciphersuite) {
        Some(export_ratchet_tree(&alice_group).expect("ratchet tree export should succeed"))
    } else {
        None
    };

    let mut joined_count = 1usize;
    for provider in &member_providers {
        let join_config = join_config(ciphersuite);
        let group = if let Some(ratchet_tree) = &ratchet_tree {
            process_welcome_with_ratchet_tree(
                provider,
                &add_result.welcome,
                &join_config,
                ratchet_tree,
            )
        } else {
            process_welcome(provider, &add_result.welcome, &join_config)
        }
        .expect("member welcome processing should succeed");
        joined_count += usize::from(group.members().count() == member_count);
    }

    black_box(alice_group.members().count() + joined_count)
}

fn bench_create_add_process_welcome(c: &mut Criterion) {
    let mut group = c.benchmark_group("kchat_mls_create_add_process_welcome");

    for ciphersuite in CIPHERSUITES {
        for member_count in GROUP_SIZES {
            group.bench_with_input(
                BenchmarkId::new(ciphersuite_name(ciphersuite), member_count),
                &(ciphersuite, member_count),
                |b, &(ciphersuite, member_count)| {
                    b.iter(|| create_add_and_process_welcome(ciphersuite, member_count));
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_create_add_process_welcome);
criterion_main!(benches);
