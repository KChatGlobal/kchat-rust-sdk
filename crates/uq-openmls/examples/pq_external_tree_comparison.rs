use openmls::{
    group::{
        MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::{Capabilities, Ciphersuite},
    test_utils::OpenMlsLibcrux,
};
use openmls_basic_credential::SignatureKeyPair;
use uq_openmls::{
    core::{
        add_members, create_group, export_ratchet_tree, generate_key_package,
        generate_signature_key, group_signer, process_operation_message,
        process_welcome_with_ratchet_tree, update_leaf_node,
    },
    error::Error,
};

const INITIAL_GROUP_SIZE: usize = 99;
const FINAL_GROUP_SIZE: usize = 100;
const BOOTSTRAP_BATCH_SIZE: usize = 10;
const FINAL_COMMITTER_INDEX: usize = INITIAL_GROUP_SIZE / 2;
const CIPHERSUITES: [Ciphersuite; 3] = [
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
];

#[derive(Debug)]
struct SizeRow {
    ciphersuite: &'static str,
    initial_group_size: usize,
    final_group_size: usize,
    bootstrap_batch_size: usize,
    bootstrap_add_operations: usize,
    priming_update_operations: usize,
    final_committer_index: usize,
    ratchet_tree_mode: &'static str,
    key_package_bytes: usize,
    welcome_bytes: usize,
    commit_bytes: usize,
    group_info_bytes: usize,
    external_ratchet_tree_bytes: usize,
    joiner_input_bytes: usize,
}

fn main() {
    println!(
        "ciphersuite,initial_group_size,final_group_size,bootstrap_batch_size,bootstrap_add_operations,priming_update_operations,final_committer_index,ratchet_tree_mode,key_package_bytes,welcome_bytes,commit_bytes,group_info_bytes,external_ratchet_tree_bytes,joiner_input_bytes"
    );

    for ciphersuite in CIPHERSUITES {
        let row = measure_external_tree_add_one_member_sizes(ciphersuite)
            .expect("external-tree comparison measurement should succeed");
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            row.ciphersuite,
            row.initial_group_size,
            row.final_group_size,
            row.bootstrap_batch_size,
            row.bootstrap_add_operations,
            row.priming_update_operations,
            row.final_committer_index,
            row.ratchet_tree_mode,
            row.key_package_bytes,
            row.welcome_bytes,
            row.commit_bytes,
            row.group_info_bytes,
            row.external_ratchet_tree_bytes,
            row.joiner_input_bytes,
        );
    }
}

fn measure_external_tree_add_one_member_sizes(ciphersuite: Ciphersuite) -> Result<SizeRow, Error> {
    let group_id = format!("external_tree_comparison_{:04x}", ciphersuite as u16);
    let alice_provider = OpenMlsLibcrux::default();
    let alice_group = create_group(
        &alice_provider,
        "alice",
        &group_id,
        ciphersuite,
        &external_tree_config(ciphersuite),
        None,
    )?;
    let alice_signer = group_signer(&alice_group, &alice_provider)?;
    let mut members = vec![Member {
        provider: alice_provider,
        signer: alice_signer,
        group: alice_group,
    }];

    let mut bootstrap_add_operations = 0;
    let mut priming_update_operations = 0;
    for batch_start in (1..INITIAL_GROUP_SIZE).step_by(BOOTSTRAP_BATCH_SIZE) {
        let batch_end = (batch_start + BOOTSTRAP_BATCH_SIZE).min(INITIAL_GROUP_SIZE);
        let mut joining_members = Vec::with_capacity(batch_end - batch_start);
        for member_index in batch_start..batch_end {
            let provider = OpenMlsLibcrux::default();
            let signer = generate_signature_key(&provider, ciphersuite)?;
            let key_package = generate_key_package(
                &format!("member_{member_index}"),
                &provider,
                ciphersuite,
                false,
                Some(signer.public().to_vec()),
            )?;
            joining_members.push(PendingMember {
                provider,
                signer,
                key_package,
            });
        }

        let key_packages = joining_members
            .iter()
            .map(|member| member.key_package.clone())
            .collect::<Vec<_>>();
        let (add_result, ratchet_tree) = {
            let alice = &mut members[0];
            let add_result = add_members(
                &mut alice.group,
                &alice.provider,
                &alice.signer,
                &key_packages,
            )?;
            alice.group.merge_pending_commit(&alice.provider)?;
            let ratchet_tree = export_ratchet_tree(&alice.group)?;
            (add_result, ratchet_tree)
        };
        for member in &mut members[1..] {
            process_operation_message(&mut member.group, &member.provider, &add_result.commit)?;
        }
        for joining_member in joining_members {
            let group = process_welcome_with_ratchet_tree(
                &joining_member.provider,
                &add_result.welcome,
                &external_tree_join_config(),
                &ratchet_tree,
            )?;
            members.push(Member {
                provider: joining_member.provider,
                signer: joining_member.signer,
                group,
            });
        }

        let updater_index = members.len() - key_packages.len();
        let update = {
            let updater = &mut members[updater_index];
            let update = update_leaf_node(&mut updater.group, &updater.provider, &updater.signer)?;
            updater.group.merge_pending_commit(&updater.provider)?;
            update
        };
        for (member_index, member) in members.iter_mut().enumerate() {
            if member_index != updater_index {
                process_operation_message(&mut member.group, &member.provider, &update.commit)?;
            }
        }
        bootstrap_add_operations += 1;
        priming_update_operations += 1;
    }
    assert_eq!(members.len(), INITIAL_GROUP_SIZE);

    let new_member_provider = OpenMlsLibcrux::default();
    let new_member_signer = generate_signature_key(&new_member_provider, ciphersuite)?;
    let new_member_key_package = generate_key_package(
        "member_100",
        &new_member_provider,
        ciphersuite,
        false,
        Some(new_member_signer.public().to_vec()),
    )?;
    let key_package_bytes = new_member_key_package.len();

    let add_result = {
        let final_committer = &mut members[FINAL_COMMITTER_INDEX];
        let add_result = add_members(
            &mut final_committer.group,
            &final_committer.provider,
            &final_committer.signer,
            &[new_member_key_package],
        )?;
        final_committer
            .group
            .merge_pending_commit(&final_committer.provider)?;
        add_result
    };
    assert_eq!(
        members[FINAL_COMMITTER_INDEX].group.members().count(),
        FINAL_GROUP_SIZE
    );

    let external_ratchet_tree = export_ratchet_tree(&members[FINAL_COMMITTER_INDEX].group)?;
    let welcome_bytes = add_result.welcome.len();
    let external_ratchet_tree_bytes = external_ratchet_tree.len();

    Ok(SizeRow {
        ciphersuite: ciphersuite_name(ciphersuite),
        initial_group_size: INITIAL_GROUP_SIZE,
        final_group_size: FINAL_GROUP_SIZE,
        bootstrap_batch_size: BOOTSTRAP_BATCH_SIZE,
        bootstrap_add_operations,
        priming_update_operations,
        final_committer_index: FINAL_COMMITTER_INDEX,
        ratchet_tree_mode: "external",
        key_package_bytes,
        welcome_bytes,
        commit_bytes: add_result.commit.len(),
        group_info_bytes: add_result.group_info.as_ref().map_or(0, Vec::len),
        external_ratchet_tree_bytes,
        joiner_input_bytes: welcome_bytes + external_ratchet_tree_bytes,
    })
}

struct Member {
    provider: OpenMlsLibcrux,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

struct PendingMember {
    provider: OpenMlsLibcrux,
    signer: SignatureKeyPair,
    key_package: Vec<u8>,
}

fn external_tree_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
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
        .use_ratchet_tree_extension(false)
        .build()
}

fn external_tree_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_comparison_flow_exports_the_tree_and_counts_it_as_joiner_input() {
        let row = measure_external_tree_add_one_member_sizes(
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        )
        .expect("the classic external-tree comparison should succeed");

        assert_eq!(row.initial_group_size, 99);
        assert_eq!(row.final_group_size, 100);
        assert_eq!(row.bootstrap_batch_size, 10);
        assert_eq!(row.bootstrap_add_operations, 10);
        assert_eq!(row.ratchet_tree_mode, "external");
        assert!(
            row.commit_bytes < 8_943,
            "a primed multi-sender tree should avoid the one-sender classic Commit size"
        );
        assert!(row.external_ratchet_tree_bytes > 0);
        assert_eq!(
            row.joiner_input_bytes,
            row.welcome_bytes + row.external_ratchet_tree_bytes
        );
    }
}
