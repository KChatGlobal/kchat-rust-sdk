use openmls::{
    group::{MlsGroupCreateConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY},
    prelude::{Capabilities, Ciphersuite},
    test_utils::OpenMlsLibcrux,
};
use uq_openmls::{
    ciphersuite::requires_external_ratchet_tree,
    core::{
        add_members, create_group, export_ratchet_tree, generate_key_package,
        generate_signature_key, group_signer,
    },
    error::Error,
};

const INITIAL_GROUP_SIZE: usize = 99;
const FINAL_GROUP_SIZE: usize = 100;
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
        "ciphersuite,initial_group_size,final_group_size,ratchet_tree_mode,key_package_bytes,welcome_bytes,commit_bytes,group_info_bytes,external_ratchet_tree_bytes,joiner_input_bytes"
    );

    for ciphersuite in CIPHERSUITES {
        let row = measure_add_one_member_sizes(ciphersuite)
            .expect("single-member add size measurement should succeed");
        println!(
            "{},{},{},{},{},{},{},{},{},{}",
            row.ciphersuite,
            row.initial_group_size,
            row.final_group_size,
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

fn measure_add_one_member_sizes(ciphersuite: Ciphersuite) -> Result<SizeRow, Error> {
    let group_id = format!("single_add_pq_group_{:04x}", ciphersuite as u16);
    let alice_provider = OpenMlsLibcrux::default();
    let mut group = create_group(
        &alice_provider,
        "alice",
        &group_id,
        ciphersuite,
        &create_config(ciphersuite),
        None,
    )?;
    let alice_signer = group_signer(&group, &alice_provider)?;

    let bootstrap_key_packages = (1..INITIAL_GROUP_SIZE)
        .map(|member_index| {
            let provider = OpenMlsLibcrux::default();
            let signer = generate_signature_key(&provider, ciphersuite)?;
            generate_key_package(
                &format!("member_{member_index}"),
                &provider,
                ciphersuite,
                false,
                Some(signer.public().to_vec()),
            )
        })
        .collect::<Result<Vec<_>, Error>>()?;
    add_members(
        &mut group,
        &alice_provider,
        &alice_signer,
        &bootstrap_key_packages,
    )?;
    group.merge_pending_commit(&alice_provider)?;
    assert_eq!(group.members().count(), INITIAL_GROUP_SIZE);

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

    let add_result = add_members(
        &mut group,
        &alice_provider,
        &alice_signer,
        &[new_member_key_package],
    )?;
    group.merge_pending_commit(&alice_provider)?;
    assert_eq!(group.members().count(), FINAL_GROUP_SIZE);

    let external_ratchet_tree = if requires_external_ratchet_tree(ciphersuite) {
        export_ratchet_tree(&group)?
    } else {
        Vec::new()
    };
    let welcome_bytes = add_result.welcome.len();
    let external_ratchet_tree_bytes = external_ratchet_tree.len();

    Ok(SizeRow {
        ciphersuite: ciphersuite_name(ciphersuite),
        initial_group_size: INITIAL_GROUP_SIZE,
        final_group_size: FINAL_GROUP_SIZE,
        ratchet_tree_mode: if requires_external_ratchet_tree(ciphersuite) {
            "external"
        } else {
            "embedded"
        },
        key_package_bytes,
        welcome_bytes,
        commit_bytes: add_result.commit.len(),
        group_info_bytes: add_result.group_info.as_ref().map_or(0, Vec::len),
        external_ratchet_tree_bytes,
        joiner_input_bytes: welcome_bytes + external_ratchet_tree_bytes,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_one_addition_after_a_ninety_nine_member_bootstrap() {
        let row =
            measure_add_one_member_sizes(Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87)
                .expect("the single-member-add scenario should succeed");

        assert_eq!(row.initial_group_size, 99);
        assert_eq!(row.final_group_size, 100);
        assert_eq!(
            row.joiner_input_bytes,
            row.welcome_bytes + row.external_ratchet_tree_bytes
        );
        assert!(row.commit_bytes > 0);
        assert!(row.welcome_bytes > 0);
        assert!(row.external_ratchet_tree_bytes > 0);
    }
}
