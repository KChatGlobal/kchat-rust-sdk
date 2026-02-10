use openmls::{
    group::{MlsGroupCreateConfig, MlsGroupJoinConfig},
    test_utils::OpenMlsRustCrypto,
};
use uq_openmls::core::{
    AddMembersResult, DEFAULT_CIPHERSUITE, add_members, create_group, generate_key_package,
    merge_pending_commit, process_welcome,
};

pub fn init_members(member_ids: &[&str]) -> Vec<(String, OpenMlsRustCrypto, Vec<u8>)> {
    let mut members = Vec::new();
    for id in member_ids {
        let provider = OpenMlsRustCrypto::default();
        let key_package =
            generate_key_package(id, &provider, DEFAULT_CIPHERSUITE, false, None).unwrap();
        members.push((id.to_string(), provider, key_package));
    }

    members
}

pub fn init_group_with_members(
    member_ids: &[&str],
    group_id: &str,
    config: MlsGroupCreateConfig,
) -> Vec<(String, OpenMlsRustCrypto)> {
    // Init members
    let members = init_members(member_ids);
    let (first_user_id, first_provider, _) = &members[0];

    let mut member_key_packages = Vec::new();
    for (_, _, key_package) in &members[1..] {
        member_key_packages.push(key_package.clone());
    }

    // first member create group
    create_group(
        first_provider,
        first_user_id,
        group_id,
        DEFAULT_CIPHERSUITE,
        &config,
        None,
    )
    .unwrap();

    // first member add others
    let AddMembersResult { welcome, .. } =
        add_members(first_provider, group_id, &member_key_packages).unwrap();
    merge_pending_commit(first_provider, group_id).unwrap();

    // Others process welcome
    for (_, member_provider, _) in &members[1..] {
        process_welcome(
            member_provider,
            &welcome.clone(),
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(config.wire_format_policy())
                .use_ratchet_tree_extension(config.use_ratchet_tree_extension())
                .max_past_epochs(config.max_past_epochs())
                .build(),
        )
        .unwrap();
    }

    members
        .into_iter()
        .map(|(id, provider, _)| (id, provider))
        .collect()
}
