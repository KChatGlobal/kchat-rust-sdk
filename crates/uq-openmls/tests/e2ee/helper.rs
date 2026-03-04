use openmls::{
    group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig},
    test_utils::OpenMlsRustCrypto,
};
use openmls_traits::OpenMlsProvider;
use uq_openmls::core::{
    AddMembersResult, DEFAULT_CIPHERSUITE, LeaveGroupResult, ProcessApplicationMessageResult,
    ProcessOperationMessageResult, ReAddResult, RemoveMembersResult, UpdateLeafNodeResult,
    add_members as core_add_members, create_group, delete_group as core_delete_group,
    encrypt_message as core_encrypt_message, export_group_info as core_export_group_info,
    generate_key_package, group as load_group, group_signer as core_group_signer,
    leave_group as core_leave_group, merge_pending_commit as core_merge_pending_commit,
    process_application_message as core_process_application_message,
    process_operation_message as core_process_operation_message, process_welcome,
    readd as core_readd, remove_members as core_remove_members,
    update_leaf_node as core_update_leaf_node,
};
use uq_openmls::error::Error;

fn with_group<Provider: OpenMlsProvider, R>(
    provider: &Provider,
    group_id: &str,
    f: impl FnOnce(&mut MlsGroup) -> Result<R, Error>,
) -> Result<R, Error> {
    let mut group = load_group(provider, group_id)?;
    f(&mut group)
}

pub fn add_members<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
    key_package_ins: &[Vec<u8>],
) -> Result<AddMembersResult, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_add_members(group, provider, &signer, key_package_ins)
    })
}

pub fn merge_pending_commit<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
) -> Result<(), Error> {
    with_group(provider, group_id, |group| {
        core_merge_pending_commit(group, provider)
    })
}

pub fn process_operation_message<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
    message: &[u8],
) -> Result<ProcessOperationMessageResult, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_process_operation_message(group, provider, &signer, message)
    })
}

pub fn process_application_message<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
    message: &[u8],
) -> Result<ProcessApplicationMessageResult, Error> {
    with_group(provider, group_id, |group| {
        core_process_application_message(group, provider, message)
    })
}

pub fn encrypt_message<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_encrypt_message(group, provider, &signer, message)
    })
}

pub fn export_group_info<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
) -> Result<Vec<u8>, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_export_group_info(group, provider, &signer)
    })
}

pub fn remove_members<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
    member_ids: &[&str],
) -> Result<RemoveMembersResult, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_remove_members(group, provider, &signer, member_ids)
    })
}

pub fn leave_group<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
) -> Result<LeaveGroupResult, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_leave_group(group, provider, &signer)
    })
}

pub fn update_leaf_node<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
) -> Result<UpdateLeafNodeResult, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_update_leaf_node(group, provider, &signer)
    })
}

pub fn readd<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
    member_ids: &[&str],
    key_package_ins: &[Vec<u8>],
) -> Result<ReAddResult, Error> {
    with_group(provider, group_id, |group| {
        let signer = core_group_signer(group, provider)?;
        core_readd(group, provider, &signer, member_ids, key_package_ins)
    })
}

pub fn delete_group<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
) -> Result<(), Error> {
    with_group(provider, group_id, |group| {
        core_delete_group(group, provider)
    })
}

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
    let mut first_group = load_group(first_provider, group_id).unwrap();
    let signer = core_group_signer(&first_group, first_provider).unwrap();
    let AddMembersResult { welcome, .. } = core_add_members(
        &mut first_group,
        first_provider,
        &signer,
        &member_key_packages,
    )
    .unwrap();
    core_merge_pending_commit(&mut first_group, first_provider).unwrap();

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
