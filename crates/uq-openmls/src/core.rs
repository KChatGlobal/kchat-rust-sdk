use openmls::{
    group::{
        GroupId, Member, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, ProposalStore,
        PublicGroup, StagedWelcome,
    },
    messages::proposals::Proposal as MlsProposal,
    prelude::{
        BasicCredential, Capabilities, Ciphersuite, ExtensionType, KeyPackage, KeyPackageIn,
        LeafNodeIndex, LeafNodeParameters, Lifetime, MlsMessageBodyIn, MlsMessageBodyOut,
        MlsMessageIn, ProcessedMessageContent, Proposal as OpenMlsProposal, ProtocolVersion,
        Sender,
        group_info::VerifiableGroupInfo,
        tls_codec::{Deserialize as _, Serialize as _},
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::{
    error::Error,
    util::{
        find_members_by_identity, get_credential_with_key, get_identity_from_key_packages,
        get_own_signature_key_from_group,
    },
};

pub const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Get the own signature key pair from a group.
///
/// Retrieves the [`SignatureKeyPair`] associated with the group's own leaf node.
/// Callers should obtain the signer once and pass it to subsequent core functions
/// that require signing, rather than each function looking it up independently.
pub fn group_signer<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
) -> Result<SignatureKeyPair, Error> {
    get_own_signature_key_from_group(group, provider)
}

/// Generate a new signature keypair.
pub fn generate_signature_key<Provider: OpenMlsProvider>(
    provider: &Provider,
    ciphersuite: Ciphersuite,
) -> Result<SignatureKeyPair, Error> {
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())?;
    signer
        .store(provider.storage())
        .map_err(|e| Error::Storage(e.to_string()))?;

    Ok(signer)
}

/// This value is used as the default lifetime if no default  lifetime is configured.
/// The value is in seconds and amounts to 36 * 28 Days, i.e. about 36 months.
const DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 60 * 60 * 24 * 28 * 36;

/// Generate new key package for the given identity.
pub fn generate_key_package<Provider: OpenMlsProvider>(
    user_id: &str,
    provider: &Provider,
    ciphersuite: Ciphersuite,
    last_resort: bool,
    public_key: Option<Vec<u8>>,
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
            .key_package_lifetime(Lifetime::new(DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS))
            .mark_as_last_resort();
    }

    let key_package = key_package_builder
        .build(ciphersuite, provider, &signer, credential_with_key)?
        .key_package()
        .clone();

    Ok(key_package.tls_serialize_detached()?)
}

/// Creates a new group with a given group ID with the creator as the only
/// member.
pub fn create_group<Provider: OpenMlsProvider>(
    provider: &Provider,
    creator_id: &str,
    group_id: &str,
    ciphersuite: Ciphersuite,
    config: &MlsGroupCreateConfig,
    public_key: Option<Vec<u8>>,
) -> Result<MlsGroup, Error> {
    let (creator_credential, signer) =
        get_credential_with_key(creator_id, provider, ciphersuite, public_key)?;

    Ok(MlsGroup::new_with_group_id(
        provider,
        &signer,
        config,
        GroupId::from_slice(group_id.as_bytes()),
        creator_credential,
    )?)
}

#[derive(Debug)]
pub struct AddMembersResult {
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

/// Adds members to the group.
///
/// New members are added by providing a [`KeyPackage`] for each member.
///
/// This operation results in a Commit with a `path`, i.e. it includes an
/// update of the committer's leaf [`KeyPackage`].
///
/// If successful, it returns a tuple of [`MlsMessageOut`]s, where the first
/// contains the commit, the second one the [`Welcome`].
pub fn add_members<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    key_package_ins: &[Vec<u8>],
) -> Result<AddMembersResult, Error> {
    let mut key_packages = Vec::new();
    for bytes in key_package_ins {
        let key_package = KeyPackageIn::tls_deserialize_exact(bytes)?
            .validate(provider.crypto(), ProtocolVersion::default())?;
        key_packages.push(key_package);
    }

    let identities = get_identity_from_key_packages(&key_packages);
    let identities: Vec<&[u8]> = identities.iter().map(|id| id.as_slice()).collect();
    if !find_members_by_identity(&group.members().collect::<Vec<Member>>(), &identities).is_empty()
    {
        return Err(Error::SomeMembersAlreadyExistedInGroup);
    }

    let (commit, welcome, group_info) = group.add_members(provider, signer, &key_packages)?;
    let group_info = if let Some(group_info) = group_info {
        Some(group_info.tls_serialize_detached()?)
    } else {
        None
    };

    Ok(AddMembersResult {
        welcome: welcome.tls_serialize_detached()?,
        commit: commit.tls_serialize_detached()?,
        group_info,
        current_epoch: group.epoch().as_u64(),
    })
}

/// Processes welcome message
///
/// Creates a new staged welcome from a [`Welcome`] message. Returns an error
/// ([`WelcomeError::NoMatchingKeyPackage`]) if no [`KeyPackage`]
/// can be found.
/// Then consumes the [`StagedWelcome`] and returns the respective [`MlsGroup`].
pub fn process_welcome<Provider: OpenMlsProvider>(
    provider: &Provider,
    welcome: &[u8],
    config: &MlsGroupJoinConfig,
) -> Result<MlsGroup, Error> {
    let welcome = MlsMessageIn::tls_deserialize_exact(welcome)?;
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        return Err(Error::InvalidWelcomeMessage);
    };

    let staged_welcome = StagedWelcome::build_from_welcome(provider, config, welcome)?
        .replace_old_group()
        .build()?;

    Ok(staged_welcome.into_group(provider)?)
}

#[derive(Debug)]
pub struct ProcessApplicationMessageResult {
    pub message: Vec<u8>,
}

/// Processes application message.
///
/// - If the message is application message, then return message.
/// - Else return InvalidApplicationMessage error.
pub fn process_application_message<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    message: &[u8],
) -> Result<ProcessApplicationMessageResult, Error> {
    let message = MlsMessageIn::tls_deserialize_exact(message)?;
    let protocol_message = message.try_into_protocol_message()?;
    let processed_message = group.process_message(provider, protocol_message)?;

    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            Ok(ProcessApplicationMessageResult {
                message: message.into_bytes(),
            })
        }
        _ => Err(Error::InvalidApplicationMessage),
    }
}

#[derive(Debug, Default)]
pub struct ProcessOperationMessageResult {
    pub commit: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
}

/// Processes operation message.
///
/// - If the message is commit message, then merge a [`StagedCommit`] into the group after inspection.
///   As this advances the epoch of the group, it also clears any pending commits.
/// - If the message is proposal message, then creates a Commit message that covers the pending proposals.
pub fn process_operation_message<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    message: &[u8],
) -> Result<ProcessOperationMessageResult, Error> {
    let message = MlsMessageIn::tls_deserialize_exact(message)?;
    let protocol_message = message.try_into_protocol_message()?;

    let processed_message = group.process_message(provider, protocol_message)?;

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group.merge_staged_commit(provider, *staged_commit)?;

            Ok(ProcessOperationMessageResult::default())
        }
        ProcessedMessageContent::ProposalMessage(staged_proposal)
        | ProcessedMessageContent::ExternalJoinProposalMessage(staged_proposal) => {
            group
                .store_pending_proposal(provider.storage(), *staged_proposal)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let (commit, _, group_info) = group.commit_to_pending_proposals(provider, signer)?;

            Ok(ProcessOperationMessageResult {
                commit: Some(commit.tls_serialize_detached()?),
                group_info: if let Some(group_info) = group_info {
                    Some(group_info.tls_serialize_detached()?)
                } else {
                    None
                },
            })
        }
        _ => Err(Error::InvalidOperationMessage),
    }
}

#[derive(Debug, Default)]
pub struct ProcessManyOperationMessagesResult {
    pub current_epoch: u64,
}

/// Process many operation message
pub fn process_many_operation_messages<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    messages: &[Vec<u8>],
    log: Option<&dyn Fn(String)>,
) -> Result<ProcessManyOperationMessagesResult, Error> {
    let emit = |msg: String| {
        if let Some(cb) = &log {
            cb(msg);
        }
    };

    emit(format!("processing {} operation messages", messages.len()));

    let mut current_epoch = group.epoch();
    for (i, message) in messages.iter().enumerate() {
        emit(format!(
            "processing message {}/{}, epoch {}",
            i + 1,
            messages.len(),
            current_epoch.as_u64()
        ));
        let message = MlsMessageIn::tls_deserialize_exact(message)?;
        let protocol_message = message.try_into_protocol_message()?;
        let processed_message = group.process_message(provider, protocol_message)?;

        match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                emit("merging staged commit".to_owned());
                group.merge_staged_commit(provider, *staged_commit)?;
            }
            ProcessedMessageContent::ProposalMessage(staged_proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(staged_proposal) => {
                emit("storing and committing pending proposal".to_owned());
                group
                    .store_pending_proposal(provider.storage(), *staged_proposal)
                    .map_err(|e| Error::Storage(e.to_string()))?;
                group.commit_to_pending_proposals(provider, signer)?;
            }
            _ => (),
        }

        current_epoch = group.epoch();
    }

    emit(format!(
        "finished processing, final epoch {}",
        current_epoch.as_u64()
    ));

    Ok(ProcessManyOperationMessagesResult {
        current_epoch: current_epoch.as_u64(),
    })
}

pub struct QueuedProposal {
    pub proposal: Proposal,
    pub sender: String,
    pub current_epoch: u64,
}

/// Decrypt proposal message and return `QueuedProposal` data.
pub fn process_proposal_message<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    message: &[u8],
) -> Result<QueuedProposal, Error> {
    let message = MlsMessageIn::tls_deserialize_exact(message)?;
    let protocol_message = message.try_into_protocol_message()?;
    let processed_message = group.process_message(provider, protocol_message)?;

    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        processed_message.into_content()
    {
        let proposal: Proposal = staged_proposal.proposal().into();
        if let Sender::Member(member_leaf_node) = staged_proposal.sender() {
            if let Some(queued_proposal) = group
                .member(*member_leaf_node)
                .and_then(|credential| BasicCredential::try_from(credential.to_owned()).ok())
                .and_then(|credential| String::from_utf8(credential.identity().to_vec()).ok())
                .map(|identity| QueuedProposal {
                    proposal,
                    sender: identity,
                    current_epoch: group.epoch().as_u64(),
                })
            {
                return Ok(queued_proposal);
            }
        }
    }

    Err(Error::InvalidProposalMessage)
}

/// Encrypt message, return MlsMessageOut.
pub fn encrypt_message<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let mls_message_out = group.create_message(provider, signer, message)?;

    Ok(mls_message_out.tls_serialize_detached()?)
}

/// Export group info
pub fn export_group_info<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, Error> {
    let group_info = group.export_group_info(provider.crypto(), signer, true)?;

    if let MlsMessageBodyOut::GroupInfo(group_info) = group_info.body() {
        Ok(group_info.tls_serialize_detached()?)
    } else {
        Err(Error::ExportGroupInfoInvalidExportType)
    }
}

#[derive(Debug)]
pub struct JoinByExternalCommitResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

/// Join an existing group through an External Commit.
///
/// If there is a group member in the group with the same identity as
/// this user, return error.
pub fn join_by_external_commit<Provider: OpenMlsProvider>(
    provider: &Provider,
    user_id: &str,
    group_info: &[u8],
    ciphersuite: Ciphersuite,
    config: &MlsGroupJoinConfig,
    public_key: Option<Vec<u8>>,
) -> Result<JoinByExternalCommitResult, Error> {
    let verifiable_group_info = if let Ok(verifiable_group_info) =
        VerifiableGroupInfo::tls_deserialize_exact(group_info)
    {
        verifiable_group_info
    } else if let Ok(mls_message_in) = MlsMessageIn::tls_deserialize_exact(group_info) {
        let MlsMessageBodyIn::GroupInfo(verifiable_group_info) = mls_message_in.extract() else {
            return Err(Error::InvalidGroupInfo);
        };
        verifiable_group_info
    } else {
        return Err(Error::InvalidGroupInfo);
    };

    let Some(ratchet_tree) = verifiable_group_info.extensions().ratchet_tree() else {
        return Err(Error::MissingRatchetTree);
    };
    let (public_group, _) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        ratchet_tree.ratchet_tree().to_owned(),
        verifiable_group_info.clone(),
        ProposalStore::new(),
    )?;

    if !find_members_by_identity(
        &public_group.members().collect::<Vec<Member>>(),
        &[user_id.as_bytes()],
    )
    .is_empty()
    {
        return Err(Error::CredentialIsExisted);
    }

    let (credential_with_key, signer) =
        get_credential_with_key(user_id, provider, ciphersuite, public_key)?;

    let builder = MlsGroup::external_commit_builder().with_config(config.clone());
    let (_, commit_bundle) = builder
        .build_group(provider, verifiable_group_info, credential_with_key)?
        .load_psks(provider.storage())?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)?
        .finalize(provider)?;

    let group_info = if let Some(group_info) = commit_bundle.group_info() {
        Some(group_info.tls_serialize_detached()?)
    } else {
        None
    };

    let commit = commit_bundle.into_commit();

    Ok(JoinByExternalCommitResult {
        commit: commit.tls_serialize_detached()?,
        group_info,
        current_epoch: public_group.group_context().epoch().as_u64(),
    })
}

#[derive(Debug)]
pub struct RemoveMembersResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

/// Removes members from the group.
///
/// Return commit and group_info
pub fn remove_members<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    member_ids: &[&str],
) -> Result<RemoveMembersResult, Error> {
    let member_identities: Vec<&[u8]> = member_ids.iter().map(|id| id.as_bytes()).collect();
    let member_leaf_node_indices = find_members_by_identity(
        &group.members().collect::<Vec<Member>>(),
        &member_identities,
    )
    .into_iter()
    .map(|member| member.index)
    .collect::<Vec<LeafNodeIndex>>();

    let (commit, _, group_info) =
        group.remove_members(provider, signer, &member_leaf_node_indices)?;
    let group_info = if let Some(group_info) = group_info {
        Some(group_info.tls_serialize_detached()?)
    } else {
        None
    };

    Ok(RemoveMembersResult {
        commit: commit.tls_serialize_detached()?,
        group_info,
        current_epoch: group.epoch().as_u64(),
    })
}

#[derive(Debug)]
pub struct LeaveGroupResult {
    pub proposal: Vec<u8>,
}

/// Leave group.
///
/// Return leave proposal. The member can't create a Commit message that covers this proposal,
/// as that would violate the Post-compromise Security guarantees of MLS
/// because the member would know the epoch secrets of the next epoch
pub fn leave_group<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
) -> Result<LeaveGroupResult, Error> {
    let proposal = group.leave_group(provider, signer)?;

    Ok(LeaveGroupResult {
        proposal: proposal.tls_serialize_detached()?,
    })
}

pub struct UpdateLeafNodeResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

/// Updates the own leaf node.
pub fn update_leaf_node<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
) -> Result<UpdateLeafNodeResult, Error> {
    let commit_bundle = group.self_update(provider, signer, LeafNodeParameters::default())?;

    Ok(UpdateLeafNodeResult {
        commit: commit_bundle.commit().tls_serialize_detached()?,
        group_info: if let Some(group_info) = commit_bundle.group_info() {
            Some(group_info.tls_serialize_detached()?)
        } else {
            None
        },
        current_epoch: group.epoch().as_u64(),
    })
}

/// Merge pending commit of group.
pub fn merge_pending_commit<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
) -> Result<(), Error> {
    group.merge_pending_commit(provider)?;

    Ok(())
}

/// Clear pending commit of group.
pub fn clear_pending_commit<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
) -> Result<(), Error> {
    group
        .clear_pending_commit(provider.storage())
        .map_err(|e| Error::Storage(e.to_string()))?;

    Ok(())
}

/// Clear pending proposals of group.
pub fn clear_pending_proposals<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
) -> Result<(), Error> {
    group
        .clear_pending_proposals(provider.storage())
        .map_err(|e| Error::Storage(e.to_string()))?;

    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Proposal {
    Add,
    Update,
    Remove,
    PreSharedKey,
    ReInit,
    ExternalInit,
    GroupContextExtensions,
    AppAck,
    SelfRemove,
    Custom,
}

impl From<&MlsProposal> for Proposal {
    fn from(value: &MlsProposal) -> Self {
        match value {
            OpenMlsProposal::Add(_) => Self::Add,
            OpenMlsProposal::Update(_) => Self::Update,
            OpenMlsProposal::Remove(_) => Self::Remove,
            OpenMlsProposal::PreSharedKey(_) => Self::PreSharedKey,
            OpenMlsProposal::ReInit(_) => Self::ReInit,
            OpenMlsProposal::ExternalInit(_) => Self::ExternalInit,
            OpenMlsProposal::GroupContextExtensions(_) => Self::GroupContextExtensions,
            OpenMlsProposal::SelfRemove => Self::SelfRemove,
            OpenMlsProposal::Custom(_) => Self::Custom,
        }
    }
}

#[derive(Debug)]
pub struct PendingCommitResult {
    pub proposal_queue: Vec<Proposal>,
}

/// Get group pending commit
pub fn pending_commit(group: &MlsGroup) -> Option<PendingCommitResult> {
    group
        .pending_commit()
        .map(|staged_commit| PendingCommitResult {
            proposal_queue: staged_commit
                .queued_proposals()
                .map(|proposal| proposal.proposal().into())
                .collect(),
        })
}

pub struct PendingProposalsResult {
    pub proposal_queue: Vec<Proposal>,
}

/// Get group pending commit
pub fn pending_proposals(group: &MlsGroup) -> PendingProposalsResult {
    PendingProposalsResult {
        proposal_queue: group
            .pending_proposals()
            .map(|p| p.proposal().into())
            .collect(),
    }
}

/// Get MLS group
pub fn group<Provider: OpenMlsProvider>(
    provider: &Provider,
    group_id: &str,
) -> Result<MlsGroup, Error> {
    let Some(group) = MlsGroup::load(
        provider.storage(),
        &GroupId::from_slice(group_id.as_bytes()),
    )
    .map_err(|e| Error::Storage(e.to_string()))?
    else {
        return Err(Error::GroupIsNotExisted);
    };

    Ok(group)
}

/// Delete group
pub fn delete_group<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
) -> Result<(), Error> {
    group
        .delete(provider.storage())
        .map_err(|e| Error::Storage(e.to_string()))
}

#[derive(Debug)]
pub struct ReAddResult {
    pub welcome: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

/// Re-add
pub fn readd<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    member_ids: &[&str],
    key_package_ins: &[Vec<u8>],
) -> Result<ReAddResult, Error> {
    let member_identities: Vec<&[u8]> = member_ids.iter().map(|id| id.as_bytes()).collect();
    let member_leaf_node_indices = find_members_by_identity(
        &group.members().collect::<Vec<Member>>(),
        &member_identities,
    )
    .into_iter()
    .map(|member| member.index.u32())
    .collect::<Vec<u32>>();

    let mut our_partition = Vec::new();
    for member in group.members() {
        if !member_leaf_node_indices.contains(&member.index.u32()) {
            our_partition.push(member.index);
        }
    }

    let builder = group
        .recover_fork_by_readding(&our_partition)
        .map_err(|e| Error::ReAdd(e.to_string()))?;

    let mut key_packages = Vec::new();
    for bytes in key_package_ins {
        let key_package = KeyPackageIn::tls_deserialize_exact(bytes)?
            .validate(provider.crypto(), ProtocolVersion::default())?;
        key_packages.push(key_package);
    }

    let readd_messages = builder
        .provide_key_packages(key_packages)
        .load_psks(provider.storage())?
        .build(provider.rand(), provider.crypto(), signer, |_| true)?
        .stage_commit(provider)?;

    let (commit, welcome, group_info) = readd_messages.clone().into_messages();
    let welcome = if let Some(welcome) = welcome {
        Some(welcome.tls_serialize_detached()?)
    } else {
        None
    };
    let group_info = if let Some(group_info) = group_info {
        if let MlsMessageBodyOut::GroupInfo(group_info) = group_info.body() {
            Some(group_info.tls_serialize_detached()?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(ReAddResult {
        welcome,
        commit: commit.tls_serialize_detached()?,
        group_info,
        current_epoch: group.epoch().as_u64(),
    })
}
