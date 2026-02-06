use kchat_mls::{
    CreateCustomProposalArgs, GroupPendingOperation, OP_JOIN_BY_EXTERNAL_COMMIT,
    create_custom_proposal, delete_group_status, get_group_pending_operation, initialize,
    insert_or_update_group_status, process_all_messages,
};
use openmls::{
    group::{
        MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
        MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY, WireFormatPolicy as OpenMlsWireFormatPolicy,
    },
    prelude::{BasicCredential, Ciphersuite, SenderRatchetConfiguration},
};
use rusqlite::Connection;
use secrecy::SecretString;
use uq_openmls::{
    core::{self, DEFAULT_CIPHERSUITE},
    provider::SqliteProvider,
};

use crate::error::Error;

#[derive(uniffi::Object)]
pub struct UqMls {
    client_id: String,
    storage_path: String,
    group_storage_path: String,
    ciphersuite: u16,
    wire_format_policy: WireFormatPolicy,
    use_ratchet_tree_extension: bool,
    max_past_epochs: u16,
    secret: Option<SecretString>,
    out_of_order_tolerance: u32,
    maximum_forward_distance: u32,
}

impl UqMls {
    fn provider(&self) -> Result<SqliteProvider, Error> {
        Ok(SqliteProvider::new(&self.storage_path, &self.secret)?)
    }

    fn ciphersuite(&self) -> Result<Ciphersuite, Error> {
        Ok(Ciphersuite::try_from(self.ciphersuite)?)
    }

    fn wire_format_policy(&self) -> OpenMlsWireFormatPolicy {
        match self.wire_format_policy {
            WireFormatPolicy::PurePlaintext => PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
            WireFormatPolicy::PureCiphertext => PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
            WireFormatPolicy::MixedPlaintext => MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
            WireFormatPolicy::MixedCiphertext => MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum WireFormatPolicy {
    PurePlaintext,
    PureCiphertext,
    MixedPlaintext,
    MixedCiphertext,
}

#[derive(uniffi::Record, Default)]
pub struct SignaturePublicKey {
    pub public: Vec<u8>,
    pub signature_scheme: u16,
}

#[derive(uniffi::Record, Default)]
pub struct GenerateKeyPackagesResult {
    pub key_packages: Vec<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct AddMembersResult {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

impl From<core::AddMembersResult> for AddMembersResult {
    fn from(value: core::AddMembersResult) -> Self {
        AddMembersResult {
            commit: value.commit,
            welcome: value.welcome,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
        }
    }
}

#[derive(uniffi::Record)]
pub struct RemoveMembersResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

impl From<core::RemoveMembersResult> for RemoveMembersResult {
    fn from(value: core::RemoveMembersResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ProcessOperationMessageResult {
    pub commit: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
}

impl From<core::ProcessOperationMessageResult> for ProcessOperationMessageResult {
    fn from(value: core::ProcessOperationMessageResult) -> Self {
        ProcessOperationMessageResult {
            commit: value.commit,
            group_info: value.group_info,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ProcessApplicationMessageResult {
    pub message: Vec<u8>,
}

impl From<core::ProcessApplicationMessageResult> for ProcessApplicationMessageResult {
    fn from(value: core::ProcessApplicationMessageResult) -> Self {
        Self {
            message: value.message,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ProcessManyOperationMessagesResult {
    pub current_epoch: u64,
}

impl From<core::ProcessManyOperationMessagesResult> for ProcessManyOperationMessagesResult {
    fn from(value: core::ProcessManyOperationMessagesResult) -> Self {
        Self {
            current_epoch: value.current_epoch,
        }
    }
}

#[derive(uniffi::Record)]
pub struct QueuedProposal {
    pub proposal: Proposal,
    pub sender: String,
    pub current_epoch: u64,
}

impl From<core::QueuedProposal> for QueuedProposal {
    fn from(value: core::QueuedProposal) -> Self {
        Self {
            proposal: value.proposal.into(),
            sender: value.sender,
            current_epoch: value.current_epoch,
        }
    }
}

#[derive(uniffi::Record)]
pub struct JoinByExternalCommitResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

impl From<core::JoinByExternalCommitResult> for JoinByExternalCommitResult {
    fn from(value: core::JoinByExternalCommitResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ReAddResult {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

impl From<core::ReAddResult> for ReAddResult {
    fn from(value: core::ReAddResult) -> Self {
        Self {
            welcome: value.welcome,
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
        }
    }
}

#[derive(uniffi::Record)]
pub struct JoinByExternalCommitArgs {
    pub group_id: String,
    pub group_info: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct WrappedJoinByExternalCommitResult {
    pub group_id: String,
    pub result: Option<JoinByExternalCommitResult>,
    pub err: Option<String>,
}

#[derive(uniffi::Record)]
pub struct LeaveGroupResult {
    pub proposal: Vec<u8>,
}

impl From<core::LeaveGroupResult> for LeaveGroupResult {
    fn from(value: core::LeaveGroupResult) -> Self {
        Self {
            proposal: value.proposal,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ProposeReAddResult {
    pub proposal: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct ProposeReAddRequest {
    pub mls_fingerprint: String,
}

#[derive(uniffi::Record)]
pub struct UpdateLeafNodeResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
}

impl From<core::UpdateLeafNodeResult> for UpdateLeafNodeResult {
    fn from(value: core::UpdateLeafNodeResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
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

impl From<core::Proposal> for Proposal {
    fn from(value: core::Proposal) -> Self {
        match value {
            core::Proposal::Add => Self::Add,
            core::Proposal::Update => Self::Update,
            core::Proposal::Remove => Self::Remove,
            core::Proposal::PreSharedKey => Self::PreSharedKey,
            core::Proposal::ReInit => Self::ReInit,
            core::Proposal::ExternalInit => Self::ExternalInit,
            core::Proposal::GroupContextExtensions => Self::GroupContextExtensions,
            core::Proposal::AppAck => Self::AppAck,
            core::Proposal::SelfRemove => Self::SelfRemove,
            core::Proposal::Custom => Self::Custom,
        }
    }
}

#[derive(uniffi::Record)]
pub struct PendingCommitResult {
    pub proposal_queue: Vec<Proposal>,
}

impl From<core::PendingCommitResult> for PendingCommitResult {
    fn from(value: core::PendingCommitResult) -> Self {
        Self {
            proposal_queue: value
                .proposal_queue
                .iter()
                .map(|&proposal| proposal.into())
                .collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct WrappedGroupEpochResult {
    pub group_id: String,
    pub epoch: i64,
    pub err: Option<String>,
    pub pending_operation: Option<String>,
}

#[derive(uniffi::Record)]
pub struct PendingProposalsResult {
    pub proposal_queue: Vec<Proposal>,
}

impl From<core::PendingProposalsResult> for PendingProposalsResult {
    fn from(value: core::PendingProposalsResult) -> Self {
        Self {
            proposal_queue: value
                .proposal_queue
                .iter()
                .map(|&proposal| proposal.into())
                .collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct ProcessAllMessagesArgs {
    pub group_messages: Vec<AllMessagesOfGroupArgs>,
}

#[derive(uniffi::Record)]
pub struct AllMessagesOfGroupArgs {
    pub group_id: String,
    pub messages: Vec<MlsMessage>,
}

#[derive(uniffi::Record)]
pub struct MlsMessage {
    pub blob: Vec<u8>,
    pub epoch: u64,
    pub sender: String,
    pub message_type: String,
}

#[derive(uniffi::Record)]
pub struct GroupResult {
    pub group_id: String,
    pub members_to_remove: Vec<MemberInfo>,
    pub members_to_readd: Vec<MemberInfo>,
}

#[derive(uniffi::Record, Debug, Eq, PartialEq, Hash, Clone)]
pub struct MemberInfo {
    pub mls_client_id: String,
    pub mls_fingerprint: String,
}

#[derive(uniffi::Record)]
pub struct ProcessAllMessagesResult {
    pub group_results: Vec<GroupResult>,
    pub deleted_groups: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct CustomProposal {
    pub mls_client_id: String,
    pub mls_fingerprint: String,
    pub group_id: String,
    pub proposal_type: String,
}

#[derive(uniffi::Record)]
pub struct GetPendingCreationGroupsResult {
    pub group_ids: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct ProcessPendingCreationsArgs {
    groups: Vec<PendingCreationGroup>,
}

#[derive(uniffi::Record)]
pub struct PendingCreationGroup {
    pub group_id: String,
    pub group_info: Vec<u8>,
}

#[uniffi::export]
impl UqMls {
    #[uniffi::constructor]
    pub fn new(
        client_id: String,
        storage_path: String,
        group_storage_path: String,
        max_past_epochs: u16,
        password: Option<String>,
        out_of_order_tolerance: u32,
        maximum_forward_distance: u32,
    ) -> Result<UqMls, Error> {
        let secret = password.map(SecretString::from);
        let conn = Connection::open(&group_storage_path)?;
        let _ = initialize(&conn);

        Ok(UqMls {
            client_id,
            storage_path,
            group_storage_path,
            ciphersuite: DEFAULT_CIPHERSUITE.into(),
            wire_format_policy: WireFormatPolicy::PureCiphertext,
            use_ratchet_tree_extension: true,
            max_past_epochs,
            secret,
            out_of_order_tolerance,
            maximum_forward_distance,
        })
    }

    pub fn generate_signature_key(&self) -> Result<SignaturePublicKey, Error> {
        let signer = core::generate_signature_key(&self.provider()?, self.ciphersuite()?)?;

        Ok(SignaturePublicKey {
            public: signer.public().to_vec(),
            signature_scheme: signer.signature_scheme() as u16,
        })
    }

    pub fn generate_key_packages(
        &self,
        quantity: u16,
        last_resort: bool,
        public_key: Option<Vec<u8>>,
    ) -> Result<GenerateKeyPackagesResult, Error> {
        let provider = self.provider()?;

        let mut result = GenerateKeyPackagesResult::default();
        for _ in 0..quantity {
            result.key_packages.push(core::generate_key_package(
                &self.client_id,
                &provider,
                self.ciphersuite()?,
                last_resort,
                public_key.clone(),
            )?);
        }

        Ok(result)
    }

    pub fn create_group(&self, group_id: &str, public_key: Option<Vec<u8>>) -> Result<(), Error> {
        let provider = self.provider()?;

        if let Ok(_) = core::group(&provider, group_id) {
            return Err(Error::GroupIsAlreadyExisted);
        }

        core::create_group(
            &provider,
            &self.client_id,
            group_id,
            self.ciphersuite()?,
            &MlsGroupCreateConfig::builder()
                .wire_format_policy(self.wire_format_policy())
                .ciphersuite(self.ciphersuite()?)
                .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                .max_past_epochs(self.max_past_epochs as usize)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                    self.out_of_order_tolerance,
                    self.maximum_forward_distance,
                ))
                .build(),
            public_key,
        )?;

        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(&conn, group_id, GroupPendingOperation::CreateGroup);

        Ok(())
    }

    pub fn add_members(
        &self,
        group_id: &str,
        key_packages: &[Vec<u8>],
    ) -> Result<AddMembersResult, Error> {
        let provider = self.provider()?;

        let result = core::add_members(&provider, group_id, key_packages)?;
        let conn = Connection::open(&self.group_storage_path)?;

        let mut current_pending_operation = GroupPendingOperation::None;
        if let Ok(op) = get_group_pending_operation(&conn, group_id) {
            current_pending_operation = op.into();
        }

        if current_pending_operation == GroupPendingOperation::None {
            let _ =
                insert_or_update_group_status(&conn, group_id, GroupPendingOperation::UpdateTree);
        }

        Ok(result.into())
    }

    pub fn readd(
        &self,
        group_id: &str,
        member_ids: &[String],
        key_packages: &[Vec<u8>],
    ) -> Result<ReAddResult, Error> {
        let provider = self.provider()?;

        let result = core::readd(
            &provider,
            group_id,
            &member_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<&str>>(),
            key_packages,
        )?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(&conn, group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    pub fn propose_readd(
        &self,
        group_id: &str,
        request: ProposeReAddRequest,
    ) -> Result<ProposeReAddResult, Error> {
        Ok(ProposeReAddResult {
            proposal: create_custom_proposal(
                &self.client_id,
                group_id,
                CreateCustomProposalArgs {
                    mls_fingerprint: request.mls_fingerprint.to_owned(),
                    custom_proposal_type: kchat_mls::CustomProposalType::ReAdd,
                },
            ),
        })
    }

    pub fn remove_members(
        &self,
        group_id: &str,
        member_ids: &[String],
    ) -> Result<RemoveMembersResult, Error> {
        let provider = self.provider()?;

        let result = core::remove_members(
            &provider,
            group_id,
            &member_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<&str>>(),
        )?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(&conn, group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    pub fn process_welcome(&self, welcome: &[u8]) -> Result<(), Error> {
        let provider = self.provider()?;

        core::process_welcome(
            &provider,
            welcome,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(self.wire_format_policy())
                .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                .max_past_epochs(self.max_past_epochs as usize)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                    self.out_of_order_tolerance,
                    self.maximum_forward_distance,
                ))
                .build(),
        )?;

        Ok(())
    }

    pub fn process_operation_message(
        &self,
        group_id: &str,
        message: &[u8],
    ) -> Result<ProcessOperationMessageResult, Error> {
        let provider = self.provider()?;

        let result = core::process_operation_message(&provider, group_id, message)?;

        Ok(result.into())
    }

    pub fn process_application_message(
        &self,
        group_id: &str,
        message: &[u8],
    ) -> Result<ProcessApplicationMessageResult, Error> {
        let provider = self.provider()?;

        let result = core::process_application_message(&provider, group_id, message)?;

        Ok(result.into())
    }

    pub fn process_many_operation_messages(
        &self,
        group_id: &str,
        messages: &[Vec<u8>],
    ) -> Result<ProcessManyOperationMessagesResult, Error> {
        let provider = self.provider()?;

        let result = core::process_many_operation_messages(&provider, group_id, messages)?;

        Ok(result.into())
    }

    pub fn process_proposal_message(
        &self,
        group_id: &str,
        message: &[u8],
    ) -> Result<QueuedProposal, Error> {
        let provider = self.provider()?;

        let queued_proposal = core::process_proposal_message(&provider, group_id, message)?;

        Ok(queued_proposal.into())
    }

    pub fn process_custom_proposal_message(
        &self,
        custom_proposal: &[u8],
    ) -> Option<CustomProposal> {
        let result = kchat_mls::process_custom_proposal(custom_proposal);

        result.map(|result| CustomProposal {
            mls_client_id: result.mls_client_id,
            mls_fingerprint: result.mls_fingerprint,
            group_id: result.group_id,
            proposal_type: result.proposal_type.to_string(),
        })
    }

    pub fn encrypt_message(&self, group_id: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        let provider = self.provider()?;

        Ok(core::encrypt_message(&provider, group_id, message)?)
    }

    pub fn export_group_info(&self, group_id: &str) -> Result<Vec<u8>, Error> {
        let provider = self.provider()?;

        Ok(core::export_group_info(&provider, group_id)?)
    }

    pub fn join_by_external_commit(
        &self,
        group_id: &str,
        group_info: &[u8],
        public_key: Option<Vec<u8>>,
    ) -> Result<JoinByExternalCommitResult, Error> {
        let provider = self.provider()?;

        let result = core::join_by_external_commit(
            &provider,
            &self.client_id,
            group_info,
            self.ciphersuite()?,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(self.wire_format_policy())
                .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                .max_past_epochs(self.max_past_epochs as usize)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                    self.out_of_order_tolerance,
                    self.maximum_forward_distance,
                ))
                .build(),
            public_key,
        )?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(
            &conn,
            group_id,
            GroupPendingOperation::JoinByExternalCommit,
        );

        Ok(result.into())
    }

    pub fn batch_join_by_external_commit(
        &self,
        args: &[JoinByExternalCommitArgs],
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<WrappedJoinByExternalCommitResult>, Error> {
        let provider = self.provider()?;
        let ciphersuite = self.ciphersuite()?;
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(self.wire_format_policy())
            .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
            .max_past_epochs(self.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.out_of_order_tolerance,
                self.maximum_forward_distance,
            ))
            .build();

        let conn = Connection::open(&self.group_storage_path)?;
        Ok(args
            .iter()
            .map(|arg| {
                match core::join_by_external_commit(
                    &provider,
                    &self.client_id,
                    &arg.group_info,
                    ciphersuite,
                    &config,
                    public_key.clone(),
                ) {
                    Ok(result) => {
                        let _ = insert_or_update_group_status(
                            &conn,
                            &arg.group_id,
                            GroupPendingOperation::JoinByExternalCommit,
                        );
                        WrappedJoinByExternalCommitResult {
                            group_id: arg.group_id.to_owned(),
                            result: Some(result.into()),
                            err: None,
                        }
                    }
                    Err(err) => WrappedJoinByExternalCommitResult {
                        group_id: arg.group_id.to_owned(),
                        result: None,
                        err: Some(err.to_string()),
                    },
                }
            })
            .collect())
    }

    pub fn leave_group(&self, group_id: &str) -> Result<LeaveGroupResult, Error> {
        let provider = self.provider()?;

        let result = core::leave_group(&provider, group_id)?;

        Ok(result.into())
    }

    pub fn update_leaf_node(&self, group_id: &str) -> Result<UpdateLeafNodeResult, Error> {
        let provider = self.provider()?;

        let result = core::update_leaf_node(&provider, group_id)?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(&conn, group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    pub fn merge_pending_commit(&self, group_id: &str) -> Result<(), Error> {
        let provider = self.provider()?;

        core::merge_pending_commit(&provider, group_id)?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(&conn, group_id, GroupPendingOperation::None);

        Ok(())
    }

    pub fn clear_pending_commit(&self, group_id: &str) -> Result<(), Error> {
        let provider = self.provider()?;

        core::clear_pending_commit(&provider, group_id)?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(&conn, group_id, GroupPendingOperation::None);

        Ok(())
    }

    pub fn clear_pending_proposals(&self, group_id: &str) -> Result<(), Error> {
        let provider = self.provider()?;

        core::clear_pending_proposals(&provider, group_id)?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = insert_or_update_group_status(&conn, group_id, GroupPendingOperation::None);

        Ok(())
    }

    pub fn pending_commit(&self, group_id: &str) -> Result<Option<PendingCommitResult>, Error> {
        let provider = self.provider()?;

        let pending_commit = core::pending_commit(&provider, group_id)?;

        Ok(pending_commit.map(|commit| commit.into()))
    }

    pub fn pending_proposals(&self, group_id: &str) -> Result<PendingProposalsResult, Error> {
        let provider = self.provider()?;

        let result = core::pending_proposals(&provider, group_id)?;

        Ok(result.into())
    }

    pub fn group_epoch(&self, group_id: &str) -> Result<WrappedGroupEpochResult, Error> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)?;
        let pending_operation = get_group_pending_operation(&conn, group_id).unwrap_or(None);

        Ok(match core::group(&provider, group_id) {
            Ok(group) => WrappedGroupEpochResult {
                group_id: group_id.to_owned(),
                epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                    group.epoch().as_u64() as i64 - 1
                } else {
                    group.epoch().as_u64() as i64
                },
                err: None,
                pending_operation,
            },
            Err(err) => WrappedGroupEpochResult {
                group_id: group_id.to_owned(),
                epoch: -1,
                err: Some(err.to_string()),
                pending_operation: None,
            },
        })
    }

    pub fn group_epochs(
        &self,
        group_ids: &[String],
    ) -> Result<Vec<WrappedGroupEpochResult>, Error> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)?;

        Ok(group_ids
            .iter()
            .map(|group_id| {
                let pending_operation =
                    get_group_pending_operation(&conn, group_id).unwrap_or(None);
                match core::group(&provider, group_id) {
                    Ok(group) => WrappedGroupEpochResult {
                        group_id: group_id.to_owned(),
                        epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                            group.epoch().as_u64() as i64 - 1
                        } else {
                            group.epoch().as_u64() as i64
                        },
                        err: None,
                        pending_operation,
                    },
                    Err(err) => WrappedGroupEpochResult {
                        group_id: group_id.to_owned(),
                        epoch: -1,
                        err: Some(err.to_string()),
                        pending_operation: None,
                    },
                }
            })
            .collect())
    }

    pub fn delete_group(&self, group_id: &str) -> Result<(), Error> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)?;
        let _ = delete_group_status(&conn, group_id);

        Ok(core::delete_group(&provider, group_id)?)
    }

    pub fn members(&self, group_id: &str) -> Result<Vec<String>, Error> {
        let provider = self.provider()?;

        let group = core::group(&provider, group_id)?;

        let members = group
            .members()
            .filter_map(|member| {
                if let Ok(credential) = BasicCredential::try_from(member.credential) {
                    if let Ok(member_id) = String::from_utf8(credential.identity().to_vec()) {
                        return Some(member_id);
                    }
                }

                None
            })
            .collect::<Vec<String>>();

        Ok(members)
    }

    pub fn process_all_messages(
        &self,
        args: ProcessAllMessagesArgs,
    ) -> Result<ProcessAllMessagesResult, Error> {
        let provider = self.provider()?;

        let conn = Connection::open(&self.group_storage_path)?;
        let result = process_all_messages(
            &conn,
            &provider,
            kchat_mls::ProcessAllMessagesArgs {
                group_messages: args
                    .group_messages
                    .iter()
                    .map(|msg| kchat_mls::AllMessagesOfGroupArgs {
                        group_id: msg.group_id.to_owned(),
                        messages: msg
                            .messages
                            .iter()
                            .map(|msg| kchat_mls::MlsMessage {
                                blob: msg.blob.to_owned(),
                                epoch: msg.epoch,
                                sender: msg.sender.to_owned(),
                                message_type: msg.message_type.as_str().into(),
                            })
                            .collect(),
                    })
                    .collect(),
            },
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(self.wire_format_policy())
                .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                .max_past_epochs(self.max_past_epochs as usize)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                    self.out_of_order_tolerance,
                    self.maximum_forward_distance,
                ))
                .build(),
        )?;

        Ok(ProcessAllMessagesResult {
            group_results: result
                .group_results
                .iter()
                .map(|group_result| GroupResult {
                    group_id: group_result.group_id.to_owned(),
                    members_to_remove: group_result
                        .members_to_remove
                        .iter()
                        .map(|member| MemberInfo {
                            mls_client_id: member.mls_client_id.to_owned(),
                            mls_fingerprint: member.mls_fingerprint.to_owned(),
                        })
                        .collect(),
                    members_to_readd: group_result
                        .members_to_readd
                        .iter()
                        .map(|member| MemberInfo {
                            mls_client_id: member.mls_client_id.to_owned(),
                            mls_fingerprint: member.mls_fingerprint.to_owned(),
                        })
                        .collect(),
                })
                .collect(),
            deleted_groups: result.deleted_groups,
        })
    }

    pub fn get_pending_creation_groups(&self) -> Result<GetPendingCreationGroupsResult, Error> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)?;

        let result = kchat_mls::get_pending_creation_groups(&conn, &provider)?;

        Ok(GetPendingCreationGroupsResult {
            group_ids: result.group_ids,
        })
    }

    pub fn process_pending_creations(
        &self,
        args: ProcessPendingCreationsArgs,
    ) -> Result<(), Error> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)?;

        Ok(kchat_mls::process_pending_creations(
            &conn,
            &provider,
            kchat_mls::ProcessPendingCreationsArgs {
                groups: args
                    .groups
                    .iter()
                    .map(|group_data| kchat_mls::PendingCreationGroup {
                        group_id: group_data.group_id.to_owned(),
                        group_info: group_data.group_info.to_owned(),
                    })
                    .collect(),
            },
        )?)
    }
}
