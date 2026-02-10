#![deny(clippy::all)]

pub mod error;

use kchat_mls::{
    CreateCustomProposalArgs, GroupPendingOperation, OP_JOIN_BY_EXTERNAL_COMMIT,
    create_custom_proposal, delete_group_status, get_group_pending_operation, initialize,
    insert_or_update_group_status, process_all_messages,
};
use napi_derive::napi;
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
    core::{
        AddMembersResult as MlsAddMembersResult, DEFAULT_CIPHERSUITE,
        JoinByExternalCommitResult as MlsJoinByExternalCommitResult,
        LeaveGroupResult as MlsLeaveGroupResult, PendingCommitResult as MlsPendingCommitResult,
        PendingProposalsResult as MlsPendingProposalsResult,
        ProcessApplicationMessageResult as MlsProcessApplicationMessageResult,
        ProcessManyOperationMessagesResult as MlsProcessManyOperationMessagesResult,
        ProcessOperationMessageResult as MlsProcessOperationMessageResult, Proposal as MlsProposal,
        QueuedProposal as MlsQueuedProposal, RemoveMembersResult as MlsRemoveMembersResult,
        UpdateLeafNodeResult as MlsUpdateLeafNodeResult, add_members, clear_pending_commit,
        clear_pending_proposals, create_group, delete_group, encrypt_message, export_group_info,
        generate_key_package, generate_signature_key, group, join_by_external_commit, leave_group,
        merge_pending_commit, pending_commit, pending_proposals, process_application_message,
        process_many_operation_messages, process_operation_message, process_proposal_message,
        process_welcome, remove_members, update_leaf_node,
    },
    provider::SqliteProvider,
};

use crate::error::Error;

impl From<Error> for napi::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::MissingSignatureKeyPair => {
                napi::Error::new(napi::Status::InvalidArg, e.to_string())
            }
            Error::Storage(_) => napi::Error::new(napi::Status::Unknown, e.to_string()),
            Error::Mls(mls) => napi::Error::new(napi::Status::InvalidArg, &mls),
        }
    }
}

#[napi]
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

#[napi]
pub enum WireFormatPolicy {
    PurePlaintext,
    PureCiphertext,
    MixedPlaintext,
    MixedCiphertext,
}

#[napi(object)]
pub struct SignaturePublicKey {
    pub public: Vec<u8>,
    pub signature_scheme: u16,
}

#[napi(object)]
pub struct GenerateKeyPackagesResult {
    pub key_packages: Vec<Vec<u8>>,
}

#[napi(object)]
pub struct AddMembersResult {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i32,
}

impl From<MlsAddMembersResult> for AddMembersResult {
    fn from(value: MlsAddMembersResult) -> Self {
        Self {
            commit: value.commit,
            welcome: value.welcome,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i32,
        }
    }
}

#[napi(object)]
pub struct RemoveMembersResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i32,
}

impl From<MlsRemoveMembersResult> for RemoveMembersResult {
    fn from(value: MlsRemoveMembersResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i32,
        }
    }
}

#[napi(object)]
pub struct ProcessApplicationMessageResult {
    pub message: Vec<u8>,
}

impl From<MlsProcessApplicationMessageResult> for ProcessApplicationMessageResult {
    fn from(value: MlsProcessApplicationMessageResult) -> Self {
        Self {
            message: value.message,
        }
    }
}

#[napi(object)]
pub struct QueuedProposal {
    pub proposal: Proposal,
    pub sender: String,
    pub current_epoch: i32,
}

impl From<MlsQueuedProposal> for QueuedProposal {
    fn from(value: MlsQueuedProposal) -> Self {
        Self {
            proposal: value.proposal.into(),
            sender: value.sender,
            current_epoch: value.current_epoch as i32,
        }
    }
}

#[napi(object)]
pub struct ProcessOperationMessageResult {
    pub commit: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
}

impl From<MlsProcessOperationMessageResult> for ProcessOperationMessageResult {
    fn from(value: MlsProcessOperationMessageResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
        }
    }
}

#[napi(object)]
pub struct ProcessManyOperationMessagesResult {
    pub current_epoch: i32,
}

impl From<MlsProcessManyOperationMessagesResult> for ProcessManyOperationMessagesResult {
    fn from(value: MlsProcessManyOperationMessagesResult) -> Self {
        Self {
            current_epoch: value.current_epoch as i32,
        }
    }
}

#[napi(object)]
pub struct JoinByExternalCommitResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i32,
}

impl From<MlsJoinByExternalCommitResult> for JoinByExternalCommitResult {
    fn from(value: MlsJoinByExternalCommitResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i32,
        }
    }
}

#[napi(object)]
pub struct JoinByExternalCommitArgs {
    pub group_id: String,
    pub group_info: Vec<u8>,
}

#[napi(object)]
pub struct WrappedJoinByExternalCommitResult {
    pub group_id: String,
    pub result: Option<JoinByExternalCommitResult>,
    pub err: Option<String>,
}

#[napi(object)]
pub struct LeaveGroupResult {
    pub proposal: Vec<u8>,
}

impl From<MlsLeaveGroupResult> for LeaveGroupResult {
    fn from(value: MlsLeaveGroupResult) -> Self {
        Self {
            proposal: value.proposal,
        }
    }
}

#[napi(object)]
pub struct UpdateLeafNodeResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i32,
}

impl From<MlsUpdateLeafNodeResult> for UpdateLeafNodeResult {
    fn from(value: MlsUpdateLeafNodeResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i32,
        }
    }
}

#[napi]
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

impl From<MlsProposal> for Proposal {
    fn from(value: MlsProposal) -> Self {
        match value {
            MlsProposal::Add => Self::Add,
            MlsProposal::Update => Self::Update,
            MlsProposal::Remove => Self::Remove,
            MlsProposal::PreSharedKey => Self::PreSharedKey,
            MlsProposal::ReInit => Self::ReInit,
            MlsProposal::ExternalInit => Self::ExternalInit,
            MlsProposal::GroupContextExtensions => Self::GroupContextExtensions,
            MlsProposal::AppAck => Self::AppAck,
            MlsProposal::SelfRemove => Self::SelfRemove,
            MlsProposal::Custom => Self::Custom,
        }
    }
}

#[napi(object)]
pub struct PendingCommitResult {
    pub proposal_queue: Vec<Proposal>,
}

impl From<MlsPendingCommitResult> for PendingCommitResult {
    fn from(value: MlsPendingCommitResult) -> Self {
        Self {
            proposal_queue: value
                .proposal_queue
                .iter()
                .map(|&proposal| proposal.into())
                .collect(),
        }
    }
}

#[napi(object)]
pub struct PendingProposalsResult {
    pub proposal_queue: Vec<Proposal>,
}

impl From<MlsPendingProposalsResult> for PendingProposalsResult {
    fn from(value: MlsPendingProposalsResult) -> Self {
        Self {
            proposal_queue: value
                .proposal_queue
                .iter()
                .map(|&proposal| proposal.into())
                .collect(),
        }
    }
}

#[napi(object)]
pub struct WrappedGroupEpochResult {
    pub group_id: String,
    pub epoch: i64,
    pub tree_hash: Vec<u8>,
    pub err: Option<String>,
    pub pending_operation: Option<String>,
}

#[napi(object)]
pub struct WrappedGroupContextResult {
    pub group_id: String,
    pub epoch: i64,
    pub tree_hash: Vec<u8>,
    pub err: Option<String>,
    pub pending_operation: Option<String>,
}

#[napi(object)]
pub struct ProcessAllMessagesArgs {
    pub group_messages: Vec<AllMessagesOfGroupArgs>,
}

#[napi(object)]
pub struct AllMessagesOfGroupArgs {
    pub group_id: String,
    pub messages: Vec<MlsMessage>,
}

#[napi(object)]
pub struct MlsMessage {
    pub blob: Vec<u8>,
    pub epoch: i64,
    pub sender: String,
    pub message_type: String,
}

#[napi(object)]
pub struct GroupResult {
    pub group_id: String,
    pub members_to_remove: Vec<MemberInfo>,
    pub members_to_readd: Vec<MemberInfo>,
}

#[napi(object)]
pub struct MemberInfo {
    pub mls_client_id: String,
    pub mls_fingerprint: String,
}

#[napi(object)]
pub struct ProcessAllMessagesResult {
    pub group_results: Vec<GroupResult>,
}

#[napi(object)]
pub struct ReAddResult {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i64,
}

impl From<uq_openmls::core::ReAddResult> for ReAddResult {
    fn from(value: uq_openmls::core::ReAddResult) -> Self {
        Self {
            welcome: value.welcome,
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
        }
    }
}

#[napi(object)]
pub struct ProposeReAddResult {
    pub proposal: Vec<u8>,
}

#[napi(object)]
pub struct ProposeReAddRequest {
    pub mls_fingerprint: String,
}

#[napi(object)]
pub struct GetPendingCreationGroupsResult {
    pub group_ids: Vec<String>,
}

#[napi(object)]
pub struct ProcessPendingCreationsArgs {
    pub groups: Vec<PendingCreationGroup>,
}

#[napi(object)]
pub struct PendingCreationGroup {
    pub group_id: String,
    pub group_info: Vec<u8>,
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

#[napi]
impl UqMls {
    #[napi(constructor)]
    pub fn new(
        client_id: String,
        storage_path: String,
        group_storage_path: String,
        max_past_epochs: u16,
        password: Option<String>,
        out_of_order_tolerance: u32,
        maximum_forward_distance: u32,
    ) -> napi::Result<Self> {
        let secret = password.map(SecretString::from);
        let conn =
            Connection::open(&group_storage_path).map_err(|e| Error::Storage(e.to_string()))?;
        let _ = initialize(&conn);

        Ok(Self {
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

    #[napi]
    pub fn generate_signature_key(&self) -> napi::Result<SignaturePublicKey> {
        let signer = generate_signature_key(&self.provider()?, self.ciphersuite()?)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(SignaturePublicKey {
            public: signer.to_public_vec(),
            signature_scheme: signer.signature_scheme() as u16,
        })
    }

    #[napi]
    pub fn generate_key_packages(
        &self,
        quantity: u16,
        last_resort: bool,
        public_key: Option<Vec<u8>>,
    ) -> napi::Result<GenerateKeyPackagesResult> {
        let provider = self.provider()?;

        let mut result = GenerateKeyPackagesResult {
            key_packages: Vec::new(),
        };
        for _ in 0..quantity {
            result.key_packages.push(
                generate_key_package(
                    &self.client_id,
                    &provider,
                    self.ciphersuite()?,
                    last_resort,
                    public_key.clone(),
                )
                .map_err(|e| Error::Mls(e.to_string()))?,
            );
        }

        Ok(result)
    }

    #[napi]
    pub fn create_group(&self, group_id: String, public_key: Option<Vec<u8>>) -> napi::Result<()> {
        let provider = self.provider()?;

        create_group(
            &provider,
            &self.client_id,
            &group_id,
            self.ciphersuite()?,
            &MlsGroupCreateConfig::builder()
                .wire_format_policy(self.wire_format_policy())
                .ciphersuite(self.ciphersuite()?)
                .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                .max_past_epochs(self.max_past_epochs as usize)
                .build(),
            public_key,
        )
        .map_err(|e| Error::Mls(e.to_string()))?;

        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::CreateGroup);

        Ok(())
    }

    #[napi]
    pub fn add_members(
        &self,
        group_id: String,
        key_packages: Vec<Vec<u8>>,
    ) -> napi::Result<AddMembersResult> {
        let provider = self.provider()?;

        let result = add_members(&provider, &group_id, &key_packages)
            .map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    #[napi]
    pub fn remove_members(
        &self,
        group_id: String,
        member_ids: Vec<String>,
    ) -> napi::Result<RemoveMembersResult> {
        let provider = self.provider()?;

        let result = remove_members(
            &provider,
            &group_id,
            &member_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<&str>>(),
        )
        .map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    #[napi]
    pub fn process_welcome(&self, welcome: Vec<u8>) -> napi::Result<()> {
        let provider = self.provider()?;

        process_welcome(
            &provider,
            &welcome,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(self.wire_format_policy())
                .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                .max_past_epochs(self.max_past_epochs as usize)
                .build(),
        )
        .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(())
    }

    #[napi]
    pub fn process_operation_message(
        &self,
        group_id: String,
        message: Vec<u8>,
    ) -> napi::Result<ProcessOperationMessageResult> {
        let provider = self.provider()?;

        let result = process_operation_message(&provider, &group_id, &message)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn process_many_operation_messages(
        &self,
        group_id: String,
        messages: Vec<Vec<u8>>,
    ) -> napi::Result<ProcessManyOperationMessagesResult> {
        let provider = self.provider()?;

        let result = process_many_operation_messages(&provider, &group_id, &messages)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn process_application_message(
        &self,
        group_id: String,
        message: Vec<u8>,
    ) -> napi::Result<ProcessApplicationMessageResult> {
        let provider = self.provider()?;

        let result = process_application_message(&provider, &group_id, &message)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn process_proposal_message(
        &self,
        group_id: String,
        message: Vec<u8>,
    ) -> napi::Result<QueuedProposal> {
        let provider = self.provider()?;

        let queued_proposal = process_proposal_message(&provider, &group_id, &message)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(queued_proposal.into())
    }

    #[napi]
    pub fn encrypt_message(&self, group_id: String, message: Vec<u8>) -> napi::Result<Vec<u8>> {
        let provider = self.provider()?;

        Ok(encrypt_message(&provider, &group_id, &message)
            .map_err(|e| Error::Mls(e.to_string()))?)
    }

    #[napi]
    pub fn export_group_info(&self, group_id: String) -> napi::Result<Vec<u8>> {
        let provider = self.provider()?;

        Ok(export_group_info(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?)
    }

    #[napi]
    pub fn join_by_external_commit(
        &self,
        group_id: String,
        group_info: Vec<u8>,
        public_key: Option<Vec<u8>>,
    ) -> napi::Result<JoinByExternalCommitResult> {
        let provider = self.provider()?;

        let result = join_by_external_commit(
            &provider,
            &self.client_id,
            &group_info,
            self.ciphersuite()?,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(self.wire_format_policy())
                .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                .max_past_epochs(self.max_past_epochs as usize)
                .build(),
            public_key,
        )
        .map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(
            &conn,
            &group_id,
            GroupPendingOperation::JoinByExternalCommit,
        );

        Ok(result.into())
    }

    #[napi]
    pub fn batch_join_by_external_commit(
        &self,
        args: Vec<JoinByExternalCommitArgs>,
        public_key: Option<Vec<u8>>,
    ) -> napi::Result<Vec<WrappedJoinByExternalCommitResult>> {
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

        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(args
            .iter()
            .map(|arg| {
                match join_by_external_commit(
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

    #[napi]
    pub fn leave_group(&self, group_id: String) -> napi::Result<LeaveGroupResult> {
        let provider = self.provider()?;

        let result = leave_group(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn update_leaf_node(&self, group_id: String) -> napi::Result<UpdateLeafNodeResult> {
        let provider = self.provider()?;

        let result =
            update_leaf_node(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    #[napi]
    pub fn readd(
        &self,
        group_id: String,
        member_ids: Vec<String>,
        key_packages: Vec<Vec<u8>>,
    ) -> napi::Result<ReAddResult> {
        let provider = self.provider()?;

        let result = uq_openmls::core::readd(
            &provider,
            &group_id,
            &member_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<&str>>(),
            &key_packages,
        )
        .map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    #[napi]
    pub fn propose_readd(
        &self,
        group_id: String,
        request: ProposeReAddRequest,
    ) -> napi::Result<ProposeReAddResult> {
        Ok(ProposeReAddResult {
            proposal: create_custom_proposal(
                &self.client_id,
                &group_id,
                CreateCustomProposalArgs {
                    mls_fingerprint: request.mls_fingerprint,
                    custom_proposal_type: kchat_mls::CustomProposalType::ReAdd,
                },
            ),
        })
    }

    #[napi]
    pub fn merge_pending_commit(&self, group_id: String) -> napi::Result<()> {
        let provider = self.provider()?;

        merge_pending_commit(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::None);

        Ok(())
    }

    #[napi]
    pub fn clear_pending_commit(&self, group_id: String) -> napi::Result<()> {
        let provider = self.provider()?;

        clear_pending_commit(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::None);

        Ok(())
    }

    #[napi]
    pub fn clear_pending_proposals(&self, group_id: String) -> napi::Result<()> {
        let provider = self.provider()?;

        clear_pending_proposals(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = insert_or_update_group_status(&conn, &group_id, GroupPendingOperation::None);

        Ok(())
    }

    #[napi]
    pub fn pending_commit(&self, group_id: String) -> napi::Result<Option<PendingCommitResult>> {
        let provider = self.provider()?;

        let pending_commit =
            pending_commit(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        Ok(pending_commit.map(|commit| commit.into()))
    }

    #[napi]
    pub fn pending_proposals(&self, group_id: String) -> napi::Result<PendingProposalsResult> {
        let provider = self.provider()?;

        let result =
            pending_proposals(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn group_epoch(&self, group_id: String) -> napi::Result<WrappedGroupEpochResult> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let pending_operation = get_group_pending_operation(&conn, &group_id).unwrap_or(None);

        Ok(match group(&provider, &group_id) {
            Ok(group) => WrappedGroupEpochResult {
                group_id: group_id.to_owned(),
                epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                    group.epoch().as_u64() as i64 - 1
                } else {
                    group.epoch().as_u64() as i64
                },
                tree_hash: group.tree_hash().to_vec(),
                err: None,
                pending_operation,
            },
            Err(err) => WrappedGroupEpochResult {
                group_id: group_id.to_owned(),
                epoch: -1,
                tree_hash: Vec::new(),
                err: Some(err.to_string()),
                pending_operation: None,
            },
        })
    }

    #[napi]
    pub fn group_epochs(
        &self,
        group_ids: Vec<String>,
    ) -> napi::Result<Vec<WrappedGroupEpochResult>> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(group_ids
            .iter()
            .map(|group_id| {
                let pending_operation =
                    get_group_pending_operation(&conn, group_id).unwrap_or(None);
                match group(&provider, group_id) {
                    Ok(group) => WrappedGroupEpochResult {
                        group_id: group_id.to_owned(),
                        epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                            group.epoch().as_u64() as i64 - 1
                        } else {
                            group.epoch().as_u64() as i64
                        },
                        tree_hash: group.tree_hash().to_vec(),
                        err: None,
                        pending_operation,
                    },
                    Err(err) => WrappedGroupEpochResult {
                        group_id: group_id.to_owned(),
                        epoch: -1,
                        tree_hash: Vec::new(),
                        err: Some(err.to_string()),
                        pending_operation: None,
                    },
                }
            })
            .collect())
    }

    #[napi]
    pub fn group_context(&self, group_id: String) -> napi::Result<WrappedGroupContextResult> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let pending_operation = get_group_pending_operation(&conn, &group_id).unwrap_or(None);

        Ok(match group(&provider, &group_id) {
            Ok(group) => WrappedGroupContextResult {
                group_id: group_id.to_owned(),
                epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                    group.epoch().as_u64() as i64 - 1
                } else {
                    group.epoch().as_u64() as i64
                },
                tree_hash: group.tree_hash().to_vec(),
                err: None,
                pending_operation,
            },
            Err(err) => WrappedGroupContextResult {
                group_id: group_id.to_owned(),
                epoch: -1,
                tree_hash: Vec::new(),
                err: Some(err.to_string()),
                pending_operation: None,
            },
        })
    }

    #[napi]
    pub fn group_contexts(
        &self,
        group_ids: Vec<String>,
    ) -> napi::Result<Vec<WrappedGroupContextResult>> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(group_ids
            .iter()
            .map(|group_id| {
                let pending_operation =
                    get_group_pending_operation(&conn, group_id).unwrap_or(None);
                match group(&provider, group_id) {
                    Ok(group) => WrappedGroupContextResult {
                        group_id: group_id.to_owned(),
                        epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                            group.epoch().as_u64() as i64 - 1
                        } else {
                            group.epoch().as_u64() as i64
                        },
                        tree_hash: group.tree_hash().to_vec(),
                        err: None,
                        pending_operation,
                    },
                    Err(err) => WrappedGroupContextResult {
                        group_id: group_id.to_owned(),
                        epoch: -1,
                        tree_hash: Vec::new(),
                        err: Some(err.to_string()),
                        pending_operation: None,
                    },
                }
            })
            .collect())
    }

    #[napi]
    pub fn delete_group(&self, group_id: String) -> napi::Result<()> {
        let provider = self.provider()?;
        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = delete_group_status(&conn, &group_id);

        Ok(delete_group(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?)
    }

    #[napi]
    pub fn members(&self, group_id: String) -> napi::Result<Vec<String>> {
        let provider = self.provider()?;

        let mls_group = group(&provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        let members = mls_group
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

    #[napi]
    pub fn process_all_messages(
        &self,
        args: ProcessAllMessagesArgs,
    ) -> napi::Result<ProcessAllMessagesResult> {
        let provider = self.provider()?;

        let conn = Connection::open(&self.group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
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
                                epoch: msg.epoch as u64,
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
        )
        .map_err(|e| Error::Mls(e.to_string()))?;

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
        })
    }

    pub fn get_pending_creation_groups(&self) -> Result<GetPendingCreationGroupsResult, Error> {
        let provider = self.provider()?;
        let conn =
            Connection::open(&self.group_storage_path).map_err(|e| Error::Mls(e.to_string()))?;

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
