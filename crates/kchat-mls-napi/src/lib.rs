#![deny(clippy::all)]

pub mod error;

use kchat_mls::{
    CreateCustomProposalArgs, GroupPendingOperation, GroupStatusConnection,
    OP_JOIN_BY_EXTERNAL_COMMIT, OP_NONE, create_custom_proposal, delete_group_status,
    get_group_pending_operation, insert_or_update_group_status, open_group_status_connection,
    process_all_messages, process_custom_proposal,
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
use secrecy::SecretString;
use uq_openmls::{
    core::{self, DEFAULT_CIPHERSUITE},
    provider::SqliteProvider,
};

use crate::error::Error;

impl From<Error> for napi::Error {
    fn from(e: Error) -> Self {
        napi::Error::new(napi::Status::GenericFailure, e.to_string())
    }
}

#[napi]
pub struct UqMls {
    client_id: String,
    ciphersuite: u16,
    wire_format_policy: WireFormatPolicy,
    use_ratchet_tree_extension: bool,
    max_past_epochs: u16,
    out_of_order_tolerance: u32,
    maximum_forward_distance: u32,
    conn: GroupStatusConnection,
    provider: SqliteProvider,
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
    pub current_epoch: i64,
}

impl From<core::AddMembersResult> for AddMembersResult {
    fn from(value: core::AddMembersResult) -> Self {
        Self {
            commit: value.commit,
            welcome: value.welcome,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
        }
    }
}

#[napi(object)]
pub struct RemoveMembersResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i64,
}

impl From<core::RemoveMembersResult> for RemoveMembersResult {
    fn from(value: core::RemoveMembersResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
        }
    }
}

#[napi(object)]
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

#[napi(object)]
pub struct QueuedProposal {
    pub proposal: Proposal,
    pub sender: String,
    pub current_epoch: i64,
}

impl From<core::QueuedProposal> for QueuedProposal {
    fn from(value: core::QueuedProposal) -> Self {
        Self {
            proposal: value.proposal.into(),
            sender: value.sender,
            current_epoch: value.current_epoch as i64,
        }
    }
}

#[napi(object)]
pub struct ProcessOperationMessageResult {
    pub commit: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
}

impl From<core::ProcessOperationMessageResult> for ProcessOperationMessageResult {
    fn from(value: core::ProcessOperationMessageResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
        }
    }
}

#[napi(object)]
pub struct ProcessManyOperationMessagesResult {
    pub current_epoch: i64,
}

impl From<core::ProcessManyOperationMessagesResult> for ProcessManyOperationMessagesResult {
    fn from(value: core::ProcessManyOperationMessagesResult) -> Self {
        Self {
            current_epoch: value.current_epoch as i64,
        }
    }
}

#[napi(object)]
pub struct JoinByExternalCommitResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i64,
}

impl From<core::JoinByExternalCommitResult> for JoinByExternalCommitResult {
    fn from(value: core::JoinByExternalCommitResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
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

impl From<core::LeaveGroupResult> for LeaveGroupResult {
    fn from(value: core::LeaveGroupResult) -> Self {
        Self {
            proposal: value.proposal,
        }
    }
}

#[napi(object)]
pub struct UpdateLeafNodeResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i64,
}

impl From<core::UpdateLeafNodeResult> for UpdateLeafNodeResult {
    fn from(value: core::UpdateLeafNodeResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
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

#[napi(object)]
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

#[napi(object)]
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
    pub current_epoch: i64,
    pub pending_epoch: i64,
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
    pub current_epoch: i64,
    pub current_tree_hash: Vec<u8>,
    pub pending_epoch: i64,
    pub pending_tree_hash: Vec<u8>,
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
    pub deleted_groups: Vec<String>,
}

#[napi(object)]
pub struct CustomProposal {
    pub mls_client_id: String,
    pub mls_fingerprint: String,
    pub group_id: String,
    pub proposal_type: String,
}

#[napi(object)]
pub struct ReAddResult {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i64,
}

impl From<core::ReAddResult> for ReAddResult {
    fn from(value: core::ReAddResult) -> Self {
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
    pub tree_hash: Vec<u8>,
}

impl UqMls {
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
        let conn = open_group_status_connection(&group_storage_path)
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(Self {
            client_id,
            ciphersuite: DEFAULT_CIPHERSUITE.into(),
            wire_format_policy: WireFormatPolicy::PureCiphertext,
            use_ratchet_tree_extension: true,
            max_past_epochs,
            out_of_order_tolerance,
            maximum_forward_distance,
            conn,
            provider: SqliteProvider::new(&storage_path, &secret)
                .map_err(|e| Error::Mls(e.to_string()))?,
        })
    }

    #[napi]
    pub fn generate_signature_key(&self) -> napi::Result<SignaturePublicKey> {
        let signer = core::generate_signature_key(&self.provider, self.ciphersuite()?)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(SignaturePublicKey {
            public: signer.public().to_vec(),
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
        let mut result = GenerateKeyPackagesResult {
            key_packages: Vec::new(),
        };
        for _ in 0..quantity {
            result.key_packages.push(
                core::generate_key_package(
                    &self.client_id,
                    &self.provider,
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
        if core::group(&self.provider, &group_id).is_ok() {
            return Err(Error::GroupIsAlreadyExisted.into());
        }

        let ciphersuite = self.ciphersuite()?;
        let config = MlsGroupCreateConfig::builder()
            .wire_format_policy(self.wire_format_policy())
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
            .max_past_epochs(self.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.out_of_order_tolerance,
                self.maximum_forward_distance,
            ))
            .build();

        let _ = self
            .provider
            .transaction(|tx_provider| {
                core::create_group(
                    tx_provider,
                    &self.client_id,
                    &group_id,
                    ciphersuite,
                    &config,
                    public_key.clone(),
                )
            })
            .map_err(|e| Error::Mls(e.to_string()))?;

        let _ = insert_or_update_group_status(
            &self.conn,
            &group_id,
            GroupPendingOperation::CreateGroup,
        );

        Ok(())
    }

    #[napi]
    pub fn add_members(
        &self,
        group_id: String,
        key_packages: Vec<Vec<u8>>,
    ) -> napi::Result<AddMembersResult> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::add_members(&mut mls_group, tx_provider, &signer, &key_packages)
            })
            .map_err(|e| Error::Mls(e.to_string()))?;

        let mut current_pending_operation = GroupPendingOperation::None;
        if let Ok(op) = get_group_pending_operation(&self.conn, &group_id) {
            current_pending_operation = op.into();
        }

        if current_pending_operation == GroupPendingOperation::None {
            let _ = insert_or_update_group_status(
                &self.conn,
                &group_id,
                GroupPendingOperation::UpdateTree,
            );
        }

        Ok(result.into())
    }

    #[napi]
    pub fn remove_members(
        &self,
        group_id: String,
        member_ids: Vec<String>,
    ) -> napi::Result<RemoveMembersResult> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::remove_members(
                    &mut mls_group,
                    tx_provider,
                    &signer,
                    &member_ids
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<&str>>(),
                )
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ =
            insert_or_update_group_status(&self.conn, &group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    #[napi]
    pub fn process_welcome(&self, welcome: Vec<u8>) -> napi::Result<()> {
        let _ = self
            .provider
            .transaction(|tx_provider| {
                core::process_welcome(
                    tx_provider,
                    &welcome,
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
                .map(|_| ())
            })
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(())
    }

    #[napi]
    pub fn process_operation_message(
        &self,
        group_id: String,
        message: Vec<u8>,
    ) -> napi::Result<ProcessOperationMessageResult> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::process_operation_message(&mut mls_group, tx_provider, &signer, &message)
            })
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn process_many_operation_messages(
        &self,
        group_id: String,
        messages: Vec<Vec<u8>>,
    ) -> napi::Result<ProcessManyOperationMessagesResult> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::process_many_operation_messages(
                    &mut mls_group,
                    tx_provider,
                    &signer,
                    &messages,
                    None,
                )
            })
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn process_application_message(
        &self,
        group_id: String,
        message: Vec<u8>,
    ) -> napi::Result<ProcessApplicationMessageResult> {
        let mut mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        let result = core::process_application_message(&mut mls_group, &self.provider, &message)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn process_proposal_message(
        &self,
        group_id: String,
        message: Vec<u8>,
    ) -> napi::Result<QueuedProposal> {
        let mut mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        let queued_proposal =
            core::process_proposal_message(&mut mls_group, &self.provider, &message)
                .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(queued_proposal.into())
    }

    #[napi]
    pub fn encrypt_message(&self, group_id: String, message: Vec<u8>) -> napi::Result<Vec<u8>> {
        let mut mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;
        let signer = core::group_signer(&mls_group, &self.provider)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(
            core::encrypt_message(&mut mls_group, &self.provider, &signer, &message)
                .map_err(|e| Error::Mls(e.to_string()))?,
        )
    }

    #[napi]
    pub fn export_group_info(&self, group_id: String) -> napi::Result<Vec<u8>> {
        let mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;
        let signer = core::group_signer(&mls_group, &self.provider)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(core::export_group_info(&mls_group, &self.provider, &signer)
            .map_err(|e| Error::Mls(e.to_string()))?)
    }

    #[napi]
    pub fn join_by_external_commit(
        &self,
        group_id: String,
        group_info: Vec<u8>,
        public_key: Option<Vec<u8>>,
    ) -> napi::Result<JoinByExternalCommitResult> {
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

        let result = self
            .provider
            .transaction(|tx_provider| {
                core::join_by_external_commit(
                    tx_provider,
                    &self.client_id,
                    &group_info,
                    ciphersuite,
                    &config,
                    public_key.clone(),
                )
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ = insert_or_update_group_status(
            &self.conn,
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

        Ok(args
            .iter()
            .map(|arg| {
                match self.provider.transaction(|tx_provider| {
                    core::join_by_external_commit(
                        tx_provider,
                        &self.client_id,
                        &arg.group_info,
                        ciphersuite,
                        &config,
                        public_key.clone(),
                    )
                }) {
                    Ok(result) => {
                        let _ = insert_or_update_group_status(
                            &self.conn,
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
        let mut mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;
        let signer = core::group_signer(&mls_group, &self.provider)
            .map_err(|e| Error::Mls(e.to_string()))?;

        let result = core::leave_group(&mut mls_group, &self.provider, &signer)
            .map_err(|e| Error::Mls(e.to_string()))?;

        Ok(result.into())
    }

    #[napi]
    pub fn update_leaf_node(&self, group_id: String) -> napi::Result<UpdateLeafNodeResult> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::update_leaf_node(&mut mls_group, tx_provider, &signer)
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ =
            insert_or_update_group_status(&self.conn, &group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    #[napi]
    pub fn readd(
        &self,
        group_id: String,
        member_ids: Vec<String>,
        key_packages: Vec<Vec<u8>>,
    ) -> napi::Result<ReAddResult> {
        if let Some(op) = get_group_pending_operation(&self.conn, &group_id).unwrap_or(None) {
            if !op.eq(OP_NONE) {
                return Err(Error::ReAdd(format!("There is a pending operation: {}", op)).into());
            }
        }

        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::readd(
                    &mut mls_group,
                    tx_provider,
                    &signer,
                    &member_ids
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<&str>>(),
                    &key_packages,
                )
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ =
            insert_or_update_group_status(&self.conn, &group_id, GroupPendingOperation::UpdateTree);

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
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                core::merge_pending_commit(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ = insert_or_update_group_status(&self.conn, &group_id, GroupPendingOperation::None);

        Ok(())
    }

    #[napi]
    pub fn clear_pending_commit(&self, group_id: String) -> napi::Result<()> {
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                core::clear_pending_commit(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ = insert_or_update_group_status(&self.conn, &group_id, GroupPendingOperation::None);

        Ok(())
    }

    #[napi]
    pub fn clear_pending_proposals(&self, group_id: String) -> napi::Result<()> {
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                core::clear_pending_proposals(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ = insert_or_update_group_status(&self.conn, &group_id, GroupPendingOperation::None);

        Ok(())
    }

    #[napi]
    pub fn pending_commit(&self, group_id: String) -> napi::Result<Option<PendingCommitResult>> {
        let mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        Ok(core::pending_commit(&mls_group).map(|commit| commit.into()))
    }

    #[napi]
    pub fn pending_proposals(&self, group_id: String) -> napi::Result<PendingProposalsResult> {
        let mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

        Ok(core::pending_proposals(&mls_group).into())
    }

    #[napi]
    pub fn group_epoch(&self, group_id: String) -> napi::Result<WrappedGroupEpochResult> {
        let pending_operation = get_group_pending_operation(&self.conn, &group_id).unwrap_or(None);

        Ok(match core::group(&self.provider, &group_id) {
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
        Ok(group_ids
            .iter()
            .map(|group_id| {
                let pending_operation =
                    get_group_pending_operation(&self.conn, group_id).unwrap_or(None);
                match core::group(&self.provider, group_id) {
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
        let pending_operation = get_group_pending_operation(&self.conn, &group_id).unwrap_or(None);

        Ok(match core::group(&self.provider, &group_id) {
            Ok(group) => WrappedGroupContextResult {
                group_id: group_id.to_owned(),
                current_epoch: group.epoch().as_u64() as i64,
                pending_epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
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
                current_epoch: -1,
                pending_epoch: -1,
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
        Ok(group_ids
            .iter()
            .map(|group_id| {
                let pending_operation =
                    get_group_pending_operation(&self.conn, group_id).unwrap_or(None);
                match core::group(&self.provider, group_id) {
                    Ok(group) => WrappedGroupContextResult {
                        group_id: group_id.to_owned(),
                        current_epoch: group.epoch().as_u64() as i64,
                        pending_epoch: if pending_operation
                            == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned())
                        {
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
                        current_epoch: -1,
                        pending_epoch: -1,
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
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &group_id)?;
                core::delete_group(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Mls(e.to_string()))?;
        let _ = delete_group_status(&self.conn, &group_id);

        Ok(())
    }

    #[napi]
    pub fn members(&self, group_id: String) -> napi::Result<Vec<String>> {
        let mls_group =
            core::group(&self.provider, &group_id).map_err(|e| Error::Mls(e.to_string()))?;

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
    pub fn process_custom_proposal_message(
        &self,
        custom_proposal: Vec<u8>,
    ) -> napi::Result<Option<CustomProposal>> {
        Ok(
            process_custom_proposal(&custom_proposal).map(|result| CustomProposal {
                mls_client_id: result.mls_client_id,
                mls_fingerprint: result.mls_fingerprint,
                group_id: result.group_id,
                proposal_type: result.proposal_type.to_string(),
            }),
        )
    }

    #[napi]
    pub fn process_all_messages(
        &self,
        args: ProcessAllMessagesArgs,
    ) -> napi::Result<ProcessAllMessagesResult> {
        let result = process_all_messages(
            &self.conn,
            &self.provider,
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
                        current_epoch: msg.current_epoch,
                        current_tree_hash: msg.current_tree_hash.to_owned(),
                        pending_epoch: msg.pending_epoch,
                        pending_tree_hash: msg.pending_tree_hash.to_owned(),
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
            None,
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
            deleted_groups: result.deleted_groups,
        })
    }
}
