use std::sync::Arc;

use kchat_mls::{
    CreateCustomProposalArgs, GroupPendingOperation, GroupStatusConnection,
    OP_JOIN_BY_EXTERNAL_COMMIT, OP_NONE, create_custom_proposal, delete_group_status,
    extract_jid_from_member_id, get_group_pending_operation, get_group_pending_operations_batch,
    insert_or_update_group_status, open_group_status_connection, process_all_messages,
};
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

#[uniffi::export(with_foreign)]
pub trait ProcessMessagesCallback: Send + Sync {
    fn on_trigger(&self, log: String);
}

#[derive(uniffi::Object)]
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
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::AddMembersResult> for AddMembersResult {
    fn from(value: core::AddMembersResult) -> Self {
        AddMembersResult {
            commit: value.commit,
            welcome: value.welcome,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
            pre_tree_hash: value.pre_tree_hash,
        }
    }
}

#[derive(uniffi::Record)]
pub struct RemoveMembersResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::RemoveMembersResult> for RemoveMembersResult {
    fn from(value: core::RemoveMembersResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
            pre_tree_hash: value.pre_tree_hash,
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
    pub sender: String,
    pub client_jid: Option<String>,
    pub mls_client_id: Option<String>,
    pub mls_fingerprint: Option<String>,
    pub epoch: Option<u64>,
    pub group_id: String,
    pub proposal: Proposal,
}

impl From<core::QueuedProposal> for QueuedProposal {
    fn from(value: core::QueuedProposal) -> Self {
        Self {
            group_id: value.group_id,
            proposal: value.proposal.into(),
            sender: value.sender.clone(),
            client_jid: extract_jid_from_member_id(&value.sender),
            mls_client_id: Some(value.sender),
            mls_fingerprint: None,
            epoch: Some(value.epoch),
        }
    }
}

#[derive(uniffi::Record)]
pub struct JoinByExternalCommitResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::JoinByExternalCommitResult> for JoinByExternalCommitResult {
    fn from(value: core::JoinByExternalCommitResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
            pre_tree_hash: value.pre_tree_hash,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ReAddResult {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: u64,
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::ReAddResult> for ReAddResult {
    fn from(value: core::ReAddResult) -> Self {
        Self {
            welcome: value.welcome,
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
            pre_tree_hash: value.pre_tree_hash,
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
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::UpdateLeafNodeResult> for UpdateLeafNodeResult {
    fn from(value: core::UpdateLeafNodeResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch,
            pre_tree_hash: value.pre_tree_hash,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum Proposal {
    Add,
    Update,
    Remove,
    ReAdd,
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

impl From<kchat_mls::CustomProposalType> for Proposal {
    fn from(value: kchat_mls::CustomProposalType) -> Self {
        match value {
            kchat_mls::CustomProposalType::ReAdd => Proposal::ReAdd,
            kchat_mls::CustomProposalType::Remove => Proposal::Remove,
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
    pub tree_hash: Vec<u8>,
    pub err: Option<String>,
    pub pending_operation: Option<String>,
}

#[derive(uniffi::Record)]
pub struct WrappedGroupContextResult {
    pub group_id: String,
    pub current_epoch: i64,
    pub pending_epoch: i64,
    pub tree_hash: Vec<u8>,
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
    pub current_epoch: i64,
    pub current_tree_hash: Vec<u8>,
    pub pending_epoch: i64,
    pub pending_tree_hash: Vec<u8>,
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
    pub error: Option<GroupError>,
}

#[derive(uniffi::Enum)]
pub enum GroupErrorCode {
    Storage,
    Aead,
    ProcessCommit,
}

#[derive(uniffi::Record)]
pub struct GroupError {
    pub error_code: GroupErrorCode,
    pub error_message: String,
}

impl From<kchat_mls::GroupError> for GroupError {
    fn from(value: kchat_mls::GroupError) -> Self {
        Self {
            error_code: match value.error_code {
                kchat_mls::GroupErrorCode::Storage => GroupErrorCode::Storage,
                kchat_mls::GroupErrorCode::Aead => GroupErrorCode::Aead,
                kchat_mls::GroupErrorCode::ProcessCommit => GroupErrorCode::ProcessCommit,
            },
            error_message: value.error_message,
        }
    }
}

#[derive(uniffi::Record, Debug, Eq, PartialEq, Hash, Clone)]
pub struct MemberInfo {
    pub client_jid: Option<String>,
    pub mls_client_id: Option<String>,
    pub mls_fingerprint: Option<String>,
}

#[derive(uniffi::Record)]
pub struct ProcessAllMessagesResult {
    pub group_results: Vec<GroupResult>,
    pub deleted_groups: Vec<String>,
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
        let conn = open_group_status_connection(&group_storage_path)?;

        Ok(UqMls {
            client_id,
            ciphersuite: DEFAULT_CIPHERSUITE.into(),
            wire_format_policy: WireFormatPolicy::PureCiphertext,
            use_ratchet_tree_extension: true,
            max_past_epochs,
            out_of_order_tolerance,
            maximum_forward_distance,
            conn,
            provider: SqliteProvider::new(&storage_path, &secret)?,
        })
    }

    pub fn generate_signature_key(&self) -> Result<SignaturePublicKey, Error> {
        let signer = core::generate_signature_key(&self.provider, self.ciphersuite()?)?;

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
        let mut result = GenerateKeyPackagesResult::default();
        for _ in 0..quantity {
            result.key_packages.push(core::generate_key_package(
                &self.client_id,
                &self.provider,
                self.ciphersuite()?,
                last_resort,
                public_key.clone(),
            )?);
        }

        Ok(result)
    }

    pub fn create_group(&self, group_id: &str, public_key: Option<Vec<u8>>) -> Result<(), Error> {
        if let Ok(_) = core::group(&self.provider, group_id) {
            return Err(Error::GroupIsAlreadyExisted);
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
                    group_id,
                    ciphersuite,
                    &config,
                    public_key.clone(),
                )
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        let _ =
            insert_or_update_group_status(&self.conn, group_id, GroupPendingOperation::CreateGroup);

        Ok(())
    }

    pub fn add_members(
        &self,
        group_id: &str,
        key_packages: &[Vec<u8>],
    ) -> Result<AddMembersResult, Error> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::add_members(&mut mls_group, tx_provider, &signer, key_packages)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        let mut current_pending_operation = GroupPendingOperation::None;
        if let Ok(op) = get_group_pending_operation(&self.conn, group_id) {
            current_pending_operation = op.into();
        }

        if current_pending_operation == GroupPendingOperation::None {
            let _ = insert_or_update_group_status(
                &self.conn,
                group_id,
                GroupPendingOperation::UpdateTree,
            );
        }

        Ok(result.into())
    }

    pub fn readd(
        &self,
        group_id: &str,
        member_ids: &[String],
        key_packages: &[Vec<u8>],
    ) -> Result<ReAddResult, Error> {
        if let Some(op) = get_group_pending_operation(&self.conn, group_id).unwrap_or(None) {
            if !op.eq(OP_NONE) {
                return Err(Error::ReAdd(format!(
                    "There is a pending operation: {}",
                    op
                )));
            }
        }

        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::readd(
                    &mut mls_group,
                    tx_provider,
                    &signer,
                    &member_ids
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<&str>>(),
                    key_packages,
                )
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ =
            insert_or_update_group_status(&self.conn, group_id, GroupPendingOperation::UpdateTree);

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
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
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
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ =
            insert_or_update_group_status(&self.conn, group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    pub fn process_welcome(&self, welcome: &[u8]) -> Result<(), Error> {
        let _ = self
            .provider
            .transaction(|tx_provider| {
                core::process_welcome(
                    tx_provider,
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
                )
                .map(|_| ())
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        Ok(())
    }

    pub fn process_operation_message(
        &self,
        group_id: &str,
        message: &[u8],
    ) -> Result<ProcessOperationMessageResult, Error> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::process_operation_message(&mut mls_group, tx_provider, message)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        Ok(result.into())
    }

    pub fn process_application_message(
        &self,
        group_id: &str,
        message: &[u8],
    ) -> Result<ProcessApplicationMessageResult, Error> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::process_application_message(&mut mls_group, tx_provider, message)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        Ok(result.into())
    }

    pub fn process_many_operation_messages(
        &self,
        group_id: &str,
        messages: &[Vec<u8>],
    ) -> Result<ProcessManyOperationMessagesResult, Error> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::process_many_operation_messages(&mut mls_group, tx_provider, messages, None)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        Ok(result.into())
    }

    pub fn process_proposal_message(
        &self,
        group_id: &str,
        message: &[u8],
    ) -> Result<QueuedProposal, Error> {
        let queued_proposal = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::process_proposal_message(&mut mls_group, tx_provider, message)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        Ok(queued_proposal.into())
    }

    pub fn process_custom_proposal_message(
        &self,
        custom_proposal: &[u8],
    ) -> Option<QueuedProposal> {
        let result = kchat_mls::process_custom_proposal(custom_proposal);

        result.map(|result| QueuedProposal {
            sender: result.mls_client_id.clone().unwrap_or_default(),
            client_jid: result.client_jid,
            mls_client_id: result.mls_client_id,
            mls_fingerprint: result.mls_fingerprint,
            epoch: result.epoch,
            group_id: result.group_id,
            proposal: result.proposal_type.into(),
        })
    }

    pub fn encrypt_message(
        &self,
        group_id: &str,
        message: &[u8],
        callback: Option<Arc<dyn ProcessMessagesCallback>>,
    ) -> Result<Vec<u8>, Error> {
        let emit = |msg: String| {
            if let Some(cb) = &callback {
                cb.on_trigger(msg);
            }
        };

        emit(format!("start encrypt message, group {}", group_id));

        let encrypted = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id).map_err(|err| {
                    emit(format!(
                        "encrypt message - load group error, group {}: {}",
                        group_id, err
                    ));
                    err
                })?;
                emit(format!(
                    "encrypt message - load group done, group {}",
                    group_id
                ));

                let signer = core::group_signer(&mls_group, tx_provider).map_err(|err| {
                    emit(format!(
                        "encrypt message - get signer error, group {}: {}",
                        group_id, err
                    ));
                    err
                })?;
                emit(format!(
                    "encrypt message - get signer done, group {}",
                    group_id
                ));

                core::encrypt_message(&mut mls_group, tx_provider, &signer, message).map_err(
                    |err| {
                        emit(format!(
                            "encrypt message error, group {}: {}",
                            group_id, err
                        ));
                        err
                    },
                )
            })
            .map_err(|err| {
                emit(format!(
                    "encrypt message error, group {}: {}",
                    group_id, err
                ));
                Error::Sqlite(err.to_string())
            })?;

        emit(format!("end encrypt message, group {}", group_id));

        Ok(encrypted)
    }

    pub fn export_group_info(&self, group_id: &str) -> Result<Vec<u8>, Error> {
        let mls_group = core::group(&self.provider, group_id)?;
        let signer = core::group_signer(&mls_group, &self.provider)?;
        Ok(core::export_group_info(
            &mls_group,
            &self.provider,
            &signer,
        )?)
    }

    pub fn join_by_external_commit(
        &self,
        group_id: &str,
        group_info: &[u8],
        public_key: Option<Vec<u8>>,
    ) -> Result<JoinByExternalCommitResult, Error> {
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
                    group_info,
                    ciphersuite,
                    &config,
                    public_key.clone(),
                )
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ = insert_or_update_group_status(
            &self.conn,
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

    pub fn leave_group(&self, group_id: &str) -> Result<LeaveGroupResult, Error> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::leave_group(&mut mls_group, tx_provider, &signer)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        Ok(result.into())
    }

    pub fn update_leaf_node(&self, group_id: &str) -> Result<UpdateLeafNodeResult, Error> {
        let result = self
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                let signer = core::group_signer(&mls_group, tx_provider)?;
                core::update_leaf_node(&mut mls_group, tx_provider, &signer)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ =
            insert_or_update_group_status(&self.conn, group_id, GroupPendingOperation::UpdateTree);

        Ok(result.into())
    }

    pub fn merge_pending_commit(&self, group_id: &str) -> Result<(), Error> {
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::merge_pending_commit(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ = insert_or_update_group_status(&self.conn, group_id, GroupPendingOperation::None);

        Ok(())
    }

    pub fn clear_pending_commit(&self, group_id: &str) -> Result<(), Error> {
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::clear_pending_commit(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ = insert_or_update_group_status(&self.conn, group_id, GroupPendingOperation::None);

        Ok(())
    }

    pub fn clear_pending_proposals(&self, group_id: &str) -> Result<(), Error> {
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::clear_pending_proposals(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ = insert_or_update_group_status(&self.conn, group_id, GroupPendingOperation::None);

        Ok(())
    }

    pub fn pending_commit(&self, group_id: &str) -> Result<Option<PendingCommitResult>, Error> {
        let mls_group = core::group(&self.provider, group_id)?;
        let pending_commit = core::pending_commit(&mls_group);

        Ok(pending_commit.map(|commit| commit.into()))
    }

    pub fn pending_proposals(&self, group_id: &str) -> Result<PendingProposalsResult, Error> {
        let mls_group = core::group(&self.provider, group_id)?;
        let result = core::pending_proposals(&mls_group);

        Ok(result.into())
    }

    pub fn group_epoch(&self, group_id: &str) -> Result<WrappedGroupEpochResult, Error> {
        let pending_operation = get_group_pending_operation(&self.conn, group_id).unwrap_or(None);

        Ok(match core::group_context(&self.provider, group_id) {
            Ok(context) => WrappedGroupEpochResult {
                group_id: group_id.to_owned(),
                epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                    context.epoch().as_u64() as i64 - 1
                } else {
                    context.epoch().as_u64() as i64
                },
                tree_hash: context.tree_hash().to_vec(),
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

    pub fn group_context(&self, group_id: &str) -> Result<WrappedGroupContextResult, Error> {
        let pending_operation = get_group_pending_operation(&self.conn, group_id).unwrap_or(None);

        Ok(match core::group_context(&self.provider, group_id) {
            Ok(context) => WrappedGroupContextResult {
                group_id: group_id.to_owned(),
                current_epoch: context.epoch().as_u64() as i64,
                pending_epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                    context.epoch().as_u64() as i64 - 1
                } else {
                    context.epoch().as_u64() as i64
                },
                tree_hash: context.tree_hash().to_vec(),
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

    pub fn group_epochs(
        &self,
        group_ids: &[String],
    ) -> Result<Vec<WrappedGroupEpochResult>, Error> {
        let pending_operations = get_group_pending_operations_batch(&self.conn, group_ids)
            .unwrap_or_else(|_| std::collections::HashMap::new());
        let join_by_external_commit_op = OP_JOIN_BY_EXTERNAL_COMMIT.to_owned();

        Ok(group_ids
            .iter()
            .map(|group_id| {
                let pending_operation = pending_operations.get(group_id).cloned();
                match core::group_context(&self.provider, group_id) {
                    Ok(context) => {
                        let epoch =
                            if pending_operation.as_ref() == Some(&join_by_external_commit_op) {
                                context.epoch().as_u64() as i64 - 1
                            } else {
                                context.epoch().as_u64() as i64
                            };

                        WrappedGroupEpochResult {
                            group_id: group_id.clone(),
                            epoch,
                            tree_hash: context.tree_hash().to_vec(),
                            err: None,
                            pending_operation,
                        }
                    }
                    Err(err) => WrappedGroupEpochResult {
                        group_id: group_id.clone(),
                        epoch: -1,
                        tree_hash: Vec::new(),
                        err: Some(err.to_string()),
                        pending_operation: None,
                    },
                }
            })
            .collect())
    }

    pub fn group_contexts(
        &self,
        group_ids: &[String],
    ) -> Result<Vec<WrappedGroupContextResult>, Error> {
        let pending_operations = get_group_pending_operations_batch(&self.conn, group_ids)
            .unwrap_or_else(|_| std::collections::HashMap::new());
        let join_by_external_commit_op = OP_JOIN_BY_EXTERNAL_COMMIT.to_owned();

        Ok(group_ids
            .iter()
            .map(|group_id| {
                let pending_operation = pending_operations.get(group_id).cloned();
                match core::group_context(&self.provider, group_id) {
                    Ok(context) => {
                        let current_epoch = context.epoch().as_u64() as i64;
                        let pending_epoch =
                            if pending_operation.as_ref() == Some(&join_by_external_commit_op) {
                                current_epoch - 1
                            } else {
                                current_epoch
                            };

                        WrappedGroupContextResult {
                            group_id: group_id.clone(),
                            current_epoch,
                            pending_epoch,
                            tree_hash: context.tree_hash().to_vec(),
                            err: None,
                            pending_operation,
                        }
                    }
                    Err(err) => WrappedGroupContextResult {
                        group_id: group_id.clone(),
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

    pub fn delete_group(&self, group_id: &str) -> Result<(), Error> {
        self.provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, group_id)?;
                core::delete_group(&mut mls_group, tx_provider)
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let _ = delete_group_status(&self.conn, group_id);

        Ok(())
    }

    pub fn members(&self, group_id: &str) -> Result<Vec<String>, Error> {
        let group = core::group(&self.provider, group_id)?;

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
        callback: Option<Arc<dyn ProcessMessagesCallback>>,
    ) -> Result<ProcessAllMessagesResult, Error> {
        let log_fn = callback.as_ref().map(|cb| {
            let cb = cb.clone();
            move |msg: String| cb.on_trigger(msg)
        });

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
                                epoch: msg.epoch,
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
            log_fn.as_ref().map(|f| f as &dyn Fn(String)),
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
                            client_jid: member.client_jid.to_owned(),
                            mls_client_id: member.mls_client_id.to_owned(),
                            mls_fingerprint: member.mls_fingerprint.to_owned(),
                        })
                        .collect(),
                    members_to_readd: group_result
                        .members_to_readd
                        .iter()
                        .map(|member| MemberInfo {
                            client_jid: member.client_jid.to_owned(),
                            mls_client_id: member.mls_client_id.to_owned(),
                            mls_fingerprint: member.mls_fingerprint.to_owned(),
                        })
                        .collect(),
                    error: group_result.error.clone().map(|e| e.into()),
                })
                .collect(),
            deleted_groups: result.deleted_groups,
        })
    }
}
