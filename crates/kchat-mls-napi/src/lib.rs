#![deny(clippy::all)]

pub mod error;

use kchat_mls::{
    CreateCustomProposalArgs, GroupPendingOperation, GroupStatusConnection,
    OP_JOIN_BY_EXTERNAL_COMMIT, OP_NONE, create_custom_proposal, delete_group_status,
    extract_jid_from_member_id, get_all_group_ids, get_group_pending_operation,
    get_group_pending_operations_batch, insert_or_update_group_status,
    open_group_status_connection, process_all_messages, process_custom_proposal,
};
use napi::{
    Task,
    bindgen_prelude::{AsyncTask, FnArgs, Function},
    threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode},
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

type LogThreadsafeFunction = ThreadsafeFunction<String, (), FnArgs<(String,)>, napi::Status, false>;
fn emit_debug_log_async(callback: Option<&LogThreadsafeFunction>, msg: String) {
    if let Some(cb) = callback {
        let _ = cb.call(msg, ThreadsafeFunctionCallMode::NonBlocking);
    }
}

fn build_log_callback(
    callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
) -> napi::Result<Option<LogThreadsafeFunction>> {
    callback
        .map(|callback| {
            callback
                .build_threadsafe_function::<String>()
                .build_callback(|ctx| Ok(FnArgs::from((ctx.value,))))
        })
        .transpose()
}

macro_rules! impl_identity_task {
    ($task:ident, $output:ty, |$this:ident| $body:block) => {
        #[napi]
        impl Task for $task {
            type Output = $output;
            type JsValue = $output;

            fn compute(&mut self) -> napi::Result<Self::Output> {
                let $this = self;
                $body
            }

            fn resolve(
                &mut self,
                _: napi::Env,
                output: Self::Output,
            ) -> napi::Result<Self::JsValue> {
                Ok(output)
            }
        }
    };
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
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::AddMembersResult> for AddMembersResult {
    fn from(value: core::AddMembersResult) -> Self {
        Self {
            commit: value.commit,
            welcome: value.welcome,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
            pre_tree_hash: value.pre_tree_hash,
        }
    }
}

#[napi(object)]
pub struct RemoveMembersResult {
    pub commit: Vec<u8>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i64,
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::RemoveMembersResult> for RemoveMembersResult {
    fn from(value: core::RemoveMembersResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
            pre_tree_hash: value.pre_tree_hash,
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
    pub sender: String,
    pub client_jid: Option<String>,
    pub mls_client_id: Option<String>,
    pub mls_fingerprint: Option<String>,
    pub epoch: Option<i64>,
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
            epoch: Some(value.epoch as i64),
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
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::JoinByExternalCommitResult> for JoinByExternalCommitResult {
    fn from(value: core::JoinByExternalCommitResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
            pre_tree_hash: value.pre_tree_hash,
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
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::UpdateLeafNodeResult> for UpdateLeafNodeResult {
    fn from(value: core::UpdateLeafNodeResult) -> Self {
        Self {
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
            pre_tree_hash: value.pre_tree_hash,
        }
    }
}

#[napi]
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
    pub error: Option<GroupError>,
}

#[napi]
pub enum GroupErrorCode {
    Storage,
    Aead,
    ProcessCommit,
}

#[napi(object)]
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

#[napi(object)]
pub struct MemberInfo {
    pub client_jid: Option<String>,
    pub mls_client_id: Option<String>,
    pub mls_fingerprint: Option<String>,
}

#[napi(object)]
pub struct ProcessAllMessagesResult {
    pub group_results: Vec<GroupResult>,
    pub deleted_groups: Vec<String>,
}

fn build_process_all_messages_args(
    args: ProcessAllMessagesArgs,
) -> kchat_mls::ProcessAllMessagesArgs {
    kchat_mls::ProcessAllMessagesArgs {
        group_messages: args
            .group_messages
            .into_iter()
            .map(|msg| kchat_mls::AllMessagesOfGroupArgs {
                group_id: msg.group_id,
                messages: msg
                    .messages
                    .into_iter()
                    .map(|msg| kchat_mls::MlsMessage {
                        blob: msg.blob,
                        epoch: msg.epoch as u64,
                        sender: msg.sender,
                        message_type: msg.message_type.as_str().into(),
                    })
                    .collect(),
                current_epoch: msg.current_epoch,
                current_tree_hash: msg.current_tree_hash,
                pending_epoch: msg.pending_epoch,
                pending_tree_hash: msg.pending_tree_hash,
            })
            .collect(),
    }
}

fn convert_process_all_messages_result(
    result: kchat_mls::ProcessAllMessagesResult,
) -> ProcessAllMessagesResult {
    ProcessAllMessagesResult {
        group_results: result
            .group_results
            .into_iter()
            .map(|group_result| GroupResult {
                group_id: group_result.group_id,
                members_to_remove: group_result
                    .members_to_remove
                    .into_iter()
                    .map(|member| MemberInfo {
                        client_jid: member.client_jid,
                        mls_client_id: member.mls_client_id,
                        mls_fingerprint: member.mls_fingerprint,
                    })
                    .collect(),
                members_to_readd: group_result
                    .members_to_readd
                    .into_iter()
                    .map(|member| MemberInfo {
                        client_jid: member.client_jid,
                        mls_client_id: member.mls_client_id,
                        mls_fingerprint: member.mls_fingerprint,
                    })
                    .collect(),
                error: group_result.error.map(|e| e.into()),
            })
            .collect(),
        deleted_groups: result.deleted_groups,
    }
}

pub struct ProcessAllMessagesTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    args: Option<kchat_mls::ProcessAllMessagesArgs>,
    join_config: Option<MlsGroupJoinConfig>,
    callback: Option<LogThreadsafeFunction>,
}

#[napi]
impl Task for ProcessAllMessagesTask {
    type Output = kchat_mls::ProcessAllMessagesResult;
    type JsValue = ProcessAllMessagesResult;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let callback = self.callback.as_ref();
        let log_fn = |msg: String| emit_debug_log_async(callback, msg);
        let args = self.args.take().ok_or_else(|| {
            napi::Error::new(
                napi::Status::GenericFailure,
                "process_all_messages task was already consumed",
            )
        })?;
        let join_config = self.join_config.take().ok_or_else(|| {
            napi::Error::new(
                napi::Status::GenericFailure,
                "process_all_messages task join config was already consumed",
            )
        })?;
        process_all_messages(
            &self.conn,
            &self.provider,
            args,
            &join_config,
            callback.map(|_| &log_fn as &dyn Fn(String)),
        )
        .map_err(|e| {
            emit_debug_log_async(callback, format!("process all messages error: {}", e));
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })
    }

    fn resolve(&mut self, _: napi::Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(convert_process_all_messages_result(output))
    }
}

pub struct EncryptMessageTask {
    provider: SqliteProvider,
    group_id: String,
    message: Vec<u8>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(EncryptMessageTask, Vec<u8>, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start encrypt message, group {}", this.group_id),
    );

    let encrypted = this
        .provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id).map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "encrypt message - load group error, group {}: {}",
                        this.group_id, e
                    ),
                );
                e
            })?;
            emit_debug_log_async(
                callback,
                format!("encrypt message - load group done, group {}", this.group_id),
            );

            let signer = core::group_signer(&mls_group, tx_provider).map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "encrypt message - get signer error, group {}: {}",
                        this.group_id, e
                    ),
                );
                e
            })?;
            emit_debug_log_async(
                callback,
                format!("encrypt message - get signer done, group {}", this.group_id),
            );

            core::encrypt_message(&mut mls_group, tx_provider, &signer, &this.message).map_err(
                |e| {
                    emit_debug_log_async(
                        callback,
                        format!("encrypt message error, group {}: {}", this.group_id, e),
                    );
                    e
                },
            )
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("encrypt message error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;

    emit_debug_log_async(
        callback,
        format!("end encrypt message, group {}", this.group_id),
    );

    Ok(encrypted)
});

pub struct MergePendingCommitTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(MergePendingCommitTask, (), |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start merge pending commit, group {}", this.group_id),
    );
    this.provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            emit_debug_log_async(
                callback,
                format!(
                    "merge pending commit - load group done, group {}",
                    this.group_id
                ),
            );
            core::merge_pending_commit(&mut mls_group, tx_provider)
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("merge pending commit error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    let _ = insert_or_update_group_status(&this.conn, &this.group_id, GroupPendingOperation::None);
    emit_debug_log_async(
        callback,
        format!("end merge pending commit, group {}", this.group_id),
    );

    Ok(())
});

pub struct ClearPendingCommitTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(ClearPendingCommitTask, (), |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start clear pending commit, group {}", this.group_id),
    );
    this.provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            emit_debug_log_async(
                callback,
                format!(
                    "clear pending commit - load group done, group {}",
                    this.group_id
                ),
            );
            core::clear_pending_commit(&mut mls_group, tx_provider)
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("clear pending commit error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    let _ = insert_or_update_group_status(&this.conn, &this.group_id, GroupPendingOperation::None);
    emit_debug_log_async(
        callback,
        format!("end clear pending commit, group {}", this.group_id),
    );

    Ok(())
});

pub struct GroupEpochTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(GroupEpochTask, WrappedGroupEpochResult, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start group epoch, group {}", this.group_id),
    );
    let pending_operation = get_group_pending_operation(&this.conn, &this.group_id).unwrap_or(None);

    let result = match core::group_context(&this.provider, &this.group_id) {
        Ok(context) => WrappedGroupEpochResult {
            group_id: this.group_id.clone(),
            epoch: if pending_operation == Some(OP_JOIN_BY_EXTERNAL_COMMIT.to_owned()) {
                context.epoch().as_u64() as i64 - 1
            } else {
                context.epoch().as_u64() as i64
            },
            tree_hash: context.tree_hash().to_vec(),
            err: None,
            pending_operation,
        },
        Err(err) => {
            emit_debug_log_async(
                callback,
                format!("group epoch error, group {}: {}", this.group_id, err),
            );
            WrappedGroupEpochResult {
                group_id: this.group_id.clone(),
                epoch: -1,
                tree_hash: Vec::new(),
                err: Some(err.to_string()),
                pending_operation: None,
            }
        }
    };
    emit_debug_log_async(
        callback,
        format!("end group epoch, group {}", this.group_id),
    );

    Ok(result)
});

pub struct GroupEpochsTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_ids: Vec<String>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(GroupEpochsTask, Vec<WrappedGroupEpochResult>, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start group epochs, count {}", this.group_ids.len()),
    );
    let pending_operations = get_group_pending_operations_batch(&this.conn, &this.group_ids)
        .unwrap_or_else(|_| std::collections::HashMap::new());
    let join_by_external_commit = OP_JOIN_BY_EXTERNAL_COMMIT.to_owned();

    let result = this
        .group_ids
        .iter()
        .map(|group_id| {
            emit_debug_log_async(
                callback,
                format!("group epochs - process group {}", group_id),
            );
            let pending_operation = pending_operations.get(group_id).cloned();
            match core::group_context(&this.provider, group_id) {
                Ok(context) => {
                    let epoch = if pending_operation.as_ref() == Some(&join_by_external_commit) {
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
                Err(err) => {
                    emit_debug_log_async(
                        callback,
                        format!("group epochs error, group {}: {}", group_id, err),
                    );
                    WrappedGroupEpochResult {
                        group_id: group_id.clone(),
                        epoch: -1,
                        tree_hash: Vec::new(),
                        err: Some(err.to_string()),
                        pending_operation: None,
                    }
                }
            }
        })
        .collect::<Vec<_>>();
    emit_debug_log_async(callback, "end group epochs".to_owned());

    Ok(result)
});

pub struct GroupContextTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(GroupContextTask, WrappedGroupContextResult, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start group context, group {}", this.group_id),
    );
    let pending_operation = get_group_pending_operation(&this.conn, &this.group_id).unwrap_or(None);

    let result = match core::group_context(&this.provider, &this.group_id) {
        Ok(context) => WrappedGroupContextResult {
            group_id: this.group_id.clone(),
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
        Err(err) => {
            emit_debug_log_async(
                callback,
                format!("group context error, group {}: {}", this.group_id, err),
            );
            WrappedGroupContextResult {
                group_id: this.group_id.clone(),
                current_epoch: -1,
                pending_epoch: -1,
                tree_hash: Vec::new(),
                err: Some(err.to_string()),
                pending_operation: None,
            }
        }
    };
    emit_debug_log_async(
        callback,
        format!("end group context, group {}", this.group_id),
    );

    Ok(result)
});

pub struct GroupContextsTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_ids: Vec<String>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(GroupContextsTask, Vec<WrappedGroupContextResult>, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start group contexts, count {}", this.group_ids.len()),
    );
    let pending_operations = get_group_pending_operations_batch(&this.conn, &this.group_ids)
        .unwrap_or_else(|_| std::collections::HashMap::new());
    let join_by_external_commit = OP_JOIN_BY_EXTERNAL_COMMIT.to_owned();

    let result = this
        .group_ids
        .iter()
        .map(|group_id| {
            emit_debug_log_async(
                callback,
                format!("group contexts - process group {}", group_id),
            );
            let pending_operation = pending_operations.get(group_id).cloned();
            match core::group_context(&this.provider, group_id) {
                Ok(context) => {
                    let current_epoch = context.epoch().as_u64() as i64;
                    let pending_epoch =
                        if pending_operation.as_ref() == Some(&join_by_external_commit) {
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
                Err(err) => {
                    emit_debug_log_async(
                        callback,
                        format!("group contexts error, group {}: {}", group_id, err),
                    );
                    WrappedGroupContextResult {
                        group_id: group_id.clone(),
                        current_epoch: -1,
                        pending_epoch: -1,
                        tree_hash: Vec::new(),
                        err: Some(err.to_string()),
                        pending_operation: None,
                    }
                }
            }
        })
        .collect::<Vec<_>>();
    emit_debug_log_async(callback, "end group contexts".to_owned());

    Ok(result)
});

pub struct DeleteGroupTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(DeleteGroupTask, (), |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start delete group, group {}", this.group_id),
    );
    this.provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            emit_debug_log_async(
                callback,
                format!("delete group - load group done, group {}", this.group_id),
            );
            core::delete_group(&mut mls_group, tx_provider)
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("delete group error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    let _ = delete_group_status(&this.conn, &this.group_id);
    emit_debug_log_async(
        callback,
        format!("end delete group, group {}", this.group_id),
    );

    Ok(())
});

pub struct CreateGroupTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    client_id: String,
    group_id: String,
    public_key: Option<Vec<u8>>,
    ciphersuite: Ciphersuite,
    config: MlsGroupCreateConfig,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(CreateGroupTask, (), |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start create group, group {}", this.group_id),
    );

    if core::group(&this.provider, &this.group_id).is_ok() {
        emit_debug_log_async(
            callback,
            format!(
                "create group error, group {}: group already exists",
                this.group_id
            ),
        );
        return Err(Error::GroupIsAlreadyExisted.into());
    }

    this.provider
        .transaction(|tx_provider| {
            core::create_group(
                tx_provider,
                &this.client_id,
                &this.group_id,
                this.ciphersuite,
                &this.config,
                this.public_key.clone(),
            )
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("create group error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    emit_debug_log_async(
        callback,
        format!("create group - transaction done, group {}", this.group_id),
    );

    let _ = insert_or_update_group_status(
        &this.conn,
        &this.group_id,
        GroupPendingOperation::CreateGroup,
    );
    emit_debug_log_async(
        callback,
        format!(
            "create group - pending operation updated, group {}",
            this.group_id
        ),
    );
    emit_debug_log_async(
        callback,
        format!("end create group, group {}", this.group_id),
    );

    Ok(())
});

pub struct AddMembersTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    key_packages: Vec<Vec<u8>>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(AddMembersTask, AddMembersResult, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start add members, group {}", this.group_id),
    );
    let result = this
        .provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            emit_debug_log_async(
                callback,
                format!("add members - load group done, group {}", this.group_id),
            );
            let signer = core::group_signer(&mls_group, tx_provider)?;
            emit_debug_log_async(
                callback,
                format!("add members - get signer done, group {}", this.group_id),
            );
            core::add_members(&mut mls_group, tx_provider, &signer, &this.key_packages)
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("add members error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;

    let mut current_pending_operation = GroupPendingOperation::None;
    if let Ok(op) = get_group_pending_operation(&this.conn, &this.group_id) {
        current_pending_operation = op.into();
    }

    if current_pending_operation == GroupPendingOperation::None {
        let _ = insert_or_update_group_status(
            &this.conn,
            &this.group_id,
            GroupPendingOperation::UpdateTree,
        );
    }
    emit_debug_log_async(
        callback,
        format!("end add members, group {}", this.group_id),
    );

    Ok(result.into())
});

pub struct RemoveMembersTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    member_ids: Vec<String>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(RemoveMembersTask, RemoveMembersResult, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start remove members, group {}", this.group_id),
    );
    let result = this
        .provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            emit_debug_log_async(
                callback,
                format!("remove members - load group done, group {}", this.group_id),
            );
            let signer = core::group_signer(&mls_group, tx_provider)?;
            emit_debug_log_async(
                callback,
                format!("remove members - get signer done, group {}", this.group_id),
            );
            core::remove_members(
                &mut mls_group,
                tx_provider,
                &signer,
                &this
                    .member_ids
                    .iter()
                    .map(|id| id.as_str())
                    .collect::<Vec<&str>>(),
            )
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("remove members error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    let _ = insert_or_update_group_status(
        &this.conn,
        &this.group_id,
        GroupPendingOperation::UpdateTree,
    );
    emit_debug_log_async(
        callback,
        format!("end remove members, group {}", this.group_id),
    );

    Ok(result.into())
});

pub struct ProcessWelcomeTask {
    provider: SqliteProvider,
    welcome: Vec<u8>,
    join_config: MlsGroupJoinConfig,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(ProcessWelcomeTask, (), |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(callback, "start process welcome".to_owned());
    this.provider
        .transaction(|tx_provider| {
            core::process_welcome(tx_provider, &this.welcome, &this.join_config).map(|_| ())
        })
        .map_err(|e| {
            emit_debug_log_async(callback, format!("process welcome error: {}", e));
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    emit_debug_log_async(callback, "end process welcome".to_owned());

    Ok(())
});

pub struct ProcessOperationMessageTask {
    provider: SqliteProvider,
    group_id: String,
    message: Vec<u8>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(
    ProcessOperationMessageTask,
    ProcessOperationMessageResult,
    |this| {
        let callback = this.callback.as_ref();
        emit_debug_log_async(
            callback,
            format!("start process operation message, group {}", this.group_id),
        );
        let result = this
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &this.group_id)?;
                emit_debug_log_async(
                    callback,
                    format!(
                        "process operation message - load group done, group {}",
                        this.group_id
                    ),
                );
                core::process_operation_message(&mut mls_group, tx_provider, &this.message)
            })
            .map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "process operation message error, group {}: {}",
                        this.group_id, e
                    ),
                );
                napi::Error::new(napi::Status::GenericFailure, e.to_string())
            })?;
        emit_debug_log_async(
            callback,
            format!("end process operation message, group {}", this.group_id),
        );

        Ok(result.into())
    }
);

pub struct ProcessManyOperationMessagesTask {
    provider: SqliteProvider,
    group_id: String,
    messages: Vec<Vec<u8>>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(
    ProcessManyOperationMessagesTask,
    ProcessManyOperationMessagesResult,
    |this| {
        let callback = this.callback.as_ref();
        emit_debug_log_async(
            callback,
            format!(
                "start process many operation messages, group {}, count {}",
                this.group_id,
                this.messages.len()
            ),
        );
        let result = this
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &this.group_id)?;
                emit_debug_log_async(
                    callback,
                    format!(
                        "process many operation messages - load group done, group {}",
                        this.group_id
                    ),
                );
                core::process_many_operation_messages(
                    &mut mls_group,
                    tx_provider,
                    &this.messages,
                    None,
                )
            })
            .map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "process many operation messages error, group {}: {}",
                        this.group_id, e
                    ),
                );
                napi::Error::new(napi::Status::GenericFailure, e.to_string())
            })?;
        emit_debug_log_async(
            callback,
            format!(
                "end process many operation messages, group {}",
                this.group_id
            ),
        );

        Ok(result.into())
    }
);

pub struct ProcessApplicationMessageTask {
    provider: SqliteProvider,
    group_id: String,
    message: Vec<u8>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(
    ProcessApplicationMessageTask,
    ProcessApplicationMessageResult,
    |this| {
        let callback = this.callback.as_ref();
        emit_debug_log_async(
            callback,
            format!("start process application message, group {}", this.group_id),
        );
        let result = this
            .provider
            .transaction(|tx_provider| {
                let mut mls_group = core::group(tx_provider, &this.group_id).map_err(|e| {
                    emit_debug_log_async(
                        callback,
                        format!(
                            "process application message - load group error, group {}: {}",
                            this.group_id, e
                        ),
                    );
                    e
                })?;
                emit_debug_log_async(
                    callback,
                    format!(
                        "process application message - load group done, group {}",
                        this.group_id
                    ),
                );

                core::process_application_message(&mut mls_group, tx_provider, &this.message)
                    .map_err(|e| {
                        emit_debug_log_async(
                            callback,
                            format!(
                                "process application message error, group {}: {}",
                                this.group_id, e
                            ),
                        );
                        e
                    })
            })
            .map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "process application message error, group {}: {}",
                        this.group_id, e
                    ),
                );
                napi::Error::new(napi::Status::GenericFailure, e.to_string())
            })?;
        emit_debug_log_async(
            callback,
            format!("end process application message, group {}", this.group_id),
        );

        Ok(result.into())
    }
);

pub struct ProcessProposalMessageTask {
    provider: SqliteProvider,
    group_id: String,
    message: Vec<u8>,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(ProcessProposalMessageTask, QueuedProposal, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start process proposal message, group {}", this.group_id),
    );
    let queued_proposal = this
        .provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id).map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "process proposal message - load group error, group {}: {}",
                        this.group_id, e
                    ),
                );
                e
            })?;
            emit_debug_log_async(
                callback,
                format!(
                    "process proposal message - load group done, group {}",
                    this.group_id
                ),
            );

            core::process_proposal_message(&mut mls_group, tx_provider, &this.message).map_err(
                |e| {
                    emit_debug_log_async(
                        callback,
                        format!(
                            "process proposal message error, group {}: {}",
                            this.group_id, e
                        ),
                    );
                    e
                },
            )
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!(
                    "process proposal message error, group {}: {}",
                    this.group_id, e
                ),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    emit_debug_log_async(
        callback,
        format!("end process proposal message, group {}", this.group_id),
    );

    Ok(queued_proposal.into())
});

pub struct JoinByExternalCommitTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    client_id: String,
    group_id: String,
    group_info: Vec<u8>,
    public_key: Option<Vec<u8>>,
    ciphersuite: Ciphersuite,
    join_config: MlsGroupJoinConfig,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(
    JoinByExternalCommitTask,
    JoinByExternalCommitResult,
    |this| {
        let callback = this.callback.as_ref();
        emit_debug_log_async(
            callback,
            format!("start join by external commit, group {}", this.group_id),
        );
        let result = this
            .provider
            .transaction(|tx_provider| {
                core::join_by_external_commit(
                    tx_provider,
                    &this.client_id,
                    &this.group_info,
                    this.ciphersuite,
                    &this.join_config,
                    this.public_key.clone(),
                )
            })
            .map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "join by external commit error, group {}: {}",
                        this.group_id, e
                    ),
                );
                napi::Error::new(napi::Status::GenericFailure, e.to_string())
            })?;
        let _ = insert_or_update_group_status(
            &this.conn,
            &this.group_id,
            GroupPendingOperation::JoinByExternalCommit,
        );
        emit_debug_log_async(
            callback,
            format!(
                "join by external commit - pending operation updated, group {}",
                this.group_id
            ),
        );
        emit_debug_log_async(
            callback,
            format!("end join by external commit, group {}", this.group_id),
        );

        Ok(result.into())
    }
);

pub struct BatchJoinByExternalCommitTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    client_id: String,
    args: Vec<JoinByExternalCommitArgs>,
    public_key: Option<Vec<u8>>,
    ciphersuite: Ciphersuite,
    join_config: MlsGroupJoinConfig,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(
    BatchJoinByExternalCommitTask,
    Vec<WrappedJoinByExternalCommitResult>,
    |this| {
        let callback = this.callback.as_ref();
        emit_debug_log_async(
            callback,
            format!(
                "start batch join by external commit, count {}",
                this.args.len()
            ),
        );
        let result = this
            .args
            .iter()
            .map(|arg| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "batch join by external commit - process group {}",
                        arg.group_id
                    ),
                );
                match this.provider.transaction(|tx_provider| {
                    core::join_by_external_commit(
                        tx_provider,
                        &this.client_id,
                        &arg.group_info,
                        this.ciphersuite,
                        &this.join_config,
                        this.public_key.clone(),
                    )
                }) {
                    Ok(result) => {
                        let _ = insert_or_update_group_status(
                            &this.conn,
                            &arg.group_id,
                            GroupPendingOperation::JoinByExternalCommit,
                        );
                        emit_debug_log_async(
                            callback,
                            format!(
                                "batch join by external commit - success, group {}",
                                arg.group_id
                            ),
                        );
                        WrappedJoinByExternalCommitResult {
                            group_id: arg.group_id.clone(),
                            result: Some(result.into()),
                            err: None,
                        }
                    }
                    Err(err) => {
                        emit_debug_log_async(
                            callback,
                            format!(
                                "batch join by external commit error, group {}: {}",
                                arg.group_id, err
                            ),
                        );
                        WrappedJoinByExternalCommitResult {
                            group_id: arg.group_id.clone(),
                            result: None,
                            err: Some(err.to_string()),
                        }
                    }
                }
            })
            .collect::<Vec<_>>();
        emit_debug_log_async(callback, "end batch join by external commit".to_owned());

        Ok(result)
    }
);

pub struct LeaveGroupTask {
    provider: SqliteProvider,
    group_id: String,
    callback: Option<LogThreadsafeFunction>,
}

impl_identity_task!(LeaveGroupTask, LeaveGroupResult, |this| {
    let callback = this.callback.as_ref();
    emit_debug_log_async(
        callback,
        format!("start leave group, group {}", this.group_id),
    );
    let result = this
        .provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id).map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "leave group - load group error, group {}: {}",
                        this.group_id, e
                    ),
                );
                e
            })?;
            emit_debug_log_async(
                callback,
                format!("leave group - load group done, group {}", this.group_id),
            );
            let signer = core::group_signer(&mls_group, tx_provider).map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!(
                        "leave group - get signer error, group {}: {}",
                        this.group_id, e
                    ),
                );
                e
            })?;
            emit_debug_log_async(
                callback,
                format!("leave group - get signer done, group {}", this.group_id),
            );

            core::leave_group(&mut mls_group, tx_provider, &signer).map_err(|e| {
                emit_debug_log_async(
                    callback,
                    format!("leave group error, group {}: {}", this.group_id, e),
                );
                e
            })
        })
        .map_err(|e| {
            emit_debug_log_async(
                callback,
                format!("leave group error, group {}: {}", this.group_id, e),
            );
            napi::Error::new(napi::Status::GenericFailure, e.to_string())
        })?;
    emit_debug_log_async(
        callback,
        format!("end leave group, group {}", this.group_id),
    );

    Ok(result.into())
});

pub struct GenerateSignatureKeyTask {
    provider: SqliteProvider,
    ciphersuite: Ciphersuite,
}

impl_identity_task!(GenerateSignatureKeyTask, SignaturePublicKey, |this| {
    let signer = core::generate_signature_key(&this.provider, this.ciphersuite)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;

    Ok(SignaturePublicKey {
        public: signer.public().to_vec(),
        signature_scheme: signer.signature_scheme() as u16,
    })
});

pub struct GenerateKeyPackagesTask {
    client_id: String,
    provider: SqliteProvider,
    ciphersuite: Ciphersuite,
    quantity: u16,
    last_resort: bool,
    public_key: Option<Vec<u8>>,
}

impl_identity_task!(GenerateKeyPackagesTask, GenerateKeyPackagesResult, |this| {
    let mut result = GenerateKeyPackagesResult {
        key_packages: Vec::new(),
    };
    for _ in 0..this.quantity {
        result.key_packages.push(
            core::generate_key_package(
                &this.client_id,
                &this.provider,
                this.ciphersuite,
                this.last_resort,
                this.public_key.clone(),
            )
            .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?,
        );
    }
    Ok(result)
});

pub struct ExportGroupInfoTask {
    provider: SqliteProvider,
    group_id: String,
}

impl_identity_task!(ExportGroupInfoTask, Vec<u8>, |this| {
    let mls_group = core::group(&this.provider, &this.group_id)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;
    let signer = core::group_signer(&mls_group, &this.provider)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;

    core::export_group_info(&mls_group, &this.provider, &signer)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))
});

pub struct UpdateLeafNodeTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
}

impl_identity_task!(UpdateLeafNodeTask, UpdateLeafNodeResult, |this| {
    let result = this
        .provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            let signer = core::group_signer(&mls_group, tx_provider)?;
            core::update_leaf_node(&mut mls_group, tx_provider, &signer)
        })
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;
    let _ = insert_or_update_group_status(
        &this.conn,
        &this.group_id,
        GroupPendingOperation::UpdateTree,
    );
    Ok(result.into())
});

pub struct ReaddTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
    member_ids: Vec<String>,
    key_packages: Vec<Vec<u8>>,
}

impl_identity_task!(ReaddTask, ReAddResult, |this| {
    if let Some(op) = get_group_pending_operation(&this.conn, &this.group_id).unwrap_or(None) {
        if !op.eq(OP_NONE) {
            return Err(Error::ReAdd(format!("There is a pending operation: {}", op)).into());
        }
    }

    let result = this
        .provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            let signer = core::group_signer(&mls_group, tx_provider)?;
            core::readd(
                &mut mls_group,
                tx_provider,
                &signer,
                &this
                    .member_ids
                    .iter()
                    .map(|id| id.as_str())
                    .collect::<Vec<&str>>(),
                &this.key_packages,
            )
        })
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;
    let _ = insert_or_update_group_status(
        &this.conn,
        &this.group_id,
        GroupPendingOperation::UpdateTree,
    );
    Ok(result.into())
});

pub struct ProposeReaddTask {
    client_id: String,
    group_id: String,
    request: ProposeReAddRequest,
}

impl_identity_task!(ProposeReaddTask, ProposeReAddResult, |this| {
    Ok(ProposeReAddResult {
        proposal: create_custom_proposal(
            &this.client_id,
            &this.group_id,
            CreateCustomProposalArgs {
                mls_fingerprint: this.request.mls_fingerprint.clone(),
                custom_proposal_type: kchat_mls::CustomProposalType::ReAdd,
            },
        ),
    })
});

pub struct ClearPendingProposalsTask {
    conn: GroupStatusConnection,
    provider: SqliteProvider,
    group_id: String,
}

impl_identity_task!(ClearPendingProposalsTask, (), |this| {
    this.provider
        .transaction(|tx_provider| {
            let mut mls_group = core::group(tx_provider, &this.group_id)?;
            core::clear_pending_proposals(&mut mls_group, tx_provider)
        })
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;
    let _ = insert_or_update_group_status(&this.conn, &this.group_id, GroupPendingOperation::None);
    Ok(())
});

pub struct PendingCommitTask {
    provider: SqliteProvider,
    group_id: String,
}

impl_identity_task!(PendingCommitTask, Option<PendingCommitResult>, |this| {
    let mls_group = core::group(&this.provider, &this.group_id)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;
    Ok(core::pending_commit(&mls_group).map(|commit| commit.into()))
});

pub struct PendingProposalsTask {
    provider: SqliteProvider,
    group_id: String,
}

impl_identity_task!(PendingProposalsTask, PendingProposalsResult, |this| {
    let mls_group = core::group(&this.provider, &this.group_id)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;
    Ok(core::pending_proposals(&mls_group).into())
});

pub struct MembersTask {
    provider: SqliteProvider,
    group_id: String,
}

impl_identity_task!(MembersTask, Vec<String>, |this| {
    let mls_group = core::group(&this.provider, &this.group_id)
        .map_err(|e| napi::Error::new(napi::Status::GenericFailure, e.to_string()))?;

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
});

pub struct ProcessCustomProposalMessageTask {
    custom_proposal: Vec<u8>,
}

impl_identity_task!(
    ProcessCustomProposalMessageTask,
    Option<QueuedProposal>,
    |this| {
        Ok(
            process_custom_proposal(&this.custom_proposal).map(|result| QueuedProposal {
                sender: result.mls_client_id.clone().unwrap_or_default(),
                client_jid: result.client_jid,
                mls_client_id: result.mls_client_id,
                mls_fingerprint: result.mls_fingerprint,
                epoch: result.epoch.map(|e| e as i64),
                group_id: result.group_id,
                proposal: result.proposal_type.into(),
            }),
        )
    }
);

pub struct AllGroupIdsTask {
    provider: SqliteProvider,
}

impl_identity_task!(AllGroupIdsTask, Vec<String>, |this| {
    Ok(get_all_group_ids(&this.provider))
});

#[napi(object)]
pub struct ReAddResult {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
    pub current_epoch: i64,
    pub pre_tree_hash: Vec<u8>,
}

impl From<core::ReAddResult> for ReAddResult {
    fn from(value: core::ReAddResult) -> Self {
        Self {
            welcome: value.welcome,
            commit: value.commit,
            group_info: value.group_info,
            current_epoch: value.current_epoch as i64,
            pre_tree_hash: value.pre_tree_hash,
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

    fn build_join_config(&self) -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .wire_format_policy(self.wire_format_policy())
            .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
            .max_past_epochs(self.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.out_of_order_tolerance,
                self.maximum_forward_distance,
            ))
            .build()
    }

    fn build_create_config(&self, ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .wire_format_policy(self.wire_format_policy())
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
            .max_past_epochs(self.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.out_of_order_tolerance,
                self.maximum_forward_distance,
            ))
            .build()
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
    pub fn generate_signature_key(&self) -> napi::Result<AsyncTask<GenerateSignatureKeyTask>> {
        Ok(AsyncTask::new(GenerateSignatureKeyTask {
            provider: self.provider.clone(),
            ciphersuite: self.ciphersuite()?,
        }))
    }

    #[napi]
    pub fn generate_key_packages(
        &self,
        quantity: u16,
        last_resort: bool,
        public_key: Option<Vec<u8>>,
    ) -> napi::Result<AsyncTask<GenerateKeyPackagesTask>> {
        Ok(AsyncTask::new(GenerateKeyPackagesTask {
            client_id: self.client_id.clone(),
            provider: self.provider.clone(),
            ciphersuite: self.ciphersuite()?,
            quantity,
            last_resort,
            public_key,
        }))
    }

    #[napi]
    pub fn create_group(
        &self,
        group_id: String,
        public_key: Option<Vec<u8>>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<CreateGroupTask>> {
        let callback = build_log_callback(callback)?;
        let ciphersuite = self.ciphersuite()?;
        Ok(AsyncTask::new(CreateGroupTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            client_id: self.client_id.clone(),
            group_id,
            public_key,
            ciphersuite,
            config: self.build_create_config(ciphersuite),
            callback,
        }))
    }

    #[napi]
    pub fn add_members(
        &self,
        group_id: String,
        key_packages: Vec<Vec<u8>>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<AddMembersTask>> {
        Ok(AsyncTask::new(AddMembersTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            key_packages,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn remove_members(
        &self,
        group_id: String,
        member_ids: Vec<String>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<RemoveMembersTask>> {
        Ok(AsyncTask::new(RemoveMembersTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            member_ids,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn process_welcome(
        &self,
        welcome: Vec<u8>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<ProcessWelcomeTask>> {
        Ok(AsyncTask::new(ProcessWelcomeTask {
            provider: self.provider.clone(),
            welcome,
            join_config: self.build_join_config(),
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn process_operation_message(
        &self,
        group_id: String,
        message: Vec<u8>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<ProcessOperationMessageTask>> {
        Ok(AsyncTask::new(ProcessOperationMessageTask {
            provider: self.provider.clone(),
            group_id,
            message,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn process_many_operation_messages(
        &self,
        group_id: String,
        messages: Vec<Vec<u8>>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<ProcessManyOperationMessagesTask>> {
        Ok(AsyncTask::new(ProcessManyOperationMessagesTask {
            provider: self.provider.clone(),
            group_id,
            messages,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn process_application_message(
        &self,
        group_id: String,
        message: Vec<u8>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<ProcessApplicationMessageTask>> {
        Ok(AsyncTask::new(ProcessApplicationMessageTask {
            provider: self.provider.clone(),
            group_id,
            message,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn process_proposal_message(
        &self,
        group_id: String,
        message: Vec<u8>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<ProcessProposalMessageTask>> {
        Ok(AsyncTask::new(ProcessProposalMessageTask {
            provider: self.provider.clone(),
            group_id,
            message,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn encrypt_message(
        &self,
        group_id: String,
        message: Vec<u8>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<EncryptMessageTask>> {
        Ok(AsyncTask::new(EncryptMessageTask {
            provider: self.provider.clone(),
            group_id,
            message,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn export_group_info(
        &self,
        group_id: String,
    ) -> napi::Result<AsyncTask<ExportGroupInfoTask>> {
        Ok(AsyncTask::new(ExportGroupInfoTask {
            provider: self.provider.clone(),
            group_id,
        }))
    }

    #[napi]
    pub fn join_by_external_commit(
        &self,
        group_id: String,
        group_info: Vec<u8>,
        public_key: Option<Vec<u8>>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<JoinByExternalCommitTask>> {
        let ciphersuite = self.ciphersuite()?;
        Ok(AsyncTask::new(JoinByExternalCommitTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            client_id: self.client_id.clone(),
            group_id,
            group_info,
            public_key,
            ciphersuite,
            join_config: self.build_join_config(),
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn batch_join_by_external_commit(
        &self,
        args: Vec<JoinByExternalCommitArgs>,
        public_key: Option<Vec<u8>>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<BatchJoinByExternalCommitTask>> {
        let ciphersuite = self.ciphersuite()?;
        Ok(AsyncTask::new(BatchJoinByExternalCommitTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            client_id: self.client_id.clone(),
            args,
            public_key,
            ciphersuite,
            join_config: self.build_join_config(),
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn leave_group(
        &self,
        group_id: String,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<LeaveGroupTask>> {
        Ok(AsyncTask::new(LeaveGroupTask {
            provider: self.provider.clone(),
            group_id,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn update_leaf_node(
        &self,
        group_id: String,
    ) -> napi::Result<AsyncTask<UpdateLeafNodeTask>> {
        Ok(AsyncTask::new(UpdateLeafNodeTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
        }))
    }

    #[napi]
    pub fn readd(
        &self,
        group_id: String,
        member_ids: Vec<String>,
        key_packages: Vec<Vec<u8>>,
    ) -> napi::Result<AsyncTask<ReaddTask>> {
        Ok(AsyncTask::new(ReaddTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            member_ids,
            key_packages,
        }))
    }

    #[napi]
    pub fn propose_readd(
        &self,
        group_id: String,
        request: ProposeReAddRequest,
    ) -> napi::Result<AsyncTask<ProposeReaddTask>> {
        Ok(AsyncTask::new(ProposeReaddTask {
            client_id: self.client_id.clone(),
            group_id,
            request,
        }))
    }

    #[napi]
    pub fn merge_pending_commit(
        &self,
        group_id: String,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<MergePendingCommitTask>> {
        Ok(AsyncTask::new(MergePendingCommitTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn clear_pending_commit(
        &self,
        group_id: String,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<ClearPendingCommitTask>> {
        Ok(AsyncTask::new(ClearPendingCommitTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn clear_pending_proposals(
        &self,
        group_id: String,
    ) -> napi::Result<AsyncTask<ClearPendingProposalsTask>> {
        Ok(AsyncTask::new(ClearPendingProposalsTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
        }))
    }

    #[napi]
    pub fn pending_commit(&self, group_id: String) -> napi::Result<AsyncTask<PendingCommitTask>> {
        Ok(AsyncTask::new(PendingCommitTask {
            provider: self.provider.clone(),
            group_id,
        }))
    }

    #[napi]
    pub fn pending_proposals(
        &self,
        group_id: String,
    ) -> napi::Result<AsyncTask<PendingProposalsTask>> {
        Ok(AsyncTask::new(PendingProposalsTask {
            provider: self.provider.clone(),
            group_id,
        }))
    }

    #[napi]
    pub fn group_epoch(
        &self,
        group_id: String,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<GroupEpochTask>> {
        Ok(AsyncTask::new(GroupEpochTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn group_epochs(
        &self,
        group_ids: Vec<String>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<GroupEpochsTask>> {
        Ok(AsyncTask::new(GroupEpochsTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_ids,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn group_context(
        &self,
        group_id: String,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<GroupContextTask>> {
        Ok(AsyncTask::new(GroupContextTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn group_contexts(
        &self,
        group_ids: Vec<String>,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<GroupContextsTask>> {
        Ok(AsyncTask::new(GroupContextsTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_ids,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn delete_group(
        &self,
        group_id: String,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<DeleteGroupTask>> {
        Ok(AsyncTask::new(DeleteGroupTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            group_id,
            callback: build_log_callback(callback)?,
        }))
    }

    #[napi]
    pub fn members(&self, group_id: String) -> napi::Result<AsyncTask<MembersTask>> {
        Ok(AsyncTask::new(MembersTask {
            provider: self.provider.clone(),
            group_id,
        }))
    }

    #[napi]
    pub fn process_custom_proposal_message(
        &self,
        custom_proposal: Vec<u8>,
    ) -> napi::Result<AsyncTask<ProcessCustomProposalMessageTask>> {
        Ok(AsyncTask::new(ProcessCustomProposalMessageTask {
            custom_proposal,
        }))
    }

    #[napi]
    pub fn process_all_messages(
        &self,
        args: ProcessAllMessagesArgs,
        callback: Option<Function<'_, FnArgs<(String,)>, ()>>,
    ) -> napi::Result<AsyncTask<ProcessAllMessagesTask>> {
        let callback = callback
            .map(|callback| {
                callback
                    .build_threadsafe_function::<String>()
                    .build_callback(|ctx| Ok(FnArgs::from((ctx.value,))))
            })
            .transpose()?;

        Ok(AsyncTask::new(ProcessAllMessagesTask {
            conn: self.conn.clone(),
            provider: self.provider.clone(),
            args: Some(build_process_all_messages_args(args)),
            join_config: Some(
                MlsGroupJoinConfig::builder()
                    .wire_format_policy(self.wire_format_policy())
                    .use_ratchet_tree_extension(self.use_ratchet_tree_extension)
                    .max_past_epochs(self.max_past_epochs as usize)
                    .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                        self.out_of_order_tolerance,
                        self.maximum_forward_distance,
                    ))
                    .build(),
            ),
            callback,
        }))
    }

    #[napi]
    pub fn all_group_ids(&self) -> AsyncTask<AllGroupIdsTask> {
        AsyncTask::new(AllGroupIdsTask {
            provider: self.provider.clone(),
        })
    }
}
