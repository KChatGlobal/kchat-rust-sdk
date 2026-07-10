use std::{
    collections::{HashMap, HashSet},
    time::Duration,
    u64,
};

use kchat_storage_provider::SqliteConnectionPool;
use openmls::{
    group::{MlsGroup, MlsGroupJoinConfig},
    prelude::{BasicCredential, Credential},
};
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, params};
use secrecy::{ExposeSecret, SecretString};
use uq_openmls::{
    core::{
        Proposal, clear_pending_commit, delete_group, group, group_with_epoch_message_secrets,
        merge_pending_commit, process_operation_message, process_proposal_message, process_welcome,
    },
    error::Error,
    provider::SqliteProvider,
};

pub type GroupStatusConnection = SqliteConnectionPool;

const GROUP_STATUS_CONNECTION_POOL_SIZE: usize = 8;
const GROUP_STATUS_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const GROUP_STATUS_PRAGMA_NAME_KEY: &str = "key";
const GROUP_STATUS_PRAGMA_NAME_JOURNAL_MODE: &str = "journal_mode";
const GROUP_STATUS_JOURNAL_MODE_WAL: &str = "WAL";

fn configure_group_status_connection(
    connection: &Connection,
    secret: &Option<SecretString>,
) -> Result<(), rusqlite::Error> {
    if let Some(secret) = secret {
        connection.pragma_update(None, GROUP_STATUS_PRAGMA_NAME_KEY, secret.expose_secret())?;
    }
    connection.pragma_update(
        None,
        GROUP_STATUS_PRAGMA_NAME_JOURNAL_MODE,
        GROUP_STATUS_JOURNAL_MODE_WAL,
    )?;
    connection.busy_timeout(GROUP_STATUS_BUSY_TIMEOUT)?;
    Ok(())
}

pub fn open_group_status_connection(
    path: &str,
    secret: &Option<SecretString>,
) -> Result<GroupStatusConnection, Error> {
    let path = path.to_owned();
    let secret = secret.clone();
    let conn = SqliteConnectionPool::new(GROUP_STATUS_CONNECTION_POOL_SIZE, move || {
        let connection = Connection::open(&path)?;
        configure_group_status_connection(&connection, &secret)?;
        Ok(connection)
    });
    initialize(&conn)?;
    Ok(conn)
}

#[inline]
fn emit_log(log: Option<&dyn Fn(String)>, build_msg: impl FnOnce() -> String) {
    if let Some(cb) = log {
        cb(build_msg());
    }
}

pub struct ProcessAllMessagesArgs {
    pub group_messages: Vec<AllMessagesOfGroupArgs>,
}

pub struct AllMessagesOfGroupArgs {
    pub group_id: String,
    pub messages: Vec<MlsMessage>,
    pub current_epoch: i64,
    pub current_tree_hash: Vec<u8>,
    pub pending_epoch: i64,
    pub pending_tree_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MlsMessage {
    pub blob: Vec<u8>,
    pub epoch: u64,
    pub sender: String,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MessageType {
    Welcome,
    Commit,
    Proposal,
    Unknown,
}

impl From<&str> for MessageType {
    fn from(value: &str) -> Self {
        match value {
            "MLS_MESSAGE_TYPE_WELCOME" => Self::Welcome,
            "MLS_MESSAGE_TYPE_COMMIT" => Self::Commit,
            "MLS_MESSAGE_TYPE_PROPOSAL" => Self::Proposal,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GroupPendingOperation {
    CreateGroup,
    JoinByExternalCommit,
    LeaveGroup,
    UpdateTree,
    None,
}

pub const OP_CREATE_GROUP: &str = "create_group";
pub const OP_JOIN_BY_EXTERNAL_COMMIT: &str = "join_by_external_commit";
pub const OP_LEAVE_GROUP: &str = "leave_group";
pub const OP_UPDATE_TREE: &str = "update_tree";
pub const OP_NONE: &str = "none";

impl From<Option<String>> for GroupPendingOperation {
    fn from(value: Option<String>) -> Self {
        match value {
            None => Self::None,
            Some(value) => match value.as_str() {
                OP_CREATE_GROUP => Self::CreateGroup,
                OP_JOIN_BY_EXTERNAL_COMMIT => Self::JoinByExternalCommit,
                OP_LEAVE_GROUP => Self::LeaveGroup,
                OP_UPDATE_TREE => Self::UpdateTree,
                _ => Self::None,
            },
        }
    }
}

impl Into<String> for GroupPendingOperation {
    fn into(self) -> String {
        match self {
            GroupPendingOperation::CreateGroup => OP_CREATE_GROUP.to_owned(),
            GroupPendingOperation::JoinByExternalCommit => OP_JOIN_BY_EXTERNAL_COMMIT.to_owned(),
            GroupPendingOperation::LeaveGroup => OP_LEAVE_GROUP.to_owned(),
            GroupPendingOperation::UpdateTree => OP_UPDATE_TREE.to_owned(),
            GroupPendingOperation::None => OP_NONE.to_owned(),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CustomProposal {
    pub client_jid: Option<String>,
    pub mls_client_id: Option<String>,
    pub mls_fingerprint: Option<String>,
    pub epoch: Option<u64>,
    pub group_id: String,
    pub proposal_type: CustomProposalType,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CustomProposalType {
    ReAdd,
    Remove,
}

impl ToString for CustomProposalType {
    fn to_string(&self) -> String {
        match self {
            CustomProposalType::ReAdd => "ReAdd".to_owned(),
            CustomProposalType::Remove => "Remove".to_owned(),
        }
    }
}

pub fn insert_or_update_group_status(
    conn: &GroupStatusConnection,
    group_id: &str,
    pending_operation: GroupPendingOperation,
) -> Result<(), Error> {
    let pending_operation: String = pending_operation.into();
    let connection = conn.checkout()?;
    let mut stmt = connection.prepare_cached(
        "
        INSERT INTO group_statuses (group_id, pending_operation)
        VALUES (?1, ?2)
        ON CONFLICT(group_id) DO UPDATE SET pending_operation = excluded.pending_operation
        ",
    )?;

    stmt.execute(params![group_id, pending_operation])?;

    Ok(())
}

pub fn delete_group_status(conn: &GroupStatusConnection, group_id: &str) -> Result<(), Error> {
    let connection = conn.checkout()?;
    let mut stmt = connection.prepare_cached("DELETE FROM group_statuses WHERE group_id = ?1")?;
    stmt.execute(params![group_id])?;

    Ok(())
}

pub fn get_group_pending_operation(
    conn: &GroupStatusConnection,
    group_id: &str,
) -> Result<Option<String>, Error> {
    let conn = conn.checkout()?;
    let mut stmt = conn.prepare_cached(
        "SELECT group_id, pending_operation FROM group_statuses WHERE group_id = ?1",
    )?;

    let mut rows = stmt.query(params![group_id])?;

    if let Some(row) = rows.next()? {
        Ok(Some(row.get(1)?))
    } else {
        Ok(None)
    }
}

pub fn get_group_pending_operations_batch(
    conn: &GroupStatusConnection,
    group_ids: &[String],
) -> Result<HashMap<String, String>, Error> {
    if group_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let conn = conn.checkout()?;
    let placeholders = (1..=group_ids.len())
        .map(|i| format!("?{}", i))
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "SELECT group_id, pending_operation FROM group_statuses WHERE group_id IN ({})",
        placeholders
    );

    let mut stmt = conn.prepare(&query)?;
    let params: Vec<&dyn rusqlite::ToSql> = group_ids
        .iter()
        .map(|id| id as &dyn rusqlite::ToSql)
        .collect();

    let mut rows = stmt.query(params.as_slice())?;
    let mut result = HashMap::new();

    while let Some(row) = rows.next()? {
        let group_id: String = row.get(0)?;
        let pending_op: String = row.get(1)?;
        result.insert(group_id, pending_op);
    }

    Ok(result)
}

pub fn initialize(conn: &GroupStatusConnection) -> Result<(), Error> {
    conn.checkout()?.execute(
        "
        CREATE TABLE IF NOT EXISTS group_statuses (
            group_id TEXT PRIMARY KEY,
            pending_operation TEXT NOT NULL
        );
        ",
        [],
    )?;

    Ok(())
}

#[derive(Debug)]
pub struct GroupResult {
    pub group_id: String,
    pub members_to_remove: Vec<MemberInfo>,
    pub members_to_readd: Vec<MemberInfo>,
    pub error: Option<GroupError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupErrorCode {
    Storage,
    Aead,
    ProcessCommit,
}

#[derive(Debug, Clone)]
pub struct GroupError {
    pub error_code: GroupErrorCode,
    pub error_message: String,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct MemberInfo {
    pub client_jid: Option<String>,
    pub mls_client_id: Option<String>,
    pub mls_fingerprint: Option<String>,
}

pub struct ProcessAllMessagesResult {
    pub group_results: Vec<GroupResult>,
    pub deleted_groups: Vec<String>,
}

pub fn process_all_messages(
    conn: &GroupStatusConnection,
    provider: &SqliteProvider,
    args: ProcessAllMessagesArgs,
    join_config: &MlsGroupJoinConfig,
    log: Option<&dyn Fn(String)>,
) -> Result<ProcessAllMessagesResult, Error> {
    emit_log(log, || "start process all messages".to_owned());

    let mut result = ProcessAllMessagesResult {
        group_results: Vec::new(),
        deleted_groups: Vec::new(),
    };

    for messages_of_group in args.group_messages {
        let group_id = &messages_of_group.group_id;
        emit_log(log, || format!("process message of group {}", group_id));

        let preload_epochs = messages_of_group
            .messages
            .iter()
            .filter(|message| message.message_type != MessageType::Welcome)
            .map(|message| message.epoch.into());
        let mut mls_group: Option<MlsGroup> =
            group_with_epoch_message_secrets(provider, group_id, preload_epochs).ok();

        let mut group_deleted = false;
        // Check desync to merge or clear pending commit
        if let Some(existing_group) = &mls_group {
            let Some(own_member_id) = own_id_from_leaf_node(existing_group) else {
                continue;
            };

            let pending_operation: GroupPendingOperation =
                get_group_pending_operation(&conn, group_id)?.into();

            let first_message = get_first_message(
                existing_group.epoch().as_u64(),
                &messages_of_group,
                pending_operation,
            );

            match pending_operation {
                GroupPendingOperation::CreateGroup
                | GroupPendingOperation::JoinByExternalCommit => {
                    if pending_operation == GroupPendingOperation::CreateGroup
                        && existing_group.epoch().as_u64() == 0
                    {
                        if messages_of_group.pending_epoch == 0 {
                            if existing_group
                                .tree_hash()
                                .to_vec()
                                .iter()
                                .eq(&messages_of_group.pending_tree_hash)
                            {
                                mls_group = Some(
                                    provider
                                        .transaction(|tx_provider| {
                                            let mut tx_group = group(tx_provider, group_id, [])?;
                                            merge_pending_commit(&mut tx_group, tx_provider)?;
                                            Ok(tx_group)
                                        })
                                        .map_err(|e| Error::Storage(e.to_string()))?,
                                );
                            } else {
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id, [])?;
                                        delete_group(&mut tx_group, tx_provider)
                                    })
                                    .map_err(|e| Error::Storage(e.to_string()))?;
                                result.deleted_groups.push(group_id.to_owned());
                                let _ = delete_group_status(&conn, group_id);
                                group_deleted = true;
                            }
                            let _ = insert_or_update_group_status(
                                &conn,
                                group_id,
                                GroupPendingOperation::None,
                            );
                        }
                    } else {
                        if let Some(msg) = first_message {
                            if !sender_matches_member_id(&own_member_id, &msg.sender) {
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id, [])?;
                                        delete_group(&mut tx_group, tx_provider)
                                    })
                                    .map_err(|e| Error::Storage(e.to_string()))?;
                                result.deleted_groups.push(group_id.to_owned());
                                let _ = delete_group_status(&conn, group_id);
                                group_deleted = true;
                            } else {
                                mls_group = Some(
                                    provider
                                        .transaction(|tx_provider| {
                                            let mut tx_group = group(tx_provider, group_id, [])?;
                                            merge_pending_commit(&mut tx_group, tx_provider)?;
                                            Ok(tx_group)
                                        })
                                        .map_err(|e| Error::Storage(e.to_string()))?,
                                );
                            }
                        } else {
                            provider
                                .transaction(|tx_provider| {
                                    let mut tx_group = group(tx_provider, group_id, [])?;
                                    delete_group(&mut tx_group, tx_provider)
                                })
                                .map_err(|e| Error::Storage(e.to_string()))?;
                            result.deleted_groups.push(group_id.to_owned());
                            let _ = delete_group_status(&conn, group_id);
                            group_deleted = true;
                        }
                        let _ = insert_or_update_group_status(
                            &conn,
                            group_id,
                            GroupPendingOperation::None,
                        );
                    }
                }
                GroupPendingOperation::UpdateTree => {
                    if let Some(msg) = first_message {
                        if !sender_matches_member_id(&own_member_id, &msg.sender) {
                            mls_group = Some(
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id, [])?;
                                        clear_pending_commit(&mut tx_group, tx_provider)?;
                                        Ok(tx_group)
                                    })
                                    .map_err(|e| Error::Storage(e.to_string()))?,
                            );
                        } else {
                            mls_group = Some(
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id, [])?;
                                        merge_pending_commit(&mut tx_group, tx_provider)?;
                                        Ok(tx_group)
                                    })
                                    .map_err(|e| Error::Storage(e.to_string()))?,
                            );
                        }
                    } else {
                        mls_group = Some(
                            provider
                                .transaction(|tx_provider| {
                                    let mut tx_group = group(tx_provider, group_id, [])?;
                                    clear_pending_commit(&mut tx_group, tx_provider)?;
                                    Ok(tx_group)
                                })
                                .map_err(|e| Error::Storage(e.to_string()))?,
                        );
                    }

                    let _ =
                        insert_or_update_group_status(&conn, group_id, GroupPendingOperation::None);
                }
                GroupPendingOperation::LeaveGroup => {
                    // NOTE: we don't handle leave group in this operation
                }
                GroupPendingOperation::None => (),
            }
        }

        if group_deleted {
            mls_group = None;
        }

        let mut members_to_remove_hashmap = HashMap::new();
        let mut members_to_readd: HashSet<MemberInfo> = HashSet::new();

        let mut group_member_sets: Option<(HashSet<String>, HashSet<String>)> = None;

        let mut lastest_epoch = 0;
        for msg in &messages_of_group.messages {
            if msg.epoch > lastest_epoch && msg.message_type == MessageType::Commit {
                lastest_epoch = msg.epoch;
            }

            if msg.message_type == MessageType::Proposal {
                if let Some(group) = &mut mls_group {
                    if let Ok(proposal) = process_proposal_message(group, provider, &msg.blob) {
                        emit_log(log, || {
                            format!("start process proposal, group {}", group_id)
                        });

                        if proposal.proposal == Proposal::Remove {
                            let (group_member_id_set, _) = group_member_sets
                                .get_or_insert_with(|| collect_group_member_ids_and_jids(group));
                            if group_member_id_set.contains(&proposal.sender) {
                                members_to_remove_hashmap.insert(
                                    MemberInfo {
                                        client_jid: extract_jid_from_member_id(&proposal.sender),
                                        mls_client_id: Some(proposal.sender),
                                        mls_fingerprint: Some(msg.sender.to_owned()),
                                    },
                                    msg.epoch,
                                );
                            }
                        }

                        emit_log(log, || format!("end process proposal, group {}", group_id));
                    } else if let Some(custom_proposal) = process_custom_proposal(&msg.blob) {
                        emit_log(log, || {
                            format!(
                                "start process custom proposal, group {}, proposal {:?}",
                                group_id, custom_proposal
                            )
                        });

                        if let Some(client_jid) = custom_proposal.client_jid {
                            if custom_proposal.proposal_type == CustomProposalType::Remove {
                                let (_, group_member_jid_set) = group_member_sets
                                    .get_or_insert_with(|| {
                                        collect_group_member_ids_and_jids(group)
                                    });
                                if group_member_jid_set.contains(&client_jid) {
                                    emit_log(log, || {
                                        format!(
                                            "process custom proposal, group {}, client jid {}",
                                            group_id, client_jid
                                        )
                                    });
                                    members_to_remove_hashmap.insert(
                                        MemberInfo {
                                            client_jid: Some(client_jid),
                                            mls_client_id: None,
                                            mls_fingerprint: None,
                                        },
                                        msg.epoch,
                                    );
                                }
                            }
                        }

                        emit_log(log, || {
                            format!("end process custom proposal, group {}", group_id)
                        });
                    }
                }
            }
        }

        // Process all messages
        let mut error = None;
        let mut commit_group_loaded = false;
        'process_operation: for msg in &messages_of_group.messages {
            match msg.message_type {
                MessageType::Welcome => {
                    emit_log(log, || format!("process welcome, group {}", group_id));
                    match provider
                        .transaction(|tx_provider| {
                            process_welcome(tx_provider, &msg.blob, join_config)
                        })
                        .map_err(|e| Error::Storage(e.to_string()))
                    {
                        Ok(new_group) => {
                            mls_group = Some(new_group);
                        }
                        Err(err) => {
                            emit_log(log, || {
                                format!("process welcome error, group {}: {}", group_id, err)
                            });
                        }
                    }
                }
                MessageType::Commit => {
                    emit_log(log, || {
                        format!(
                            "start process commit, group {}, epoch {}",
                            group_id, msg.epoch
                        )
                    });
                    if mls_group.is_some() {
                        if !commit_group_loaded {
                            match group_with_epoch_message_secrets(
                                provider,
                                group_id,
                                [msg.epoch.into()],
                            ) {
                                Ok(fresh_group) => {
                                    emit_log(log, || {
                                        format!(
                                            "process commit - load group data done, group {}, epoch {}",
                                            group_id, msg.epoch
                                        )
                                    });
                                    mls_group = Some(fresh_group);
                                    commit_group_loaded = true;
                                }
                                Err(err) => {
                                    let err_log = format!(
                                        "process commit - load group data error, group {}: {}",
                                        group_id, err
                                    );
                                    emit_log(log, || err_log.clone());
                                    if err_log
                                        .contains("Error writing updated group data to storage")
                                        || err_log.contains("database is locked")
                                        || err_log.contains("Error interacting with storage")
                                    {
                                        error = Some(GroupError {
                                            error_code: convert_to_error_code(&err),
                                            error_message: err_log.to_owned(),
                                        });
                                        members_to_remove_hashmap.clear();
                                        break 'process_operation;
                                    }
                                }
                            }
                        }

                        if let Some(mut current_group) = mls_group.take() {
                            match provider
                                .transaction(|tx_provider| {
                                    let _ = process_operation_message(
                                        &mut current_group,
                                        tx_provider,
                                        &msg.blob,
                                    )?;
                                    Ok(())
                                })
                                .map_err(|e| Error::ProcessMessage(e.to_string()))
                            {
                                Ok(()) => {
                                    mls_group = Some(current_group);
                                }
                                Err(err) => {
                                    mls_group = Some(current_group);
                                    let err_log = format!(
                                        "process commit error, group {}: {}",
                                        group_id, err
                                    );
                                    emit_log(log, || err_log.clone());
                                    if err_log
                                        .contains("Error writing updated group data to storage")
                                        || err_log.contains("database is locked")
                                        || err_log.contains("Error interacting with storage")
                                    {
                                        error = Some(GroupError {
                                            error_code: convert_to_error_code(&err),
                                            error_message: err_log.to_owned(),
                                        });
                                        members_to_remove_hashmap.clear();
                                        break 'process_operation;
                                    }
                                }
                            }
                        } else {
                            emit_log(log, || {
                                format!("process commit error, group {}: group not found", group_id)
                            });
                        }

                        emit_log(log, || {
                            format!(
                                "end process commit, group {}, epoch {}",
                                group_id, msg.epoch
                            )
                        });
                    } else {
                        emit_log(log, || {
                            format!("process commit error, group {}: group not found", group_id)
                        });
                    }

                    if !members_to_remove_hashmap.is_empty() {
                        let mut already_remove_members = Vec::new();
                        if let Some(group) = &mls_group {
                            let (group_member_id_set, group_member_jid_set) =
                                collect_group_member_ids_and_jids(group);
                            for (member_info, epoch) in members_to_remove_hashmap.iter() {
                                if let Some(mls_client_id) = &member_info.mls_client_id {
                                    if msg.epoch >= *epoch
                                        && !group_member_id_set.contains(mls_client_id)
                                    {
                                        already_remove_members.push(member_info.to_owned());
                                    }
                                } else if let Some(client_jid) = &member_info.client_jid {
                                    if msg.epoch >= *epoch
                                        && !group_member_jid_set.contains(client_jid)
                                    {
                                        already_remove_members.push(member_info.to_owned());
                                    }
                                }
                            }
                        }

                        for member_id in already_remove_members {
                            members_to_remove_hashmap.remove(&member_id);
                        }
                    }
                }
                MessageType::Proposal => {
                    if let Some(custom_proposal) = process_custom_proposal(&msg.blob) {
                        if custom_proposal.proposal_type == CustomProposalType::ReAdd
                            && msg.epoch > lastest_epoch
                        {
                            members_to_readd.insert(MemberInfo {
                                client_jid: if let Some(client_jid) = &custom_proposal.client_jid {
                                    Some(client_jid.to_owned())
                                } else if let Some(mls_client_id) = &custom_proposal.mls_client_id {
                                    extract_jid_from_member_id(mls_client_id)
                                } else {
                                    None
                                },
                                mls_client_id: custom_proposal.mls_client_id,
                                mls_fingerprint: Some(msg.sender.to_owned()),
                            });
                        }
                    }
                }
                MessageType::Unknown => {
                    emit_log(log, || {
                        format!("unknown message type {:?}", msg.message_type)
                    });
                }
            }
        }

        result.group_results.push(GroupResult {
            group_id: group_id.to_owned(),
            members_to_remove: members_to_remove_hashmap
                .keys()
                .into_iter()
                .map(|member_id| member_id.to_owned())
                .collect(),
            members_to_readd: members_to_readd
                .into_iter()
                .map(|member_id| member_id.to_owned())
                .collect(),
            error,
        });
    }

    emit_log(log, || "end process all messages".to_owned());

    Ok(result)
}

// TODO: refactor this later match by error enum
fn convert_to_error_code(err: &Error) -> GroupErrorCode {
    let err_str = err.to_string();
    if err_str.contains("An error occurred during AEAD decryption.") {
        GroupErrorCode::Aead
    } else if err_str.contains("Storage error") {
        GroupErrorCode::Storage
    } else {
        GroupErrorCode::ProcessCommit
    }
}

pub struct CreateCustomProposalArgs {
    pub mls_fingerprint: String,
    pub custom_proposal_type: CustomProposalType,
}

pub fn create_custom_proposal(
    mls_client_id: &str,
    group_id: &str,
    request: CreateCustomProposalArgs,
) -> Vec<u8> {
    let proposal = CustomProposal {
        mls_client_id: Some(mls_client_id.to_owned()),
        client_jid: extract_jid_from_member_id(mls_client_id),
        mls_fingerprint: Some(request.mls_fingerprint),
        epoch: None,
        group_id: group_id.to_owned(),
        proposal_type: request.custom_proposal_type,
    };

    serde_json::to_vec(&proposal).unwrap_or_default()
}

pub fn process_custom_proposal(custom_proposal: &[u8]) -> Option<CustomProposal> {
    serde_json::from_slice::<CustomProposal>(custom_proposal).ok()
}

fn get_first_message(
    mut group_epoch: u64,
    messages_of_group: &AllMessagesOfGroupArgs,
    pending_operation: GroupPendingOperation,
) -> Option<&MlsMessage> {
    if pending_operation == GroupPendingOperation::JoinByExternalCommit {
        group_epoch -= 1;
    }

    for message in &messages_of_group.messages {
        if message.epoch == group_epoch + 1 && message.message_type == MessageType::Commit {
            return Some(message);
        }
    }

    None
}

fn own_id_from_leaf_node(group: &MlsGroup) -> Option<String> {
    if let Some(own_leaf) = group.own_leaf() {
        if let Ok(basic_cred) = BasicCredential::try_from(own_leaf.credential().to_owned()) {
            if let Ok(id) = String::from_utf8(basic_cred.identity().to_vec()) {
                return Some(id);
            }
        }
    }

    None
}

fn sender_matches_member_id(member_id: &str, sender: &str) -> bool {
    if sender.is_empty() {
        return false;
    }

    member_id == sender
        || member_id
            .split_once('/')
            .is_some_and(|(_, fingerprint)| fingerprint == sender)
}

fn id_from_credential(cred: &Credential) -> Option<String> {
    if let Ok(basic_cred) = BasicCredential::try_from(cred.to_owned()) {
        if let Ok(id) = String::from_utf8(basic_cred.identity().to_vec()) {
            return Some(id);
        }
    }

    None
}

fn collect_group_member_ids_and_jids(group: &MlsGroup) -> (HashSet<String>, HashSet<String>) {
    let mut id_set = HashSet::new();
    let mut jid_set = HashSet::new();

    for member in group.members() {
        if let Some(id) = id_from_credential(&member.credential) {
            if let Some(jid) = extract_jid_from_member_id(&id) {
                jid_set.insert(jid);
            }

            id_set.insert(id);
        }
    }

    (id_set, jid_set)
}

pub fn extract_jid_from_member_id(id: &str) -> Option<String> {
    if let Some(slash_pos) = id.find('/') {
        let jid = &id[..slash_pos];
        return Some(jid.to_owned());
    }

    None
}
pub fn get_all_group_ids(provider: &SqliteProvider) -> Vec<String> {
    let mut group_ids = Vec::new();
    let mut seen = HashSet::new();

    let connection = match provider.storage().connection_pool().checkout() {
        Ok(conn) => conn,
        Err(_) => return group_ids,
    };

    let mut stmt = match connection
        .prepare("SELECT DISTINCT group_id FROM openmls_group_data WHERE provider_version = ?")
    {
        Ok(stmt) => stmt,
        Err(_) => return group_ids,
    };

    let blobs: Vec<Vec<u8>> = match stmt
        .query_map([kchat_storage_provider::STORAGE_PROVIDER_VERSION], |row| {
            row.get::<_, Vec<u8>>(0)
        }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => return group_ids,
    };

    for blob in blobs {
        if let Ok(group_id) = serde_json::from_slice::<openmls::group::GroupId>(&blob) {
            let group_id = String::from_utf8_lossy(group_id.as_slice()).to_string();
            if seen.insert(group_id.clone()) {
                group_ids.push(group_id);
            }
        }
    }

    group_ids
}

#[cfg(test)]
mod tests {
    use super::sender_matches_member_id;

    #[test]
    fn sender_matches_full_member_id_or_exact_fingerprint() {
        let member_id = "alice@example.com/device-fingerprint";

        assert!(sender_matches_member_id(member_id, member_id));
        assert!(sender_matches_member_id(member_id, "device-fingerprint"));
    }

    #[test]
    fn sender_rejects_partial_or_empty_matches() {
        let member_id = "alice@example.com/device-fingerprint";

        assert!(!sender_matches_member_id(member_id, "alice@example.com"));
        assert!(!sender_matches_member_id(member_id, "device"));
        assert!(!sender_matches_member_id(member_id, "fingerprint"));
        assert!(!sender_matches_member_id(member_id, ""));
    }
}
