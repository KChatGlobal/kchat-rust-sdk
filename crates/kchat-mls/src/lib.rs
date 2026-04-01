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
use rusqlite::{Connection, params};
use uq_openmls::{
    core::{
        Proposal, clear_pending_commit, delete_group, group, group_signer, merge_pending_commit,
        process_operation_message, process_proposal_message, process_welcome,
    },
    error::Error,
    provider::SqliteProvider,
};

pub type GroupStatusConnection = SqliteConnectionPool;

const GROUP_STATUS_CONNECTION_POOL_SIZE: usize = 8;
const GROUP_STATUS_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn configure_group_status_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.busy_timeout(GROUP_STATUS_BUSY_TIMEOUT)?;
    Ok(())
}

pub fn open_group_status_connection(path: &str) -> Result<GroupStatusConnection, Error> {
    let path = path.to_owned();
    let conn = SqliteConnectionPool::new(GROUP_STATUS_CONNECTION_POOL_SIZE, move || {
        let connection = Connection::open(&path)?;
        configure_group_status_connection(&connection)?;
        Ok(connection)
    });
    initialize(&conn)?;
    Ok(conn)
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
}

impl From<&str> for MessageType {
    fn from(value: &str) -> Self {
        match value {
            "MLS_MESSAGE_TYPE_WELCOME" => Self::Welcome,
            "MLS_MESSAGE_TYPE_COMMIT" => Self::Commit,
            "MLS_MESSAGE_TYPE_PROPOSAL" => Self::Proposal,
            _ => panic!("invalid message type"),
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

#[derive(
    Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, serde::Serialize, serde::Deserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct CustomProposal {
    pub mls_client_id: String,
    pub mls_fingerprint: String,
    pub group_id: String,
    pub proposal_type: CustomProposalType,
}

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum CustomProposalType {
    ReAdd,
}

impl ToString for CustomProposalType {
    fn to_string(&self) -> String {
        match self {
            CustomProposalType::ReAdd => "ReAdd".to_owned(),
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

pub struct GroupResult {
    pub group_id: String,
    pub members_to_remove: Vec<MemberInfo>,
    pub members_to_readd: Vec<MemberInfo>,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct MemberInfo {
    pub mls_client_id: String,
    pub mls_fingerprint: String,
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
    let emit = |msg: String| {
        if let Some(cb) = &log {
            cb(msg);
        }
    };

    emit("start process all messages".to_owned());

    let mut result = ProcessAllMessagesResult {
        group_results: Vec::new(),
        deleted_groups: Vec::new(),
    };

    for messages_of_group in args.group_messages {
        let group_id = &messages_of_group.group_id;
        emit(format!("process message of group {}", group_id));

        let mut mls_group: Option<MlsGroup> = group(provider, group_id).ok();

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
                                            let mut tx_group = group(tx_provider, group_id)?;
                                            merge_pending_commit(&mut tx_group, tx_provider)?;
                                            Ok(tx_group)
                                        })
                                        .map_err(|e| Error::Storage(e.to_string()))?,
                                );
                            } else {
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id)?;
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
                            if !own_member_id.contains(&msg.sender) {
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id)?;
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
                                            let mut tx_group = group(tx_provider, group_id)?;
                                            merge_pending_commit(&mut tx_group, tx_provider)?;
                                            Ok(tx_group)
                                        })
                                        .map_err(|e| Error::Storage(e.to_string()))?,
                                );
                            }
                        } else {
                            provider
                                .transaction(|tx_provider| {
                                    let mut tx_group = group(tx_provider, group_id)?;
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
                        if !own_member_id.contains(&msg.sender) {
                            mls_group = Some(
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id)?;
                                        clear_pending_commit(&mut tx_group, tx_provider)?;
                                        Ok(tx_group)
                                    })
                                    .map_err(|e| Error::Storage(e.to_string()))?,
                            );
                        } else {
                            mls_group = Some(
                                provider
                                    .transaction(|tx_provider| {
                                        let mut tx_group = group(tx_provider, group_id)?;
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
                                    let mut tx_group = group(tx_provider, group_id)?;
                                    clear_pending_commit(&mut tx_group, tx_provider)?;
                                    Ok(tx_group)
                                })
                                .map_err(|e| Error::Storage(e.to_string()))?,
                        );
                    }

                    let _ =
                        insert_or_update_group_status(&conn, group_id, GroupPendingOperation::None);
                }
                GroupPendingOperation::LeaveGroup => {}
                GroupPendingOperation::None => (),
            }
        }

        if group_deleted {
            mls_group = None;
        }

        let mut members_to_remove_hashmap = HashMap::new();
        let mut members_to_readd = HashSet::new();

        let group_member_set = mls_group
            .as_ref()
            .map(|group| collect_group_member_ids(group));

        let mut lastest_epoch = 0;
        for msg in &messages_of_group.messages {
            if msg.epoch > lastest_epoch && msg.message_type == MessageType::Commit {
                lastest_epoch = msg.epoch;
            }

            if msg.message_type == MessageType::Proposal {
                if let Some(group) = &mut mls_group {
                    if let Ok(proposal) = process_proposal_message(group, provider, &msg.blob) {
                        if group_member_set
                            .as_ref()
                            .map(|set| set.contains(&proposal.sender))
                            .unwrap_or(false)
                            && proposal.proposal == Proposal::Remove
                        {
                            members_to_remove_hashmap.insert(
                                MemberInfo {
                                    mls_client_id: proposal.sender,
                                    mls_fingerprint: msg.sender.to_owned(),
                                },
                                msg.epoch,
                            );
                        }
                    }
                }
            }
        }

        // Process all messages
        for msg in &messages_of_group.messages {
            match msg.message_type {
                MessageType::Welcome => {
                    emit(format!("process welcome, group {}", group_id));
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
                            emit(format!(
                                "process welcome error, group {}: {}",
                                group_id, err
                            ));
                        }
                    }
                }
                MessageType::Commit => {
                    emit(format!(
                        "start process commit, group {}, epoch {}",
                        group_id, msg.epoch
                    ));
                    if mls_group.is_some() {
                        match provider
                            .transaction(|tx_provider| {
                                let mut tx_group = group(tx_provider, group_id)?;
                                let tx_signer = group_signer(&tx_group, tx_provider)?;
                                let _ = process_operation_message(
                                    &mut tx_group,
                                    tx_provider,
                                    &tx_signer,
                                    &msg.blob,
                                )?;
                                Ok(tx_group)
                            })
                            .map_err(|e| Error::Storage(e.to_string()))
                        {
                            Ok(updated_group) => {
                                mls_group = Some(updated_group);
                            }
                            Err(err) => {
                                emit(format!("process commit error, group {}: {}", group_id, err));
                            }
                        }

                        emit(format!(
                            "end process commit, group {}, epoch {}",
                            group_id, msg.epoch
                        ));
                    } else {
                        emit(format!(
                            "process commit error, group {}: group not found",
                            group_id
                        ));
                    }

                    if !members_to_remove_hashmap.is_empty() {
                        let mut already_remove_members = Vec::new();
                        if let Some(group) = &mls_group {
                            let group_member_set = collect_group_member_ids(group);
                            for (member_info, epoch) in members_to_remove_hashmap.iter() {
                                if msg.epoch >= *epoch
                                    && !group_member_set.contains(&member_info.mls_client_id)
                                {
                                    already_remove_members.push(member_info.to_owned());
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
                                mls_client_id: custom_proposal.mls_client_id,
                                mls_fingerprint: msg.sender.to_owned(),
                            });
                        }
                    }
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
        });
    }

    emit("end process all messages".to_owned());

    Ok(result)
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
        mls_client_id: mls_client_id.to_owned(),
        mls_fingerprint: request.mls_fingerprint,
        group_id: group_id.to_owned(),
        proposal_type: request.custom_proposal_type,
    };

    // rkyv::to_bytes::<rkyv::rancor::Error>(&proposal)
    //     .map(|bytes| bytes.into_vec())
    //     .unwrap_or_default()

    serde_json::to_vec(&proposal).unwrap_or_default()
}

pub fn process_custom_proposal(custom_proposal: &[u8]) -> Option<CustomProposal> {
    if let Ok(raw) = rkyv::from_bytes::<CustomProposal, rkyv::rancor::Error>(custom_proposal) {
        Some(raw)
    } else {
        serde_json::from_slice::<CustomProposal>(custom_proposal).ok()
    }
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

fn id_from_credential(cred: &Credential) -> Option<String> {
    if let Ok(basic_cred) = BasicCredential::try_from(cred.to_owned()) {
        if let Ok(id) = String::from_utf8(basic_cred.identity().to_vec()) {
            return Some(id);
        }
    }

    None
}

fn collect_group_member_ids(group: &MlsGroup) -> HashSet<String> {
    let mut set = HashSet::new();

    for member in group.members() {
        if let Some(id) = id_from_credential(&member.credential) {
            set.insert(id);
        }
    }

    set
}
