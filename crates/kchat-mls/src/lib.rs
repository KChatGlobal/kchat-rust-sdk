use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    u64,
};

use openmls::{
    group::{MlsGroup, MlsGroupJoinConfig},
    prelude::{BasicCredential, Credential},
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uq_openmls::{
    core::{
        Proposal, clear_pending_commit, delete_group, group, group_signer, merge_pending_commit,
        process_operation_message, process_proposal_message, process_welcome,
    },
    error::Error,
    provider::SqliteProvider,
};

pub struct ProcessAllMessagesArgs {
    pub group_messages: Vec<AllMessagesOfGroupArgs>,
}

pub struct AllMessagesOfGroupArgs {
    pub group_id: String,
    pub messages: Vec<MlsMessage>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomProposal {
    pub mls_client_id: String,
    pub mls_fingerprint: String,
    pub group_id: String,
    pub proposal_type: CustomProposalType,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
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
    conn: &Arc<Mutex<Connection>>,
    group_id: &str,
    pending_operation: GroupPendingOperation,
) -> Result<(), Error> {
    let pending_operation: String = pending_operation.into();

    conn.lock().unwrap().execute(
        "
        INSERT INTO group_statuses (group_id, pending_operation)
        VALUES (?1, ?2)
        ON CONFLICT(group_id) DO UPDATE SET pending_operation = excluded.pending_operation
        ",
        params![group_id, pending_operation],
    )?;

    Ok(())
}

pub fn delete_group_status(conn: &Arc<Mutex<Connection>>, group_id: &str) -> Result<(), Error> {
    conn.lock().unwrap().execute(
        "DELETE FROM group_statuses WHERE group_id = ?1",
        params![group_id],
    )?;

    Ok(())
}

pub fn get_group_pending_operation(
    conn: &Arc<Mutex<Connection>>,
    group_id: &str,
) -> Result<Option<String>, Error> {
    let conn = conn.lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT group_id, pending_operation FROM group_statuses WHERE group_id = ?1")?;

    let mut rows = stmt.query(params![group_id])?;

    if let Some(row) = rows.next()? {
        Ok(Some(row.get(1)?))
    } else {
        Ok(None)
    }
}

pub fn initialize(conn: &Arc<Mutex<Connection>>) -> Result<(), Error> {
    conn.lock().unwrap().execute(
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
    conn: &Arc<Mutex<Connection>>,
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
        if let Some(group) = &mut mls_group {
            let Some(own_member_id) = own_id_from_leaf_node(group) else {
                continue;
            };

            let mut pending_operation: GroupPendingOperation =
                get_group_pending_operation(&conn, group_id)?.into();
            if group.epoch().as_u64() == 0 {
                pending_operation = GroupPendingOperation::CreateGroup;
            }
            let first_message = get_first_message(
                group.epoch().as_u64(),
                &messages_of_group,
                pending_operation,
            );

            match pending_operation {
                GroupPendingOperation::CreateGroup
                | GroupPendingOperation::JoinByExternalCommit => {
                    if let Some(msg) = first_message {
                        if !own_member_id.contains(&msg.sender) {
                            delete_group(group, provider)?;
                            group_deleted = true;
                            result.deleted_groups.push(group_id.to_owned());
                            let _ = delete_group_status(&conn, group_id);
                        } else {
                            merge_pending_commit(group, provider)?;
                        }
                    } else {
                        delete_group(group, provider)?;
                        group_deleted = true;
                        result.deleted_groups.push(group_id.to_owned());
                        let _ = delete_group_status(&conn, group_id);
                    }

                    let _ =
                        insert_or_update_group_status(&conn, group_id, GroupPendingOperation::None);
                }
                GroupPendingOperation::LeaveGroup => {
                    // TODO: handle leave group
                }
                GroupPendingOperation::UpdateTree => {
                    if let Some(msg) = first_message {
                        if !own_member_id.contains(&msg.sender) {
                            clear_pending_commit(group, provider)?;
                        } else {
                            merge_pending_commit(group, provider)?;
                        }
                    } else {
                        clear_pending_commit(group, provider)?;
                    }

                    let _ =
                        insert_or_update_group_status(&conn, group_id, GroupPendingOperation::None);
                }
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

        let mut signer = match mls_group.as_ref() {
            Some(g) => match group_signer(g, provider) {
                Ok(s) => Some(s),
                Err(err) => {
                    emit(format!("get signer error, group {}: {}", group_id, err));
                    None
                }
            },
            None => None,
        };

        for msg in &messages_of_group.messages {
            match msg.message_type {
                MessageType::Welcome => {
                    emit(format!("process welcome, group {}", group_id));
                    match process_welcome(provider, &msg.blob, join_config) {
                        Ok(new_group) => {
                            signer = group_signer(&new_group, provider).ok();
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
                    if let Some(group) = &mut mls_group {
                        if let Some(signer) = &signer {
                            if let Err(err) =
                                process_operation_message(group, provider, signer, &msg.blob)
                            {
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
    serde_json::to_vec(&CustomProposal {
        mls_client_id: mls_client_id.to_owned(),
        mls_fingerprint: request.mls_fingerprint.to_owned(),
        group_id: group_id.to_owned(),
        proposal_type: request.custom_proposal_type,
    })
    .unwrap_or_default()
}

pub fn process_custom_proposal(custom_proposal: &[u8]) -> Option<CustomProposal> {
    serde_json::from_slice::<CustomProposal>(custom_proposal).ok()
}

pub struct GetPendingCreationGroupsResult {
    pub group_ids: Vec<String>,
}

// Note: only get pending creation groups without add members
pub fn get_pending_creation_groups(
    conn: &Arc<Mutex<Connection>>,
    provider: &SqliteProvider,
) -> Result<GetPendingCreationGroupsResult, Error> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT group_id, pending_operation FROM group_statuses WHERE pending_operation = ?1",
    )?;

    let mut rows = stmt.query(params![OP_CREATE_GROUP])?;
    let mut group_ids = Vec::new();

    while let Some(row) = rows.next()? {
        let group_id: String = row.get(0)?;

        if let Ok(group) = group(provider, &group_id) {
            if group.epoch().as_u64() == 0 {
                group_ids.push(group_id);
            }
        }
    }

    Ok(GetPendingCreationGroupsResult { group_ids })
}

pub struct ProcessPendingCreationsArgs {
    pub groups: Vec<PendingCreationGroup>,
}

pub struct PendingCreationGroup {
    pub group_id: String,
    pub tree_hash: Vec<u8>,
}

pub struct ProcessPendingCreationsResult {
    pub groups: Vec<PendingCreationGroupResult>,
}

pub struct PendingCreationGroupResult {
    pub group_id: String,
    pub err: Option<String>,
}

// Note: only process pending creation groups without add members
pub fn process_pending_creations(
    conn: &Arc<Mutex<Connection>>,
    provider: &SqliteProvider,
    args: ProcessPendingCreationsArgs,
) -> Result<ProcessPendingCreationsResult, Error> {
    let mut results = Vec::new();

    for group_data in args.groups {
        match group(provider, &group_data.group_id) {
            Ok(mut mls_group) => {
                if mls_group.epoch().as_u64() > 0 {
                    results.push(PendingCreationGroupResult {
                        group_id: group_data.group_id.to_owned(),
                        err: Some("Group epoch > 0".to_owned()),
                    });
                    continue;
                }

                let Ok(pending_operation) = get_group_pending_operation(conn, &group_data.group_id)
                else {
                    results.push(PendingCreationGroupResult {
                        group_id: group_data.group_id.to_owned(),
                        err: Some("Get pending operation error".to_owned()),
                    });
                    continue;
                };

                if pending_operation == Some(OP_CREATE_GROUP.to_string()) {
                    if !mls_group
                        .tree_hash()
                        .to_vec()
                        .iter()
                        .eq(&group_data.tree_hash)
                    {
                        delete_group(&mut mls_group, provider)?;
                    }

                    let _ = delete_group_status(conn, &group_data.group_id);
                }
            }
            Err(err) => {
                results.push(PendingCreationGroupResult {
                    group_id: group_data.group_id.to_owned(),
                    err: Some(err.to_string()),
                });
            }
        }
    }

    Ok(ProcessPendingCreationsResult { groups: results })
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
