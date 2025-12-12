use std::collections::HashSet;

use openmls::{
    group::{MlsGroup, MlsGroupJoinConfig},
    prelude::{BasicCredential, Credential},
};
use rusqlite::{params, Connection};
use uq_openmls::{
    core::{
        clear_pending_commit, delete_group, group, merge_pending_commit, process_operation_message,
        process_proposal_message, process_welcome, Proposal,
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

pub struct MlsMessage {
    pub blob: Vec<u8>,
    pub epoch: u64,
    pub sender: String,
    pub message_type: MessageType,
}

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

pub fn insert_or_update_group_status(
    group_storage_path: &str,
    group_id: &str,
    pending_operation: GroupPendingOperation,
) -> Result<(), Error> {
    let conn = Connection::open(group_storage_path)?;
    let pending_operation: String = pending_operation.into();

    conn.execute(
        "
        INSERT INTO group_statuses (group_id, pending_operation)
        VALUES (?1, ?2)
        ON CONFLICT(group_id) DO UPDATE SET pending_operation = excluded.pending_operation
        ",
        params![group_id, pending_operation],
    )?;

    Ok(())
}

pub fn delete_group_status(group_storage_path: &str, group_id: &str) -> Result<(), Error> {
    let conn = Connection::open(group_storage_path)?;

    conn.execute(
        "DELETE FROM group_statuses WHERE group_id = ?1",
        params![group_id],
    )?;

    Ok(())
}

pub fn get_group_pending_operation(
    group_storage_path: &str,
    group_id: &str,
) -> Result<Option<String>, Error> {
    let conn = Connection::open(group_storage_path)?;

    let mut stmt =
        conn.prepare("SELECT group_id, pending_operation FROM group_statuses WHERE group_id = ?1")?;

    let mut rows = stmt.query(params![group_id])?;

    if let Some(row) = rows.next()? {
        Ok(Some(row.get(1)?))
    } else {
        Ok(None)
    }
}

pub fn initialize(group_storage_path: &str) -> Result<(), Error> {
    let conn = Connection::open(group_storage_path)?;

    conn.execute(
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
    pub members_to_remove: Vec<String>,
}

pub struct ProcessAllMessagesResult {
    pub group_results: Vec<GroupResult>,
}

pub fn process_all_messages(
    group_storage_path: &str,
    provider: &SqliteProvider,
    args: ProcessAllMessagesArgs,
    join_config: &MlsGroupJoinConfig,
) -> Result<ProcessAllMessagesResult, Error> {
    let mut result = ProcessAllMessagesResult {
        group_results: Vec::new(),
    };

    for messages_of_group in args.group_messages {
        let group_id = &messages_of_group.group_id;
        if let Ok(group) = group(provider, group_id) {
            let Some(own_member_id) = own_id_from_leaf_node(&group) else {
                continue;
            };

            let mut pending_operation: GroupPendingOperation =
                get_group_pending_operation(group_storage_path, group_id)?.into();
            let first_mls_message = messages_of_group.messages.first();
            if group.epoch().as_u64() == 0 {
                pending_operation = GroupPendingOperation::CreateGroup;
            }

            match pending_operation {
                GroupPendingOperation::CreateGroup
                | GroupPendingOperation::JoinByExternalCommit => {
                    if let Some(msg) = first_mls_message {
                        if !own_member_id.contains(&msg.sender) {
                            delete_group(provider, group_id)?;
                            let _ = delete_group_status(group_storage_path, group_id);
                        }
                    } else {
                        delete_group(provider, group_id)?;
                        let _ = delete_group_status(group_storage_path, group_id);
                    }
                }
                GroupPendingOperation::LeaveGroup => {
                    // TODO: handle leave group
                }
                GroupPendingOperation::UpdateTree => {
                    if let Some(msg) = first_mls_message {
                        if !own_member_id.contains(&msg.sender) {
                            clear_pending_commit(provider, group_id)?;
                        } else {
                            merge_pending_commit(provider, group_id)?;
                        }
                    } else {
                        clear_pending_commit(provider, group_id)?;
                    }

                    let _ = insert_or_update_group_status(
                        group_storage_path,
                        group_id,
                        GroupPendingOperation::None,
                    );
                }
                GroupPendingOperation::None => (),
            }
        }

        let mut group_result = GroupResult {
            group_id: group_id.to_owned(),
            members_to_remove: Vec::new(),
        };
        let mut group_member_set = HashSet::new();
        if let Ok(group) = group(provider, group_id) {
            for member in group.members() {
                if let Some(id) = id_from_credential(&member.credential) {
                    group_member_set.insert(id);
                }
            }
        }

        for msg in &messages_of_group.messages {
            match msg.message_type {
                MessageType::Welcome => {
                    if let Err(err) = process_welcome(provider, &msg.blob, join_config) {
                        println!("process welcome error: {:?}", err.to_string());
                    }
                }
                MessageType::Commit => {
                    if let Err(err) = process_operation_message(provider, group_id, &msg.blob) {
                        println!("process commit error: {:?}", err.to_string());
                    }
                }
                MessageType::Proposal => {
                    if let Ok(proposal) = process_proposal_message(provider, group_id, &msg.blob) {
                        if group_member_set.contains(&proposal.sender) {
                            if let Proposal::Remove = proposal.proposal {
                                group_result.members_to_remove.push(proposal.sender);
                            }
                        }
                    }
                }
            }
        }

        result.group_results.push(group_result);
    }

    Ok(result)
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
