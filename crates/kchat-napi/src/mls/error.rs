#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("MLS error: {0}")]
    Mls(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Key package new error: {0}")]
    KeyPackageNew(String),
    #[error("Add members error: {0}")]
    AddMembers(String),
    #[error("Merge pending commit error: {0}")]
    MergePendingCommit(String),
    #[error("New group error: {0}")]
    NewGroup(String),
    #[error("Process message error: {0}")]
    ProcessMessage(String),
    #[error("Merge commit error: {0}")]
    MergeCommit(String),
    #[error("Invalid operation message")]
    InvalidOperationMessage,
    #[error("Invalid welcome message")]
    InvalidWelcomeMessage,
    #[error("Invalid application message")]
    InvalidApplicationMessage,
    #[error("Invalid proposal message")]
    InvalidProposalMessage,
    #[error("Invalid group info")]
    InvalidGroupInfo,
    #[error("Welcome error: {0}")]
    Welcome(String),
    #[error("Welcome error: a group with the same id existed.")]
    WelcomeGroupAlreadyExisted,
    #[error("Protocol message error: {0}")]
    ProtocolMessage(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Key package verify error: {0}")]
    KeyPackageVerify(String),
    #[error("Group is not existed")]
    GroupIsNotExisted,
    #[error("Group is already existed")]
    GroupIsAlreadyExisted,
    #[error("Create message error: {0}")]
    CreateMessage(String),
    #[error("Export group info error: {0}")]
    ExportGroupInfo(String),
    #[error("Export group info error: invalid export type")]
    ExportGroupInfoInvalidExportType,
    #[error("External commit error: {0}")]
    ExternalCommit(String),
    #[error("Creation from external error: {0}")]
    CreationFromExternal(String),
    #[error("Missing ratchet tree error")]
    MissingRatchetTree,
    #[error("Credential is existed.")]
    CredentialIsExisted,
    #[error("Remove members error: {0}")]
    RemoveMembers(String),
    #[error("Commit to pending proposals error: {0}")]
    CommitToPendingProposals(String),
    #[error("Leave group error: {0}")]
    LeaveGroup(String),
    #[error("Update leaf node error: {0}")]
    UpdateLeafNode(String),
    #[error("Sqlite error: {0}")]
    Sqlite(String),
    #[error("Sqlite error: not found")]
    SqliteNotFound,
    #[error("Sqlite migration error: {0}")]
    SqliteMigration(String),
    #[error("Deserialize error")]
    Deserialize,
    #[error("Serialize error")]
    Serialize,
    #[error("Missing own leaf node in group")]
    MissingOwnLeafNodeInGroup,
    #[error("Missing signature key pair")]
    MissingSignatureKeyPair,
    #[error("Some members already existed in group")]
    SomeMembersAlreadyExistedInGroup,
    #[error("External commit builder error: {0}")]
    ExternalCommitBuilder(String),
    #[error("External commit builder finalize error: {0}")]
    ExternalCommitBuilderFinalize(String),
    #[error("Create commit error: {0}")]
    CreateCommit(String),
    #[error("Export secret error: {0}")]
    ExportSecret(String),
    #[error("Re-add error: {0}")]
    ReAdd(String),
    #[error("Commit builder stage error: {0}")]
    CommitBuilderStage(String),
    #[error("Proposal error: {0}")]
    Proposal(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Mls(_) => "MLS_ERROR",
            Error::Crypto(_) => "CRYPTO_ERROR",
            Error::KeyPackageNew(_) => "KEY_PACKAGE_NEW_ERROR",
            Error::AddMembers(_) => "ADD_MEMBERS_ERROR",
            Error::MergePendingCommit(_) => "MERGE_PENDING_COMMIT_ERROR",
            Error::NewGroup(_) => "NEW_GROUP_ERROR",
            Error::ProcessMessage(_) => "PROCESS_MESSAGE_ERROR",
            Error::MergeCommit(_) => "MERGE_COMMIT_ERROR",
            Error::InvalidOperationMessage => "INVALID_OPERATION_MESSAGE",
            Error::InvalidWelcomeMessage => "INVALID_WELCOME_MESSAGE",
            Error::InvalidApplicationMessage => "INVALID_APPLICATION_MESSAGE",
            Error::InvalidProposalMessage => "INVALID_PROPOSAL_MESSAGE",
            Error::InvalidGroupInfo => "INVALID_GROUP_INFO",
            Error::Welcome(_) => "WELCOME_ERROR",
            Error::WelcomeGroupAlreadyExisted => "WELCOME_GROUP_ALREADY_EXISTED",
            Error::ProtocolMessage(_) => "PROTOCOL_MESSAGE_ERROR",
            Error::Storage(_) => "STORAGE_ERROR",
            Error::KeyPackageVerify(_) => "KEY_PACKAGE_VERIFY_ERROR",
            Error::GroupIsNotExisted => "GROUP_NOT_EXISTED",
            Error::GroupIsAlreadyExisted => "GROUP_ALREADY_EXISTED",
            Error::CreateMessage(_) => "CREATE_MESSAGE_ERROR",
            Error::ExportGroupInfo(_) => "EXPORT_GROUP_INFO_ERROR",
            Error::ExportGroupInfoInvalidExportType => "EXPORT_GROUP_INFO_INVALID_EXPORT_TYPE",
            Error::ExternalCommit(_) => "EXTERNAL_COMMIT_ERROR",
            Error::CreationFromExternal(_) => "CREATION_FROM_EXTERNAL_ERROR",
            Error::MissingRatchetTree => "MISSING_RATCHET_TREE",
            Error::CredentialIsExisted => "CREDENTIAL_ALREADY_EXISTED",
            Error::RemoveMembers(_) => "REMOVE_MEMBERS_ERROR",
            Error::CommitToPendingProposals(_) => "COMMIT_TO_PENDING_PROPOSALS_ERROR",
            Error::LeaveGroup(_) => "LEAVE_GROUP_ERROR",
            Error::UpdateLeafNode(_) => "UPDATE_LEAF_NODE_ERROR",
            Error::Sqlite(_) => "SQLITE_ERROR",
            Error::SqliteNotFound => "SQLITE_NOT_FOUND",
            Error::SqliteMigration(_) => "SQLITE_MIGRATION_ERROR",
            Error::Deserialize => "DESERIALIZE_ERROR",
            Error::Serialize => "SERIALIZE_ERROR",
            Error::MissingOwnLeafNodeInGroup => "MISSING_OWN_LEAF_NODE_IN_GROUP",
            Error::MissingSignatureKeyPair => "MISSING_SIGNATURE_KEY_PAIR",
            Error::SomeMembersAlreadyExistedInGroup => "SOME_MEMBERS_ALREADY_EXISTED_IN_GROUP",
            Error::ExternalCommitBuilder(_) => "EXTERNAL_COMMIT_BUILDER_ERROR",
            Error::ExternalCommitBuilderFinalize(_) => "EXTERNAL_COMMIT_BUILDER_FINALIZE_ERROR",
            Error::CreateCommit(_) => "CREATE_COMMIT_ERROR",
            Error::ExportSecret(_) => "EXPORT_SECRET_ERROR",
            Error::ReAdd(_) => "RE_ADD_ERROR",
            Error::CommitBuilderStage(_) => "COMMIT_BUILDER_STAGE_ERROR",
            Error::Proposal(_) => "PROPOSAL_ERROR",
        }
    }

    pub fn napi_status(&self) -> napi::Status {
        match self {
            Error::InvalidOperationMessage
            | Error::InvalidWelcomeMessage
            | Error::InvalidApplicationMessage
            | Error::InvalidProposalMessage
            | Error::InvalidGroupInfo
            | Error::ExportGroupInfoInvalidExportType
            | Error::KeyPackageVerify(_)
            | Error::MissingRatchetTree
            | Error::Deserialize => napi::Status::InvalidArg,
            _ => napi::Status::GenericFailure,
        }
    }
}

impl From<Error> for napi::Error {
    fn from(e: Error) -> Self {
        napi::Error::new(e.napi_status(), format!("[{}] {}", e.code(), e))
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Self::Mls(e)
    }
}

impl From<uq_openmls::error::Error> for Error {
    fn from(e: uq_openmls::error::Error) -> Self {
        use uq_openmls::error::Error as MlsError;
        match e {
            MlsError::Mls(e) => Self::Mls(e),
            MlsError::Crypto(e) => Self::Crypto(e),
            MlsError::KeyPackageNew(e) => Self::KeyPackageNew(e),
            MlsError::AddMembers(e) => Self::AddMembers(e),
            MlsError::MergePendingCommit(e) => Self::MergePendingCommit(e),
            MlsError::NewGroup(e) => Self::NewGroup(e),
            MlsError::ProcessMessage(e) => Self::ProcessMessage(e),
            MlsError::MergeCommit(e) => Self::MergeCommit(e),
            MlsError::InvalidOperationMessage => Self::InvalidOperationMessage,
            MlsError::InvalidWelcomeMessage => Self::InvalidWelcomeMessage,
            MlsError::InvalidApplicationMessage => Self::InvalidApplicationMessage,
            MlsError::InvalidProposalMessage => Self::InvalidProposalMessage,
            MlsError::InvalidGroupInfo => Self::InvalidGroupInfo,
            MlsError::Welcome(e) => Self::Welcome(e),
            MlsError::WelcomeGroupAlreadyExisted => Self::WelcomeGroupAlreadyExisted,
            MlsError::ProtocolMessage(e) => Self::ProtocolMessage(e),
            MlsError::Storage(e) => Self::Storage(e),
            MlsError::KeyPackageVerify(e) => Self::KeyPackageVerify(e),
            MlsError::GroupIsNotExisted => Self::GroupIsNotExisted,
            MlsError::CreateMessage(e) => Self::CreateMessage(e),
            MlsError::ExportGroupInfo(e) => Self::ExportGroupInfo(e),
            MlsError::ExportGroupInfoInvalidExportType => Self::ExportGroupInfoInvalidExportType,
            MlsError::ExternalCommit(e) => Self::ExternalCommit(e),
            MlsError::CreationFromExternal(e) => Self::CreationFromExternal(e),
            MlsError::MissingRatchetTree => Self::MissingRatchetTree,
            MlsError::CredentialIsExisted => Self::CredentialIsExisted,
            MlsError::RemoveMembers(e) => Self::RemoveMembers(e),
            MlsError::CommitToPendingProposals(e) => Self::CommitToPendingProposals(e),
            MlsError::LeaveGroup(e) => Self::LeaveGroup(e),
            MlsError::UpdateLeafNode(e) => Self::UpdateLeafNode(e),
            MlsError::Sqlite(e) => Self::Sqlite(e),
            MlsError::SqliteNotFound => Self::SqliteNotFound,
            MlsError::SqliteMigration(e) => Self::SqliteMigration(e),
            MlsError::Deserialize => Self::Deserialize,
            MlsError::Serialize => Self::Serialize,
            MlsError::MissingOwnLeafNodeInGroup => Self::MissingOwnLeafNodeInGroup,
            MlsError::MissingSignatureKeyPair => Self::MissingSignatureKeyPair,
            MlsError::SomeMembersAlreadyExistedInGroup => Self::SomeMembersAlreadyExistedInGroup,
            MlsError::ExternalCommitBuilder(e) => Self::ExternalCommitBuilder(e),
            MlsError::ExternalCommitBuilderFinalize(e) => Self::ExternalCommitBuilderFinalize(e),
            MlsError::CreateCommit(e) => Self::CreateCommit(e),
            MlsError::ReAdd(e) => Self::ReAdd(e),
            MlsError::CommitBuilderStage(e) => Self::CommitBuilderStage(e),
            MlsError::Proposal(e) => Self::Proposal(e),
        }
    }
}

impl From<openmls::prelude::Error> for Error {
    fn from(e: openmls::prelude::Error) -> Self {
        Self::Mls(e.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}
