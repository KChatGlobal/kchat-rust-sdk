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
