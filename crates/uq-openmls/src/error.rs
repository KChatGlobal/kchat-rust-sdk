use thiserror::Error;

#[derive(Error, Debug)]
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
    #[error("Re-add error: {0}")]
    ReAdd(String),
    #[error("Commit build stage error: {0}")]
    CommitBuilderStage(String),
    #[error("Proposal error: {0}")]
    Proposal(String),
    #[error("Unsupported ciphersuite: {0}")]
    UnsupportedCiphersuite(String),
}

impl From<openmls::prelude::Error> for Error {
    fn from(err: openmls::prelude::Error) -> Self {
        Error::Mls(err.to_string())
    }
}

impl From<openmls::prelude::CryptoError> for Error {
    fn from(err: openmls::prelude::CryptoError) -> Self {
        Error::Crypto(err.to_string())
    }
}

impl From<openmls::prelude::KeyPackageNewError> for Error {
    fn from(err: openmls::prelude::KeyPackageNewError) -> Self {
        Error::KeyPackageNew(err.to_string())
    }
}

impl<T> From<openmls::group::AddMembersError<T>> for Error {
    fn from(err: openmls::group::AddMembersError<T>) -> Self {
        Error::AddMembers(err.to_string())
    }
}

impl<T> From<openmls::group::MergePendingCommitError<T>> for Error {
    fn from(err: openmls::group::MergePendingCommitError<T>) -> Self {
        Error::MergePendingCommit(err.to_string())
    }
}

impl<T> From<openmls::group::NewGroupError<T>> for Error {
    fn from(err: openmls::group::NewGroupError<T>) -> Self {
        Error::NewGroup(err.to_string())
    }
}

impl<T> From<openmls::group::ProcessMessageError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::ProcessMessageError<T>) -> Self {
        Error::ProcessMessage(err.to_string())
    }
}

impl<T> From<openmls::group::MergeCommitError<T>> for Error {
    fn from(err: openmls::group::MergeCommitError<T>) -> Self {
        Error::MergeCommit(err.to_string())
    }
}

impl<T> From<openmls::group::WelcomeError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::WelcomeError<T>) -> Self {
        Error::Welcome(err.to_string())
    }
}

impl From<openmls::framing::errors::ProtocolMessageError> for Error {
    fn from(err: openmls::framing::errors::ProtocolMessageError) -> Self {
        Error::ProtocolMessage(err.to_string())
    }
}

impl From<openmls::prelude::KeyPackageVerifyError> for Error {
    fn from(err: openmls::prelude::KeyPackageVerifyError) -> Self {
        Error::KeyPackageVerify(err.to_string())
    }
}

impl From<openmls::group::CreateMessageError> for Error {
    fn from(err: openmls::group::CreateMessageError) -> Self {
        Error::CreateMessage(err.to_string())
    }
}

impl From<openmls::group::ExportGroupInfoError> for Error {
    fn from(err: openmls::group::ExportGroupInfoError) -> Self {
        Error::ExportGroupInfo(err.to_string())
    }
}

impl<T> From<openmls::group::ExternalCommitError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::ExternalCommitError<T>) -> Self {
        Error::ExternalCommit(err.to_string())
    }
}

impl<T> From<openmls::prelude::CreationFromExternalError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::prelude::CreationFromExternalError<T>) -> Self {
        Error::CreationFromExternal(err.to_string())
    }
}

impl<T> From<openmls::group::RemoveMembersError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::RemoveMembersError<T>) -> Self {
        Error::RemoveMembers(err.to_string())
    }
}

impl<T> From<openmls::group::CommitToPendingProposalsError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::CommitToPendingProposalsError<T>) -> Self {
        Error::RemoveMembers(err.to_string())
    }
}

impl<T> From<openmls::group::LeaveGroupError<T>> for Error {
    fn from(err: openmls::group::LeaveGroupError<T>) -> Self {
        Error::LeaveGroup(err.to_string())
    }
}

impl<T> From<openmls::group::SelfUpdateError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::SelfUpdateError<T>) -> Self {
        Error::UpdateLeafNode(err.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        Error::Sqlite(err.to_string())
    }
}

impl<T> From<openmls::group::ExternalCommitBuilderError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::ExternalCommitBuilderError<T>) -> Self {
        Self::ExternalCommitBuilder(err.to_string())
    }
}

impl From<openmls::group::CreateCommitError> for Error {
    fn from(err: openmls::group::CreateCommitError) -> Self {
        Error::CreateCommit(err.to_string())
    }
}

impl<T> From<openmls::group::ExternalCommitBuilderFinalizeError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::ExternalCommitBuilderFinalizeError<T>) -> Self {
        Self::ExternalCommitBuilderFinalize(err.to_string())
    }
}

impl<T> From<openmls::group::CommitBuilderStageError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::CommitBuilderStageError<T>) -> Self {
        Self::CommitBuilderStage(err.to_string())
    }
}

impl<T> From<openmls::group::ProposalError<T>> for Error
where
    T: std::fmt::Display,
{
    fn from(err: openmls::group::ProposalError<T>) -> Self {
        Self::Proposal(err.to_string())
    }
}
