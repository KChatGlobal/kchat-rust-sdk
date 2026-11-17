use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileCryptoErrorCode {
    InvalidArgument,
    UnsupportedProfile,
    PepperRequired,
    KeyConfigRequired,
    ProfileNotAllowed,
    KKeyProofInvalid,
    KKeySignatureInvalid,
    KeyConflict,
    IntegrityError,
    OperationConflict,
    SourceChanged,
    InvalidStoreKey,
    AccountMismatch,
    MalformedMessage,
    UnauthorizedSender,
    WrongRecipient,
    StoreError,
    ResourceLimitExceeded,
    Cancelled,
    IoError,
    InvalidState,
    KeySyncRequired,
    KeyEnvelopeInvalid,
    PolicyViolation,
}

#[derive(Debug, Error)]
#[error("file crypto operation failed: {code:?}")]
pub struct FileCryptoError {
    code: FileCryptoErrorCode,
}

impl FileCryptoError {
    #[doc(hidden)]
    pub const fn from_code(code: FileCryptoErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(&self) -> FileCryptoErrorCode {
        self.code
    }
}

impl From<rusqlite::Error> for FileCryptoError {
    fn from(_: rusqlite::Error) -> Self {
        Self::store_error()
    }
}

/// One constructor per code.
impl FileCryptoError {
    pub(crate) const fn invalid_argument() -> Self {
        Self::from_code(FileCryptoErrorCode::InvalidArgument)
    }
    pub(crate) const fn unsupported_profile() -> Self {
        Self::from_code(FileCryptoErrorCode::UnsupportedProfile)
    }
    pub(crate) const fn pepper_required() -> Self {
        Self::from_code(FileCryptoErrorCode::PepperRequired)
    }
    pub(crate) const fn key_config_required() -> Self {
        Self::from_code(FileCryptoErrorCode::KeyConfigRequired)
    }
    pub(crate) const fn profile_not_allowed() -> Self {
        Self::from_code(FileCryptoErrorCode::ProfileNotAllowed)
    }
    pub(crate) const fn kkey_proof_invalid() -> Self {
        Self::from_code(FileCryptoErrorCode::KKeyProofInvalid)
    }
    pub(crate) const fn kkey_signature_invalid() -> Self {
        Self::from_code(FileCryptoErrorCode::KKeySignatureInvalid)
    }
    pub(crate) const fn key_conflict() -> Self {
        Self::from_code(FileCryptoErrorCode::KeyConflict)
    }
    pub(crate) const fn integrity_error() -> Self {
        Self::from_code(FileCryptoErrorCode::IntegrityError)
    }
    pub(crate) const fn operation_conflict() -> Self {
        Self::from_code(FileCryptoErrorCode::OperationConflict)
    }
    pub(crate) const fn source_changed() -> Self {
        Self::from_code(FileCryptoErrorCode::SourceChanged)
    }
    pub(crate) const fn invalid_store_key() -> Self {
        Self::from_code(FileCryptoErrorCode::InvalidStoreKey)
    }
    pub(crate) const fn account_mismatch() -> Self {
        Self::from_code(FileCryptoErrorCode::AccountMismatch)
    }
    pub(crate) const fn malformed_message() -> Self {
        Self::from_code(FileCryptoErrorCode::MalformedMessage)
    }
    pub(crate) const fn unauthorized_sender() -> Self {
        Self::from_code(FileCryptoErrorCode::UnauthorizedSender)
    }
    pub(crate) const fn wrong_recipient() -> Self {
        Self::from_code(FileCryptoErrorCode::WrongRecipient)
    }
    pub(crate) const fn store_error() -> Self {
        Self::from_code(FileCryptoErrorCode::StoreError)
    }
    pub(crate) const fn resource_limit_exceeded() -> Self {
        Self::from_code(FileCryptoErrorCode::ResourceLimitExceeded)
    }
    pub(crate) const fn cancelled() -> Self {
        Self::from_code(FileCryptoErrorCode::Cancelled)
    }
    pub(crate) const fn io_error() -> Self {
        Self::from_code(FileCryptoErrorCode::IoError)
    }
    pub(crate) const fn invalid_state() -> Self {
        Self::from_code(FileCryptoErrorCode::InvalidState)
    }
    pub(crate) const fn key_sync_required() -> Self {
        Self::from_code(FileCryptoErrorCode::KeySyncRequired)
    }
    pub(crate) const fn key_envelope_invalid() -> Self {
        Self::from_code(FileCryptoErrorCode::KeyEnvelopeInvalid)
    }
    pub(crate) const fn policy_violation() -> Self {
        Self::from_code(FileCryptoErrorCode::PolicyViolation)
    }
}
