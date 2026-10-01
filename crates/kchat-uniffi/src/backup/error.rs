use kchat_backup::{BackupError, BackupErrorCode};

#[derive(Debug, thiserror::Error, uniffi::Error, PartialEq)]
pub enum BackupFfiError {
    #[error("backup operation failed: invalid argument")]
    InvalidArgument,
    #[error("backup operation failed: empty password")]
    EmptyPassword,
    #[error("backup operation failed: invalid mnemonic")]
    InvalidMnemonic,
    #[error("backup operation failed: invalid mnemonic key")]
    InvalidMnemonicKey,
    #[error("backup operation failed: invalid password key")]
    InvalidPasswordKey,
    #[error("backup operation failed: unsupported format")]
    UnsupportedFormat,
    #[error("backup operation failed: context mismatch")]
    ContextMismatch,
    #[error("backup operation failed: I/O error")]
    IoError,
    #[error("backup operation failed: invalid state")]
    InvalidState,
    #[error("backup operation failed: authentication failed")]
    AuthenticationFailed,
    #[error("backup operation failed: resource limit exceeded")]
    ResourceLimitExceeded,
    #[error("backup operation failed: cancelled")]
    Cancelled,
    #[error("backup operation failed: integrity mismatch")]
    IntegrityMismatch,
    #[error("backup operation failed: malformed object")]
    MalformedObject,
    #[error("backup operation failed: not implemented")]
    NotImplemented,
    #[error("backup operation failed: invalid compressed data")]
    InvalidCompressedData,
}

impl From<BackupError> for BackupFfiError {
    fn from(error: BackupError) -> Self {
        match error.code() {
            BackupErrorCode::InvalidArgument => Self::InvalidArgument,
            BackupErrorCode::EmptyPassword => Self::EmptyPassword,
            BackupErrorCode::InvalidMnemonic => Self::InvalidMnemonic,
            BackupErrorCode::InvalidMnemonicKey => Self::InvalidMnemonicKey,
            BackupErrorCode::InvalidPasswordKey => Self::InvalidPasswordKey,
            BackupErrorCode::UnsupportedFormat => Self::UnsupportedFormat,
            BackupErrorCode::ContextMismatch => Self::ContextMismatch,
            BackupErrorCode::IoError => Self::IoError,
            BackupErrorCode::InvalidState => Self::InvalidState,
            BackupErrorCode::AuthenticationFailed => Self::AuthenticationFailed,
            BackupErrorCode::ResourceLimitExceeded => Self::ResourceLimitExceeded,
            BackupErrorCode::Cancelled => Self::Cancelled,
            BackupErrorCode::IntegrityMismatch => Self::IntegrityMismatch,
            BackupErrorCode::MalformedObject => Self::MalformedObject,
            BackupErrorCode::NotImplemented => Self::NotImplemented,
            BackupErrorCode::InvalidCompressedData => Self::InvalidCompressedData,
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for BackupFfiError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::IoError
    }
}
