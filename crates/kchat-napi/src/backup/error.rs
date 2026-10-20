use kchat_backup::{BackupError, BackupErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid backup argument")]
    InvalidArgument,
    #[error("Password is empty")]
    EmptyPassword,
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    #[error("Invalid mnemonic key")]
    InvalidMnemonicKey,
    #[error("Invalid password key")]
    InvalidPasswordKey,
    #[error("Unsupported backup format")]
    UnsupportedFormat,
    #[error("Backup context does not match")]
    ContextMismatch,
    #[error("Backup I/O error")]
    IoError,
    #[error("Invalid backup state")]
    InvalidState,
    #[error("Backup authentication failed")]
    AuthenticationFailed,
    #[error("Backup resource limit exceeded")]
    ResourceLimitExceeded,
    #[error("Backup operation cancelled")]
    Cancelled,
    #[error("Backup integrity mismatch")]
    IntegrityMismatch,
    #[error("Malformed backup object")]
    MalformedObject,
    #[error("Invalid compressed backup data")]
    InvalidCompressedData,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::InvalidArgument => "INVALID_ARGUMENT",
            Error::EmptyPassword => "EMPTY_PASSWORD",
            Error::InvalidMnemonic => "INVALID_MNEMONIC",
            Error::InvalidMnemonicKey => "INVALID_MNEMONIC_KEY",
            Error::InvalidPasswordKey => "INVALID_PASSWORD_KEY",
            Error::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Error::ContextMismatch => "CONTEXT_MISMATCH",
            Error::IoError => "IO_ERROR",
            Error::InvalidState => "INVALID_STATE",
            Error::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Error::ResourceLimitExceeded => "RESOURCE_LIMIT_EXCEEDED",
            Error::Cancelled => "CANCELLED",
            Error::IntegrityMismatch => "INTEGRITY_MISMATCH",
            Error::MalformedObject => "MALFORMED_OBJECT",
            Error::InvalidCompressedData => "INVALID_COMPRESSED_DATA",
        }
    }

    pub fn napi_status(&self) -> napi::Status {
        match self {
            Error::InvalidArgument
            | Error::EmptyPassword
            | Error::InvalidMnemonic
            | Error::InvalidMnemonicKey
            | Error::InvalidPasswordKey => napi::Status::InvalidArg,
            Error::Cancelled => napi::Status::Cancelled,
            _ => napi::Status::GenericFailure,
        }
    }
}

impl From<BackupErrorCode> for Error {
    fn from(code: BackupErrorCode) -> Self {
        match code {
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
            BackupErrorCode::InvalidCompressedData => Self::InvalidCompressedData,
        }
    }
}

impl From<BackupError> for Error {
    fn from(error: BackupError) -> Self {
        error.code().into()
    }
}

impl From<Error> for napi::Error {
    fn from(error: Error) -> Self {
        napi::Error::new(error.napi_status(), format!("[{}] {}", error.code(), error))
    }
}

pub(crate) fn map_error(error: BackupError) -> napi::Error {
    Error::from(error).into()
}

pub(crate) fn invalid_argument() -> napi::Error {
    Error::InvalidArgument.into()
}

pub(crate) fn invalid_state() -> napi::Error {
    Error::InvalidState.into()
}
