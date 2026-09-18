use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupErrorCode {
    InvalidArgument,
    EmptyPassword,
    InvalidMnemonic,
    InvalidMnemonicKey,
    InvalidPasswordKey,
    UnsupportedFormat,
    ContextMismatch,
    IoError,
    InvalidState,
    AuthenticationFailed,
    ResourceLimitExceeded,
    Cancelled,
}

#[derive(Debug, Error)]
#[error("backup operation failed: {code:?}")]
pub struct BackupError {
    code: BackupErrorCode,
}

impl BackupError {
    pub(crate) const fn from_code(code: BackupErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn invalid_argument() -> Self {
        Self {
            code: BackupErrorCode::InvalidArgument,
        }
    }

    pub(crate) const fn empty_password() -> Self {
        Self {
            code: BackupErrorCode::EmptyPassword,
        }
    }

    pub(crate) const fn invalid_mnemonic() -> Self {
        Self {
            code: BackupErrorCode::InvalidMnemonic,
        }
    }

    pub(crate) const fn unsupported_format() -> Self {
        Self {
            code: BackupErrorCode::UnsupportedFormat,
        }
    }

    pub(crate) const fn context_mismatch() -> Self {
        Self {
            code: BackupErrorCode::ContextMismatch,
        }
    }

    pub(crate) const fn invalid_mnemonic_key() -> Self {
        Self {
            code: BackupErrorCode::InvalidMnemonicKey,
        }
    }

    pub(crate) const fn invalid_password_key() -> Self {
        Self {
            code: BackupErrorCode::InvalidPasswordKey,
        }
    }

    pub(crate) const fn io_error() -> Self {
        Self {
            code: BackupErrorCode::IoError,
        }
    }

    pub(crate) const fn invalid_state() -> Self {
        Self {
            code: BackupErrorCode::InvalidState,
        }
    }

    pub(crate) const fn authentication_failed() -> Self {
        Self {
            code: BackupErrorCode::AuthenticationFailed,
        }
    }

    pub(crate) const fn resource_limit_exceeded() -> Self {
        Self {
            code: BackupErrorCode::ResourceLimitExceeded,
        }
    }

    pub(crate) const fn cancelled() -> Self {
        Self {
            code: BackupErrorCode::Cancelled,
        }
    }

    pub const fn code(&self) -> BackupErrorCode {
        self.code
    }
}
