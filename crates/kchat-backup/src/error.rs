use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupErrorCode {
    InvalidArgument,
    InvalidMnemonic,
    InvalidMasterKey,
    UnsupportedFormat,
    ContextMismatch,
    IoError,
    InvalidState,
}

#[derive(Debug, Error)]
#[error("backup operation failed: {code:?}")]
pub struct BackupError {
    code: BackupErrorCode,
}

impl BackupError {
    pub(crate) const fn invalid_argument() -> Self {
        Self {
            code: BackupErrorCode::InvalidArgument,
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

    pub(crate) const fn invalid_master_key() -> Self {
        Self {
            code: BackupErrorCode::InvalidMasterKey,
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

    pub const fn code(&self) -> BackupErrorCode {
        self.code
    }
}
