#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Mls error: {0}")]
    Mls(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Missing signature key pair")]
    MissingSignatureKeyPair,
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Self::Mls(e)
    }
}

impl From<uq_openmls::error::Error> for Error {
    fn from(e: uq_openmls::error::Error) -> Self {
        Self::Mls(e.to_string())
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
