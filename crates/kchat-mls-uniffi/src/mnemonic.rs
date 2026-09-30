use kchat_mls::mnemonic::{self, MnemonicError};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, uniffi::Error, PartialEq, Eq)]
pub enum MnemonicFfiError {
    #[error("unsupported recovery mnemonic word count")]
    InvalidWordCount,
    #[error("invalid recovery mnemonic")]
    InvalidMnemonic,
    #[error("invalid recovery user ID")]
    InvalidUserId,
    #[error("recovery randomness unavailable")]
    RandomnessUnavailable,
    #[error("recovery key derivation failed")]
    DerivationFailed,
}

impl From<MnemonicError> for MnemonicFfiError {
    fn from(error: MnemonicError) -> Self {
        match error {
            MnemonicError::InvalidWordCount => Self::InvalidWordCount,
            MnemonicError::InvalidMnemonic => Self::InvalidMnemonic,
            MnemonicError::InvalidUserId => Self::InvalidUserId,
            MnemonicError::RandomnessUnavailable => Self::RandomnessUnavailable,
            MnemonicError::DerivationFailed => Self::DerivationFailed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RecoveryKeyAlgorithm {
    Ed25519,
    P256Ecdsa,
}

#[derive(uniffi::Record)]
pub struct RecoveryKeyPair {
    pub format_version: u16,
    pub algorithm: RecoveryKeyAlgorithm,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[uniffi::export]
pub fn generate_recovery_mnemonic(word_count: u32) -> Result<String, MnemonicFfiError> {
    Ok(mnemonic::generate_recovery_mnemonic(word_count)?)
}

#[uniffi::export]
pub fn derive_recovery_key_pair(
    mnemonic: String,
    user_id: String,
    algorithm: RecoveryKeyAlgorithm,
) -> Result<RecoveryKeyPair, MnemonicFfiError> {
    let mnemonic = Zeroizing::new(mnemonic);
    let core_algorithm = match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => mnemonic::RecoveryKeyAlgorithm::Ed25519,
        RecoveryKeyAlgorithm::P256Ecdsa => mnemonic::RecoveryKeyAlgorithm::P256Ecdsa,
    };
    let pair = mnemonic::derive_recovery_key_pair(&mnemonic, &user_id, core_algorithm)?;
    let private_key = Zeroizing::new(pair.export_private_key());
    Ok(RecoveryKeyPair {
        format_version: 1,
        algorithm,
        public_key: pair.public_key().to_vec(),
        private_key: private_key.to_vec(),
    })
}
