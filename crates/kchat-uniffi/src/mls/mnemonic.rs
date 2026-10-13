use kchat_mls::mnemonic::{self, MnemonicError, RecoverySignatureError};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, uniffi::Error, PartialEq, Eq)]
pub enum MnemonicFfiError {
    #[error("unsupported recovery mnemonic word count")]
    InvalidWordCount,
    #[error("invalid recovery mnemonic")]
    InvalidMnemonic,
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
            MnemonicError::RandomnessUnavailable => Self::RandomnessUnavailable,
            MnemonicError::DerivationFailed => Self::DerivationFailed,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error, PartialEq, Eq)]
pub enum RecoverySignatureFfiError {
    #[error("invalid recovery private key")]
    InvalidPrivateKey,
    #[error("invalid recovery public key")]
    InvalidPublicKey,
}

impl From<RecoverySignatureError> for RecoverySignatureFfiError {
    fn from(error: RecoverySignatureError) -> Self {
        match error {
            RecoverySignatureError::InvalidPrivateKey => Self::InvalidPrivateKey,
            RecoverySignatureError::InvalidPublicKey => Self::InvalidPublicKey,
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
    algorithm: RecoveryKeyAlgorithm,
) -> Result<RecoveryKeyPair, MnemonicFfiError> {
    let mnemonic = Zeroizing::new(mnemonic);
    let core_algorithm = match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => mnemonic::RecoveryKeyAlgorithm::Ed25519,
        RecoveryKeyAlgorithm::P256Ecdsa => mnemonic::RecoveryKeyAlgorithm::P256Ecdsa,
    };
    let pair = mnemonic::derive_recovery_key_pair(&mnemonic, core_algorithm)?;
    let private_key = Zeroizing::new(pair.export_private_key());
    Ok(RecoveryKeyPair {
        format_version: 1,
        algorithm,
        public_key: pair.public_key().to_vec(),
        private_key: private_key.to_vec(),
    })
}

#[uniffi::export]
pub fn sign_recovery_message(
    algorithm: RecoveryKeyAlgorithm,
    private_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, RecoverySignatureFfiError> {
    let private_key = Zeroizing::new(private_key);
    let algorithm = match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => mnemonic::RecoveryKeyAlgorithm::Ed25519,
        RecoveryKeyAlgorithm::P256Ecdsa => mnemonic::RecoveryKeyAlgorithm::P256Ecdsa,
    };
    Ok(mnemonic::sign_recovery_message(
        algorithm,
        &private_key,
        &message,
    )?)
}

#[uniffi::export]
pub fn verify_recovery_signature(
    algorithm: RecoveryKeyAlgorithm,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, RecoverySignatureFfiError> {
    let algorithm = match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => mnemonic::RecoveryKeyAlgorithm::Ed25519,
        RecoveryKeyAlgorithm::P256Ecdsa => mnemonic::RecoveryKeyAlgorithm::P256Ecdsa,
    };
    Ok(mnemonic::verify_recovery_signature(
        algorithm,
        &public_key,
        &message,
        &signature,
    )?)
}
