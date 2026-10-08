uniffi::setup_scaffolding!();

pub mod error;
pub mod mls;
pub mod mnemonic;

pub use mnemonic::{
    MnemonicFfiError, RecoveryKeyAlgorithm, RecoveryKeyPair, RecoverySignatureFfiError,
    derive_recovery_key_pair, generate_recovery_mnemonic, sign_recovery_message,
    verify_recovery_signature,
};
