uniffi::setup_scaffolding!();

pub mod error;
pub mod mls;
pub mod mnemonic;

pub use mnemonic::{
    MnemonicFfiError, RecoveryKeyAlgorithm, RecoveryKeyPair, derive_recovery_key_pair,
    generate_recovery_mnemonic,
};
