use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use p256::ecdsa::SigningKey as P256SigningKey;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MASTER_KEY_INFO: &[u8] = b"KCHAT_RECOVERY_V1_MASTER";
const ED25519_KEY_INFO: &[u8] = b"KCHAT_RECOVERY_V1_ED25519";
const P256_ECDSA_KEY_INFO: &[u8] = b"KCHAT_RECOVERY_V1_P256_ECDSA";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryKeyAlgorithm {
    Ed25519,
    P256Ecdsa,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MnemonicError {
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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKeyPair {
    private_key: [u8; 32],
    public_key: Vec<u8>,
}

impl RecoveryKeyPair {
    /// Returns a raw 32-byte Ed25519 seed or P-256 private scalar for native secure storage.
    pub fn export_private_key(&self) -> [u8; 32] {
        self.private_key
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl std::fmt::Debug for RecoveryKeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecoveryKeyPair(REDACTED)")
    }
}

/// Generates 12, 15, 18, 21, or 24 English BIP39 words from OS randomness.
pub fn generate_recovery_mnemonic(word_count: u32) -> Result<String, MnemonicError> {
    let entropy_len = match word_count {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _ => return Err(MnemonicError::InvalidWordCount),
    };
    let mut entropy = Zeroizing::new(vec![0_u8; entropy_len]);
    getrandom::fill(entropy.as_mut()).map_err(|_| MnemonicError::RandomnessUnavailable)?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
        .map_err(|_| MnemonicError::DerivationFailed)?;
    Ok(mnemonic.to_string())
}

/// Derives a deterministic recovery signing pair for the selected algorithm.
/// The mnemonic uses an empty BIP39 passphrase; user_id must be a UUID.
pub fn derive_recovery_key_pair(
    mnemonic: &str,
    user_id: &str,
    algorithm: RecoveryKeyAlgorithm,
) -> Result<RecoveryKeyPair, MnemonicError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| MnemonicError::InvalidMnemonic)?;
    let user_id = Uuid::parse_str(user_id).map_err(|_| MnemonicError::InvalidUserId)?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let mut master = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(None, seed.as_ref())
        .expand(MASTER_KEY_INFO, master.as_mut())
        .map_err(|_| MnemonicError::DerivationFailed)?;

    let label = match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => ED25519_KEY_INFO,
        RecoveryKeyAlgorithm::P256Ecdsa => P256_ECDSA_KEY_INFO,
    };
    let mut info = Vec::with_capacity(label.len() + 17);
    info.extend_from_slice(label);
    info.extend_from_slice(user_id.as_bytes());

    let mut private_key = Zeroizing::new([0_u8; 32]);
    let hkdf = Hkdf::<Sha256>::new(None, master.as_ref());
    match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => {
            hkdf.expand(&info, private_key.as_mut())
                .map_err(|_| MnemonicError::DerivationFailed)?;
            let signer = SigningKey::from_bytes(&private_key);

            Ok(RecoveryKeyPair {
                private_key: *private_key,
                public_key: signer.verifying_key().to_bytes().to_vec(),
            })
        }
        RecoveryKeyAlgorithm::P256Ecdsa => {
            let base_info_len = info.len();
            for counter in 0..=u8::MAX {
                info.truncate(base_info_len);
                if counter != 0 {
                    info.push(counter);
                }
                hkdf.expand(&info, private_key.as_mut())
                    .map_err(|_| MnemonicError::DerivationFailed)?;

                if let Ok(signer) = P256SigningKey::from_slice(private_key.as_ref()) {
                    return Ok(RecoveryKeyPair {
                        private_key: *private_key,
                        public_key: signer
                            .verifying_key()
                            .to_sec1_point(false)
                            .as_bytes()
                            .to_vec(),
                    });
                }
            }
            Err(MnemonicError::DerivationFailed)
        }
    }
}
