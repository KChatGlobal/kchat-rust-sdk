use bip39::{Language, Mnemonic};
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey, VerifyingKey,
    pkcs8::{DecodePublicKey as _, EncodePublicKey as _},
};
use hkdf::Hkdf;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use sha2::Sha256;
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
    #[error("recovery randomness unavailable")]
    RandomnessUnavailable,
    #[error("recovery key derivation failed")]
    DerivationFailed,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoverySignatureError {
    #[error("invalid recovery private key")]
    InvalidPrivateKey,
    #[error("invalid recovery public key")]
    InvalidPublicKey,
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

    /// Returns the public key as X.509 SubjectPublicKeyInfo DER.
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
/// The mnemonic uses an empty BIP39 passphrase.
pub fn derive_recovery_key_pair(
    mnemonic: &str,
    algorithm: RecoveryKeyAlgorithm,
) -> Result<RecoveryKeyPair, MnemonicError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|_| MnemonicError::InvalidMnemonic)?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let mut master = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(None, seed.as_ref())
        .expand(MASTER_KEY_INFO, master.as_mut())
        .map_err(|_| MnemonicError::DerivationFailed)?;

    let label = match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => ED25519_KEY_INFO,
        RecoveryKeyAlgorithm::P256Ecdsa => P256_ECDSA_KEY_INFO,
    };
    let mut info = label.to_vec();

    let mut private_key = Zeroizing::new([0_u8; 32]);
    let hkdf = Hkdf::<Sha256>::new(None, master.as_ref());
    match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => {
            hkdf.expand(&info, private_key.as_mut())
                .map_err(|_| MnemonicError::DerivationFailed)?;
            let signer = SigningKey::from_bytes(&private_key);

            Ok(RecoveryKeyPair {
                private_key: *private_key,
                public_key: signer
                    .verifying_key()
                    .to_public_key_der()
                    .map_err(|_| MnemonicError::DerivationFailed)?
                    .as_bytes()
                    .to_vec(),
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
                            .to_public_key_der()
                            .map_err(|_| MnemonicError::DerivationFailed)?
                            .as_bytes()
                            .to_vec(),
                    });
                }
            }
            Err(MnemonicError::DerivationFailed)
        }
    }
}

pub fn sign_recovery_message(
    algorithm: RecoveryKeyAlgorithm,
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, RecoverySignatureError> {
    match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => {
            let private_key: &[u8; 32] = private_key
                .try_into()
                .map_err(|_| RecoverySignatureError::InvalidPrivateKey)?;
            let signer = SigningKey::from_bytes(private_key);
            let signature: Ed25519Signature = signer.sign(message);
            Ok(signature.to_bytes().to_vec())
        }
        RecoveryKeyAlgorithm::P256Ecdsa => {
            if private_key.len() != 32 {
                return Err(RecoverySignatureError::InvalidPrivateKey);
            }
            let signer = P256SigningKey::from_slice(private_key)
                .map_err(|_| RecoverySignatureError::InvalidPrivateKey)?;
            let signature: P256Signature = signer.sign(message);
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }
}

pub fn verify_recovery_signature(
    algorithm: RecoveryKeyAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, RecoverySignatureError> {
    match algorithm {
        RecoveryKeyAlgorithm::Ed25519 => {
            let verifier = VerifyingKey::from_public_key_der(public_key)
                .map_err(|_| RecoverySignatureError::InvalidPublicKey)?;
            let Ok(signature) = Ed25519Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(verifier.verify_strict(message, &signature).is_ok())
        }
        RecoveryKeyAlgorithm::P256Ecdsa => {
            let verifier = P256VerifyingKey::from_public_key_der(public_key)
                .map_err(|_| RecoverySignatureError::InvalidPublicKey)?;
            let Ok(signature) = P256Signature::from_der(signature) else {
                return Ok(false);
            };
            Ok(verifier.verify(message, &signature).is_ok())
        }
    }
}
