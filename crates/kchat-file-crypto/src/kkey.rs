use ed25519_dalek::{Signature, VerifyingKey};
use voprf::{Group, Ristretto255};

use crate::{FileCryptoError, TenantId, encoding::Encoder};

const PUBLIC_KEY_SIGNATURE_LABEL: &str = "kchat-storage/kkey-public-key/v1";
const POLICY_SIGNATURE_LABEL: &str = "kchat-storage/kkey-policy/v1";
const HYBRID_POLICY_NAME: &str = "HYBRID";
const MAX_POLICY_NAME_BYTES: usize = 64;
pub(crate) const KKEY_PUBLIC_KEY_BYTES: usize = 32;

pub(crate) type KKeyElement = <Ristretto255 as Group>::Elem;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfilePolicy {
    /// `hybrid-voprf/v1`: key service plus tenant pepper.
    Hybrid,
    /// `random-dek/v1`: random key, no deduplication.
    Random,
}

impl ProfilePolicy {
    /// Only `"HYBRID"` enables hybrid plans; unknown (newer) names map to `Random`.
    pub(crate) fn from_name(name: &str) -> Self {
        if name == HYBRID_POLICY_NAME {
            Self::Hybrid
        } else {
            Self::Random
        }
    }
}

/// Ed25519 key of the key service's signing root, supplied by the host on every open.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KKeyRootKey(VerifyingKey);

impl KKeyRootKey {
    /// Rejects invalid and small-order (weak) points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FileCryptoError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| FileCryptoError::invalid_argument())?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| FileCryptoError::invalid_argument())?;
        if key.is_weak() {
            return Err(FileCryptoError::invalid_argument());
        }
        Ok(Self(key))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// `verify_strict` also rejects malleable signatures.
    fn verifies(&self, message: &[u8], signature: &Signature) -> bool {
        self.0.verify_strict(message, signature).is_ok()
    }
}

impl core::fmt::Debug for KKeyRootKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KKeyRootKey(..)")
    }
}

/// What the key store currently holds for a tenant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeySourceStatus {
    pub(crate) policy: Option<ProfilePolicy>,
    pub(crate) policy_version: Option<u64>,
    pub(crate) key_gen: Option<u64>,
    pub(crate) pepper_gen: Option<u64>,
}

impl KeySourceStatus {
    pub const fn policy(&self) -> Option<ProfilePolicy> {
        self.policy
    }

    pub const fn policy_version(&self) -> Option<u64> {
        self.policy_version
    }

    pub const fn key_gen(&self) -> Option<u64> {
        self.key_gen
    }

    pub const fn pepper_gen(&self) -> Option<u64> {
        self.pepper_gen
    }

    pub const fn needs_key_config(&self) -> bool {
        self.policy.is_none() || self.key_gen.is_none()
    }
}

/// Verifies the signature over the raw bytes, then decodes the point.
pub(crate) fn verify_public_key(
    root: Option<&KKeyRootKey>,
    tenant: &TenantId,
    key_gen: u64,
    public_key: &[u8],
    signature: &[u8],
) -> Result<[u8; KKEY_PUBLIC_KEY_BYTES], FileCryptoError> {
    let message = Encoder::new(PUBLIC_KEY_SIGNATURE_LABEL)
        .text(tenant.as_str())
        .u64(key_gen)
        .bytes(public_key)
        .finish();
    verify_signature(root, &message, signature)?;
    let encoded: [u8; KKEY_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| FileCryptoError::kkey_signature_invalid())?;
    decode_public_key(&encoded).map_err(|_| FileCryptoError::kkey_signature_invalid())?;
    Ok(encoded)
}

pub(crate) fn verify_policy(
    root: Option<&KKeyRootKey>,
    tenant: &TenantId,
    policy_version: u64,
    policy: &str,
    signature: &[u8],
) -> Result<(), FileCryptoError> {
    if policy.is_empty() || policy.len() > MAX_POLICY_NAME_BYTES {
        return Err(FileCryptoError::invalid_argument());
    }
    let message = Encoder::new(POLICY_SIGNATURE_LABEL)
        .text(tenant.as_str())
        .u64(policy_version)
        .text(policy)
        .finish();
    verify_signature(root, &message, signature)
}

/// Rejects non-canonical encodings and the identity element (which would make the OPRF output
/// independent of `k_T`). Also used for stored keys, hence `StoreError`.
pub(crate) fn decode_public_key(
    encoded: &[u8; KKEY_PUBLIC_KEY_BYTES],
) -> Result<KKeyElement, FileCryptoError> {
    Ristretto255::deserialize_elem(encoded).map_err(|_| FileCryptoError::store_error())
}

fn verify_signature(
    root: Option<&KKeyRootKey>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), FileCryptoError> {
    let signature =
        Signature::from_slice(signature).map_err(|_| FileCryptoError::kkey_signature_invalid())?;
    match root {
        Some(root) if root.verifies(message, &signature) => Ok(()),
        _ => Err(FileCryptoError::kkey_signature_invalid()),
    }
}
