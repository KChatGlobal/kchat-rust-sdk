//! Content profiles and their key derivation.
//!
//! `hybrid-voprf/v1` expands the DEK and nonce prefix from
//! `PRK = HKDF-Extract(salt, oprf_out || pepper || SHA-256(P))`. The nonce is deterministic but
//! safe: key and nonce both depend on the plaintext, so they only repeat for identical bytes.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{FileCryptoError, encoding::Encoder, oprf::OUTPUT_BYTES, pepper::PEPPER_BYTES};

pub(crate) const DEK_BYTES: usize = 32;
pub(crate) const NONCE_PREFIX_BYTES: usize = 19;
pub(crate) const CONTENT_HASH_BYTES: usize = 32;

const HYBRID_PROFILE_ID: &str = "kchat-file/whole-file/xchacha-stream-64k/hybrid-voprf/v1";
const RANDOM_PROFILE_ID: &str = "kchat-file/whole-file/xchacha-stream-64k/random-dek/v1";
const HYBRID_PRK_SALT: &[u8] = b"kchat-storage/hybrid-voprf/v1";
const HYBRID_KEY_INFO: &[u8] = b"kchat-file/whole-file/xchacha-stream/hybrid-voprf/key/v1";
const HYBRID_NONCE_PREFIX_INFO: &[u8] =
    b"kchat-file/whole-file/xchacha-stream/hybrid-voprf/nonce-prefix/v1";
const HYBRID_AAD_LABEL: &str = "kchat-file/whole-file/xchacha-stream/hybrid-voprf/v1";
const RANDOM_AAD_LABEL: &str = "kchat-file/whole-file/xchacha-stream/random-dek/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentProfile {
    HybridVoprfV1 { key_gen: u64, pepper_gen: u64 },
    RandomDekV1,
}

impl ContentProfile {
    pub const fn id(&self) -> &'static str {
        match self {
            Self::HybridVoprfV1 { .. } => HYBRID_PROFILE_ID,
            Self::RandomDekV1 => RANDOM_PROFILE_ID,
        }
    }

    pub(crate) fn from_parts(
        id: &str,
        key_gen: Option<u64>,
        pepper_gen: Option<u64>,
        inconsistent: fn() -> FileCryptoError,
    ) -> Result<Self, FileCryptoError> {
        match (id, key_gen, pepper_gen) {
            (HYBRID_PROFILE_ID, Some(key_gen), Some(pepper_gen)) => Ok(Self::HybridVoprfV1 {
                key_gen,
                pepper_gen,
            }),
            (RANDOM_PROFILE_ID, None, None) => Ok(Self::RandomDekV1),
            (HYBRID_PROFILE_ID | RANDOM_PROFILE_ID, _, _) => Err(inconsistent()),
            _ => Err(FileCryptoError::unsupported_profile()),
        }
    }

    pub(crate) const fn generations(&self) -> (Option<u64>, Option<u64>) {
        match self {
            Self::HybridVoprfV1 {
                key_gen,
                pepper_gen,
            } => (Some(*key_gen), Some(*pepper_gen)),
            Self::RandomDekV1 => (None, None),
        }
    }

    pub(crate) fn aad(&self, plaintext_len: u64) -> Vec<u8> {
        match self {
            Self::HybridVoprfV1 {
                key_gen,
                pepper_gen,
            } => Encoder::new(HYBRID_AAD_LABEL)
                .u64(*key_gen)
                .u64(*pepper_gen)
                .u64(plaintext_len)
                .finish(),
            Self::RandomDekV1 => Encoder::new(RANDOM_AAD_LABEL).u64(plaintext_len).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomPlanReason {
    KKeyUnavailable,
    PolicyRandom,
    PolicyUnavailable,
    RateLimited,
    PepperMissing,
    NoTenant,
    SmallFile,
}

impl RandomPlanReason {
    const ALL: [Self; 7] = [
        Self::KKeyUnavailable,
        Self::PolicyRandom,
        Self::PolicyUnavailable,
        Self::RateLimited,
        Self::PepperMissing,
        Self::NoTenant,
        Self::SmallFile,
    ];

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::KKeyUnavailable => "KKeyUnavailable",
            Self::PolicyRandom => "PolicyRandom",
            Self::PolicyUnavailable => "PolicyUnavailable",
            Self::RateLimited => "RateLimited",
            Self::PepperMissing => "PepperMissing",
            Self::NoTenant => "NoTenant",
            Self::SmallFile => "SmallFile",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, FileCryptoError> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == value)
            .ok_or_else(FileCryptoError::store_error)
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ContentKeyMaterial {
    pub(crate) dek: [u8; DEK_BYTES],
    pub(crate) nonce_prefix: [u8; NONCE_PREFIX_BYTES],
}

impl ContentKeyMaterial {
    pub(crate) fn derive_hybrid(
        oprf_output: &[u8; OUTPUT_BYTES],
        pepper: &[u8; PEPPER_BYTES],
        content_hash: &[u8; CONTENT_HASH_BYTES],
    ) -> Result<Self, FileCryptoError> {
        // `concat` allocates the exact size once, so no copy is left behind.
        let input_key_material =
            Zeroizing::new([oprf_output.as_slice(), pepper, content_hash].concat());
        let prk = Hkdf::<Sha256>::new(Some(HYBRID_PRK_SALT), &input_key_material);
        let mut material = Self::default();
        prk.expand(HYBRID_KEY_INFO, &mut material.dek)
            .map_err(|_| FileCryptoError::invalid_state())?;
        prk.expand(HYBRID_NONCE_PREFIX_INFO, &mut material.nonce_prefix)
            .map_err(|_| FileCryptoError::invalid_state())?;
        Ok(material)
    }

    pub(crate) fn random() -> Result<Self, FileCryptoError> {
        let mut material = Self::default();
        getrandom::fill(&mut material.dek).map_err(|_| FileCryptoError::io_error())?;
        getrandom::fill(&mut material.nonce_prefix).map_err(|_| FileCryptoError::io_error())?;
        Ok(material)
    }

    pub(crate) fn from_slices(dek: &[u8], nonce_prefix: &[u8]) -> Result<Self, FileCryptoError> {
        Ok(Self {
            dek: dek.try_into().map_err(|_| FileCryptoError::store_error())?,
            nonce_prefix: nonce_prefix
                .try_into()
                .map_err(|_| FileCryptoError::store_error())?,
        })
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            dek: self.dek,
            nonce_prefix: self.nonce_prefix,
        }
    }
}
