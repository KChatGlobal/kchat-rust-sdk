use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ContentProfile, FileCryptoError, OperationId, RandomPlanReason, TenantId,
    kkey::KKeyElement,
    oprf::{BlindBatch, ELEMENT_BYTES},
    pepper::Pepper,
    profile::{CONTENT_HASH_BYTES, ContentKeyMaterial},
};

/// Maximum contents blinded per `Evaluate` call; matches the KKey limit.
pub const MAX_OPRF_BATCH_SIZE: usize = 32;

/// SHA-256 and length of a plaintext from the first read pass, bound to its operation. The hash
/// is never exposed: it would let anyone confirm a guessed file offline.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentHash {
    #[zeroize(skip)]
    operation_id: OperationId,
    plaintext_sha256: [u8; CONTENT_HASH_BYTES],
    #[zeroize(skip)]
    plaintext_len: u64,
}

impl ContentHash {
    pub(crate) const fn new(
        operation_id: OperationId,
        plaintext_sha256: [u8; CONTENT_HASH_BYTES],
        plaintext_len: u64,
    ) -> Self {
        Self {
            operation_id,
            plaintext_sha256,
            plaintext_len,
        }
    }

    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub const fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    pub(crate) const fn plaintext_sha256(&self) -> &[u8; CONTENT_HASH_BYTES] {
        &self.plaintext_sha256
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self::new(
            self.operation_id.clone(),
            self.plaintext_sha256,
            self.plaintext_len,
        )
    }
}

impl core::fmt::Debug for ContentHash {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ContentHash")
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

/// Immutable key plan for one content operation, persisted until `forget_operation`. Sealing the
/// same source again yields the same bytes, so a retry needs no key-service call.
pub struct ContentPlan {
    profile: ContentProfile,
    material: ContentKeyMaterial,
    content: ContentHash,
    random_reason: Option<RandomPlanReason>,
}

impl ContentPlan {
    pub(crate) const fn new(
        profile: ContentProfile,
        material: ContentKeyMaterial,
        content: ContentHash,
        random_reason: Option<RandomPlanReason>,
    ) -> Self {
        Self {
            profile,
            material,
            content,
            random_reason,
        }
    }

    pub const fn operation_id(&self) -> &OperationId {
        &self.content.operation_id
    }

    pub const fn profile(&self) -> ContentProfile {
        self.profile
    }

    pub const fn plaintext_len(&self) -> u64 {
        self.content.plaintext_len
    }

    pub const fn random_reason(&self) -> Option<RandomPlanReason> {
        self.random_reason
    }

    pub(crate) const fn material(&self) -> &ContentKeyMaterial {
        &self.material
    }

    pub(crate) const fn content(&self) -> &ContentHash {
        &self.content
    }
}

impl core::fmt::Debug for ContentPlan {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ContentPlan")
            .field("profile", &self.profile)
            .field("plaintext_len", &self.content.plaintext_len)
            .field("random_reason", &self.random_reason)
            .finish_non_exhaustive()
    }
}

/// Blinded elements for the key service's `Evaluate`; the tenant comes from the host's token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OprfRequest {
    key_gen: u64,
    blinded_elements: Vec<[u8; ELEMENT_BYTES]>,
}

impl OprfRequest {
    /// The key service must evaluate with exactly this generation.
    pub const fn key_gen(&self) -> u64 {
        self.key_gen
    }

    /// One 32-byte element per content, in `begin_oprf` order.
    pub fn blinded_elements(&self) -> &[[u8; ELEMENT_BYTES]] {
        &self.blinded_elements
    }
}

/// Raw `Evaluate` result, validated by `finish_oprf` (`KKeyProofInvalid` on any mismatch).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OprfResponse {
    key_gen: u64,
    evaluated_elements: Vec<Vec<u8>>,
    proof: Vec<u8>,
}

impl OprfResponse {
    pub const fn new(key_gen: u64, evaluated_elements: Vec<Vec<u8>>, proof: Vec<u8>) -> Self {
        Self {
            key_gen,
            evaluated_elements,
            proof,
        }
    }

    pub const fn key_gen(&self) -> u64 {
        self.key_gen
    }

    pub fn evaluated_elements(&self) -> &[Vec<u8>] {
        &self.evaluated_elements
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}

/// In-flight evaluation holding the blinds and pepper. Never persisted (after a crash, start a new
/// one) and consumed by `finish_oprf`, so blinds are never reused.
pub struct OprfSession {
    tenant: TenantId,
    key_gen: u64,
    public_key: KKeyElement,
    pepper: Pepper,
    contents: Vec<ContentHash>,
    blinds: BlindBatch,
}

impl OprfSession {
    pub const fn key_gen(&self) -> u64 {
        self.key_gen
    }

    pub const fn pepper_gen(&self) -> u64 {
        self.pepper.generation()
    }

    pub fn content_count(&self) -> usize {
        self.contents.len()
    }

    pub(crate) fn begin(
        tenant: &TenantId,
        key_gen: u64,
        public_key: KKeyElement,
        pepper: Pepper,
        contents: &[&ContentHash],
    ) -> Result<(Self, OprfRequest), FileCryptoError> {
        let mut blinds = BlindBatch::with_capacity(contents.len());
        let mut blinded_elements = Vec::with_capacity(contents.len());
        for content in contents {
            blinded_elements.push(blinds.blind(content.plaintext_sha256())?);
        }
        let session = Self {
            tenant: tenant.clone(),
            key_gen,
            public_key,
            pepper,
            contents: contents.iter().map(|content| content.duplicate()).collect(),
            blinds,
        };
        let request = OprfRequest {
            key_gen,
            blinded_elements,
        };
        Ok((session, request))
    }

    pub(crate) const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Verifies the proof, then derives one plan per content; `FileKeyring::finish_oprf` stores
    /// them.
    pub(crate) fn finish(
        &self,
        response: &OprfResponse,
    ) -> Result<Vec<ContentPlan>, FileCryptoError> {
        if response.key_gen != self.key_gen {
            return Err(FileCryptoError::kkey_proof_invalid());
        }
        let inputs = self
            .contents
            .iter()
            .map(|content| content.plaintext_sha256().as_slice())
            .collect();
        let outputs = self.blinds.finalize(
            inputs,
            &response.evaluated_elements,
            &response.proof,
            self.public_key,
        )?;

        let profile = ContentProfile::HybridVoprfV1 {
            key_gen: self.key_gen,
            pepper_gen: self.pepper.generation(),
        };
        self.contents
            .iter()
            .zip(outputs.iter())
            .map(|(content, output)| {
                let material = ContentKeyMaterial::derive_hybrid(
                    output,
                    self.pepper.as_bytes(),
                    content.plaintext_sha256(),
                )?;
                Ok(ContentPlan::new(
                    profile,
                    material,
                    content.duplicate(),
                    None,
                ))
            })
            .collect()
    }
}

impl core::fmt::Debug for OprfSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OprfSession")
            .field("key_gen", &self.key_gen)
            .field("pepper_gen", &self.pepper.generation())
            .field("contents", &self.contents.len())
            .finish_non_exhaustive()
    }
}
