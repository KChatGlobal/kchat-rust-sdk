use chacha20poly1305::{AeadInOut, Key, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{FileCryptoError, TenantId, encoding::Encoder, ids::validate_id};

pub(crate) const KEY_BYTES: usize = 32;
pub const KEY_HASH_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
pub(crate) const RECORD_OVERHEAD_BYTES: usize = NONCE_BYTES + TAG_BYTES;
const WRAPPED_KEY_BYTES: usize = RECORD_OVERHEAD_BYTES + KEY_BYTES;

const LINK_AAD_LABEL: &str = "kchat-storage/node-link/v1";
const KEY_HASH_LABEL: &str = "kchat-storage/node-key-commit/v1";

/// The `u8` value goes into AAD and the key store; never renumber.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeKind {
    PersonalRoot,
    GroupRoot,
    File,
}

impl NodeKind {
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::PersonalRoot => 1,
            Self::GroupRoot => 2,
            Self::File => 3,
        }
    }

    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PersonalRoot),
            2 => Some(Self::GroupRoot),
            3 => Some(Self::File),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootKind {
    Group,
    Personal,
}

impl RootKind {
    pub(crate) const fn node_kind(self) -> NodeKind {
        match self {
            Self::Group => NodeKind::GroupRoot,
            Self::Personal => NodeKind::PersonalRoot,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RootId {
    tenant: TenantId,
    kind: RootKind,
    node_id: String,
}

impl RootId {
    pub fn group(tenant: &TenantId, group_node_id: &str) -> Result<Self, FileCryptoError> {
        Self::new(tenant, RootKind::Group, group_node_id)
    }

    pub fn personal(tenant: &TenantId, personal_node_id: &str) -> Result<Self, FileCryptoError> {
        Self::new(tenant, RootKind::Personal, personal_node_id)
    }

    pub(crate) fn new(
        tenant: &TenantId,
        kind: RootKind,
        node_id: &str,
    ) -> Result<Self, FileCryptoError> {
        validate_id(node_id)?;
        Ok(Self {
            tenant: tenant.clone(),
            kind,
            node_id: node_id.to_owned(),
        })
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub const fn kind(&self) -> RootKind {
        self.kind
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

impl core::fmt::Debug for RootId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RootId")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeKeyRef {
    tenant: TenantId,
    node_id: String,
    generation: u64,
}

impl NodeKeyRef {
    pub fn new(tenant: &TenantId, node_id: &str, generation: u64) -> Result<Self, FileCryptoError> {
        validate_id(node_id)?;
        validate_generation(generation)?;
        Ok(Self {
            tenant: tenant.clone(),
            node_id: node_id.to_owned(),
            generation,
        })
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl core::fmt::Debug for NodeKeyRef {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NodeKeyRef")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

pub(crate) fn validate_generation(generation: u64) -> Result<(), FileCryptoError> {
    if generation > i64::MAX as u64 {
        return Err(FileCryptoError::invalid_argument());
    }
    Ok(())
}

/// Pending root key. The host CASes `(epoch, key_hash)` on the server, then calls
/// `activate_node_key` (won) or `discard_node_key` (lost).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyProposal {
    key: NodeKeyRef,
    key_hash: [u8; KEY_HASH_BYTES],
}

impl KeyProposal {
    pub(crate) const fn new(key: NodeKeyRef, key_hash: [u8; KEY_HASH_BYTES]) -> Self {
        Self { key, key_hash }
    }

    pub const fn key(&self) -> &NodeKeyRef {
        &self.key
    }

    /// 0 for a root without keys, otherwise the highest active epoch + 1.
    pub const fn epoch(&self) -> u64 {
        self.key.generation
    }

    pub const fn key_hash(&self) -> &[u8; KEY_HASH_BYTES] {
        &self.key_hash
    }
}

impl core::fmt::Debug for KeyProposal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeyProposal")
            .field("epoch", &self.key.generation)
            .finish_non_exhaustive()
    }
}

/// Server-stored File NodeKey wrapped by one root epoch; only `ciphertext` is secret.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeLink {
    root: RootId,
    epoch: u64,
    file_node_id: String,
    file_generation: u64,
    key_hash: Option<[u8; KEY_HASH_BYTES]>,
    ciphertext: Vec<u8>,
}

impl NodeLink {
    /// Rebuilds a link returned by the server.
    pub fn from_parts(
        root: &RootId,
        epoch: u64,
        file_node_id: &str,
        file_generation: u64,
        key_hash: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Self, FileCryptoError> {
        validate_generation(epoch)?;
        validate_id(file_node_id)?;
        validate_generation(file_generation)?;
        let key_hash: Option<[u8; KEY_HASH_BYTES]> = key_hash
            .map(<[u8; KEY_HASH_BYTES]>::try_from)
            .transpose()
            .map_err(|_| FileCryptoError::invalid_argument())?;
        if ciphertext.len() != WRAPPED_KEY_BYTES {
            return Err(FileCryptoError::invalid_argument());
        }
        Ok(Self {
            root: root.clone(),
            epoch,
            file_node_id: file_node_id.to_owned(),
            file_generation,
            key_hash,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub const fn root(&self) -> &RootId {
        &self.root
    }

    /// Epoch of the wrapping root key.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn file_node_id(&self) -> &str {
        &self.file_node_id
    }

    pub const fn file_generation(&self) -> u64 {
        self.file_generation
    }

    /// Set on links from `create_file_key` (send it as `key_commitment`); may be absent on links
    /// rebuilt from the server.
    pub const fn key_hash(&self) -> Option<&[u8; KEY_HASH_BYTES]> {
        self.key_hash.as_ref()
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub(crate) fn file_key_ref(&self) -> NodeKeyRef {
        NodeKeyRef {
            tenant: self.root.tenant.clone(),
            node_id: self.file_node_id.clone(),
            generation: self.file_generation,
        }
    }

    pub(crate) fn wrap(
        root: &RootId,
        epoch: u64,
        root_key: &SecretKey,
        file_node_id: &str,
        file_generation: u64,
        file_key: &SecretKey,
    ) -> Result<Self, FileCryptoError> {
        let aad = link_aad(root, epoch, file_node_id, file_generation);
        let ciphertext = seal_record(root_key, &aad, file_key.as_bytes())?;
        Ok(Self {
            root: root.clone(),
            epoch,
            file_node_id: file_node_id.to_owned(),
            file_generation,
            key_hash: Some(file_key.key_hash(&root.tenant, file_node_id, file_generation)),
            ciphertext,
        })
    }

    pub(crate) fn unwrap(&self, root_key: &SecretKey) -> Result<SecretKey, FileCryptoError> {
        let aad = link_aad(
            &self.root,
            self.epoch,
            &self.file_node_id,
            self.file_generation,
        );
        let plaintext = open_record(root_key, &aad, &self.ciphertext)?;
        let file_key = SecretKey::from_slice(&plaintext)?;
        // AEAD passed but key_hash differs: a root-key holder wrote a bad record.
        if let Some(expected) = &self.key_hash
            && file_key.key_hash(&self.root.tenant, &self.file_node_id, self.file_generation)
                != *expected
        {
            return Err(FileCryptoError::key_envelope_invalid());
        }
        Ok(file_key)
    }
}

impl core::fmt::Debug for NodeLink {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NodeLink")
            .field("epoch", &self.epoch)
            .field("file_generation", &self.file_generation)
            .finish_non_exhaustive()
    }
}

fn link_aad(root: &RootId, epoch: u64, file_node_id: &str, file_generation: u64) -> Vec<u8> {
    Encoder::new(LINK_AAD_LABEL)
        .text(root.tenant.as_str())
        .text(&root.node_id)
        .u64(epoch)
        .u8(root.kind.node_kind().as_u8())
        .text(file_node_id)
        .u64(file_generation)
        .u8(NodeKind::File.as_u8())
        .finish()
}

#[derive(Clone, PartialEq, Eq)]
pub struct NewFileKey {
    link: NodeLink,
}

impl NewFileKey {
    pub(crate) const fn new(link: NodeLink) -> Self {
        Self { link }
    }

    /// Activate this key once the server accepts the link.
    pub fn file_key(&self) -> NodeKeyRef {
        self.link.file_key_ref()
    }

    pub const fn link(&self) -> &NodeLink {
        &self.link
    }
}

impl core::fmt::Debug for NewFileKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NewFileKey")
            .field("link", &self.link)
            .finish()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretKey([u8; KEY_BYTES]);

impl SecretKey {
    pub(crate) fn generate() -> Result<Self, FileCryptoError> {
        let mut bytes = [0_u8; KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| FileCryptoError::io_error())?;
        Ok(Self(bytes))
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, FileCryptoError> {
        let bytes: [u8; KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| FileCryptoError::invalid_argument())?;
        Ok(Self(bytes))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    /// `HMAC-SHA256(key, (tenant, node_id, generation))`, computed as HKDF-Extract (RFC 5869)
    /// to avoid an `hmac` dependency.
    pub(crate) fn key_hash(
        &self,
        tenant: &TenantId,
        node_id: &str,
        generation: u64,
    ) -> [u8; KEY_HASH_BYTES] {
        let message = Encoder::new(KEY_HASH_LABEL)
            .text(tenant.as_str())
            .text(node_id)
            .u64(generation)
            .finish();
        Hkdf::<Sha256>::extract(Some(&self.0), &message).0.into()
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretKey(REDACTED)")
    }
}

/// `nonce (24) || ciphertext || tag (16)` with a random nonce; used by links and descriptors.
pub(crate) fn seal_record(
    key: &SecretKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, FileCryptoError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| FileCryptoError::io_error())?;
    // Room for the tag up front, so no reallocation leaves a plaintext copy behind.
    let mut body = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_BYTES));
    body.extend_from_slice(plaintext);
    cipher(key)
        .encrypt_in_place(&XNonce::from(nonce), aad, &mut *body)
        .map_err(|_| FileCryptoError::invalid_state())?;
    Ok([nonce.as_slice(), &body].concat())
}

pub(crate) fn open_record(
    key: &SecretKey,
    aad: &[u8],
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FileCryptoError> {
    let (nonce, body) = record
        .split_first_chunk::<NONCE_BYTES>()
        .ok_or_else(FileCryptoError::key_envelope_invalid)?;
    let mut buffer = Zeroizing::new(body.to_vec());
    cipher(key)
        .decrypt_in_place(&XNonce::from(*nonce), aad, &mut *buffer)
        .map_err(|_| FileCryptoError::key_envelope_invalid())?;
    Ok(buffer)
}

fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    let mut key = Key::from(key.0);
    let cipher = XChaCha20Poly1305::new(&key);
    key.zeroize();
    cipher
}
