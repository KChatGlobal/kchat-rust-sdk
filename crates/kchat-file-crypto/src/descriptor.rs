//! Blob descriptor (KFiles `EncryptedDescriptor`): the object's DEK, nonce prefix, lengths and
//! ciphertext hash as CBOR, sealed with the File NodeKey. The AAD binds `file_node_id` and
//! `file_gen` but not `blob_id`, which the server assigns after sealing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    ContentKey, ContentProfile, FileCryptoError, NodeKeyRef, SealedContent, TenantId,
    cbor::{ByteString, FixedBytes, decode_cbor},
    encoding::Encoder,
    ids::validate_id,
    key_tree::{RECORD_OVERHEAD_BYTES, SecretKey, open_record, seal_record, validate_generation},
    profile::{ContentKeyMaterial, DEK_BYTES, NONCE_PREFIX_BYTES},
};

/// Descriptor format (the AAD `profile_id`), the only one the server accepts.
pub const DESCRIPTOR_PROFILE_V2: &str = "kchat-storage/descriptor/v2";
/// Largest descriptor CBOR plaintext; matches the KFiles ciphertext limit (1 MiB + 40).
pub const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;

const DESCRIPTOR_AAD_LABEL: &str = "kchat-storage/descriptor/v2";
const SEAL_REQUEST_LABEL: &str = "kchat-file/seal-descriptor-request/v1";
const DESCRIPTOR_VERSION: u64 = 1;
/// Upper bound of the plaintext outside `app`, so the buffer is allocated once.
const FIXED_PART_BYTES: usize = 1024;

/// KFiles `EncryptedDescriptor`: the ciphertext plus the File NodeKey that sealed it.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedDescriptor {
    file_node_id: String,
    file_generation: u64,
    ciphertext: Vec<u8>,
}

impl EncryptedDescriptor {
    /// Rebuilds a descriptor returned by the server; other profiles (including V1) return
    /// `UnsupportedProfile`. `file_node_id` is the lane's File NodeKey (`file_id`, or
    /// `<file_id>:user:<jid>` for a private lane); `file_generation` is `file_epoch`.
    pub fn from_parts(
        profile_id: &str,
        file_node_id: &str,
        file_generation: u64,
        ciphertext: &[u8],
    ) -> Result<Self, FileCryptoError> {
        if profile_id != DESCRIPTOR_PROFILE_V2 {
            return Err(FileCryptoError::unsupported_profile());
        }
        validate_id(file_node_id)?;
        validate_generation(file_generation)?;
        if ciphertext.len() > MAX_DESCRIPTOR_BYTES + RECORD_OVERHEAD_BYTES {
            return Err(FileCryptoError::resource_limit_exceeded());
        }
        if ciphertext.len() <= RECORD_OVERHEAD_BYTES {
            return Err(FileCryptoError::invalid_argument());
        }
        Ok(Self::from_stored(
            file_node_id.to_owned(),
            file_generation,
            ciphertext.to_vec(),
        ))
    }

    pub(crate) const fn from_stored(
        file_node_id: String,
        file_generation: u64,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            file_node_id,
            file_generation,
            ciphertext,
        }
    }

    /// `EncryptedDescriptor.profile_id`.
    pub const fn profile_id(&self) -> &'static str {
        DESCRIPTOR_PROFILE_V2
    }

    pub fn file_node_id(&self) -> &str {
        &self.file_node_id
    }

    /// `EncryptedDescriptor.file_epoch`.
    pub const fn file_generation(&self) -> u64 {
        self.file_generation
    }

    /// `EncryptedDescriptor.ciphertext`: nonce (24) || ciphertext || tag (16).
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl core::fmt::Debug for EncryptedDescriptor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncryptedDescriptor")
            .field("file_generation", &self.file_generation)
            .field("len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

pub struct OpenedBlob {
    object_id: String,
    key: ContentKey,
    app: Option<Zeroizing<Vec<u8>>>,
}

impl OpenedBlob {
    /// Object id recorded at seal time; compare it with the object fetched.
    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub const fn content_key(&self) -> &ContentKey {
        &self.key
    }

    pub fn app_manifest(&self) -> Option<&[u8]> {
        self.app.as_deref().map(Vec::as_slice)
    }
}

impl core::fmt::Debug for OpenedBlob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenedBlob")
            .field("app_len", &self.app.as_ref().map(|app| app.len()))
            .finish_non_exhaustive()
    }
}

pub(crate) fn seal_blob(
    file_key_ref: &NodeKeyRef,
    file_key: &SecretKey,
    file_id: &str,
    object_id: &str,
    key: &ContentKey,
    app: Option<&[u8]>,
) -> Result<EncryptedDescriptor, FileCryptoError> {
    let plaintext = encode_descriptor(object_id, key, app)?;
    seal_raw_descriptor(file_key_ref, file_key, file_id, &plaintext)
}

pub(crate) fn open_blob(
    tenant: &TenantId,
    file_id: &str,
    file_key: &SecretKey,
    descriptor: &EncryptedDescriptor,
) -> Result<OpenedBlob, FileCryptoError> {
    let plaintext = open_raw_descriptor(tenant, file_id, file_key, descriptor)?;
    decode_descriptor(&plaintext)
}

/// Re-encrypts the same plaintext under a new File NodeKey.
pub(crate) fn reseal_blob(
    tenant: &TenantId,
    file_id: &str,
    (descriptor, old_key): (&EncryptedDescriptor, &SecretKey),
    (new_key_ref, new_key): (&NodeKeyRef, &SecretKey),
) -> Result<EncryptedDescriptor, FileCryptoError> {
    let plaintext = open_raw_descriptor(tenant, file_id, old_key, descriptor)?;
    // Validate before resealing so corrupt data is never duplicated.
    decode_descriptor(&plaintext)?;
    seal_raw_descriptor(new_key_ref, new_key, file_id, &plaintext)
}

/// Raw CBOR plaintext, to compare two descriptors of one blob without decoding.
pub(crate) fn open_raw_descriptor(
    tenant: &TenantId,
    file_id: &str,
    file_key: &SecretKey,
    descriptor: &EncryptedDescriptor,
) -> Result<Zeroizing<Vec<u8>>, FileCryptoError> {
    let aad = descriptor_aad(
        tenant,
        file_id,
        &descriptor.file_node_id,
        descriptor.file_generation,
    );
    open_record(file_key, &aad, &descriptor.ciphertext)
}

fn seal_raw_descriptor(
    file_key_ref: &NodeKeyRef,
    file_key: &SecretKey,
    file_id: &str,
    plaintext: &[u8],
) -> Result<EncryptedDescriptor, FileCryptoError> {
    let aad = descriptor_aad(
        file_key_ref.tenant(),
        file_id,
        file_key_ref.node_id(),
        file_key_ref.generation(),
    );
    Ok(EncryptedDescriptor::from_stored(
        file_key_ref.node_id().to_owned(),
        file_key_ref.generation(),
        seal_record(file_key, &aad, plaintext)?,
    ))
}

/// Digest of a seal request (without the DEK), so a retry returns the stored ciphertext and a
/// different request for the same blob is detected.
pub(crate) fn request_digest(
    file_key_ref: &NodeKeyRef,
    object_id: &str,
    key: &ContentKey,
    app: Option<&[u8]>,
) -> [u8; 32] {
    let (key_gen, pepper_gen) = key.profile().generations();
    let encoded = Encoder::new(SEAL_REQUEST_LABEL)
        .text(file_key_ref.node_id())
        .u64(file_key_ref.generation())
        .text(object_id)
        .text(key.profile().id())
        .u64(key_gen.unwrap_or(0))
        .u64(pepper_gen.unwrap_or(0))
        .u64(key.plaintext_len())
        .u64(key.ciphertext_len())
        .bytes(key.ciphertext_sha256())
        // `Some(&[])` is rejected at seal time, so `None` and an empty manifest never collide.
        .bytes(&Sha256::digest(app.unwrap_or_default()))
        .finish();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(&encoded));
    digest
}

fn descriptor_aad(
    tenant: &TenantId,
    file_id: &str,
    file_node_id: &str,
    file_generation: u64,
) -> Vec<u8> {
    Encoder::new(DESCRIPTOR_AAD_LABEL)
        .text(tenant.as_str())
        .text(file_id)
        .text(file_node_id)
        .u64(file_generation)
        .text(DESCRIPTOR_PROFILE_V2)
        .finish()
}

fn encode_descriptor(
    object_id: &str,
    key: &ContentKey,
    app: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, FileCryptoError> {
    let app_len = app.map_or(0, <[u8]>::len);
    if app.is_some_and(<[u8]>::is_empty) {
        return Err(FileCryptoError::invalid_argument());
    }
    if app_len > MAX_DESCRIPTOR_BYTES {
        return Err(FileCryptoError::resource_limit_exceeded());
    }
    let (kg, pg) = key.profile().generations();
    let wire = WireDescriptor {
        v: DESCRIPTOR_VERSION,
        object: object_id.to_owned(),
        profile: key.profile().id().to_owned(),
        kg,
        pg,
        dek: FixedBytes(key.material().dek),
        prefix: FixedBytes(key.material().nonce_prefix),
        psize: key.plaintext_len(),
        csize: key.ciphertext_len(),
        csha: FixedBytes(*key.ciphertext_sha256()),
        app: app.map(|app| ByteString(Zeroizing::new(app.to_vec()))),
    };
    // Reserved up front so no reallocation leaves a DEK copy in freed memory.
    let mut bytes = Zeroizing::new(Vec::with_capacity(FIXED_PART_BYTES + app_len));
    ciborium::into_writer(&wire, &mut *bytes).map_err(|_| FileCryptoError::invalid_state())?;
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(FileCryptoError::resource_limit_exceeded());
    }
    Ok(bytes)
}

/// Strict: anyone holding the File NodeKey can write a descriptor, so it is untrusted after AEAD.
fn decode_descriptor(plaintext: &[u8]) -> Result<OpenedBlob, FileCryptoError> {
    // Read "v" alone first: an unknown version is a newer SDK's descriptor, not corruption.
    let version: WireVersion = decode_cbor(plaintext)?;
    if version.v != DESCRIPTOR_VERSION {
        return Err(FileCryptoError::unsupported_profile());
    }
    let wire: WireDescriptor = decode_cbor(plaintext)?;
    validate_id(&wire.object).map_err(|_| FileCryptoError::malformed_message())?;
    if wire.app.as_ref().is_some_and(|app| app.0.is_empty()) {
        return Err(FileCryptoError::malformed_message());
    }
    let profile = ContentProfile::from_parts(
        &wire.profile,
        wire.kg,
        wire.pg,
        FileCryptoError::malformed_message,
    )?;
    let sealed = SealedContent::from_member(wire.psize, wire.csize, wire.csha.0)
        .ok_or_else(FileCryptoError::malformed_message)?;
    let material = ContentKeyMaterial {
        dek: wire.dek.0,
        nonce_prefix: wire.prefix.0,
    };
    Ok(OpenedBlob {
        object_id: wire.object,
        key: ContentKey::from_parts(profile, material, sealed),
        app: wire.app.map(|app| app.0),
    })
}

/// Reads only "v"; other fields are ignored.
#[derive(Deserialize)]
struct WireVersion {
    v: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDescriptor {
    v: u64,
    #[serde(rename = "obj")]
    object: String,
    profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kg: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pg: Option<u64>,
    dek: FixedBytes<DEK_BYTES>,
    prefix: FixedBytes<NONCE_PREFIX_BYTES>,
    psize: u64,
    csize: u64,
    csha: FixedBytes<32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app: Option<ByteString>,
}
