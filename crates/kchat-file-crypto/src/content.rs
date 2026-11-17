//! Whole-file STREAM-BE32 encryption (XChaCha20-Poly1305, 64 KiB blocks) shared by every V1
//! profile.
//!
//! The layout is canonical, so every client produces identical bytes: each block but the last
//! holds exactly 64 KiB; a non-zero multiple of 64 KiB ends with a full last block; empty
//! plaintext is one empty last block.

use aead_stream::{DecryptorBE32, EncryptorBE32, Key, Nonce, StreamBE32, aead::Payload};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ContentHash, ContentPlan, ContentProfile, FileCryptoError, OperationId,
    profile::ContentKeyMaterial,
};

pub const MAX_CIPHERTEXT_BYTES_V1: u64 = 5 * 1024 * 1024 * 1024;
pub const MAX_IO_CHUNK_BYTES: usize = 64 * 1024;

const BLOCK_BYTES: usize = 64 * 1024;
const TAG_BYTES: usize = 16;

type StreamKey = Key<XChaCha20Poly1305>;
type StreamNonce = Nonce<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>;

pub trait ContentSource {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, FileCryptoError>;

    fn is_cancelled(&self) -> bool {
        false
    }
}

pub trait ContentSink {
    fn write_chunk(&mut self, source: &[u8]) -> Result<(), FileCryptoError>;

    fn commit(&mut self) -> Result<(), FileCryptoError>;

    fn abort(&mut self) -> Result<(), FileCryptoError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedContent {
    plaintext_len: u64,
    ciphertext_len: u64,
    ciphertext_sha256: [u8; 32],
}

impl SealedContent {
    /// `None` unless the lengths fit the V1 layout.
    pub(crate) fn from_member(
        plaintext_len: u64,
        ciphertext_len_value: u64,
        ciphertext_sha256: [u8; 32],
    ) -> Option<Self> {
        (ciphertext_len(plaintext_len) == Some(ciphertext_len_value)).then_some(Self {
            plaintext_len,
            ciphertext_len: ciphertext_len_value,
            ciphertext_sha256,
        })
    }

    pub const fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    pub const fn ciphertext_len(&self) -> u64 {
        self.ciphertext_len
    }

    pub const fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.ciphertext_sha256
    }
}

pub struct ContentKey {
    profile: ContentProfile,
    material: ContentKeyMaterial,
    sealed: SealedContent,
}

impl ContentKey {
    pub fn from_sealed(
        plan: &ContentPlan,
        sealed: &SealedContent,
    ) -> Result<Self, FileCryptoError> {
        if sealed.plaintext_len != plan.plaintext_len() {
            return Err(FileCryptoError::invalid_argument());
        }
        Ok(Self::from_parts(
            plan.profile(),
            plan.material().duplicate(),
            *sealed,
        ))
    }

    pub(crate) const fn from_parts(
        profile: ContentProfile,
        material: ContentKeyMaterial,
        sealed: SealedContent,
    ) -> Self {
        Self {
            profile,
            material,
            sealed,
        }
    }

    /// Explicit copy with its own zeroizing DEK; the type is deliberately not `Clone`.
    pub fn duplicate(&self) -> Self {
        Self::from_parts(self.profile, self.material.duplicate(), self.sealed)
    }

    pub(crate) const fn material(&self) -> &ContentKeyMaterial {
        &self.material
    }

    pub const fn profile(&self) -> ContentProfile {
        self.profile
    }

    pub const fn plaintext_len(&self) -> u64 {
        self.sealed.plaintext_len
    }

    pub const fn ciphertext_len(&self) -> u64 {
        self.sealed.ciphertext_len
    }

    pub const fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.sealed.ciphertext_sha256
    }
}

impl core::fmt::Debug for ContentKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ContentKey")
            .field("profile", &self.profile)
            .field("sealed", &self.sealed)
            .finish_non_exhaustive()
    }
}

pub fn hash_content(
    operation_id: &OperationId,
    source: &mut dyn ContentSource,
) -> Result<ContentHash, FileCryptoError> {
    let mut buffer = Zeroizing::new([0_u8; MAX_IO_CHUNK_BYTES]);
    let mut hash = Sha256::new();
    let mut plaintext_len = 0_u64;
    loop {
        let count = read_from(source, &mut buffer[..])?;
        if count == 0 {
            break;
        }
        plaintext_len = plaintext_len
            .checked_add(count as u64)
            .filter(|length| ciphertext_len(*length).is_some())
            .ok_or_else(FileCryptoError::resource_limit_exceeded)?;
        hash.update(&buffer[..count]);
    }
    Ok(ContentHash::new(
        operation_id.clone(),
        hash.finalize().into(),
        plaintext_len,
    ))
}

pub fn seal_content(
    plan: &ContentPlan,
    source: &mut dyn ContentSource,
    sink: &mut dyn ContentSink,
) -> Result<SealedContent, FileCryptoError> {
    let result = seal_into(plan, source, sink);
    commit_or_abort(sink, result)
}

pub fn open_content(
    key: &ContentKey,
    source: &mut dyn ContentSource,
    sink: &mut dyn ContentSink,
) -> Result<(), FileCryptoError> {
    let result = open_into(key, source, sink);
    commit_or_abort(sink, result)
}

/// Commits after success, otherwise aborts. Abort errors are dropped: the host needs the original.
fn commit_or_abort<T>(
    sink: &mut dyn ContentSink,
    result: Result<T, FileCryptoError>,
) -> Result<T, FileCryptoError> {
    let result = result.and_then(|value| sink.commit().map(|()| value));
    if result.is_err() {
        let _ = sink.abort();
    }
    result
}

fn seal_into(
    plan: &ContentPlan,
    source: &mut dyn ContentSource,
    sink: &mut dyn ContentSink,
) -> Result<SealedContent, FileCryptoError> {
    let expected_len = plan.plaintext_len();
    // The AAD binds the first-pass length; a changed length fails the check below.
    let aad = plan.profile().aad(expected_len);
    let mut encryptor = new_encryptor(plan.material());
    let mut output = CiphertextOutput::new(sink);
    let mut buffer = Zeroizing::new([0_u8; MAX_IO_CHUNK_BYTES]);
    let mut block = Zeroizing::new(Vec::with_capacity(BLOCK_BYTES));
    let mut hash = Sha256::new();
    let mut plaintext_len = 0_u64;

    loop {
        let count = read_from(source, &mut buffer[..])?;
        if count == 0 {
            break;
        }
        plaintext_len = plaintext_len
            .checked_add(count as u64)
            .filter(|length| *length <= expected_len)
            .ok_or_else(FileCryptoError::source_changed)?;
        hash.update(&buffer[..count]);

        let mut remaining = &buffer[..count];
        while !remaining.is_empty() {
            // A full block is written only once more bytes arrive: then it is not the last one.
            if block.len() == BLOCK_BYTES {
                let payload = Payload {
                    msg: &block,
                    aad: &aad,
                };
                output.write(
                    &encryptor
                        .encrypt_next(payload)
                        .map_err(|_| FileCryptoError::invalid_state())?,
                )?;
                block.clear();
            }
            let take = remaining.len().min(BLOCK_BYTES - block.len());
            block.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
        }
    }

    // Compare with the first pass before the last block, so incomplete output never commits.
    let mut plaintext_sha256: [u8; 32] = hash.finalize().into();
    let unchanged =
        plaintext_len == expected_len && plaintext_sha256 == *plan.content().plaintext_sha256();
    plaintext_sha256.zeroize();
    if !unchanged {
        return Err(FileCryptoError::source_changed());
    }
    let payload = Payload {
        msg: &block,
        aad: &aad,
    };
    output.write(
        &encryptor
            .encrypt_last(payload)
            .map_err(|_| FileCryptoError::invalid_state())?,
    )?;
    let (ciphertext_len_value, ciphertext_sha256) = output.finish();
    debug_assert_eq!(ciphertext_len(plaintext_len), Some(ciphertext_len_value));
    Ok(SealedContent {
        plaintext_len,
        ciphertext_len: ciphertext_len_value,
        ciphertext_sha256,
    })
}

fn open_into(
    key: &ContentKey,
    source: &mut dyn ContentSource,
    sink: &mut dyn ContentSink,
) -> Result<(), FileCryptoError> {
    let plaintext_len = key.plaintext_len();
    let aad = key.profile.aad(plaintext_len);
    let mut decryptor = new_decryptor(&key.material);
    let mut input = CiphertextInput::new(source);
    let mut frame = vec![0_u8; BLOCK_BYTES + TAG_BYTES];

    // Objects are unframed: block boundaries follow from the plaintext length.
    let full_blocks = plaintext_len.div_ceil(BLOCK_BYTES as u64).max(1) - 1;
    for _ in 0..full_blocks {
        input.read_exact(&mut frame)?;
        let payload = Payload {
            msg: &frame,
            aad: &aad,
        };
        let plaintext = decryptor
            .decrypt_next(payload)
            .map_err(|_| FileCryptoError::integrity_error())?;
        write_plaintext(sink, plaintext)?;
    }
    let last_len = (plaintext_len - full_blocks * BLOCK_BYTES as u64) as usize + TAG_BYTES;
    let last = &mut frame[..last_len];
    input.read_exact(last)?;
    input.expect_eof()?;
    let payload = Payload {
        msg: last,
        aad: &aad,
    };
    let plaintext = decryptor
        .decrypt_last(payload)
        .map_err(|_| FileCryptoError::integrity_error())?;
    write_plaintext(sink, plaintext)?;

    if input.finish() != *key.ciphertext_sha256() {
        return Err(FileCryptoError::integrity_error());
    }
    Ok(())
}

/// V1 ciphertext size for `plaintext_len`, or `None` above the object limit.
pub(crate) fn ciphertext_len(plaintext_len: u64) -> Option<u64> {
    // Empty plaintext still has one (empty) last block; the product cannot overflow.
    let blocks = plaintext_len.div_ceil(BLOCK_BYTES as u64).max(1);
    plaintext_len
        .checked_add(blocks * TAG_BYTES as u64)
        .filter(|length| *length <= MAX_CIPHERTEXT_BYTES_V1)
}

/// Reads one chunk, failing with `Cancelled` if the host cancels before or during the read.
fn read_from(
    source: &mut dyn ContentSource,
    destination: &mut [u8],
) -> Result<usize, FileCryptoError> {
    if source.is_cancelled() {
        return Err(FileCryptoError::cancelled());
    }
    let count = source.read_chunk(destination)?;
    if count > destination.len() {
        return Err(FileCryptoError::invalid_state());
    }
    if source.is_cancelled() {
        return Err(FileCryptoError::cancelled());
    }
    Ok(count)
}

fn write_plaintext(sink: &mut dyn ContentSink, plaintext: Vec<u8>) -> Result<(), FileCryptoError> {
    Zeroizing::new(plaintext)
        .chunks(MAX_IO_CHUNK_BYTES)
        .try_for_each(|chunk| sink.write_chunk(chunk))
}

fn new_encryptor(material: &ContentKeyMaterial) -> EncryptorBE32<XChaCha20Poly1305> {
    let mut key = StreamKey::from(material.dek);
    let encryptor = EncryptorBE32::new(&key, &stream_nonce(material));
    key.zeroize();
    encryptor
}

fn new_decryptor(material: &ContentKeyMaterial) -> DecryptorBE32<XChaCha20Poly1305> {
    let mut key = StreamKey::from(material.dek);
    let decryptor = DecryptorBE32::new(&key, &stream_nonce(material));
    key.zeroize();
    decryptor
}

/// The 19-byte prefix; the library appends the block counter and last-block flag.
fn stream_nonce(material: &ContentKeyMaterial) -> StreamNonce {
    StreamNonce::from(material.nonce_prefix)
}

/// Writes ciphertext to the sink while counting and hashing it.
struct CiphertextOutput<'a> {
    sink: &'a mut dyn ContentSink,
    bytes: u64,
    hash: Sha256,
}

impl<'a> CiphertextOutput<'a> {
    fn new(sink: &'a mut dyn ContentSink) -> Self {
        Self {
            sink,
            bytes: 0,
            hash: Sha256::new(),
        }
    }

    fn write(&mut self, ciphertext: &[u8]) -> Result<(), FileCryptoError> {
        self.bytes += ciphertext.len() as u64;
        self.hash.update(ciphertext);
        ciphertext
            .chunks(MAX_IO_CHUNK_BYTES)
            .try_for_each(|chunk| self.sink.write_chunk(chunk))
    }

    fn finish(self) -> (u64, [u8; 32]) {
        (self.bytes, self.hash.finalize().into())
    }
}

/// Reads ciphertext from the source while hashing it.
struct CiphertextInput<'a> {
    source: &'a mut dyn ContentSource,
    hash: Sha256,
}

impl<'a> CiphertextInput<'a> {
    fn new(source: &'a mut dyn ContentSource) -> Self {
        Self {
            source,
            hash: Sha256::new(),
        }
    }

    fn read(&mut self, destination: &mut [u8]) -> Result<usize, FileCryptoError> {
        let capacity = destination.len().min(MAX_IO_CHUNK_BYTES);
        let count = read_from(&mut *self.source, &mut destination[..capacity])?;
        self.hash.update(&destination[..count]);
        Ok(count)
    }

    fn read_exact(&mut self, mut destination: &mut [u8]) -> Result<(), FileCryptoError> {
        while !destination.is_empty() {
            let count = self.read(destination)?;
            if count == 0 {
                return Err(FileCryptoError::integrity_error());
            }
            destination = &mut destination[count..];
        }
        Ok(())
    }

    fn expect_eof(&mut self) -> Result<(), FileCryptoError> {
        if self.read(&mut [0_u8; 1])? != 0 {
            return Err(FileCryptoError::integrity_error());
        }
        Ok(())
    }

    fn finish(self) -> [u8; 32] {
        self.hash.finalize().into()
    }
}
