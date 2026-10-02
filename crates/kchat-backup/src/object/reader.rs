//! KCBK V1 reader with bounded Zstd and opaque payloads.
//! A ciphertext preflight precedes one decryption/decompression pass. Output is
//! provisional until the final integrity and decompression checks succeed.

use aead_stream::{DecryptorBE32, Key, Nonce, StreamBE32, aead::Payload};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    BackupByteSink, BackupByteSource, BackupByteSourceFactory, BackupError, BackupErrorCode,
    BackupObjectContextV1, BackupObjectDescriptor, MAX_CIPHERTEXT_OBJECT_BYTES_V1,
    MAX_COMPRESSED_OBJECT_BYTES_V1, MAX_ENCRYPTED_BLOCKS_PER_OBJECT_V1, MAX_IO_CHUNK_BYTES_V1,
};

use super::compression::BoundedDecoder;
use super::envelope::{
    AEAD_TAG_BYTES, COMPRESSED_BLOCK_BYTES, ENVELOPE_HEADER_BYTES, ENVELOPE_VERSION, parse_header,
};

/// Expected transport metadata from a fixed committed inventory entry.
///
/// Keep this distinct from `BackupObjectDescriptor`, which is produced by the
/// writer. A valid constructor only validates arguments, not object contents.
/// Identity comes from the separately constructed `BackupObjectContextV1`.
/// Generation/storage-version pinning remains the factory/caller's responsibility.
#[derive(Clone, Copy)]
pub struct ExpectedBackupObjectV1 {
    ciphertext_size: u64,
    ciphertext_sha256: [u8; 32],
}

impl ExpectedBackupObjectV1 {
    pub fn new(
        ciphertext_size: u64,
        ciphertext_sha256: [u8; 32],
        format_version: u16,
    ) -> Result<Self, BackupError> {
        if format_version != ENVELOPE_VERSION {
            return Err(BackupError::unsupported_format());
        }
        if ciphertext_size > MAX_CIPHERTEXT_OBJECT_BYTES_V1 {
            return Err(BackupError::resource_limit_exceeded());
        }
        // Even an envelope with an empty FINAL needs header + length + tag.
        if ciphertext_size < (ENVELOPE_HEADER_BYTES + 4 + AEAD_TAG_BYTES) as u64 {
            return Err(BackupError::invalid_argument());
        }
        Ok(Self {
            ciphertext_size,
            ciphertext_sha256,
        })
    }
}

impl From<BackupObjectDescriptor> for ExpectedBackupObjectV1 {
    fn from(descriptor: BackupObjectDescriptor) -> Self {
        Self {
            ciphertext_size: descriptor.ciphertext_size(),
            ciphertext_sha256: *descriptor.ciphertext_sha256(),
        }
    }
}

/// Verify only transport integrity and the encrypted envelope; discard the
/// authenticated compressed bytes. Success does NOT validate Zstd or records.
///
/// Pass 1: hash/count ciphertext to exact EOF before doing any decryption.
/// Pass 2: reopen, authenticate all blocks and recheck the same hash/count.
/// SHA-256 is an inventory comparison, not a keyed authenticity check. AEAD is
/// still required even if an attacker can replace both the bytes and their hash.
pub fn verify_object_envelope_v1(
    context: &BackupObjectContextV1,
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
) -> Result<(), BackupError> {
    preflight(factory, expected)?;
    let mut input = CheckedSource::open(factory, expected)?;
    authenticate_envelope(context, &mut input, &mut |_, _| Ok(()))?;
    input.finish()
}

/// Preflight ciphertext integrity, then decrypt/decompress opaque plaintext into
/// `sink` in one pass. No payload schema is interpreted or validated.
/// Requires two opens: ciphertext preflight, then streaming verification/output.
/// Each frame must pass AEAD authentication before decompression and output.
///
/// Output is provisional until this function returns `Ok(())`: a changed source,
/// late authentication/decompression/integrity error, I/O failure or cancellation
/// can leave bytes in the sink, including bytes from a different valid object.
/// Write to fresh staging, discard it on any error, and activate it only after
/// this function and the whole restore succeed. Writes are not atomic.
pub fn open_object_v1(
    context: &BackupObjectContextV1,
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
    sink: &mut dyn BackupByteSink,
) -> Result<(), BackupError> {
    preflight(factory, expected)?;
    process_payload(context, factory, expected, &mut |bytes| {
        sink.write_chunk(bytes)
    })
}

fn preflight(
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
) -> Result<(), BackupError> {
    let mut input = CheckedSource::open(factory, expected)?;
    let mut buffer = [0; MAX_IO_CHUNK_BYTES_V1];
    while input.read(&mut buffer)? != 0 {}
    input.finish()
}

pub(super) fn validate_payload_v1(
    context: &BackupObjectContextV1,
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
) -> Result<(), BackupError> {
    preflight(factory, expected)?;
    process_payload(context, factory, expected, &mut |_| Ok(()))?;
    check_factory_cancelled(factory)
}

fn process_payload(
    context: &BackupObjectContextV1,
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
    emit: &mut dyn FnMut(&[u8]) -> Result<(), BackupError>,
) -> Result<(), BackupError> {
    let mut input = CheckedSource::open(factory, expected)?;
    let mut decoder = BoundedDecoder::new()?;
    authenticate_envelope(context, &mut input, &mut |bytes, cancelled| {
        decoder.push(bytes, emit, cancelled)
    })?;
    input.finish()?;
    decoder.finish()
}

fn check_factory_cancelled(factory: &dyn BackupByteSourceFactory) -> Result<(), BackupError> {
    if factory.is_cancelled() {
        Err(BackupError::cancelled())
    } else {
        Ok(())
    }
}

/// Counts/hashes every byte actually consumed, including the header and lengths.
/// Never allocate based on an untrusted wire length. Probe one byte beyond the
/// expected size so `take(expected_size)` cannot hide trailing data.
struct CheckedSource<'a> {
    source: Box<dyn BackupByteSource>,
    factory: &'a dyn BackupByteSourceFactory,
    expected: &'a ExpectedBackupObjectV1,
    bytes: u64,
    hash: Sha256,
    eof: bool,
}

impl<'a> CheckedSource<'a> {
    fn open(
        factory: &'a mut dyn BackupByteSourceFactory,
        expected: &'a ExpectedBackupObjectV1,
    ) -> Result<Self, BackupError> {
        if factory.is_cancelled() {
            return Err(BackupError::cancelled());
        }
        let source = factory.open()?;
        let input = Self {
            source,
            factory,
            expected,
            bytes: 0,
            hash: Sha256::new(),
            eof: false,
        };
        input.check_cancelled()?;
        Ok(input)
    }

    fn check_cancelled(&self) -> Result<(), BackupError> {
        if self.factory.is_cancelled() || self.source.is_cancelled() {
            Err(BackupError::cancelled())
        } else {
            Ok(())
        }
    }

    fn read(&mut self, destination: &mut [u8]) -> Result<usize, BackupError> {
        self.check_cancelled()?;
        if self.eof || destination.is_empty() {
            return Ok(0);
        }
        let remaining_with_probe = (self.expected.ciphertext_size - self.bytes + 1) as usize;
        let capacity = destination
            .len()
            .min(MAX_IO_CHUNK_BYTES_V1)
            .min(remaining_with_probe);
        let count = self.source.read_chunk(&mut destination[..capacity])?;
        self.check_cancelled()?;
        if count > capacity {
            return Err(BackupError::invalid_state());
        }
        self.bytes += count as u64;
        if self.bytes > self.expected.ciphertext_size {
            return Err(BackupError::from_code(BackupErrorCode::IntegrityMismatch));
        }
        self.hash.update(&destination[..count]);
        self.eof = count == 0;
        Ok(count)
    }

    fn read_exact(&mut self, mut destination: &mut [u8]) -> Result<(), BackupError> {
        while !destination.is_empty() {
            let count = self.read(destination)?;
            if count == 0 {
                return Err(BackupError::from_code(BackupErrorCode::MalformedObject));
            }
            destination = &mut destination[count..];
        }
        Ok(())
    }

    /// Zero bytes at a frame boundary means EOF. One to three bytes of a length
    /// means truncation, never EOF. Short callback reads do not imply truncation.
    fn next_length(&mut self) -> Result<Option<usize>, BackupError> {
        let mut length = [0; 4];
        if self.read(&mut length[..1])? == 0 {
            return Ok(None);
        }
        self.read_exact(&mut length[1..])?;
        let length = u32::from_be_bytes(length) as usize;
        if !(AEAD_TAG_BYTES..=COMPRESSED_BLOCK_BYTES + AEAD_TAG_BYTES).contains(&length) {
            return Err(BackupError::from_code(BackupErrorCode::MalformedObject));
        }
        Ok(Some(length))
    }

    fn finish(self) -> Result<(), BackupError> {
        self.check_cancelled()?;
        if !self.eof || self.bytes != self.expected.ciphertext_size {
            return Err(BackupError::from_code(BackupErrorCode::IntegrityMismatch));
        }
        let digest: [u8; 32] = self.hash.finalize().into();
        // These hashes are public inventory metadata, not secret authenticators.
        if digest != self.expected.ciphertext_sha256 {
            return Err(BackupError::from_code(BackupErrorCode::IntegrityMismatch));
        }
        Ok(())
    }
}

type CompressedConsumer<'a> =
    dyn FnMut(&[u8], &dyn Fn() -> Result<(), BackupError>) -> Result<(), BackupError> + 'a;

fn authenticate_envelope(
    context: &BackupObjectContextV1,
    input: &mut CheckedSource<'_>,
    consume: &mut CompressedConsumer<'_>,
) -> Result<(), BackupError> {
    let mut header = [0; ENVELOPE_HEADER_BYTES];
    input.read_exact(&mut header)?;
    let prefix = parse_header(&header)?;
    let mut key = Key::<XChaCha20Poly1305>::try_from(context.object_key().as_slice())
        .map_err(|_| BackupError::invalid_state())?;
    let nonce =
        Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::try_from(prefix.as_slice())
            .map_err(|_| BackupError::invalid_state())?;
    let mut decryptor = DecryptorBE32::<XChaCha20Poly1305>::new(&key, &nonce);
    key.zeroize();

    let mut length = input
        .next_length()?
        .ok_or_else(|| BackupError::from_code(BackupErrorCode::MalformedObject))?;
    // One bounded ciphertext frame, one library-produced plaintext block, and
    // a 4-byte lookahead. Never buffer the entire compressed or plaintext object.
    let mut frame = vec![0; COMPRESSED_BLOCK_BYTES + AEAD_TAG_BYTES];
    let mut blocks = 0_u64;
    let mut compressed_bytes = 0_u64;
    loop {
        blocks += 1;
        if blocks > MAX_ENCRYPTED_BLOCKS_PER_OBJECT_V1 {
            return Err(BackupError::resource_limit_exceeded());
        }
        input.read_exact(&mut frame[..length])?;
        let next = input.next_length()?;
        // NEXT/FINAL is implicit in the STREAM nonce. EOF only identifies a
        // final CANDIDATE; decrypt_last must authenticate the final flag as well.
        // Cutting at a NEXT boundary or appending after FINAL fails authentication.
        if next.is_some() && length != COMPRESSED_BLOCK_BYTES + AEAD_TAG_BYTES {
            return Err(BackupError::from_code(BackupErrorCode::MalformedObject));
        }
        let payload = Payload {
            msg: &frame[..length],
            aad: context.canonical_bytes(),
        };
        let decrypted = match next {
            Some(_) => decryptor.decrypt_next(payload),
            None => {
                let decrypted = decryptor
                    .decrypt_last(payload)
                    .map_err(|_| BackupError::authentication_failed())?;
                let decrypted = Zeroizing::new(decrypted);
                count_compressed(&mut compressed_bytes, decrypted.len())?;
                input.check_cancelled()?;
                consume(&decrypted, &|| input.check_cancelled())?;
                return Ok(());
            }
        }
        .map_err(|_| BackupError::authentication_failed())?;
        let decrypted = Zeroizing::new(decrypted);
        count_compressed(&mut compressed_bytes, decrypted.len())?;
        input.check_cancelled()?;
        consume(&decrypted, &|| input.check_cancelled())?;
        length = next.ok_or_else(BackupError::invalid_state)?;
    }
}

fn count_compressed(total: &mut u64, added: usize) -> Result<(), BackupError> {
    *total = total
        .checked_add(added as u64)
        .filter(|value| *value <= MAX_COMPRESSED_OBJECT_BYTES_V1)
        .ok_or_else(BackupError::resource_limit_exceeded)?;
    Ok(())
}
