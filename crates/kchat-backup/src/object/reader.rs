//! KCBK V1 reader with bounded Zstd and caller-defined payload semantics.
//! Full validation precedes output. A private, bounded frame-digest proof guards
//! the output replay BEFORE each frame reaches the decoder, not merely at EOF.

use aead_stream::{DecryptorBE32, Key, Nonce, StreamBE32, aead::Payload};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    BackupByteSink, BackupByteSource, BackupByteSourceFactory, BackupError, BackupErrorCode,
    BackupObjectContextV1, BackupObjectDescriptor, BackupObjectValidatorV1, BackupPayloadValidator,
    MAX_CIPHERTEXT_OBJECT_BYTES_V1, MAX_COMPRESSED_OBJECT_BYTES_V1,
    MAX_ENCRYPTED_BLOCKS_PER_OBJECT_V1, MAX_IO_CHUNK_BYTES_V1,
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
    authenticate_envelope(context, &mut input, &mut ProofMode::Ignore, &mut |_, _| {
        Ok(())
    })?;
    input.finish()
}

/// Verify, decompress and validate the entire object, then replay its plaintext
/// to `sink`. Requires three opens: ciphertext preflight, full validation, output.
///
/// The semantic validator is part of the trusted validation boundary: it sees
/// tentative plaintext and must not publish it. The sink sees only bytes from a
/// fully validated object. Each replay frame is checked against a private digest
/// recorded during validation BEFORE it can yield output; changed sources cannot
/// substitute a different authenticated plaintext after the validation pass.
///
/// Sink/I/O failure or cancellation during replay may leave a prefix of VALIDATED
/// plaintext in the sink. This is not an atomic import API. Use a fresh staging
/// store and activate it only after this function and the whole restore succeed.
pub fn open_object_v1(
    context: &BackupObjectContextV1,
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
    semantics: &mut dyn BackupPayloadValidator,
    sink: &mut dyn BackupByteSink,
) -> Result<(), BackupError> {
    let proof = BackupObjectValidatorV1::new()
        .validate_with_proof(context, factory, expected, semantics)?;
    process_payload(
        context,
        factory,
        expected,
        &mut ProofMode::Check(&proof),
        &mut |bytes| sink.write_chunk(bytes),
    )
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

/// Only a successful full validation may hand this to the output pass. No public
/// constructor/token API: proof, context and inventory stay within one operation.
/// At most 4,096 SHA-256 digests (128 KiB) plus the exact 29-byte header are held.
pub(super) struct ReplayProof {
    header: [u8; ENVELOPE_HEADER_BYTES],
    frames: Vec<[u8; 32]>,
}

enum ProofMode<'a> {
    Ignore,
    Record(&'a mut ReplayProof),
    Check(&'a ReplayProof),
}
impl ProofMode<'_> {
    fn header(&mut self, header: &[u8; ENVELOPE_HEADER_BYTES]) -> Result<(), BackupError> {
        match self {
            Self::Record(proof) => proof.header = *header,
            Self::Check(proof) if &proof.header != header => {
                return Err(BackupError::from_code(BackupErrorCode::IntegrityMismatch));
            }
            _ => {}
        }
        Ok(())
    }
    fn frame(&mut self, index: usize, bytes: &[u8], final_block: bool) -> Result<(), BackupError> {
        if matches!(self, Self::Ignore) {
            return Ok(());
        }
        let mut hash = Sha256::new();
        hash.update((bytes.len() as u32).to_be_bytes());
        hash.update(bytes);
        hash.update([u8::from(final_block)]);
        let digest: [u8; 32] = hash.finalize().into();
        match self {
            Self::Record(proof) => proof.frames.push(digest),
            Self::Check(proof) => {
                if proof.frames.get(index) != Some(&digest)
                    || (final_block && index + 1 != proof.frames.len())
                {
                    return Err(BackupError::from_code(BackupErrorCode::IntegrityMismatch));
                }
            }
            Self::Ignore => {}
        }
        Ok(())
    }
}

pub(super) fn validate_payload_v1(
    context: &BackupObjectContextV1,
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
    semantics: &mut dyn BackupPayloadValidator,
) -> Result<ReplayProof, BackupError> {
    preflight(factory, expected)?;
    let mut proof = ReplayProof {
        header: [0; ENVELOPE_HEADER_BYTES],
        frames: Vec::with_capacity(MAX_ENCRYPTED_BLOCKS_PER_OBJECT_V1 as usize),
    };
    process_payload(
        context,
        factory,
        expected,
        &mut ProofMode::Record(&mut proof),
        &mut |bytes| semantics.validate_chunk(bytes),
    )?;
    check_factory_cancelled(factory)?;
    // EOF semantic checks (missing records, unresolved references, incomplete
    // parser state) are mandatory, even for empty plaintext. They run once only
    // after envelope, Zstd completion and inventory integrity have all succeeded.
    semantics.finish()?;
    check_factory_cancelled(factory)?;
    Ok(proof)
}

fn process_payload(
    context: &BackupObjectContextV1,
    factory: &mut dyn BackupByteSourceFactory,
    expected: &ExpectedBackupObjectV1,
    proof: &mut ProofMode<'_>,
    emit: &mut dyn FnMut(&[u8]) -> Result<(), BackupError>,
) -> Result<(), BackupError> {
    let mut input = CheckedSource::open(factory, expected)?;
    let mut decoder = BoundedDecoder::new()?;
    authenticate_envelope(context, &mut input, proof, &mut |bytes, cancelled| {
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
    proof: &mut ProofMode<'_>,
    consume: &mut CompressedConsumer<'_>,
) -> Result<(), BackupError> {
    let mut header = [0; ENVELOPE_HEADER_BYTES];
    input.read_exact(&mut header)?;
    proof.header(&header)?;
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
        // Check before decryption/decoding on output replay. Include FINAL in the
        // digest so a shortened/extended stream cannot masquerade as the original.
        proof.frame((blocks - 1) as usize, &frame[..length], next.is_none())?;
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

#[cfg(test)]
mod tests {
    use super::super::envelope::serialize_header;
    use super::*;
    use crate::{BackupAccountId, BackupChunkId, BackupId, MnemonicBackupKey};
    use aead_stream::EncryptorBE32;

    struct Source(std::io::Cursor<Vec<u8>>);
    impl BackupByteSource for Source {
        fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError> {
            std::io::Read::read(&mut self.0, destination).map_err(|_| BackupError::io_error())
        }
    }
    struct Factory(Vec<u8>);
    impl BackupByteSourceFactory for Factory {
        fn open(&mut self) -> Result<Box<dyn BackupByteSource>, BackupError> {
            Ok(Box::new(Source(std::io::Cursor::new(self.0.clone()))))
        }
    }

    #[test]
    fn authenticates_tag_only_final_without_claiming_payload_validity() {
        struct NeverCalled;
        impl BackupPayloadValidator for NeverCalled {
            fn validate_chunk(&mut self, _: &[u8]) -> Result<(), BackupError> {
                panic!("invalid Zstd must not yield plaintext")
            }
            fn finish(&mut self) -> Result<(), BackupError> {
                panic!("invalid Zstd must not finish semantics")
            }
        }
        let master = MnemonicBackupKey::import_from_raw(&[3; 32]).unwrap();
        let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let namespace = BackupId::derive(&master, &account).unwrap();
        let context = BackupObjectContextV1::new(
            &master,
            account,
            namespace,
            1,
            BackupChunkId::from_bytes([7; 16]).unwrap(),
        )
        .unwrap();
        let key = Key::<XChaCha20Poly1305>::try_from(context.object_key().as_slice()).unwrap();
        let prefix = [42; 19]; // Fixed test-only nonce; never use this in production.
        let nonce =
            Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::try_from(prefix.as_slice())
                .unwrap();
        let tag = EncryptorBE32::<XChaCha20Poly1305>::new(&key, &nonce)
            .encrypt_last(Payload {
                msg: &[],
                aad: context.canonical_bytes(),
            })
            .unwrap();
        assert_eq!(tag.len(), 16);
        let mut bytes = serialize_header(&prefix).to_vec();
        bytes.extend_from_slice(&16_u32.to_be_bytes());
        bytes.extend_from_slice(&tag);
        let expected =
            ExpectedBackupObjectV1::new(bytes.len() as u64, Sha256::digest(&bytes).into(), 1)
                .unwrap();
        let mut factory = Factory(bytes);
        verify_object_envelope_v1(&context, &mut factory, &expected).unwrap();
        // This envelope authenticates, but contains no Zstd stream whatsoever.
        // A full validator must never report it as a restorable backup.
        assert_eq!(
            BackupObjectValidatorV1::new()
                .validate(&context, &mut factory, &expected, &mut NeverCalled)
                .unwrap_err()
                .code(),
            BackupErrorCode::InvalidCompressedData
        );
    }

    #[test]
    fn compressed_limit_rejects_overflow_without_large_allocations() {
        let mut total = MAX_COMPRESSED_OBJECT_BYTES_V1 - 1;
        count_compressed(&mut total, 1).unwrap();
        assert_eq!(
            count_compressed(&mut total, 1).unwrap_err().code(),
            BackupErrorCode::ResourceLimitExceeded
        );
        let mut total = u64::MAX;
        assert_eq!(
            count_compressed(&mut total, 1).unwrap_err().code(),
            BackupErrorCode::ResourceLimitExceeded
        );
    }

    #[test]
    fn authenticated_invalid_compression_never_reaches_output() {
        // Generate valid AEAD around deliberately invalid compression. Merely
        // flipping ciphertext would only exercise AEAD, not the decoder boundary.
        use std::io::Write;
        let master = MnemonicBackupKey::import_from_raw(&[3; 32]).unwrap();
        let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let namespace = BackupId::derive(&master, &account).unwrap();
        let context = BackupObjectContextV1::new(
            &master,
            account,
            namespace,
            1,
            BackupChunkId::from_bytes([7; 16]).unwrap(),
        )
        .unwrap();
        let key = Key::<XChaCha20Poly1305>::try_from(context.object_key().as_slice()).unwrap();
        let valid = zstd::stream::encode_all(&b"some plaintext"[..], 3).unwrap();
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut concatenated = valid.clone();
        concatenated.extend_from_slice(&valid);
        let mut checksummed = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        checksummed.include_checksum(true).unwrap();
        checksummed.write_all(b"some plaintext").unwrap();
        let mut checksummed = checksummed.finish().unwrap();
        *checksummed.last_mut().unwrap() ^= 1;
        let cases = [
            vec![],
            b"not zstd".to_vec(),
            valid[..valid.len() - 1].to_vec(),
            trailing,
            concatenated,
            checksummed,
            vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
            vec![0x28, 0xb5, 0x2f, 0xfd, 1, 0, 1],
            vec![0x28, 0xb5, 0x2f, 0xfd, 0, 14 << 3],
        ];
        struct Policy {
            finished: bool,
        }
        impl BackupPayloadValidator for Policy {
            fn validate_chunk(&mut self, _: &[u8]) -> Result<(), BackupError> {
                Ok(())
            }
            fn finish(&mut self) -> Result<(), BackupError> {
                self.finished = true;
                Ok(())
            }
        }
        struct NoOutput;
        impl BackupByteSink for NoOutput {
            fn write_chunk(&mut self, _: &[u8]) -> Result<(), BackupError> {
                panic!("unvalidated output")
            }
        }
        for (index, compressed) in cases.iter().enumerate() {
            let prefix = [index as u8; 19]; // Unique deterministic test-only prefixes.
            let nonce = Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::try_from(
                prefix.as_slice(),
            )
            .unwrap();
            let ciphertext = EncryptorBE32::<XChaCha20Poly1305>::new(&key, &nonce)
                .encrypt_last(Payload {
                    msg: compressed,
                    aad: context.canonical_bytes(),
                })
                .unwrap();
            let mut bytes = serialize_header(&prefix).to_vec();
            bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&ciphertext);
            let expected =
                ExpectedBackupObjectV1::new(bytes.len() as u64, Sha256::digest(&bytes).into(), 1)
                    .unwrap();
            let mut factory = Factory(bytes);
            verify_object_envelope_v1(&context, &mut factory, &expected).unwrap();
            let mut policy = Policy { finished: false };
            let error = open_object_v1(
                &context,
                &mut factory,
                &expected,
                &mut policy,
                &mut NoOutput,
            )
            .unwrap_err();
            assert!(matches!(
                error.code(),
                BackupErrorCode::InvalidCompressedData | BackupErrorCode::ResourceLimitExceeded
            ));
            assert!(!policy.finished);
        }
    }
}
