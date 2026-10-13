use std::io::{self, Write};

use aead_stream::{EncryptorBE32, Key, Nonce, StreamBE32, aead::Payload};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    BackupByteSink, BackupByteSource, BackupError, BackupErrorCode, BackupObjectContextV1,
    MAX_CIPHERTEXT_OBJECT_BYTES_V1, MAX_COMPRESSED_OBJECT_BYTES_V1,
    MAX_ENCRYPTED_BLOCKS_PER_OBJECT_V1, MAX_IO_CHUNK_BYTES_V1, MAX_PLAINTEXT_OBJECT_BYTES_V1,
};

use super::envelope::{
    AEAD_TAG_BYTES, COMPRESSED_BLOCK_BYTES, ENVELOPE_VERSION, STREAM_NONCE_PREFIX_BYTES,
    serialize_header,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupObjectDescriptor {
    ciphertext_size: u64,
    ciphertext_sha256: [u8; 32],
    format_version: u16,
}

impl BackupObjectDescriptor {
    pub const fn ciphertext_size(&self) -> u64 {
        self.ciphertext_size
    }

    pub const fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.ciphertext_sha256
    }

    pub const fn format_version(&self) -> u16 {
        self.format_version
    }
}

/// Seals one opaque caller-owned object and returns metadata only after its final STREAM block.
pub fn seal_object_v1(
    context: &BackupObjectContextV1,
    source: &mut dyn BackupByteSource,
    sink: &mut dyn BackupByteSink,
) -> Result<BackupObjectDescriptor, BackupError> {
    if source.is_cancelled() {
        return Err(BackupError::cancelled());
    }
    let mut writer = BackupObjectWriterV1::new(context, sink)?;
    let mut source_buffer = Zeroizing::new([0_u8; MAX_IO_CHUNK_BYTES_V1]);
    loop {
        if source.is_cancelled() {
            let _ = writer.abort();
            return Err(BackupError::cancelled());
        }
        let count = source.read_chunk(source_buffer.as_mut())?;
        if count > source_buffer.len() {
            return Err(BackupError::invalid_state());
        }
        if count == 0 {
            break;
        }
        if source.is_cancelled() {
            let _ = writer.abort();
            return Err(BackupError::cancelled());
        }
        writer.write_plaintext(&source_buffer[..count])?;
    }
    if source.is_cancelled() {
        let _ = writer.abort();
        return Err(BackupError::cancelled());
    }
    writer.finish()
}

pub struct BackupObjectWriterV1<'a> {
    active: Option<ActiveWriter<'a>>,
    terminal: WriterTerminal,
}

struct ActiveWriter<'a> {
    encoder: zstd::stream::write::Encoder<'static, EnvelopeWriter<'a>>,
    plaintext_bytes: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WriterTerminal {
    Active,
    Finished,
    Aborted,
    Failed,
}

impl<'a> BackupObjectWriterV1<'a> {
    pub fn new(
        context: &'a BackupObjectContextV1,
        sink: &'a mut dyn BackupByteSink,
    ) -> Result<Self, BackupError> {
        let mut nonce_prefix = [0_u8; STREAM_NONCE_PREFIX_BYTES];
        getrandom::fill(&mut nonce_prefix).map_err(|_| BackupError::io_error())?;
        let envelope = EnvelopeWriter::new(context, sink, nonce_prefix)?;
        nonce_prefix.zeroize();
        let encoder =
            zstd::stream::write::Encoder::new(envelope, 3).map_err(|_| BackupError::io_error())?;
        Ok(Self {
            active: Some(ActiveWriter {
                encoder,
                plaintext_bytes: 0,
            }),
            terminal: WriterTerminal::Active,
        })
    }

    pub fn write_plaintext(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        if self.terminal != WriterTerminal::Active {
            return Err(BackupError::invalid_state());
        }
        let result = {
            let active = self
                .active
                .as_mut()
                .ok_or_else(BackupError::invalid_state)?;
            match checked_add_limited(
                active.plaintext_bytes,
                bytes.len() as u64,
                MAX_PLAINTEXT_OBJECT_BYTES_V1,
            ) {
                Err(error) => Err(error),
                Ok(plaintext_bytes) => {
                    active.plaintext_bytes = plaintext_bytes;
                    if active.encoder.write_all(bytes).is_err() {
                        Err(active
                            .encoder
                            .get_mut()
                            .take_failure()
                            .unwrap_or_else(BackupError::io_error))
                    } else {
                        Ok(())
                    }
                }
            }
        };
        if result.is_err() {
            self.active.take();
            self.terminal = WriterTerminal::Failed;
        }
        result
    }

    pub fn finish(&mut self) -> Result<BackupObjectDescriptor, BackupError> {
        if self.terminal != WriterTerminal::Active {
            return Err(BackupError::invalid_state());
        }
        let active = self.active.take().ok_or_else(BackupError::invalid_state)?;
        let envelope = match active.encoder.try_finish() {
            Ok(envelope) => envelope,
            Err((mut encoder, _)) => {
                self.terminal = WriterTerminal::Failed;
                return Err(encoder
                    .get_mut()
                    .take_failure()
                    .unwrap_or_else(BackupError::io_error));
            }
        };
        match envelope.finish() {
            Ok(descriptor) => {
                self.terminal = WriterTerminal::Finished;
                Ok(descriptor)
            }
            Err(error) => {
                self.terminal = WriterTerminal::Failed;
                Err(error)
            }
        }
    }

    pub fn abort(&mut self) -> Result<(), BackupError> {
        if self.terminal != WriterTerminal::Active {
            return Err(BackupError::invalid_state());
        }
        self.active.take();
        self.terminal = WriterTerminal::Aborted;
        Ok(())
    }
}

struct EnvelopeWriter<'a> {
    sink: &'a mut dyn BackupByteSink,
    encryptor: Option<EncryptorBE32<XChaCha20Poly1305>>,
    canonical_context: &'a [u8],
    pending: Vec<u8>,
    compressed_bytes: u64,
    ciphertext_bytes: u64,
    block_count: u64,
    hash: Sha256,
    failure: Option<BackupErrorCode>,
}

impl<'a> EnvelopeWriter<'a> {
    fn new(
        context: &'a BackupObjectContextV1,
        sink: &'a mut dyn BackupByteSink,
        nonce_prefix: [u8; STREAM_NONCE_PREFIX_BYTES],
    ) -> Result<Self, BackupError> {
        let mut key = Key::<XChaCha20Poly1305>::try_from(context.object_key().as_slice())
            .map_err(|_| BackupError::invalid_state())?;
        let nonce = Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::try_from(
            nonce_prefix.as_slice(),
        )
        .map_err(|_| BackupError::invalid_state())?;
        let mut writer = Self {
            sink,
            encryptor: Some(EncryptorBE32::new(&key, &nonce)),
            canonical_context: context.canonical_bytes(),
            pending: Vec::with_capacity(COMPRESSED_BLOCK_BYTES),
            compressed_bytes: 0,
            ciphertext_bytes: 0,
            block_count: 0,
            hash: Sha256::new(),
            failure: None,
        };
        key.zeroize();
        writer.write_envelope_bytes(&serialize_header(&nonce_prefix))?;
        Ok(writer)
    }

    fn finish(mut self) -> Result<BackupObjectDescriptor, BackupError> {
        let encryptor = self
            .encryptor
            .take()
            .ok_or_else(BackupError::invalid_state)?;
        let mut pending = core::mem::take(&mut self.pending);
        let ciphertext = encryptor
            .encrypt_last(Payload {
                msg: &pending,
                aad: self.canonical_context,
            })
            .map_err(|_| BackupError::invalid_state())?;
        pending.zeroize();
        self.write_encrypted_block(&ciphertext)?;
        let digest = self.hash.finalize_reset();
        let mut ciphertext_sha256 = [0_u8; 32];
        ciphertext_sha256.copy_from_slice(&digest);
        Ok(BackupObjectDescriptor {
            ciphertext_size: self.ciphertext_bytes,
            ciphertext_sha256,
            format_version: ENVELOPE_VERSION,
        })
    }

    fn write_compressed(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        self.compressed_bytes = checked_add_limited(
            self.compressed_bytes,
            bytes.len() as u64,
            MAX_COMPRESSED_OBJECT_BYTES_V1,
        )?;
        self.pending.extend_from_slice(bytes);
        while self.pending.len() >= COMPRESSED_BLOCK_BYTES {
            let remainder = self.pending.split_off(COMPRESSED_BLOCK_BYTES);
            let mut block = core::mem::replace(&mut self.pending, remainder);
            let ciphertext = self
                .encryptor
                .as_mut()
                .ok_or_else(BackupError::invalid_state)?
                .encrypt_next(Payload {
                    msg: &block,
                    aad: self.canonical_context,
                })
                .map_err(|_| BackupError::invalid_state())?;
            block.zeroize();
            self.write_encrypted_block(&ciphertext)?;
        }
        Ok(())
    }

    fn write_encrypted_block(&mut self, ciphertext: &[u8]) -> Result<(), BackupError> {
        if ciphertext.len() < AEAD_TAG_BYTES
            || ciphertext.len() > COMPRESSED_BLOCK_BYTES + AEAD_TAG_BYTES
        {
            return Err(BackupError::invalid_state());
        }
        self.block_count =
            checked_add_limited(self.block_count, 1, MAX_ENCRYPTED_BLOCKS_PER_OBJECT_V1)?;
        let length = u32::try_from(ciphertext.len()).map_err(|_| BackupError::invalid_state())?;
        self.write_envelope_bytes(&length.to_be_bytes())?;
        self.write_envelope_bytes(ciphertext)
    }

    fn write_envelope_bytes(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        self.ciphertext_bytes = checked_add_limited(
            self.ciphertext_bytes,
            bytes.len() as u64,
            MAX_CIPHERTEXT_OBJECT_BYTES_V1,
        )?;
        self.hash.update(bytes);
        for chunk in bytes.chunks(MAX_IO_CHUNK_BYTES_V1) {
            self.sink.write_chunk(chunk)?;
        }
        Ok(())
    }

    fn take_failure(&mut self) -> Option<BackupError> {
        self.failure.take().map(BackupError::from_code)
    }
}

impl Write for EnvelopeWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Err(error) = self.write_compressed(bytes) {
            self.failure = Some(error.code());
            return Err(io::Error::other("backup envelope write failed"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EnvelopeWriter<'_> {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

fn checked_add_limited(current: u64, added: u64, maximum: u64) -> Result<u64, BackupError> {
    current
        .checked_add(added)
        .filter(|total| *total <= maximum)
        .ok_or_else(BackupError::resource_limit_exceeded)
}
