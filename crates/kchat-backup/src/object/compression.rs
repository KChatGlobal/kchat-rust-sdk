//! Strict single-frame Zstd decoding. Envelope/AEAD validity alone is insufficient:
//! this layer also requires a complete standard frame and no dictionary, second
//! frame, skippable frame or trailing bytes. It accepts the existing V1 writer.

use crate::{
    BackupError, BackupErrorCode, MAX_IO_CHUNK_BYTES_V1, MAX_PLAINTEXT_OBJECT_BYTES_V1,
    MAX_ZSTD_WINDOW_BYTES_V1,
};
use zeroize::Zeroizing;
use zstd::stream::raw::{DParameter, Decoder, Operation};

pub(super) struct BoundedDecoder {
    decoder: Decoder<'static>,
    header: Vec<u8>,
    header_checked: bool,
    complete: bool,
    total: u64,
    limit: u64,
    output: Zeroizing<Vec<u8>>,
}

fn invalid() -> BackupError {
    BackupError::from_code(BackupErrorCode::InvalidCompressedData)
}

impl BoundedDecoder {
    pub(super) fn new() -> Result<Self, BackupError> {
        let mut decoder = Decoder::new().map_err(|_| BackupError::io_error())?;
        // Set BEFORE processing input: do not let the library allocate an
        // attacker-requested large history window and only check afterwards.
        decoder
            .set_parameter(DParameter::WindowLogMax(MAX_ZSTD_WINDOW_BYTES_V1.ilog2()))
            .map_err(|_| BackupError::invalid_state())?;
        Ok(Self {
            decoder,
            header: Vec::with_capacity(14),
            header_checked: false,
            complete: false,
            total: 0,
            limit: MAX_PLAINTEXT_OBJECT_BYTES_V1,
            output: Zeroizing::new(vec![0; MAX_IO_CHUNK_BYTES_V1]),
        })
    }

    /// `emit` belongs to a trusted validator, or to the output pass AFTER full
    /// validation. It must consume the borrowed slice synchronously. Cancellation
    /// is checked on every decoder iteration, even for highly compressible input.
    pub(super) fn push(
        &mut self,
        mut bytes: &[u8],
        emit: &mut dyn FnMut(&[u8]) -> Result<(), BackupError>,
        cancelled: &dyn Fn() -> Result<(), BackupError>,
    ) -> Result<(), BackupError> {
        while !self.header_checked && !bytes.is_empty() {
            self.header.push(bytes[0]);
            bytes = &bytes[1..];
            if check_header(&self.header)? {
                self.header_checked = true;
                let header = core::mem::take(&mut self.header);
                self.decode(&header, emit, cancelled)?;
            }
        }
        if self.header_checked {
            self.decode(bytes, emit, cancelled)?;
        }
        Ok(())
    }

    fn decode(
        &mut self,
        mut bytes: &[u8],
        emit: &mut dyn FnMut(&[u8]) -> Result<(), BackupError>,
        cancelled: &dyn Fn() -> Result<(), BackupError>,
    ) -> Result<(), BackupError> {
        if self.complete {
            return if bytes.is_empty() {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        loop {
            cancelled()?;
            // Allow a one-byte probe over the remaining quota to distinguish
            // an exact-limit frame from a bomb. Never forward the excess byte.
            let capacity = self
                .output
                .len()
                .min((self.limit - self.total + 1) as usize);
            let status = self
                .decoder
                .run_on_buffers(bytes, &mut self.output[..capacity])
                .map_err(|_| invalid())?;
            self.total = self
                .total
                .checked_add(status.bytes_written as u64)
                .filter(|&n| n <= self.limit)
                .ok_or_else(BackupError::resource_limit_exceeded)?;
            cancelled()?;
            if status.bytes_written != 0 {
                emit(&self.output[..status.bytes_written])?;
            }
            cancelled()?;
            bytes = &bytes[status.bytes_read..];
            if status.remaining == 0 {
                self.complete = true;
                return if bytes.is_empty() {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
            if status.bytes_read == 0 && status.bytes_written == 0 {
                return if bytes.is_empty() {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
            // Empty input may still flush a full decoder output buffer. Keep
            // draining until no progress; finish() will require frame completion.
        }
    }

    pub(super) fn finish(&self) -> Result<(), BackupError> {
        if self.header_checked && self.complete {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

/// Inspect the small standard Zstd header before the decoder sees it. The window
/// descriptor covers non-single-segment frames; single-segment frames use the
/// content size as their window. This also rejects large known plaintext sizes
/// early. The decoder remains responsible for actual blocks/checksum validation.
fn check_header(header: &[u8]) -> Result<bool, BackupError> {
    if header.len() < 5 {
        return Ok(false);
    }
    if header[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(invalid());
    }
    let descriptor = header[4];
    if descriptor & 0x1b != 0 {
        return Err(invalid());
    } // reserved/unused bits + dictionary flag
    let single = descriptor & 0x20 != 0;
    let size_bytes = match descriptor >> 6 {
        0 if single => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let size_offset = if single { 5 } else { 6 };
    if header.len() < size_offset + size_bytes {
        return Ok(false);
    }
    let mut size = 0_u64;
    for (i, &byte) in header[size_offset..size_offset + size_bytes]
        .iter()
        .enumerate()
    {
        size |= (byte as u64) << (8 * i);
    }
    if size_bytes == 2 {
        size += 256;
    }
    let window = if single {
        size
    } else {
        let base = 1_u64 << (10 + (header[5] >> 3));
        base + (base / 8) * u64::from(header[5] & 7)
    };
    if window > MAX_ZSTD_WINDOW_BYTES_V1 || size > MAX_PLAINTEXT_OBJECT_BYTES_V1 {
        return Err(BackupError::resource_limit_exceeded());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8], limit: u64) -> Result<Vec<u8>, BackupError> {
        let mut decoder = BoundedDecoder::new()?;
        decoder.limit = limit;
        let mut result = Vec::new();
        for byte in bytes {
            decoder.push(
                &[*byte],
                &mut |data| {
                    result.extend_from_slice(data);
                    Ok(())
                },
                &|| Ok(()),
            )?;
        }
        decoder.finish()?;
        Ok(result)
    }

    #[test]
    fn short_input_and_output_draining_preserve_plaintext() {
        let plaintext = vec![42; 200_000];
        let compressed = zstd::stream::encode_all(plaintext.as_slice(), 3).unwrap();
        assert_eq!(decode(&compressed, 200_000).unwrap(), plaintext);
        assert_eq!(
            decode(&compressed, 199_999).unwrap_err().code(),
            BackupErrorCode::ResourceLimitExceeded
        );
    }

    #[test]
    fn rejects_truncation_second_frame_trailing_and_skippable_frames() {
        let compressed = zstd::stream::encode_all(&b"data"[..], 3).unwrap();
        for end in 0..compressed.len() {
            assert!(decode(&compressed[..end], 100).is_err());
        }
        let mut trailing = compressed.clone();
        trailing.push(0);
        assert!(decode(&trailing, 100).is_err());
        let mut concat = compressed.clone();
        concat.extend_from_slice(&compressed);
        assert!(decode(&concat, 100).is_err());
        assert!(decode(&[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0], 100).is_err());
    }

    #[test]
    fn rejects_large_windows_and_dictionary_headers_before_decoding() {
        // Standard magic, no content size, 16-MiB window descriptor.
        assert_eq!(
            decode(&[0x28, 0xb5, 0x2f, 0xfd, 0, 14 << 3], 100)
                .unwrap_err()
                .code(),
            BackupErrorCode::ResourceLimitExceeded
        );
        assert!(decode(&[0x28, 0xb5, 0x2f, 0xfd, 1, 0, 1], 100).is_err());
        let mut single = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        single.extend_from_slice(&(16_u32 * 1024 * 1024).to_le_bytes());
        assert_eq!(
            decode(&single, 100).unwrap_err().code(),
            BackupErrorCode::ResourceLimitExceeded
        );
    }
}
