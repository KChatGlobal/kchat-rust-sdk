//! Bounded, single-frame Zstd decoding without dictionaries or trailing bytes.

use zeroize::Zeroizing;
use zstd::stream::raw::{DParameter, Decoder, Operation};

use crate::{
    BackupError, BackupErrorCode, MAX_IO_CHUNK_BYTES_V1, MAX_PLAINTEXT_OBJECT_BYTES_V1,
    MAX_ZSTD_WINDOW_BYTES_V1,
};

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
        // Limit the window before decoding untrusted input.
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
            // Probe one byte past the limit without emitting it.
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
    }
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
