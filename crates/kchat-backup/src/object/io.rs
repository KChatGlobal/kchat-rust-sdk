use crate::{BackupError, MAX_IO_CHUNK_BYTES_V1, MAX_PLAINTEXT_OBJECT_BYTES_V1};

pub trait BackupByteSource {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError>;

    /// Returns whether the caller has cancelled the active operation.
    fn is_cancelled(&self) -> bool {
        false
    }
}

pub trait BackupByteSink {
    fn write_chunk(&mut self, source: &[u8]) -> Result<(), BackupError>;
}

/// Copies raw caller bytes in bounded chunks without decoding or classifying them.
pub fn copy_opaque_bytes_v1(
    source: &mut dyn BackupByteSource,
    sink: &mut dyn BackupByteSink,
) -> Result<u64, BackupError> {
    let mut buffer = [0_u8; MAX_IO_CHUNK_BYTES_V1];
    let mut total = 0_u64;
    loop {
        let count = source.read_chunk(&mut buffer)?;
        if count > buffer.len() {
            return Err(BackupError::invalid_state());
        }
        if count == 0 {
            return Ok(total);
        }
        total = total
            .checked_add(count as u64)
            .filter(|total| *total <= MAX_PLAINTEXT_OBJECT_BYTES_V1)
            .ok_or_else(BackupError::resource_limit_exceeded)?;
        sink.write_chunk(&buffer[..count])?;
    }
}
