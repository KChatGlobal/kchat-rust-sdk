use crate::{BackupError, MAX_IO_CHUNK_BYTES_V1, MAX_PLAINTEXT_OBJECT_BYTES_V1};

pub trait BackupByteSource {
    /// Fill at most `destination.len()` bytes. Short reads are allowed; zero means
    /// permanent EOF, never "temporarily unavailable". Propagate I/O failures.
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError>;

    /// Returns whether the caller has cancelled the active operation.
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Reopens ONE exact committed ciphertext object at offset zero.
///
/// The caller owns storage/network policy. Every opened source must refer to the
/// same immutable storage version, not a mutable "latest" URL. The reader also
/// rechecks size/hash on subsequent passes. The output pass additionally checks
/// each encrypted frame against a private digest recorded during full validation
/// before it can produce plaintext. A changed stream can still interrupt output;
/// callers must not activate a partial restore.
///
/// Sources own their callback/file handles and release them on drop. No seek,
/// file path, HTTP client or async runtime is imposed by the core. Callbacks are
/// synchronous: their return provides backpressure. Run on a worker thread and
/// make blocking callbacks interruptible; cancellation cannot preempt a callback.
pub trait BackupByteSourceFactory {
    fn open(&mut self) -> Result<Box<dyn BackupByteSource>, BackupError>;

    /// Share a cancellation flag with all opened sources. The core checks this
    /// before/after opening and reading; the caller must unblock pending I/O.
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
