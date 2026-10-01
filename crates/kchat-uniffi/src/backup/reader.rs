//! Bounded Kotlin/Swift callbacks for the verified backup reader.
//!
//! Each factory open must return a fresh handle at offset zero for the same
//! committed ciphertext object. The core reads it twice, decrypting/decompressing
//! once into provisional staging. Callback failures are sanitized to `IoError`.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use kchat_backup::{
    BackupByteSink, BackupByteSource, BackupByteSourceFactory, BackupError, BackupErrorCode,
    ExpectedBackupObjectV1, MAX_IO_CHUNK_BYTES_V1, open_object_v1,
};
use zeroize::Zeroizing;

use super::{BackupFfiError, BackupObjectContext, BackupObjectMetadata};

/// Open the same immutable ciphertext version anew on every call. Each source
/// must start at byte zero; no seek or platform-specific file API is imposed.
#[uniffi::export(with_foreign)]
pub trait BackupCiphertextSourceFactory: Send + Sync {
    fn open(&self) -> Result<Arc<dyn BackupCiphertextSource>, BackupFfiError>;
    fn is_cancelled(&self) -> Result<bool, BackupFfiError>;
}

#[uniffi::export(with_foreign)]
pub trait BackupCiphertextSource: Send + Sync {
    /// An empty array means permanent EOF, not a temporary lack of data.
    fn read_chunk(&self, maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError>;
    fn is_cancelled(&self) -> Result<bool, BackupFfiError>;
    /// Called once when a reader pass ends, including after a read error.
    /// Cleanup failures cannot replace the primary restore result.
    fn release_stream(&self) -> Result<(), BackupFfiError>;
}

/// Receives provisional opaque plaintext from AEAD-authenticated frames.
/// Final integrity/decompression checks can fail after output has started;
/// callers must discard staging on any error and activate only after full restore.
/// Schema validation is outside the SDK.
#[uniffi::export(with_foreign)]
pub trait BackupPlaintextSink: Send + Sync {
    fn write_chunk(&self, bytes: Vec<u8>) -> Result<(), BackupFfiError>;
}

#[uniffi::export]
pub fn open_backup_object_v1(
    context: Arc<BackupObjectContext>,
    factory: Arc<dyn BackupCiphertextSourceFactory>,
    metadata: BackupObjectMetadata,
    sink: Arc<dyn BackupPlaintextSink>,
) -> Result<(), BackupFfiError> {
    let expected_hash: [u8; 32] = metadata
        .ciphertext_sha256
        .try_into()
        .map_err(|_| BackupFfiError::InvalidArgument)?;
    let expected = ExpectedBackupObjectV1::new(
        metadata.ciphertext_size,
        expected_hash,
        metadata.format_version,
    )?;

    let callback_failed = Arc::new(AtomicBool::new(false));
    let mut factory_adapter = FactoryAdapter {
        factory,
        callback_failed: Arc::clone(&callback_failed),
    };
    let mut sink_adapter = SinkAdapter { sink };
    let result = open_object_v1(
        context.as_core(),
        &mut factory_adapter,
        &expected,
        &mut sink_adapter,
    );
    // A failed cancellation callback looks like cancellation to the synchronous
    // core. Report it as I/O instead of implying the user cancelled the restore.
    if callback_failed.load(Ordering::Relaxed) {
        return Err(BackupFfiError::IoError);
    }
    result.map_err(Into::into)
}

struct FactoryAdapter {
    factory: Arc<dyn BackupCiphertextSourceFactory>,
    callback_failed: Arc<AtomicBool>,
}

impl BackupByteSourceFactory for FactoryAdapter {
    fn open(&mut self) -> Result<Box<dyn BackupByteSource>, BackupError> {
        let source = self
            .factory
            .open()
            .map_err(|_| BackupError::from_code(BackupErrorCode::IoError))?;
        Ok(Box::new(SourceAdapter {
            source,
            callback_failed: Arc::clone(&self.callback_failed),
        }))
    }

    fn is_cancelled(&self) -> bool {
        callback_cancelled(&self.callback_failed, self.factory.is_cancelled())
    }
}

struct SourceAdapter {
    source: Arc<dyn BackupCiphertextSource>,
    callback_failed: Arc<AtomicBool>,
}

impl Drop for SourceAdapter {
    fn drop(&mut self) {
        // Every pass owns a fresh source. This hook lets Kotlin close a file or
        // HTTP response deterministically even if validation aborts early.
        let _ = self.source.release_stream();
    }
}

impl BackupByteSource for SourceAdapter {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError> {
        let bytes = self
            .source
            .read_chunk(destination.len() as u32)
            .map_err(|_| BackupError::from_code(BackupErrorCode::IoError))?;
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > destination.len() {
            return Err(BackupError::from_code(BackupErrorCode::InvalidState));
        }
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    fn is_cancelled(&self) -> bool {
        callback_cancelled(&self.callback_failed, self.source.is_cancelled())
    }
}

fn callback_cancelled(flag: &AtomicBool, result: Result<bool, BackupFfiError>) -> bool {
    match result {
        Ok(cancelled) => cancelled,
        Err(_) => {
            flag.store(true, Ordering::Relaxed);
            true
        }
    }
}

struct SinkAdapter {
    sink: Arc<dyn BackupPlaintextSink>,
}

impl BackupByteSink for SinkAdapter {
    fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        if bytes.len() > MAX_IO_CHUNK_BYTES_V1 {
            return Err(BackupError::from_code(BackupErrorCode::InvalidState));
        }
        self.sink
            .write_chunk(bytes.to_vec())
            .map_err(|_| BackupError::from_code(BackupErrorCode::IoError))
    }
}
