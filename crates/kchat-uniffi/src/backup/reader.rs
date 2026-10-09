//! Kotlin/Swift callbacks for the verified backup reader.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use kchat_backup::{
    BackupByteSink, BackupByteSource, BackupByteSourceFactory, BackupError, BackupErrorCode,
    ExpectedBackupObjectV1, MAX_IO_CHUNK_BYTES_V1, open_object_v1,
};
use zeroize::Zeroizing;

use super::{BackupFfiError, BackupMasterKey, BackupObjectMetadata};

/// Open the same immutable ciphertext from offset zero on each call.
#[uniffi::export(with_foreign)]
pub trait BackupCiphertextSourceFactory: Send + Sync {
    fn open(&self) -> Result<Arc<dyn BackupCiphertextSource>, BackupFfiError>;
    fn is_cancelled(&self) -> Result<bool, BackupFfiError>;
}

#[uniffi::export(with_foreign)]
pub trait BackupCiphertextSource: Send + Sync {
    /// An empty array means permanent EOF.
    fn read_chunk(&self, maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError>;
    fn is_cancelled(&self) -> Result<bool, BackupFfiError>;
    /// Called after each pass, including failed reads.
    fn release_stream(&self) -> Result<(), BackupFfiError>;
}

/// Receives provisional plaintext; discard it if restore fails.
#[uniffi::export(with_foreign)]
pub trait BackupPlaintextSink: Send + Sync {
    fn write_chunk(&self, bytes: Vec<u8>) -> Result<(), BackupFfiError>;
}

/// Derive context and open one object into provisional staging.
#[uniffi::export]
pub fn open_backup_object_v1(
    key: Arc<BackupMasterKey>,
    account_id: String,
    chunk_id: Vec<u8>,
    factory: Arc<dyn BackupCiphertextSourceFactory>,
    metadata: BackupObjectMetadata,
    sink: Arc<dyn BackupPlaintextSink>,
) -> Result<(), BackupFfiError> {
    let backup_id = key.derive_backup_id(account_id.clone())?;
    let context = key.create_object_context(account_id, backup_id, chunk_id)?;
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
    // Report cancellation callback failures as I/O errors.
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
