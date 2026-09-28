use std::sync::{Arc, Mutex};

use kchat_backup::{
    BackupByteSink, BackupByteSource, BackupError, BackupErrorCode, BackupObjectDescriptor,
    MAX_IO_CHUNK_BYTES_V1, seal_object_v1,
};
use zeroize::Zeroizing;

use crate::{BackupFfiError, BackupObjectContext};

#[derive(uniffi::Record)]
pub struct BackupObjectMetadata {
    pub ciphertext_size: u64,
    pub ciphertext_sha256: Vec<u8>,
    pub format_version: u16,
}

#[uniffi::export(with_foreign)]
pub trait BackupPlaintextSource: Send + Sync {
    fn read_chunk(&self, maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError>;
    fn is_cancelled(&self) -> Result<bool, BackupFfiError>;
}

#[uniffi::export(with_foreign)]
pub trait BackupCiphertextSink: Send + Sync {
    fn write_chunk(&self, bytes: Vec<u8>) -> Result<(), BackupFfiError>;
}

#[uniffi::export]
pub fn seal_backup_object_v1(
    context: Arc<BackupObjectContext>,
    source: Arc<dyn BackupPlaintextSource>,
    sink: Arc<dyn BackupCiphertextSink>,
) -> Result<BackupObjectMetadata, BackupFfiError> {
    let mut source_adapter = SourceAdapter {
        source,
        cancellation_callback_failed: Mutex::new(false),
    };
    let mut sink_adapter = SinkAdapter { sink };
    let result = seal_object_v1(context.as_core(), &mut source_adapter, &mut sink_adapter);
    if source_adapter.cancellation_callback_failed() {
        return Err(BackupFfiError::IoError);
    }
    let descriptor = result?;
    Ok(BackupObjectMetadata::from(descriptor))
}

struct SourceAdapter {
    source: Arc<dyn BackupPlaintextSource>,
    cancellation_callback_failed: Mutex<bool>,
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
        match self.source.is_cancelled() {
            Ok(is_cancelled) => is_cancelled,
            Err(_) => {
                if let Ok(mut callback_failed) = self.cancellation_callback_failed.lock() {
                    *callback_failed = true;
                }
                true
            }
        }
    }
}

impl SourceAdapter {
    fn cancellation_callback_failed(&self) -> bool {
        self.cancellation_callback_failed
            .lock()
            .map(|callback_failed| *callback_failed)
            .unwrap_or(true)
    }
}

struct SinkAdapter {
    sink: Arc<dyn BackupCiphertextSink>,
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

impl From<BackupObjectDescriptor> for BackupObjectMetadata {
    fn from(descriptor: BackupObjectDescriptor) -> Self {
        Self {
            ciphertext_size: descriptor.ciphertext_size(),
            ciphertext_sha256: descriptor.ciphertext_sha256().to_vec(),
            format_version: descriptor.format_version(),
        }
    }
}
