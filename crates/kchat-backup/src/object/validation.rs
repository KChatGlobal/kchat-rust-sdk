//! Full-object envelope, integrity and bounded decompression validation.
//! Payload bytes are opaque; schema validation belongs to the application.

use super::reader::{ReplayProof, validate_payload_v1};
use crate::{
    BackupByteSourceFactory, BackupError, BackupErrorCode, BackupObjectContextV1,
    ExpectedBackupObjectV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupValidationState {
    Ready,
    Running,
    /// Envelope, decompression, inventory all succeeded.
    Completed,
    Failed,
    Cancelled,
}

/// One validation attempt per instance; all terminal states reject reuse.
///
/// This synchronous core owns no worker threads. During `validate`, cancellation
/// comes from the factory/source flags, checked around callback boundaries.
/// Dropping the validator releases its state; opened source handles are local to
/// the verification pass and are dropped on both success and failure.
pub struct BackupObjectValidatorV1 {
    state: BackupValidationState,
}

impl Default for BackupObjectValidatorV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl BackupObjectValidatorV1 {
    pub const fn new() -> Self {
        Self {
            state: BackupValidationState::Ready,
        }
    }

    pub const fn state(&self) -> BackupValidationState {
        self.state
    }

    /// Cancel before starting. To cancel a running call, signal its factory/source.
    pub fn cancel(&mut self) -> Result<(), BackupError> {
        if self.state != BackupValidationState::Ready {
            return Err(BackupError::invalid_state());
        }
        self.state = BackupValidationState::Cancelled;
        Ok(())
    }

    /// Validate the envelope, integrity and compression without an output sink.
    pub fn validate(
        &mut self,
        context: &BackupObjectContextV1,
        factory: &mut dyn BackupByteSourceFactory,
        expected: &ExpectedBackupObjectV1,
    ) -> Result<(), BackupError> {
        self.validate_with_proof(context, factory, expected)
            .map(|_| ())
    }

    pub(super) fn validate_with_proof(
        &mut self,
        context: &BackupObjectContextV1,
        factory: &mut dyn BackupByteSourceFactory,
        expected: &ExpectedBackupObjectV1,
    ) -> Result<ReplayProof, BackupError> {
        if self.state != BackupValidationState::Ready {
            return Err(BackupError::invalid_state());
        }
        self.state = BackupValidationState::Running;
        let result = validate_payload_v1(context, factory, expected);
        self.state = match &result {
            Ok(_) => BackupValidationState::Completed,
            Err(error) if error.code() == BackupErrorCode::Cancelled => {
                BackupValidationState::Cancelled
            }
            Err(_) => BackupValidationState::Failed,
        };
        result
    }
}
