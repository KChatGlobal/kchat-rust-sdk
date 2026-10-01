//! Full-object validation lifecycle with caller-defined payload semantics.
//!
//! An authenticated envelope is necessary but insufficient for a valid backup.
//! Completion must also mean bounded decompression AND semantic validation. The
//! caller supplies schema rules; the SDK never assumes opaque bytes are valid chat.

use super::reader::{ReplayProof, validate_payload_v1};
use crate::{
    BackupByteSourceFactory, BackupError, BackupErrorCode, BackupObjectContextV1,
    ExpectedBackupObjectV1,
};

/// Trusted, incremental semantic validator for the caller-owned payload format.
/// No default accept-all implementation is provided. `validate_chunk` receives
/// arbitrary byte slices (at most 64 KiB), NOT record-aligned frames. Retain only
/// bounded parsing/reference state and enforce schema-specific limits yourself.
///
/// This callback belongs INSIDE the verification boundary: bytes are tentative
/// until the entire object and `finish` succeed. Never publish/import/log them.
/// Return `InvalidPayload` for semantic rejection, `ResourceLimitExceeded` for
/// schema limits. On any failure discard this validator and its private state;
/// a retry requires a fresh instance. `finish` is called exactly once on a
/// structurally/integrity-valid object, and never on an earlier failure.
pub trait BackupPayloadValidator {
    fn validate_chunk(&mut self, plaintext: &[u8]) -> Result<(), BackupError>;
    fn finish(&mut self) -> Result<(), BackupError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupValidationState {
    Ready,
    Running,
    /// Envelope, decompression, inventory and caller semantics all succeeded.
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

    /// Validate all layers without an output sink. Supply a fresh semantic
    /// validator per attempt; application-specific records remain caller-owned.
    pub fn validate(
        &mut self,
        context: &BackupObjectContextV1,
        factory: &mut dyn BackupByteSourceFactory,
        expected: &ExpectedBackupObjectV1,
        semantics: &mut dyn BackupPayloadValidator,
    ) -> Result<(), BackupError> {
        self.validate_with_proof(context, factory, expected, semantics)
            .map(|_| ())
    }

    pub(super) fn validate_with_proof(
        &mut self,
        context: &BackupObjectContextV1,
        factory: &mut dyn BackupByteSourceFactory,
        expected: &ExpectedBackupObjectV1,
        semantics: &mut dyn BackupPayloadValidator,
    ) -> Result<ReplayProof, BackupError> {
        if self.state != BackupValidationState::Ready {
            return Err(BackupError::invalid_state());
        }
        self.state = BackupValidationState::Running;
        let result = validate_payload_v1(context, factory, expected, semantics);
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
