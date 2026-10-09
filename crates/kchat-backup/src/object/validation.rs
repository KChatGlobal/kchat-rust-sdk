//! Validates object integrity and compression without parsing payloads.

use super::reader::validate_payload_v1;
use crate::{
    BackupByteSourceFactory, BackupError, BackupErrorCode, BackupObjectContextV1,
    ExpectedBackupObjectV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupValidationState {
    Ready,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Allows one validation attempt per instance.
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

    /// Cancel before validation starts.
    pub fn cancel(&mut self) -> Result<(), BackupError> {
        if self.state != BackupValidationState::Ready {
            return Err(BackupError::invalid_state());
        }
        self.state = BackupValidationState::Cancelled;
        Ok(())
    }

    pub fn validate(
        &mut self,
        context: &BackupObjectContextV1,
        factory: &mut dyn BackupByteSourceFactory,
        expected: &ExpectedBackupObjectV1,
    ) -> Result<(), BackupError> {
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
