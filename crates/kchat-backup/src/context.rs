use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    BackupAccountId, BackupError,
    key::{BackupKeyMaterial, ObjectBackupKey, derive_account_key},
};

pub const BACKUP_FORMAT_VERSION_V1: u16 = 1;
const OBJECT_CONTEXT_LABEL: &[u8] = b"KCHAT_BACKUP_OBJECT_CONTEXT_V1";
const CANONICAL_CONTEXT_LENGTH: usize = OBJECT_CONTEXT_LABEL.len() + 2 + 32 + 16;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupId([u8; 32]);

impl BackupId {
    pub fn derive(
        master_key: &impl BackupKeyMaterial,
        account_id: &BackupAccountId,
    ) -> Result<Self, BackupError> {
        let account_key = derive_account_key(master_key, account_id.as_bytes())?;
        Ok(Self(account_key.derive_backup_id()?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for BackupId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupId(REDACTED)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupChunkId([u8; 16]);

impl BackupChunkId {
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, BackupError> {
        if bytes == [0; 16] {
            return Err(BackupError::invalid_argument());
        }
        Ok(Self(bytes))
    }

    const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for BackupChunkId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupChunkId(REDACTED)")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BackupObjectContextV1 {
    /// "KCHAT_BACKUP_OBJECT_CONTEXT_V1"
    /// || format_version:u16-be
    /// || backup_id:[u8; 32]
    /// || chunk_id:[u8; 16]
    canonical_bytes: [u8; CANONICAL_CONTEXT_LENGTH],
    object_key: ObjectBackupKey,
}

impl BackupObjectContextV1 {
    pub fn new(
        master_key: &impl BackupKeyMaterial,
        account_id: BackupAccountId,
        backup_id: BackupId,
        format_version: u16,
        chunk_id: BackupChunkId,
    ) -> Result<Self, BackupError> {
        if format_version != BACKUP_FORMAT_VERSION_V1 {
            return Err(BackupError::unsupported_format());
        }
        let expected_backup_id = BackupId::derive(master_key, &account_id)?;
        if backup_id != expected_backup_id {
            return Err(BackupError::context_mismatch());
        }

        let mut canonical_bytes = [0_u8; CANONICAL_CONTEXT_LENGTH];
        canonical_bytes[..OBJECT_CONTEXT_LABEL.len()].copy_from_slice(OBJECT_CONTEXT_LABEL);
        canonical_bytes[OBJECT_CONTEXT_LABEL.len()..OBJECT_CONTEXT_LABEL.len() + 2]
            .copy_from_slice(&format_version.to_be_bytes());
        let backup_id_start = OBJECT_CONTEXT_LABEL.len() + 2;
        canonical_bytes[backup_id_start..backup_id_start + 32]
            .copy_from_slice(backup_id.as_bytes());
        canonical_bytes[backup_id_start + 32..].copy_from_slice(chunk_id.as_bytes());

        let account_key = derive_account_key(master_key, account_id.as_bytes())?;
        let object_key = account_key.derive_object(&canonical_bytes)?;

        Ok(Self {
            canonical_bytes,
            object_key,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[allow(dead_code)]
    pub(crate) fn object_key(&self) -> &[u8; 32] {
        self.object_key.as_bytes()
    }
}

impl core::fmt::Debug for BackupObjectContextV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupObjectContextV1(REDACTED)")
    }
}
