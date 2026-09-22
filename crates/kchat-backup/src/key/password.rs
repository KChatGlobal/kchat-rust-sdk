use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{BackupAccountId, BackupError};

use super::{ACCOUNT_KEY_LABEL, BackupKeyMaterial, derive_hkdf, private};

const PASSWORD_ROOT_LABEL: &[u8] = b"KCHAT_BACKUP_PASSWORD_ROOT_V1";
const ARGON2_MEMORY_KIB_V1: u32 = 65_536;
const ARGON2_ITERATIONS_V1: u32 = 3;
const ARGON2_LANES_V1: u32 = 4;
const ARGON2_OUTPUT_BYTES_V1: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasswordBackupKey([u8; 32]);

impl PasswordBackupKey {
    pub fn from_password(
        password_raw_utf8: &[u8],
        account_id: &BackupAccountId,
        salt: [u8; 16],
    ) -> Result<Self, BackupError> {
        if password_raw_utf8.is_empty() {
            return Err(BackupError::empty_password());
        }

        let params = Params::new(
            ARGON2_MEMORY_KIB_V1,
            ARGON2_ITERATIONS_V1,
            ARGON2_LANES_V1,
            Some(ARGON2_OUTPUT_BYTES_V1),
        )
        .map_err(|_| BackupError::invalid_state())?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut password_kdf = [0_u8; ARGON2_OUTPUT_BYTES_V1];
        let mut memory_blocks = Vec::new();
        memory_blocks
            .try_reserve_exact(argon2.params().block_count())
            .map_err(|_| BackupError::invalid_state())?;
        memory_blocks.resize(argon2.params().block_count(), Block::new());
        let hash_result = argon2.hash_password_into_with_memory(
            password_raw_utf8,
            &salt,
            &mut password_kdf,
            &mut memory_blocks,
        );
        memory_blocks.zeroize();
        if hash_result.is_err() {
            password_kdf.zeroize();
            return Err(BackupError::invalid_state());
        }

        let mut info = Vec::with_capacity(PASSWORD_ROOT_LABEL.len() + 16);
        info.extend_from_slice(PASSWORD_ROOT_LABEL);
        info.extend_from_slice(account_id.as_bytes());
        let root = derive_hkdf(&password_kdf, &info);
        password_kdf.zeroize();
        info.zeroize();
        Ok(Self(root?))
    }

    fn derive_account_key_material(&self, account_id: &[u8; 16]) -> Result<[u8; 32], BackupError> {
        let mut info = [0_u8; ACCOUNT_KEY_LABEL.len() + 16];
        info[..ACCOUNT_KEY_LABEL.len()].copy_from_slice(ACCOUNT_KEY_LABEL);
        info[ACCOUNT_KEY_LABEL.len()..].copy_from_slice(account_id);
        derive_hkdf(&self.0, &info)
    }
}

impl private::Sealed for PasswordBackupKey {
    fn derive_account_key_material(&self, account_id: &[u8; 16]) -> Result<[u8; 32], BackupError> {
        self.derive_account_key_material(account_id)
    }
}

impl BackupKeyMaterial for PasswordBackupKey {}

impl core::fmt::Debug for PasswordBackupKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PasswordBackupKey(REDACTED)")
    }
}
