use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::BackupError;

const MASTER_KEY_INFO: &[u8] = b"KCHAT_BACKUP_V1_MASTER";
pub(crate) const ACCOUNT_KEY_LABEL: &[u8] = b"KCHAT_BACKUP_V1_ACCOUNT";
pub(crate) const NAMESPACE_KEY_LABEL: &[u8] = b"KCHAT_BACKUP_V1_NAMESPACE";
pub(crate) const OBJECT_KEY_LABEL: &[u8] = b"KCHAT_BACKUP_V1_OBJECT";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BackupMasterKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct AccountBackupKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ObjectBackupKey([u8; 32]);

impl BackupMasterKey {
    pub fn generate() -> Result<(String, Self), BackupError> {
        let mut entropy = [0_u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| BackupError::io_error())?;
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|_| BackupError::invalid_state())?;
        entropy.zeroize();
        let master_key = Self::from_parsed_mnemonic(&mnemonic)?;
        Ok((mnemonic.to_string(), master_key))
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self, BackupError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| BackupError::invalid_mnemonic())?;
        Self::from_parsed_mnemonic(&mnemonic)
    }

    fn from_parsed_mnemonic(mnemonic: &Mnemonic) -> Result<Self, BackupError> {
        if mnemonic.word_count() != 24 {
            return Err(BackupError::invalid_mnemonic());
        }

        let mut seed = mnemonic.to_seed("");
        let mut key = [0_u8; 32];
        Hkdf::<Sha256>::new(None, &seed)
            .expand(MASTER_KEY_INFO, &mut key)
            .map_err(|_| BackupError::invalid_state())?;
        seed.zeroize();
        Ok(Self(key))
    }

    pub fn export_for_secure_storage(&self) -> [u8; 32] {
        self.0
    }

    pub fn import_from_secure_storage(bytes: &[u8]) -> Result<Self, BackupError> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| BackupError::invalid_master_key())?;
        Ok(Self(key))
    }

    pub(crate) fn derive_account_key(
        &self,
        account_id: &[u8; 16],
    ) -> Result<AccountBackupKey, BackupError> {
        let mut info = [0_u8; ACCOUNT_KEY_LABEL.len() + 16];
        info[..ACCOUNT_KEY_LABEL.len()].copy_from_slice(ACCOUNT_KEY_LABEL);
        info[ACCOUNT_KEY_LABEL.len()..].copy_from_slice(account_id);
        Ok(AccountBackupKey(derive_hkdf(&self.0, &info)?))
    }
}

impl AccountBackupKey {
    pub(crate) fn derive_namespace(&self) -> Result<[u8; 32], BackupError> {
        derive_hkdf(&self.0, NAMESPACE_KEY_LABEL)
    }

    pub(crate) fn derive_object(
        &self,
        canonical_context: &[u8],
    ) -> Result<ObjectBackupKey, BackupError> {
        let mut info = Vec::with_capacity(OBJECT_KEY_LABEL.len() + canonical_context.len());
        info.extend_from_slice(OBJECT_KEY_LABEL);
        info.extend_from_slice(canonical_context);
        let object_key = ObjectBackupKey(derive_hkdf(&self.0, &info)?);
        info.zeroize();
        Ok(object_key)
    }
}

impl ObjectBackupKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn derive_hkdf(
    input_key_material: &[u8; 32],
    info: &[u8],
) -> Result<[u8; 32], BackupError> {
    let mut output = [0_u8; 32];
    Hkdf::<Sha256>::new(None, input_key_material)
        .expand(info, &mut output)
        .map_err(|_| BackupError::invalid_state())?;
    Ok(output)
}

impl core::fmt::Debug for BackupMasterKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupMasterKey(REDACTED)")
    }
}
