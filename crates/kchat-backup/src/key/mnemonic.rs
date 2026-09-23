use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::BackupError;

use super::{ACCOUNT_KEY_LABEL, BackupKeyMaterial, derive_hkdf, private};

const MASTER_KEY_INFO: &[u8] = b"KCHAT_BACKUP_V1_MASTER";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MnemonicBackupKey([u8; 32]);

impl MnemonicBackupKey {
    pub fn generate() -> Result<(String, Self), BackupError> {
        let mut entropy = [0_u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| BackupError::io_error())?;
        let mnemonic_result = Mnemonic::from_entropy_in(Language::English, &entropy);
        entropy.zeroize();
        let mnemonic = mnemonic_result.map_err(|_| BackupError::invalid_state())?;
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
        let expansion = Hkdf::<Sha256>::new(None, &seed)
            .expand(MASTER_KEY_INFO, &mut key)
            .map_err(|_| BackupError::invalid_state());
        seed.zeroize();
        match expansion {
            Ok(()) => Ok(Self(key)),
            Err(error) => {
                key.zeroize();
                Err(error)
            }
        }
    }

    pub fn export_for_secure_storage(&self) -> [u8; 32] {
        self.0
    }

    pub fn import_from_secure_storage(bytes: &[u8]) -> Result<Self, BackupError> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| BackupError::invalid_mnemonic_key())?;
        Ok(Self(key))
    }

    fn derive_account_key_material(&self, account_id: &[u8; 16]) -> Result<[u8; 32], BackupError> {
        let mut info = [0_u8; ACCOUNT_KEY_LABEL.len() + 16];
        info[..ACCOUNT_KEY_LABEL.len()].copy_from_slice(ACCOUNT_KEY_LABEL);
        info[ACCOUNT_KEY_LABEL.len()..].copy_from_slice(account_id);
        derive_hkdf(&self.0, &info)
    }
}

impl private::Sealed for MnemonicBackupKey {
    fn derive_account_key_material(&self, account_id: &[u8; 16]) -> Result<[u8; 32], BackupError> {
        self.derive_account_key_material(account_id)
    }
}

impl BackupKeyMaterial for MnemonicBackupKey {}

impl core::fmt::Debug for MnemonicBackupKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MnemonicBackupKey(REDACTED)")
    }
}
