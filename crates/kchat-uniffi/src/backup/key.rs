use std::sync::Arc;

use kchat_backup::{
    BACKUP_FORMAT_VERSION_V1, BackupAccountId, BackupChunkId, BackupId, BackupKeyMaterial,
    BackupObjectContextV1, DescriptorHeaderV1, MnemonicBackupKey, PasswordBackupKey,
    seal_descriptor_v1,
};
use zeroize::Zeroize;

use super::BackupFfiError;

#[derive(uniffi::Enum, Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupKeyMode {
    Mnemonic,
    Password,
}

#[derive(uniffi::Enum)]
pub enum BackupDescriptorBootstrap {
    Mnemonic,
    Password { salt: Vec<u8> },
}

#[derive(uniffi::Object)]
pub struct BackupMasterKey {
    key: CoreBackupMasterKey,
}

enum CoreBackupMasterKey {
    Mnemonic(MnemonicBackupKey),
    Password(PasswordBackupKey),
}

#[derive(uniffi::Object)]
pub struct BackupObjectContext {
    context: BackupObjectContextV1,
}

#[derive(uniffi::Record)]
pub struct GeneratedMnemonicBackupKey {
    pub mnemonic: String,
    pub key: Arc<BackupMasterKey>,
}

#[derive(uniffi::Record)]
pub struct GeneratedPasswordBackupKey {
    pub salt: Vec<u8>,
    pub key: Arc<BackupMasterKey>,
}

#[uniffi::export]
pub fn generate_mnemonic(word_count: u32) -> Result<GeneratedMnemonicBackupKey, BackupFfiError> {
    let (mnemonic, key) = MnemonicBackupKey::generate(word_count)?;
    Ok(GeneratedMnemonicBackupKey {
        mnemonic,
        key: Arc::new(BackupMasterKey {
            key: CoreBackupMasterKey::Mnemonic(key),
        }),
    })
}

#[uniffi::export]
pub fn generate_password(
    mut password_raw_utf8: Vec<u8>,
) -> Result<GeneratedPasswordBackupKey, BackupFfiError> {
    let result = PasswordBackupKey::generate(&password_raw_utf8);
    password_raw_utf8.zeroize();
    let (salt, key) = result?;
    Ok(GeneratedPasswordBackupKey {
        salt: salt.to_vec(),
        key: Arc::new(BackupMasterKey {
            key: CoreBackupMasterKey::Password(key),
        }),
    })
}

#[uniffi::export]
pub fn import_from_raw(
    mode: BackupKeyMode,
    mut bytes: Vec<u8>,
) -> Result<Arc<BackupMasterKey>, BackupFfiError> {
    let result = match mode {
        BackupKeyMode::Mnemonic => {
            MnemonicBackupKey::import_from_raw(&bytes).map(CoreBackupMasterKey::Mnemonic)
        }
        BackupKeyMode::Password => {
            PasswordBackupKey::import_from_raw(&bytes).map(CoreBackupMasterKey::Password)
        }
    };
    bytes.zeroize();
    let key = result?;
    Ok(Arc::new(BackupMasterKey { key }))
}

#[uniffi::export]
impl BackupMasterKey {
    pub fn mode(&self) -> BackupKeyMode {
        match self.key {
            CoreBackupMasterKey::Mnemonic(_) => BackupKeyMode::Mnemonic,
            CoreBackupMasterKey::Password(_) => BackupKeyMode::Password,
        }
    }

    pub fn export_raw(&self) -> Vec<u8> {
        match &self.key {
            CoreBackupMasterKey::Mnemonic(key) => key.export_raw().to_vec(),
            CoreBackupMasterKey::Password(key) => key.export_raw().to_vec(),
        }
    }

    pub fn derive_backup_id(&self, account_id: String) -> Result<Vec<u8>, BackupFfiError> {
        let account_id = BackupAccountId::parse(&account_id)?;
        match &self.key {
            CoreBackupMasterKey::Mnemonic(key) => derive_backup_id(key, &account_id),
            CoreBackupMasterKey::Password(key) => derive_backup_id(key, &account_id),
        }
    }

    pub fn seal_descriptor(
        &self,
        account_id: String,
        bootstrap: BackupDescriptorBootstrap,
    ) -> Result<Vec<u8>, BackupFfiError> {
        let account_id = BackupAccountId::parse(&account_id)?;
        let header = self.descriptor_header(bootstrap)?;
        match &self.key {
            CoreBackupMasterKey::Mnemonic(key) => seal_descriptor(key, &account_id, header),
            CoreBackupMasterKey::Password(key) => seal_descriptor(key, &account_id, header),
        }
    }

    pub fn create_object_context(
        &self,
        account_id: String,
        backup_id: Vec<u8>,
        chunk_id: Vec<u8>,
    ) -> Result<Arc<BackupObjectContext>, BackupFfiError> {
        let account_id = BackupAccountId::parse(&account_id)?;
        let backup_id = exact_array(backup_id)?;
        let chunk_id = BackupChunkId::from_bytes(exact_array(chunk_id)?)?;
        let context = match &self.key {
            CoreBackupMasterKey::Mnemonic(key) => {
                create_context(key, account_id, backup_id, chunk_id)
            }
            CoreBackupMasterKey::Password(key) => {
                create_context(key, account_id, backup_id, chunk_id)
            }
        }?;
        Ok(Arc::new(BackupObjectContext { context }))
    }
}

impl BackupMasterKey {
    fn descriptor_header(
        &self,
        bootstrap: BackupDescriptorBootstrap,
    ) -> Result<DescriptorHeaderV1, BackupFfiError> {
        match (&self.key, bootstrap) {
            (CoreBackupMasterKey::Mnemonic(_), BackupDescriptorBootstrap::Mnemonic) => {
                Ok(DescriptorHeaderV1::mnemonic())
            }
            (CoreBackupMasterKey::Password(_), BackupDescriptorBootstrap::Password { salt }) => {
                Ok(DescriptorHeaderV1::password(exact_array(salt)?))
            }
            _ => Err(BackupFfiError::InvalidArgument),
        }
    }
}

impl BackupObjectContext {
    pub(crate) fn as_core(&self) -> &BackupObjectContextV1 {
        &self.context
    }
}

impl core::fmt::Debug for BackupMasterKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "BackupMasterKey({:?})", self.mode())
    }
}

impl core::fmt::Debug for BackupObjectContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupObjectContext(REDACTED)")
    }
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], BackupFfiError> {
    bytes
        .try_into()
        .map_err(|_| BackupFfiError::InvalidArgument)
}

fn derive_backup_id(
    key: &impl BackupKeyMaterial,
    account_id: &BackupAccountId,
) -> Result<Vec<u8>, BackupFfiError> {
    Ok(BackupId::derive(key, account_id)?.as_bytes().to_vec())
}

fn seal_descriptor(
    key: &impl BackupKeyMaterial,
    account_id: &BackupAccountId,
    header: DescriptorHeaderV1,
) -> Result<Vec<u8>, BackupFfiError> {
    Ok(seal_descriptor_v1(key, account_id, header)?)
}

fn create_context(
    key: &impl BackupKeyMaterial,
    account_id: BackupAccountId,
    backup_id: [u8; 32],
    chunk_id: BackupChunkId,
) -> Result<BackupObjectContextV1, BackupFfiError> {
    let expected_backup_id = BackupId::derive(key, &account_id)?;
    if backup_id != *expected_backup_id.as_bytes() {
        return Err(BackupFfiError::ContextMismatch);
    }
    Ok(BackupObjectContextV1::new(
        key,
        account_id,
        expected_backup_id,
        BACKUP_FORMAT_VERSION_V1,
        chunk_id,
    )?)
}
