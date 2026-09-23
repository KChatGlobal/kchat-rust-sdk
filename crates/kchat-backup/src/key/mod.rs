mod mnemonic;
mod password;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::BackupError;

pub use mnemonic::MnemonicBackupKey;
pub use password::PasswordBackupKey;

pub(crate) const ACCOUNT_KEY_LABEL: &[u8] = b"KCHAT_BACKUP_V1_ACCOUNT";
pub(crate) const NAMESPACE_KEY_LABEL: &[u8] = b"KCHAT_BACKUP_V1_NAMESPACE";
pub(crate) const OBJECT_KEY_LABEL: &[u8] = b"KCHAT_BACKUP_V1_OBJECT";
pub(crate) const DESCRIPTOR_KEY_LABEL: &[u8] = b"KCHAT_BACKUP_V1_DESCRIPTOR";

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct AccountBackupKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ObjectBackupKey([u8; 32]);
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DescriptorBackupKey([u8; 32]);

pub trait BackupKeyMaterial: private::Sealed {}

pub(crate) mod private {
    use crate::BackupError;

    pub trait Sealed {
        fn derive_account_key_material(
            &self,
            account_id: &[u8; 16],
        ) -> Result<[u8; 32], BackupError>;
    }
}

pub(crate) fn derive_account_key(
    master_key: &impl BackupKeyMaterial,
    account_id: &[u8; 16],
) -> Result<AccountBackupKey, BackupError> {
    Ok(AccountBackupKey(
        private::Sealed::derive_account_key_material(master_key, account_id)?,
    ))
}

impl AccountBackupKey {
    pub(crate) fn derive_descriptor(&self) -> Result<DescriptorBackupKey, BackupError> {
        Ok(DescriptorBackupKey(derive_hkdf(
            &self.0,
            DESCRIPTOR_KEY_LABEL,
        )?))
    }
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

impl DescriptorBackupKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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
