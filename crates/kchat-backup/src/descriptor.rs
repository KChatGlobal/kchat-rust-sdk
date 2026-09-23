//! Unified V1 `KCBD` descriptor wire format (110 bytes).
//!
//! ```text
//!  0..4   magic: "KCBD"
//!  4..6   format_version: u16-be = 1
//!  6      backup_mode: 1 mnemonic, 2 password
//!  7      reserved: 0
//!  8..10  kdf_profile_id: 0 mnemonic, 1 Argon2id V1 password
//! 10..26  salt: [u8; 16] (zero mnemonic; random password)
//! 26..50  nonce: [u8; 24]
//! 50..110 ciphertext_and_tag: [u8; 60]
//! ```

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{
    BackupAccountId, BackupError, BackupKeyMaterial, BackupNamespaceId, key::derive_account_key,
};

const MAGIC: &[u8; 4] = b"KCBD";
const FORMAT_VERSION: u16 = 1;
const MNEMONIC_MODE: u8 = 1;
const PASSWORD_MODE: u8 = 2;
const MNEMONIC_KDF_PROFILE: u16 = 0;
const PASSWORD_KDF_PROFILE: u16 = 1;
const HEADER_BYTES: usize = 26;
const NONCE_BYTES: usize = 24;
const PLAINTEXT_BYTES: usize = 44;
const SERIALIZED_BYTES: usize = HEADER_BYTES + NONCE_BYTES + PLAINTEXT_BYTES + 16;
const AAD_LABEL: &[u8] = b"KCHAT_BACKUP_DESCRIPTOR_V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorBackupModeV1 {
    Mnemonic,
    Password,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DescriptorHeaderV1([u8; HEADER_BYTES]);

impl DescriptorHeaderV1 {
    pub const fn mnemonic() -> Self {
        let mut bytes = [0_u8; HEADER_BYTES];
        bytes[0] = b'K';
        bytes[1] = b'C';
        bytes[2] = b'B';
        bytes[3] = b'D';
        bytes[4] = 0;
        bytes[5] = 1;
        bytes[6] = MNEMONIC_MODE;
        Self(bytes)
    }

    pub fn password(salt: [u8; 16]) -> Self {
        let mut bytes = Self::mnemonic().0;
        bytes[6] = PASSWORD_MODE;
        bytes[8..10].copy_from_slice(&PASSWORD_KDF_PROFILE.to_be_bytes());
        bytes[10..].copy_from_slice(&salt);
        Self(bytes)
    }

    pub fn parse(serialized: &[u8]) -> Result<Self, BackupError> {
        if serialized.len() != SERIALIZED_BYTES {
            return Err(BackupError::invalid_argument());
        }
        let header: [u8; HEADER_BYTES] = serialized[..HEADER_BYTES]
            .try_into()
            .map_err(|_| BackupError::invalid_state())?;
        let header = Self(header);
        header.validate()?;
        Ok(header)
    }

    pub const fn backup_mode(&self) -> DescriptorBackupModeV1 {
        if self.0[6] == MNEMONIC_MODE {
            DescriptorBackupModeV1::Mnemonic
        } else {
            DescriptorBackupModeV1::Password
        }
    }

    pub const fn salt(&self) -> [u8; 16] {
        let mut salt = [0_u8; 16];
        let mut index = 0;
        while index < 16 {
            salt[index] = self.0[10 + index];
            index += 1;
        }
        salt
    }

    fn validate(&self) -> Result<(), BackupError> {
        if self.0[..4] != *MAGIC || self.0[4..6] != FORMAT_VERSION.to_be_bytes() {
            return Err(BackupError::unsupported_format());
        }
        if self.0[7] != 0 {
            return Err(BackupError::unsupported_format());
        }
        match self.0[6] {
            MNEMONIC_MODE
                if self.0[8..10] == MNEMONIC_KDF_PROFILE.to_be_bytes()
                    && self.0[10..] == [0_u8; 16] =>
            {
                Ok(())
            }
            PASSWORD_MODE if self.0[8..10] == PASSWORD_KDF_PROFILE.to_be_bytes() => Ok(()),
            _ => Err(BackupError::unsupported_format()),
        }
    }
}

impl core::fmt::Debug for DescriptorHeaderV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DescriptorHeaderV1(..)")
    }
}

pub fn seal_descriptor_v1(
    master_key: &impl BackupKeyMaterial,
    account_id: &BackupAccountId,
    header: DescriptorHeaderV1,
) -> Result<Vec<u8>, BackupError> {
    header.validate()?;
    let namespace = BackupNamespaceId::derive(master_key, account_id)?;
    let descriptor_key = derive_descriptor_key(master_key, account_id)?;
    let aad = descriptor_aad(&header, &namespace);
    let plaintext = descriptor_plaintext(&namespace);

    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| BackupError::io_error())?;
    let cipher = XChaCha20Poly1305::new_from_slice(descriptor_key.as_bytes())
        .map_err(|_| BackupError::invalid_state())?;
    let nonce = XNonce::try_from(&nonce[..]).map_err(|_| BackupError::invalid_state())?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| BackupError::invalid_state())?;

    let mut serialized = Vec::with_capacity(SERIALIZED_BYTES);
    serialized.extend_from_slice(&header.0);
    serialized.extend_from_slice(&nonce);
    serialized.extend_from_slice(&ciphertext);
    Ok(serialized)
}

pub fn open_descriptor_v1(
    master_key: &impl BackupKeyMaterial,
    account_id: &BackupAccountId,
    serialized: &[u8],
) -> Result<(DescriptorHeaderV1, BackupNamespaceId), BackupError> {
    let header = DescriptorHeaderV1::parse(serialized)?;
    let namespace = BackupNamespaceId::derive(master_key, account_id)?;
    let descriptor_key = derive_descriptor_key(master_key, account_id)?;
    let aad = descriptor_aad(&header, &namespace);
    let cipher = XChaCha20Poly1305::new_from_slice(descriptor_key.as_bytes())
        .map_err(|_| BackupError::invalid_state())?;
    let nonce = XNonce::try_from(&serialized[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES])
        .map_err(|_| BackupError::invalid_state())?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &serialized[HEADER_BYTES + NONCE_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| BackupError::authentication_failed())?;
    validate_plaintext(&plaintext, namespace)?;
    Ok((header, namespace))
}

fn derive_descriptor_key(
    master_key: &impl BackupKeyMaterial,
    account_id: &BackupAccountId,
) -> Result<crate::key::DescriptorBackupKey, BackupError> {
    derive_account_key(master_key, account_id.as_bytes())?.derive_descriptor()
}

fn descriptor_plaintext(namespace: &BackupNamespaceId) -> [u8; PLAINTEXT_BYTES] {
    let mut plaintext = [0_u8; PLAINTEXT_BYTES];
    plaintext[..4].copy_from_slice(MAGIC);
    plaintext[4..6].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    plaintext[6..38].copy_from_slice(namespace.as_bytes());
    plaintext[38..40].copy_from_slice(&1_u16.to_be_bytes());
    plaintext
}

fn validate_plaintext(plaintext: &[u8], namespace: BackupNamespaceId) -> Result<(), BackupError> {
    if plaintext.len() != PLAINTEXT_BYTES
        || plaintext[..4] != *MAGIC
        || plaintext[4..6] != FORMAT_VERSION.to_be_bytes()
        || plaintext[6..38] != *namespace.as_bytes()
        || plaintext[38..40] != 1_u16.to_be_bytes()
        || plaintext[40..44] != [0_u8; 4]
    {
        return Err(BackupError::authentication_failed());
    }
    Ok(())
}

fn descriptor_aad(header: &DescriptorHeaderV1, namespace: &BackupNamespaceId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LABEL.len() + HEADER_BYTES + 32);
    aad.extend_from_slice(AAD_LABEL);
    aad.extend_from_slice(&header.0);
    aad.extend_from_slice(namespace.as_bytes());
    aad
}
