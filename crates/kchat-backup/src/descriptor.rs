//! V1 descriptor wire format. All integer fields are big-endian.
//!
//! DescriptorPlaintextV1 (44 bytes; authenticated and encrypted)
//!   0..4    magic: "KCBD"
//!   4..6    format_version: u16 = 1
//!   6..38   backup_namespace_id: [u8; 32]
//!   38..40  crypto_profile_id: u16 = 1
//!   40..44  capabilities: u32 = 0
//!
//! DescriptorAADV1
//!   "KCHAT_BACKUP_DESCRIPTOR_V1" || backup_namespace_id
//!
//! SerializedDescriptorV1 (90 bytes)
//!   0..4    outer magic: "KCBD"
//!   4..6    outer format_version: u16 = 1
//!   6..30   nonce: [u8; 24]
//!   30..90  ciphertext_and_tag: [u8; 60]
//!
//! `ciphertext_and_tag` is one-shot XChaCha20Poly1305 encryption of the
//! 44-byte plaintext and therefore includes its 16-byte authentication tag.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{BackupAccountId, BackupError, BackupNamespaceId, MnemonicBackupKey};
use crate::key::derive_account_key;

const DESCRIPTOR_MAGIC: &[u8; 4] = b"KCBD";
const DESCRIPTOR_VERSION: u16 = 1;
const CRYPTO_PROFILE_ID: u16 = 1;
const DESCRIPTOR_PLAINTEXT_BYTES: usize = 44;
const SERIALIZED_DESCRIPTOR_BYTES: usize = 90;
const DESCRIPTOR_AAD_LABEL: &[u8] = b"KCHAT_BACKUP_DESCRIPTOR_V1";

pub fn seal_descriptor_v1(
    master_key: &MnemonicBackupKey,
    account_id: &BackupAccountId,
) -> Result<Vec<u8>, BackupError> {
    let namespace_id = BackupNamespaceId::derive(master_key, account_id)?;
    let mut plaintext = [0_u8; DESCRIPTOR_PLAINTEXT_BYTES];
    plaintext[..4].copy_from_slice(DESCRIPTOR_MAGIC);
    plaintext[4..6].copy_from_slice(&DESCRIPTOR_VERSION.to_be_bytes());
    plaintext[6..38].copy_from_slice(namespace_id.as_bytes());
    plaintext[38..40].copy_from_slice(&CRYPTO_PROFILE_ID.to_be_bytes());

    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| BackupError::io_error())?;
    let account_key = derive_account_key(master_key, account_id.as_bytes())?;
    let descriptor_key = account_key.derive_descriptor()?;
    let cipher = XChaCha20Poly1305::new_from_slice(descriptor_key.as_bytes())
        .map_err(|_| BackupError::invalid_state())?;
    let aad = descriptor_aad(&namespace_id);
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

    let mut serialized = Vec::with_capacity(SERIALIZED_DESCRIPTOR_BYTES);
    serialized.extend_from_slice(DESCRIPTOR_MAGIC);
    serialized.extend_from_slice(&DESCRIPTOR_VERSION.to_be_bytes());
    serialized.extend_from_slice(&nonce);
    serialized.extend_from_slice(&ciphertext);
    Ok(serialized)
}

pub fn open_descriptor_v1(
    master_key: &MnemonicBackupKey,
    account_id: &BackupAccountId,
    serialized: &[u8],
) -> Result<BackupNamespaceId, BackupError> {
    if serialized.len() != SERIALIZED_DESCRIPTOR_BYTES {
        return Err(BackupError::invalid_argument());
    }
    if &serialized[..4] != DESCRIPTOR_MAGIC || serialized[4..6] != DESCRIPTOR_VERSION.to_be_bytes()
    {
        return Err(BackupError::unsupported_format());
    }

    let namespace_id = BackupNamespaceId::derive(master_key, account_id)?;
    let account_key = derive_account_key(master_key, account_id.as_bytes())?;
    let descriptor_key = account_key.derive_descriptor()?;
    let cipher = XChaCha20Poly1305::new_from_slice(descriptor_key.as_bytes())
        .map_err(|_| BackupError::invalid_state())?;
    let aad = descriptor_aad(&namespace_id);
    let nonce = XNonce::try_from(&serialized[6..30]).map_err(|_| BackupError::invalid_state())?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &serialized[30..],
                aad: &aad,
            },
        )
        .map_err(|_| BackupError::authentication_failed())?;

    if plaintext.len() != DESCRIPTOR_PLAINTEXT_BYTES
        || &plaintext[..4] != DESCRIPTOR_MAGIC
        || plaintext[4..6] != DESCRIPTOR_VERSION.to_be_bytes()
        || plaintext[6..38] != *namespace_id.as_bytes()
        || plaintext[38..40] != CRYPTO_PROFILE_ID.to_be_bytes()
        || plaintext[40..44] != [0; 4]
    {
        return Err(BackupError::unsupported_format());
    }
    Ok(namespace_id)
}

fn descriptor_aad(namespace_id: &BackupNamespaceId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DESCRIPTOR_AAD_LABEL.len() + 32);
    aad.extend_from_slice(DESCRIPTOR_AAD_LABEL);
    aad.extend_from_slice(namespace_id.as_bytes());
    aad
}
