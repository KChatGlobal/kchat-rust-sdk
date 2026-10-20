#![deny(clippy::all)]

pub mod error;
mod io;

use std::sync::Arc;

use kchat_backup::{
    BACKUP_FORMAT_VERSION_V1, BackupAccountId, BackupChunkId, BackupId, BackupKeyMaterial,
    BackupObjectContextV1, DescriptorBackupModeV1, DescriptorHeaderV1, MnemonicBackupKey,
    PasswordBackupKey, open_descriptor_v1, seal_descriptor_v1,
};
use napi::{
    Task,
    bindgen_prelude::{AsyncTask, Buffer},
};
use napi_derive::napi;
use zeroize::Zeroizing;

use crate::error::{Error, invalid_argument, invalid_state, map_error};

pub use crate::io::*;

#[napi]
pub enum BackupKeyMode {
    Mnemonic,
    Password,
}

enum CoreBackupMasterKey {
    Mnemonic(MnemonicBackupKey),
    Password(PasswordBackupKey),
}

#[napi]
pub struct BackupMasterKey {
    key: Option<Arc<CoreBackupMasterKey>>,
}

#[napi]
pub struct BackupObjectContext {
    context: Option<Arc<BackupObjectContextV1>>,
}

#[napi(object, object_from_js = false)]
pub struct GeneratedMnemonicBackupKey {
    pub mnemonic: String,
    pub key: BackupMasterKey,
}

#[napi(object, object_from_js = false)]
pub struct GeneratedPasswordBackupKey {
    pub salt: Buffer,
    pub key: BackupMasterKey,
}

#[napi(object)]
pub struct BackupDescriptorHeader {
    pub mode: BackupKeyMode,
    pub salt: Buffer,
}

#[napi(object)]
pub struct OpenedBackupDescriptor {
    pub header: BackupDescriptorHeader,
    pub backup_id: Buffer,
}

macro_rules! with_core_key {
    ($key:expr, |$inner:ident| $body:expr) => {
        match $key {
            CoreBackupMasterKey::Mnemonic($inner) => $body,
            CoreBackupMasterKey::Password($inner) => $body,
        }
    };
}

impl BackupMasterKey {
    fn new(key: CoreBackupMasterKey) -> Self {
        Self {
            key: Some(Arc::new(key)),
        }
    }

    fn as_core(&self) -> napi::Result<&CoreBackupMasterKey> {
        self.key.as_deref().ok_or_else(invalid_state)
    }
}

#[napi]
impl BackupMasterKey {
    #[napi]
    pub fn mode(&self) -> napi::Result<BackupKeyMode> {
        Ok(match self.as_core()? {
            CoreBackupMasterKey::Mnemonic(_) => BackupKeyMode::Mnemonic,
            CoreBackupMasterKey::Password(_) => BackupKeyMode::Password,
        })
    }

    #[napi]
    pub fn export_raw(&self) -> napi::Result<Buffer> {
        let bytes = with_core_key!(self.as_core()?, |key| Zeroizing::new(key.export_raw()));
        Ok(bytes.to_vec().into())
    }

    #[napi]
    pub fn derive_backup_id(&self, account_id: String) -> napi::Result<Buffer> {
        let account = BackupAccountId::parse(&account_id).map_err(map_error)?;
        let id = with_core_key!(self.as_core()?, |key| BackupId::derive(key, &account))
            .map_err(map_error)?;
        Ok(id.as_bytes().to_vec().into())
    }

    #[napi]
    pub fn seal_descriptor(
        &self,
        account_id: String,
        salt: Option<Buffer>,
    ) -> napi::Result<Buffer> {
        let account = BackupAccountId::parse(&account_id).map_err(map_error)?;
        let key = self.as_core()?;
        let header = match (key, salt) {
            (CoreBackupMasterKey::Mnemonic(_), None) => DescriptorHeaderV1::mnemonic(),
            (CoreBackupMasterKey::Password(_), Some(salt)) => {
                DescriptorHeaderV1::password(exact_array(&salt)?)
            }
            _ => return Err(invalid_argument()),
        };
        with_core_key!(key, |key| seal_descriptor_v1(key, &account, header))
            .map(Buffer::from)
            .map_err(map_error)
    }

    #[napi]
    pub fn open_descriptor(
        &self,
        account_id: String,
        bytes: Buffer,
    ) -> napi::Result<OpenedBackupDescriptor> {
        let account = BackupAccountId::parse(&account_id).map_err(map_error)?;
        let key = self.as_core()?;
        let header = DescriptorHeaderV1::parse(&bytes).map_err(map_error)?;
        let mode_matches = matches!(
            (key, header.backup_mode()),
            (
                CoreBackupMasterKey::Mnemonic(_),
                DescriptorBackupModeV1::Mnemonic
            ) | (
                CoreBackupMasterKey::Password(_),
                DescriptorBackupModeV1::Password
            )
        );
        if !mode_matches {
            return Err(invalid_argument());
        }
        let (header, id) = with_core_key!(key, |key| open_descriptor_v1(key, &account, &bytes))
            .map_err(map_error)?;
        Ok(OpenedBackupDescriptor {
            header: header.into(),
            backup_id: id.as_bytes().to_vec().into(),
        })
    }

    #[napi]
    pub fn create_object_context(
        &self,
        account_id: String,
        backup_id: Buffer,
        chunk_id: Buffer,
    ) -> napi::Result<BackupObjectContext> {
        let account = BackupAccountId::parse(&account_id).map_err(map_error)?;
        let backup_id: [u8; 32] = exact_array(&backup_id)?;
        let chunk = BackupChunkId::from_bytes(exact_array(&chunk_id)?).map_err(map_error)?;
        let context = with_core_key!(self.as_core()?, |key| create_context(
            key, account, backup_id, chunk
        ))?;
        Ok(BackupObjectContext {
            context: Some(Arc::new(context)),
        })
    }

    #[napi]
    pub fn dispose(&mut self) {
        self.key.take();
    }
}

impl BackupObjectContext {
    pub(crate) fn shared(&self) -> napi::Result<Arc<BackupObjectContextV1>> {
        self.context.clone().ok_or_else(invalid_state)
    }
}

#[napi]
impl BackupObjectContext {
    #[napi]
    pub fn dispose(&mut self) {
        self.context.take();
    }
}

impl From<DescriptorHeaderV1> for BackupDescriptorHeader {
    fn from(header: DescriptorHeaderV1) -> Self {
        Self {
            mode: match header.backup_mode() {
                DescriptorBackupModeV1::Mnemonic => BackupKeyMode::Mnemonic,
                DescriptorBackupModeV1::Password => BackupKeyMode::Password,
            },
            salt: header.salt().to_vec().into(),
        }
    }
}

#[napi]
pub fn parse_descriptor_header(bytes: Buffer) -> napi::Result<BackupDescriptorHeader> {
    DescriptorHeaderV1::parse(&bytes)
        .map(Into::into)
        .map_err(map_error)
}

#[napi]
pub fn import_from_raw(mode: BackupKeyMode, bytes: Buffer) -> napi::Result<BackupMasterKey> {
    let key = match mode {
        BackupKeyMode::Mnemonic => {
            MnemonicBackupKey::import_from_raw(&bytes).map(CoreBackupMasterKey::Mnemonic)
        }
        BackupKeyMode::Password => {
            PasswordBackupKey::import_from_raw(&bytes).map(CoreBackupMasterKey::Password)
        }
    }
    .map_err(map_error)?;
    Ok(BackupMasterKey::new(key))
}

pub struct GenerateMnemonicTask {
    word_count: u32,
}

#[napi]
impl Task for GenerateMnemonicTask {
    type Output = (Zeroizing<String>, MnemonicBackupKey);
    type JsValue = GeneratedMnemonicBackupKey;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        MnemonicBackupKey::generate(self.word_count)
            .map(|(phrase, key)| (Zeroizing::new(phrase), key))
            .map_err(map_error)
    }

    fn resolve(
        &mut self,
        _: napi::Env,
        (phrase, key): Self::Output,
    ) -> napi::Result<Self::JsValue> {
        Ok(GeneratedMnemonicBackupKey {
            mnemonic: phrase.to_string(),
            key: BackupMasterKey::new(CoreBackupMasterKey::Mnemonic(key)),
        })
    }
}

#[napi]
pub fn generate_mnemonic(word_count: u32) -> AsyncTask<GenerateMnemonicTask> {
    AsyncTask::new(GenerateMnemonicTask { word_count })
}

pub struct ImportMnemonicTask {
    phrase: Zeroizing<String>,
}

#[napi]
impl Task for ImportMnemonicTask {
    type Output = MnemonicBackupKey;
    type JsValue = BackupMasterKey;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        MnemonicBackupKey::from_mnemonic(&self.phrase).map_err(map_error)
    }

    fn resolve(&mut self, _: napi::Env, key: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(BackupMasterKey::new(CoreBackupMasterKey::Mnemonic(key)))
    }
}

#[napi]
pub fn import_from_mnemonic(mnemonic_phrase: String) -> AsyncTask<ImportMnemonicTask> {
    AsyncTask::new(ImportMnemonicTask {
        phrase: Zeroizing::new(mnemonic_phrase),
    })
}

pub struct GeneratePasswordTask {
    password: Zeroizing<Vec<u8>>,
}

#[napi]
impl Task for GeneratePasswordTask {
    type Output = ([u8; 16], PasswordBackupKey);
    type JsValue = GeneratedPasswordBackupKey;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        PasswordBackupKey::generate(&self.password).map_err(map_error)
    }

    fn resolve(&mut self, _: napi::Env, (salt, key): Self::Output) -> napi::Result<Self::JsValue> {
        Ok(GeneratedPasswordBackupKey {
            salt: salt.to_vec().into(),
            key: BackupMasterKey::new(CoreBackupMasterKey::Password(key)),
        })
    }
}

#[napi]
pub fn generate_password(password_raw_utf8: Buffer) -> AsyncTask<GeneratePasswordTask> {
    AsyncTask::new(GeneratePasswordTask {
        password: Zeroizing::new(password_raw_utf8.to_vec()),
    })
}

pub struct ImportPasswordTask {
    password: Zeroizing<Vec<u8>>,
    salt: [u8; 16],
}

#[napi]
impl Task for ImportPasswordTask {
    type Output = PasswordBackupKey;
    type JsValue = BackupMasterKey;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        PasswordBackupKey::from_password(&self.password, self.salt).map_err(map_error)
    }

    fn resolve(&mut self, _: napi::Env, key: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(BackupMasterKey::new(CoreBackupMasterKey::Password(key)))
    }
}

#[napi]
pub fn import_from_password(
    password_raw_utf8: Buffer,
    salt: Buffer,
) -> napi::Result<AsyncTask<ImportPasswordTask>> {
    Ok(AsyncTask::new(ImportPasswordTask {
        password: Zeroizing::new(password_raw_utf8.to_vec()),
        salt: exact_array(&salt)?,
    }))
}

fn exact_array<const N: usize>(bytes: &[u8]) -> napi::Result<[u8; N]> {
    bytes.try_into().map_err(|_| invalid_argument())
}

fn create_context(
    key: &impl BackupKeyMaterial,
    account: BackupAccountId,
    expected_id: [u8; 32],
    chunk: BackupChunkId,
) -> napi::Result<BackupObjectContextV1> {
    let id = BackupId::derive(key, &account).map_err(map_error)?;
    if id.as_bytes() != &expected_id {
        return Err(Error::ContextMismatch.into());
    }
    BackupObjectContextV1::new(key, account, id, BACKUP_FORMAT_VERSION_V1, chunk).map_err(map_error)
}
