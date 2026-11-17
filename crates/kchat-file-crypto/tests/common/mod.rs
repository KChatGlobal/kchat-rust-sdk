// Each integration test binary uses only some of these helpers.
#![allow(dead_code)]

use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use ed25519_dalek::{Signer, SigningKey};
use kchat_file_crypto::{
    ContentHash, ContentSink, ContentSource, FileCryptoError, FileKeyring, KKeyRootKey,
    OperationId, OprfRequest, OprfResponse, TenantId, hash_content,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use voprf::{BlindedElement, Group, Ristretto255, VoprfServer};

pub const TENANT: &str = "tenant-a";
pub const ACCOUNT: &str = "account-1";
pub const DB_KEY: [u8; 32] = [0x5A; 32];
pub const PEPPER: [u8; 32] = [0x77; 32];

/// Rebuilds the signed-message encoding independently of the crate.
pub fn encode(label: &str, fields: &[Field<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_lp(&mut bytes, label.as_bytes());
    for field in fields {
        match field {
            Field::Bytes(value) => push_lp(&mut bytes, value),
            Field::U64(value) => bytes.extend_from_slice(&value.to_be_bytes()),
        }
    }
    bytes
}

pub enum Field<'a> {
    Bytes(&'a [u8]),
    U64(u64),
}

fn push_lp(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

pub fn tenant() -> TenantId {
    TenantId::parse(TENANT).unwrap()
}

pub fn commitment(pepper: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"kchat-storage/pepper-commit/v1");
    hash.update(pepper);
    hash.finalize().into()
}

pub fn next_operation() -> OperationId {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    OperationId::parse(&format!("op-{}", NEXT.fetch_add(1, Ordering::Relaxed))).unwrap()
}

pub fn hash(bytes: &[u8]) -> ContentHash {
    hash_for(&next_operation(), bytes)
}

pub fn hash_for(operation: &OperationId, bytes: &[u8]) -> ContentHash {
    hash_content(operation, &mut MemorySource::new(bytes)).unwrap()
}

pub struct TestKeyring {
    // Declared first so the store is closed before the directory is removed.
    keyring: FileKeyring,
    pub dir: TempDir,
    pub path: PathBuf,
}

impl TestKeyring {
    pub fn new(root: Option<KKeyRootKey>) -> Self {
        Self::with_account(root, ACCOUNT)
    }

    pub fn with_account(root: Option<KKeyRootKey>, account: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file-keys.db");
        let keyring = FileKeyring::open(&path, &DB_KEY, account, root).unwrap();
        Self { keyring, dir, path }
    }

    pub fn close(self) -> (TempDir, PathBuf) {
        self.keyring.close().unwrap();
        (self.dir, self.path)
    }
}

impl Deref for TestKeyring {
    type Target = FileKeyring;

    fn deref(&self) -> &FileKeyring {
        &self.keyring
    }
}

pub fn reopen(path: &Path, root: Option<KKeyRootKey>) -> FileKeyring {
    FileKeyring::open(path, &DB_KEY, ACCOUNT, root).unwrap()
}

pub fn install_pepper(keyring: &FileKeyring, generation: u64, pepper: &[u8; 32]) {
    keyring
        .import_pepper(&tenant(), generation, pepper, &commitment(pepper))
        .unwrap();
}

pub struct FakeKKey {
    server: VoprfServer<Ristretto255>,
    root: SigningKey,
    pub key_gen: u64,
}

impl FakeKKey {
    pub fn new(seed: u8, key_gen: u64) -> Self {
        Self::with_root(
            seed,
            key_gen,
            SigningKey::from_bytes(&[seed.wrapping_add(100); 32]),
        )
    }

    pub fn with_root(seed: u8, key_gen: u64, root: SigningKey) -> Self {
        Self {
            server: VoprfServer::new_from_seed(&[seed; 32], b"test key").unwrap(),
            root,
            key_gen,
        }
    }

    pub fn root_key(&self) -> KKeyRootKey {
        KKeyRootKey::from_bytes(self.root.verifying_key().as_bytes()).unwrap()
    }

    pub fn public_key(&self) -> Vec<u8> {
        Ristretto255::serialize_elem(self.server.get_public_key()).to_vec()
    }

    pub fn sign_public_key(&self, tenant: &str, key_gen: u64, public_key: &[u8]) -> Vec<u8> {
        let message = encode(
            "kchat-storage/kkey-public-key/v1",
            &[
                Field::Bytes(tenant.as_bytes()),
                Field::U64(key_gen),
                Field::Bytes(public_key),
            ],
        );
        self.root.sign(&message).to_bytes().to_vec()
    }

    pub fn sign_policy(&self, tenant: &str, version: u64, policy: &str) -> Vec<u8> {
        let message = encode(
            "kchat-storage/kkey-policy/v1",
            &[
                Field::Bytes(tenant.as_bytes()),
                Field::U64(version),
                Field::Bytes(policy.as_bytes()),
            ],
        );
        self.root.sign(&message).to_bytes().to_vec()
    }

    pub fn import_public_key(&self, keyring: &FileKeyring) {
        let public_key = self.public_key();
        keyring
            .import_public_key(
                &tenant(),
                self.key_gen,
                &public_key,
                &self.sign_public_key(TENANT, self.key_gen, &public_key),
            )
            .unwrap();
    }

    pub fn import_policy(&self, keyring: &FileKeyring, version: u64, policy: &str) {
        keyring
            .import_policy(
                &tenant(),
                version,
                policy,
                &self.sign_policy(TENANT, version, policy),
            )
            .unwrap();
    }

    pub fn keyring(&self, policy: &str) -> TestKeyring {
        let keyring = TestKeyring::new(Some(self.root_key()));
        self.import_public_key(&keyring);
        self.import_policy(&keyring, 1, policy);
        install_pepper(&keyring, 1, &PEPPER);
        keyring
    }

    pub fn evaluate(&self, request: &OprfRequest) -> OprfResponse {
        let blinded: Vec<BlindedElement<Ristretto255>> = request
            .blinded_elements()
            .iter()
            .map(|element| BlindedElement::deserialize(element).unwrap())
            .collect();
        let result = self
            .server
            .batch_blind_evaluate(&mut TestRng, &blinded)
            .unwrap();
        OprfResponse::new(
            request.key_gen(),
            result
                .messages
                .iter()
                .map(|message| message.serialize().to_vec())
                .collect(),
            result.proof.serialize().to_vec(),
        )
    }
}

pub struct TestRng;

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        getrandom::fill(destination).unwrap();
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

pub struct MemorySource {
    bytes: Vec<u8>,
    offset: usize,
    max_chunk: usize,
}

impl MemorySource {
    pub fn new(bytes: &[u8]) -> Self {
        Self::chunked(bytes, usize::MAX)
    }

    pub fn chunked(bytes: &[u8], max_chunk: usize) -> Self {
        Self {
            bytes: bytes.to_vec(),
            offset: 0,
            max_chunk,
        }
    }
}

impl ContentSource for MemorySource {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, FileCryptoError> {
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(destination.len()).min(self.max_chunk);
        destination[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        Ok(count)
    }
}

pub struct CancelledSource;

impl ContentSource for CancelledSource {
    fn read_chunk(&mut self, _: &mut [u8]) -> Result<usize, FileCryptoError> {
        Ok(0)
    }

    fn is_cancelled(&self) -> bool {
        true
    }
}

#[derive(Default)]
pub struct RecordingSink {
    pub bytes: Vec<u8>,
    pub committed: bool,
    pub aborted: bool,
    pub largest_chunk: usize,
}

impl ContentSink for RecordingSink {
    fn write_chunk(&mut self, source: &[u8]) -> Result<(), FileCryptoError> {
        assert!(
            !self.committed && !self.aborted,
            "write after terminal state"
        );
        self.largest_chunk = self.largest_chunk.max(source.len());
        self.bytes.extend_from_slice(source);
        Ok(())
    }

    fn commit(&mut self) -> Result<(), FileCryptoError> {
        self.committed = true;
        Ok(())
    }

    fn abort(&mut self) -> Result<(), FileCryptoError> {
        self.aborted = true;
        self.bytes.clear();
        Ok(())
    }
}

pub fn sample(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed) ^ (index >> 8) as u8)
        .collect()
}
