//! End-to-end example: create a backup-set descriptor, encrypt JSON, and store the
//! descriptor, ciphertext, and inventory metadata on a simulated server. Then use
//! the descriptor to construct the context, verify the object, and restore the
//! original bytes.

use std::sync::Arc;

use kchat_backup::{
    BackupAccountId, BackupByteSink, BackupByteSource, BackupByteSourceFactory, BackupChunkId,
    BackupError, BackupId, BackupObjectContextV1, DescriptorBackupModeV1, DescriptorHeaderV1,
    ExpectedBackupObjectV1, MnemonicBackupKey, open_descriptor_v1, open_object_v1,
    seal_descriptor_v1, seal_object_v1,
};
use sha2::{Digest, Sha256};

const JSON: &[u8] = br#"{"name": "alice", "age":18}"#;
const ACCOUNT_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
// This fixed master key is for testing only and must not be used for real backups.
const TEST_MASTER_KEY: [u8; 32] = [0x5a; 32];
const CHUNK_ID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x40, 0xde, 0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
];

fn object_context(
    master: &MnemonicBackupKey,
    account: BackupAccountId,
    backup_id: BackupId,
) -> BackupObjectContextV1 {
    let chunk = BackupChunkId::from_bytes(CHUNK_ID).unwrap();
    BackupObjectContextV1::new(master, account, backup_id, 1, chunk).unwrap()
}

struct MemorySource {
    bytes: Arc<[u8]>,
    offset: usize,
}

impl BackupByteSource for MemorySource {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError> {
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(destination.len());
        destination[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        Ok(count)
    }
}

#[derive(Default)]
struct MemorySink(Vec<u8>);

impl BackupByteSink for MemorySink {
    fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

// Simulates an immutable committed object. The server stores only ciphertext and
// metadata, never plaintext or keys. A real system also stores the chunk ID and generation.
struct StoredChunk {
    descriptor: Arc<[u8]>,
    ciphertext: Arc<[u8]>,
    ciphertext_size: u64,
    ciphertext_sha256: [u8; 32],
    format_version: u16,
    opens: usize,
}

impl BackupByteSourceFactory for StoredChunk {
    fn open(&mut self) -> Result<Box<dyn BackupByteSource>, BackupError> {
        self.opens += 1;
        Ok(Box::new(MemorySource {
            bytes: Arc::clone(&self.ciphertext),
            offset: 0,
        }))
    }
}

#[test]
fn encrypt_upload_download_verify_and_decrypt_json() {
    let backup_master = MnemonicBackupKey::import_from_raw(&TEST_MASTER_KEY).unwrap();
    let backup_account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let backup_id = BackupId::derive(&backup_master, &backup_account).unwrap();

    // The client initializes the backup set. The KCBD descriptor is encrypted with
    // a dedicated key derived from the master key and account. The server stores
    // only the resulting descriptor blob.
    let sealed_descriptor = seal_descriptor_v1(
        &backup_master,
        &backup_account,
        DescriptorHeaderV1::mnemonic(),
    )
    .unwrap();
    assert_eq!(sealed_descriptor.len(), 110);
    assert_eq!(&sealed_descriptor[..4], b"KCBD");

    // The client reads the JSON, compresses it with Zstd, and encrypts it into a
    // KCBK object in upload_sink.
    let mut plaintext_source = MemorySource {
        bytes: Arc::from(JSON),
        offset: 0,
    };
    let mut upload_sink = MemorySink::default();
    let backup_context = object_context(&backup_master, backup_account, backup_id);
    let writer_metadata =
        seal_object_v1(&backup_context, &mut plaintext_source, &mut upload_sink).unwrap();

    assert_eq!(&upload_sink.0[..4], b"KCBK");
    println!("Plain-text: {:?}", JSON.len());
    println!("Cipher: {:?}", upload_sink.0.len());
    assert_ne!(upload_sink.0.as_slice(), JSON);
    assert_eq!(
        writer_metadata.ciphertext_size(),
        upload_sink.0.len() as u64
    );
    assert_eq!(
        writer_metadata.ciphertext_sha256(),
        &<[u8; 32]>::from(Sha256::digest(&upload_sink.0))
    );

    // Simulate upload and commit: the server stores the backup-set descriptor and
    // ciphertext together with its size, hash, and version. This test uses memory
    // and performs no network I/O.
    let mut server = StoredChunk {
        descriptor: sealed_descriptor.into(),
        ciphertext: upload_sink.0.into(),
        ciphertext_size: writer_metadata.ciphertext_size(),
        ciphertext_sha256: *writer_metadata.ciphertext_sha256(),
        format_version: writer_metadata.format_version(),
        opens: 0,
    };

    // In a new session, the restoring client reconstructs the recovery key, then
    // downloads and opens the descriptor to authenticate the account/key and obtain
    // the BackupId. It uses that BackupId to construct the object context for the
    // chunk listed in the inventory.
    let restore_master = MnemonicBackupKey::import_from_raw(&TEST_MASTER_KEY).unwrap();
    let restore_account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let (descriptor_header, restore_backup_id) =
        open_descriptor_v1(&restore_master, &restore_account, &server.descriptor).unwrap();
    assert_eq!(
        descriptor_header.backup_mode(),
        DescriptorBackupModeV1::Mnemonic
    );
    assert_eq!(restore_backup_id, backup_id);
    let restore_context = object_context(&restore_master, restore_account, restore_backup_id);

    // The expected size, hash, and version come from the server's committed inventory.
    let expected = ExpectedBackupObjectV1::new(
        server.ciphertext_size,
        server.ciphertext_sha256,
        server.format_version,
    )
    .unwrap();
    let mut restore_sink = MemorySink::default();
    open_object_v1(&restore_context, &mut server, &expected, &mut restore_sink).unwrap();

    // The reader opens the object three times: size/hash preflight, full validation,
    // and plaintext output.
    assert_eq!(server.opens, 3);
    assert_eq!(restore_sink.0, JSON);
}
