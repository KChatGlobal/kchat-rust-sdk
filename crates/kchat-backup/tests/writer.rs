use kchat_backup::{
    BackupAccountId, BackupByteSink, BackupByteSource, BackupChunkId, BackupErrorCode,
    MnemonicBackupKey, BackupNamespaceId, BackupObjectContextV1, BackupObjectWriterV1,
    seal_object_v1,
};
use sha2::{Digest, Sha256};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

struct Source {
    bytes: Vec<u8>,
    offset: usize,
}

struct CancelledSource;

struct CancelsAfterFirstRead {
    read_once: bool,
}

impl BackupByteSource for CancelledSource {
    fn read_chunk(&mut self, _: &mut [u8]) -> Result<usize, kchat_backup::BackupError> {
        Ok(0)
    }

    fn is_cancelled(&self) -> bool {
        true
    }
}

impl BackupByteSource for CancelsAfterFirstRead {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, kchat_backup::BackupError> {
        if self.read_once {
            return Ok(0);
        }
        destination[..4].copy_from_slice(b"data");
        self.read_once = true;
        Ok(4)
    }

    fn is_cancelled(&self) -> bool {
        self.read_once
    }
}

impl BackupByteSource for Source {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, kchat_backup::BackupError> {
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(destination.len());
        destination[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        Ok(count)
    }
}

#[derive(Default)]
struct Sink(Vec<u8>);

impl BackupByteSink for Sink {
    fn write_chunk(&mut self, source: &[u8]) -> Result<(), kchat_backup::BackupError> {
        self.0.extend_from_slice(source);
        Ok(())
    }
}

struct FailingSink {
    writes: usize,
}

impl BackupByteSink for FailingSink {
    fn write_chunk(&mut self, _: &[u8]) -> Result<(), kchat_backup::BackupError> {
        self.writes += 1;
        Err(MnemonicBackupKey::from_mnemonic("not a valid mnemonic").unwrap_err())
    }
}

fn context() -> BackupObjectContextV1 {
    let master_key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let namespace = BackupNamespaceId::derive(&master_key, &account).unwrap();
    let chunk_id = BackupChunkId::from_bytes([7; 16]).unwrap();
    BackupObjectContextV1::new(&master_key, account, namespace, 1, chunk_id).unwrap()
}

#[test]
fn seals_an_opaque_object_with_the_fixed_v1_envelope() {
    let mut source = Source {
        bytes: b"opaque client-owned bytes".to_vec(),
        offset: 0,
    };
    let mut sink = Sink::default();

    let descriptor = seal_object_v1(&context(), &mut source, &mut sink).unwrap();

    assert_eq!(&sink.0[..4], b"KCBK");
    assert_eq!(&sink.0[4..6], &[0, 1]);
    assert_eq!(&sink.0[6..8], &[0, 1]);
    assert_eq!(&sink.0[8..10], &[0, 1]);
    assert!(sink.0.len() >= 29 + 4 + 16);
    assert_eq!(descriptor.ciphertext_size(), sink.0.len() as u64);
    let expected_hash: [u8; 32] = Sha256::digest(&sink.0).into();
    assert_eq!(descriptor.ciphertext_sha256(), &expected_hash);
    assert_eq!(descriptor.format_version(), 1);
}

#[test]
fn never_returns_a_descriptor_after_a_sink_failure() {
    let mut source = Source {
        bytes: b"opaque client-owned bytes".to_vec(),
        offset: 0,
    };
    let mut sink = FailingSink { writes: 0 };

    let error = seal_object_v1(&context(), &mut source, &mut sink).unwrap_err();

    assert_eq!(error.code(), BackupErrorCode::InvalidMnemonic);
    assert_eq!(sink.writes, 1);
}

#[test]
fn returns_cancelled_without_finalizing_when_the_source_cancels() {
    let mut source = CancelledSource;
    let mut sink = Sink::default();

    let error = seal_object_v1(&context(), &mut source, &mut sink).unwrap_err();

    assert_eq!(error.code(), BackupErrorCode::Cancelled);
    assert!(sink.0.is_empty());
}

#[test]
fn cancellation_after_a_source_read_does_not_write_a_final_block() {
    let mut source = CancelsAfterFirstRead { read_once: false };
    let mut sink = Sink::default();

    let error = seal_object_v1(&context(), &mut source, &mut sink).unwrap_err();

    assert_eq!(error.code(), BackupErrorCode::Cancelled);
    assert_eq!(sink.0.len(), 29);
}

#[test]
fn frames_full_compressed_blocks_before_one_authenticated_final_block() {
    let mut state = 0x0123_4567_89ab_cdef_u64;
    let bytes = (0..(2 * 65_536))
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 56) as u8
        })
        .collect();
    let mut source = Source { bytes, offset: 0 };
    let mut sink = Sink::default();

    seal_object_v1(&context(), &mut source, &mut sink).unwrap();

    let mut offset = 29;
    let mut lengths = Vec::new();
    while offset < sink.0.len() {
        let length = u32::from_be_bytes(sink.0[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + length;
        lengths.push(length);
    }
    assert_eq!(offset, sink.0.len());
    assert!(lengths.len() >= 2);
    assert!(
        lengths[..lengths.len() - 1]
            .iter()
            .all(|length| *length == 65_552)
    );
    assert!((16..=65_552).contains(lengths.last().unwrap()));
}

#[test]
fn independent_encryptions_use_fresh_nonce_prefixes() {
    let plaintext = b"same opaque client-owned bytes".to_vec();
    let mut first_source = Source {
        bytes: plaintext.clone(),
        offset: 0,
    };
    let mut second_source = Source {
        bytes: plaintext,
        offset: 0,
    };
    let mut first_sink = Sink::default();
    let mut second_sink = Sink::default();
    let context = context();

    seal_object_v1(&context, &mut first_source, &mut first_sink).unwrap();
    seal_object_v1(&context, &mut second_source, &mut second_sink).unwrap();

    assert_ne!(&first_sink.0[10..29], &second_sink.0[10..29]);
    assert_ne!(first_sink.0, second_sink.0);
}

#[test]
fn rejects_writes_and_finish_after_abort() {
    let mut sink = Sink::default();
    let context = context();
    let mut writer = BackupObjectWriterV1::new(&context, &mut sink).unwrap();

    writer.abort().unwrap();

    assert_eq!(
        writer
            .write_plaintext(b"must not encrypt")
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidState
    );
    assert_eq!(
        writer.finish().unwrap_err().code(),
        BackupErrorCode::InvalidState
    );
}

#[test]
fn rejects_writes_and_a_second_finish_after_successful_finish() {
    let mut sink = Sink::default();
    let context = context();
    let mut writer = BackupObjectWriterV1::new(&context, &mut sink).unwrap();

    writer
        .write_plaintext(b"opaque client-owned bytes")
        .unwrap();
    writer.finish().unwrap();

    assert_eq!(
        writer
            .write_plaintext(b"must not encrypt")
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidState
    );
    assert_eq!(
        writer.finish().unwrap_err().code(),
        BackupErrorCode::InvalidState
    );
}
