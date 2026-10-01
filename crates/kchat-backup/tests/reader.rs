//! Executable malformed fixtures for the reader foundation. Expected hashes are
//! intentionally recomputed for malformed envelopes so tests reach the parser/
//! AEAD layer rather than stopping at the inventory check every time.
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use kchat_backup::{
    BackupAccountId, BackupByteSink, BackupByteSource, BackupByteSourceFactory, BackupChunkId,
    BackupError, BackupErrorCode, BackupId, BackupObjectContextV1, BackupObjectValidatorV1,
    BackupObjectWriterV1, BackupValidationState, ExpectedBackupObjectV1,
    MAX_CIPHERTEXT_OBJECT_BYTES_V1, MAX_IO_CHUNK_BYTES_V1, MnemonicBackupKey, open_object_v1,
    verify_object_envelope_v1,
};
use sha2::{Digest, Sha256};

fn context(account: &str, key: u8, chunk: u8) -> BackupObjectContextV1 {
    let master = MnemonicBackupKey::import_from_raw(&[key; 32]).unwrap();
    let account = BackupAccountId::parse(account).unwrap();
    let namespace = BackupId::derive(&master, &account).unwrap();
    BackupObjectContextV1::new(
        &master,
        account,
        namespace,
        1,
        BackupChunkId::from_bytes([chunk; 16]).unwrap(),
    )
    .unwrap()
}

const ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";

#[derive(Default)]
struct Sink(Vec<u8>);
impl BackupByteSink for Sink {
    fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn seal(payload: &[u8]) -> Vec<u8> {
    let context = context(ACCOUNT, 3, 7);
    let mut sink = Sink::default();
    {
        let mut writer = BackupObjectWriterV1::new(&context, &mut sink).unwrap();
        writer.write_plaintext(payload).unwrap();
        writer.finish().unwrap();
    }
    sink.0
}

fn expected(bytes: &[u8]) -> ExpectedBackupObjectV1 {
    ExpectedBackupObjectV1::new(bytes.len() as u64, Sha256::digest(bytes).into(), 1).unwrap()
}

struct Source {
    bytes: Arc<[u8]>,
    offset: usize,
    max_read: usize,
    cancel_on_read: bool,
    cancelled: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}
impl BackupByteSource for Source {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError> {
        assert!(destination.len() <= MAX_IO_CHUNK_BYTES_V1);
        let count = destination
            .len()
            .min(self.max_read)
            .min(self.bytes.len() - self.offset);
        destination[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        if self.cancel_on_read {
            self.cancelled.store(true, Ordering::Relaxed);
        }
        Ok(count)
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

struct Factory {
    versions: VecDeque<Arc<[u8]>>,
    opens: usize,
    max_read: usize,
    cancel_on_read: bool,
    cancelled: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}
impl Factory {
    fn new(bytes: &[u8]) -> Self {
        let bytes: Arc<[u8]> = bytes.into();
        Self {
            versions: VecDeque::from([bytes.clone(), bytes.clone(), bytes]),
            opens: 0,
            max_read: usize::MAX,
            cancel_on_read: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicUsize::new(0)),
        }
    }
}
impl BackupByteSourceFactory for Factory {
    fn open(&mut self) -> Result<Box<dyn BackupByteSource>, BackupError> {
        self.opens += 1;
        let bytes = self
            .versions
            .pop_front()
            .ok_or_else(|| BackupError::from_code(BackupErrorCode::IoError))?;
        Ok(Box::new(Source {
            bytes,
            offset: 0,
            max_read: self.max_read,
            cancel_on_read: self.cancel_on_read,
            cancelled: self.cancelled.clone(),
            dropped: self.dropped.clone(),
        }))
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

fn verify(bytes: &[u8]) -> Result<(), BackupError> {
    verify_object_envelope_v1(
        &context(ACCOUNT, 3, 7),
        &mut Factory::new(bytes),
        &expected(bytes),
    )
}

fn noisy_payload() -> Vec<u8> {
    let mut state = 123_u64;
    (0..150_000)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 56) as u8
        })
        .collect()
}

fn frames(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut offset = 29;
    let mut result = Vec::new();
    while offset < bytes.len() {
        let size = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let end = offset + 4 + size;
        result.push(offset..end);
        offset = end;
    }
    result
}

#[test]
fn verifies_writer_output_with_empty_small_and_multiblock_payloads() {
    for payload in [
        vec![],
        b"opaque bytes, not canonical chat records".to_vec(),
        noisy_payload(),
    ] {
        let bytes = seal(&payload);
        let mut factory = Factory::new(&bytes);
        // Exercise short reads across header, length prefixes, data and tags.
        factory.max_read = 7;
        verify_object_envelope_v1(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
            .unwrap();
        assert_eq!(factory.opens, 2);
        assert_eq!(factory.dropped.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn rejects_inventory_mismatch_before_opening_the_decryption_pass() {
    let bytes = seal(b"private payload");
    for metadata in [
        ExpectedBackupObjectV1::new(bytes.len() as u64, [0; 32], 1).unwrap(),
        ExpectedBackupObjectV1::new(bytes.len() as u64 - 1, Sha256::digest(&bytes).into(), 1)
            .unwrap(),
        ExpectedBackupObjectV1::new(bytes.len() as u64 + 1, Sha256::digest(&bytes).into(), 1)
            .unwrap(),
    ] {
        let mut factory = Factory::new(&bytes);
        let error = verify_object_envelope_v1(&context(ACCOUNT, 3, 7), &mut factory, &metadata)
            .unwrap_err();
        assert_eq!(error.code(), BackupErrorCode::IntegrityMismatch);
        assert_eq!(factory.opens, 1);
        assert_eq!(factory.dropped.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn rejects_wrong_account_key_and_chunk_context() {
    let bytes = seal(b"payload");
    for wrong in [
        context("ffeeddcc-bbaa-9988-7766-554433221100", 3, 7),
        context(ACCOUNT, 4, 7),
        context(ACCOUNT, 3, 8),
    ] {
        let error = verify_object_envelope_v1(&wrong, &mut Factory::new(&bytes), &expected(&bytes))
            .unwrap_err();
        assert_eq!(error.code(), BackupErrorCode::AuthenticationFailed);
    }
}

#[test]
fn rejects_unsupported_header_fields() {
    for index in [0, 5, 7, 9] {
        let mut bytes = seal(b"payload");
        bytes[index] ^= 0x80;
        assert_eq!(
            verify(&bytes).unwrap_err().code(),
            BackupErrorCode::UnsupportedFormat
        );
    }
}

#[test]
fn rejects_nonce_ciphertext_and_tag_corruption_even_with_recomputed_inventory_hash() {
    let original = seal(&noisy_payload());
    let ranges = frames(&original);
    let mut indices = vec![10];
    for frame in ranges {
        indices.extend([frame.start + 4, frame.end - 1]);
    }
    for index in indices {
        let mut bytes = original.clone();
        bytes[index] ^= 1;
        assert_eq!(
            verify(&bytes).unwrap_err().code(),
            BackupErrorCode::AuthenticationFailed
        );
    }
}

#[test]
fn rejects_invalid_lengths_without_allocating_them() {
    for length in [0_u32, 15, 65_553, u32::MAX] {
        let mut bytes = seal(b"payload");
        bytes[29..33].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            verify(&bytes).unwrap_err().code(),
            BackupErrorCode::MalformedObject
        );
    }
}

#[test]
fn rejects_truncated_payload_and_partial_trailing_length() {
    let original = seal(&noisy_payload());
    let mut truncated = original.clone();
    truncated.pop();
    assert_eq!(
        verify(&truncated).unwrap_err().code(),
        BackupErrorCode::MalformedObject
    );
    for count in 1..=3 {
        let mut bytes = original.clone();
        bytes.extend(vec![0; count]);
        assert_eq!(
            verify(&bytes).unwrap_err().code(),
            BackupErrorCode::MalformedObject
        );
    }
}

#[test]
fn rejects_missing_final_swapped_and_duplicated_full_frames() {
    let bytes = seal(&noisy_payload());
    let ranges = frames(&bytes);
    assert!(ranges.len() >= 3);
    let without_final = &bytes[..ranges.last().unwrap().start];
    assert_eq!(
        verify(without_final).unwrap_err().code(),
        BackupErrorCode::AuthenticationFailed
    );

    let mut swapped = bytes[..29].to_vec();
    swapped.extend_from_slice(&bytes[ranges[1].clone()]);
    swapped.extend_from_slice(&bytes[ranges[0].clone()]);
    swapped.extend_from_slice(&bytes[ranges[2].start..]);
    assert_eq!(
        verify(&swapped).unwrap_err().code(),
        BackupErrorCode::AuthenticationFailed
    );

    let mut duplicated = bytes[..ranges[1].start].to_vec();
    duplicated.extend_from_slice(&bytes[ranges[0].clone()]);
    duplicated.extend_from_slice(&bytes[ranges[1].start..]);
    assert_eq!(
        verify(&duplicated).unwrap_err().code(),
        BackupErrorCode::AuthenticationFailed
    );
}

#[test]
fn rejects_complete_frame_after_final() {
    let mut bytes = seal(b"payload");
    bytes.extend_from_slice(&16_u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 16]);
    assert_eq!(
        verify(&bytes).unwrap_err().code(),
        BackupErrorCode::MalformedObject
    );
}

#[test]
fn rechecks_reopened_object_even_when_both_versions_have_valid_aead() {
    let first = seal(b"same content");
    let second = seal(b"same content");
    assert_eq!(first.len(), second.len());
    let mut factory = Factory::new(&first);
    factory.versions[1] = second.into();
    let error = verify_object_envelope_v1(&context(ACCOUNT, 3, 7), &mut factory, &expected(&first))
        .unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::IntegrityMismatch);
    assert_eq!(factory.dropped.load(Ordering::Relaxed), 2);
}

#[test]
fn integrity_failure_is_terminal_and_never_releases_plaintext() {
    let mut bytes = seal(b"sensitive plaintext");
    bytes[33] ^= 1;
    let mut validator = BackupObjectValidatorV1::new();
    let mut factory = Factory::new(&bytes);
    assert_eq!(validator.state(), BackupValidationState::Ready);
    let error = validator
        .validate(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
        .unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::AuthenticationFailed);
    assert_eq!(validator.state(), BackupValidationState::Failed);
    assert_eq!(
        validator
            .validate(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidState
    );
    assert_eq!(
        validator.cancel().unwrap_err().code(),
        BackupErrorCode::InvalidState
    );

    let mut sink = Sink::default();
    let error = open_object_v1(
        &context(ACCOUNT, 3, 7),
        &mut Factory::new(&bytes),
        &expected(&bytes),
        &mut sink,
    )
    .unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::AuthenticationFailed);
    assert!(sink.0.is_empty());
}

#[test]
fn cancellation_is_terminal_and_releases_open_sources() {
    let bytes = seal(b"payload");
    for before_open in [true, false] {
        let mut factory = Factory::new(&bytes);
        factory.cancelled.store(before_open, Ordering::Relaxed);
        factory.cancel_on_read = !before_open;
        let mut validator = BackupObjectValidatorV1::new();
        let error = validator
            .validate(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
            .unwrap_err();
        assert_eq!(error.code(), BackupErrorCode::Cancelled);
        assert_eq!(validator.state(), BackupValidationState::Cancelled);
        assert_eq!(factory.dropped.load(Ordering::Relaxed), factory.opens);
        assert_eq!(factory.opens, if before_open { 0 } else { 1 });
    }
    let mut validator = BackupObjectValidatorV1::new();
    validator.cancel().unwrap();
    let mut factory = Factory::new(&bytes);
    assert_eq!(
        validator
            .validate(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidState
    );
    assert_eq!(factory.opens, 0);
}

#[test]
fn propagates_reopen_failure_without_reporting_success() {
    let bytes = seal(b"payload");
    let mut factory = Factory::new(&bytes);
    factory.versions.truncate(1);
    let error = verify_object_envelope_v1(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
        .unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::IoError);
    assert_eq!(factory.dropped.load(Ordering::Relaxed), 1);
}

#[test]
fn rejects_invalid_inventory_before_io() {
    assert!(
        matches!(ExpectedBackupObjectV1::new(49, [0; 32], 2), Err(e) if e.code() == BackupErrorCode::UnsupportedFormat)
    );
    assert!(
        matches!(ExpectedBackupObjectV1::new(48, [0; 32], 1), Err(e) if e.code() == BackupErrorCode::InvalidArgument)
    );
    assert!(
        matches!(ExpectedBackupObjectV1::new(MAX_CIPHERTEXT_OBJECT_BYTES_V1 + 1, [0; 32], 1), Err(e) if e.code() == BackupErrorCode::ResourceLimitExceeded)
    );
}

#[test]
fn handles_callback_faults_without_panicking_or_exposing_plaintext() {
    struct FaultySource(bool);
    impl BackupByteSource for FaultySource {
        fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError> {
            if self.0 {
                Ok(destination.len() + 1)
            } else {
                Err(BackupError::from_code(BackupErrorCode::IoError))
            }
        }
    }
    struct FaultyFactory(bool);
    impl BackupByteSourceFactory for FaultyFactory {
        fn open(&mut self) -> Result<Box<dyn BackupByteSource>, BackupError> {
            Ok(Box::new(FaultySource(self.0)))
        }
    }
    let bytes = seal(b"payload");
    for (bad_count, code) in [
        (true, BackupErrorCode::InvalidState),
        (false, BackupErrorCode::IoError),
    ] {
        let mut sink = Sink::default();
        let error = open_object_v1(
            &context(ACCOUNT, 3, 7),
            &mut FaultyFactory(bad_count),
            &expected(&bytes),
            &mut sink,
        )
        .unwrap_err();
        assert_eq!(error.code(), code);
        assert!(sink.0.is_empty());
    }
}

#[test]
fn cancellation_after_reopen_drops_the_second_handle() {
    struct CancelsOnReopen(Factory);
    impl BackupByteSourceFactory for CancelsOnReopen {
        fn open(&mut self) -> Result<Box<dyn BackupByteSource>, BackupError> {
            let source = self.0.open()?;
            if self.0.opens == 2 {
                self.0.cancelled.store(true, Ordering::Relaxed);
            }
            Ok(source)
        }
        fn is_cancelled(&self) -> bool {
            self.0.is_cancelled()
        }
    }
    let bytes = seal(b"payload");
    let mut factory = CancelsOnReopen(Factory::new(&bytes));
    let error = verify_object_envelope_v1(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
        .unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::Cancelled);
    assert_eq!(factory.0.opens, 2);
    assert_eq!(factory.0.dropped.load(Ordering::Relaxed), 2);
}

#[test]
fn rejects_each_truncation_point_of_a_small_object() {
    let original = seal(b"some canonical-looking but opaque bytes");
    for end in 0..original.len() {
        let bytes = &original[..end];
        let metadata =
            ExpectedBackupObjectV1::new(bytes.len() as u64, Sha256::digest(bytes).into(), 1);
        match metadata {
            Err(e) => assert_eq!(e.code(), BackupErrorCode::InvalidArgument),
            Ok(metadata) => {
                assert!(
                    verify_object_envelope_v1(
                        &context(ACCOUNT, 3, 7),
                        &mut Factory::new(bytes),
                        &metadata
                    )
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn opens_opaque_writer_objects_without_schema_validation() {
    for plaintext in [
        vec![],
        b"opaque payload".to_vec(),
        noisy_payload(),
        vec![42; 300_000],
    ] {
        let bytes = seal(&plaintext);
        let mut factory = Factory::new(&bytes);
        factory.max_read = 11;
        let mut sink = Sink::default();
        open_object_v1(
            &context(ACCOUNT, 3, 7),
            &mut factory,
            &expected(&bytes),
            &mut sink,
        )
        .unwrap();
        assert_eq!(sink.0, plaintext);
        assert_eq!(factory.opens, 3);
        assert_eq!(factory.dropped.load(Ordering::Relaxed), 3);
    }
}

#[test]
fn validator_completes_once_without_opening_an_output_pass() {
    let bytes = seal(b"payload");
    let mut factory = Factory::new(&bytes);
    let mut validator = BackupObjectValidatorV1::new();
    validator
        .validate(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
        .unwrap();
    assert_eq!(validator.state(), BackupValidationState::Completed);
    assert_eq!(factory.opens, 2);
    assert_eq!(
        validator
            .validate(&context(ACCOUNT, 3, 7), &mut factory, &expected(&bytes))
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidState
    );
}

#[test]
fn changed_output_replay_header_or_first_frame_never_reaches_sink() {
    let bytes = seal(b"payload");
    let mut changed_frame = bytes.clone();
    changed_frame[33] ^= 1;
    for changed in [seal(b"payload"), changed_frame] {
        let mut factory = Factory::new(&bytes);
        factory.versions[2] = changed.into();
        let mut sink = Sink::default();
        let error = open_object_v1(
            &context(ACCOUNT, 3, 7),
            &mut factory,
            &expected(&bytes),
            &mut sink,
        )
        .unwrap_err();
        assert_eq!(error.code(), BackupErrorCode::IntegrityMismatch);
        assert!(sink.0.is_empty());
        assert_eq!(factory.dropped.load(Ordering::Relaxed), 3);
    }
}

#[test]
fn changed_late_output_frame_can_only_leave_a_prevalidated_prefix() {
    let plaintext = noisy_payload();
    let bytes = seal(&plaintext);
    let mut changed = bytes.clone();
    let last = frames(&bytes).last().unwrap().clone();
    changed[last.start + 4] ^= 1;
    let mut factory = Factory::new(&bytes);
    factory.versions[2] = changed.into();
    let mut sink = Sink::default();
    let error = open_object_v1(
        &context(ACCOUNT, 3, 7),
        &mut factory,
        &expected(&bytes),
        &mut sink,
    )
    .unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::IntegrityMismatch);
    assert!(sink.0.len() < plaintext.len());
    assert_eq!(sink.0, plaintext[..sink.0.len()]);
}

#[test]
fn sink_errors_are_propagated() {
    struct FailingSink(usize);
    impl BackupByteSink for FailingSink {
        fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
            assert!(bytes.len() <= MAX_IO_CHUNK_BYTES_V1);
            self.0 += 1;
            Err(BackupError::from_code(BackupErrorCode::IoError))
        }
    }
    let bytes = seal(b"payload");
    let mut sink = FailingSink(0);
    let mut factory = Factory::new(&bytes);
    assert_eq!(
        open_object_v1(
            &context(ACCOUNT, 3, 7),
            &mut factory,
            &expected(&bytes),
            &mut sink
        )
        .unwrap_err()
        .code(),
        BackupErrorCode::IoError
    );
    assert_eq!(sink.0, 1);
    assert_eq!(factory.dropped.load(Ordering::Relaxed), 3);
}

#[test]
fn cancellation_inside_output_stops_without_more_callbacks() {
    struct CancelSink(Arc<AtomicBool>, usize);
    impl BackupByteSink for CancelSink {
        fn write_chunk(&mut self, _: &[u8]) -> Result<(), BackupError> {
            self.1 += 1;
            self.0.store(true, Ordering::Relaxed);
            Ok(())
        }
    }
    let plaintext = vec![42; 300_000];
    let bytes = seal(&plaintext);
    let mut factory = Factory::new(&bytes);
    let mut sink = CancelSink(factory.cancelled.clone(), 0);
    assert_eq!(
        open_object_v1(
            &context(ACCOUNT, 3, 7),
            &mut factory,
            &expected(&bytes),
            &mut sink
        )
        .unwrap_err()
        .code(),
        BackupErrorCode::Cancelled
    );
    assert_eq!(sink.1, 1);
}
