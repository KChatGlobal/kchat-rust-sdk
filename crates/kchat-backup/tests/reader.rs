use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use kchat_backup::{
    BackupAccountId, BackupByteSink, BackupByteSource, BackupChunkId, BackupError, BackupErrorCode,
    BackupId, BackupObjectContextV1, BackupObjectWriterV1, MAX_IO_CHUNK_BYTES_V1,
    MnemonicBackupKey, open_object_v1,
};

fn context(account: &str, key: u8, chunk: u8) -> BackupObjectContextV1 {
    let master = MnemonicBackupKey::import_from_raw(&[key; 32]).unwrap();
    let account = BackupAccountId::parse(account).unwrap();
    let namespace = BackupId::derive(&master, &account).unwrap();
    BackupObjectContextV1::new(
        &master,
        account,
        namespace,
        1,
        BackupChunkId::from_bytes([chunk; 32]).unwrap(),
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

struct Source {
    bytes: Arc<[u8]>,
    offset: usize,
    eof_reads: usize,
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
        if count == 0 {
            self.eof_reads += 1;
            assert_eq!(self.eof_reads, 1, "source must not be read again after EOF");
        }
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

impl Source {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
            offset: 0,
            eof_reads: 0,
            max_read: usize::MAX,
            cancel_on_read: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicUsize::new(0)),
        }
    }
}

fn open_discarding_output(
    context: &BackupObjectContextV1,
    source: &mut dyn BackupByteSource,
) -> Result<(), BackupError> {
    struct DiscardSink;
    impl BackupByteSink for DiscardSink {
        fn write_chunk(&mut self, _: &[u8]) -> Result<(), BackupError> {
            Ok(())
        }
    }
    open_object_v1(context, source, &mut DiscardSink)
}

fn open_bytes(bytes: &[u8]) -> Result<(), BackupError> {
    open_discarding_output(&context(ACCOUNT, 3, 7), &mut Source::new(bytes))
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
fn validates_writer_output_with_empty_small_and_multiblock_payloads() {
    for payload in [
        vec![],
        b"opaque bytes, not canonical chat records".to_vec(),
        noisy_payload(),
    ] {
        let bytes = seal(&payload);
        let mut source = Source::new(&bytes);
        source.max_read = 7;
        open_discarding_output(&context(ACCOUNT, 3, 7), &mut source).unwrap();
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
        let error = open_discarding_output(&wrong, &mut Source::new(&bytes)).unwrap_err();
        assert_eq!(error.code(), BackupErrorCode::AuthenticationFailed);
    }
}

#[test]
fn rejects_unsupported_header_fields() {
    for index in [0, 5, 7, 9] {
        let mut bytes = seal(b"payload");
        bytes[index] ^= 0x80;
        assert_eq!(
            open_bytes(&bytes).unwrap_err().code(),
            BackupErrorCode::UnsupportedFormat
        );
    }
}

#[test]
fn rejects_nonce_ciphertext_and_tag_corruption_without_inventory_metadata() {
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
            open_bytes(&bytes).unwrap_err().code(),
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
            open_bytes(&bytes).unwrap_err().code(),
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
        open_bytes(&truncated).unwrap_err().code(),
        BackupErrorCode::MalformedObject
    );
    for count in 1..=3 {
        let mut bytes = original.clone();
        bytes.extend(vec![0; count]);
        assert_eq!(
            open_bytes(&bytes).unwrap_err().code(),
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
        open_bytes(without_final).unwrap_err().code(),
        BackupErrorCode::AuthenticationFailed
    );

    let mut swapped = bytes[..29].to_vec();
    swapped.extend_from_slice(&bytes[ranges[1].clone()]);
    swapped.extend_from_slice(&bytes[ranges[0].clone()]);
    swapped.extend_from_slice(&bytes[ranges[2].start..]);
    assert_eq!(
        open_bytes(&swapped).unwrap_err().code(),
        BackupErrorCode::AuthenticationFailed
    );

    let mut duplicated = bytes[..ranges[1].start].to_vec();
    duplicated.extend_from_slice(&bytes[ranges[0].clone()]);
    duplicated.extend_from_slice(&bytes[ranges[1].start..]);
    assert_eq!(
        open_bytes(&duplicated).unwrap_err().code(),
        BackupErrorCode::AuthenticationFailed
    );
}

#[test]
fn rejects_complete_frame_after_final() {
    let mut bytes = seal(b"payload");
    bytes.extend_from_slice(&16_u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 16]);
    assert_eq!(
        open_bytes(&bytes).unwrap_err().code(),
        BackupErrorCode::MalformedObject
    );
}

#[test]
fn authentication_failure_never_releases_plaintext() {
    let mut bytes = seal(b"sensitive plaintext");
    bytes[33] ^= 1;
    let mut sink = Sink::default();
    let error =
        open_object_v1(&context(ACCOUNT, 3, 7), &mut Source::new(&bytes), &mut sink).unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::AuthenticationFailed);
    assert!(sink.0.is_empty());
}

#[test]
fn cancellation_before_or_during_read_stops_without_output() {
    let bytes = seal(b"payload");
    for before_read in [true, false] {
        let mut source = Source::new(&bytes);
        source.cancelled.store(before_read, Ordering::Relaxed);
        source.cancel_on_read = !before_read;
        let mut sink = Sink::default();
        let error = open_object_v1(&context(ACCOUNT, 3, 7), &mut source, &mut sink).unwrap_err();
        assert_eq!(error.code(), BackupErrorCode::Cancelled);
        assert_eq!(source.offset == 0, before_read);
        assert!(sink.0.is_empty());
    }
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
    for (bad_count, code) in [
        (true, BackupErrorCode::InvalidState),
        (false, BackupErrorCode::IoError),
    ] {
        let mut sink = Sink::default();
        let error = open_object_v1(
            &context(ACCOUNT, 3, 7),
            &mut FaultySource(bad_count),
            &mut sink,
        )
        .unwrap_err();
        assert_eq!(error.code(), code);
        assert!(sink.0.is_empty());
    }
}

#[test]
fn rejects_each_truncation_point_of_a_small_object() {
    let original = seal(b"some canonical-looking but opaque bytes");
    for end in 0..original.len() {
        assert!(
            open_bytes(&original[..end]).is_err(),
            "accepted truncation at {end}"
        );
    }
}

#[test]
fn opens_opaque_writer_objects_reading_each_byte_once() {
    for plaintext in [
        vec![],
        b"opaque payload".to_vec(),
        noisy_payload(),
        vec![42; 300_000],
    ] {
        let bytes = seal(&plaintext);
        let mut source = Source::new(&bytes);
        source.max_read = 11;
        let mut sink = Sink::default();
        open_object_v1(&context(ACCOUNT, 3, 7), &mut source, &mut sink).unwrap();
        assert_eq!(sink.0, plaintext);
        assert_eq!(source.offset, bytes.len());
        assert_eq!(source.eof_reads, 1);
        assert_eq!(source.dropped.load(Ordering::Relaxed), 0);
        let dropped = source.dropped.clone();
        drop(source);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn corrupted_nonce_or_first_frame_never_reaches_sink() {
    let bytes = seal(b"payload");
    for index in [10, 33, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        let mut source = Source::new(&changed);
        let mut sink = Sink::default();
        let error = open_object_v1(&context(ACCOUNT, 3, 7), &mut source, &mut sink).unwrap_err();
        assert_eq!(error.code(), BackupErrorCode::AuthenticationFailed);
        assert!(sink.0.is_empty());
    }
}

#[test]
fn opens_each_authenticated_object_for_the_same_context_without_inventory_metadata() {
    for payload in [b"payload-A", b"payload-B"] {
        let ciphertext = seal(payload);
        let mut source = Source::new(&ciphertext);
        let mut sink = Sink::default();
        open_object_v1(&context(ACCOUNT, 3, 7), &mut source, &mut sink).unwrap();
        assert_eq!(sink.0, payload);
    }
}

#[test]
fn corrupted_late_frame_leaves_only_an_authenticated_prefix() {
    let plaintext = noisy_payload();
    let bytes = seal(&plaintext);
    let mut changed = bytes.clone();
    let last = frames(&bytes).last().unwrap().clone();
    changed[last.start + 4] ^= 1;
    let mut source = Source::new(&changed);
    let mut sink = Sink::default();
    let error = open_object_v1(&context(ACCOUNT, 3, 7), &mut source, &mut sink).unwrap_err();
    assert_eq!(error.code(), BackupErrorCode::AuthenticationFailed);
    assert!(!sink.0.is_empty());
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
    let mut source = Source::new(&bytes);
    assert_eq!(
        open_object_v1(&context(ACCOUNT, 3, 7), &mut source, &mut sink)
            .unwrap_err()
            .code(),
        BackupErrorCode::IoError
    );
    assert_eq!(sink.0, 1);
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
    let mut source = Source::new(&bytes);
    let mut sink = CancelSink(source.cancelled.clone(), 0);
    assert_eq!(
        open_object_v1(&context(ACCOUNT, 3, 7), &mut source, &mut sink)
            .unwrap_err()
            .code(),
        BackupErrorCode::Cancelled
    );
    assert_eq!(sink.1, 1);
}
