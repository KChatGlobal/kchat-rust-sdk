use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use kchat_mobile_sdk_rs::{
    BackupCiphertextSink, BackupFfiError, BackupObjectContext, BackupPlaintextSource,
    generate_mnemonic, seal_backup_object_v1,
};

const ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";

#[test]
fn seals_opaque_bytes_through_bounded_foreign_callbacks() {
    let source = TestSource::new(vec![0xff, 0x00, 0xc3, 0x28]);
    let sink = TestSink::default();

    let metadata =
        seal_backup_object_v1(context(), Arc::new(source), Arc::new(sink.clone())).unwrap();

    assert_eq!(metadata.format_version, 1);
    assert_eq!(metadata.ciphertext_sha256.len(), 32);
    assert_eq!(metadata.ciphertext_size, sink.bytes().len() as u64);
    assert!(sink.largest_write() <= 65_536);
}

#[test]
fn returns_metadata_for_an_empty_source_only_after_the_final_block_is_written() {
    let sink = TestSink::default();

    let metadata = seal_backup_object_v1(
        context(),
        Arc::new(TestSource::empty()),
        Arc::new(sink.clone()),
    )
    .unwrap();

    assert_eq!(metadata.ciphertext_size, sink.bytes().len() as u64);
    assert!(!sink.bytes().is_empty());
}

#[test]
fn maps_callback_failure_to_io_error_without_metadata() {
    assert!(matches!(
        seal_backup_object_v1(
            context(),
            Arc::new(TestSource::empty()),
            Arc::new(FailingSink)
        ),
        Err(BackupFfiError::IoError)
    ));
}

#[test]
fn maps_a_sink_failure_after_partial_output_to_io_error() {
    let sink = Arc::new(FailingAfterFirstSink::default());

    assert!(matches!(
        seal_backup_object_v1(
            context(),
            Arc::new(TestSource::new(vec![1; 128])),
            sink.clone()
        ),
        Err(BackupFfiError::IoError)
    ));
    assert_eq!(sink.write_count.load(Ordering::Relaxed), 2);
}

#[test]
fn maps_source_callback_failure_to_io_error() {
    assert!(matches!(
        seal_backup_object_v1(
            context(),
            Arc::new(FailingSource),
            Arc::new(TestSink::default())
        ),
        Err(BackupFfiError::IoError)
    ));
}

#[test]
fn maps_cancellation_callback_failure_to_io_error() {
    assert!(matches!(
        seal_backup_object_v1(
            context(),
            Arc::new(FailingCancellationSource),
            Arc::new(TestSink::default()),
        ),
        Err(BackupFfiError::IoError)
    ));
}

#[test]
fn returns_cancelled_without_writing_when_the_source_is_cancelled() {
    let sink = TestSink::default();

    assert!(matches!(
        seal_backup_object_v1(context(), Arc::new(CancelledSource), Arc::new(sink.clone())),
        Err(BackupFfiError::Cancelled)
    ));
    assert!(sink.bytes().is_empty());
}

#[test]
fn rejects_callback_source_chunks_larger_than_the_requested_bound() {
    assert!(matches!(
        seal_backup_object_v1(
            context(),
            Arc::new(OversizedSource),
            Arc::new(TestSink::default()),
        ),
        Err(BackupFfiError::InvalidState)
    ));
}

fn context() -> Arc<BackupObjectContext> {
    let generated = generate_mnemonic().unwrap();
    let backup_id = generated.key.derive_backup_id(ACCOUNT.to_owned()).unwrap();
    generated
        .key
        .create_object_context(ACCOUNT.to_owned(), backup_id, vec![1; 16])
        .unwrap()
}

struct TestSource {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl TestSource {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Mutex::new(Some(bytes)),
        }
    }

    fn empty() -> Self {
        Self::new(Vec::new())
    }
}

impl BackupPlaintextSource for TestSource {
    fn read_chunk(&self, maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError> {
        assert_eq!(maximum_bytes, 65_536);
        Ok(self.bytes.lock().unwrap().take().unwrap_or_default())
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Ok(false)
    }
}

#[derive(Clone, Default)]
struct TestSink {
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl TestSink {
    fn bytes(&self) -> Vec<u8> {
        self.writes.lock().unwrap().concat()
    }

    fn largest_write(&self) -> usize {
        self.writes
            .lock()
            .unwrap()
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or_default()
    }
}

impl BackupCiphertextSink for TestSink {
    fn write_chunk(&self, bytes: Vec<u8>) -> Result<(), BackupFfiError> {
        self.writes.lock().unwrap().push(bytes);
        Ok(())
    }
}

struct FailingSink;

impl BackupCiphertextSink for FailingSink {
    fn write_chunk(&self, _bytes: Vec<u8>) -> Result<(), BackupFfiError> {
        Err(BackupFfiError::IoError)
    }
}

#[derive(Default)]
struct FailingAfterFirstSink {
    write_count: AtomicUsize,
}

impl BackupCiphertextSink for FailingAfterFirstSink {
    fn write_chunk(&self, _bytes: Vec<u8>) -> Result<(), BackupFfiError> {
        if self.write_count.fetch_add(1, Ordering::Relaxed) == 0 {
            Ok(())
        } else {
            Err(BackupFfiError::IoError)
        }
    }
}

struct FailingSource;

impl BackupPlaintextSource for FailingSource {
    fn read_chunk(&self, _maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError> {
        Err(BackupFfiError::IoError)
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Ok(false)
    }
}

struct FailingCancellationSource;

impl BackupPlaintextSource for FailingCancellationSource {
    fn read_chunk(&self, _maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError> {
        Ok(Vec::new())
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Err(BackupFfiError::IoError)
    }
}

struct CancelledSource;

impl BackupPlaintextSource for CancelledSource {
    fn read_chunk(&self, _maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError> {
        Ok(Vec::new())
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Ok(true)
    }
}

struct OversizedSource;

impl BackupPlaintextSource for OversizedSource {
    fn read_chunk(&self, maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError> {
        Ok(vec![0; maximum_bytes as usize + 1])
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Ok(false)
    }
}
