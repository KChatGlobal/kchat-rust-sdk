use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use kchat_mobile_sdk_rs::backup::{
    BackupCiphertextSink, BackupCiphertextSource, BackupCiphertextSourceFactory, BackupFfiError,
    BackupKeyMode, BackupMasterKey, BackupObjectContext, BackupObjectMetadata, BackupPlaintextSink,
    BackupPlaintextSource, generate_mnemonic, import_from_raw, open_backup_object_v1,
    seal_backup_object_v1,
};

const ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";
const JSON: &[u8] = br#"{"name": "alice", "age":18}"#;

struct PlaintextSource(Mutex<Option<Vec<u8>>>);

impl BackupPlaintextSource for PlaintextSource {
    fn read_chunk(&self, _maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError> {
        Ok(self.0.lock().unwrap().take().unwrap_or_default())
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Ok(false)
    }
}

#[derive(Default)]
struct CiphertextSink(Mutex<Vec<u8>>);

impl BackupCiphertextSink for CiphertextSink {
    fn write_chunk(&self, bytes: Vec<u8>) -> Result<(), BackupFfiError> {
        self.0.lock().unwrap().extend(bytes);
        Ok(())
    }
}

struct CiphertextSource {
    bytes: Arc<[u8]>,
    offset: Mutex<usize>,
    closes: Arc<AtomicUsize>,
}

impl BackupCiphertextSource for CiphertextSource {
    fn read_chunk(&self, maximum_bytes: u32) -> Result<Vec<u8>, BackupFfiError> {
        let mut offset = self.offset.lock().unwrap();
        let count = (self.bytes.len() - *offset)
            .min(maximum_bytes as usize)
            .min(7); // Exercise short foreign callback reads.
        let bytes = self.bytes[*offset..*offset + count].to_vec();
        *offset += count;
        Ok(bytes)
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Ok(false)
    }

    fn release_stream(&self) -> Result<(), BackupFfiError> {
        self.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct SourceFactory {
    bytes: Arc<[u8]>,
    opens: AtomicUsize,
    closes: Arc<AtomicUsize>,
}

impl SourceFactory {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
            opens: AtomicUsize::new(0),
            closes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl BackupCiphertextSourceFactory for SourceFactory {
    fn open(&self) -> Result<Arc<dyn BackupCiphertextSource>, BackupFfiError> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(CiphertextSource {
            bytes: Arc::clone(&self.bytes),
            offset: Mutex::new(0),
            closes: Arc::clone(&self.closes),
        }))
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Ok(false)
    }
}

#[derive(Default)]
struct PlaintextSink(Mutex<Vec<u8>>);

impl BackupPlaintextSink for PlaintextSink {
    fn write_chunk(&self, bytes: Vec<u8>) -> Result<(), BackupFfiError> {
        self.0.lock().unwrap().extend(bytes);
        Ok(())
    }
}

fn context() -> (Arc<BackupMasterKey>, Arc<BackupObjectContext>) {
    let generated = generate_mnemonic(24).unwrap();
    let backup_id = generated.key.derive_backup_id(ACCOUNT.to_owned()).unwrap();
    let context = generated
        .key
        .create_object_context(ACCOUNT.to_owned(), backup_id, vec![7; 16])
        .unwrap();
    (generated.key, context)
}

#[test]
fn kotlin_style_callbacks_seal_and_open_the_same_json() {
    let (key, context) = context();
    let ciphertext_sink = Arc::new(CiphertextSink::default());
    let metadata = seal_backup_object_v1(
        Arc::clone(&context),
        Arc::new(PlaintextSource(Mutex::new(Some(JSON.to_vec())))),
        ciphertext_sink.clone(),
    )
    .unwrap();
    let factory = Arc::new(SourceFactory::new(
        ciphertext_sink.0.lock().unwrap().clone(),
    ));
    let plaintext_sink = Arc::new(PlaintextSink::default());

    open_backup_object_v1(
        key,
        ACCOUNT.to_owned(),
        vec![7; 16],
        factory.clone(),
        metadata,
        plaintext_sink.clone(),
    )
    .unwrap();

    assert_eq!(factory.opens.load(Ordering::Relaxed), 2);
    assert_eq!(factory.closes.load(Ordering::Relaxed), 2);
    assert_eq!(*plaintext_sink.0.lock().unwrap(), JSON);
}

#[test]
fn opens_an_object_for_both_key_modes() {
    for mode in [BackupKeyMode::Mnemonic, BackupKeyMode::Password] {
        let key = import_from_raw(mode, vec![42; 32]).unwrap();
        let backup_id = key.derive_backup_id(ACCOUNT.to_owned()).unwrap();
        let context = key
            .create_object_context(ACCOUNT.to_owned(), backup_id, vec![7; 16])
            .unwrap();
        let ciphertext_sink = Arc::new(CiphertextSink::default());
        let metadata = seal_backup_object_v1(
            context,
            Arc::new(PlaintextSource(Mutex::new(Some(JSON.to_vec())))),
            ciphertext_sink.clone(),
        )
        .unwrap();
        let factory = Arc::new(SourceFactory::new(
            ciphertext_sink.0.lock().unwrap().clone(),
        ));
        let plaintext_sink = Arc::new(PlaintextSink::default());

        open_backup_object_v1(
            Arc::clone(&key),
            ACCOUNT.to_owned(),
            vec![7; 16],
            factory.clone(),
            metadata,
            plaintext_sink.clone(),
        )
        .unwrap();

        assert_eq!(factory.opens.load(Ordering::Relaxed), 2);
        assert_eq!(factory.closes.load(Ordering::Relaxed), 2);
        assert_eq!(*plaintext_sink.0.lock().unwrap(), JSON);
    }
}

#[test]
fn open_rejects_invalid_identity_and_inventory() {
    let key = import_from_raw(BackupKeyMode::Mnemonic, vec![42; 32]).unwrap();
    let backup_id = key.derive_backup_id(ACCOUNT.to_owned()).unwrap();
    let context = key
        .create_object_context(ACCOUNT.to_owned(), backup_id, vec![7; 16])
        .unwrap();
    let ciphertext_sink = Arc::new(CiphertextSink::default());
    let metadata = seal_backup_object_v1(
        context,
        Arc::new(PlaintextSource(Mutex::new(Some(JSON.to_vec())))),
        ciphertext_sink.clone(),
    )
    .unwrap();

    for (account, chunk, corrupt_hash, expected_error, expected_opens) in [
        (
            "invalid",
            vec![7; 16],
            false,
            BackupFfiError::InvalidArgument,
            0,
        ),
        (
            ACCOUNT,
            vec![7; 15],
            false,
            BackupFfiError::InvalidArgument,
            0,
        ),
        (
            ACCOUNT,
            vec![0; 16],
            false,
            BackupFfiError::InvalidArgument,
            0,
        ),
        (
            ACCOUNT,
            vec![8; 16],
            false,
            BackupFfiError::AuthenticationFailed,
            2,
        ),
        (
            "10112233-4455-6677-8899-aabbccddeeff",
            vec![7; 16],
            false,
            BackupFfiError::AuthenticationFailed,
            2,
        ),
        (
            ACCOUNT,
            vec![7; 16],
            true,
            BackupFfiError::IntegrityMismatch,
            1,
        ),
    ] {
        let factory = Arc::new(SourceFactory::new(
            ciphertext_sink.0.lock().unwrap().clone(),
        ));
        let plaintext_sink = Arc::new(PlaintextSink::default());
        let mut ciphertext_sha256 = metadata.ciphertext_sha256.clone();
        if corrupt_hash {
            ciphertext_sha256[0] ^= 1;
        }
        let result = open_backup_object_v1(
            Arc::clone(&key),
            account.to_owned(),
            chunk,
            factory.clone(),
            BackupObjectMetadata {
                ciphertext_size: metadata.ciphertext_size,
                ciphertext_sha256,
                format_version: metadata.format_version,
            },
            plaintext_sink.clone(),
        );
        assert_eq!(result.unwrap_err(), expected_error);
        assert_eq!(factory.opens.load(Ordering::Relaxed), expected_opens);
        assert_eq!(factory.closes.load(Ordering::Relaxed), expected_opens);
        assert!(plaintext_sink.0.lock().unwrap().is_empty());
    }
}

#[test]
fn inventory_mismatch_prevents_plaintext_callback() {
    let (key, context) = context();
    let ciphertext_sink = Arc::new(CiphertextSink::default());
    let mut metadata = seal_backup_object_v1(
        Arc::clone(&context),
        Arc::new(PlaintextSource(Mutex::new(Some(JSON.to_vec())))),
        ciphertext_sink.clone(),
    )
    .unwrap();
    metadata.ciphertext_sha256[0] ^= 1;
    let factory = Arc::new(SourceFactory::new(
        ciphertext_sink.0.lock().unwrap().clone(),
    ));
    let plaintext_sink = Arc::new(PlaintextSink::default());

    assert!(matches!(
        open_backup_object_v1(
            key,
            ACCOUNT.to_owned(),
            vec![7; 16],
            factory.clone(),
            metadata,
            plaintext_sink.clone()
        ),
        Err(BackupFfiError::IntegrityMismatch)
    ));
    assert_eq!(factory.opens.load(Ordering::Relaxed), 1);
    assert_eq!(factory.closes.load(Ordering::Relaxed), 1);
    assert!(plaintext_sink.0.lock().unwrap().is_empty());
}

struct FailedCancellationCallback;

impl BackupCiphertextSourceFactory for FailedCancellationCallback {
    fn open(&self) -> Result<Arc<dyn BackupCiphertextSource>, BackupFfiError> {
        panic!("reader must check cancellation before opening a source")
    }

    fn is_cancelled(&self) -> Result<bool, BackupFfiError> {
        Err(BackupFfiError::InvalidArgument)
    }
}

#[test]
fn failed_cancellation_callback_is_sanitized_to_io_error() {
    let (key, context) = context();
    let ciphertext_sink = Arc::new(CiphertextSink::default());
    let metadata = seal_backup_object_v1(
        Arc::clone(&context),
        Arc::new(PlaintextSource(Mutex::new(Some(JSON.to_vec())))),
        ciphertext_sink,
    )
    .unwrap();
    let plaintext_sink = Arc::new(PlaintextSink::default());

    assert!(matches!(
        open_backup_object_v1(
            key,
            ACCOUNT.to_owned(),
            vec![7; 16],
            Arc::new(FailedCancellationCallback),
            metadata,
            plaintext_sink.clone(),
        ),
        Err(BackupFfiError::IoError)
    ));
    assert!(plaintext_sink.0.lock().unwrap().is_empty());
}
