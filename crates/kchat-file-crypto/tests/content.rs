mod common;

use kchat_file_crypto::{
    ContentKey, ContentPlan, ContentSource, FileCryptoError, FileCryptoErrorCode,
    MAX_IO_CHUNK_BYTES, RandomPlanReason, SealedContent, hash_content, open_content, seal_content,
};

use crate::common::{
    CancelledSource, MemorySource, RecordingSink, TestKeyring, hash, next_operation, sample,
};

const BLOCK: usize = 64 * 1024;

fn random_plan(keyring: &TestKeyring, plaintext: &[u8]) -> ContentPlan {
    keyring
        .plan_random(&hash(plaintext), RandomPlanReason::SmallFile)
        .unwrap()
}

fn seal(plan: &ContentPlan, plaintext: &[u8]) -> (SealedContent, Vec<u8>) {
    let mut sink = RecordingSink::default();
    let sealed = seal_content(plan, &mut MemorySource::new(plaintext), &mut sink).unwrap();
    assert!(sink.committed && !sink.aborted);
    (sealed, sink.bytes)
}

fn open(key: &ContentKey, ciphertext: &[u8]) -> Result<Vec<u8>, FileCryptoErrorCode> {
    let mut sink = RecordingSink::default();
    let result = open_content(key, &mut MemorySource::new(ciphertext), &mut sink);
    match result {
        Ok(()) => {
            assert!(sink.committed && !sink.aborted);
            Ok(sink.bytes)
        }
        Err(error) => {
            assert!(sink.aborted && !sink.committed);
            Err(error.code())
        }
    }
}

fn expected_ciphertext_len(plaintext_len: usize) -> usize {
    plaintext_len + 16 * plaintext_len.div_ceil(BLOCK).max(1)
}

#[test]
fn round_trips_canonical_sizes() {
    let keyring = TestKeyring::new(None);
    for length in [
        0,
        1,
        BLOCK - 1,
        BLOCK,
        BLOCK + 1,
        2 * BLOCK,
        3 * BLOCK + 17,
        5 * 1024 * 1024,
    ] {
        let plaintext = sample(length, length as u8);
        let plan = random_plan(&keyring, &plaintext);
        let (sealed, ciphertext) = seal(&plan, &plaintext);
        assert_eq!(sealed.plaintext_len(), length as u64);
        assert_eq!(
            ciphertext.len(),
            expected_ciphertext_len(length),
            "length {length}"
        );
        assert_eq!(sealed.ciphertext_len(), ciphertext.len() as u64);

        let key = ContentKey::from_sealed(&plan, &sealed).unwrap();
        assert_eq!(
            open(&key, &ciphertext).unwrap(),
            plaintext,
            "length {length}"
        );
    }
}

#[test]
fn short_reads_produce_identical_output() {
    let keyring = TestKeyring::new(None);
    let plaintext = sample(3 * BLOCK + 5, 1);
    let plan = random_plan(&keyring, &plaintext);
    let (_, whole) = seal(&plan, &plaintext);

    let mut sink = RecordingSink::default();
    seal_content(
        &plan,
        &mut MemorySource::chunked(&plaintext, 7_919),
        &mut sink,
    )
    .unwrap();
    assert_eq!(sink.bytes, whole);
    assert!(sink.largest_chunk <= MAX_IO_CHUNK_BYTES);

    let short_hash = hash_content(
        &next_operation(),
        &mut MemorySource::chunked(&plaintext, 13),
    )
    .unwrap();
    assert_eq!(short_hash.plaintext_len(), plaintext.len() as u64);
}

#[test]
fn ciphertext_hash_is_sha256_of_the_object() {
    use sha2::{Digest, Sha256};
    let keyring = TestKeyring::new(None);
    let plaintext = sample(100_000, 2);
    let plan = random_plan(&keyring, &plaintext);
    let (sealed, ciphertext) = seal(&plan, &plaintext);
    assert_eq!(
        sealed.ciphertext_sha256().as_slice(),
        Sha256::digest(&ciphertext).as_slice()
    );
}

#[test]
fn changed_source_aborts_without_committing() {
    let keyring = TestKeyring::new(None);
    let plaintext = sample(2 * BLOCK + 9, 3);
    let plan = random_plan(&keyring, &plaintext);

    let mut same_length = plaintext.clone();
    same_length[BLOCK + 1] ^= 1;
    let mut longer = plaintext.clone();
    longer.push(0);
    let shorter = plaintext[..plaintext.len() - 1].to_vec();

    for changed in [same_length, longer, shorter, Vec::new()] {
        let mut sink = RecordingSink::default();
        let error = seal_content(&plan, &mut MemorySource::new(&changed), &mut sink).unwrap_err();
        assert_eq!(error.code(), FileCryptoErrorCode::SourceChanged);
        assert!(sink.aborted && !sink.committed && sink.bytes.is_empty());
    }
}

#[test]
fn rejects_tampered_ciphertext() {
    let keyring = TestKeyring::new(None);
    let plaintext = sample(3 * BLOCK + 100, 4);
    let plan = random_plan(&keyring, &plaintext);
    let (sealed, ciphertext) = seal(&plan, &plaintext);
    let key = ContentKey::from_sealed(&plan, &sealed).unwrap();
    let frame = BLOCK + 16;

    let mut flipped = ciphertext.clone();
    flipped[frame + 10] ^= 1;
    let truncated = ciphertext[..ciphertext.len() - 1].to_vec();
    let mut extended = ciphertext.clone();
    extended.push(0);
    let mut swapped = ciphertext.clone();
    swapped[..frame].copy_from_slice(&ciphertext[frame..2 * frame]);
    swapped[frame..2 * frame].copy_from_slice(&ciphertext[..frame]);
    let mut duplicated = ciphertext.clone();
    duplicated[frame..2 * frame].copy_from_slice(&ciphertext[..frame]);

    for tampered in [
        flipped,
        truncated,
        extended,
        swapped,
        duplicated,
        Vec::new(),
    ] {
        assert_eq!(
            open(&key, &tampered),
            Err(FileCryptoErrorCode::IntegrityError)
        );
    }
}

#[test]
fn rejects_wrong_key_or_metadata() {
    let keyring = TestKeyring::new(None);
    let plaintext = sample(BLOCK + 3, 5);
    let plan = random_plan(&keyring, &plaintext);
    let (sealed, ciphertext) = seal(&plan, &plaintext);

    let other_plan = random_plan(&keyring, &plaintext);
    let other_key = ContentKey::from_sealed(&other_plan, &sealed).unwrap();
    assert_eq!(
        open(&other_key, &ciphertext),
        Err(FileCryptoErrorCode::IntegrityError)
    );

    let (again, _) = seal(&plan, &plaintext);
    assert_eq!(again, sealed);

    let different = sample(BLOCK + 3, 6);
    let different_plan = random_plan(&keyring, &different);
    let (different_sealed, _) = seal(&different_plan, &different);
    let mismatched = ContentKey::from_sealed(&plan, &different_sealed).unwrap();
    assert_eq!(
        open(&mismatched, &ciphertext),
        Err(FileCryptoErrorCode::IntegrityError)
    );

    let short = sample(10, 7);
    let (short_sealed, _) = seal(&random_plan(&keyring, &short), &short);
    assert_eq!(
        ContentKey::from_sealed(&plan, &short_sealed)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::InvalidArgument
    );
}

#[test]
fn cancellation_aborts_the_sink() {
    let keyring = TestKeyring::new(None);
    let plaintext = sample(10, 8);
    let plan = random_plan(&keyring, &plaintext);
    let mut sink = RecordingSink::default();
    let error = seal_content(&plan, &mut CancelledSource, &mut sink).unwrap_err();
    assert_eq!(error.code(), FileCryptoErrorCode::Cancelled);
    assert!(sink.aborted && !sink.committed);

    assert_eq!(
        hash_content(&next_operation(), &mut CancelledSource)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::Cancelled
    );
}

struct OversizedReadSource;

impl ContentSource for OversizedReadSource {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, FileCryptoError> {
        Ok(destination.len() + 1)
    }
}

#[test]
fn rejects_sources_reporting_more_than_requested() {
    assert_eq!(
        hash_content(&next_operation(), &mut OversizedReadSource)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::InvalidState
    );
}
