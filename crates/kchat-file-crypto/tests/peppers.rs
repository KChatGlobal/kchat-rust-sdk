mod common;

use kchat_file_crypto::{FileCryptoErrorCode, FileKeyring, seal_content};

use crate::common::{
    FakeKKey, MemorySource, PEPPER, RecordingSink, TestKeyring, commitment, hash, reopen, tenant,
};

const KEY_GEN: u64 = 1_700_000_000;

fn configured(kkey: &FakeKKey) -> TestKeyring {
    let keyring = TestKeyring::new(Some(kkey.root_key()));
    kkey.import_public_key(&keyring);
    kkey.import_policy(&keyring, 1, "HYBRID");
    keyring
}

fn hybrid_ciphertext(kkey: &FakeKKey, keyring: &FileKeyring, plaintext: &[u8]) -> Vec<u8> {
    let content = hash(plaintext);
    let (session, request) = keyring.begin_oprf(&tenant(), &[&content]).unwrap();
    let plans = keyring
        .finish_oprf(session, &kkey.evaluate(&request))
        .unwrap();
    let mut sink = RecordingSink::default();
    seal_content(&plans[0], &mut MemorySource::new(plaintext), &mut sink).unwrap();
    sink.bytes
}

fn pepper_gen(keyring: &FileKeyring) -> Option<u64> {
    keyring.key_source_status(&tenant()).unwrap().pepper_gen()
}

#[test]
fn generated_pepper_is_pending_until_activated() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = configured(&kkey);

    let first = keyring.generate_pepper(&tenant(), 4).unwrap();
    assert_eq!(keyring.generate_pepper(&tenant(), 4).unwrap(), first);
    assert_eq!(pepper_gen(&keyring), None);

    keyring.activate_pepper(&tenant(), 4).unwrap();
    keyring.activate_pepper(&tenant(), 4).unwrap();
    assert_eq!(pepper_gen(&keyring), Some(4));
    assert_eq!(
        keyring.generate_pepper(&tenant(), 4).unwrap_err().code(),
        FileCryptoErrorCode::KeyConflict
    );

    assert_ne!(keyring.generate_pepper(&tenant(), 5).unwrap(), first);
}

#[test]
fn discard_only_removes_pending_peppers() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = configured(&kkey);

    keyring.generate_pepper(&tenant(), 1).unwrap();
    keyring.discard_pepper(&tenant(), 1).unwrap();
    keyring.discard_pepper(&tenant(), 1).unwrap();
    assert_eq!(
        keyring.activate_pepper(&tenant(), 1).unwrap_err().code(),
        FileCryptoErrorCode::InvalidArgument
    );

    keyring.generate_pepper(&tenant(), 2).unwrap();
    keyring.activate_pepper(&tenant(), 2).unwrap();
    assert_eq!(
        keyring.discard_pepper(&tenant(), 2).unwrap_err().code(),
        FileCryptoErrorCode::InvalidArgument
    );
    assert_eq!(pepper_gen(&keyring), Some(2));
}

#[test]
fn import_checks_the_commitment() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = configured(&kkey);

    let wrong = commitment(&[0x01; 32]);
    assert_eq!(
        keyring
            .import_pepper(&tenant(), 1, &PEPPER, &wrong)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::InvalidArgument
    );
    for length in [0, 31, 33] {
        let pepper = vec![0x07; length];
        assert_eq!(
            keyring
                .import_pepper(&tenant(), 1, &pepper, &commitment(&pepper))
                .unwrap_err()
                .code(),
            FileCryptoErrorCode::InvalidArgument
        );
    }
    assert_eq!(pepper_gen(&keyring), None);

    keyring
        .import_pepper(&tenant(), 1, &PEPPER, &commitment(&PEPPER))
        .unwrap();
    keyring
        .import_pepper(&tenant(), 1, &PEPPER, &commitment(&PEPPER))
        .unwrap();
    assert_eq!(pepper_gen(&keyring), Some(1));

    let other = [0x02; 32];
    assert_eq!(
        keyring
            .import_pepper(&tenant(), 1, &other, &commitment(&other))
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::KeyConflict
    );
}

#[test]
fn losing_the_cas_adopts_the_winners_pepper() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let plaintext = b"shared template";

    let loser = configured(&kkey);
    let candidate = loser.generate_pepper(&tenant(), 1).unwrap();
    assert_ne!(candidate, commitment(&PEPPER));
    loser
        .import_pepper(&tenant(), 1, &PEPPER, &commitment(&PEPPER))
        .unwrap();
    assert_eq!(pepper_gen(&loser), Some(1));

    let other_member = configured(&kkey);
    other_member
        .import_pepper(&tenant(), 1, &PEPPER, &commitment(&PEPPER))
        .unwrap();

    assert_eq!(
        hybrid_ciphertext(&kkey, &loser, plaintext),
        hybrid_ciphertext(&kkey, &other_member, plaintext)
    );
}

#[test]
fn generated_peppers_differ_between_devices() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let plaintext = b"same file";
    let first = configured(&kkey);
    let second = configured(&kkey);
    for keyring in [&first, &second] {
        keyring.generate_pepper(&tenant(), 1).unwrap();
        keyring.activate_pepper(&tenant(), 1).unwrap();
    }
    assert_ne!(
        hybrid_ciphertext(&kkey, &first, plaintext),
        hybrid_ciphertext(&kkey, &second, plaintext)
    );
}

#[test]
fn peppers_persist_across_restarts() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let plaintext = b"persisted";
    let keyring = configured(&kkey);
    keyring.generate_pepper(&tenant(), 7).unwrap();
    keyring.activate_pepper(&tenant(), 7).unwrap();
    let before = hybrid_ciphertext(&kkey, &keyring, plaintext);

    let (_dir, path) = keyring.close();
    let reopened = reopen(&path, Some(kkey.root_key()));
    assert_eq!(pepper_gen(&reopened), Some(7));
    assert_eq!(hybrid_ciphertext(&kkey, &reopened, plaintext), before);
}
