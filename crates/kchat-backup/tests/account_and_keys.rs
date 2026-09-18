use kchat_backup::{
    BackupAccountId, BackupChunkId, BackupErrorCode, BackupMasterKey, BackupNamespaceId,
    BackupObjectContextV1,
};

const TWENTY_FOUR_WORD_ENGLISH_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const EXPECTED_MASTER_KEY: [u8; 32] = [
    0xc7, 0xd1, 0x83, 0x2a, 0x85, 0x77, 0x37, 0xcc, 0x10, 0x93, 0x37, 0x7f, 0x09, 0x80, 0x87, 0xd5,
    0x11, 0x15, 0x5e, 0x78, 0xda, 0x6e, 0xf2, 0x4f, 0x45, 0x83, 0x35, 0x92, 0xc3, 0x8f, 0x04, 0xef,
];

#[test]
fn parses_uuid_into_canonical_network_order_bytes() {
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();

    assert_eq!(
        account.as_bytes(),
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ]
    );
}

#[test]
fn rejects_non_uuid_account_input() {
    assert!(BackupAccountId::parse("not-a-kchat-user-id").is_err());
}

#[test]
fn derives_a_master_key_from_an_exactly_twenty_four_word_english_mnemonic() {
    let key = BackupMasterKey::from_mnemonic(TWENTY_FOUR_WORD_ENGLISH_MNEMONIC).unwrap();

    assert_eq!(key.export_for_secure_storage(), EXPECTED_MASTER_KEY);
    assert_eq!(format!("{key:?}"), "BackupMasterKey(REDACTED)");
}

#[test]
fn rejects_non_twenty_four_word_or_non_english_mnemonics() {
    let twelve_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let non_english = "こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは";

    assert_eq!(
        BackupMasterKey::from_mnemonic(twelve_word)
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonic
    );
    assert_eq!(
        BackupMasterKey::from_mnemonic(non_english)
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonic
    );
}

#[test]
fn validates_the_derived_namespace_before_constructing_object_context() {
    let master_key = BackupMasterKey::from_mnemonic(TWENTY_FOUR_WORD_ENGLISH_MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let other_account = BackupAccountId::parse("ffeeddcc-bbaa-9988-7766-554433221100").unwrap();
    let namespace = BackupNamespaceId::derive(&master_key, &account).unwrap();
    let wrong_namespace = BackupNamespaceId::derive(&master_key, &other_account).unwrap();
    let chunk = BackupChunkId::from_bytes([0x11; 16]).unwrap();

    assert_eq!(
        BackupObjectContextV1::new(&master_key, account, wrong_namespace, 1, chunk)
            .unwrap_err()
            .code(),
        BackupErrorCode::ContextMismatch
    );
    assert!(BackupObjectContextV1::new(&master_key, account, namespace, 1, chunk).is_ok());
}

#[test]
fn context_uses_fixed_big_endian_canonical_bytes_and_rejects_invalid_inputs() {
    let master_key = BackupMasterKey::from_mnemonic(TWENTY_FOUR_WORD_ENGLISH_MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let namespace = BackupNamespaceId::derive(&master_key, &account).unwrap();
    let chunk = BackupChunkId::from_bytes([0xaa; 16]).unwrap();
    let context = BackupObjectContextV1::new(&master_key, account, namespace, 1, chunk).unwrap();

    let mut expected = b"KCHAT_BACKUP_OBJECT_CONTEXT_V1".to_vec();
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.extend_from_slice(namespace.as_bytes());
    expected.extend_from_slice(&[0xaa; 16]);
    assert_eq!(context.canonical_bytes(), expected.as_slice());

    assert_eq!(
        BackupChunkId::from_bytes([0; 16]).unwrap_err().code(),
        BackupErrorCode::InvalidArgument
    );
    assert_eq!(
        BackupObjectContextV1::new(&master_key, account, namespace, 2, chunk)
            .unwrap_err()
            .code(),
        BackupErrorCode::UnsupportedFormat
    );
}

#[test]
fn generates_a_recoverable_twenty_four_word_mnemonic_without_exposing_key_debug_data() {
    let (phrase, generated_key) = BackupMasterKey::generate().unwrap();

    println!("{:?}", phrase);

    assert_eq!(phrase.split_whitespace().count(), 24);
    assert_eq!(
        generated_key.export_for_secure_storage(),
        BackupMasterKey::from_mnemonic(&phrase)
            .unwrap()
            .export_for_secure_storage()
    );
    assert_eq!(format!("{generated_key:?}"), "BackupMasterKey(REDACTED)");
}

#[test]
fn rejects_master_key_imports_with_any_length_other_than_thirty_two_bytes() {
    assert_eq!(
        BackupMasterKey::import_from_secure_storage(&[0x11; 31])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMasterKey
    );
    assert_eq!(
        BackupMasterKey::import_from_secure_storage(&[0x11; 33])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMasterKey
    );
}
