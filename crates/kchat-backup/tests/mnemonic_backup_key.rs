use kchat_backup::{BackupErrorCode, MnemonicBackupKey};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const EXPECTED_KEY: [u8; 32] = [
    0xc7, 0xd1, 0x83, 0x2a, 0x85, 0x77, 0x37, 0xcc, 0x10, 0x93, 0x37, 0x7f, 0x09, 0x80, 0x87, 0xd5,
    0x11, 0x15, 0x5e, 0x78, 0xda, 0x6e, 0xf2, 0x4f, 0x45, 0x83, 0x35, 0x92, 0xc3, 0x8f, 0x04, 0xef,
];

#[test]
fn derives_a_mnemonic_backup_key_from_a_valid_phrase() {
    let key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();

    assert_eq!(key.export_for_secure_storage(), EXPECTED_KEY);
    assert_eq!(format!("{key:?}"), "MnemonicBackupKey(REDACTED)");
}

#[test]
fn rejects_invalid_mnemonic_input() {
    let twelve_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let non_english = "こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは";

    assert_eq!(
        MnemonicBackupKey::from_mnemonic(twelve_word)
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonic
    );
    assert_eq!(
        MnemonicBackupKey::from_mnemonic(non_english)
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonic
    );
}

#[test]
fn generates_a_recoverable_mnemonic_backup_key() {
    let (phrase, generated_key) = MnemonicBackupKey::generate().unwrap();

    println!("{:?}", phrase);

    assert_eq!(phrase.split_whitespace().count(), 24);
    assert_eq!(
        generated_key.export_for_secure_storage(),
        MnemonicBackupKey::from_mnemonic(&phrase)
            .unwrap()
            .export_for_secure_storage()
    );
    assert_eq!(format!("{generated_key:?}"), "MnemonicBackupKey(REDACTED)");
}

#[test]
fn rejects_mnemonic_backup_key_imports_with_an_invalid_length() {
    assert_eq!(
        MnemonicBackupKey::import_from_secure_storage(&[0x11; 31])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonicKey
    );
    assert_eq!(
        MnemonicBackupKey::import_from_secure_storage(&[0x11; 33])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonicKey
    );
}
