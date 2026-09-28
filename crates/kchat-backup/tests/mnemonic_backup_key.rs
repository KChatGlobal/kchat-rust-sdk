use kchat_backup::{BackupErrorCode, MnemonicBackupKey};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const EXPECTED_KEY: [u8; 32] = [
    0xc7, 0xd1, 0x83, 0x2a, 0x85, 0x77, 0x37, 0xcc, 0x10, 0x93, 0x37, 0x7f, 0x09, 0x80, 0x87, 0xd5,
    0x11, 0x15, 0x5e, 0x78, 0xda, 0x6e, 0xf2, 0x4f, 0x45, 0x83, 0x35, 0x92, 0xc3, 0x8f, 0x04, 0xef,
];

#[test]
fn derives_a_mnemonic_backup_key_from_a_valid_phrase() {
    let key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();

    assert_eq!(key.export_raw(), EXPECTED_KEY);
    assert_eq!(format!("{key:?}"), "MnemonicBackupKey(REDACTED)");
}

#[test]
fn rejects_invalid_mnemonic_input() {
    let invalid_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let non_english = "こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは こんにちは";

    assert_eq!(
        MnemonicBackupKey::from_mnemonic(invalid_checksum)
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
fn restores_a_twelve_word_mnemonic_backup_key() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let key = MnemonicBackupKey::from_mnemonic(phrase).unwrap();
    let imported = MnemonicBackupKey::import_from_raw(&key.export_raw()).unwrap();

    assert_eq!(key.export_raw(), imported.export_raw());
}

#[test]
fn generates_a_recoverable_mnemonic_backup_key() {
    for word_count in [12, 15, 18, 21, 24] {
        let (phrase, generated_key) = MnemonicBackupKey::generate(word_count).unwrap();

        println!("{:?}", phrase);

        assert_eq!(phrase.split_whitespace().count(), word_count as usize);
        assert_eq!(
            generated_key.export_raw(),
            MnemonicBackupKey::from_mnemonic(&phrase)
                .unwrap()
                .export_raw()
        );
        assert_eq!(format!("{generated_key:?}"), "MnemonicBackupKey(REDACTED)");
    }
}

#[test]
fn rejects_unsupported_mnemonic_word_counts() {
    for word_count in [0, 1, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, u32::MAX] {
        assert_eq!(
            MnemonicBackupKey::generate(word_count).unwrap_err().code(),
            BackupErrorCode::InvalidArgument
        );
    }
}

#[test]
fn rejects_mnemonic_backup_key_imports_with_an_invalid_length() {
    assert_eq!(
        MnemonicBackupKey::import_from_raw(&[0x11; 31])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonicKey
    );
    assert_eq!(
        MnemonicBackupKey::import_from_raw(&[0x11; 33])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidMnemonicKey
    );
}
