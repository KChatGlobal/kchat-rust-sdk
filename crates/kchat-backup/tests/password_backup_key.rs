use kchat_backup::{
    BackupAccountId, BackupChunkId, BackupErrorCode, BackupNamespaceId, BackupObjectContextV1,
    PasswordBackupKey,
};

const ACCOUNT_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OTHER_ACCOUNT_ID: &str = "ffeeddcc-bbaa-9988-7766-554433221100";
const SALT: [u8; 16] = [0x11; 16];
const EXPECTED_PASSWORD_KEY: [u8; 32] = [
    0xf9, 0x7d, 0xcd, 0xd4, 0xdb, 0xa7, 0xfa, 0x4c, 0xd8, 0xfd, 0x78, 0x41, 0x9c, 0x8f, 0x8f, 0x79,
    0xaa, 0x99, 0x1f, 0x0c, 0xc8, 0x00, 0x50, 0xe4, 0xde, 0x10, 0x8a, 0xce, 0xcf, 0x66, 0x42, 0x2c,
];

#[test]
fn rejects_invalid_password_input_before_key_derivation() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();

    assert_eq!(
        PasswordBackupKey::from_password(b"", &account, SALT)
            .unwrap_err()
            .code(),
        BackupErrorCode::EmptyPassword
    );
}

#[test]
fn exports_and_imports_a_password_backup_key_for_secure_storage() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let key = PasswordBackupKey::from_password(b"password", &account, SALT).unwrap();
    let exported = key.export_for_secure_storage();

    let imported = PasswordBackupKey::import_from_secure_storage(&exported).unwrap();

    assert_eq!(
        BackupNamespaceId::derive(&key, &account).unwrap(),
        BackupNamespaceId::derive(&imported, &account).unwrap()
    );
    assert_eq!(format!("{imported:?}"), "PasswordBackupKey(REDACTED)");
}

#[test]
fn rejects_password_backup_key_imports_with_an_invalid_length() {
    assert_eq!(
        PasswordBackupKey::import_from_secure_storage(&[0x11; 31])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidPasswordKey
    );
    assert_eq!(
        PasswordBackupKey::import_from_secure_storage(&[0x11; 33])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidPasswordKey
    );
}

#[test]
fn derives_a_password_backup_key_from_exact_raw_bytes_account_and_salt() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let other_account = BackupAccountId::parse(OTHER_ACCOUNT_ID).unwrap();
    let password = b"password";

    let key = PasswordBackupKey::from_password(password, &account, SALT).unwrap();
    let same_key = PasswordBackupKey::from_password(password, &account, SALT).unwrap();
    let trailing_space = PasswordBackupKey::from_password(b"password ", &account, SALT).unwrap();
    let composed =
        PasswordBackupKey::from_password("caf\u{e9}".as_bytes(), &account, SALT).unwrap();
    let decomposed =
        PasswordBackupKey::from_password("cafe\u{301}".as_bytes(), &account, SALT).unwrap();
    let other_account_key =
        PasswordBackupKey::from_password(password, &other_account, SALT).unwrap();
    let other_salt_key = PasswordBackupKey::from_password(password, &account, [0x22; 16]).unwrap();

    let namespace = BackupNamespaceId::derive(&key, &account).unwrap();
    assert_eq!(key.export_for_secure_storage(), EXPECTED_PASSWORD_KEY);
    assert_eq!(
        namespace,
        BackupNamespaceId::derive(&same_key, &account).unwrap()
    );
    assert_ne!(
        namespace,
        BackupNamespaceId::derive(&trailing_space, &account).unwrap()
    );
    assert_ne!(
        namespace,
        BackupNamespaceId::derive(&composed, &account).unwrap()
    );
    assert_ne!(
        namespace,
        BackupNamespaceId::derive(&decomposed, &account).unwrap()
    );
    assert_ne!(
        BackupNamespaceId::derive(&composed, &account).unwrap(),
        BackupNamespaceId::derive(&decomposed, &account).unwrap()
    );
    assert_ne!(
        namespace,
        BackupNamespaceId::derive(&other_account_key, &other_account).unwrap()
    );
    assert_ne!(
        namespace,
        BackupNamespaceId::derive(&other_salt_key, &account).unwrap()
    );

    let chunk = BackupChunkId::from_bytes([0x33; 16]).unwrap();
    let context = BackupObjectContextV1::new(&key, account, namespace, 1, chunk).unwrap();
    let same_context = BackupObjectContextV1::new(&same_key, account, namespace, 1, chunk).unwrap();
    assert_eq!(context.canonical_bytes(), same_context.canonical_bytes());
    assert_eq!(format!("{key:?}"), "PasswordBackupKey(REDACTED)");
}
