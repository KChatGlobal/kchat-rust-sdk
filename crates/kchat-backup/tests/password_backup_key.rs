use kchat_backup::{
    BackupAccountId, BackupChunkId, BackupErrorCode, BackupNamespaceId, BackupObjectContextV1,
    PasswordBackupKey,
};

const ACCOUNT_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OTHER_ACCOUNT_ID: &str = "ffeeddcc-bbaa-9988-7766-554433221100";
const SALT: [u8; 16] = [0x11; 16];

#[test]
fn rejects_invalid_password_input_before_key_derivation() {
    assert_eq!(
        PasswordBackupKey::from_password(b"", SALT)
            .unwrap_err()
            .code(),
        BackupErrorCode::EmptyPassword
    );
    assert_eq!(
        PasswordBackupKey::generate(b"").unwrap_err().code(),
        BackupErrorCode::EmptyPassword
    );
}

#[test]
fn exports_and_imports_a_password_backup_key_for_secure_storage() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let key = PasswordBackupKey::from_password(b"password", SALT).unwrap();
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
fn derives_an_account_independent_password_master_key_from_exact_raw_bytes_and_salt() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let other_account = BackupAccountId::parse(OTHER_ACCOUNT_ID).unwrap();
    let password = b"password";

    let key = PasswordBackupKey::from_password(password, SALT).unwrap();
    let same_key = PasswordBackupKey::from_password(password, SALT).unwrap();
    let trailing_space = PasswordBackupKey::from_password(b"password ", SALT).unwrap();
    let composed = PasswordBackupKey::from_password("caf\u{e9}".as_bytes(), SALT).unwrap();
    let decomposed = PasswordBackupKey::from_password("cafe\u{301}".as_bytes(), SALT).unwrap();
    let other_salt_key = PasswordBackupKey::from_password(password, [0x22; 16]).unwrap();

    let namespace = BackupNamespaceId::derive(&key, &account).unwrap();
    assert_eq!(
        key.export_for_secure_storage(),
        same_key.export_for_secure_storage()
    );
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
        BackupNamespaceId::derive(&key, &other_account).unwrap()
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

#[test]
fn generates_a_fresh_salt_and_key_that_rederives_from_that_salt() {
    let (first_salt, first_key) = PasswordBackupKey::generate(b"password").unwrap();
    let (second_salt, second_key) = PasswordBackupKey::generate(b"password").unwrap();

    assert_ne!(first_salt, second_salt);
    assert_eq!(
        first_key.export_for_secure_storage(),
        PasswordBackupKey::from_password(b"password", first_salt)
            .unwrap()
            .export_for_secure_storage(),
    );
    assert_ne!(
        first_key.export_for_secure_storage(),
        second_key.export_for_secure_storage()
    );
}
