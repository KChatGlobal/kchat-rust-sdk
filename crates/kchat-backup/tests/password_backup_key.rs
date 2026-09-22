use kchat_backup::{
    BackupAccountId, BackupChunkId, BackupErrorCode, BackupNamespaceId, BackupObjectContextV1,
    PasswordBackupKey,
};

const ACCOUNT_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OTHER_ACCOUNT_ID: &str = "ffeeddcc-bbaa-9988-7766-554433221100";
const SALT: [u8; 16] = [0x11; 16];

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
