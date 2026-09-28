use kchat_backup::{
    BackupAccountId, BackupChunkId, BackupErrorCode, BackupId, BackupObjectContextV1,
    MnemonicBackupKey,
};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const ACCOUNT_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";

#[test]
fn parses_a_uuid_account_id_into_canonical_network_order_bytes() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    assert_eq!(
        account.as_bytes(),
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ]
    );
}

#[test]
fn rejects_invalid_account_id_input() {
    assert!(BackupAccountId::parse("not-a-kchat-user-id").is_err());
}

#[test]
fn backup_id_derivation_keeps_v1_bytes() {
    let master_key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let backup_id = BackupId::derive(&master_key, &account).unwrap();

    assert_eq!(
        *backup_id.as_bytes(),
        [
            190, 61, 122, 127, 200, 27, 93, 99, 83, 185, 152, 48, 82, 221, 214, 187, 43, 113, 214,
            87, 32, 184, 49, 68, 142, 201, 226, 242, 224, 21, 241, 116,
        ]
    );
}

#[test]
fn validates_backup_id_before_constructing_an_object_context() {
    let master_key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let other_account = BackupAccountId::parse("ffeeddcc-bbaa-9988-7766-554433221100").unwrap();
    let backup_id = BackupId::derive(&master_key, &account).unwrap();
    let wrong_backup_id = BackupId::derive(&master_key, &other_account).unwrap();
    let chunk = BackupChunkId::from_bytes([0x11; 16]).unwrap();
    assert_eq!(
        BackupObjectContextV1::new(&master_key, account, wrong_backup_id, 1, chunk)
            .unwrap_err()
            .code(),
        BackupErrorCode::ContextMismatch
    );
    assert!(BackupObjectContextV1::new(&master_key, account, backup_id, 1, chunk).is_ok());
}

#[test]
fn encodes_a_validated_object_context_with_fixed_big_endian_fields() {
    let master_key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let backup_id = BackupId::derive(&master_key, &account).unwrap();
    let chunk = BackupChunkId::from_bytes([0xaa; 16]).unwrap();
    let context = BackupObjectContextV1::new(&master_key, account, backup_id, 1, chunk).unwrap();
    let mut expected = b"KCHAT_BACKUP_OBJECT_CONTEXT_V1".to_vec();
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.extend_from_slice(backup_id.as_bytes());
    expected.extend_from_slice(&[0xaa; 16]);
    assert_eq!(context.canonical_bytes(), expected.as_slice());
    assert_eq!(
        BackupChunkId::from_bytes([0; 16]).unwrap_err().code(),
        BackupErrorCode::InvalidArgument
    );
    assert_eq!(
        BackupObjectContextV1::new(&master_key, account, backup_id, 2, chunk)
            .unwrap_err()
            .code(),
        BackupErrorCode::UnsupportedFormat
    );
}
