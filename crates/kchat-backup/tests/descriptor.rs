use kchat_backup::{
    BackupAccountId, BackupErrorCode, BackupNamespaceId, DescriptorBackupModeV1,
    DescriptorHeaderV1, MnemonicBackupKey, PasswordBackupKey, open_descriptor_v1,
    seal_descriptor_v1,
};

const ACCOUNT_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

#[test]
fn seals_and_opens_a_unified_mnemonic_descriptor() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let serialized = seal_descriptor_v1(&key, &account, DescriptorHeaderV1::mnemonic()).unwrap();

    assert_eq!(serialized.len(), 110);
    assert_eq!(&serialized[..4], b"KCBD");
    assert_eq!(serialized[6], 1);
    assert_eq!(serialized[8..26], [0_u8; 18]);
    assert_eq!(
        open_descriptor_v1(&key, &account, &serialized).unwrap().1,
        BackupNamespaceId::derive(&key, &account).unwrap()
    );
}

#[test]
fn seals_and_opens_a_unified_password_descriptor() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let salt = [0x11; 16];
    let key = PasswordBackupKey::from_password(b"password", &account, salt).unwrap();
    let serialized =
        seal_descriptor_v1(&key, &account, DescriptorHeaderV1::password(salt)).unwrap();

    let (header, namespace) = open_descriptor_v1(&key, &account, &serialized).unwrap();
    assert_eq!(header.backup_mode(), DescriptorBackupModeV1::Password);
    assert_eq!(header.salt(), salt);
    assert_eq!(
        namespace,
        BackupNamespaceId::derive(&key, &account).unwrap()
    );
}

#[test]
fn rejects_a_structurally_valid_tampered_password_header() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let salt = [0x11; 16];
    let key = PasswordBackupKey::from_password(b"password", &account, salt).unwrap();
    let mut serialized =
        seal_descriptor_v1(&key, &account, DescriptorHeaderV1::password(salt)).unwrap();

    serialized[10] ^= 1;

    assert_eq!(
        open_descriptor_v1(&key, &account, &serialized)
            .unwrap_err()
            .code(),
        BackupErrorCode::AuthenticationFailed
    );
}

#[test]
fn rejects_invalid_headers_before_key_derivation_and_tampering_afterwards() {
    let account = BackupAccountId::parse(ACCOUNT_ID).unwrap();
    let key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let serialized = seal_descriptor_v1(&key, &account, DescriptorHeaderV1::mnemonic()).unwrap();

    for index in [0, 4, 6, 7, 8, 10] {
        let mut invalid = serialized.clone();
        invalid[index] ^= 1;
        assert_eq!(
            open_descriptor_v1(&key, &account, &invalid)
                .unwrap_err()
                .code(),
            BackupErrorCode::UnsupportedFormat
        );
    }

    let mut tampered = serialized;
    tampered[26] ^= 1;
    assert_eq!(
        open_descriptor_v1(&key, &account, &tampered)
            .unwrap_err()
            .code(),
        BackupErrorCode::AuthenticationFailed
    );
}
