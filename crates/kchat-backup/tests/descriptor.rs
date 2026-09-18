use kchat_backup::{
    BackupAccountId, BackupErrorCode, MnemonicBackupKey, BackupNamespaceId, open_descriptor_v1,
    seal_descriptor_v1,
};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const FIXTURE_DESCRIPTOR_HEX: &str = "4b43424400015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a3f49baa9158794ca47880b7311f0982e1b961a23a195fd43eee37e8c3e08210df99b1f4fc662d301c32b9cd32732cc7884d24a1386bc0e7421d577dd";

fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn seals_a_fixed_size_descriptor_that_opens_to_the_derived_namespace() {
    let master_key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();

    let serialized = seal_descriptor_v1(&master_key, &account).unwrap();

    assert_eq!(serialized.len(), 90);
    assert_eq!(&serialized[..4], b"KCBD");
    assert_eq!(&serialized[4..6], &[0, 1]);
    assert_eq!(
        open_descriptor_v1(&master_key, &account, &serialized).unwrap(),
        BackupNamespaceId::derive(&master_key, &account).unwrap()
    );
}

#[test]
fn rejects_wrong_length_tampering_and_a_different_authenticated_account() {
    let master_key = MnemonicBackupKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let other_account = BackupAccountId::parse("ffeeddcc-bbaa-9988-7766-554433221100").unwrap();
    let serialized = seal_descriptor_v1(&master_key, &account).unwrap();

    assert_eq!(
        open_descriptor_v1(&master_key, &account, &serialized[..89])
            .unwrap_err()
            .code(),
        BackupErrorCode::InvalidArgument
    );

    let mut tampered = serialized.clone();
    tampered[20] ^= 1;
    assert!(open_descriptor_v1(&master_key, &account, &tampered).is_err());
    assert!(open_descriptor_v1(&master_key, &other_account, &serialized).is_err());
}

#[test]
fn opens_the_fixed_v1_descriptor_fixture() {
    let master_key = BackupMasterKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let serialized = decode_hex(FIXTURE_DESCRIPTOR_HEX);

    assert_eq!(serialized.len(), 90);
    assert_eq!(
        open_descriptor_v1(&master_key, &account, &serialized).unwrap(),
        BackupNamespaceId::derive(&master_key, &account).unwrap()
    );
}
