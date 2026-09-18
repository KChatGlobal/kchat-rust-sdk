use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use kchat_backup::{
    BackupAccountId, BackupErrorCode, MnemonicBackupKey, BackupNamespaceId, open_descriptor_v1,
    seal_descriptor_v1,
};
use sha2::Sha256;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const DESCRIPTOR_HEX: &str = "4b43424400015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a3f49baa9158794ca47880b7311f0982e1b961a23a195fd43eee37e8c3e08210df99b1f4fc662d301c32b9cd32732cc7884d24a1386bc0e7421d577dd";
const ACCOUNT_BYTES: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn derive_key(input_key_material: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    Hkdf::<Sha256>::new(None, input_key_material)
        .expand(info, &mut output)
        .unwrap();
    output
}

fn authenticated_descriptor(
    master_key: &BackupMasterKey,
    namespace_id: &BackupNamespaceId,
    plaintext: [u8; 44],
) -> Vec<u8> {
    let mut account_info = b"KCHAT_BACKUP_V1_ACCOUNT".to_vec();
    account_info.extend_from_slice(&ACCOUNT_BYTES);
    let account_key = derive_key(&master_key.export_for_secure_storage(), &account_info);
    let descriptor_key = derive_key(&account_key, b"KCHAT_BACKUP_V1_DESCRIPTOR");
    let cipher = XChaCha20Poly1305::new_from_slice(&descriptor_key).unwrap();
    let nonce = [0x7c; 24];
    let mut aad = b"KCHAT_BACKUP_DESCRIPTOR_V1".to_vec();
    aad.extend_from_slice(namespace_id.as_bytes());
    let nonce = XNonce::try_from(&nonce[..]).unwrap();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    let mut serialized = Vec::with_capacity(90);
    serialized.extend_from_slice(b"KCBD");
    serialized.extend_from_slice(&1_u16.to_be_bytes());
    serialized.extend_from_slice(&nonce);
    serialized.extend_from_slice(&ciphertext);
    serialized
}

fn valid_plaintext(namespace_id: &BackupNamespaceId) -> [u8; 44] {
    let mut plaintext = [0_u8; 44];
    plaintext[..4].copy_from_slice(b"KCBD");
    plaintext[4..6].copy_from_slice(&1_u16.to_be_bytes());
    plaintext[6..38].copy_from_slice(namespace_id.as_bytes());
    plaintext[38..40].copy_from_slice(&1_u16.to_be_bytes());
    plaintext
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
fn opens_the_fixed_v1_descriptor() {
    let master_key = BackupMasterKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let serialized = decode_hex(DESCRIPTOR_HEX);

    assert_eq!(serialized.len(), 90);
    assert_eq!(
        open_descriptor_v1(&master_key, &account, &serialized).unwrap(),
        BackupNamespaceId::derive(&master_key, &account).unwrap()
    );
}

#[test]
fn rejects_invalid_outer_magic_and_version_before_decryption() {
    let master_key = BackupMasterKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let serialized = decode_hex(DESCRIPTOR_HEX);

    let mut wrong_magic = serialized.clone();
    wrong_magic[..4].copy_from_slice(b"BAD!");
    assert_eq!(
        open_descriptor_v1(&master_key, &account, &wrong_magic)
            .unwrap_err()
            .code(),
        BackupErrorCode::UnsupportedFormat
    );

    let mut wrong_version = serialized;
    wrong_version[4..6].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        open_descriptor_v1(&master_key, &account, &wrong_version)
            .unwrap_err()
            .code(),
        BackupErrorCode::UnsupportedFormat
    );
}

#[test]
fn rejects_authenticated_descriptors_with_invalid_inner_fields() {
    let master_key = BackupMasterKey::from_mnemonic(MNEMONIC).unwrap();
    let account = BackupAccountId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let namespace_id = BackupNamespaceId::derive(&master_key, &account).unwrap();
    let mut cases = Vec::new();

    let mut wrong_magic = valid_plaintext(&namespace_id);
    wrong_magic[..4].copy_from_slice(b"BAD!");
    cases.push(wrong_magic);

    let mut wrong_version = valid_plaintext(&namespace_id);
    wrong_version[4..6].copy_from_slice(&2_u16.to_be_bytes());
    cases.push(wrong_version);

    let mut wrong_namespace = valid_plaintext(&namespace_id);
    wrong_namespace[6..38].copy_from_slice(&[0x42; 32]);
    cases.push(wrong_namespace);

    let mut wrong_profile = valid_plaintext(&namespace_id);
    wrong_profile[38..40].copy_from_slice(&2_u16.to_be_bytes());
    cases.push(wrong_profile);

    let mut nonzero_capabilities = valid_plaintext(&namespace_id);
    nonzero_capabilities[40..44].copy_from_slice(&1_u32.to_be_bytes());
    cases.push(nonzero_capabilities);

    for plaintext in cases {
        let serialized = authenticated_descriptor(&master_key, &namespace_id, plaintext);
        assert_eq!(
            open_descriptor_v1(&master_key, &account, &serialized)
                .unwrap_err()
                .code(),
            BackupErrorCode::UnsupportedFormat
        );
    }
}
