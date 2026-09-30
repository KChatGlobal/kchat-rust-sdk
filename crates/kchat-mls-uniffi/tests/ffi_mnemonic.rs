use mls_mobile_sdk_rs::mnemonic::{
    MnemonicFfiError, RecoveryKeyAlgorithm, derive_recovery_key_pair, generate_recovery_mnemonic,
};

const USER_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn exposes_versioned_recovery_bytes_without_an_mls_provider() {
    let pair = derive_recovery_key_pair(
        PHRASE.to_owned(),
        USER_ID.to_owned(),
        RecoveryKeyAlgorithm::Ed25519,
    )
    .unwrap();
    assert_eq!(pair.format_version, 1);
    assert_eq!(pair.algorithm, RecoveryKeyAlgorithm::Ed25519);
    assert_eq!(
        pair.private_key,
        bytes("8f0ba8ccacc985ec2f009b55d22d67cc4e7061096f4d37f174a03a8a076db81b")
    );
    assert_eq!(
        pair.public_key,
        bytes("34ec80fad18e2e212526b5315c47009e028349e557996551bc6a17456d99c7e4")
    );
}

#[test]
fn exports_p256_ecdsa_as_raw_scalar_and_uncompressed_sec1_public_key() {
    let pair = derive_recovery_key_pair(
        PHRASE.to_owned(),
        USER_ID.to_owned(),
        RecoveryKeyAlgorithm::P256Ecdsa,
    )
    .unwrap();
    assert_eq!(pair.format_version, 1);
    assert_eq!(pair.algorithm, RecoveryKeyAlgorithm::P256Ecdsa);
    assert_eq!(
        pair.private_key,
        bytes("23a97dc00b349f96034c3b80af7e15ac54fcec4a4d48edf289033a5cf22de309")
    );
    assert_eq!(pair.public_key.len(), 65);
    assert_eq!(pair.public_key[0], 0x04);
    assert_eq!(
        pair.public_key,
        bytes(
            "0445c5b666571800528f30fae198fd22943ed84e9b22fb1734446cb1903a235daac826b4b7ad2d5fb4df9c569f416195089002a8c3d805239e6eaa256c731b5da9"
        )
    );
    let ed25519 = derive_recovery_key_pair(
        PHRASE.to_owned(),
        USER_ID.to_owned(),
        RecoveryKeyAlgorithm::Ed25519,
    )
    .unwrap();
    assert_ne!(pair.private_key, ed25519.private_key);
}

#[test]
fn recovers_generated_phrase_through_native_api() {
    for word_count in [12, 15, 18, 21, 24] {
        let phrase = generate_recovery_mnemonic(word_count).unwrap();
        assert_eq!(phrase.split_whitespace().count(), word_count as usize);
        for algorithm in [
            RecoveryKeyAlgorithm::Ed25519,
            RecoveryKeyAlgorithm::P256Ecdsa,
        ] {
            let original =
                derive_recovery_key_pair(phrase.clone(), USER_ID.to_owned(), algorithm).unwrap();
            let recovered =
                derive_recovery_key_pair(phrase.clone(), USER_ID.to_owned(), algorithm).unwrap();
            assert_eq!(original.private_key, recovered.private_key);
            assert_eq!(original.public_key, recovered.public_key);
            assert_eq!(original.private_key.len(), 32);
            assert_eq!(
                original.public_key.len(),
                if algorithm == RecoveryKeyAlgorithm::Ed25519 {
                    32
                } else {
                    65
                }
            );
        }
    }
}

#[test]
fn maps_unsupported_generation_word_counts() {
    for count in [0, 11, 13, 25, u32::MAX] {
        assert!(matches!(
            generate_recovery_mnemonic(count),
            Err(MnemonicFfiError::InvalidWordCount)
        ));
    }
}

#[test]
fn maps_redacted_input_errors() {
    assert!(matches!(
        derive_recovery_key_pair(
            "invalid phrase".to_owned(),
            USER_ID.to_owned(),
            RecoveryKeyAlgorithm::Ed25519
        ),
        Err(MnemonicFfiError::InvalidMnemonic)
    ));
    assert!(matches!(
        derive_recovery_key_pair(
            PHRASE.to_owned(),
            "alice".to_owned(),
            RecoveryKeyAlgorithm::P256Ecdsa
        ),
        Err(MnemonicFfiError::InvalidUserId)
    ));
    assert_eq!(
        MnemonicFfiError::InvalidMnemonic.to_string(),
        "invalid recovery mnemonic"
    );
    assert_eq!(
        MnemonicFfiError::InvalidUserId.to_string(),
        "invalid recovery user ID"
    );
}
