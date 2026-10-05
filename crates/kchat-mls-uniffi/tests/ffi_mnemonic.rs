use mls_mobile_sdk_rs::mnemonic::{
    MnemonicFfiError, RecoveryKeyAlgorithm, derive_recovery_key_pair, generate_recovery_mnemonic,
};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn exposes_versioned_recovery_bytes_without_an_mls_provider() {
    let pair = derive_recovery_key_pair(PHRASE.to_owned(), RecoveryKeyAlgorithm::Ed25519).unwrap();
    assert_eq!(pair.format_version, 1);
    assert_eq!(pair.algorithm, RecoveryKeyAlgorithm::Ed25519);
    assert_eq!(
        pair.private_key,
        bytes("ff5ff68d317dbac80476dd3d86edbded67928661695ddbcb0b4b73f5eac93530")
    );
    assert_eq!(
        pair.public_key,
        bytes("e91441a2e27aae26a5a1c4a79057a15cf11eeafde63f08c803c20558c3cfe007")
    );
}

#[test]
fn exports_p256_ecdsa_as_raw_scalar_and_uncompressed_sec1_public_key() {
    let pair =
        derive_recovery_key_pair(PHRASE.to_owned(), RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(pair.format_version, 1);
    assert_eq!(pair.algorithm, RecoveryKeyAlgorithm::P256Ecdsa);
    assert_eq!(
        pair.private_key,
        bytes("77ed7a856a5ae22bc5bd3d6ca29db7093ebdf26f1c8508f1aae6ddba3f32fbb1")
    );
    assert_eq!(pair.public_key.len(), 65);
    assert_eq!(pair.public_key[0], 0x04);
    assert_eq!(
        pair.public_key,
        bytes(
            "04c87f59bc53882f9cba411786b871c49fa4c521f679ad9ba441d689b81cb9ba39ed0fdfa451d13811df4270ab2bd942c4922777c7381c7ac56db944b81d90bc1a"
        )
    );
    let ed25519 =
        derive_recovery_key_pair(PHRASE.to_owned(), RecoveryKeyAlgorithm::Ed25519).unwrap();
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
            let original = derive_recovery_key_pair(phrase.clone(), algorithm).unwrap();
            let recovered = derive_recovery_key_pair(phrase.clone(), algorithm).unwrap();
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
        derive_recovery_key_pair("invalid phrase".to_owned(), RecoveryKeyAlgorithm::Ed25519),
        Err(MnemonicFfiError::InvalidMnemonic)
    ));
    assert_eq!(
        MnemonicFfiError::InvalidMnemonic.to_string(),
        "invalid recovery mnemonic"
    );
}
