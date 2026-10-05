use ed25519_dalek::{Signer, SigningKey};
use kchat_mls::mnemonic::{
    MnemonicError, RecoveryKeyAlgorithm, derive_recovery_key_pair, generate_recovery_mnemonic,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::Verifier as _,
};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn bytes(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn derives_recovery_pair_from_mnemonic_without_user_id() {
    let ed = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::Ed25519).unwrap();
    assert_eq!(
        ed.export_private_key(),
        bytes("ff5ff68d317dbac80476dd3d86edbded67928661695ddbcb0b4b73f5eac93530")
    );
    assert_eq!(
        ed.public_key(),
        bytes("e91441a2e27aae26a5a1c4a79057a15cf11eeafde63f08c803c20558c3cfe007")
    );

    let p256 = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(
        p256.export_private_key(),
        bytes("77ed7a856a5ae22bc5bd3d6ca29db7093ebdf26f1c8508f1aae6ddba3f32fbb1")
    );
    assert_eq!(
        p256.public_key(),
        bytes_any(
            "04c87f59bc53882f9cba411786b871c49fa4c521f679ad9ba441d689b81cb9ba39ed0fdfa451d13811df4270ab2bd942c4922777c7381c7ac56db944b81d90bc1a"
        )
    );
}

#[test]
fn matches_independent_recovery_vectors_and_can_sign() {
    // Independently derived with Python hashlib/hmac PBKDF2/HKDF and cryptography 48.0.0 Ed25519.
    // BIP39 passphrase is empty; both HKDF salts are None; the master label is KCHAT_RECOVERY_V1_MASTER.
    let zoo = [["zoo"; 23].join(" "), "vote".to_owned()].join(" ");
    let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let vectors = [
        (
            PHRASE,
            "ff5ff68d317dbac80476dd3d86edbded67928661695ddbcb0b4b73f5eac93530",
            "e91441a2e27aae26a5a1c4a79057a15cf11eeafde63f08c803c20558c3cfe007",
        ),
        (
            zoo.as_str(),
            "7486b46029b22f7b6dad69c079368869c036b14c1d6954b5ac0500aeb7d7c8f7",
            "a70b8228c1fc8f7add9612785684791b7bc49007d76ea2bbf468694f665a9509",
        ),
        (
            twelve,
            "42607c0b25a444d0d450ed0c626c88a2e80138e438687e65627aa68ee13daff2",
            "9857253c49add3ae1f9c79ea4e48ba8cca8571ba815d391103bcd4fcc1d630d2",
        ),
    ];
    for (mnemonic, private_key, public_key) in vectors {
        let pair = derive_recovery_key_pair(mnemonic, RecoveryKeyAlgorithm::Ed25519).unwrap();
        assert_eq!(pair.export_private_key(), bytes(private_key));
        assert_eq!(pair.public_key(), bytes(public_key));
        let signer = SigningKey::from_bytes(&pair.export_private_key());
        assert_eq!(signer.verifying_key().to_bytes(), pair.public_key());
        let message = b"recovery proof";
        let signature = signer.sign(message);
        signer
            .verifying_key()
            .verify_strict(message, &signature)
            .unwrap();
        assert!(
            signer
                .verifying_key()
                .verify_strict(b"other proof", &signature)
                .is_err()
        );
        assert_eq!(format!("{pair:?}"), "RecoveryKeyPair(REDACTED)");
    }
}

#[test]
fn derives_p256_ecdsa_with_independent_sec1_vectors_and_signs() {
    // Independently generated using Python hashlib/hmac and cryptography SECP256R1/X9.62.
    let pair = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(
        pair.export_private_key(),
        bytes("77ed7a856a5ae22bc5bd3d6ca29db7093ebdf26f1c8508f1aae6ddba3f32fbb1")
    );
    let expected_public = "04c87f59bc53882f9cba411786b871c49fa4c521f679ad9ba441d689b81cb9ba39ed0fdfa451d13811df4270ab2bd942c4922777c7381c7ac56db944b81d90bc1a";
    assert_eq!(pair.public_key().len(), 65);
    assert_eq!(pair.public_key()[0], 0x04);
    assert_eq!(pair.public_key(), bytes_any(expected_public));
    let signer = P256SigningKey::from_slice(&pair.export_private_key()).unwrap();
    let verifier = P256VerifyingKey::from_sec1_bytes(pair.public_key()).unwrap();
    let signature: P256Signature = signer.sign(b"recovery proof");
    verifier.verify(b"recovery proof", &signature).unwrap();
    assert!(verifier.verify(b"other proof", &signature).is_err());

    let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let other = derive_recovery_key_pair(twelve, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(
        other.export_private_key(),
        bytes("ad839e943124df53b1c4ebcd1032969c0f76eef59375acd1733fb0a354a71de7")
    );
    assert_eq!(
        other.public_key(),
        bytes_any(
            "049c510f45212cb231ad8df8f53b94c970428f1e00784134dbdf57787dad4e2b4f1ebf446f096bd34f03c178361cd68faab5985a32c453587704a60cb8c2ac19e0"
        )
    );
    assert_ne!(pair.public_key(), other.public_key());
}

#[test]
fn algorithm_selection_separates_key_pairs() {
    let selected = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::Ed25519).unwrap();
    assert_eq!(
        selected.export_private_key(),
        bytes("ff5ff68d317dbac80476dd3d86edbded67928661695ddbcb0b4b73f5eac93530")
    );
    let p256 = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_ne!(p256.export_private_key(), selected.export_private_key());
}

fn bytes_any(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn generates_each_supported_word_count_and_recovers_on_another_call() {
    for word_count in [12, 15, 18, 21, 24] {
        let first = generate_recovery_mnemonic(word_count).unwrap();
        let second = generate_recovery_mnemonic(word_count).unwrap();
        assert_ne!(first, second);
        for phrase in [first, second] {
            assert_eq!(phrase.split_whitespace().count(), word_count as usize);
            for algorithm in [
                RecoveryKeyAlgorithm::Ed25519,
                RecoveryKeyAlgorithm::P256Ecdsa,
            ] {
                let original = derive_recovery_key_pair(&phrase, algorithm).unwrap();
                let recovered = derive_recovery_key_pair(&phrase, algorithm).unwrap();
                assert_eq!(
                    original.export_private_key(),
                    recovered.export_private_key()
                );
                assert_eq!(original.public_key(), recovered.public_key());
            }
        }
    }
}

#[test]
fn rejects_unsupported_generation_word_counts() {
    for count in [0, 1, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, u32::MAX] {
        assert_eq!(
            generate_recovery_mnemonic(count).unwrap_err(),
            MnemonicError::InvalidWordCount
        );
    }
}

#[test]
fn preserves_mnemonic_parser_normalization() {
    let original = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::Ed25519).unwrap();
    for phrase in [
        format!("  {PHRASE}\n"),
        PHRASE.replace(' ', "\t"),
        PHRASE.replace(' ', "\u{3000}"),
    ] {
        let pair = derive_recovery_key_pair(&phrase, RecoveryKeyAlgorithm::Ed25519).unwrap();
        assert_eq!(original.export_private_key(), pair.export_private_key());
    }
}

#[test]
fn rejects_invalid_phrase_lengths_words_and_checksum() {
    for phrase in [
        "".to_owned(),
        ["abandon"; 11].join(" "),
        ["abandon"; 13].join(" "),
        ["abandon"; 25].join(" "),
        ["abandon"; 24].join(" "),
        PHRASE.replace("art", "notaword"),
        PHRASE.replace("art", "こんにちは"),
    ] {
        let error = derive_recovery_key_pair(&phrase, RecoveryKeyAlgorithm::Ed25519).unwrap_err();
        assert_eq!(error, MnemonicError::InvalidMnemonic);
        assert_eq!(error.to_string(), "invalid recovery mnemonic");
    }
}
