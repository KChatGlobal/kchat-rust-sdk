use ed25519_dalek::{Signer, SigningKey, VerifyingKey, pkcs8::DecodePublicKey as _};
use kchat_mls::mnemonic::{
    MnemonicError, RecoveryKeyAlgorithm, RecoverySignatureError, derive_recovery_key_pair,
    generate_recovery_mnemonic, sign_recovery_message, verify_recovery_signature,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::{Verifier as _, hazmat::PrehashVerifier as _},
};
use sha2::{Digest as _, Sha256};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn bytes(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn exports_spki_der_public_keys_for_auth_go() {
    let ed = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::Ed25519).unwrap();
    assert_eq!(
        ed.public_key(),
        bytes_any(
            "302a300506032b6570032100e91441a2e27aae26a5a1c4a79057a15cf11eeafde63f08c803c20558c3cfe007"
        )
    );
    let p256 = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(
        p256.public_key(),
        bytes_any(
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004c87f59bc53882f9cba411786b871c49fa4c521f679ad9ba441d689b81cb9ba39ed0fdfa451d13811df4270ab2bd942c4922777c7381c7ac56db944b81d90bc1a"
        )
    );
}

#[test]
fn signs_and_verifies_recovery_messages_in_auth_go_formats() {
    let message = b"recovery challenge";
    for algorithm in [
        RecoveryKeyAlgorithm::Ed25519,
        RecoveryKeyAlgorithm::P256Ecdsa,
    ] {
        let pair = derive_recovery_key_pair(PHRASE, algorithm).unwrap();
        let signature =
            sign_recovery_message(algorithm, &pair.export_private_key(), message).unwrap();
        assert!(
            verify_recovery_signature(algorithm, pair.public_key(), message, &signature).unwrap()
        );
        assert!(
            !verify_recovery_signature(
                algorithm,
                pair.public_key(),
                b"wrong challenge",
                &signature
            )
            .unwrap()
        );
        if algorithm == RecoveryKeyAlgorithm::Ed25519 {
            assert_eq!(signature.len(), 64);
        } else {
            let verifier = P256VerifyingKey::from_public_key_der(pair.public_key()).unwrap();
            let parsed = P256Signature::from_der(&signature).unwrap();
            verifier
                .verify_prehash(&Sha256::digest(message), &parsed)
                .unwrap();
        }
    }
}

#[test]
fn rejects_wrong_recovery_keys_and_malformed_signatures() {
    let ed = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::Ed25519).unwrap();
    let p256 = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(
        sign_recovery_message(RecoveryKeyAlgorithm::Ed25519, &[0; 31], b"msg"),
        Err(RecoverySignatureError::InvalidPrivateKey)
    );
    assert_eq!(
        sign_recovery_message(RecoveryKeyAlgorithm::P256Ecdsa, &[0; 32], b"msg"),
        Err(RecoverySignatureError::InvalidPrivateKey)
    );
    assert_eq!(
        sign_recovery_message(RecoveryKeyAlgorithm::P256Ecdsa, &[1; 31], b"msg"),
        Err(RecoverySignatureError::InvalidPrivateKey)
    );
    assert_eq!(
        verify_recovery_signature(
            RecoveryKeyAlgorithm::Ed25519,
            p256.public_key(),
            b"msg",
            &[0; 64]
        ),
        Err(RecoverySignatureError::InvalidPublicKey)
    );
    assert_eq!(
        verify_recovery_signature(
            RecoveryKeyAlgorithm::P256Ecdsa,
            ed.public_key(),
            b"msg",
            &[0; 64]
        ),
        Err(RecoverySignatureError::InvalidPublicKey)
    );
    assert!(
        !verify_recovery_signature(
            RecoveryKeyAlgorithm::Ed25519,
            ed.public_key(),
            b"msg",
            &[0; 12]
        )
        .unwrap()
    );
    assert!(
        !verify_recovery_signature(
            RecoveryKeyAlgorithm::P256Ecdsa,
            p256.public_key(),
            b"msg",
            &[0; 64]
        )
        .unwrap()
    );
}

#[test]
fn derives_recovery_pair_from_mnemonic_without_user_id() {
    let ed = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::Ed25519).unwrap();
    assert_eq!(
        ed.export_private_key(),
        bytes("ff5ff68d317dbac80476dd3d86edbded67928661695ddbcb0b4b73f5eac93530")
    );
    assert_eq!(
        VerifyingKey::from_public_key_der(ed.public_key())
            .unwrap()
            .to_bytes(),
        bytes("e91441a2e27aae26a5a1c4a79057a15cf11eeafde63f08c803c20558c3cfe007")
    );

    let p256 = derive_recovery_key_pair(PHRASE, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(
        p256.export_private_key(),
        bytes("77ed7a856a5ae22bc5bd3d6ca29db7093ebdf26f1c8508f1aae6ddba3f32fbb1")
    );
    assert_eq!(
        P256VerifyingKey::from_public_key_der(p256.public_key())
            .unwrap()
            .to_sec1_point(false)
            .as_bytes(),
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
        assert_eq!(
            VerifyingKey::from_public_key_der(pair.public_key())
                .unwrap()
                .to_bytes(),
            bytes(public_key)
        );
        let signer = SigningKey::from_bytes(&pair.export_private_key());
        assert_eq!(
            signer.verifying_key().to_bytes(),
            VerifyingKey::from_public_key_der(pair.public_key())
                .unwrap()
                .to_bytes()
        );
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
    assert_eq!(pair.public_key().len(), 91);
    let verifier = P256VerifyingKey::from_public_key_der(pair.public_key()).unwrap();
    assert_eq!(
        verifier.to_sec1_point(false).as_bytes(),
        bytes_any(expected_public)
    );
    let signer = P256SigningKey::from_slice(&pair.export_private_key()).unwrap();
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
        P256VerifyingKey::from_public_key_der(other.public_key())
            .unwrap()
            .to_sec1_point(false)
            .as_bytes(),
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
