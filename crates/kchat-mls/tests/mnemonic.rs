use ed25519_dalek::{Signer, SigningKey};
use kchat_mls::mnemonic::{
    MnemonicError, RecoveryKeyAlgorithm, derive_recovery_key_pair, generate_recovery_mnemonic,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::Verifier as _,
};

const USER_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn bytes(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
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
            USER_ID,
            "8f0ba8ccacc985ec2f009b55d22d67cc4e7061096f4d37f174a03a8a076db81b",
            "34ec80fad18e2e212526b5315c47009e028349e557996551bc6a17456d99c7e4",
        ),
        (
            PHRASE,
            "00112233-4455-6677-8899-aabbccddeefe",
            "0a39e8f011562c5d5928fee730246fff407123c593a4c4e4a15034616668b145",
            "2a6931ac72b34b6206760d46d6dc3010c533ac92c485c8831c393750586a19f9",
        ),
        (
            zoo.as_str(),
            USER_ID,
            "d37aed1f9750f99c5bdd53220a59ed687e44bd8c8d797ee98f5ecf3621d93cd2",
            "65716a31bd0e2674d12e30fabb0706858e51159145ed423bafd4d402cb54225f",
        ),
        (
            twelve,
            USER_ID,
            "a2a2d6cafba8a2a03f9dd834accef32e4b33c2862a77609beda27921ba15277b",
            "6831019e5b7e766c04ba869ffde610a428fba8213b65319cb5d5cfa6527c2349",
        ),
    ];
    for (mnemonic, user_id, private_key, public_key) in vectors {
        let pair =
            derive_recovery_key_pair(mnemonic, user_id, RecoveryKeyAlgorithm::Ed25519).unwrap();
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
    let pair = derive_recovery_key_pair(PHRASE, USER_ID, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(
        pair.export_private_key(),
        bytes("23a97dc00b349f96034c3b80af7e15ac54fcec4a4d48edf289033a5cf22de309")
    );
    let expected_public = "0445c5b666571800528f30fae198fd22943ed84e9b22fb1734446cb1903a235daac826b4b7ad2d5fb4df9c569f416195089002a8c3d805239e6eaa256c731b5da9";
    assert_eq!(pair.public_key().len(), 65);
    assert_eq!(pair.public_key()[0], 0x04);
    assert_eq!(pair.public_key(), bytes_any(expected_public));
    let signer = P256SigningKey::from_slice(&pair.export_private_key()).unwrap();
    let verifier = P256VerifyingKey::from_sec1_bytes(pair.public_key()).unwrap();
    let signature: P256Signature = signer.sign(b"recovery proof");
    verifier.verify(b"recovery proof", &signature).unwrap();
    assert!(verifier.verify(b"other proof", &signature).is_err());

    let other = derive_recovery_key_pair(
        PHRASE,
        "00112233-4455-6677-8899-aabbccddeefe",
        RecoveryKeyAlgorithm::P256Ecdsa,
    )
    .unwrap();
    assert_eq!(
        other.export_private_key(),
        bytes("e71a5f519c76f3203957f7675e0213cba25a50ec10d7e7fa42a0af26c421fb93")
    );
    assert_eq!(
        other.public_key(),
        bytes_any(
            "04467c6192dd88863bfc5c4caca93ec1472a5deab3263e1ae47557a6179adc94f8ac4d4cad9f14934057f6f6f354607955a39bb68910652eaa75655f415029e8be"
        )
    );
    assert_ne!(pair.public_key(), other.public_key());
}

#[test]
fn algorithm_selection_separates_key_pairs_and_canonicalizes_uuid() {
    let selected =
        derive_recovery_key_pair(PHRASE, USER_ID, RecoveryKeyAlgorithm::Ed25519).unwrap();
    assert_eq!(
        selected.export_private_key(),
        bytes("8f0ba8ccacc985ec2f009b55d22d67cc4e7061096f4d37f174a03a8a076db81b")
    );
    let p256 = derive_recovery_key_pair(
        PHRASE,
        "00112233-4455-6677-8899-AABBCCDDEEFF",
        RecoveryKeyAlgorithm::P256Ecdsa,
    )
    .unwrap();
    let p256_lower =
        derive_recovery_key_pair(PHRASE, USER_ID, RecoveryKeyAlgorithm::P256Ecdsa).unwrap();
    assert_eq!(p256.export_private_key(), p256_lower.export_private_key());
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
                let original = derive_recovery_key_pair(&phrase, USER_ID, algorithm).unwrap();
                let recovered = derive_recovery_key_pair(&phrase, USER_ID, algorithm).unwrap();
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
fn canonicalizes_uuid_and_preserves_mnemonic_parser_normalization() {
    let original =
        derive_recovery_key_pair(PHRASE, USER_ID, RecoveryKeyAlgorithm::Ed25519).unwrap();
    for id in [
        "00112233-4455-6677-8899-AABBCCDDEEFF",
        "00112233445566778899aabbccddeeff",
    ] {
        let pair = derive_recovery_key_pair(PHRASE, id, RecoveryKeyAlgorithm::Ed25519).unwrap();
        assert_eq!(original.export_private_key(), pair.export_private_key());
        assert_eq!(original.public_key(), pair.public_key());
    }
    for phrase in [
        format!("  {PHRASE}\n"),
        PHRASE.replace(' ', "\t"),
        PHRASE.replace(' ', "\u{3000}"),
    ] {
        let pair =
            derive_recovery_key_pair(&phrase, USER_ID, RecoveryKeyAlgorithm::Ed25519).unwrap();
        assert_eq!(original.export_private_key(), pair.export_private_key());
    }
    assert!(
        derive_recovery_key_pair(
            PHRASE,
            "00000000-0000-0000-0000-000000000000",
            RecoveryKeyAlgorithm::Ed25519
        )
        .is_ok()
    );
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
        let error =
            derive_recovery_key_pair(&phrase, USER_ID, RecoveryKeyAlgorithm::Ed25519).unwrap_err();
        assert_eq!(error, MnemonicError::InvalidMnemonic);
        assert_eq!(error.to_string(), "invalid recovery mnemonic");
    }
}

#[test]
fn rejects_invalid_uuid_without_echoing_inputs() {
    for user_id in ["", "alice", "00112233-4455-6677-8899-aabbccddeefg"] {
        let error =
            derive_recovery_key_pair(PHRASE, user_id, RecoveryKeyAlgorithm::Ed25519).unwrap_err();
        assert_eq!(error, MnemonicError::InvalidUserId);
        assert_eq!(error.to_string(), "invalid recovery user ID");
        assert_eq!(format!("{error:?}"), "InvalidUserId");
    }
}
