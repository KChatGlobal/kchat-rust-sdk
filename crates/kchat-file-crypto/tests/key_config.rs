mod common;

use ed25519_dalek::SigningKey;
use kchat_file_crypto::{
    FileCryptoErrorCode, FileKeyring, KKeyRootKey, MAX_ID_BYTES, ProfilePolicy, TenantId,
};

use crate::common::{FakeKKey, TENANT, TestKeyring, hash, reopen, tenant};

fn import_key(
    keyring: &FileKeyring,
    kkey: &FakeKKey,
    key_gen: u64,
) -> Result<(), FileCryptoErrorCode> {
    let public_key = kkey.public_key();
    keyring
        .import_public_key(
            &tenant(),
            key_gen,
            &public_key,
            &kkey.sign_public_key(TENANT, key_gen, &public_key),
        )
        .map_err(|error| error.code())
}

fn import_policy(
    keyring: &FileKeyring,
    kkey: &FakeKKey,
    version: u64,
    policy: &str,
) -> Result<(), FileCryptoErrorCode> {
    keyring
        .import_policy(
            &tenant(),
            version,
            policy,
            &kkey.sign_policy(TENANT, version, policy),
        )
        .map_err(|error| error.code())
}

#[test]
fn imports_signed_key_and_policy() {
    let kkey = FakeKKey::new(1, 1_700_000_000);
    let keyring = TestKeyring::new(Some(kkey.root_key()));
    assert!(
        keyring
            .key_source_status(&tenant())
            .unwrap()
            .needs_key_config()
    );

    import_key(&keyring, &kkey, kkey.key_gen).unwrap();
    assert!(
        keyring
            .key_source_status(&tenant())
            .unwrap()
            .needs_key_config()
    );
    import_policy(&keyring, &kkey, 10, "HYBRID").unwrap();

    let status = keyring.key_source_status(&tenant()).unwrap();
    assert!(!status.needs_key_config());
    assert_eq!(status.policy(), Some(ProfilePolicy::Hybrid));
    assert_eq!(status.policy_version(), Some(10));
    assert_eq!(status.key_gen(), Some(kkey.key_gen));
    assert_eq!(status.pepper_gen(), None);
}

#[test]
fn rejects_signatures_from_unknown_roots_or_other_messages() {
    let kkey = FakeKKey::new(1, 5);
    let stranger = FakeKKey::new(2, 5);
    let keyring = TestKeyring::new(Some(kkey.root_key()));
    let public_key = kkey.public_key();

    let cases = [
        // Signed by a root the store does not trust.
        stranger.sign_public_key(TENANT, 5, &public_key),
        // Signed for another tenant.
        kkey.sign_public_key("tenant-b", 5, &public_key),
        // Signed for another generation.
        kkey.sign_public_key(TENANT, 6, &public_key),
        // Signed for another key.
        kkey.sign_public_key(TENANT, 5, &stranger.public_key()),
        // Malformed signature.
        vec![0; 64],
        vec![0; 63],
    ];
    for signature in cases {
        let error = keyring
            .import_public_key(&tenant(), 5, &public_key, &signature)
            .unwrap_err();
        assert_eq!(error.code(), FileCryptoErrorCode::KKeySignatureInvalid);
    }

    let error = keyring
        .import_policy(
            &tenant(),
            1,
            "HYBRID",
            &kkey.sign_policy(TENANT, 1, "RANDOM"),
        )
        .unwrap_err();
    assert_eq!(error.code(), FileCryptoErrorCode::KKeySignatureInvalid);
    assert!(
        keyring
            .key_source_status(&tenant())
            .unwrap()
            .needs_key_config()
    );
}

#[test]
fn stores_without_a_root_reject_every_configuration() {
    let kkey = FakeKKey::new(1, 5);
    let keyring = TestKeyring::new(None);
    assert_eq!(
        import_key(&keyring, &kkey, 5),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    assert_eq!(
        import_policy(&keyring, &kkey, 1, "HYBRID"),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
}

#[test]
fn rejects_identity_or_malformed_public_keys_even_when_signed() {
    let kkey = FakeKKey::new(1, 5);
    let keyring = TestKeyring::new(Some(kkey.root_key()));
    for public_key in [
        vec![0_u8; 32],
        vec![0xFF; 32],
        kkey.public_key()[..31].to_vec(),
    ] {
        let signature = kkey.sign_public_key(TENANT, 5, &public_key);
        let error = keyring
            .import_public_key(&tenant(), 5, &public_key, &signature)
            .unwrap_err();
        assert_eq!(error.code(), FileCryptoErrorCode::KKeySignatureInvalid);
    }
}

#[test]
fn generations_only_move_forward_across_restarts() {
    let kkey = FakeKKey::new(1, 0);
    let rotated = FakeKKey::with_root(3, 0, SigningKey::from_bytes(&[101; 32]));
    let keyring = TestKeyring::new(Some(kkey.root_key()));

    import_key(&keyring, &kkey, 100).unwrap();
    import_key(&keyring, &kkey, 100).unwrap();
    assert_eq!(
        import_key(&keyring, &rotated, 100),
        Err(FileCryptoErrorCode::KeyConflict)
    );
    assert_eq!(
        import_key(&keyring, &kkey, 99),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    import_key(&keyring, &rotated, 1_000).unwrap();

    let (_dir, path) = keyring.close();
    let reopened = reopen(&path, Some(kkey.root_key()));
    assert_eq!(
        reopened.key_source_status(&tenant()).unwrap().key_gen(),
        Some(1_000)
    );
    assert_eq!(
        import_key(&reopened, &kkey, 100),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
}

#[test]
fn policy_versions_only_move_forward_across_restarts() {
    let kkey = FakeKKey::new(1, 1);
    let keyring = TestKeyring::new(Some(kkey.root_key()));

    import_policy(&keyring, &kkey, 20, "RANDOM").unwrap();
    import_policy(&keyring, &kkey, 20, "RANDOM").unwrap();
    assert_eq!(
        import_policy(&keyring, &kkey, 20, "HYBRID"),
        Err(FileCryptoErrorCode::KeyConflict)
    );
    assert_eq!(
        import_policy(&keyring, &kkey, 19, "HYBRID"),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    import_policy(&keyring, &kkey, 21, "HYBRID").unwrap();

    let (_dir, path) = keyring.close();
    let reopened = reopen(&path, Some(kkey.root_key()));
    assert_eq!(
        reopened.key_source_status(&tenant()).unwrap().policy(),
        Some(ProfilePolicy::Hybrid)
    );
    assert_eq!(
        import_policy(&reopened, &kkey, 20, "RANDOM"),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
}

#[test]
fn unknown_policy_names_are_treated_as_random() {
    let kkey = FakeKKey::new(1, 1);
    let keyring = TestKeyring::new(Some(kkey.root_key()));
    import_policy(&keyring, &kkey, 1, "PEPPER_ONLY").unwrap();
    assert_eq!(
        keyring.key_source_status(&tenant()).unwrap().policy(),
        Some(ProfilePolicy::Random)
    );

    assert_eq!(
        import_policy(&keyring, &kkey, 2, ""),
        Err(FileCryptoErrorCode::InvalidArgument)
    );
    assert_eq!(
        import_policy(&keyring, &kkey, 2, &"H".repeat(65)),
        Err(FileCryptoErrorCode::InvalidArgument)
    );
}

#[test]
fn trusts_only_the_root_it_was_opened_with() {
    let old_root = FakeKKey::new(1, 1);
    let new_root = FakeKKey::new(2, 2);
    let keyring = TestKeyring::new(Some(old_root.root_key()));
    import_key(&keyring, &old_root, 1).unwrap();
    assert_eq!(
        import_key(&keyring, &new_root, 2),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );

    // Root change: reopen with a new root. Keys signed by the old root are pruned on open and its
    // signatures are rejected from then on.
    let (_dir, path) = keyring.close();
    let reopened = reopen(&path, Some(new_root.root_key()));
    assert_eq!(
        reopened.key_source_status(&tenant()).unwrap().key_gen(),
        None
    );
    import_key(&reopened, &new_root, 2).unwrap();
    assert_eq!(
        import_key(&reopened, &old_root, 3),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    assert_eq!(
        reopened.key_source_status(&tenant()).unwrap().key_gen(),
        Some(2)
    );
}

#[test]
fn a_new_root_starts_from_its_own_rollback_floor() {
    let old_root = FakeKKey::new(1, 100);
    let new_root = FakeKKey::new(2, 5);
    let keyring = TestKeyring::new(Some(old_root.root_key()));
    import_key(&keyring, &old_root, 100).unwrap();
    import_policy(&keyring, &old_root, 20, "HYBRID").unwrap();

    // Generations and versions signed by the old root do not block lower values from the new root.
    let (_dir, path) = keyring.close();
    let reopened = reopen(&path, Some(new_root.root_key()));
    let status = reopened.key_source_status(&tenant()).unwrap();
    assert_eq!((status.key_gen(), status.policy()), (None, None));
    import_key(&reopened, &new_root, 5).unwrap();
    import_policy(&reopened, &new_root, 1, "RANDOM").unwrap();

    reopened.close().unwrap();
    let again = reopen(&path, Some(new_root.root_key()));
    let status = again.key_source_status(&tenant()).unwrap();
    assert_eq!(status.key_gen(), Some(5));
    assert_eq!(status.policy(), Some(ProfilePolicy::Random));
    assert_eq!(
        import_key(&again, &new_root, 4),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
}

#[test]
fn reopening_without_a_root_drops_the_config_but_keeps_the_pepper() {
    let kkey = FakeKKey::new(1, 7);
    let keyring = kkey.keyring("HYBRID");
    assert!(keyring.begin_oprf(&tenant(), &[&hash(b"content")]).is_ok());

    let (_dir, path) = keyring.close();
    let reopened = reopen(&path, None);
    let status = reopened.key_source_status(&tenant()).unwrap();
    assert!(status.needs_key_config());
    assert_eq!((status.key_gen(), status.policy()), (None, None));
    assert_eq!(status.pepper_gen(), Some(1));
    let error = reopened
        .begin_oprf(&tenant(), &[&hash(b"content")])
        .unwrap_err();
    assert_eq!(error.code(), FileCryptoErrorCode::KeyConfigRequired);

    reopened.close().unwrap();
    let restored = reopen(&path, Some(kkey.root_key()));
    assert!(
        restored
            .key_source_status(&tenant())
            .unwrap()
            .needs_key_config()
    );
    import_key(&restored, &kkey, kkey.key_gen).unwrap();
    import_policy(&restored, &kkey, 1, "HYBRID").unwrap();
    assert!(restored.begin_oprf(&tenant(), &[&hash(b"content")]).is_ok());
}

#[test]
fn tenants_are_isolated() {
    let kkey = FakeKKey::new(1, 1);
    let keyring = kkey.keyring("HYBRID");
    let other = TenantId::parse("tenant-b").unwrap();
    let status = keyring.key_source_status(&other).unwrap();
    assert!(status.needs_key_config());
    assert_eq!(status.policy(), None);
    assert_eq!(status.pepper_gen(), None);
}

#[test]
fn rejects_invalid_roots_and_ids() {
    assert!(KKeyRootKey::from_bytes(&[1; 31]).is_err());
    // The identity point is a weak (small-order) Ed25519 key.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    assert!(KKeyRootKey::from_bytes(&identity).is_err());

    assert!(TenantId::parse("").is_err());
    assert!(TenantId::parse(&"t".repeat(MAX_ID_BYTES)).is_ok());
    assert!(TenantId::parse(&"t".repeat(MAX_ID_BYTES + 1)).is_err());
}

#[test]
fn opening_without_a_root_keeps_the_rollback_floor() {
    let kkey = FakeKKey::new(1, 0);
    let keyring = TestKeyring::new(Some(kkey.root_key()));
    import_key(&keyring, &kkey, 100).unwrap();
    import_policy(&keyring, &kkey, 20, "RANDOM").unwrap();

    // One open without a root drops the signed rows, but not how far they had advanced.
    let (_dir, path) = keyring.close();
    reopen(&path, None).close().unwrap();
    let restored = reopen(&path, Some(kkey.root_key()));
    assert!(
        restored
            .key_source_status(&tenant())
            .unwrap()
            .needs_key_config()
    );
    assert_eq!(
        import_key(&restored, &kkey, 99),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    assert_eq!(
        import_policy(&restored, &kkey, 19, "HYBRID"),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    import_key(&restored, &kkey, 100).unwrap();
    import_policy(&restored, &kkey, 20, "RANDOM").unwrap();
}

#[test]
fn switching_back_to_an_earlier_root_keeps_its_rollback_floor() {
    let old_root = FakeKKey::new(1, 100);
    let new_root = FakeKKey::new(2, 5);
    let keyring = TestKeyring::new(Some(old_root.root_key()));
    import_key(&keyring, &old_root, 100).unwrap();
    import_policy(&keyring, &old_root, 20, "RANDOM").unwrap();

    let (_dir, path) = keyring.close();
    let other = reopen(&path, Some(new_root.root_key()));
    import_key(&other, &new_root, 5).unwrap();
    other.close().unwrap();

    let back = reopen(&path, Some(old_root.root_key()));
    assert_eq!(
        import_key(&back, &old_root, 99),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    assert_eq!(
        import_policy(&back, &old_root, 1, "HYBRID"),
        Err(FileCryptoErrorCode::KKeySignatureInvalid)
    );
    import_key(&back, &old_root, 101).unwrap();
    import_policy(&back, &old_root, 21, "HYBRID").unwrap();
}
