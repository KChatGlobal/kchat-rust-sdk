use kchat_mobile_sdk_rs::{
    BackupDescriptorBootstrap, BackupFfiError, BackupKeyMode, generate_mnemonic, generate_password,
    import_from_raw,
};

const ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";

#[test]
fn generates_a_mnemonic_with_the_requested_word_count() {
    for word_count in [12, 15, 18, 21, 24] {
        let generated = generate_mnemonic(word_count).unwrap();
        assert_eq!(
            generated.mnemonic.split_whitespace().count(),
            word_count as usize
        );
        assert_eq!(generated.key.mode(), BackupKeyMode::Mnemonic);

        let descriptor = generated
            .key
            .seal_descriptor(ACCOUNT.to_owned(), BackupDescriptorBootstrap::Mnemonic)
            .unwrap();
        let imported =
            import_from_raw(BackupKeyMode::Mnemonic, generated.key.export_raw()).unwrap();
        assert_eq!(&descriptor[..4], b"KCBD");
        assert_eq!(
            generated.key.derive_backup_id(ACCOUNT.to_owned()).unwrap(),
            imported.derive_backup_id(ACCOUNT.to_owned()).unwrap(),
        );
    }
}

#[test]
fn rejects_unsupported_mnemonic_word_counts() {
    for word_count in [0, 11, 13, 25, u32::MAX] {
        assert!(matches!(
            generate_mnemonic(word_count),
            Err(BackupFfiError::InvalidArgument)
        ));
    }
}

#[test]
fn password_generation_preserves_raw_bytes_and_seals_a_password_descriptor() {
    let generated = generate_password(vec![0x68, 0xc3, 0xa9]).unwrap();

    assert_eq!(generated.salt.len(), 16);
    assert_eq!(generated.key.mode(), BackupKeyMode::Password);

    let descriptor = generated
        .key
        .seal_descriptor(
            ACCOUNT.to_owned(),
            BackupDescriptorBootstrap::Password {
                salt: generated.salt.clone(),
            },
        )
        .unwrap();

    assert_eq!(&descriptor[..4], b"KCBD");
    assert_eq!(descriptor[6], 2);
    assert_eq!(&descriptor[10..26], generated.salt.as_slice());
}

#[test]
fn rejects_empty_password_before_key_derivation() {
    assert!(matches!(
        generate_password(Vec::new()),
        Err(BackupFfiError::EmptyPassword)
    ));
}

#[test]
fn rejects_invalid_password_key_import_length() {
    assert!(matches!(
        import_from_raw(BackupKeyMode::Password, vec![0; 31]),
        Err(BackupFfiError::InvalidPasswordKey)
    ));
}

#[test]
fn rejects_a_descriptor_bootstrap_that_does_not_match_the_key_mode() {
    let generated = generate_mnemonic(24).unwrap();

    assert_eq!(
        generated
            .key
            .seal_descriptor(
                ACCOUNT.to_owned(),
                BackupDescriptorBootstrap::Password { salt: vec![0; 16] },
            )
            .unwrap_err(),
        BackupFfiError::InvalidArgument,
    );
}

#[test]
fn imports_a_secure_storage_root_with_its_persisted_mode() {
    let generated = generate_password(vec![0x68, 0xc3, 0xa9]).unwrap();
    let exported = generated.key.export_raw();
    let imported = import_from_raw(BackupKeyMode::Password, exported).unwrap();

    assert_eq!(
        generated.key.derive_backup_id(ACCOUNT.to_owned()).unwrap(),
        imported.derive_backup_id(ACCOUNT.to_owned()).unwrap(),
    );
}

#[test]
fn rejects_an_object_context_with_a_mismatched_backup_id() {
    let generated = generate_mnemonic(24).unwrap();

    assert!(matches!(
        generated
            .key
            .create_object_context(ACCOUNT.to_owned(), vec![0; 32], vec![1; 16]),
        Err(BackupFfiError::ContextMismatch)
    ));
}
