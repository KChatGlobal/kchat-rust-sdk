mod common;

use ed25519_dalek::SigningKey;
use kchat_file_crypto::{
    ContentHash, ContentKey, ContentPlan, ContentProfile, FileCryptoErrorCode, FileKeyring,
    MAX_OPRF_BATCH_SIZE, OprfResponse, OprfSession, RandomPlanReason, SealedContent, open_content,
    seal_content,
};

use crate::common::{
    FakeKKey, MemorySource, PEPPER, RecordingSink, TENANT, TestKeyring, hash, hash_for,
    install_pepper, next_operation, reopen, sample, tenant,
};

const KEY_GEN: u64 = 1_700_000_000;

type ResponseTamper = Box<dyn Fn(&OprfResponse) -> OprfResponse>;

fn hybrid_plans(
    kkey: &FakeKKey,
    keyring: &FileKeyring,
    contents: &[&ContentHash],
) -> Vec<ContentPlan> {
    let (session, request) = keyring.begin_oprf(&tenant(), contents).unwrap();
    assert_eq!(request.blinded_elements().len(), contents.len());
    keyring
        .finish_oprf(session, &kkey.evaluate(&request))
        .unwrap()
}

fn seal(plan: &ContentPlan, plaintext: &[u8]) -> (SealedContent, Vec<u8>) {
    let mut sink = RecordingSink::default();
    let sealed = seal_content(plan, &mut MemorySource::new(plaintext), &mut sink).unwrap();
    assert!(sink.committed);
    (sealed, sink.bytes)
}

fn hybrid_ciphertext(kkey: &FakeKKey, keyring: &FileKeyring, plaintext: &[u8]) -> Vec<u8> {
    seal(
        &hybrid_plans(kkey, keyring, &[&hash(plaintext)])[0],
        plaintext,
    )
    .1
}

struct TwoContentSession {
    kkey: FakeKKey,
    keyring: TestKeyring,
    contents: [ContentHash; 2],
    session: OprfSession,
    response: OprfResponse,
}

fn two_content_session() -> TwoContentSession {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let contents = [hash(b"a"), hash(b"b")];
    let (session, request) = keyring
        .begin_oprf(&tenant(), &[&contents[0], &contents[1]])
        .unwrap();
    let response = kkey.evaluate(&request);
    TwoContentSession {
        kkey,
        keyring,
        contents,
        session,
        response,
    }
}

fn assert_rejected(
    keyring: &FileKeyring,
    contents: &[ContentHash; 2],
    session: OprfSession,
    response: &OprfResponse,
) {
    assert_eq!(
        keyring.finish_oprf(session, response).unwrap_err().code(),
        FileCryptoErrorCode::KKeyProofInvalid
    );
    for content in contents {
        assert!(keyring.prepared_plan(content).unwrap().is_none());
    }
}

#[test]
fn hybrid_plans_follow_request_order_and_generations() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let plaintexts = [sample(10, 1), sample(70_000, 2), Vec::new()];
    let contents: Vec<ContentHash> = plaintexts.iter().map(|bytes| hash(bytes)).collect();
    let refs: Vec<&ContentHash> = contents.iter().collect();

    let plans = hybrid_plans(&kkey, &keyring, &refs);
    assert_eq!(plans.len(), 3);
    for ((plan, plaintext), content) in plans.iter().zip(&plaintexts).zip(&contents) {
        assert_eq!(plan.operation_id(), content.operation_id());
        assert_eq!(
            plan.profile(),
            ContentProfile::HybridVoprfV1 {
                key_gen: KEY_GEN,
                pepper_gen: 1
            }
        );
        assert_eq!(plan.plaintext_len(), content.plaintext_len());
        assert_eq!(plan.random_reason(), None);

        let (sealed, ciphertext) = seal(plan, plaintext);
        let key = ContentKey::from_sealed(plan, &sealed).unwrap();
        let mut sink = RecordingSink::default();
        open_content(&key, &mut MemorySource::new(&ciphertext), &mut sink).unwrap();
        assert_eq!(&sink.bytes, plaintext);
    }
}

#[test]
fn independent_devices_with_same_pepper_produce_identical_ciphertext() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let plaintext = sample(200_000, 7);
    let first = hybrid_ciphertext(&kkey, &kkey.keyring("HYBRID"), &plaintext);
    let second = hybrid_ciphertext(&kkey, &kkey.keyring("HYBRID"), &plaintext);
    assert_eq!(first, second);
}

#[test]
fn stored_plans_survive_restarts_and_key_rotation() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let plaintext = sample(90_000, 3);
    let operation = next_operation();
    let plan = hybrid_plans(&kkey, &keyring, &[&hash_for(&operation, &plaintext)]).remove(0);
    let (sealed, bytes) = seal(&plan, &plaintext);
    drop(plan);

    // Restart after finish_oprf, with the key rotated in between.
    let (_dir, path) = keyring.close();
    let restarted = reopen(&path, Some(kkey.root_key()));
    let rotated = FakeKKey::with_root(9, KEY_GEN + 3_600, SigningKey::from_bytes(&[101; 32]));
    rotated.import_public_key(&restarted);

    let resumed = restarted
        .prepared_plan(&hash_for(&operation, &plaintext))
        .unwrap()
        .expect("plan was persisted");
    assert_eq!(
        resumed.profile(),
        ContentProfile::HybridVoprfV1 {
            key_gen: KEY_GEN,
            pepper_gen: 1
        }
    );
    let (resealed, rebytes) = seal(&resumed, &plaintext);
    assert_eq!(resealed, sealed);
    assert_eq!(rebytes, bytes);

    let (session, request) = restarted
        .begin_oprf(&tenant(), &[&hash_for(&operation, &plaintext)])
        .unwrap();
    assert_eq!(request.key_gen(), KEY_GEN + 3_600);
    let again = restarted
        .finish_oprf(session, &rotated.evaluate(&request))
        .unwrap();
    assert_eq!(seal(&again[0], &plaintext).1, bytes);

    let random = restarted
        .plan_random(
            &hash_for(&operation, &plaintext),
            RandomPlanReason::KKeyUnavailable,
        )
        .unwrap();
    assert_eq!(random.profile(), resumed.profile());
    assert_eq!(random.random_reason(), None);

    restarted.forget_operation(&operation).unwrap();
    assert!(
        restarted
            .prepared_plan(&hash_for(&operation, &plaintext))
            .unwrap()
            .is_none()
    );
}

#[test]
fn reusing_an_operation_for_other_content_conflicts() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let operation = next_operation();
    keyring
        .plan_random(&hash_for(&operation, b"first"), RandomPlanReason::SmallFile)
        .unwrap();

    let other = hash_for(&operation, b"second");
    assert_eq!(
        keyring.prepared_plan(&other).unwrap_err().code(),
        FileCryptoErrorCode::OperationConflict
    );
    assert_eq!(
        keyring
            .plan_random(&other, RandomPlanReason::SmallFile)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::OperationConflict
    );
    let (session, request) = keyring.begin_oprf(&tenant(), &[&other]).unwrap();
    assert_eq!(
        keyring
            .finish_oprf(session, &kkey.evaluate(&request))
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::OperationConflict
    );
}

#[test]
fn any_changed_input_changes_the_ciphertext() {
    let plaintext = sample(1_000, 3);
    let kkey = FakeKKey::new(1, KEY_GEN);
    let base = hybrid_ciphertext(&kkey, &kkey.keyring("HYBRID"), &plaintext);

    // Newer pepper generation with different bytes.
    let rotated_pepper = kkey.keyring("HYBRID");
    install_pepper(&rotated_pepper, 2, &[0x78; 32]);
    // Same pepper bytes, newer generation.
    let renumbered_pepper = kkey.keyring("HYBRID");
    install_pepper(&renumbered_pepper, 2, &PEPPER);
    // Another key-service key, and another generation of the same key.
    let other_key = FakeKKey::new(2, KEY_GEN);
    let next_gen = FakeKKey::new(1, KEY_GEN + 60);

    for variant in [
        hybrid_ciphertext(&kkey, &rotated_pepper, &plaintext),
        hybrid_ciphertext(&kkey, &renumbered_pepper, &plaintext),
        hybrid_ciphertext(&other_key, &other_key.keyring("HYBRID"), &plaintext),
        hybrid_ciphertext(&next_gen, &next_gen.keyring("HYBRID"), &plaintext),
    ] {
        assert_ne!(variant, base);
    }
}

#[test]
fn accepts_the_genuine_response() {
    let setup = two_content_session();
    let plans = setup
        .keyring
        .finish_oprf(setup.session, &setup.response)
        .unwrap();
    assert_eq!(plans.len(), 2);
    assert!(
        setup
            .keyring
            .prepared_plan(&setup.contents[0])
            .unwrap()
            .is_some()
    );
}

#[test]
fn rejects_responses_that_do_not_verify_and_writes_nothing() {
    // Evaluated for another session's blinds.
    let setup = two_content_session();
    let (_, other_request) = setup
        .keyring
        .begin_oprf(&tenant(), &[&setup.contents[0], &setup.contents[1]])
        .unwrap();
    assert_rejected(
        &setup.keyring,
        &setup.contents,
        setup.session,
        &setup.kkey.evaluate(&other_request),
    );

    // Evaluated with another key-service key.
    let setup = two_content_session();
    let (_, request) = setup
        .keyring
        .begin_oprf(&tenant(), &[&setup.contents[0], &setup.contents[1]])
        .unwrap();
    let wrong_key = FakeKKey::new(9, KEY_GEN).evaluate(&request);
    assert_rejected(&setup.keyring, &setup.contents, setup.session, &wrong_key);

    let variants: Vec<ResponseTamper> = vec![
        // Wrong generation.
        Box::new(|genuine| {
            OprfResponse::new(
                genuine.key_gen() + 1,
                genuine.evaluated_elements().to_vec(),
                genuine.proof().to_vec(),
            )
        }),
        // Tampered proof.
        Box::new(|genuine| {
            let mut proof = genuine.proof().to_vec();
            proof[5] ^= 1;
            OprfResponse::new(
                genuine.key_gen(),
                genuine.evaluated_elements().to_vec(),
                proof,
            )
        }),
        // Swapped elements.
        Box::new(|genuine| {
            let mut elements = genuine.evaluated_elements().to_vec();
            elements.swap(0, 1);
            OprfResponse::new(genuine.key_gen(), elements, genuine.proof().to_vec())
        }),
        // Missing element.
        Box::new(|genuine| {
            OprfResponse::new(
                genuine.key_gen(),
                genuine.evaluated_elements()[..1].to_vec(),
                genuine.proof().to_vec(),
            )
        }),
        // Extra element.
        Box::new(|genuine| {
            let mut elements = genuine.evaluated_elements().to_vec();
            elements.push(elements[0].clone());
            OprfResponse::new(genuine.key_gen(), elements, genuine.proof().to_vec())
        }),
        // Wrong element and proof sizes.
        Box::new(|genuine| {
            let mut elements = genuine.evaluated_elements().to_vec();
            elements[1].push(0);
            OprfResponse::new(genuine.key_gen(), elements, genuine.proof().to_vec())
        }),
        Box::new(|genuine| {
            OprfResponse::new(
                genuine.key_gen(),
                genuine.evaluated_elements().to_vec(),
                genuine.proof()[..63].to_vec(),
            )
        }),
        // Identity element.
        Box::new(|genuine| {
            let mut elements = genuine.evaluated_elements().to_vec();
            elements[0] = vec![0; 32];
            OprfResponse::new(genuine.key_gen(), elements, genuine.proof().to_vec())
        }),
    ];
    for variant in variants {
        let setup = two_content_session();
        let tampered = variant(&setup.response);
        assert_rejected(&setup.keyring, &setup.contents, setup.session, &tampered);
    }
}

#[test]
fn requires_hybrid_policy_key_and_pepper() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let content = hash(b"x");
    let begin_error = |keyring: &FileKeyring| {
        keyring
            .begin_oprf(&tenant(), &[&content])
            .unwrap_err()
            .code()
    };

    for policy in ["RANDOM", "SOMETHING_NEW"] {
        assert_eq!(
            begin_error(&kkey.keyring(policy)),
            FileCryptoErrorCode::ProfileNotAllowed
        );
    }

    let empty = TestKeyring::new(Some(kkey.root_key()));
    assert_eq!(begin_error(&empty), FileCryptoErrorCode::KeyConfigRequired);

    kkey.import_policy(&empty, 1, "HYBRID");
    install_pepper(&empty, 1, &PEPPER);
    assert_eq!(begin_error(&empty), FileCryptoErrorCode::KeyConfigRequired);

    let no_pepper = TestKeyring::new(Some(kkey.root_key()));
    kkey.import_public_key(&no_pepper);
    kkey.import_policy(&no_pepper, 1, "HYBRID");
    assert_eq!(begin_error(&no_pepper), FileCryptoErrorCode::PepperRequired);
    no_pepper.generate_pepper(&tenant(), 1).unwrap();
    assert_eq!(begin_error(&no_pepper), FileCryptoErrorCode::PepperRequired);
    no_pepper.activate_pepper(&tenant(), 1).unwrap();
    assert!(no_pepper.begin_oprf(&tenant(), &[&content]).is_ok());
}

#[test]
fn bounds_batch_size_and_rejects_duplicate_operations() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");

    assert_eq!(
        keyring.begin_oprf(&tenant(), &[]).unwrap_err().code(),
        FileCryptoErrorCode::InvalidArgument
    );
    let content = hash(b"dup");
    assert_eq!(
        keyring
            .begin_oprf(&tenant(), &[&content, &content])
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::InvalidArgument
    );

    let full: Vec<ContentHash> = (0..MAX_OPRF_BATCH_SIZE).map(|_| hash(b"x")).collect();
    let refs: Vec<&ContentHash> = full.iter().collect();
    let (session, request) = keyring.begin_oprf(&tenant(), &refs).unwrap();
    assert_eq!(session.content_count(), MAX_OPRF_BATCH_SIZE);
    assert_eq!(
        keyring
            .finish_oprf(session, &kkey.evaluate(&request))
            .unwrap()
            .len(),
        MAX_OPRF_BATCH_SIZE
    );

    let over: Vec<ContentHash> = (0..=MAX_OPRF_BATCH_SIZE).map(|_| hash(b"x")).collect();
    let refs: Vec<&ContentHash> = over.iter().collect();
    assert_eq!(
        keyring.begin_oprf(&tenant(), &refs).unwrap_err().code(),
        FileCryptoErrorCode::ResourceLimitExceeded
    );
}

#[test]
fn uses_highest_verified_generation_and_pepper() {
    let old = FakeKKey::new(1, 100);
    let keyring = old.keyring("HYBRID");
    let new = FakeKKey::with_root(2, 200, SigningKey::from_bytes(&[101; 32]));
    new.import_public_key(&keyring);
    install_pepper(&keyring, 3, &[0x33; 32]);

    let content = hash(b"rotated");
    let (session, request) = keyring.begin_oprf(&tenant(), &[&content]).unwrap();
    assert_eq!(request.key_gen(), 200);
    assert_eq!(session.key_gen(), 200);
    assert_eq!(session.pepper_gen(), 3);
    let plans = keyring
        .finish_oprf(session, &new.evaluate(&request))
        .unwrap();
    assert_eq!(
        plans[0].profile(),
        ContentProfile::HybridVoprfV1 {
            key_gen: 200,
            pepper_gen: 3
        }
    );
}

#[test]
fn random_plans_need_no_key_config_and_keep_the_reason() {
    let keyring = TestKeyring::new(None);
    let plaintext = sample(5_000, 9);
    let first = keyring
        .plan_random(&hash(&plaintext), RandomPlanReason::KKeyUnavailable)
        .unwrap();
    let second = keyring
        .plan_random(&hash(&plaintext), RandomPlanReason::PepperMissing)
        .unwrap();
    assert_eq!(first.profile(), ContentProfile::RandomDekV1);
    assert_eq!(
        first.random_reason(),
        Some(RandomPlanReason::KKeyUnavailable)
    );
    assert_eq!(
        second.random_reason(),
        Some(RandomPlanReason::PepperMissing)
    );

    let (first_sealed, first_bytes) = seal(&first, &plaintext);
    let (_, second_bytes) = seal(&second, &plaintext);
    assert_ne!(first_bytes, second_bytes);

    let key = ContentKey::from_sealed(&first, &first_sealed).unwrap();
    let mut sink = RecordingSink::default();
    open_content(&key, &mut MemorySource::new(&first_bytes), &mut sink).unwrap();
    assert_eq!(sink.bytes, plaintext);

    let again = keyring
        .plan_random(
            &hash_for(first.operation_id(), &plaintext),
            RandomPlanReason::RateLimited,
        )
        .unwrap();
    assert_eq!(
        again.random_reason(),
        Some(RandomPlanReason::KKeyUnavailable)
    );
    assert_eq!(seal(&again, &plaintext).1, first_bytes);
}

#[test]
fn debug_output_hides_secrets() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let content = hash(b"debug");
    let (session, request) = keyring.begin_oprf(&tenant(), &[&content]).unwrap();
    let session_debug = format!("{session:?}");
    let plans = keyring
        .finish_oprf(session, &kkey.evaluate(&request))
        .unwrap();

    for debug in [
        session_debug,
        format!("{:?}", plans[0]),
        format!("{content:?}"),
        format!("{:?}", *keyring),
        format!("{:?}", tenant()),
        format!("{:?}", content.operation_id()),
    ] {
        assert!(!debug.contains("119"), "{debug}"); // 0x77, a pepper byte
        assert!(!debug.to_lowercase().contains("7777"), "{debug}");
        assert!(!debug.contains(TENANT), "{debug}");
        assert!(!debug.contains("op-"), "{debug}");
    }
}

#[test]
fn every_session_blinds_with_fresh_randomness() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let content = hash(b"same content");
    let (_, first) = keyring.begin_oprf(&tenant(), &[&content]).unwrap();
    let (_, second) = keyring.begin_oprf(&tenant(), &[&content]).unwrap();
    assert_ne!(first.blinded_elements(), second.blinded_elements());
}

#[test]
fn finish_rechecks_the_policy() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let content = hash(b"policy changes in flight");
    let (session, request) = keyring.begin_oprf(&tenant(), &[&content]).unwrap();

    // The tenant switches to RANDOM while the key service answers: no hybrid plan is stored.
    kkey.import_policy(&keyring, 2, "RANDOM");
    let error = keyring
        .finish_oprf(session, &kkey.evaluate(&request))
        .unwrap_err();
    assert_eq!(error.code(), FileCryptoErrorCode::ProfileNotAllowed);
    assert!(keyring.prepared_plan(&content).unwrap().is_none());
}

#[test]
fn a_hybrid_plan_is_never_reused_for_another_tenant() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let keyring = kkey.keyring("HYBRID");
    let other = kchat_file_crypto::TenantId::parse("tenant-b").unwrap();
    let public_key = kkey.public_key();
    keyring
        .import_public_key(
            &other,
            KEY_GEN,
            &public_key,
            &kkey.sign_public_key("tenant-b", KEY_GEN, &public_key),
        )
        .unwrap();
    keyring
        .import_policy(
            &other,
            1,
            "HYBRID",
            &kkey.sign_policy("tenant-b", 1, "HYBRID"),
        )
        .unwrap();
    keyring
        .import_pepper(&other, 1, &PEPPER, &crate::common::commitment(&PEPPER))
        .unwrap();

    // The host reuses an operation id across tenants.
    let content = hash(b"same operation, two tenants");
    hybrid_plans(&kkey, &keyring, &[&content]);
    let (session, request) = keyring.begin_oprf(&other, &[&content]).unwrap();
    let error = keyring
        .finish_oprf(session, &kkey.evaluate(&request))
        .unwrap_err();
    assert_eq!(error.code(), FileCryptoErrorCode::OperationConflict);
}
