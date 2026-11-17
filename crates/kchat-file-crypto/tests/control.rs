mod common;

use std::cell::{Cell, RefCell};

use ciborium::Value;
use kchat_file_crypto::{
    ControlAuthority, ControlOutcome, ControlPeer, ControlRecipient, ControlRequest,
    FileCryptoErrorCode, FileKeyring, MAX_CONTROL_MESSAGE_BYTES, MAX_ID_BYTES, TenantId,
    is_control_message, seal_content,
};

use crate::common::{
    ACCOUNT, DB_KEY, FakeKKey, MemorySource, PEPPER, RecordingSink, TENANT, TestKeyring,
    commitment, hash, install_pepper, tenant,
};

const KEY_GEN: u64 = 1_700_000_000;
const MEMBER: &str = "account-2";
const MEMBER_DEVICE: &str = "device-m1";
const ADMIN_DEVICE: &str = "device-a1";

#[derive(Default)]
struct Authority {
    deny: bool,
    commitment: Option<[u8; 32]>,
    asked: RefCell<Vec<(String, String, String, u64)>>,
    commitment_lookups: Cell<usize>,
}

impl Authority {
    fn publishing(commitment: [u8; 32]) -> Self {
        Self {
            commitment: Some(commitment),
            ..Self::default()
        }
    }
}

impl ControlAuthority for Authority {
    fn allow(&self, sender: &ControlPeer, request: &ControlRequest<'_>) -> bool {
        match request {
            ControlRequest::PepperDistribution { tenant, generation } => {
                self.asked.borrow_mut().push((
                    sender.account_id().to_owned(),
                    sender.device_id().to_owned(),
                    tenant.as_str().to_owned(),
                    *generation,
                ));
                !self.deny
            }
            _ => false,
        }
    }

    fn published_pepper_commitment(&self, _: &TenantId, _: u64) -> Option<[u8; 32]> {
        self.commitment_lookups
            .set(self.commitment_lookups.get() + 1);
        self.commitment
    }
}

fn admin_sender() -> ControlPeer {
    ControlPeer::new(ACCOUNT, ADMIN_DEVICE).unwrap()
}

fn to_member() -> ControlRecipient {
    ControlRecipient::account(MEMBER).unwrap()
}

fn configured(kkey: &FakeKKey, account: &str) -> TestKeyring {
    let keyring = TestKeyring::with_account(Some(kkey.root_key()), account);
    kkey.import_public_key(&keyring);
    kkey.import_policy(&keyring, 1, "HYBRID");
    keyring
}

fn bootstrap(admin: &FileKeyring, generation: u64) -> [u8; 32] {
    let published = admin.generate_pepper(&tenant(), generation).unwrap();
    admin.activate_pepper(&tenant(), generation).unwrap();
    published
}

fn process(
    member: &FileKeyring,
    message: &[u8],
    authority: &dyn ControlAuthority,
) -> Result<ControlOutcome, FileCryptoErrorCode> {
    member
        .process_control(&admin_sender(), MEMBER_DEVICE, message, authority)
        .map_err(|error| error.code())
}

fn imported(generation: u64) -> Result<ControlOutcome, FileCryptoErrorCode> {
    Ok(ControlOutcome::PepperImported {
        tenant: tenant(),
        generation,
    })
}

fn pepper_gen(keyring: &FileKeyring) -> Option<u64> {
    keyring.key_source_status(&tenant()).unwrap().pepper_gen()
}

fn hybrid_ciphertext(kkey: &FakeKKey, keyring: &FileKeyring, plaintext: &[u8]) -> Vec<u8> {
    let content = hash(plaintext);
    let (session, request) = keyring.begin_oprf(&tenant(), &[&content]).unwrap();
    let plans = keyring
        .finish_oprf(session, &kkey.evaluate(&request))
        .unwrap();
    let mut sink = RecordingSink::default();
    seal_content(&plans[0], &mut MemorySource::new(plaintext), &mut sink).unwrap();
    sink.bytes
}

#[test]
fn member_receives_the_admin_pepper_and_dedups_with_it() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    let published = bootstrap(&admin, 1);

    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();
    assert!(is_control_message(message.as_bytes()));

    let authority = Authority::publishing(published);
    assert_eq!(
        process(&member, message.as_bytes(), &authority),
        imported(1)
    );
    assert_eq!(pepper_gen(&member), Some(1));
    assert_eq!(
        *authority.asked.borrow(),
        [(
            ACCOUNT.to_owned(),
            ADMIN_DEVICE.to_owned(),
            TENANT.to_owned(),
            1
        )]
    );

    // Both devices now hold the same pepper, so the same content yields the same ciphertext.
    let plaintext = b"cung mot noi dung trong tenant";
    assert_eq!(
        hybrid_ciphertext(&kkey, &admin, plaintext),
        hybrid_ciphertext(&kkey, &member, plaintext)
    );
}

#[test]
fn each_event_is_processed_once_even_after_restart() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    let authority = Authority::publishing(bootstrap(&admin, 1));
    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();

    assert_eq!(
        process(&member, message.as_bytes(), &authority),
        imported(1)
    );
    // Redelivery (e.g. a crash before the ACK) must not ask the host again.
    assert_eq!(
        process(&member, message.as_bytes(), &authority),
        Ok(ControlOutcome::AlreadyProcessed)
    );
    assert_eq!(authority.asked.borrow().len(), 1);
    assert_eq!(authority.commitment_lookups.get(), 1);

    let (_dir, path) = member.close();
    let member = FileKeyring::open(&path, &DB_KEY, MEMBER, Some(kkey.root_key())).unwrap();
    assert_eq!(
        process(&member, message.as_bytes(), &authority),
        Ok(ControlOutcome::AlreadyProcessed)
    );
    assert_eq!(pepper_gen(&member), Some(1));

    let resent = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();
    assert_ne!(resent.event_id(), message.event_id());
    assert_eq!(process(&member, resent.as_bytes(), &authority), imported(1));
}

#[test]
fn received_pepper_replaces_a_losing_pending_candidate() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    let published = bootstrap(&admin, 1);
    assert_ne!(member.generate_pepper(&tenant(), 1).unwrap(), published);

    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();
    assert_eq!(
        process(
            &member,
            message.as_bytes(),
            &Authority::publishing(published)
        ),
        imported(1)
    );
    let plaintext = b"noi dung";
    assert_eq!(
        hybrid_ciphertext(&kkey, &admin, plaintext),
        hybrid_ciphertext(&kkey, &member, plaintext)
    );
}

#[test]
fn authority_may_call_back_into_the_keyring() {
    /// The host reads key-store state inside the callback, so the SDK must not hold the lock then.
    struct Reentrant<'a> {
        keyring: &'a FileKeyring,
        commitment: [u8; 32],
    }

    impl ControlAuthority for Reentrant<'_> {
        fn allow(&self, _: &ControlPeer, _: &ControlRequest<'_>) -> bool {
            self.keyring.key_source_status(&tenant()).is_ok()
        }

        fn published_pepper_commitment(&self, _: &TenantId, _: u64) -> Option<[u8; 32]> {
            self.keyring.key_source_status(&tenant()).ok()?;
            Some(self.commitment)
        }
    }

    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    let authority = Reentrant {
        keyring: &member,
        commitment: bootstrap(&admin, 1),
    };
    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();
    assert_eq!(
        process(&member, message.as_bytes(), &authority),
        imported(1)
    );
}

#[test]
fn only_active_peppers_can_be_sent() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let build = |generation| {
        admin
            .build_pepper_distribution(&tenant(), generation, &to_member())
            .map(|message| *message.event_id())
            .map_err(|error| error.code())
    };

    assert_eq!(build(1), Err(FileCryptoErrorCode::PepperRequired));
    admin.generate_pepper(&tenant(), 2).unwrap();
    assert_eq!(build(2), Err(FileCryptoErrorCode::PepperRequired));

    admin.activate_pepper(&tenant(), 2).unwrap();
    let first = build(2).unwrap();
    assert_ne!(build(2).unwrap(), first);
    assert_eq!(build(1), Err(FileCryptoErrorCode::PepperRequired));
}

#[test]
fn sdk_messages_follow_the_documented_layout() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let published = bootstrap(&admin, 7);

    for (recipient, device) in [
        (to_member(), None),
        (
            ControlRecipient::device(MEMBER, MEMBER_DEVICE).unwrap(),
            Some(MEMBER_DEVICE),
        ),
    ] {
        let message = admin
            .build_pepper_distribution(&tenant(), 7, &recipient)
            .unwrap();
        let bytes = message.as_bytes();
        assert_eq!(&bytes[..5], b"KSTC\x01");

        let value: Value = ciborium::from_reader(&bytes[5..]).unwrap();
        let top = value.as_map().unwrap();
        assert_eq!(
            keys(top),
            ["type", "event_id", "tenant", "recipient", "body"]
        );
        assert_eq!(get(top, "type").as_text(), Some("PepperDistribution"));
        assert_eq!(get(top, "event_id").as_bytes().unwrap(), message.event_id());
        assert_eq!(get(top, "tenant").as_text(), Some(TENANT));

        let recipient = get(top, "recipient").as_map().unwrap();
        assert_eq!(get(recipient, "account").as_text(), Some(MEMBER));
        match device {
            Some(device) => assert_eq!(get(recipient, "device").as_text(), Some(device)),
            None => assert_eq!(keys(recipient), ["account"]),
        }

        let body = get(top, "body").as_map().unwrap();
        assert_eq!(keys(body), ["generation", "pepper", "commitment"]);
        assert_eq!(get(body, "generation").as_integer(), Some(7.into()));
        let pepper = get(body, "pepper").as_bytes().unwrap();
        assert_eq!(pepper.len(), 32);
        assert_eq!(get(body, "commitment").as_bytes().unwrap(), &published);
        assert_eq!(commitment(pepper), published);
    }
}

#[test]
fn recipient_must_match_account_and_device() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    let authority = Authority::publishing(bootstrap(&admin, 1));
    let send = |recipient: ControlRecipient| {
        admin
            .build_pepper_distribution(&tenant(), 1, &recipient)
            .unwrap()
    };

    let other_account = send(ControlRecipient::account(ACCOUNT).unwrap());
    let other_device = send(ControlRecipient::device(MEMBER, "device-m2").unwrap());
    for message in [&other_account, &other_device] {
        assert_eq!(
            process(&member, message.as_bytes(), &authority),
            Err(FileCryptoErrorCode::WrongRecipient)
        );
    }
    assert!(authority.asked.borrow().is_empty());
    assert_eq!(pepper_gen(&member), None);

    let this_device = send(ControlRecipient::device(MEMBER, MEMBER_DEVICE).unwrap());
    assert_eq!(
        member
            .process_control(&admin_sender(), "", this_device.as_bytes(), &authority)
            .unwrap_err()
            .code(),
        FileCryptoErrorCode::InvalidArgument
    );
    assert_eq!(
        process(&member, this_device.as_bytes(), &authority),
        imported(1)
    );

    for invalid in [
        ControlRecipient::account("").map(drop),
        ControlRecipient::device(MEMBER, "").map(drop),
        ControlPeer::new(ACCOUNT, "").map(drop),
        ControlPeer::new(&"a".repeat(MAX_ID_BYTES + 1), ADMIN_DEVICE).map(drop),
    ] {
        assert_eq!(
            invalid.unwrap_err().code(),
            FileCryptoErrorCode::InvalidArgument
        );
    }
}

#[test]
fn unauthorized_sender_is_rejected_and_nothing_is_stored() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    let published = bootstrap(&admin, 1);
    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();

    let denying = Authority {
        deny: true,
        ..Authority::publishing(published)
    };
    assert_eq!(
        process(&member, message.as_bytes(), &denying),
        Err(FileCryptoErrorCode::UnauthorizedSender)
    );
    assert_eq!(denying.commitment_lookups.get(), 0);
    assert_eq!(pepper_gen(&member), None);

    // Not recorded as processed: once permission is granted, the message is accepted.
    assert_eq!(
        process(
            &member,
            message.as_bytes(),
            &Authority::publishing(published)
        ),
        imported(1)
    );
}

#[test]
fn published_commitment_is_required_and_must_match() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    let published = bootstrap(&admin, 1);
    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();

    assert_eq!(
        process(&member, message.as_bytes(), &Authority::default()),
        Err(FileCryptoErrorCode::KeyConfigRequired)
    );
    assert_eq!(
        process(
            &member,
            message.as_bytes(),
            &Authority::publishing([0xEE; 32])
        ),
        Err(FileCryptoErrorCode::KeyConflict)
    );
    assert_eq!(pepper_gen(&member), None);

    assert_eq!(
        process(
            &member,
            message.as_bytes(),
            &Authority::publishing(published)
        ),
        imported(1)
    );
}

#[test]
fn received_pepper_never_replaces_a_different_active_pepper() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    let member = configured(&kkey, MEMBER);
    install_pepper(&member, 1, &PEPPER);
    let authority = Authority::publishing(bootstrap(&admin, 1));
    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();

    for _ in 0..2 {
        // Still `KeyConflict`: a failed transaction does not record the event_id.
        assert_eq!(
            process(&member, message.as_bytes(), &authority),
            Err(FileCryptoErrorCode::KeyConflict)
        );
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn keys(map: &[(Value, Value)]) -> Vec<&str> {
    map.iter().map(|(key, _)| key.as_text().unwrap()).collect()
}

fn get<'a>(map: &'a [(Value, Value)], key: &str) -> &'a Value {
    map.iter()
        .find(|(name, _)| name.as_text() == Some(key))
        .map(|(_, value)| value)
        .unwrap()
}

fn get_mut<'a>(map: &'a mut [(Value, Value)], key: &str) -> &'a mut Value {
    map.iter_mut()
        .find(|(name, _)| name.as_text() == Some(key))
        .map(|(_, value)| value)
        .unwrap()
}

/// Valid message built by hand from the format docs, not with the SDK encoder: [`PEPPER`]
/// generation 1 for [`MEMBER`].
fn spec_fields() -> Vec<(Value, Value)> {
    vec![
        (text("type"), text("PepperDistribution")),
        (text("event_id"), bytes(&[0x11; 16])),
        (text("tenant"), text(TENANT)),
        (
            text("recipient"),
            Value::Map(vec![(text("account"), text(MEMBER))]),
        ),
        (
            text("body"),
            Value::Map(vec![
                (text("generation"), Value::Integer(1.into())),
                (text("pepper"), bytes(&PEPPER)),
                (text("commitment"), bytes(&commitment(&PEPPER))),
            ]),
        ),
    ]
}

fn wire(prefix: &[u8], payload: &Value) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    ciborium::into_writer(payload, &mut bytes).unwrap();
    bytes
}

fn spec_message(edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut fields = spec_fields();
    edit(&mut fields);
    wire(b"KSTC\x01", &Value::Map(fields))
}

fn spec_message_in(section: &str, edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    spec_message(|fields| edit(get_mut(fields, section).as_map_mut().unwrap()))
}

#[test]
fn hand_built_message_is_accepted() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let member = configured(&kkey, MEMBER);
    let authority = Authority::publishing(commitment(&PEPPER));
    assert_eq!(
        process(&member, &spec_message(|_| {}), &authority),
        imported(1)
    );
    // A matching `device` is accepted too (new event_id, otherwise `AlreadyProcessed`).
    let to_device = spec_message(|fields| {
        *get_mut(fields, "event_id") = bytes(&[0x22; 16]);
        get_mut(fields, "recipient")
            .as_map_mut()
            .unwrap()
            .push((text("device"), text(MEMBER_DEVICE)));
    });
    assert_eq!(process(&member, &to_device, &authority), imported(1));
}

#[test]
fn malformed_messages_are_rejected_before_asking_the_host() {
    use FileCryptoErrorCode::{MalformedMessage, UnsupportedProfile};

    let valid = spec_message(|_| {});
    let mut oversized = valid.clone();
    oversized.resize(MAX_CONTROL_MESSAGE_BYTES + 1, 0);
    let mut trailing = valid.clone();
    trailing.push(0x00);
    let pepper = |value: Value| spec_message_in("body", |body| *get_mut(body, "pepper") = value);
    let generation =
        |value: Value| spec_message_in("body", |body| *get_mut(body, "generation") = value);
    let tenant_id = |value: &str| spec_message(|fields| *get_mut(fields, "tenant") = text(value));

    let cases: Vec<(&str, Vec<u8>, FileCryptoErrorCode)> = vec![
        ("empty", Vec::new(), MalformedMessage),
        ("magic only", b"KSTC".to_vec(), MalformedMessage),
        ("header only", b"KSTC\x01".to_vec(), MalformedMessage),
        (
            "magic sai",
            wire(b"KSTX\x01", &Value::Map(spec_fields())),
            MalformedMessage,
        ),
        (
            "unknown version",
            wire(b"KSTC\x02", &Value::Map(spec_fields())),
            UnsupportedProfile,
        ),
        (
            "unknown type",
            spec_message(|fields| *get_mut(fields, "type") = text("KeyRotation")),
            UnsupportedProfile,
        ),
        (
            "missing type",
            spec_message(|fields| fields.retain(|(key, _)| key.as_text() != Some("type"))),
            MalformedMessage,
        ),
        (
            "type is not text",
            spec_message(|fields| *get_mut(fields, "type") = Value::Integer(1.into())),
            MalformedMessage,
        ),
        (
            "not a map",
            wire(b"KSTC\x01", &Value::Array(vec![text("PepperDistribution")])),
            MalformedMessage,
        ),
        (
            "unknown top-level field",
            spec_message(|fields| fields.push((text("extra"), text("x")))),
            MalformedMessage,
        ),
        (
            "unknown field in recipient",
            spec_message_in("recipient", |recipient| {
                recipient.push((text("extra"), text("x")));
            }),
            MalformedMessage,
        ),
        (
            "unknown field in body",
            spec_message_in("body", |body| body.push((text("extra"), text("x")))),
            MalformedMessage,
        ),
        (
            "duplicate field",
            spec_message(|fields| fields.push((text("tenant"), text(TENANT)))),
            MalformedMessage,
        ),
        (
            "missing body",
            spec_message(|fields| fields.retain(|(key, _)| key.as_text() != Some("body"))),
            MalformedMessage,
        ),
        (
            "event_id 15 byte",
            spec_message(|fields| *get_mut(fields, "event_id") = bytes(&[0x11; 15])),
            MalformedMessage,
        ),
        (
            "pepper 31 byte",
            pepper(bytes(&[0x77; 31])),
            MalformedMessage,
        ),
        (
            "pepper 33 byte",
            pepper(bytes(&[0x77; 33])),
            MalformedMessage,
        ),
        (
            "pepper as integer array",
            pepper(Value::Array(
                PEPPER
                    .iter()
                    .map(|byte| Value::Integer((*byte).into()))
                    .collect(),
            )),
            MalformedMessage,
        ),
        (
            "commitment does not match pepper",
            spec_message_in("body", |body| {
                *get_mut(body, "commitment") = bytes(&commitment(&[0x78; 32]));
            }),
            MalformedMessage,
        ),
        (
            "negative generation",
            generation(Value::Integer((-1_i64).into())),
            MalformedMessage,
        ),
        (
            "generation above i64",
            generation(Value::Integer(u64::MAX.into())),
            MalformedMessage,
        ),
        ("empty tenant", tenant_id(""), MalformedMessage),
        (
            "tenant too long",
            tenant_id(&"t".repeat(MAX_ID_BYTES + 1)),
            MalformedMessage,
        ),
        (
            "empty account",
            spec_message_in("recipient", |recipient| {
                *get_mut(recipient, "account") = text("");
            }),
            MalformedMessage,
        ),
        ("trailing bytes after CBOR", trailing, MalformedMessage),
        (
            "truncated",
            valid[..valid.len() - 1].to_vec(),
            MalformedMessage,
        ),
        ("oversized", oversized, MalformedMessage),
    ];

    let kkey = FakeKKey::new(1, KEY_GEN);
    let member = configured(&kkey, MEMBER);
    let authority = Authority::publishing(commitment(&PEPPER));
    for (name, message, expected) in cases {
        assert_eq!(
            process(&member, &message, &authority),
            Err(expected),
            "{name}"
        );
    }
    assert!(authority.asked.borrow().is_empty());
    assert_eq!(pepper_gen(&member), None);
}

#[test]
fn arbitrary_input_never_panics() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let member = configured(&kkey, MEMBER);
    let authority = Authority::publishing(commitment(&PEPPER));
    let valid = spec_message(|_| {});

    for length in 0..valid.len() {
        assert!(process(&member, &valid[..length], &authority).is_err());
    }
    // Flipping a bit may still yield a valid message (e.g. inside event_id), but must never panic.
    for index in 0..valid.len() {
        for bit in 0..8 {
            let mut flipped = valid.clone();
            flipped[index] ^= 1 << bit;
            let _ = process(&member, &flipped, &authority);
        }
    }
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    for length in [1, 2, 7, 64, 513, 4096] {
        let mut message = b"KSTC\x01".to_vec();
        message.extend((0..length).map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        }));
        assert!(process(&member, &message, &authority).is_err());
    }
}

#[test]
fn debug_output_hides_ids_and_bytes() {
    let kkey = FakeKKey::new(1, KEY_GEN);
    let admin = configured(&kkey, ACCOUNT);
    bootstrap(&admin, 1);
    let message = admin
        .build_pepper_distribution(&tenant(), 1, &to_member())
        .unwrap();

    let debug = format!(
        "{message:?} {:?} {:?} {:?}",
        admin_sender(),
        to_member(),
        ControlRequest::PepperDistribution {
            tenant: &tenant(),
            generation: 1
        }
    );
    for secret in [ACCOUNT, MEMBER, ADMIN_DEVICE, TENANT] {
        assert!(!debug.contains(secret), "{debug}");
    }
    assert!(debug.contains("len"), "{debug}");
}

#[test]
fn text_starting_with_the_magic_is_not_a_control_message() {
    use kchat_file_crypto::is_control_message;

    assert!(!is_control_message(b"KSTC is just chat text"));
    assert!(!is_control_message(b"KSTC\x01"));
    assert!(is_control_message(b"KSTC\x01\xa0"));
    // A newer version is still routed to `process_control`, which reports `UnsupportedProfile`.
    assert!(is_control_message(b"KSTC\x02\xa0"));
}
