//! `KSTC` control messages, `"KSTC" || u8 version || CBOR`, that carry peppers and root keys
//! between devices over MLS.
//!
//! Messages contain plaintext keys: hosts must never parse or log them, and keep them only in an
//! encrypted store until processed. Decoding is strict since the sender may be a compromised
//! device: an unknown version or type is `UnsupportedProfile`, anything else invalid is
//! `MalformedMessage`.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    FileCryptoError, RootId, RootKind, TenantId,
    cbor::{FixedBytes, decode_cbor},
    ids::validate_id,
    key_tree::{KEY_BYTES, KEY_HASH_BYTES, NodeKind, SecretKey, validate_generation},
    pepper::Pepper,
};

/// Largest control message accepted; checked before decoding.
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 1024 * 1024;
/// Most root keys (or requested epochs) in one message.
pub const MAX_ROOT_KEYS_PER_MESSAGE: usize = 4096;

pub(crate) const PEPPER_DISTRIBUTION: &str = "PepperDistribution";
pub(crate) const NODE_KEY_DISTRIBUTION: &str = "NodeKeyDistribution";
const KEY_SYNC_REQUEST: &str = "KeySyncRequest";
pub(crate) const EVENT_ID_BYTES: usize = 16;

const MAGIC: &[u8; 4] = b"KSTC";
const CONTROL_VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1;
/// Version bytes are non-printable, so text starting with "KSTC" is never taken for a message.
const MAX_VERSION_BYTE: u8 = 0x1F;
/// Fits the largest pepper message, so the buffer never reallocates and leaves a key copy behind.
const ENCODE_CAPACITY: usize = 2048;
/// Upper bound per root key in a `NodeKeyDistribution`.
const ENCODE_BYTES_PER_KEY: usize = 128;

/// Whether `bytes` is an SDK control message of any version, to route it to `process_control`.
pub fn is_control_message(bytes: &[u8]) -> bool {
    bytes.len() > HEADER_BYTES
        && bytes.starts_with(MAGIC)
        && (1..=MAX_VERSION_BYTE).contains(&bytes[MAGIC.len()])
}

/// MLS-authenticated sender. IDs inside a message body are never trusted.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlPeer {
    account_id: String,
    device_id: String,
}

impl ControlPeer {
    pub fn new(account_id: &str, device_id: &str) -> Result<Self, FileCryptoError> {
        validate_id(account_id)?;
        validate_id(device_id)?;
        Ok(Self {
            account_id: account_id.to_owned(),
            device_id: device_id.to_owned(),
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

impl fmt::Debug for ControlPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlPeer(REDACTED)")
    }
}

/// Addressee: an account, optionally one device (otherwise every device of the account).
#[derive(Clone, PartialEq, Eq)]
pub struct ControlRecipient {
    account_id: String,
    device_id: Option<String>,
}

impl ControlRecipient {
    pub fn account(account_id: &str) -> Result<Self, FileCryptoError> {
        validate_id(account_id)?;
        Ok(Self {
            account_id: account_id.to_owned(),
            device_id: None,
        })
    }

    pub fn device(account_id: &str, device_id: &str) -> Result<Self, FileCryptoError> {
        validate_id(device_id)?;
        let mut recipient = Self::account(account_id)?;
        recipient.device_id = Some(device_id.to_owned());
        Ok(recipient)
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }
}

impl fmt::Debug for ControlRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlRecipient(REDACTED)")
    }
}

/// What the SDK asks `ControlAuthority` before accepting a message. Answer `false` for unknown
/// variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlRequest<'a> {
    PepperDistribution {
        tenant: &'a TenantId,
        generation: u64,
    },
    RootKeyDistribution {
        root: &'a RootId,
        epochs: &'a [u64],
    },
    /// May the requester (`sender`) receive `root` at `epoch`? Asked per epoch, so hosts can apply
    /// the group's history policy.
    KeySyncRequest {
        root: &'a RootId,
        epoch: u64,
    },
}

/// Host answers for what the SDK cannot know (membership, admin rights, server state). Called
/// without the key-store lock, so implementations may call back into `FileKeyring`.
pub trait ControlAuthority {
    /// Whether `sender` may send this message:
    /// - `PepperDistribution`: sender is a device of a current tenant admin and this device
    ///   belongs to a tenant member.
    /// - Group `RootKeyDistribution`: sender and this account are current group members (the SDK
    ///   checks personal roots itself).
    /// - `KeySyncRequest`: the requester is still a member on a verified device and the group's
    ///   history policy allows the epoch.
    fn allow(&self, sender: &ControlPeer, request: &ControlRequest<'_>) -> bool;

    /// Server-published commitment of pepper `(tenant, generation)`, i.e. the CAS winner. `None`
    /// returns `KeyConfigRequired` so the host keeps the message for a retry.
    fn published_pepper_commitment(&self, tenant: &TenantId, generation: u64) -> Option<[u8; 32]>;

    /// Server-stored `key_hash` (`key_commitment`) of root key `(root, epoch)`; only a matching key
    /// is accepted. `None` behaves as above, so by default no root key is accepted.
    fn published_root_key_hash(&self, root: &RootId, epoch: u64) -> Option<[u8; 32]> {
        let _ = (root, epoch);
        None
    }
}

/// Encoded message for MLS. Holds plaintext keys and is zeroized on drop: pass `as_bytes()` to
/// MLS without copying it.
pub struct OutgoingControlMessage {
    event_id: [u8; EVENT_ID_BYTES],
    bytes: Zeroizing<Vec<u8>>,
}

impl OutgoingControlMessage {
    /// Random id the receiver uses to drop duplicates.
    pub fn event_id(&self) -> &[u8; EVENT_ID_BYTES] {
        &self.event_id
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for OutgoingControlMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutgoingControlMessage")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Result of `process_control`. The host ACKs the MLS message in every case.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlOutcome {
    PepperImported {
        tenant: TenantId,
        generation: u64,
    },
    RootKeysImported {
        root: RootId,
        epochs: Vec<u64>,
    },
    /// A device asked for root keys; nothing was stored. Answer with `build_key_sync_response`.
    KeySyncRequested(KeySyncRequest),
    AlreadyProcessed,
}

#[derive(Clone, PartialEq, Eq)]
pub struct KeySyncRequest {
    root: RootId,
    epochs: Vec<u64>,
    requester: ControlPeer,
}

impl KeySyncRequest {
    pub const fn root(&self) -> &RootId {
        &self.root
    }

    pub fn epochs(&self) -> &[u64] {
        &self.epochs
    }

    /// The requesting device; the response is addressed to it alone.
    pub const fn requester(&self) -> &ControlPeer {
        &self.requester
    }
}

impl fmt::Debug for KeySyncRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeySyncRequest")
            .field("root", &self.root)
            .field("epochs", &self.epochs)
            .finish_non_exhaustive()
    }
}

pub(crate) enum DecodedControl {
    Pepper(PepperDistribution),
    RootKeys(RootKeyDistribution),
    KeySync(KeySyncMessage),
}

pub(crate) struct PepperDistribution {
    pub(crate) event_id: [u8; EVENT_ID_BYTES],
    pub(crate) tenant: TenantId,
    pub(crate) recipient: ControlRecipient,
    pub(crate) pepper: Pepper,
    pub(crate) commitment: [u8; 32],
}

pub(crate) struct RootKeyDistribution {
    pub(crate) event_id: [u8; EVENT_ID_BYTES],
    pub(crate) root: RootId,
    /// `None`: the whole MLS group carrying the message (group roots only).
    pub(crate) recipient: Option<ControlRecipient>,
    pub(crate) keys: Vec<RootKeyEntry>,
}

pub(crate) struct RootKeyEntry {
    pub(crate) epoch: u64,
    pub(crate) key: SecretKey,
    pub(crate) key_hash: [u8; KEY_HASH_BYTES],
}

pub(crate) struct KeySyncMessage {
    pub(crate) root: RootId,
    /// `None`: the whole MLS group carrying the message (group roots only).
    pub(crate) recipient: Option<ControlRecipient>,
    pub(crate) epochs: Vec<u64>,
}

impl KeySyncMessage {
    pub(crate) fn with_requester(self, requester: &ControlPeer) -> KeySyncRequest {
        KeySyncRequest {
            root: self.root,
            epochs: self.epochs,
            requester: requester.clone(),
        }
    }
}

pub(crate) fn encode_pepper_distribution(
    tenant: &TenantId,
    recipient: &ControlRecipient,
    pepper: &Pepper,
) -> Result<OutgoingControlMessage, FileCryptoError> {
    let body = WirePepperBody {
        generation: pepper.generation(),
        pepper: FixedBytes(*pepper.as_bytes()),
        commitment: FixedBytes(pepper.commitment()),
    };
    encode(
        PEPPER_DISTRIBUTION,
        tenant,
        Some(recipient),
        body,
        ENCODE_CAPACITY,
    )
}

/// `keys` must be non-empty and hold at most [`MAX_ROOT_KEYS_PER_MESSAGE`] entries.
pub(crate) fn encode_root_keys(
    root: &RootId,
    recipient: Option<&ControlRecipient>,
    keys: &[RootKeyEntry],
) -> Result<OutgoingControlMessage, FileCryptoError> {
    debug_assert!(!keys.is_empty() && keys.len() <= MAX_ROOT_KEYS_PER_MESSAGE);
    let body = WireRootKeyBody {
        node: root.node_id().to_owned(),
        kind: root.kind().node_kind().as_u8(),
        keys: keys
            .iter()
            .map(|entry| WireRootKey {
                generation: entry.epoch,
                key: FixedBytes(*entry.key.as_bytes()),
                key_hash: FixedBytes(entry.key_hash),
            })
            .collect(),
    };
    let capacity = ENCODE_CAPACITY + keys.len() * ENCODE_BYTES_PER_KEY;
    encode(
        NODE_KEY_DISTRIBUTION,
        root.tenant(),
        recipient,
        body,
        capacity,
    )
}

pub(crate) fn encode_key_sync_request(
    root: &RootId,
    recipient: Option<&ControlRecipient>,
    epochs: &[u64],
) -> Result<OutgoingControlMessage, FileCryptoError> {
    check_epochs(epochs)?;
    let body = WireKeySyncBody {
        node: root.node_id().to_owned(),
        kind: root.kind().node_kind().as_u8(),
        generations: epochs.to_vec(),
    };
    encode(
        KEY_SYNC_REQUEST,
        root.tenant(),
        recipient,
        body,
        ENCODE_CAPACITY,
    )
}

/// Checks only internal consistency; recipient, sender and server checks happen in
/// `FileKeyring::process_control`.
pub(crate) fn decode_control(bytes: &[u8]) -> Result<DecodedControl, FileCryptoError> {
    if bytes.len() > MAX_CONTROL_MESSAGE_BYTES || !is_control_message(bytes) {
        return Err(FileCryptoError::malformed_message());
    }
    if bytes[MAGIC.len()] != CONTROL_VERSION {
        return Err(FileCryptoError::unsupported_profile());
    }
    let payload = &bytes[HEADER_BYTES..];

    // Read "type" alone first: an unknown type is a newer SDK's message, not corruption.
    let header: WireHeader = decode_cbor(payload)?;
    match header.kind.as_str() {
        PEPPER_DISTRIBUTION => decode_pepper(payload).map(DecodedControl::Pepper),
        NODE_KEY_DISTRIBUTION => decode_root_keys(payload).map(DecodedControl::RootKeys),
        KEY_SYNC_REQUEST => decode_key_sync(payload).map(DecodedControl::KeySync),
        _ => Err(FileCryptoError::unsupported_profile()),
    }
}

fn decode_pepper(payload: &[u8]) -> Result<PepperDistribution, FileCryptoError> {
    let malformed = FileCryptoError::malformed_message;
    let wire: WireMessage<WirePepperBody> = decode_cbor(payload)?;
    let tenant = TenantId::parse(&wire.tenant).map_err(|_| malformed())?;
    let recipient = wire.recipient.as_ref().ok_or_else(malformed)?.parse()?;
    let body = &wire.body;
    validate_generation(body.generation).map_err(|_| malformed())?;
    let pepper = Pepper::from_bytes(body.generation, &body.pepper.0).map_err(|_| malformed())?;
    if pepper.commitment() != body.commitment.0 {
        return Err(malformed());
    }
    Ok(PepperDistribution {
        event_id: wire.event_id.0,
        tenant,
        recipient,
        pepper,
        commitment: body.commitment.0,
    })
}

fn decode_root_keys(payload: &[u8]) -> Result<RootKeyDistribution, FileCryptoError> {
    let malformed = FileCryptoError::malformed_message;
    let wire: WireMessage<WireRootKeyBody> = decode_cbor(payload)?;
    let (root, recipient) = decode_root_target(&wire, wire.body.kind, &wire.body.node)?;
    let epochs: Vec<u64> = wire
        .body
        .keys
        .iter()
        .map(|entry| entry.generation)
        .collect();
    check_epochs(&epochs).map_err(|_| malformed())?;

    let keys = wire
        .body
        .keys
        .iter()
        .map(|entry| {
            let key = SecretKey::from_slice(&entry.key.0).map_err(|_| malformed())?;
            let key_hash = key.key_hash(root.tenant(), root.node_id(), entry.generation);
            if key_hash != entry.key_hash.0 {
                return Err(malformed());
            }
            Ok(RootKeyEntry {
                epoch: entry.generation,
                key,
                key_hash,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RootKeyDistribution {
        event_id: wire.event_id.0,
        root,
        recipient,
        keys,
    })
}

fn decode_key_sync(payload: &[u8]) -> Result<KeySyncMessage, FileCryptoError> {
    let wire: WireMessage<WireKeySyncBody> = decode_cbor(payload)?;
    let (root, recipient) = decode_root_target(&wire, wire.body.kind, &wire.body.node)?;
    check_epochs(&wire.body.generations).map_err(|_| FileCryptoError::malformed_message())?;
    Ok(KeySyncMessage {
        root,
        recipient,
        epochs: wire.body.generations,
    })
}

/// Only root keys travel over MLS (File NodeKeys go through server links), and personal ones
/// must name one account, never a whole group.
fn decode_root_target<B>(
    wire: &WireMessage<B>,
    kind: u8,
    node: &str,
) -> Result<(RootId, Option<ControlRecipient>), FileCryptoError> {
    let malformed = FileCryptoError::malformed_message;
    let tenant = TenantId::parse(&wire.tenant).map_err(|_| malformed())?;
    let kind = match NodeKind::from_u8(kind) {
        Some(NodeKind::GroupRoot) => RootKind::Group,
        Some(NodeKind::PersonalRoot) => RootKind::Personal,
        _ => return Err(malformed()),
    };
    let root = RootId::new(&tenant, kind, node).map_err(|_| malformed())?;
    let recipient = wire
        .recipient
        .as_ref()
        .map(WireRecipient::parse)
        .transpose()?;
    if kind == RootKind::Personal && recipient.is_none() {
        return Err(malformed());
    }
    Ok((root, recipient))
}

/// Epochs must be non-empty, strictly increasing and valid generations. Errors are
/// `InvalidArgument`; decoders map them to `MalformedMessage`.
fn check_epochs(epochs: &[u64]) -> Result<(), FileCryptoError> {
    if epochs.len() > MAX_ROOT_KEYS_PER_MESSAGE {
        return Err(FileCryptoError::resource_limit_exceeded());
    }
    if epochs.is_empty() || !epochs.is_sorted_by(|a, b| a < b) {
        return Err(FileCryptoError::invalid_argument());
    }
    epochs
        .iter()
        .try_for_each(|epoch| validate_generation(*epoch))
}

fn encode<B: Serialize>(
    kind: &str,
    tenant: &TenantId,
    recipient: Option<&ControlRecipient>,
    body: B,
    capacity: usize,
) -> Result<OutgoingControlMessage, FileCryptoError> {
    let mut event_id = [0_u8; EVENT_ID_BYTES];
    getrandom::fill(&mut event_id).map_err(|_| FileCryptoError::io_error())?;
    let wire = WireMessage {
        kind: kind.to_owned(),
        event_id: FixedBytes(event_id),
        tenant: tenant.as_str().to_owned(),
        recipient: recipient.map(WireRecipient::from_recipient),
        body,
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    bytes.extend_from_slice(MAGIC);
    bytes.push(CONTROL_VERSION);
    ciborium::into_writer(&wire, &mut *bytes).map_err(|_| FileCryptoError::invalid_state())?;
    if bytes.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(FileCryptoError::resource_limit_exceeded());
    }
    Ok(OutgoingControlMessage { event_id, bytes })
}

/// Reads only "type"; other fields are ignored.
#[derive(Deserialize)]
struct WireHeader {
    #[serde(rename = "type")]
    kind: String,
}

/// Envelope shared by every message type.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMessage<B> {
    #[serde(rename = "type")]
    kind: String,
    event_id: FixedBytes<EVENT_ID_BYTES>,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient: Option<WireRecipient>,
    body: B,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecipient {
    account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device: Option<String>,
}

impl WireRecipient {
    fn from_recipient(recipient: &ControlRecipient) -> Self {
        Self {
            account: recipient.account_id.clone(),
            device: recipient.device_id.clone(),
        }
    }

    fn parse(&self) -> Result<ControlRecipient, FileCryptoError> {
        match &self.device {
            Some(device) => ControlRecipient::device(&self.account, device),
            None => ControlRecipient::account(&self.account),
        }
        .map_err(|_| FileCryptoError::malformed_message())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePepperBody {
    generation: u64,
    pepper: FixedBytes<32>,
    commitment: FixedBytes<32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRootKeyBody {
    node: String,
    kind: u8,
    keys: Vec<WireRootKey>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRootKey {
    generation: u64,
    key: FixedBytes<KEY_BYTES>,
    key_hash: FixedBytes<KEY_HASH_BYTES>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireKeySyncBody {
    node: String,
    kind: u8,
    generations: Vec<u64>,
}
