//! File encryption core for KChat.
//!
//! Content keys use one of two profiles:
//! - `hybrid-voprf/v1` (default): the tenant key service's VOPRF output (RFC 9497,
//!   ristretto255-SHA512) combined with a device-only tenant pepper. Identical content within a
//!   tenant gives identical ciphertext, so the server can deduplicate it.
//! - `random-dek/v1`: fallback with a random key and no deduplication.
//!
//! The crate does no network I/O: the host relays key configuration and OPRF messages.
//!
//! # Invariants
//!
//! - Secret types are not `Clone`, redact `Debug` and zeroize on drop.
//! - Hybrid plans need a verified `HYBRID` policy and proof; the SDK never falls back to
//!   `random-dek/v1` on its own.
//! - A plan is immutable per operation id, so sealing again yields the same bytes.
//! - Active keys (peppers, root keys, File NodeKeys) are never deleted or replaced.
//! - Personal-branch keys never leave this account.
//! - Errors carry only codes: no keys, IDs or SQLite messages.

mod cbor;
mod content;
mod control;
mod descriptor;
mod encoding;
mod error;
mod ids;
mod key_tree;
mod keyring;
mod kkey;
mod oprf;
mod pepper;
mod plan;
mod profile;

pub use content::{
    ContentKey, ContentSink, ContentSource, MAX_CIPHERTEXT_BYTES_V1, MAX_IO_CHUNK_BYTES,
    SealedContent, hash_content, open_content, seal_content,
};
pub use control::{
    ControlAuthority, ControlOutcome, ControlPeer, ControlRecipient, ControlRequest,
    KeySyncRequest, MAX_CONTROL_MESSAGE_BYTES, MAX_ROOT_KEYS_PER_MESSAGE, OutgoingControlMessage,
    is_control_message,
};
pub use descriptor::{
    DESCRIPTOR_PROFILE_V2, EncryptedDescriptor, MAX_DESCRIPTOR_BYTES, OpenedBlob,
};
pub use error::{FileCryptoError, FileCryptoErrorCode};
pub use ids::{MAX_ID_BYTES, OperationId, TenantId};
pub use key_tree::{
    KEY_HASH_BYTES, KeyProposal, NewFileKey, NodeKeyRef, NodeLink, RootId, RootKind,
};
pub use keyring::{FileKeyring, KEY_STORE_KEY_BYTES};
pub use kkey::{KKeyRootKey, KeySourceStatus, ProfilePolicy};
pub use plan::{
    ContentHash, ContentPlan, MAX_OPRF_BATCH_SIZE, OprfRequest, OprfResponse, OprfSession,
};
pub use profile::{ContentProfile, RandomPlanReason};
