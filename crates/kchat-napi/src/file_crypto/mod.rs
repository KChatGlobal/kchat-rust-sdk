//! Binding NAPI cho [`kchat_file_crypto`]: mã hóa file của KChat cho host JS (Desktop).
//!
//! Lớp này chỉ chuyển kiểu, không thêm logic: mọi kiểm tra và bất biến vẫn nằm trong crate gốc.
//! Không API nào trả DEK, pepper, blind hay NodeKey: JS chỉ cầm handle (`ContentPlan`,
//! `ContentKey`, `OpenedBlob`, `OprfSession`) và bytes đã mã hóa. Ngoại lệ duy nhất là bytes của
//! control message (`OutgoingControlMessage.bytes`), thứ host phải chuyển thẳng cho MLS.
//!
//! ```text
//! FileKeyring.open(path, dbKey, accountId, kkeyRoot)
//! importPublicKey / importPolicy            cấu hình key service đã ký
//! hashContent(operationId, read)            lượt đọc 1 -> ContentHash
//! preparedPlan(hash) ?? beginOprf -> Evaluate (host) -> finishOprf   hoặc planRandom
//! sealContent(plan, read, sink)             lượt đọc 2 -> SealedContent
//! createFileKey / activateNodeKey           File NodeKey + link cho server
//! sealDescriptor(fileKey, ..., ContentKey.fromSealed(plan, sealed))
//! forgetOperation(operationId)
//!
//! Đọc: openFileKey(link) -> openDescriptor(...) -> OpenedBlob -> openContent(blob.contentKey(), ...)
//! Key qua MLS: build*Distribution / buildKeySyncRequest -> bytes; processControl(sender, ...)
//! ```
//!
//! Lỗi là `Error` JS có `code` ổn định (xem `error.rs`).

pub mod error;
mod handles;
mod io;
mod keyring;
mod types;

use kchat_file_crypto as fc;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

pub use handles::{
    ContentHash, ContentKey, ContentPlan, KeySyncRequest, OpenedBlob, OprfSession, SealedContent,
};
pub use io::{
    FILE_CRYPTO_MAX_IO_CHUNK_BYTES, FileCryptoCancellation, hash_content, open_content,
    seal_content,
};
pub use keyring::{BeginOprfResult, FileKeyring};
pub use types::{
    ContentProfile, ControlOutcome, ControlOutcomeKind, ControlPeer, ControlRecipient,
    ControlRequest, ControlRequestKind, EncryptedDescriptor, KeyProposal, KeySourceStatus,
    NewFileKey, NodeKeyRef, NodeLink, OprfRequest, OprfResponse, OutgoingControlMessage,
    ProfilePolicy, RandomPlanReason, RootId, RootKind,
};

/// `EncryptedDescriptor.profileId` của descriptor do SDK tạo.
#[napi]
pub const DESCRIPTOR_PROFILE_V2: &str = fc::DESCRIPTOR_PROFILE_V2;

/// Số nội dung tối đa trong một lần `beginOprf` (một lần `Evaluate`).
#[napi]
pub const MAX_OPRF_BATCH_SIZE: u32 = fc::MAX_OPRF_BATCH_SIZE as u32;

/// Độ dài key của key store (`dbKey` của `FileKeyring.open`).
#[napi]
pub const FILE_KEY_STORE_KEY_BYTES: u32 = fc::KEY_STORE_KEY_BYTES as u32;

/// Bytes nhận được qua MLS có phải control message `KSTC` không. Host dùng để tách message của
/// storage ra khỏi message chat, rồi lưu bền trước khi `processControl`.
#[napi]
pub fn is_control_message(bytes: Buffer) -> bool {
    fc::is_control_message(&bytes)
}
