//! Handle opaque giữ giá trị Rust (có thể chứa bí mật) mà JS chỉ cầm, không đọc được key.
//!
//! Không handle nào có API trả DEK, pepper, blind hay NodeKey. Handle dùng trong tác vụ I/O
//! (`ContentPlan`, `ContentKey`) bọc `Arc` để worker thread dùng chung mà không chép key.

use std::sync::Arc;

use kchat_file_crypto as fc;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use super::{
    error::{ErrorCode, Result, map_error},
    types::{ContentProfile, ControlPeer, RandomPlanReason, RootId, from_u64},
};

/// Kết quả lượt đọc 1 (`hashContent`): độ dài plaintext gắn với operation. Hash không bao giờ lộ
/// ra JS.
#[napi]
pub struct ContentHash {
    pub(crate) inner: fc::ContentHash,
}

#[napi]
impl ContentHash {
    #[napi(getter)]
    pub fn operation_id(&self) -> String {
        self.inner.operation_id().as_str().to_owned()
    }

    #[napi(getter)]
    pub fn plaintext_len(&self) -> Result<f64> {
        from_u64(self.inner.plaintext_len())
    }
}

/// Plan bất biến của một operation; giữ DEK trong bộ nhớ Rust, zeroize khi bị thu gom.
#[napi]
pub struct ContentPlan {
    pub(crate) inner: Arc<fc::ContentPlan>,
}

impl ContentPlan {
    pub(crate) fn new(plan: fc::ContentPlan) -> Self {
        Self {
            inner: Arc::new(plan),
        }
    }
}

#[napi]
impl ContentPlan {
    #[napi(getter)]
    pub fn operation_id(&self) -> String {
        self.inner.operation_id().as_str().to_owned()
    }

    #[napi(getter)]
    pub fn profile(&self) -> Result<ContentProfile> {
        ContentProfile::from_core(self.inner.profile())
    }

    #[napi(getter)]
    pub fn plaintext_len(&self) -> Result<f64> {
        from_u64(self.inner.plaintext_len())
    }

    /// Lý do fallback về `random-dek/v1`; `null` với plan hybrid.
    #[napi(getter)]
    pub fn random_reason(&self) -> Option<RandomPlanReason> {
        self.inner.random_reason().map(RandomPlanReason::from_core)
    }
}

/// Lần evaluate VOPRF đang dở (blind + pepper trong bộ nhớ); bị tiêu thụ ở `finishOprf`.
#[napi]
pub struct OprfSession {
    pub(crate) inner: Option<fc::OprfSession>,
}

impl OprfSession {
    fn session(&self) -> Result<&fc::OprfSession> {
        self.inner
            .as_ref()
            .ok_or_else(|| ErrorCode::invalid_state().into())
    }
}

#[napi]
impl OprfSession {
    #[napi(getter)]
    pub fn key_gen(&self) -> Result<f64> {
        from_u64(self.session()?.key_gen())
    }

    #[napi(getter)]
    pub fn pepper_gen(&self) -> Result<f64> {
        from_u64(self.session()?.pepper_gen())
    }

    #[napi(getter)]
    pub fn content_count(&self) -> Result<u32> {
        Ok(self.session()?.content_count() as u32)
    }

    /// Session đã được dùng cho `finishOprf` (hoặc đã bị bỏ) chưa.
    #[napi(getter)]
    pub fn is_consumed(&self) -> bool {
        self.inner.is_none()
    }
}

/// Kết quả công khai của `sealContent`; `ciphertextSha256` dùng cho dedup phía server.
#[napi]
pub struct SealedContent {
    pub(crate) inner: fc::SealedContent,
}

#[napi]
impl SealedContent {
    #[napi(getter)]
    pub fn plaintext_len(&self) -> Result<f64> {
        from_u64(self.inner.plaintext_len())
    }

    #[napi(getter)]
    pub fn ciphertext_len(&self) -> Result<f64> {
        from_u64(self.inner.ciphertext_len())
    }

    #[napi(getter)]
    pub fn ciphertext_sha256(&self) -> Buffer {
        self.inner.ciphertext_sha256().to_vec().into()
    }
}

/// Mọi thứ cần để mở một content object (đúng những gì descriptor mang). Key không lộ ra JS.
#[napi]
pub struct ContentKey {
    pub(crate) inner: Arc<fc::ContentKey>,
}

impl ContentKey {
    pub(crate) fn new(key: fc::ContentKey) -> Self {
        Self {
            inner: Arc::new(key),
        }
    }
}

#[napi]
impl ContentKey {
    /// Gắn plan với kết quả seal của chính nó, để `sealDescriptor` hoặc `openContent`.
    #[napi(factory)]
    pub fn from_sealed(plan: &ContentPlan, sealed: &SealedContent) -> Result<Self> {
        fc::ContentKey::from_sealed(&plan.inner, &sealed.inner)
            .map(Self::new)
            .map_err(map_error)
    }

    #[napi(getter)]
    pub fn profile(&self) -> Result<ContentProfile> {
        ContentProfile::from_core(self.inner.profile())
    }

    #[napi(getter)]
    pub fn plaintext_len(&self) -> Result<f64> {
        from_u64(self.inner.plaintext_len())
    }

    #[napi(getter)]
    pub fn ciphertext_len(&self) -> Result<f64> {
        from_u64(self.inner.ciphertext_len())
    }

    #[napi(getter)]
    pub fn ciphertext_sha256(&self) -> Buffer {
        self.inner.ciphertext_sha256().to_vec().into()
    }
}

/// Blob đã mở từ descriptor: object id, key của object và manifest của ứng dụng.
#[napi]
pub struct OpenedBlob {
    pub(crate) inner: fc::OpenedBlob,
}

#[napi]
impl OpenedBlob {
    /// Object ghi lúc seal; host so với object nó tải về nếu biết id đó.
    #[napi(getter)]
    pub fn object_id(&self) -> String {
        self.inner.object_id().to_owned()
    }

    /// Manifest tùy chọn của ứng dụng; `null` khi lúc seal không có.
    #[napi(getter)]
    pub fn app_manifest(&self) -> Option<Buffer> {
        self.inner
            .app_manifest()
            .map(|manifest| manifest.to_vec().into())
    }

    /// Handle key riêng để `openContent`; mỗi lần gọi trả một handle mới.
    #[napi]
    pub fn content_key(&self) -> ContentKey {
        ContentKey::new(self.inner.content_key().duplicate())
    }
}

/// Yêu cầu key sync đã nhận (`processControl` → `KeySyncRequested`); không chứa bí mật.
#[napi]
pub struct KeySyncRequest {
    pub(crate) inner: fc::KeySyncRequest,
}

impl KeySyncRequest {
    pub(crate) const fn new(inner: fc::KeySyncRequest) -> Self {
        Self { inner }
    }
}

#[napi]
impl KeySyncRequest {
    #[napi(getter)]
    pub fn root(&self) -> RootId {
        RootId::from_core(self.inner.root())
    }

    #[napi(getter)]
    pub fn epochs(&self) -> Result<Vec<f64>> {
        self.inner
            .epochs()
            .iter()
            .map(|epoch| from_u64(*epoch))
            .collect()
    }

    /// Danh tính MLS của thiết bị đang xin key.
    #[napi(getter)]
    pub fn requester(&self) -> ControlPeer {
        ControlPeer::from_core(self.inner.requester())
    }
}
