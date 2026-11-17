//! Object JS thuần (không chứa bí mật) và chuyển đổi qua lại với kiểu của `kchat-file-crypto`.
//!
//! Generation, epoch và độ dài là `number` của JS: chỉ nhận số nguyên an toàn (`0..=2^53-1`), để
//! không có giá trị nào bị làm tròn khi qua ranh giới.

use kchat_file_crypto as fc;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use super::{
    error::{ErrorCode, Result, map_error},
    handles::KeySyncRequest,
};

/// `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Số nguyên không âm do JS truyền vào.
pub(crate) fn to_u64(value: f64) -> Result<u64> {
    if value.is_finite() && value.fract() == 0.0 && (0.0..=MAX_SAFE_INTEGER as f64).contains(&value)
    {
        Ok(value as u64)
    } else {
        Err(ErrorCode::invalid_argument().into())
    }
}

/// Số trả ra JS; giá trị vượt số nguyên an toàn bị từ chối thay vì làm tròn.
pub(crate) fn from_u64(value: u64) -> Result<f64> {
    if value <= MAX_SAFE_INTEGER {
        Ok(value as f64)
    } else {
        Err(ErrorCode::invalid_state().into())
    }
}

pub(crate) fn tenant_id(tenant: &str) -> Result<fc::TenantId> {
    fc::TenantId::parse(tenant).map_err(map_error)
}

pub(crate) fn operation_id(operation: &str) -> Result<fc::OperationId> {
    fc::OperationId::parse(operation).map_err(map_error)
}

// ─── Root, node key, link ───────────────────────────────────────────────────────────────────────

/// Loại root của cây key: group (Group NodeKey) hoặc personal (draft của chính user).
#[napi(string_enum = "lowercase")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootKind {
    Group,
    Personal,
}

/// Một root của cây key: tenant, loại và node id do server cấp (ví dụ group id).
#[napi(object)]
#[derive(Clone, Debug)]
pub struct RootId {
    pub tenant: String,
    pub kind: RootKind,
    pub node_id: String,
}

impl RootId {
    pub(crate) fn to_core(&self) -> Result<fc::RootId> {
        let tenant = tenant_id(&self.tenant)?;
        match self.kind {
            RootKind::Group => fc::RootId::group(&tenant, &self.node_id),
            RootKind::Personal => fc::RootId::personal(&tenant, &self.node_id),
        }
        .map_err(map_error)
    }

    pub(crate) fn from_core(root: &fc::RootId) -> Self {
        Self {
            tenant: root.tenant().as_str().to_owned(),
            kind: match root.kind() {
                fc::RootKind::Group => RootKind::Group,
                fc::RootKind::Personal => RootKind::Personal,
            },
            node_id: root.node_id().to_owned(),
        }
    }
}

/// Tham chiếu tới một NodeKey trong key store (root key hoặc File NodeKey); không chứa key.
#[napi(object)]
#[derive(Clone, Debug)]
pub struct NodeKeyRef {
    pub tenant: String,
    pub node_id: String,
    pub generation: f64,
}

impl NodeKeyRef {
    pub(crate) fn to_core(&self) -> Result<fc::NodeKeyRef> {
        fc::NodeKeyRef::new(
            &tenant_id(&self.tenant)?,
            &self.node_id,
            to_u64(self.generation)?,
        )
        .map_err(map_error)
    }

    pub(crate) fn from_core(key: &fc::NodeKeyRef) -> Result<Self> {
        Ok(Self {
            tenant: key.tenant().as_str().to_owned(),
            node_id: key.node_id().to_owned(),
            generation: from_u64(key.generation())?,
        })
    }
}

/// Root key mới (pending) để host CAS trên server (`CreateRootKey` / `RotateRootKey`).
#[napi(object)]
pub struct KeyProposal {
    /// Thắng CAS thì `activateNodeKey(key)`, thua thì `discardNodeKey(key)`.
    pub key: NodeKeyRef,
    pub epoch: f64,
    /// `key_hash` (32 byte) gửi lên server làm `key_commitment`.
    pub key_hash: Buffer,
}

impl KeyProposal {
    pub(crate) fn from_core(proposal: &fc::KeyProposal) -> Result<Self> {
        Ok(Self {
            key: NodeKeyRef::from_core(proposal.key())?,
            epoch: from_u64(proposal.epoch())?,
            key_hash: proposal.key_hash().to_vec().into(),
        })
    }
}

/// Record server lưu: File NodeKey được root key của một epoch wrap. Host lưu đủ mọi field.
#[napi(object)]
pub struct NodeLink {
    pub root: RootId,
    /// Epoch của root key đã wrap File NodeKey.
    pub epoch: f64,
    pub file_node_id: String,
    pub file_generation: f64,
    /// `key_hash` (32 byte) của File NodeKey bên trong. Luôn có ở link do `createFileKey` tạo
    /// (gửi làm `key_commitment`); bỏ trống khi dựng lại từ `EncryptedFileKey` của KFiles, vì
    /// server không trả nó: SDK chỉ dựa vào AEAD và tự tính `key_hash` sau khi mở.
    pub key_hash: Option<Buffer>,
    /// Record đã wrap (72 byte).
    pub ciphertext: Buffer,
}

impl NodeLink {
    pub(crate) fn to_core(&self) -> Result<fc::NodeLink> {
        fc::NodeLink::from_parts(
            &self.root.to_core()?,
            to_u64(self.epoch)?,
            &self.file_node_id,
            to_u64(self.file_generation)?,
            self.key_hash.as_deref(),
            &self.ciphertext,
        )
        .map_err(map_error)
    }

    pub(crate) fn from_core(link: &fc::NodeLink) -> Result<Self> {
        Ok(Self {
            root: RootId::from_core(link.root()),
            epoch: from_u64(link.epoch())?,
            file_node_id: link.file_node_id().to_owned(),
            file_generation: from_u64(link.file_generation())?,
            key_hash: link.key_hash().map(|hash| hash.to_vec().into()),
            ciphertext: link.ciphertext().to_vec().into(),
        })
    }
}

/// Kết quả `createFileKey`: File NodeKey (pending) và link để server lưu.
#[napi(object)]
pub struct NewFileKey {
    /// Sau khi server nhận link thì `activateNodeKey(fileKey)`.
    pub file_key: NodeKeyRef,
    pub link: NodeLink,
}

// ─── Descriptor ─────────────────────────────────────────────────────────────────────────────────

/// `EncryptedDescriptor` của KFiles: `profileId`, `ciphertext`, `fileGeneration` (`file_epoch`).
#[napi(object)]
pub struct EncryptedDescriptor {
    /// Luôn là `kchat-storage/descriptor/v2` (`DESCRIPTOR_PROFILE_V2`).
    pub profile_id: String,
    /// File NodeKey của lane chứa blob: `file_id` (lane group) hoặc `<file_id>:user:<jid>`.
    pub file_node_id: String,
    /// Generation của File NodeKey (`EncryptedDescriptor.file_epoch`).
    pub file_generation: f64,
    /// nonce (24) || ciphertext || tag (16).
    pub ciphertext: Buffer,
}

impl EncryptedDescriptor {
    pub(crate) fn to_core(&self) -> Result<fc::EncryptedDescriptor> {
        fc::EncryptedDescriptor::from_parts(
            &self.profile_id,
            &self.file_node_id,
            to_u64(self.file_generation)?,
            &self.ciphertext,
        )
        .map_err(map_error)
    }

    pub(crate) fn from_core(descriptor: &fc::EncryptedDescriptor) -> Result<Self> {
        Ok(Self {
            profile_id: descriptor.profile_id().to_owned(),
            file_node_id: descriptor.file_node_id().to_owned(),
            file_generation: from_u64(descriptor.file_generation())?,
            ciphertext: descriptor.ciphertext().to_vec().into(),
        })
    }
}

// ─── Cấu hình key và profile ────────────────────────────────────────────────────────────────────

/// Policy đã verify của tenant.
#[napi(string_enum = "UPPERCASE")]
#[derive(Debug, Eq, PartialEq)]
pub enum ProfilePolicy {
    Hybrid,
    Random,
}

/// Những gì key store đang có cho một tenant.
#[napi(object)]
pub struct KeySourceStatus {
    /// Không có khi chưa import policy có chữ ký nào.
    pub policy: Option<ProfilePolicy>,
    pub policy_version: Option<f64>,
    /// Generation public key cao nhất đã verify.
    pub key_gen: Option<f64>,
    /// Generation pepper active cao nhất.
    pub pepper_gen: Option<f64>,
    /// Host phải lấy cấu hình key trước khi tạo được plan hybrid.
    pub needs_key_config: bool,
}

impl KeySourceStatus {
    pub(crate) fn from_core(status: &fc::KeySourceStatus) -> Result<Self> {
        Ok(Self {
            policy: status.policy().map(|policy| match policy {
                fc::ProfilePolicy::Hybrid => ProfilePolicy::Hybrid,
                fc::ProfilePolicy::Random => ProfilePolicy::Random,
            }),
            policy_version: status.policy_version().map(from_u64).transpose()?,
            key_gen: status.key_gen().map(from_u64).transpose()?,
            pepper_gen: status.pepper_gen().map(from_u64).transpose()?,
            needs_key_config: status.needs_key_config(),
        })
    }
}

/// Content profile ghi trong descriptor; `keyGen`/`pepperGen` chỉ có với profile hybrid.
#[napi(object)]
pub struct ContentProfile {
    /// `kchat-file/whole-file/xchacha-stream-64k/hybrid-voprf/v1` hoặc `.../random-dek/v1`.
    pub id: String,
    pub key_gen: Option<f64>,
    pub pepper_gen: Option<f64>,
}

impl ContentProfile {
    pub(crate) fn from_core(profile: fc::ContentProfile) -> Result<Self> {
        let (key_gen, pepper_gen) = match profile {
            fc::ContentProfile::HybridVoprfV1 {
                key_gen,
                pepper_gen,
            } => (Some(from_u64(key_gen)?), Some(from_u64(pepper_gen)?)),
            fc::ContentProfile::RandomDekV1 => (None, None),
        };
        Ok(Self {
            id: profile.id().to_owned(),
            key_gen,
            pepper_gen,
        })
    }
}

/// Lý do host chọn `random-dek/v1`; lưu trong plan để làm telemetry.
#[napi(string_enum)]
#[derive(Debug, Eq, PartialEq)]
pub enum RandomPlanReason {
    KKeyUnavailable,
    PolicyRandom,
    PolicyUnavailable,
    RateLimited,
    PepperMissing,
    NoTenant,
    SmallFile,
}

impl RandomPlanReason {
    pub(crate) const fn to_core(&self) -> fc::RandomPlanReason {
        match self {
            Self::KKeyUnavailable => fc::RandomPlanReason::KKeyUnavailable,
            Self::PolicyRandom => fc::RandomPlanReason::PolicyRandom,
            Self::PolicyUnavailable => fc::RandomPlanReason::PolicyUnavailable,
            Self::RateLimited => fc::RandomPlanReason::RateLimited,
            Self::PepperMissing => fc::RandomPlanReason::PepperMissing,
            Self::NoTenant => fc::RandomPlanReason::NoTenant,
            Self::SmallFile => fc::RandomPlanReason::SmallFile,
        }
    }

    pub(crate) const fn from_core(reason: fc::RandomPlanReason) -> Self {
        match reason {
            fc::RandomPlanReason::KKeyUnavailable => Self::KKeyUnavailable,
            fc::RandomPlanReason::PolicyRandom => Self::PolicyRandom,
            fc::RandomPlanReason::PolicyUnavailable => Self::PolicyUnavailable,
            fc::RandomPlanReason::RateLimited => Self::RateLimited,
            fc::RandomPlanReason::PepperMissing => Self::PepperMissing,
            fc::RandomPlanReason::NoTenant => Self::NoTenant,
            fc::RandomPlanReason::SmallFile => Self::SmallFile,
        }
    }
}

// ─── VOPRF ──────────────────────────────────────────────────────────────────────────────────────

/// Request đã blind; host đóng gói vào `Evaluate` của key service.
#[napi(object)]
pub struct OprfRequest {
    /// Generation key mà key service phải dùng.
    pub key_gen: f64,
    /// Mỗi phần tử 32 byte, theo thứ tự các content đưa vào `beginOprf`.
    pub blinded_elements: Vec<Buffer>,
}

impl OprfRequest {
    pub(crate) fn from_core(request: &fc::OprfRequest) -> Result<Self> {
        Ok(Self {
            key_gen: from_u64(request.key_gen())?,
            blinded_elements: request
                .blinded_elements()
                .iter()
                .map(|element| element.to_vec().into())
                .collect(),
        })
    }
}

/// Kết quả `Evaluate` đúng như host nhận được; `finishOprf` kiểm tra mọi thứ.
#[napi(object)]
pub struct OprfResponse {
    pub key_gen: f64,
    pub evaluated_elements: Vec<Buffer>,
    pub proof: Buffer,
}

impl OprfResponse {
    pub(crate) fn to_core(&self) -> Result<fc::OprfResponse> {
        Ok(fc::OprfResponse::new(
            to_u64(self.key_gen)?,
            self.evaluated_elements
                .iter()
                .map(|element| element.to_vec())
                .collect(),
            self.proof.to_vec(),
        ))
    }
}

// ─── Control message ────────────────────────────────────────────────────────────────────────────

/// Danh tính MLS đã xác thực của một thiết bị.
#[napi(object)]
#[derive(Clone, Debug)]
pub struct ControlPeer {
    pub account_id: String,
    pub device_id: String,
}

impl ControlPeer {
    pub(crate) fn to_core(&self) -> Result<fc::ControlPeer> {
        fc::ControlPeer::new(&self.account_id, &self.device_id).map_err(map_error)
    }

    pub(crate) fn from_core(peer: &fc::ControlPeer) -> Self {
        Self {
            account_id: peer.account_id().to_owned(),
            device_id: peer.device_id().to_owned(),
        }
    }
}

/// Người nhận control message: một account (mọi thiết bị), hoặc một thiết bị cụ thể.
#[napi(object)]
#[derive(Clone, Debug)]
pub struct ControlRecipient {
    pub account_id: String,
    pub device_id: Option<String>,
}

impl ControlRecipient {
    pub(crate) fn to_core(&self) -> Result<fc::ControlRecipient> {
        match &self.device_id {
            None => fc::ControlRecipient::account(&self.account_id),
            Some(device_id) => fc::ControlRecipient::device(&self.account_id, device_id),
        }
        .map_err(map_error)
    }
}

/// Control message `KSTC` để host gửi qua MLS.
///
/// `bytes` chứa key dạng rõ: chuyển thẳng cho MLS, không log, không lưu ngoài store đã mã hóa.
#[napi(object)]
pub struct OutgoingControlMessage {
    /// ID ngẫu nhiên (16 byte); thiết bị nhận dùng để không xử lý hai lần.
    pub event_id: Buffer,
    pub bytes: Buffer,
}

impl OutgoingControlMessage {
    pub(crate) fn from_core(message: &fc::OutgoingControlMessage) -> Self {
        Self {
            event_id: message.event_id().to_vec().into(),
            bytes: message.as_bytes().to_vec().into(),
        }
    }
}

/// Loại câu hỏi SDK gửi cho `authority.allow`.
#[napi(string_enum)]
#[derive(Debug, Eq, PartialEq)]
pub enum ControlRequestKind {
    /// Sender muốn giao pepper `generation` của `tenant` cho thiết bị này.
    PepperDistribution,
    /// Sender muốn giao root key của `root` ở các `epochs`.
    RootKeyDistribution,
    /// Khi trả lời key sync: `sender` (người xin) có được nhận root key của `root` ở `epoch`.
    KeySyncRequest,
}

/// Điều SDK hỏi `authority.allow(sender, request)` trước khi nhận hoặc gửi key.
#[napi(object, object_from_js = false)]
pub struct ControlRequest {
    pub kind: ControlRequestKind,
    pub tenant: Option<String>,
    pub generation: Option<f64>,
    pub root: Option<RootId>,
    pub epochs: Option<Vec<f64>>,
    pub epoch: Option<f64>,
}

impl ControlRequest {
    /// `None` với loại request mà binding này chưa biết; host coi như từ chối.
    pub(crate) fn from_core(request: &fc::ControlRequest<'_>) -> Option<Result<Self>> {
        let empty = |kind| Self {
            kind,
            tenant: None,
            generation: None,
            root: None,
            epochs: None,
            epoch: None,
        };
        Some(match request {
            fc::ControlRequest::PepperDistribution { tenant, generation } => from_u64(*generation)
                .map(|generation| Self {
                    tenant: Some(tenant.as_str().to_owned()),
                    generation: Some(generation),
                    ..empty(ControlRequestKind::PepperDistribution)
                }),
            fc::ControlRequest::RootKeyDistribution { root, epochs } => epochs
                .iter()
                .map(|epoch| from_u64(*epoch))
                .collect::<Result<Vec<_>>>()
                .map(|epochs| Self {
                    tenant: Some(root.tenant().as_str().to_owned()),
                    root: Some(RootId::from_core(root)),
                    epochs: Some(epochs),
                    ..empty(ControlRequestKind::RootKeyDistribution)
                }),
            fc::ControlRequest::KeySyncRequest { root, epoch } => {
                from_u64(*epoch).map(|epoch| Self {
                    tenant: Some(root.tenant().as_str().to_owned()),
                    root: Some(RootId::from_core(root)),
                    epoch: Some(epoch),
                    ..empty(ControlRequestKind::KeySyncRequest)
                })
            }
            _ => return None,
        })
    }
}

/// Loại kết quả của `processControl`. Mọi trường hợp host đều ACK message trên MLS.
#[napi(string_enum)]
#[derive(Debug, Eq, PartialEq)]
pub enum ControlOutcomeKind {
    /// Pepper đã được lưu active: `tenant`, `generation`.
    PepperImported,
    /// Root key các epoch này đã được lưu active: `root`, `epochs`.
    RootKeysImported,
    /// Một thiết bị xin root key: `keySyncRequest`. Không có gì được ghi.
    KeySyncRequested,
    /// `event_id` đã được xử lý trước đó; không thay đổi gì.
    AlreadyProcessed,
}

/// Kết quả của `processControl`.
#[napi(object, object_from_js = false)]
pub struct ControlOutcome {
    pub kind: ControlOutcomeKind,
    pub tenant: Option<String>,
    pub generation: Option<f64>,
    pub root: Option<RootId>,
    pub epochs: Option<Vec<f64>>,
    /// Có khi `kind` là `KeySyncRequested`; truyền cho `buildKeySyncResponse`.
    pub key_sync_request: Option<KeySyncRequest>,
}

impl ControlOutcome {
    pub(crate) fn from_core(outcome: fc::ControlOutcome) -> Result<Self> {
        let empty = |kind| Self {
            kind,
            tenant: None,
            generation: None,
            root: None,
            epochs: None,
            key_sync_request: None,
        };
        Ok(match outcome {
            fc::ControlOutcome::PepperImported { tenant, generation } => Self {
                tenant: Some(tenant.as_str().to_owned()),
                generation: Some(from_u64(generation)?),
                ..empty(ControlOutcomeKind::PepperImported)
            },
            fc::ControlOutcome::RootKeysImported { root, epochs } => Self {
                tenant: Some(root.tenant().as_str().to_owned()),
                root: Some(RootId::from_core(&root)),
                epochs: Some(
                    epochs
                        .into_iter()
                        .map(from_u64)
                        .collect::<Result<Vec<_>>>()?,
                ),
                ..empty(ControlOutcomeKind::RootKeysImported)
            },
            fc::ControlOutcome::KeySyncRequested(request) => Self {
                tenant: Some(request.root().tenant().as_str().to_owned()),
                root: Some(RootId::from_core(request.root())),
                epochs: Some(
                    request
                        .epochs()
                        .iter()
                        .map(|epoch| from_u64(*epoch))
                        .collect::<Result<Vec<_>>>()?,
                ),
                key_sync_request: Some(KeySyncRequest::new(request)),
                ..empty(ControlOutcomeKind::KeySyncRequested)
            },
            fc::ControlOutcome::AlreadyProcessed => empty(ControlOutcomeKind::AlreadyProcessed),
            // Kết quả mới của SDK mà binding chưa biết: không đoán nghĩa của nó.
            _ => return Err(ErrorCode::invalid_state().into()),
        })
    }
}
