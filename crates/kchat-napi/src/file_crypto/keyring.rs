//! `FileKeyring`: key store SQLCipher của một account trên một thiết bị.
//!
//! Mọi method đều đồng bộ (SQLite cục bộ, không gọi mạng), nên `authority` của `processControl` và
//! `buildKeySyncResponse` được gọi ngay trên thread JS, theo đúng thứ tự SDK hỏi. Desktop chạy các
//! method này trong worker thread nếu không muốn chặn event loop.

use std::{
    cell::RefCell,
    path::Path,
    sync::{Arc, Mutex},
};

use kchat_file_crypto::{self as fc, ControlAuthority};
use napi::{
    Env,
    bindgen_prelude::{Buffer, ClassInstance, FnArgs, Function, JsObjectValue, Object},
};
use napi_derive::napi;

use super::{
    error::{ErrorCode, Result, js_error, map_error},
    handles::{ContentHash, ContentKey, ContentPlan, KeySyncRequest, OpenedBlob, OprfSession},
    types::{
        ControlOutcome, ControlPeer, ControlRecipient, ControlRequest, EncryptedDescriptor,
        KeyProposal, KeySourceStatus, NewFileKey, NodeKeyRef, NodeLink, OprfRequest, OprfResponse,
        OutgoingControlMessage, RandomPlanReason, RootId, from_u64, operation_id, tenant_id,
        to_u64,
    },
};

/// Kết quả của `beginOprf`: session giữ trong bộ nhớ và request gửi cho key service.
#[napi(object, object_from_js = false)]
pub struct BeginOprfResult {
    pub session: OprfSession,
    pub request: OprfRequest,
}

/// Key store đã mở. Đóng bằng `close()`; handle bị thu gom cũng đóng kết nối.
#[napi]
pub struct FileKeyring {
    // `Arc` để một lời gọi đang chạy (ví dụ `processControl` gọi ngược JS) vẫn giữ store khi JS
    // gọi `close()` lồng bên trong.
    inner: Mutex<Option<Arc<fc::FileKeyring>>>,
}

impl FileKeyring {
    fn keyring(&self) -> Result<Arc<fc::FileKeyring>> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.clone())
            .ok_or_else(|| ErrorCode::invalid_state().into())
    }
}

fn outgoing(
    message: std::result::Result<fc::OutgoingControlMessage, fc::FileCryptoError>,
) -> Result<OutgoingControlMessage> {
    message
        .map(|message| OutgoingControlMessage::from_core(&message))
        .map_err(map_error)
}

fn recipient(recipient: Option<&ControlRecipient>) -> Result<Option<fc::ControlRecipient>> {
    recipient.map(ControlRecipient::to_core).transpose()
}

#[napi]
impl FileKeyring {
    /// Mở hoặc tạo key store tại `path`.
    ///
    /// - `dbKey`: 32 byte, dùng làm raw key của SQLCipher; host tự giữ (vault/Keychain).
    /// - `kkeyRoot`: public key Ed25519 (32 byte) của root ký duy nhất được tin cậy cho cấu hình
    ///   key service; bỏ trống (`undefined`/`null`) thì chỉ tạo được plan random.
    ///   Cấu hình KKey đã lưu được verify lại bằng root này khi mở; dòng không verify được bị xóa.
    ///
    /// Lỗi: `INVALID_ARGUMENT` (root sai độ dài hoặc không hợp lệ), `INVALID_STORE_KEY` (sai key
    /// hoặc file plaintext), `ACCOUNT_MISMATCH`, `STORE_ERROR`.
    #[napi(factory)]
    pub fn open(
        path: String,
        db_key: Buffer,
        account_id: String,
        kkey_root: Option<Buffer>,
    ) -> Result<Self> {
        let root = kkey_root
            .map(|root| fc::KKeyRootKey::from_bytes(&root))
            .transpose()
            .map_err(map_error)?;
        let keyring = fc::FileKeyring::open(Path::new(&path), &db_key, &account_id, root)
            .map_err(map_error)?;
        Ok(Self {
            inner: Mutex::new(Some(Arc::new(keyring))),
        })
    }

    /// Đóng store; sau đó mọi method trả `INVALID_STATE`. Gọi lại khi đã đóng thì không làm gì.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ErrorCode::invalid_state().into_error())?;
        let Some(keyring) = inner.take() else {
            return Ok(());
        };
        match Arc::try_unwrap(keyring) {
            Ok(keyring) => keyring.close().map_err(map_error),
            Err(keyring) => {
                // Đang có lời gọi khác dùng store (close lồng trong authority): giữ nguyên.
                *inner = Some(keyring);
                Err(ErrorCode::invalid_state().into())
            }
        }
    }

    // ─── Cấu hình key service ──────────────────────────────────────────────────────────────────

    /// Verify và lưu public key có chữ ký của key service. Generation không được lùi.
    #[napi]
    pub fn import_public_key(
        &self,
        tenant: String,
        key_gen: f64,
        public_key: Buffer,
        signature: Buffer,
    ) -> Result<()> {
        self.keyring()?
            .import_public_key(
                &tenant_id(&tenant)?,
                to_u64(key_gen)?,
                &public_key,
                &signature,
            )
            .map_err(map_error)
    }

    /// Verify và lưu policy có chữ ký (`"HYBRID"`, `"RANDOM"`; tên lạ được coi là `RANDOM`).
    #[napi]
    pub fn import_policy(
        &self,
        tenant: String,
        policy_version: f64,
        policy: String,
        signature: Buffer,
    ) -> Result<()> {
        self.keyring()?
            .import_policy(
                &tenant_id(&tenant)?,
                to_u64(policy_version)?,
                &policy,
                &signature,
            )
            .map_err(map_error)
    }

    #[napi]
    pub fn key_source_status(&self, tenant: String) -> Result<KeySourceStatus> {
        let status = self
            .keyring()?
            .key_source_status(&tenant_id(&tenant)?)
            .map_err(map_error)?;
        KeySourceStatus::from_core(&status)
    }

    // ─── Pepper ────────────────────────────────────────────────────────────────────────────────

    /// Sinh pepper pending; trả commitment (32 byte) để host CAS trên server.
    #[napi]
    pub fn generate_pepper(&self, tenant: String, generation: f64) -> Result<Buffer> {
        let commitment = self
            .keyring()?
            .generate_pepper(&tenant_id(&tenant)?, to_u64(generation)?)
            .map_err(map_error)?;
        Ok(commitment.to_vec().into())
    }

    /// Kích hoạt pepper pending sau khi host thắng CAS.
    #[napi]
    pub fn activate_pepper(&self, tenant: String, generation: f64) -> Result<()> {
        self.keyring()?
            .activate_pepper(&tenant_id(&tenant)?, to_u64(generation)?)
            .map_err(map_error)
    }

    /// Bỏ pepper pending sau khi host thua CAS.
    #[napi]
    pub fn discard_pepper(&self, tenant: String, generation: f64) -> Result<()> {
        self.keyring()?
            .discard_pepper(&tenant_id(&tenant)?, to_u64(generation)?)
            .map_err(map_error)
    }

    /// Lưu pepper nhận được (active) nếu khớp `commitment`.
    #[napi]
    pub fn import_pepper(
        &self,
        tenant: String,
        generation: f64,
        pepper: Buffer,
        commitment: Buffer,
    ) -> Result<()> {
        self.keyring()?
            .import_pepper(
                &tenant_id(&tenant)?,
                to_u64(generation)?,
                &pepper,
                &commitment,
            )
            .map_err(map_error)
    }

    // ─── Plan nội dung ─────────────────────────────────────────────────────────────────────────

    /// Blind tối đa `MAX_OPRF_BATCH_SIZE` nội dung cho một lần `Evaluate`. Không ghi gì vào store.
    ///
    /// Lỗi: `PROFILE_NOT_ALLOWED` (policy `RANDOM`), `KEY_CONFIG_REQUIRED`, `PEPPER_REQUIRED`.
    #[napi]
    pub fn begin_oprf(
        &self,
        tenant: String,
        contents: Vec<ClassInstance<ContentHash>>,
    ) -> Result<BeginOprfResult> {
        let contents = contents
            .iter()
            .map(|content| &content.inner)
            .collect::<Vec<_>>();
        let (session, request) = self
            .keyring()?
            .begin_oprf(&tenant_id(&tenant)?, &contents)
            .map_err(map_error)?;
        Ok(BeginOprfResult {
            request: OprfRequest::from_core(&request)?,
            session: OprfSession {
                inner: Some(session),
            },
        })
    }

    /// Verify response của key service, derive và lưu một plan cho mỗi nội dung (cùng thứ tự).
    ///
    /// Luôn tiêu thụ `session`. Lỗi `KKEY_PROOF_INVALID`: dừng upload, không fallback.
    #[napi]
    pub fn finish_oprf(
        &self,
        session: &mut OprfSession,
        response: OprfResponse,
    ) -> Result<Vec<ContentPlan>> {
        let session = session
            .inner
            .take()
            .ok_or_else(|| ErrorCode::invalid_state().into_error())?;
        let response = response.to_core()?;
        let plans = self
            .keyring()?
            .finish_oprf(session, &response)
            .map_err(map_error)?;
        Ok(plans.into_iter().map(ContentPlan::new).collect())
    }

    /// Tạo và lưu plan `random-dek/v1` (fallback có nhãn), hoặc trả plan đã có của operation.
    #[napi]
    pub fn plan_random(
        &self,
        content: &ContentHash,
        reason: RandomPlanReason,
    ) -> Result<ContentPlan> {
        self.keyring()?
            .plan_random(&content.inner, reason.to_core())
            .map(ContentPlan::new)
            .map_err(map_error)
    }

    /// Plan đã lưu của operation (resume sau crash mà không gọi lại key service), hoặc `null`.
    #[napi]
    pub fn prepared_plan(&self, content: &ContentHash) -> Result<Option<ContentPlan>> {
        Ok(self
            .keyring()?
            .prepared_plan(&content.inner)
            .map_err(map_error)?
            .map(ContentPlan::new))
    }

    /// Xóa plan của operation sau khi descriptor đã commit, hoặc khi bỏ hẳn operation.
    #[napi]
    pub fn forget_operation(&self, operation: String) -> Result<()> {
        self.keyring()?
            .forget_operation(&operation_id(&operation)?)
            .map_err(map_error)
    }

    // ─── Control message ───────────────────────────────────────────────────────────────────────

    /// Đóng gói pepper active `generation` cho `recipient`; host gửi `bytes` qua MLS 1-1.
    #[napi]
    pub fn build_pepper_distribution(
        &self,
        tenant: String,
        generation: f64,
        recipient: ControlRecipient,
    ) -> Result<OutgoingControlMessage> {
        outgoing(self.keyring()?.build_pepper_distribution(
            &tenant_id(&tenant)?,
            to_u64(generation)?,
            &recipient.to_core()?,
        ))
    }

    /// Đóng gói root key `epoch`; `recipient` bỏ trống để gửi cho cả group qua MLS group.
    #[napi]
    pub fn build_root_key_distribution(
        &self,
        root: RootId,
        epoch: f64,
        recipient: Option<ControlRecipient>,
    ) -> Result<OutgoingControlMessage> {
        outgoing(self.keyring()?.build_root_key_distribution(
            &root.to_core()?,
            to_u64(epoch)?,
            self::recipient(recipient.as_ref())?.as_ref(),
        ))
    }

    /// Gom mọi epoch active của `root` cho một thành viên mới.
    #[napi]
    pub fn build_root_key_bundle(
        &self,
        root: RootId,
        recipient: ControlRecipient,
    ) -> Result<OutgoingControlMessage> {
        outgoing(
            self.keyring()?
                .build_root_key_bundle(&root.to_core()?, &recipient.to_core()?),
        )
    }

    /// Xin root key của `root` ở các `epochs` (tăng dần, không trùng) khi gặp `KEY_SYNC_REQUIRED`.
    #[napi]
    pub fn build_key_sync_request(
        &self,
        root: RootId,
        epochs: Vec<f64>,
        recipient: Option<ControlRecipient>,
    ) -> Result<OutgoingControlMessage> {
        let epochs = epochs.into_iter().map(to_u64).collect::<Result<Vec<_>>>()?;
        outgoing(self.keyring()?.build_key_sync_request(
            &root.to_core()?,
            &epochs,
            self::recipient(recipient.as_ref())?.as_ref(),
        ))
    }

    /// Trả lời một `KeySyncRequest`: chỉ các epoch thiết bị này có và `authority.allow` cho phép.
    #[napi]
    pub fn build_key_sync_response(
        &self,
        env: Env,
        request: &KeySyncRequest,
        #[napi(
            ts_arg_type = "{ allow(sender: ControlPeer, request: ControlRequest): boolean; publishedPepperCommitment(tenant: string, generation: number): Buffer | null | undefined; publishedRootKeyHash?(root: RootId, epoch: number): Buffer | null | undefined }"
        )]
        authority: Object,
    ) -> napi::Result<OutgoingControlMessage> {
        let keyring = self
            .keyring()
            .map_err(|error| js_error(&env, error.status))?;
        let authority = JsAuthority::new(env, authority)?;
        let result = keyring.build_key_sync_response(&request.inner, &authority);
        authority.finish(result.map(|message| OutgoingControlMessage::from_core(&message)))
    }

    /// Xử lý control message nhận qua MLS và lưu key vào store, trong một transaction.
    ///
    /// - `sender`: danh tính MLS đã xác thực của người gửi.
    /// - `localDeviceId`: thiết bị đang chạy.
    /// - `authority`: được gọi đồng bộ; nếu nó ném lỗi thì lỗi đó được ném lại, không có gì bị lưu.
    ///
    /// `MALFORMED_MESSAGE`, `WRONG_RECIPIENT`, `UNAUTHORIZED_SENDER`, `KEY_CONFLICT` là vĩnh viễn
    /// (ACK và bỏ); `KEY_CONFIG_REQUIRED`, `STORE_ERROR` là tạm thời (giữ bytes, thử lại).
    #[napi]
    pub fn process_control(
        &self,
        env: Env,
        sender: ControlPeer,
        local_device_id: String,
        message: Buffer,
        #[napi(
            ts_arg_type = "{ allow(sender: ControlPeer, request: ControlRequest): boolean; publishedPepperCommitment(tenant: string, generation: number): Buffer | null | undefined; publishedRootKeyHash?(root: RootId, epoch: number): Buffer | null | undefined }"
        )]
        authority: Object,
    ) -> napi::Result<ControlOutcome> {
        let to_js = |error: napi::Error<ErrorCode>| js_error(&env, error.status);
        let keyring = self.keyring().map_err(to_js)?;
        let sender = sender.to_core().map_err(to_js)?;
        let authority = JsAuthority::new(env, authority)?;
        let result = keyring.process_control(&sender, &local_device_id, &message, &authority);
        let outcome = authority.finish(result)?;
        ControlOutcome::from_core(outcome).map_err(to_js)
    }

    // ─── Cây key ───────────────────────────────────────────────────────────────────────────────

    /// Sinh root key mới (pending): epoch 0 khi tạo, +1 khi rotate; retry trả lại proposal cũ.
    #[napi]
    pub fn propose_root_key(&self, root: RootId) -> Result<KeyProposal> {
        let proposal = self
            .keyring()?
            .propose_root_key(&root.to_core()?)
            .map_err(map_error)?;
        KeyProposal::from_core(&proposal)
    }

    /// Kích hoạt key pending (root key hoặc File NodeKey) sau khi server nhận nó.
    #[napi]
    pub fn activate_node_key(&self, key: NodeKeyRef) -> Result<()> {
        self.keyring()?
            .activate_node_key(&key.to_core()?)
            .map_err(map_error)
    }

    /// Bỏ key pending khi thua CAS.
    #[napi]
    pub fn discard_node_key(&self, key: NodeKeyRef) -> Result<()> {
        self.keyring()?
            .discard_node_key(&key.to_core()?)
            .map_err(map_error)
    }

    /// Epoch active cao nhất của `root` trên thiết bị này, hoặc `null`.
    #[napi]
    pub fn root_epoch(&self, root: RootId) -> Result<Option<f64>> {
        self.keyring()?
            .root_epoch(&root.to_core()?)
            .map_err(map_error)?
            .map(from_u64)
            .transpose()
    }

    /// File NodeKey cho lần ghi, wrap bằng epoch hiện tại của `root`, kèm link cho `CommitUpload`:
    /// `fileGeneration` 0 nếu file chưa có key (CREATE), +1 nếu root đã rotate sau key mới nhất
    /// (ROTATE, key pending), còn lại trả key đang dùng. Server có file epoch cao hơn thì
    /// `openFileKey(current_file_key)` trước.
    #[napi]
    pub fn create_file_key(&self, root: RootId, file_node_id: String) -> Result<NewFileKey> {
        let created = self
            .keyring()?
            .create_file_key(&root.to_core()?, &file_node_id)
            .map_err(map_error)?;
        Ok(NewFileKey {
            file_key: NodeKeyRef::from_core(&created.file_key())?,
            link: NodeLink::from_core(created.link())?,
        })
    }

    /// Mở File NodeKey từ link server trả về và lưu active. Thiếu root key: `KEY_SYNC_REQUIRED`.
    #[napi]
    pub fn open_file_key(&self, link: NodeLink) -> Result<NodeKeyRef> {
        let key = self
            .keyring()?
            .open_file_key(&link.to_core()?)
            .map_err(map_error)?;
        NodeKeyRef::from_core(&key)
    }

    // ─── Descriptor ────────────────────────────────────────────────────────────────────────────

    /// Mã hóa descriptor của blob bằng `fileKey`; idempotent theo `(tenant, fileId, blobId)`.
    ///
    /// `app` là manifest tùy chọn của ứng dụng (SDK không đọc); không có thì bỏ trống.
    #[napi]
    pub fn seal_descriptor(
        &self,
        file_key: NodeKeyRef,
        file_id: String,
        blob_id: String,
        object_id: String,
        key: &ContentKey,
        app: Option<Buffer>,
    ) -> Result<EncryptedDescriptor> {
        let descriptor = self
            .keyring()?
            .seal_descriptor(
                &file_key.to_core()?,
                &file_id,
                &blob_id,
                &object_id,
                &key.inner,
                app.as_deref(),
            )
            .map_err(map_error)?;
        EncryptedDescriptor::from_core(&descriptor)
    }

    /// Mở descriptor bằng File NodeKey đã có trên thiết bị (từ `openFileKey`).
    #[napi]
    pub fn open_descriptor(
        &self,
        tenant: String,
        file_id: String,
        descriptor: EncryptedDescriptor,
    ) -> Result<OpenedBlob> {
        let opened = self
            .keyring()?
            .open_descriptor(&tenant_id(&tenant)?, &file_id, &descriptor.to_core()?)
            .map_err(map_error)?;
        Ok(OpenedBlob { inner: opened })
    }

    /// Mã hóa lại descriptor bằng File NodeKey khác (`FILE_EPOCH_MISMATCH`, publish draft).
    #[napi]
    pub fn reseal_descriptor(
        &self,
        file_id: String,
        blob_id: String,
        descriptor: EncryptedDescriptor,
        new_file_key: NodeKeyRef,
    ) -> Result<EncryptedDescriptor> {
        let descriptor = self
            .keyring()?
            .reseal_descriptor(
                &file_id,
                &blob_id,
                &descriptor.to_core()?,
                &new_file_key.to_core()?,
            )
            .map_err(map_error)?;
        EncryptedDescriptor::from_core(&descriptor)
    }
}

// ─── Authority gọi ngược JS ─────────────────────────────────────────────────────────────────────

type AllowFn<'env> = Function<'env, FnArgs<(ControlPeer, ControlRequest)>, bool>;
type CommitmentFn<'env> = Function<'env, FnArgs<(String, f64)>, Option<Buffer>>;
type RootKeyHashFn<'env> = Function<'env, FnArgs<(RootId, f64)>, Option<Buffer>>;

/// `ControlAuthority` do JS cài, gọi đồng bộ trên thread JS với `this` là object `authority`.
///
/// Trait của SDK không trả lỗi được, nên lỗi đầu tiên từ JS (ném ra, sai kiểu trả về) được giữ
/// lại: SDK nhận câu trả lời an toàn nhất (từ chối / chưa có giá trị), rồi [`JsAuthority::finish`]
/// ném lại chính lỗi đó cho JS thay vì kết quả của SDK.
struct JsAuthority<'env> {
    env: Env,
    this: Object<'env>,
    allow: AllowFn<'env>,
    pepper_commitment: CommitmentFn<'env>,
    root_key_hash: Option<RootKeyHashFn<'env>>,
    error: RefCell<Option<napi::Error>>,
}

impl<'env> JsAuthority<'env> {
    fn new(env: Env, this: Object<'env>) -> napi::Result<Self> {
        let allow = this.get_named_property::<AllowFn>("allow")?;
        let pepper_commitment =
            this.get_named_property::<CommitmentFn>("publishedPepperCommitment")?;
        let root_key_hash =
            this.get_named_property::<Option<RootKeyHashFn>>("publishedRootKeyHash")?;
        Ok(Self {
            env,
            this,
            allow,
            pepper_commitment,
            root_key_hash,
            error: RefCell::new(None),
        })
    }

    fn record<T>(&self, result: napi::Result<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.error.borrow_mut().get_or_insert(error);
                None
            }
        }
    }

    /// Giá trị 32 byte do JS trả về; sai độ dài là lỗi của host.
    fn hash(&self, value: Option<Buffer>) -> Option<[u8; 32]> {
        let value = value?;
        let hash = <[u8; 32]>::try_from(value.as_ref());
        if hash.is_err() {
            self.record::<()>(Err(js_error(&self.env, ErrorCode::invalid_argument())));
        }
        hash.ok()
    }

    fn finish<T>(self, result: std::result::Result<T, fc::FileCryptoError>) -> napi::Result<T> {
        if let Some(error) = self.error.into_inner() {
            return Err(error);
        }
        result.map_err(|error| js_error(&self.env, ErrorCode::from(&error)))
    }
}

impl ControlAuthority for JsAuthority<'_> {
    fn allow(&self, sender: &fc::ControlPeer, request: &fc::ControlRequest<'_>) -> bool {
        // Loại request binding chưa biết: từ chối, như SDK khuyên.
        let Some(request) = ControlRequest::from_core(request) else {
            return false;
        };
        let Some(request) = self.record(request.map_err(|error| js_error(&self.env, error.status)))
        else {
            return false;
        };
        let args = FnArgs::from((ControlPeer::from_core(sender), request));
        self.record(self.allow.apply(self.this, args))
            .unwrap_or(false)
    }

    fn published_pepper_commitment(
        &self,
        tenant: &fc::TenantId,
        generation: u64,
    ) -> Option<[u8; 32]> {
        let generation =
            self.record(from_u64(generation).map_err(|error| js_error(&self.env, error.status)))?;
        let args = FnArgs::from((tenant.as_str().to_owned(), generation));
        let value = self.record(self.pepper_commitment.apply(self.this, args))?;
        self.hash(value)
    }

    fn published_root_key_hash(&self, root: &fc::RootId, epoch: u64) -> Option<[u8; 32]> {
        let callback = self.root_key_hash.as_ref()?;
        let epoch =
            self.record(from_u64(epoch).map_err(|error| js_error(&self.env, error.status)))?;
        let args = FnArgs::from((RootId::from_core(root), epoch));
        let value = self.record(callback.apply(self.this, args))?;
        self.hash(value)
    }
}
