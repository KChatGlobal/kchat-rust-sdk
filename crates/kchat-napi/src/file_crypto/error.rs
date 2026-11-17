//! Lỗi của `kchat-file-crypto` khi ra JS.
//!
//! Mỗi lỗi là một `Error` JS có `code` là mã ổn định (`KEY_SYNC_REQUIRED`, `PEPPER_REQUIRED`...),
//! khớp một-một với [`FileCryptoErrorCode`], và `message` dạng `[CODE] mô tả`, giống module backup.
//! Lỗi không bao giờ chứa key, ID hay message của SQLite.

use kchat_file_crypto::{FileCryptoError, FileCryptoErrorCode};
use napi::{
    Env,
    bindgen_prelude::{FromNapiValue, JsError, Unknown},
};

/// `status` của `napi::Error` mà JS đọc được qua `error.code`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorCode {
    code: &'static str,
    message: &'static str,
}

impl AsRef<str> for ErrorCode {
    fn as_ref(&self) -> &str {
        self.code
    }
}

/// Kết quả của các API đồng bộ: lỗi ném ra JS có `code` là mã ổn định.
pub type Result<T> = napi::Result<T, ErrorCode>;

impl ErrorCode {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn into_error(self) -> napi::Error<ErrorCode> {
        napi::Error::new(self, format!("[{}] {}", self.code, self.message))
    }

    pub(crate) const fn invalid_argument() -> Self {
        Self::from_code(FileCryptoErrorCode::InvalidArgument)
    }

    pub(crate) const fn invalid_state() -> Self {
        Self::from_code(FileCryptoErrorCode::InvalidState)
    }

    pub(crate) const fn from_code(code: FileCryptoErrorCode) -> Self {
        use FileCryptoErrorCode as C;
        match code {
            C::InvalidArgument => Self::new("INVALID_ARGUMENT", "Invalid file crypto argument"),
            C::UnsupportedProfile => Self::new(
                "UNSUPPORTED_PROFILE",
                "Unsupported content or descriptor profile",
            ),
            C::PepperRequired => Self::new("PEPPER_REQUIRED", "No active tenant pepper"),
            C::KeyConfigRequired => Self::new(
                "KEY_CONFIG_REQUIRED",
                "Verified key configuration is required",
            ),
            C::ProfileNotAllowed => Self::new(
                "PROFILE_NOT_ALLOWED",
                "Content profile not allowed by the policy",
            ),
            C::KKeyProofInvalid => Self::new("KKEY_PROOF_INVALID", "Key service proof is invalid"),
            C::KKeySignatureInvalid => Self::new(
                "KKEY_SIGNATURE_INVALID",
                "Key configuration signature is invalid or rolled back",
            ),
            C::KeyConflict => Self::new("KEY_CONFLICT", "Conflicting key for the same generation"),
            C::IntegrityError => Self::new("INTEGRITY_ERROR", "Content integrity check failed"),
            C::OperationConflict => Self::new(
                "OPERATION_CONFLICT",
                "Operation id reused for another request",
            ),
            C::SourceChanged => Self::new("SOURCE_CHANGED", "Source changed since it was hashed"),
            C::InvalidStoreKey => Self::new("INVALID_STORE_KEY", "Key store key is invalid"),
            C::AccountMismatch => {
                Self::new("ACCOUNT_MISMATCH", "Key store belongs to another account")
            }
            C::MalformedMessage => Self::new("MALFORMED_MESSAGE", "Malformed control message"),
            C::UnauthorizedSender => Self::new(
                "UNAUTHORIZED_SENDER",
                "Sender is not allowed to send this message",
            ),
            C::WrongRecipient => Self::new(
                "WRONG_RECIPIENT",
                "Control message is for another recipient",
            ),
            C::StoreError => Self::new("STORE_ERROR", "Key store error"),
            C::ResourceLimitExceeded => Self::new(
                "RESOURCE_LIMIT_EXCEEDED",
                "File crypto resource limit exceeded",
            ),
            C::Cancelled => Self::new("CANCELLED", "File crypto operation cancelled"),
            C::IoError => Self::new("IO_ERROR", "File crypto I/O error"),
            C::InvalidState => Self::new("INVALID_STATE", "Invalid file crypto state"),
            C::KeySyncRequired => Self::new("KEY_SYNC_REQUIRED", "Key sync required"),
            C::KeyEnvelopeInvalid => {
                Self::new("KEY_ENVELOPE_INVALID", "Key link or descriptor is invalid")
            }
            C::PolicyViolation => Self::new("POLICY_VIOLATION", "Key tree policy violation"),
        }
    }
}

impl From<FileCryptoErrorCode> for ErrorCode {
    fn from(code: FileCryptoErrorCode) -> Self {
        Self::from_code(code)
    }
}

impl From<ErrorCode> for napi::Error<ErrorCode> {
    fn from(code: ErrorCode) -> Self {
        code.into_error()
    }
}

impl From<&FileCryptoError> for ErrorCode {
    fn from(error: &FileCryptoError) -> Self {
        error.code().into()
    }
}

/// Cho phép dùng `?` trực tiếp trên kết quả của crate gốc trong API đồng bộ.
pub(crate) fn map_error(error: FileCryptoError) -> napi::Error<ErrorCode> {
    ErrorCode::from(&error).into_error()
}

/// Tạo lỗi JS mang `code` ổn định ở dạng `napi::Error` thường.
///
/// Dùng ở những chỗ chỉ nhận `napi::Error` (promise của tác vụ I/O, API gọi ngược JS): giá trị JS
/// được giữ lại qua reference, nên khi reject hay throw, JS nhận đúng object có `code`.
pub(crate) fn js_error(env: &Env, code: ErrorCode) -> napi::Error {
    let raw = unsafe { JsError::from(code.into_error()).into_value(env.raw()) };
    match unsafe { Unknown::from_napi_value(env.raw(), raw) } {
        Ok(value) => napi::Error::from(value),
        Err(error) => error,
    }
}
