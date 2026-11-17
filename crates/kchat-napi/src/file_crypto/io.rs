//! Stream nội dung qua ranh giới NAPI: `hashContent`, `sealContent`, `openContent`.
//!
//! Cùng mẫu với `backup::io`: SDK chạy trên một thread riêng và đọc/ghi qua callback JS trả
//! `Promise`. Mỗi lần chỉ có một callback đang chờ, chunk tối đa `FILE_CRYPTO_MAX_IO_CHUNK_BYTES`,
//! nên bộ nhớ không tăng theo kích thước file (tới 5 GiB).
//!
//! - `read(maxBytes)` trả `Promise<Buffer>` tối đa `maxBytes` byte; Buffer rỗng là EOF.
//! - `sink.write(chunk)` nhận bản sao của chunk; `sink.commit()` chỉ được gọi khi toàn bộ output
//!   đã được xác thực; `sink.abort()` khi có lỗi, và host phải bỏ mọi byte đã nhận.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    },
    time::Duration,
};

use kchat_file_crypto::{
    self as fc, ContentSink, ContentSource, FileCryptoError, FileCryptoErrorCode,
    MAX_IO_CHUNK_BYTES,
};
use napi::{
    Env, JsDeferred, JsValue, Status,
    bindgen_prelude::{
        Buffer, CallbackContext, FnArgs, FromNapiValue, Function, JsObjectValue,
        JsValuesTupleIntoVec, Object, PromiseRaw, ToNapiValue, Unknown,
    },
    threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode},
};
use napi_derive::napi;
use zeroize::Zeroizing;

use super::{
    error::{ErrorCode, js_error},
    handles::{ContentHash, ContentKey, ContentPlan, SealedContent},
    types::operation_id,
};

/// Số byte tối đa SDK xin trong một lần `read`, và gửi trong một lần `sink.write`.
#[napi]
pub const FILE_CRYPTO_MAX_IO_CHUNK_BYTES: u32 = MAX_IO_CHUNK_BYTES as u32;

/// Token hủy cho `hashContent`, `sealContent`, `openContent`. Hủy thì sink bị abort.
#[napi]
pub struct FileCryptoCancellation {
    cancelled: Arc<AtomicBool>,
}

impl Default for FileCryptoCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[napi]
impl FileCryptoCancellation {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[napi]
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[napi]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

// ─── Callback JS ────────────────────────────────────────────────────────────────────────────────

// PromiseRaw chỉ được dùng bên trong `call_with_return_value`, trên thread JS.
type Callback<Value, Args, Resolved> =
    ThreadsafeFunction<Value, PromiseRaw<'static, Resolved>, Args, Status, false, false, 1>;
type ReadCallback = Callback<u32, FnArgs<(u32,)>, Buffer>;
type WriteCallback = Callback<Zeroizing<Vec<u8>>, FnArgs<(Buffer,)>, ()>;
type FinishCallback = Callback<(), (), ()>;

type ReadFn<'a> = Function<'a, FnArgs<(u32,)>, PromiseRaw<'static, Buffer>>;
type WriteFn<'a> = Function<'a, FnArgs<(Buffer,)>, PromiseRaw<'static, ()>>;
type FinishFn<'a> = Function<'a, (), PromiseRaw<'static, ()>>;

type CallbackResult<T> = Result<T, FileCryptoErrorCode>;

fn core_error(code: FileCryptoErrorCode) -> FileCryptoError {
    FileCryptoError::from_code(code)
}

/// Gắn `then`/`catch` vào promise JS trả về; callback phải trả `Promise` (ví dụ hàm `async`).
fn settle_promise<Resolved, Out, Convert>(
    env: Env,
    promise: PromiseRaw<'_, Resolved>,
    convert: Convert,
    sender: SyncSender<CallbackResult<Out>>,
) -> napi::Result<()>
where
    Resolved: FromNapiValue + 'static,
    Out: Send + 'static,
    Convert: FnOnce(Resolved) -> CallbackResult<Out> + Clone + 'static,
{
    let attach = env.create_function_from_closure::<FnArgs<(PromiseRaw<Resolved>,)>, (), _>(
        "attachFileCryptoPromiseHandlers",
        move |ctx| {
            let promise: PromiseRaw<Resolved> = ctx.first_arg()?;
            if !promise.is_promise()? {
                return Err(napi::Error::new(
                    Status::InvalidArg,
                    "Callback must return a Promise",
                ));
            }
            let (success, failure) = (sender.clone(), sender.clone());
            let convert = convert.clone();
            promise
                .then(move |ctx: CallbackContext<Resolved>| {
                    let _ = success.try_send(convert(ctx.value));
                    Ok(())
                })?
                .catch(move |_: CallbackContext<Unknown>| {
                    let _ = failure.try_send(Err(FileCryptoErrorCode::IoError));
                    Ok(())
                })?;
            Ok(())
        },
    )?;
    attach.call(FnArgs::from((promise,)))
}

/// Chờ kết quả từ thread JS, vẫn kiểm hủy và việc callback bị giải phóng trong lúc chờ.
fn wait_for_callback<T>(
    receiver: Receiver<CallbackResult<T>>,
    cancelled: &AtomicBool,
    closed: impl Fn() -> bool,
) -> Result<T, FileCryptoError> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(core_error(FileCryptoErrorCode::Cancelled));
        }
        if closed() {
            return Err(core_error(FileCryptoErrorCode::IoError));
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(result) => return result.map_err(core_error),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(core_error(FileCryptoErrorCode::IoError));
            }
        }
    }
}

/// Gọi một callback JS từ thread của SDK và chờ promise của nó.
fn call_js<Value, Args, Resolved, Out, Convert>(
    callback: &Callback<Value, Args, Resolved>,
    value: Value,
    convert: Convert,
    cancelled: &AtomicBool,
) -> Result<Out, FileCryptoError>
where
    Value: 'static,
    Args: JsValuesTupleIntoVec + 'static,
    Resolved: FromNapiValue + 'static,
    Out: Send + 'static,
    Convert: FnOnce(Resolved) -> CallbackResult<Out> + Clone + Send + 'static,
{
    if cancelled.load(Ordering::Acquire) {
        return Err(core_error(FileCryptoErrorCode::Cancelled));
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let status = callback.call_with_return_value(
        value,
        ThreadsafeFunctionCallMode::NonBlocking,
        move |result, env| {
            let fallback = sender.clone();
            if result
                .and_then(|promise| settle_promise(env, promise, convert, sender))
                .is_err()
            {
                let _ = fallback.try_send(Err(FileCryptoErrorCode::IoError));
            }
            Ok(())
        },
    );
    if status != Status::Ok {
        return Err(core_error(FileCryptoErrorCode::IoError));
    }
    wait_for_callback(receiver, cancelled, || callback.aborted())
}

struct SourceAdapter {
    read: ReadCallback,
    cancelled: Arc<AtomicBool>,
}

impl ContentSource for SourceAdapter {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, FileCryptoError> {
        let maximum = destination.len().min(MAX_IO_CHUNK_BYTES);
        let bytes = call_js(
            &self.read,
            maximum as u32,
            // Chép trên thread JS, để JS sửa Buffer sau đó không ảnh hưởng tới lần đọc này.
            move |chunk: Buffer| {
                if chunk.len() > maximum {
                    Err(FileCryptoErrorCode::InvalidState)
                } else {
                    Ok(Zeroizing::new(chunk.to_vec()))
                }
            },
            &self.cancelled,
        )?;
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

struct SinkAdapter {
    write: WriteCallback,
    commit: FinishCallback,
    abort: FinishCallback,
    cancelled: Arc<AtomicBool>,
}

fn resolved(_: ()) -> CallbackResult<()> {
    Ok(())
}

impl ContentSink for SinkAdapter {
    fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), FileCryptoError> {
        if bytes.len() > MAX_IO_CHUNK_BYTES {
            return Err(core_error(FileCryptoErrorCode::InvalidState));
        }
        call_js(
            &self.write,
            Zeroizing::new(bytes.to_vec()),
            resolved,
            &self.cancelled,
        )
    }

    fn commit(&mut self) -> Result<(), FileCryptoError> {
        call_js(&self.commit, (), resolved, &self.cancelled)
    }

    fn abort(&mut self) -> Result<(), FileCryptoError> {
        // Abort phải tới được JS kể cả khi thao tác bị hủy, để host xóa phần đã ghi.
        call_js(&self.abort, (), resolved, &AtomicBool::new(false))
    }
}

fn cancellation_flag(cancellation: Option<&FileCryptoCancellation>) -> Arc<AtomicBool> {
    cancellation
        .map(|token| Arc::clone(&token.cancelled))
        .unwrap_or_default()
}

fn source(read: ReadFn<'_>, cancelled: &Arc<AtomicBool>) -> napi::Result<SourceAdapter> {
    let read = read
        .build_threadsafe_function::<u32>()
        .max_queue_size::<1>()
        .build_callback(|ctx| Ok(FnArgs::from((ctx.value,))))?;
    Ok(SourceAdapter {
        read,
        cancelled: Arc::clone(cancelled),
    })
}

fn finish_callback(sink: &Object<'_>, name: &str) -> napi::Result<FinishCallback> {
    let callback: FinishFn = sink.get_named_property(name)?;
    callback
        .bind(sink)?
        .build_threadsafe_function::<()>()
        .max_queue_size::<1>()
        .build_callback(|_| Ok(()))
}

/// Ba method của `sink`, gọi với `this` là chính object đó.
fn sink(sink: Object<'_>, cancelled: &Arc<AtomicBool>) -> napi::Result<SinkAdapter> {
    let write: WriteFn = sink.get_named_property("write")?;
    let write = write
        .bind(sink)?
        .build_threadsafe_function::<Zeroizing<Vec<u8>>>()
        .max_queue_size::<1>()
        .build_callback(|ctx| Ok(FnArgs::from((Buffer::from(ctx.value.to_vec()),))))?;
    Ok(SinkAdapter {
        write,
        commit: finish_callback(&sink, "commit")?,
        abort: finish_callback(&sink, "abort")?,
        cancelled: Arc::clone(cancelled),
    })
}

// ─── Tác vụ nền ─────────────────────────────────────────────────────────────────────────────────

type Resolver<T> = Box<dyn FnOnce(Env) -> napi::Result<T>>;
type Deferred<T> = JsDeferred<T, Resolver<T>>;

/// Chạy `work` trên một thread riêng (callback JS cần thread JS rảnh) và trả promise của nó.
///
/// Lỗi của SDK reject promise bằng `Error` JS có `code` ổn định.
fn spawn_io<'env, Out, Js>(
    env: &'env Env,
    work: impl FnOnce() -> Result<Out, FileCryptoError> + Send + 'static,
    resolve: fn(Out) -> Js,
) -> napi::Result<PromiseRaw<'env, Js>>
where
    Out: Send + 'static,
    Js: ToNapiValue + 'static,
{
    let (sender, receiver) = mpsc::sync_channel::<Deferred<Js>>(1);
    std::thread::Builder::new()
        .name("kchat-file-crypto-io".into())
        .spawn(move || {
            if let Ok(deferred) = receiver.recv() {
                let result = catch_unwind(AssertUnwindSafe(work))
                    .unwrap_or_else(|_| Err(core_error(FileCryptoErrorCode::InvalidState)));
                deferred.resolve(Box::new(move |env| match result {
                    Ok(output) => Ok(resolve(output)),
                    Err(error) => Err(js_error(&env, ErrorCode::from(&error))),
                }));
            }
        })
        .map_err(|_| {
            js_error(
                env,
                ErrorCode::from(FileCryptoErrorCode::ResourceLimitExceeded),
            )
        })?;
    let (deferred, promise) = env.create_deferred::<Js, Resolver<Js>>()?;
    if let Err(error) = sender.send(deferred) {
        error.0.reject(js_error(env, ErrorCode::invalid_state()));
    }
    Ok(PromiseRaw::new(env.raw(), promise.raw()))
}

// ─── API ────────────────────────────────────────────────────────────────────────────────────────

/// Lượt đọc 1: hash plaintext cho `operationId` và kiểm giới hạn kích thước object.
#[napi(ts_return_type = "Promise<ContentHash>")]
pub fn hash_content<'env>(
    env: &'env Env,
    operation_id: String,
    #[napi(ts_arg_type = "(maxBytes: number) => Promise<Buffer>")] read: ReadFn<'_>,
    cancellation: Option<&FileCryptoCancellation>,
) -> napi::Result<PromiseRaw<'env, ContentHash>> {
    let operation =
        self::operation_id(&operation_id).map_err(|error| js_error(env, error.status))?;
    let cancelled = cancellation_flag(cancellation);
    let mut source = source(read, &cancelled)?;
    spawn_io(
        env,
        move || fc::hash_content(&operation, &mut source),
        |inner| ContentHash { inner },
    )
}

/// Lượt đọc 2: mã hóa `read` bằng `plan` vào `sink`.
///
/// Sink chỉ được commit khi nguồn vẫn khớp lượt đọc 1 (nếu không: `SOURCE_CHANGED`, sink bị abort).
/// Host không được gửi output đi trước khi promise resolve.
#[napi(ts_return_type = "Promise<SealedContent>")]
pub fn seal_content<'env>(
    env: &'env Env,
    plan: &ContentPlan,
    #[napi(ts_arg_type = "(maxBytes: number) => Promise<Buffer>")] read: ReadFn<'_>,
    #[napi(
        ts_arg_type = "{ write(chunk: Buffer): Promise<void>; commit(): Promise<void>; abort(): Promise<void> }"
    )]
    sink: Object<'_>,
    cancellation: Option<&FileCryptoCancellation>,
) -> napi::Result<PromiseRaw<'env, SealedContent>> {
    let plan = Arc::clone(&plan.inner);
    let cancelled = cancellation_flag(cancellation);
    let mut source = source(read, &cancelled)?;
    let mut sink = self::sink(sink, &cancelled)?;
    spawn_io(
        env,
        move || fc::seal_content(&plan, &mut source, &mut sink),
        |inner| SealedContent { inner },
    )
}

/// Xác thực và giải mã một content object vào `sink`.
///
/// Sink chỉ được commit sau khi block cuối qua xác thực, độ dài và SHA-256 ciphertext khớp; mọi
/// trường hợp khác đều abort (`INTEGRITY_ERROR`...).
#[napi(ts_return_type = "Promise<void>")]
pub fn open_content<'env>(
    env: &'env Env,
    key: &ContentKey,
    #[napi(ts_arg_type = "(maxBytes: number) => Promise<Buffer>")] read: ReadFn<'_>,
    #[napi(
        ts_arg_type = "{ write(chunk: Buffer): Promise<void>; commit(): Promise<void>; abort(): Promise<void> }"
    )]
    sink: Object<'_>,
    cancellation: Option<&FileCryptoCancellation>,
) -> napi::Result<PromiseRaw<'env, ()>> {
    let key = Arc::clone(&key.inner);
    let cancelled = cancellation_flag(cancellation);
    let mut source = source(read, &cancelled)?;
    let mut sink = self::sink(sink, &cancelled)?;
    spawn_io(
        env,
        move || fc::open_content(&key, &mut source, &mut sink),
        |()| (),
    )
}
