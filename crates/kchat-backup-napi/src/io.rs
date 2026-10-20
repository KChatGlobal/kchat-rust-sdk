use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    time::Duration,
};

use kchat_backup::{
    BackupByteSink, BackupByteSource, BackupError, BackupErrorCode, BackupObjectContextV1,
    BackupObjectDescriptor, MAX_IO_CHUNK_BYTES_V1, open_object_v1, seal_object_v1,
};
use napi::{
    Env, JsDeferred, JsValue, Task,
    bindgen_prelude::{
        BigInt, Buffer, CallbackContext, FnArgs, FromNapiValue, Function, PromiseRaw, Unknown,
    },
    threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode},
};
use napi_derive::napi;
use zeroize::Zeroizing;

use crate::{
    BackupObjectContext,
    error::{Error, invalid_state, map_error},
};

#[napi]
pub const MAX_IO_CHUNK_BYTES: u32 = MAX_IO_CHUNK_BYTES_V1 as u32;

#[napi]
pub struct BackupCancellation {
    cancelled: Arc<AtomicBool>,
}

impl Default for BackupCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[napi]
impl BackupCancellation {
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

#[napi(object)]
pub struct BackupObjectMetadata {
    pub ciphertext_size: BigInt,
    pub ciphertext_sha256: Buffer,
    pub format_version: u16,
}

impl From<BackupObjectDescriptor> for BackupObjectMetadata {
    fn from(value: BackupObjectDescriptor) -> Self {
        Self {
            ciphertext_size: BigInt::from(value.ciphertext_size()),
            ciphertext_sha256: value.ciphertext_sha256().to_vec().into(),
            format_version: value.format_version(),
        }
    }
}

// PromiseRaw values are consumed only inside call_with_return_value on the JS thread.
type ReadCallback = ThreadsafeFunction<
    u32,
    PromiseRaw<'static, Buffer>,
    FnArgs<(u32,)>,
    napi::Status,
    false,
    false,
    1,
>;
type WriteCallback = ThreadsafeFunction<
    Zeroizing<Vec<u8>>,
    PromiseRaw<'static, ()>,
    FnArgs<(Buffer,)>,
    napi::Status,
    false,
    false,
    1,
>;

struct SourceAdapter {
    callback: ReadCallback,
    cancelled: Arc<AtomicBool>,
}

struct SinkAdapter {
    callback: WriteCallback,
    cancelled: Arc<AtomicBool>,
}

fn core_error(code: BackupErrorCode) -> BackupError {
    BackupError::from_code(code)
}

fn attach_promise_handlers<T, Resolve, Reject>(
    env: Env,
    promise: PromiseRaw<'_, T>,
    resolve: Resolve,
    reject: Reject,
) -> napi::Result<()>
where
    T: FromNapiValue + 'static,
    Resolve: Clone + FnOnce(CallbackContext<T>) -> napi::Result<()> + 'static,
    Reject: Clone + FnOnce(CallbackContext<Unknown>) -> napi::Result<()> + 'static,
{
    let attach = env.create_function_from_closure::<FnArgs<(PromiseRaw<T>,)>, (), _>(
        "attachBackupPromiseHandlers",
        move |ctx| {
            let promise: PromiseRaw<T> = ctx.first_arg()?;
            if !promise.is_promise()? {
                return Err(Error::IoError.into());
            }
            promise.then(resolve.clone())?.catch(reject.clone())?;
            Ok(())
        },
    )?;
    attach.call(FnArgs::from((promise,)))
}

fn wait_for_callback<T>(
    receiver: Receiver<Result<T, BackupErrorCode>>,
    cancelled: &AtomicBool,
    closed: impl Fn() -> bool,
) -> Result<T, BackupError> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(core_error(BackupErrorCode::Cancelled));
        }
        if closed() {
            return Err(core_error(BackupErrorCode::IoError));
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(result) => {
                if cancelled.load(Ordering::Acquire) {
                    return Err(core_error(BackupErrorCode::Cancelled));
                }
                return result.map_err(core_error);
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(core_error(BackupErrorCode::IoError));
            }
        }
    }
}

impl BackupByteSource for SourceAdapter {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, BackupError> {
        if self.is_cancelled() {
            return Err(core_error(BackupErrorCode::Cancelled));
        }
        let maximum = destination.len().min(MAX_IO_CHUNK_BYTES_V1);
        let (sender, receiver) = mpsc::sync_channel(1);
        let status = self.callback.call_with_return_value(
            maximum as u32,
            ThreadsafeFunctionCallMode::NonBlocking,
            move |result, env| {
                let success = sender.clone();
                let failure = sender.clone();
                let attached = result.and_then(|promise| {
                    attach_promise_handlers(
                        env,
                        promise,
                        move |ctx| {
                            // Copy on the JS thread before sending bytes to Rust so
                            // later JS mutations cannot race the worker's reads.
                            let result = if ctx.value.len() > maximum {
                                Err(BackupErrorCode::InvalidState)
                            } else {
                                Ok(Zeroizing::new(ctx.value.to_vec()))
                            };
                            let _ = success.try_send(result);
                            Ok(())
                        },
                        move |_: CallbackContext<Unknown>| {
                            let _ = failure.try_send(Err(BackupErrorCode::IoError));
                            Ok(())
                        },
                    )
                });
                if attached.is_err() {
                    let _ = sender.try_send(Err(BackupErrorCode::IoError));
                }
                Ok(())
            },
        );
        if status != napi::Status::Ok {
            return Err(core_error(BackupErrorCode::IoError));
        }
        let bytes = wait_for_callback(receiver, &self.cancelled, || self.callback.aborted())?;
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl BackupByteSink for SinkAdapter {
    fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(core_error(BackupErrorCode::Cancelled));
        }
        if bytes.len() > MAX_IO_CHUNK_BYTES_V1 {
            return Err(core_error(BackupErrorCode::InvalidState));
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let status = self.callback.call_with_return_value(
            Zeroizing::new(bytes.to_vec()),
            ThreadsafeFunctionCallMode::NonBlocking,
            move |result, env| {
                let success = sender.clone();
                let failure = sender.clone();
                let attached = result.and_then(|promise| {
                    attach_promise_handlers(
                        env,
                        promise,
                        move |_| {
                            let _ = success.try_send(Ok(()));
                            Ok(())
                        },
                        move |_: CallbackContext<Unknown>| {
                            let _ = failure.try_send(Err(BackupErrorCode::IoError));
                            Ok(())
                        },
                    )
                });
                if attached.is_err() {
                    let _ = sender.try_send(Err(BackupErrorCode::IoError));
                }
                Ok(())
            },
        );
        if status != napi::Status::Ok {
            return Err(core_error(BackupErrorCode::IoError));
        }
        wait_for_callback(receiver, &self.cancelled, || self.callback.aborted())
    }
}

fn adapters(
    read: Function<'_, FnArgs<(u32,)>, PromiseRaw<'static, Buffer>>,
    write: Function<'_, FnArgs<(Buffer,)>, PromiseRaw<'static, ()>>,
    cancellation: Option<&BackupCancellation>,
) -> napi::Result<(SourceAdapter, SinkAdapter)> {
    let cancelled = cancellation
        .map(|token| Arc::clone(&token.cancelled))
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Cancelled.into());
    }
    let read = read
        .build_threadsafe_function::<u32>()
        .max_queue_size::<1>()
        .build_callback(|ctx| Ok(FnArgs::from((ctx.value,))))?;
    let write = write
        .build_threadsafe_function::<Zeroizing<Vec<u8>>>()
        .max_queue_size::<1>()
        .build_callback(|ctx| Ok(FnArgs::from((Buffer::from(ctx.value.to_vec()),))))?;
    Ok((
        SourceAdapter {
            callback: read,
            cancelled: Arc::clone(&cancelled),
        },
        SinkAdapter {
            callback: write,
            cancelled,
        },
    ))
}

pub struct SealBackupObjectTask {
    context: Arc<BackupObjectContextV1>,
    source: SourceAdapter,
    sink: SinkAdapter,
}

#[napi]
impl Task for SealBackupObjectTask {
    type Output = BackupObjectDescriptor;
    type JsValue = BackupObjectMetadata;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        seal_object_v1(&self.context, &mut self.source, &mut self.sink).map_err(map_error)
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output.into())
    }
}

pub struct OpenBackupObjectTask {
    context: Arc<BackupObjectContextV1>,
    source: SourceAdapter,
    sink: SinkAdapter,
}

#[napi]
impl Task for OpenBackupObjectTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        open_object_v1(&self.context, &mut self.source, &mut self.sink).map_err(map_error)
    }

    fn resolve(&mut self, _: Env, _: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(())
    }
}

#[napi]
pub fn seal_backup_object_v1<'env>(
    env: &'env Env,
    context: &BackupObjectContext,
    read: Function<'_, FnArgs<(u32,)>, PromiseRaw<'static, Buffer>>,
    #[napi(ts_arg_type = "(chunk: Buffer) => Promise<void>")] write: Function<
        '_,
        FnArgs<(Buffer,)>,
        PromiseRaw<'static, ()>,
    >,
    cancellation: Option<&BackupCancellation>,
) -> napi::Result<PromiseRaw<'env, BackupObjectMetadata>> {
    let context = context.shared()?;
    let (source, sink) = adapters(read, write, cancellation)?;
    spawn_io_task(
        env,
        SealBackupObjectTask {
            context,
            source,
            sink,
        },
    )
}

#[napi(ts_return_type = "Promise<void>")]
pub fn open_backup_object_v1<'env>(
    env: &'env Env,
    context: &BackupObjectContext,
    read: Function<'_, FnArgs<(u32,)>, PromiseRaw<'static, Buffer>>,
    #[napi(ts_arg_type = "(chunk: Buffer) => Promise<void>")] write: Function<
        '_,
        FnArgs<(Buffer,)>,
        PromiseRaw<'static, ()>,
    >,
    cancellation: Option<&BackupCancellation>,
) -> napi::Result<PromiseRaw<'env, ()>> {
    let context = context.shared()?;
    let (source, sink) = adapters(read, write, cancellation)?;
    spawn_io_task(
        env,
        OpenBackupObjectTask {
            context,
            source,
            sink,
        },
    )
}

type Resolver<T> = Box<dyn FnOnce(Env) -> napi::Result<T>>;
type Deferred<T> = JsDeferred<T, Resolver<T>>;

fn spawn_io_task<T: Task + 'static>(env: &Env, task: T) -> napi::Result<PromiseRaw<'_, T::JsValue>>
where
    T::JsValue: 'static,
{
    let (sender, receiver) = mpsc::sync_channel::<(T, Deferred<T::JsValue>)>(1);
    std::thread::Builder::new()
        .name("kchat-backup-io".into())
        .spawn(move || {
            if let Ok((mut task, deferred)) = receiver.recv() {
                let result = catch_unwind(AssertUnwindSafe(|| task.compute()))
                    .unwrap_or_else(|_| Err(invalid_state()));
                deferred.resolve(Box::new(move |env| {
                    let result = match result {
                        Ok(output) => task.resolve(env, output),
                        Err(error) => task.reject(env, error),
                    };
                    task.finally(env)?;
                    result
                }));
            }
        })
        .map_err(|_| napi::Error::from(Error::ResourceLimitExceeded))?;
    let (deferred, promise) = env.create_deferred::<T::JsValue, Resolver<T::JsValue>>()?;
    if let Err(error) = sender.send((task, deferred)) {
        error.0.1.reject(invalid_state());
    }
    Ok(PromiseRaw::new(env.raw(), promise.raw()))
}
